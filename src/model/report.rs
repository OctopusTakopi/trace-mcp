use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::events::TimeQuality;
use super::ids::{AnalysisId, ReportId, SnapshotId, ThreadId};
use super::json::Count;
use crate::error::{Error, Result};
use crate::model::config::{DEFAULT_QUERY_ROWS, MAX_QUERY_ROWS, validate_relative_ns};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    #[serde(default)]
    pub thread_id: Option<ThreadId>,
    #[serde(default)]
    pub start_ns: Option<u64>,
    #[serde(default)]
    pub end_ns: Option<u64>,
}

impl Selection {
    pub fn validate(&self) -> Result<()> {
        if let Some(s) = self.start_ns {
            validate_relative_ns(s)?;
        }
        if let Some(e) = self.end_ns {
            validate_relative_ns(e)?;
        }
        match (self.start_ns, self.end_ns) {
            (Some(s), Some(e)) if s >= e => {
                Err(Error::invalid_argument("start_ns must be < end_ns"))
            }
            _ => Ok(()),
        }
    }

    /// Half-open `[start, end)` intersection test. Missing bounds select the whole range.
    pub fn contains_instant(&self, ns: u64) -> bool {
        self.start_ns.is_none_or(|s| ns >= s) && self.end_ns.is_none_or(|e| ns < e)
    }

    pub fn intersects(&self, start: Option<u64>, end: Option<u64>) -> bool {
        let sel_s = self.start_ns.unwrap_or(0);
        let sel_e = self.end_ns.unwrap_or(u64::MAX);
        let a = start.unwrap_or(0);
        let b = end.unwrap_or(u64::MAX);
        a < sel_e && b > sel_s
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryKind {
    Summary,
    /// Spans intersecting the selection, ordered by start time.
    Timeline {
        /// Keep spans whose demangled function name contains this substring.
        #[serde(default)]
        function_contains: Option<String>,
        /// Keep spans whose known duration is at least this long (incomplete spans are dropped).
        #[serde(default)]
        min_duration_ns: Option<u64>,
    },
    /// Aggregates over complete spans fully inside the selection.
    Hotpaths {
        /// Keep rows whose path (or function) contains this substring.
        #[serde(default)]
        function_contains: Option<String>,
        /// `path` (default: full caller chain) or `function` (one row per function, any caller).
        #[serde(default)]
        group: HotpathGroup,
        /// `inclusive` (default), `self_time`, or `calls`.
        #[serde(default)]
        sort: HotpathSort,
        /// Keep only the innermost N frames of each path (prefix shown as `.../`).
        #[serde(default)]
        max_depth: Option<u32>,
    },
    Instructions,
    Branches,
    /// Every image of the snapshot with path, content hash and build id.
    Images,
    /// Instruction analysis only: executed-instruction counts per
    /// (symbol, innermost inlined function). Exact counts from PT; the way
    /// to see inside a function that LTO flattened.
    InlineProfile,
    /// Calls analysis: what every thread was executing at one instant
    /// (innermost open span and its call chain). Use it to relate threads,
    /// e.g. what the consumer was doing when the producer pushed.
    AtInstant {
        at_ns: u64,
    },
    /// Resolve one place in the code to image, symbol, file:line and DWARF
    /// inline frames. Give exactly one of the reference fields.
    Source {
        #[serde(default)]
        location_id: Option<String>,
        #[serde(default)]
        function_id: Option<String>,
        #[serde(default)]
        evidence_id: Option<String>,
        /// Virtual address as printed in instruction/branch rows (hex, `0x` optional).
        #[serde(default)]
        address: Option<String>,
    },
    Quality,
    Comparison,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HotpathGroup {
    #[default]
    Path,
    Function,
    /// Rows per `symbol > inlined > inlined...` from executed blocks: exact
    /// instruction counts and quantized elapsed time inside LTO-flattened code.
    Inline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HotpathSort {
    #[default]
    Inclusive,
    SelfTime,
    Calls,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryTarget {
    Snapshot {
        snapshot_id: SnapshotId,
        #[serde(default)]
        analysis_id: Option<AnalysisId>,
    },
    Report {
        report_id: ReportId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryRequest {
    pub target: QueryTarget,
    pub query: QueryKind,
    #[serde(default)]
    pub selection: Option<Selection>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

impl QueryRequest {
    pub fn row_limit(&self) -> Result<u32> {
        match self.limit.unwrap_or(DEFAULT_QUERY_ROWS) {
            0 => Err(Error::invalid_argument("limit must be > 0")),
            n if n > MAX_QUERY_ROWS => Err(Error::invalid_argument(format!(
                "limit {n} exceeds maximum {MAX_QUERY_ROWS}"
            ))),
            n => Ok(n),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePage<T> {
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<SnapshotId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_id: Option<AnalysisId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_id: Option<ReportId>,
    #[serde(default)]
    pub selection: Option<Selection>,
    pub quality: PageQuality,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageQuality {
    pub timing: TimeQuality,
    pub gap_count: Count,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum CompareMode {
    #[default]
    Exploratory,
    StrictPerformance,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareRequest {
    pub baseline: CompareSide,
    pub candidate: CompareSide,
    #[serde(default)]
    pub mode: CompareMode,
    #[serde(default)]
    pub function_pairs: Vec<FunctionPair>,
    /// `path` (caller chains, default) or `function` (one row per function).
    #[serde(default)]
    pub group: HotpathGroup,
    /// Keep only rows whose path/function contains this substring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_contains: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareSide {
    pub snapshot_id: SnapshotId,
    #[serde(default)]
    pub analysis_id: Option<AnalysisId>,
    #[serde(default)]
    pub selection: Option<Selection>,
    #[serde(default)]
    pub workload: Option<super::trace::WorkloadMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionPair {
    pub baseline_function_id: String,
    pub candidate_function_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparabilityCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareRow {
    pub path: String,
    pub baseline: Option<MetricValue>,
    pub candidate: Option<MetricValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absolute_delta: Option<i128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_delta: Option<String>,
    pub unit: String,
    pub normalization: String,
    pub match_kind: String,
    pub baseline_evidence: Vec<String>,
    pub candidate_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    pub value: i128,
    pub n: Count,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclusions: Option<Count>,
}

pub fn relative_delta(abs: i128, baseline: i128) -> Option<String> {
    if baseline == 0 {
        None
    } else {
        Some(format!("{:.6}", abs as f64 / baseline as f64))
    }
}

/// Nearest-rank quantile: Q(p) = x[ceil(p*n)-1] for sorted x.
pub fn nearest_rank(sorted: &[u64], p_times_100: u32) -> Option<u64> {
    let n = sorted.len();
    if n == 0 {
        return None;
    }
    let num = u128::from(p_times_100) * n as u128;
    let ceil = num.div_ceil(100);
    let idx = ceil.saturating_sub(1) as usize;
    sorted.get(idx.min(n - 1)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantile_empty() {
        assert_eq!(nearest_rank(&[], 50), None);
    }

    #[test]
    fn quantile_single() {
        assert_eq!(nearest_rank(&[10], 99), Some(10));
    }

    #[test]
    fn relative_delta_zero_baseline() {
        assert_eq!(relative_delta(5, 0), None);
        assert_eq!(relative_delta(5, 10), Some("0.500000".into()));
    }

    #[test]
    fn selection_half_open() {
        let s = Selection {
            thread_id: None,
            start_ns: Some(10),
            end_ns: Some(20),
        };
        assert!(s.contains_instant(10));
        assert!(s.contains_instant(19));
        assert!(!s.contains_instant(20));
        assert!(!s.contains_instant(9));
    }
}
