use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::config::IntelPtConfig;
use super::events::{ClockOrigin, DetailLevel, QualityReport};
use super::ids::{AnalysisId, JobId, SessionId, SnapshotId, ThreadId};
use super::json::Count;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Starting,
    Armed,
    Finalizing,
    Captured,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureReason {
    Snapshot,
    AfterMs,
    TargetExit,
    TimeLimit,
    Stop,
    /// A configured trigger fired (symbol hit or the workload wrote to the
    /// `TRACE_MCP_TRIGGER` FIFO).
    Trigger,
}

/// Snapshot trigger for launch targets. The capture still ends on
/// `after_ms`, target exit, `max_capture_ms`, or an explicit stop if the
/// trigger never fires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Trigger {
    /// Break on a function in the launched executable (exact demangled Rust
    /// path, raw symbol, or unique substring) and snapshot on the `hits`-th
    /// call. Inlined functions have no symbol. Implemented with a ptrace
    /// `int3` that is removed after the trigger fires.
    Symbol {
        symbol: String,
        #[serde(default = "default_hits")]
        hits: u32,
    },
    /// The workload fires the snapshot itself by writing a line to the FIFO
    /// named by the `TRACE_MCP_TRIGGER` environment variable.
    Fifo,
}

fn default_hits() -> u32 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobPhase {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    InitialDecode,
    InstructionDecode,
    Compare,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Launch {
        argv: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        /// Extra environment for the workload (added to the server's own).
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        env: std::collections::BTreeMap<String, String>,
    },
    Attach {
        pid: u32,
    },
}

impl Target {
    pub fn validate(&self) -> crate::error::Result<()> {
        match self {
            Self::Launch { argv, .. } => {
                if argv.is_empty() || argv[0].is_empty() {
                    return Err(crate::error::Error::invalid_argument(
                        "launch argv must be non-empty",
                    ));
                }
            }
            Self::Attach { pid } => {
                if *pid == 0 {
                    return Err(crate::error::Error::invalid_argument(
                        "attach pid must be > 0",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn owns_workload(&self) -> bool {
        matches!(self, Self::Launch { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadMeta {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub input_fingerprint: Option<String>,
}

/// What the PT hardware actually recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureScope {
    /// Only the target task tree, on every CPU it ran on.
    #[default]
    Task,
    /// Every user task on the listed CPUs (perf `-C`). Analyses keep only the
    /// target tree; raw perf.data still contains the other tasks' PT bytes.
    CpuWide { cpus: Vec<u32> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub schema_version: u32,
    pub snapshot_id: SnapshotId,
    pub session_id: SessionId,
    pub capture_reason: CaptureReason,
    pub lifecycle: SessionPhase,
    pub requested_config: IntelPtConfig,
    pub effective_event: String,
    pub cpu_vendor: String,
    pub cpu_model: String,
    #[serde(default)]
    pub cpu_family: String,
    #[serde(default)]
    pub cpu_stepping: String,
    pub kernel: String,
    pub perf_version: String,
    pub perf_argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_clock: Option<String>,
    pub raw_bytes: Count,
    pub target: Target,
    #[serde(default)]
    pub scope: CaptureScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<Trigger>,
    /// Runtime address of the symbol breakpoint, when a symbol trigger fired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_address: Option<super::json::Address>,
    /// Effective perf address filter clauses, when configured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address_filters: Vec<String>,
    #[serde(default)]
    pub workload: Option<WorkloadMeta>,
    pub observed_threads: Vec<ObservedThread>,
    pub images: Vec<ImageIdentity>,
    pub missing_images: Vec<String>,
    pub redecode_ready: bool,
    pub diagnostics: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_exit_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorder_exit_status: Option<i32>,
    /// `direct` (per-thread perf_event_open bundle, native decoder only) or
    /// `perf` (perf record). Missing in snapshots older than 2026-09-08.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorder: Option<String>,
    /// Number of direct-recorder AUX rings that wrapped before capture ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_rings: Option<Count>,
    /// The traced process tree's root pid (direct recorder).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedThread {
    pub thread_id: ThreadId,
    pub pid: u32,
    pub tid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageIdentity {
    pub path: String,
    pub content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    pub archived: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisManifest {
    pub schema_version: u32,
    pub ir_version: u32,
    pub analysis_id: AnalysisId,
    pub snapshot_id: SnapshotId,
    pub detail: DetailLevel,
    pub decoder_version: String,
    pub decoder_argv: Vec<String>,
    pub dialect: String,
    pub cache_key: String,
    pub origin: ClockOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<super::report::Selection>,
    pub quality: QualityReport,
    pub function_count: Count,
    pub span_count: Count,
    pub event_count: Count,
    pub covered_start_ns: Option<u64>,
    pub covered_end_ns: Option<u64>,
    #[serde(default)]
    pub thread_count: Count,
    /// PT samples decoded in this pass (branches for calls, instructions for detail).
    #[serde(default)]
    pub sample_count: Count,
    #[serde(default)]
    pub script_lines: Count,
    #[serde(default)]
    pub script_bytes: Count,
    #[serde(default)]
    pub decode_wall_ms: u64,
    /// Snapshot-relative time of the trigger trap observed in the trace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_hit_ns: Option<u64>,
    /// `full` (branches) or `fast` (calls/returns only) for calls analyses.
    #[serde(default = "default_decode_mode")]
    pub decode_mode: String,
    #[serde(default = "default_streams")]
    pub decode_streams: u32,
}

/// Number of parallel `perf script` streams used (1 = serial).
#[allow(dead_code)]
fn default_streams() -> u32 {
    1
}

fn default_decode_mode() -> String {
    "full".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub job_id: JobId,
    pub kind: JobKind,
    pub phase: JobPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<SnapshotId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_id: Option<AnalysisId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_id: Option<super::ids::ReportId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawCaptureState {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedState {
    Pending,
    Ready,
    Failed,
}
