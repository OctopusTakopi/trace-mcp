use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorCode, Result};

/// JSON numbers that must remain exact in IEEE-754 doubles (MCP relative_ns).
pub const JSON_SAFE_INT_MAX: u64 = 9_007_199_254_740_991;

pub const SCHEMA_VERSION: u32 = 1;
pub const IR_VERSION: u32 = 42;

pub const DEFAULT_AUX_BYTES: u64 = 4 * 1024 * 1024;
/// Default ring per traced thread for the direct recorder.
pub const DEFAULT_DIRECT_AUX_BYTES: u64 = 32 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_AUX: u64 = 128 * 1024 * 1024;
pub const DEFAULT_MAX_CAPTURE_MS: u64 = 30_000;
pub const DEFAULT_STARTUP_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_FINALIZE_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_OWNED_TERM_GRACE_MS: u64 = 2_000;
/// perf's text decoder runs ~100 MB/s; a 32 MiB AUX capture is ~12 GB of
/// text, about two minutes. Measured 2026-09-07 on Xeon Gold 6230.
pub const DEFAULT_DECODE_TIMEOUT_MS: u64 = 600_000;
pub const DEFAULT_RAW_DISK_BUDGET: u64 = 512 * 1024 * 1024;
pub const DEFAULT_IMAGE_BUDGET: u64 = 512 * 1024 * 1024;
pub const DEFAULT_DERIVED_BUDGET: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_REPORT_BUDGET: u64 = 64 * 1024 * 1024;
pub const DEFAULT_RESIDENT_DECODE_BUDGET: u64 = 256 * 1024 * 1024;
pub const DEFAULT_STORE_BUDGET: u64 = 4 * 1024 * 1024 * 1024;
pub const DEFAULT_MCP_RESULT_BUDGET: usize = 32 * 1024;
pub const DEFAULT_QUERY_ROWS: u32 = 50;
pub const MAX_QUERY_ROWS: u32 = 200;
pub const DEFAULT_META_PAGES: u64 = 16;
pub const DEFAULT_ACTIVE_CAPTURES: u32 = 1;
pub const DEFAULT_DECODE_JOBS: u32 = 1;
pub const DEFAULT_PENDING_EXPENSIVE: u32 = 4;
/// `perf script` children run in parallel, one per CPU stream .
pub const DEFAULT_DECODE_PARALLELISM: u32 = 8;
pub const P99_MIN_SAMPLES: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum TimingProfile {
    LowBandwidth,
    #[default]
    Balanced,
    Detailed,
}

impl TimingProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowBandwidth => "low_bandwidth",
            Self::Balanced => "balanced",
            Self::Detailed => "detailed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntelPtConfig {
    #[serde(default)]
    pub timing: TimingProfile,
    /// Per-CPU AUX ring bytes (power of two, page multiple). Omit for auto:
    /// 4 MiB, shrunk to fit `max_total_aux_bytes` across all online CPUs, or
    /// grown to fill the budget when `cpus` is restricted. After capture the
    /// manifest holds the effective value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aux_bytes_per_buffer: Option<u64>,
    /// Set when `aux_bytes_per_buffer` was filled in by topology fitting
    /// rather than requested (the direct recorder then sizes per thread).
    #[serde(default, skip_serializing)]
    pub aux_bytes_auto: bool,
    #[serde(default = "default_total_aux")]
    pub max_total_aux_bytes: u64,
    #[serde(default = "default_capture_ms")]
    pub max_capture_ms: u64,
    /// Record only these CPUs and pin the launched workload to them. perf
    /// allocates one AUX ring per recorded CPU, so restricting an 80-CPU host
    /// to 4 CPUs turns the same total budget into 20x more history per CPU
    /// and removes migration holes. With the default `aux_bytes_per_buffer`
    /// the ring grows to fill `max_total_aux_bytes`. Launch targets only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<Vec<u32>>,
    /// Hardware address filters (at most `num_address_ranges`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address_filters: Vec<AddressFilter>,
}

/// Intel PT hardware address filter. `filter` traces only inside the
/// symbol's range, `tracestop` stops tracing inside it (an idle loop that
/// has its own function), `start`/`stop` toggle tracing at its first byte.
/// The hardware has `num_address_ranges` slots (2 on Skylake-SP). Symbols
/// are resolved by trace-mcp against `image` (default: the launched
/// executable) and passed to perf as file offsets. Code outside a `filter`
/// range is unobserved: calls into it appear as `trace_boundary` gaps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressFilter {
    pub kind: AddressFilterKind,
    pub symbol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AddressFilterKind {
    Filter,
    Tracestop,
    Start,
    Stop,
}

impl AddressFilterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filter => "filter",
            Self::Tracestop => "tracestop",
            Self::Start => "start",
            Self::Stop => "stop",
        }
    }

    pub fn needs_size(self) -> bool {
        matches!(self, Self::Filter | Self::Tracestop)
    }
}

/// Largest per-CPU AUX ring chosen automatically when `cpus` is restricted.
pub const MAX_AUTO_AUX_BYTES: u64 = 256 * 1024 * 1024;

fn default_total_aux() -> u64 {
    DEFAULT_MAX_TOTAL_AUX
}
fn default_capture_ms() -> u64 {
    DEFAULT_MAX_CAPTURE_MS
}

impl Default for IntelPtConfig {
    fn default() -> Self {
        Self {
            timing: TimingProfile::Balanced,
            aux_bytes_per_buffer: None,
            aux_bytes_auto: false,
            max_total_aux_bytes: DEFAULT_MAX_TOTAL_AUX,
            max_capture_ms: DEFAULT_MAX_CAPTURE_MS,
            cpus: None,
            address_filters: Vec::new(),
        }
    }
}

impl IntelPtConfig {
    pub fn validate(&self, page_size: u64) -> Result<()> {
        if self.max_capture_ms == 0 {
            return Err(Error::invalid_argument("max_capture_ms must be > 0"));
        }
        validate_aux_bytes(
            self.aux_bytes_per_buffer.unwrap_or(DEFAULT_AUX_BYTES),
            page_size,
        )?;
        if let Some(cpus) = &self.cpus {
            if cpus.is_empty() {
                return Err(Error::invalid_argument("cpus must list at least one CPU"));
            }
            let mut seen = std::collections::HashSet::new();
            for c in cpus {
                if !seen.insert(*c) {
                    return Err(Error::invalid_argument(format!("cpus lists CPU {c} twice")));
                }
            }
        }
        for f in &self.address_filters {
            if f.symbol.trim().is_empty() {
                return Err(Error::invalid_argument(
                    "address filter symbol must not be empty",
                ));
            }
        }
        if self.max_total_aux_bytes < self.aux_bytes_per_buffer.unwrap_or(DEFAULT_AUX_BYTES) {
            return Err(Error::new(
                ErrorCode::UnsupportedPtConfig,
                "max_total_aux_bytes is smaller than aux_bytes_per_buffer",
            ));
        }
        Ok(())
    }

    /// Resolve the effective per-CPU AUX size. An explicit size is honoured
    /// or rejected; an omitted size is 4 MiB shrunk to fit the total budget
    /// on all online CPUs, or grown to fill it when `cpus` is restricted.
    pub fn fit_aux_topology(
        &mut self,
        online_cpus: u64,
        page_size: u64,
        meta_pages: u64,
    ) -> Result<AuxTopology> {
        self.validate(page_size)?;
        let explicit = self.aux_bytes_per_buffer;
        let ncpus = match &self.cpus {
            Some(cpus) => {
                if let Some(bad) = cpus.iter().find(|&&c| u64::from(c) >= online_cpus) {
                    return Err(Error::invalid_argument(format!(
                        "cpu {bad} is not online ({online_cpus} online CPUs)"
                    )));
                }
                cpus.len() as u64
            }
            None => online_cpus,
        };
        let requested = match (explicit, &self.cpus) {
            (Some(v), _) => v,
            (None, Some(_)) => {
                // The caller restricted CPUs to buy history: fill the budget.
                suggested_aux(ncpus, self.max_total_aux_bytes, page_size)
                    .clamp(DEFAULT_AUX_BYTES, MAX_AUTO_AUX_BYTES)
            }
            (None, None) => DEFAULT_AUX_BYTES,
        };
        let top = match AuxTopology::compute(
            ncpus,
            page_size,
            meta_pages,
            requested,
            self.max_total_aux_bytes,
        ) {
            Ok(top) => top,
            Err(_) if explicit.is_none() => {
                let suggest = suggested_aux(ncpus, self.max_total_aux_bytes, page_size);
                validate_aux_bytes(suggest, page_size)?;
                AuxTopology::compute(
                    ncpus,
                    page_size,
                    meta_pages,
                    suggest,
                    self.max_total_aux_bytes,
                )?
            }
            Err(err) => return Err(err),
        };
        if explicit.is_none() {
            self.aux_bytes_auto = true;
        }
        self.aux_bytes_per_buffer = Some(top.aux_bytes_per_buffer);
        Ok(top)
    }

    /// Resolve the per-thread ring size used by the direct recorder. It
    /// opens one ring per traced thread and stops tracing new threads once
    /// `max_total_aux_bytes` is spent, so only a single ring has to fit the
    /// budget here; the per-CPU product of `fit_aux_topology` does not apply.
    /// An explicit size is honoured (or rejected by `validate`); an omitted
    /// size is 32 MiB, shrunk to the budget.
    pub fn fit_aux_per_thread(&mut self, page_size: u64, meta_pages: u64) -> Result<AuxTopology> {
        self.validate(page_size)?;
        let explicit = self.aux_bytes_per_buffer;
        let mut aux = explicit
            .unwrap_or(DEFAULT_DIRECT_AUX_BYTES)
            .min(self.max_total_aux_bytes);
        if !aux.is_power_of_two() {
            aux = 1u64 << (63 - aux.leading_zeros());
        }
        validate_aux_bytes(aux, page_size)?;
        if explicit.is_none() {
            self.aux_bytes_auto = true;
        }
        self.aux_bytes_per_buffer = Some(aux);
        Ok(AuxTopology {
            ncpus: 1,
            page_size,
            meta_pages,
            aux_bytes_per_buffer: aux,
            aux_total: aux,
            meta_total: meta_pages.saturating_mul(page_size),
        })
    }
}

pub fn validate_aux_bytes(aux: u64, page_size: u64) -> Result<()> {
    if page_size == 0 || !page_size.is_power_of_two() {
        return Err(Error::new(
            ErrorCode::UnsupportedPtConfig,
            format!("unusable page size {page_size}"),
        ));
    }
    if aux == 0 || !aux.is_multiple_of(page_size) || !aux.is_power_of_two() {
        return Err(Error::new(
            ErrorCode::UnsupportedPtConfig,
            format!("aux_bytes_per_buffer {aux} must be a power of two multiple of page size {page_size}"),
        )
        .with_next("Choose 256KiB, 1MiB, or 4MiB"));
    }
    Ok(())
}

/// Hardware PT terms discovered from sysfs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtCapabilities {
    pub mtc: bool,
    pub mtc_periods_mask: u64,
    pub psb_cyc: bool,
    pub psb_periods_mask: u64,
    pub cycle_thresholds_mask: u64,
    pub ptwrite: bool,
    pub tnt_disable: bool,
    pub num_address_ranges: u32,
    pub event_type: u32,
}

impl PtCapabilities {
    pub fn values_from_mask(mask: u64) -> Vec<u8> {
        (0..64)
            .filter(|bit| (mask >> bit) & 1 == 1)
            .map(|b| b as u8)
            .collect()
    }

    pub fn nearest(want: u8, supported: &[u8]) -> Option<u8> {
        supported.iter().copied().min_by_key(|v| {
            let dist = i16::from(*v).abs_diff(i16::from(want));
            (dist, *v)
        })
    }
}

/// Encoded intel_pt/.../u terms actually requested from perf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectivePtTerms {
    pub profile: TimingProfile,
    pub tsc: bool,
    pub mtc: bool,
    pub mtc_period: Option<u8>,
    pub cyc: bool,
    pub cyc_thresh: Option<u8>,
    pub noretcomp: bool,
    pub psb_period: u8,
    pub branch: bool,
    pub event_spec: String,
}

impl EffectivePtTerms {
    pub fn resolve(profile: TimingProfile, caps: &PtCapabilities, aux_bytes: u64) -> Result<Self> {
        let mut terms = Self {
            profile,
            tsc: true,
            mtc: false,
            mtc_period: None,
            cyc: false,
            cyc_thresh: None,
            noretcomp: false,
            psb_period: 0,
            branch: true,
            event_spec: String::new(),
        };

        match profile {
            TimingProfile::LowBandwidth => {
                terms.tsc = true;
                terms.mtc = false;
                terms.cyc = false;
                terms.noretcomp = false;
            }
            TimingProfile::Balanced => {
                if !caps.mtc {
                    return Err(Error::new(
                        ErrorCode::UnsupportedPtConfig,
                        "balanced profile requires MTC support",
                    )
                    .with_next("Use timing=low_bandwidth or a CPU with MTC"));
                }
                let periods = PtCapabilities::values_from_mask(caps.mtc_periods_mask);
                let period = PtCapabilities::nearest(3, &periods).ok_or_else(|| {
                    Error::new(ErrorCode::UnsupportedPtConfig, "no supported MTC periods")
                })?;
                terms.mtc = true;
                terms.mtc_period = Some(period);
                terms.cyc = false;
                terms.noretcomp = false;
            }
            TimingProfile::Detailed => {
                if !caps.mtc {
                    return Err(Error::new(
                        ErrorCode::UnsupportedPtConfig,
                        "detailed profile requires MTC support",
                    ));
                }
                if !caps.psb_cyc {
                    return Err(Error::new(
                        ErrorCode::UnsupportedPtConfig,
                        "detailed profile requires CYC support (psb_cyc)",
                    ));
                }
                let periods = PtCapabilities::values_from_mask(caps.mtc_periods_mask);
                let period = periods.iter().copied().min().ok_or_else(|| {
                    Error::new(ErrorCode::UnsupportedPtConfig, "no supported MTC periods")
                })?;
                let cycs = PtCapabilities::values_from_mask(caps.cycle_thresholds_mask);
                let thresh = PtCapabilities::nearest(1, &cycs).ok_or_else(|| {
                    Error::new(
                        ErrorCode::UnsupportedPtConfig,
                        "no supported CYC thresholds",
                    )
                })?;
                terms.mtc = true;
                terms.mtc_period = Some(period);
                terms.cyc = true;
                terms.cyc_thresh = Some(thresh);
                terms.noretcomp = true;
            }
        }

        terms.psb_period = choose_psb_period(caps, aux_bytes)?;
        terms.event_spec = terms.render_event_spec();
        Ok(terms)
    }

    pub fn render_event_spec(&self) -> String {
        let mut parts = vec!["tsc=1".to_string(), "branch=1".to_string()];
        if self.mtc {
            parts.push("mtc=1".into());
            if let Some(p) = self.mtc_period {
                parts.push(format!("mtc_period={p}"));
            }
        } else {
            parts.push("mtc=0".into());
        }
        if self.cyc {
            parts.push("cyc=1".into());
            if let Some(t) = self.cyc_thresh {
                parts.push(format!("cyc_thresh={t}"));
            }
        } else {
            parts.push("cyc=0".into());
        }
        parts.push(format!("noretcomp={}", u8::from(self.noretcomp)));
        parts.push(format!("psb_period={}", self.psb_period));
        format!("intel_pt/{}/u", parts.join(","))
    }
}

pub fn psb_spacing_bytes(period: u8) -> u64 {
    1u64 << (u32::from(period) + 11)
}

fn choose_psb_period(caps: &PtCapabilities, aux_bytes: u64) -> Result<u8> {
    if !caps.psb_cyc {
        return Ok(0);
    }
    let supported = PtCapabilities::values_from_mask(caps.psb_periods_mask);
    if supported.is_empty() {
        return Ok(0);
    }
    let mut chosen = None;
    for p in &supported {
        let spacing = psb_spacing_bytes(*p);
        if spacing + 256 < aux_bytes / 2 {
            chosen = Some(*p);
        }
    }
    chosen
        .or_else(|| {
            supported
                .iter()
                .copied()
                .min()
                .filter(|p| psb_spacing_bytes(*p) < aux_bytes)
        })
        .ok_or_else(|| {
            Error::new(
                ErrorCode::UnsupportedPtConfig,
                format!("AUX {aux_bytes} is too small for a supported PSB period"),
            )
            .with_next("Increase aux_bytes_per_buffer")
        })
}

#[derive(Debug, Clone, Copy)]
pub struct AuxTopology {
    pub ncpus: u64,
    pub page_size: u64,
    pub meta_pages: u64,
    pub aux_bytes_per_buffer: u64,
    pub aux_total: u64,
    pub meta_total: u64,
}

impl AuxTopology {
    pub fn compute(
        ncpus: u64,
        page_size: u64,
        meta_pages: u64,
        aux_bytes: u64,
        max_total_aux: u64,
    ) -> Result<Self> {
        if ncpus == 0 {
            return Err(Error::new(
                ErrorCode::UnsupportedPtConfig,
                "cannot bound AUX topology: CPU count is unknown",
            ));
        }
        validate_aux_bytes(aux_bytes, page_size)?;
        let aux_total = ncpus
            .checked_mul(aux_bytes)
            .ok_or_else(|| Error::new(ErrorCode::UnsupportedPtConfig, "AUX topology overflow"))?;
        if aux_total > max_total_aux {
            return Err(Error::new(
                ErrorCode::UnsupportedPtConfig,
                format!(
                    "per-CPU AUX topology {ncpus} x {aux_bytes} = {aux_total} exceeds max_total_aux_bytes {max_total_aux}"
                ),
            )
            .with_next(format!(
                "Lower aux_bytes_per_buffer; largest power-of-two that fits is {}",
                suggested_aux(ncpus, max_total_aux, page_size)
            )));
        }
        let meta_total = ncpus
            .checked_mul(meta_pages)
            .and_then(|p| p.checked_mul(page_size))
            .ok_or_else(|| {
                Error::new(ErrorCode::UnsupportedPtConfig, "metadata topology overflow")
            })?;
        Ok(Self {
            ncpus,
            page_size,
            meta_pages,
            aux_bytes_per_buffer: aux_bytes,
            aux_total,
            meta_total,
        })
    }
}

pub fn suggested_aux(ncpus: u64, max_total: u64, page_size: u64) -> u64 {
    if ncpus == 0 {
        return page_size;
    }
    let per = max_total / ncpus;
    let mut v = per.next_power_of_two();
    if v > per {
        v >>= 1;
    }
    v.max(page_size)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub max_active_captures: u32,
    pub max_decode_jobs: u32,
    pub max_pending_expensive: u32,
    pub startup_timeout_ms: u64,
    pub finalize_timeout_ms: u64,
    pub owned_term_grace_ms: u64,
    pub decode_timeout_ms: u64,
    pub raw_disk_budget: u64,
    pub image_budget: u64,
    pub derived_budget: u64,
    pub report_budget: u64,
    pub resident_decode_budget: u64,
    pub store_budget: u64,
    pub mcp_result_budget: usize,
    pub default_query_rows: u32,
    pub max_query_rows: u32,
    pub meta_pages: u64,
    #[serde(default = "default_parallelism")]
    pub decode_parallelism: u32,
    /// Decode PT with libipt in-process (default) instead of `perf script`.
    /// `TRACE_MCP_DECODER=perf` forces the perf path (the parity oracle).
    #[serde(default = "default_true")]
    pub native_decoder: bool,
    /// Record launched workloads with the direct per-thread recorder
    /// (`perf_event_open` per thread; default) instead of `perf record`.
    /// `TRACE_MCP_RECORDER=perf` forces perf record.
    #[serde(default = "default_true")]
    pub direct_recorder: bool,
}

fn default_true() -> bool {
    true
}

fn default_parallelism() -> u32 {
    DEFAULT_DECODE_PARALLELISM
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_active_captures: DEFAULT_ACTIVE_CAPTURES,
            max_decode_jobs: DEFAULT_DECODE_JOBS,
            max_pending_expensive: DEFAULT_PENDING_EXPENSIVE,
            startup_timeout_ms: DEFAULT_STARTUP_TIMEOUT_MS,
            finalize_timeout_ms: DEFAULT_FINALIZE_TIMEOUT_MS,
            owned_term_grace_ms: DEFAULT_OWNED_TERM_GRACE_MS,
            decode_timeout_ms: DEFAULT_DECODE_TIMEOUT_MS,
            raw_disk_budget: DEFAULT_RAW_DISK_BUDGET,
            image_budget: DEFAULT_IMAGE_BUDGET,
            derived_budget: DEFAULT_DERIVED_BUDGET,
            report_budget: DEFAULT_REPORT_BUDGET,
            resident_decode_budget: DEFAULT_RESIDENT_DECODE_BUDGET,
            store_budget: std::env::var("TRACE_MCP_STORE_BUDGET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_STORE_BUDGET),
            mcp_result_budget: DEFAULT_MCP_RESULT_BUDGET,
            default_query_rows: DEFAULT_QUERY_ROWS,
            max_query_rows: MAX_QUERY_ROWS,
            meta_pages: DEFAULT_META_PAGES,
            decode_parallelism: std::env::var("TRACE_MCP_DECODE_PARALLELISM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_DECODE_PARALLELISM),
            native_decoder: std::env::var("TRACE_MCP_DECODER").map_or(true, |v| v != "perf"),
            direct_recorder: std::env::var("TRACE_MCP_RECORDER").map_or(true, |v| v != "perf"),
        }
    }
}

pub fn validate_relative_ns(ns: u64) -> Result<u64> {
    if ns > JSON_SAFE_INT_MAX {
        Err(Error::invalid_argument(format!(
            "relative_ns {ns} exceeds JSON-safe integer {JSON_SAFE_INT_MAX}"
        )))
    } else {
        Ok(ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aux_must_be_page_pow2() {
        assert!(validate_aux_bytes(4096, 4096).is_ok());
        assert!(validate_aux_bytes(4 * 1024 * 1024, 4096).is_ok());
        assert!(validate_aux_bytes(3000, 4096).is_err());
        assert!(validate_aux_bytes(8192, 4096).is_ok());
    }

    #[test]
    fn topology_rejects_80x4mib() {
        let err =
            AuxTopology::compute(80, 4096, 16, 4 * 1024 * 1024, 128 * 1024 * 1024).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedPtConfig);
    }

    #[test]
    fn topology_accepts_80x1mib() {
        let top = AuxTopology::compute(80, 4096, 16, 1024 * 1024, 128 * 1024 * 1024).unwrap();
        assert_eq!(top.aux_total, 80 * 1024 * 1024);
        assert_eq!(top.meta_total, 80 * 16 * 4096);
    }

    #[test]
    fn default_aux_unchanged_when_topology_fits() {
        let mut cfg = IntelPtConfig::default();
        let top = cfg.fit_aux_topology(32, 4096, 16).unwrap();
        assert_eq!(cfg.aux_bytes_per_buffer, Some(DEFAULT_AUX_BYTES));
        assert_eq!(top.aux_total, 32 * DEFAULT_AUX_BYTES);
    }

    #[test]
    fn default_aux_auto_fits_80_cpu_budget() {
        let mut cfg = IntelPtConfig::default();
        assert_eq!(cfg.aux_bytes_per_buffer, None);
        let top = cfg.fit_aux_topology(80, 4096, 16).unwrap();
        assert_eq!(cfg.aux_bytes_per_buffer, Some(1024 * 1024));
        assert_eq!(top.aux_total, 80 * 1024 * 1024);
    }

    #[test]
    fn explicit_oversize_aux_is_still_rejected() {
        let mut cfg = IntelPtConfig {
            aux_bytes_per_buffer: Some(2 * 1024 * 1024),
            ..IntelPtConfig::default()
        };
        let err = cfg.fit_aux_topology(80, 4096, 16).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedPtConfig);
        assert_eq!(cfg.aux_bytes_per_buffer, Some(2 * 1024 * 1024));
    }

    #[test]
    fn restricted_cpus_fill_the_budget() {
        let mut cfg = IntelPtConfig {
            cpus: Some(vec![4, 5, 6, 7]),
            ..IntelPtConfig::default()
        };
        let top = cfg.fit_aux_topology(80, 4096, 16).unwrap();
        assert_eq!(top.ncpus, 4);
        assert_eq!(cfg.aux_bytes_per_buffer, Some(32 * 1024 * 1024));
        assert_eq!(top.aux_total, 128 * 1024 * 1024);
        let mut bad = IntelPtConfig {
            cpus: Some(vec![4, 99]),
            ..IntelPtConfig::default()
        };
        assert_eq!(
            bad.fit_aux_topology(80, 4096, 16).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        let dup = IntelPtConfig {
            cpus: Some(vec![4, 4]),
            ..IntelPtConfig::default()
        };
        assert!(dup.validate(4096).is_err());
        // An explicit size is honoured, not grown.
        let mut explicit = IntelPtConfig {
            cpus: Some(vec![1, 2]),
            aux_bytes_per_buffer: Some(1024 * 1024),
            ..IntelPtConfig::default()
        };
        explicit.fit_aux_topology(80, 4096, 16).unwrap();
        assert_eq!(explicit.aux_bytes_per_buffer, Some(1024 * 1024));
        // An explicit 4 MiB with restricted cpus is honoured, not grown.
        let mut four = IntelPtConfig {
            cpus: Some(vec![1, 2]),
            aux_bytes_per_buffer: Some(DEFAULT_AUX_BYTES),
            ..IntelPtConfig::default()
        };
        four.fit_aux_topology(80, 4096, 16).unwrap();
        assert_eq!(four.aux_bytes_per_buffer, Some(DEFAULT_AUX_BYTES));
    }

    #[test]
    fn nearest_prefers_smaller_on_tie() {
        assert_eq!(PtCapabilities::nearest(4, &[3, 5]), Some(3));
        assert_eq!(PtCapabilities::nearest(3, &[0, 3, 6, 9]), Some(3));
    }

    #[test]
    fn per_thread_fit_ignores_cpu_count() {
        // 128 MiB per thread under a 384 MiB budget is valid for the direct
        // recorder even on an 80-CPU host, where the per-CPU fit rejects it.
        let mut cfg = IntelPtConfig {
            aux_bytes_per_buffer: Some(128 << 20),
            max_total_aux_bytes: 384 << 20,
            ..IntelPtConfig::default()
        };
        assert!(cfg.clone().fit_aux_topology(80, 4096, 16).is_err());
        let top = cfg.fit_aux_per_thread(4096, 16).unwrap();
        assert_eq!(top.aux_bytes_per_buffer, 128 << 20);
        assert_eq!(top.ncpus, 1);
        assert!(!cfg.aux_bytes_auto);

        // Omitted: 32 MiB default, shrunk to a smaller budget, flagged auto.
        let mut small = IntelPtConfig {
            max_total_aux_bytes: 24 << 20,
            ..IntelPtConfig::default()
        };
        let top = small.fit_aux_per_thread(4096, 16).unwrap();
        assert_eq!(top.aux_bytes_per_buffer, 16 << 20);
        assert!(small.aux_bytes_auto);
        assert_eq!(small.aux_bytes_per_buffer, Some(16 << 20));

        // Explicit larger than the budget is still rejected.
        let mut bad = IntelPtConfig {
            aux_bytes_per_buffer: Some(256 << 20),
            max_total_aux_bytes: 128 << 20,
            ..IntelPtConfig::default()
        };
        assert_eq!(
            bad.fit_aux_per_thread(4096, 16).unwrap_err().code,
            ErrorCode::UnsupportedPtConfig
        );
    }
}
