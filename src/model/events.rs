use serde::{Deserialize, Serialize};

use super::ids::{LocalId, ThreadId};
use super::json::{AbsTime, Address, Count};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeQuality {
    DecoderEstimate,
    MarkerClock,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTime {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_ns: Option<u64>,
    /// Omitted in JSON when it is the default `decoder_estimate`.
    #[serde(
        default = "TimeQuality::default_for_json",
        skip_serializing_if = "TimeQuality::is_estimate"
    )]
    pub quality: TimeQuality,
}

impl TimeQuality {
    fn default_for_json() -> Self {
        Self::DecoderEstimate
    }

    fn is_estimate(&self) -> bool {
        matches!(self, Self::DecoderEstimate)
    }
}

impl EventTime {
    pub fn unknown() -> Self {
        Self {
            relative_ns: None,
            quality: TimeQuality::Unknown,
        }
    }

    pub fn estimate(relative_ns: u64) -> Self {
        Self {
            relative_ns: Some(relative_ns),
            quality: TimeQuality::DecoderEstimate,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
    Call,
    Return,
    Jump,
    Conditional,
    AsyncBoundary,
    TraceBegin,
    TraceEnd,
}

/// Independent boundary bits. Serialized compactly: false fields are omitted
/// and an all-false value is omitted from its parent record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct BoundaryFlags {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trace_begin: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trace_end: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub async_event: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub transaction: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub interrupt: bool,
    /// `syscall` / `sysret` transfer (user-only PT: paired with a trace boundary).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub syscall: bool,
}

impl BoundaryFlags {
    pub fn takes_precedence(self) -> bool {
        self.trace_begin
            || self.trace_end
            || self.async_event
            || self.interrupt
            || self.syscall
            || self.transaction
    }

    pub fn any(self) -> bool {
        self.takes_precedence()
    }

    pub fn is_discontinuity(self) -> bool {
        self.trace_end || self.async_event
    }

    pub fn is_none(&self) -> bool {
        !self.any()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEvent {
    pub id: LocalId,
    pub thread: ThreadId,
    pub sequence: u64,
    pub time: EventTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<LocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<LocalId>,
    pub kind: FlowKind,
    #[serde(default, skip_serializing_if = "BoundaryFlags::is_none")]
    pub boundary: BoundaryFlags,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virt_from: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virt_to: Option<Address>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanCompleteness {
    Complete,
    OpenStart,
    OpenEnd,
    OpenBoth,
    InterruptedByGap,
    UncertainUnwind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRange {
    pub start_id: LocalId,
    pub end_id: LocalId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSpan {
    pub id: LocalId,
    pub thread: ThreadId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<LocalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<LocalId>,
    pub start: EventTime,
    pub end: EventTime,
    pub completeness: SpanCompleteness,
    pub evidence: EventRange,
    /// Virtual address of the call instruction that opened this span, when
    /// it was observed. Resolving it through DWARF names the inlined
    /// function the call was made from (`call_site_inline` in timeline rows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_site: Option<Address>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    RingTruncation,
    UndecodablePrefix,
    PtLoss,
    MissingImage,
    DecoderError,
    TimeRegression,
    /// User tracing paused (syscall, interrupt, preemption) and resumed in the
    /// same function; the call stack was preserved across the gap.
    TraceBoundary,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapRecord {
    pub id: LocalId,
    pub thread: ThreadId,
    pub kind: GapKind,
    pub start: EventTime,
    pub end: EventTime,
    pub extent_known: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchOutcome {
    Taken,
    NotTaken,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionRecord {
    pub id: LocalId,
    pub thread: ThreadId,
    pub sequence: u64,
    pub time: EventTime,
    pub location: Option<LocalId>,
    pub virt_ip: Address,
    /// Demangled symbol containing `virt_ip`, when the image was archived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Innermost DWARF inlined function at `virt_ip` when it differs from
    /// `symbol` (LTO/opt-level=3 inline everything; this is where the
    /// instruction really came from).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inlined: Option<String>,
    /// Image-relative address of `virt_ip` (ELF VM address), when resolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_offset: Option<Address>,
    pub len: u8,
    pub kind: InsnKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_target: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallthrough: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<BranchOutcome>,
    pub bytes_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsnKind {
    Sequential,
    Conditional,
    Jump,
    IndirectJump,
    Call,
    IndirectCall,
    Return,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRecord {
    pub generation: u32,
    pub pid: u32,
    pub start: Address,
    pub end: Address,
    pub pgoff: u64,
    pub prot: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    pub valid_from: EventTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<EventTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadLifetime {
    pub id: ThreadId,
    pub pid: u32,
    pub tid: u32,
    /// First decoded sample on this thread (snapshot-relative).
    pub start: EventTime,
    /// Last decoded sample on this thread.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<EventTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    /// All PT branch samples decoded for this thread.
    #[serde(default)]
    pub branch_count: Count,
    /// Branch samples retained as flow events (function transfers and boundaries).
    #[serde(default)]
    pub event_count: Count,
    #[serde(default)]
    pub span_count: Count,
    #[serde(default)]
    pub gap_count: Count,
    /// Sum of contiguous decoded history for this thread. This, not
    /// `end - start`, is the actual lookback: AUX rings are per CPU and a
    /// migrating thread leaves holes.
    #[serde(default)]
    pub covered_ns: Count,
    #[serde(default)]
    pub segment_count: Count,
    /// Up to 32 `[start_ns, end_ns]` coverage segments (snapshot-relative).
    #[serde(default)]
    pub segments: Vec<[u64; 2]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRecord {
    pub id: LocalId,
    pub name: String,
    pub demangled: String,
    pub image_id: String,
    pub start: Address,
    pub end: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub id: LocalId,
    pub image_id: String,
    pub image_offset: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virt_ip: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<LocalId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inlined: Option<String>,
}

/// Executed straight-line blocks attributed to the DWARF inline chain at
/// the block start. Instruction counts are exact (decoded
/// from the archived bytes); elapsed time is the quantized delta between
/// the branch samples bounding each block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineRow {
    pub thread: ThreadId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<LocalId>,
    /// Innermost first; empty when the block belongs to the symbol's own body.
    pub chain: Vec<String>,
    pub instructions: Count,
    pub blocks: Count,
    pub elapsed_ns: Count,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityReport {
    pub timing: TimeQuality,
    pub gap_count: Count,
    pub incomplete_span_count: Count,
    pub missing_image_count: Count,
    pub decoder_error_count: Count,
    pub ring_truncation: bool,
    pub undecodable_prefix: bool,
    pub notes: Vec<String>,
    /// Gap records per `GapKind` (snake_case), so timer-tick boundaries do
    /// not hide real loss.
    #[serde(default)]
    pub gaps_by_kind: std::collections::BTreeMap<String, Count>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockOrigin {
    pub abs_perf_time: AbsTime,
    pub relative_zero_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetailLevel {
    Calls,
    Instructions,
}
