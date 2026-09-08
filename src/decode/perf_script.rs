//! Parser for the tested `perf script` numeric dialect.
//!
//! Grammar is pinned in `docs/perf-compatibility.md`. Flags may contain spaces;
//! the parser never uses a global `split_whitespace()` on a sample line.
//!
//! The hot path (`branches:u:` / `instructions:u:` sample lines) is parsed by
//! [`fastline`], a zero-allocation byte scanner. Sideband and error lines are
//! rare and go through the tolerant token parser below.

use std::fmt;
use std::io::Read;

use crate::error::{Error, Result};
use crate::model::parse_address;

pub mod fastline;

pub const DIALECT: &str = crate::capture::perf::PERF_DIALECT;

/// Which synthesized event a sample line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SampleEvent {
    Branches,
    Instructions,
    /// Any other event name (kept for quality accounting only).
    Other,
}

impl SampleEvent {
    pub fn is_instruction(self) -> bool {
        matches!(self, Self::Instructions)
    }
}

/// perf's fixed flag vocabulary as a bit set. Rendering order matches perf:
/// `tr strt` / `tr end` prefix, then the branch class.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Flags(pub u16);

impl Flags {
    pub const CALL: Flags = Flags(1 << 0);
    pub const RETURN: Flags = Flags(1 << 1);
    pub const JCC: Flags = Flags(1 << 2);
    pub const JMP: Flags = Flags(1 << 3);
    pub const INT: Flags = Flags(1 << 4);
    pub const IRET: Flags = Flags(1 << 5);
    pub const SYSCALL: Flags = Flags(1 << 6);
    pub const SYSRET: Flags = Flags(1 << 7);
    pub const ASYNC: Flags = Flags(1 << 8);
    pub const HW_INT: Flags = Flags(1 << 9);
    pub const TX_ABORT: Flags = Flags(1 << 10);
    pub const TR_START: Flags = Flags(1 << 11);
    pub const TR_END: Flags = Flags(1 << 12);
    pub const VMENTRY: Flags = Flags(1 << 13);
    pub const VMEXIT: Flags = Flags(1 << 14);
    /// A token perf printed that this parser does not know (raw `bcros...` form).
    pub const UNKNOWN: Flags = Flags(1 << 15);

    pub const EMPTY: Flags = Flags(0);

    #[inline]
    pub const fn has(self, f: Flags) -> bool {
        self.0 & f.0 != 0
    }

    #[inline]
    pub const fn union(self, f: Flags) -> Flags {
        Flags(self.0 | f.0)
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Match one whitespace-separated token. Two-word flags (`tr strt`,
    /// `hw int`, `tx abrt`) are matched through their second word; the first
    /// word is accepted as a no-op so callers can feed tokens in order.
    #[inline]
    pub fn from_token(tok: &[u8]) -> Option<Flags> {
        Some(match tok {
            b"call" => Self::CALL,
            b"return" => Self::RETURN,
            b"jcc" => Self::JCC,
            b"jmp" => Self::JMP,
            b"int" => Self::INT,
            b"iret" => Self::IRET,
            b"syscall" => Self::SYSCALL,
            b"sysret" => Self::SYSRET,
            b"async" => Self::ASYNC,
            b"abrt" => Self::TX_ABORT,
            b"strt" | b"start" => Self::TR_START,
            b"end" => Self::TR_END,
            b"vmentry" => Self::VMENTRY,
            b"vmexit" => Self::VMEXIT,
            b"tr" | b"hw" | b"tx" | b"trace" | b"begin" => Self::EMPTY,
            _ => return None,
        })
    }

    /// perf may print a raw per-bit string such as `bcrosyiABExghDt` when a
    /// combination is not in its name table. Decode the known letters.
    pub fn from_raw_letters(tok: &[u8]) -> Option<Flags> {
        if tok.is_empty() || tok.len() > 16 {
            return None;
        }
        let mut f = Flags::EMPTY;
        for &c in tok {
            f = f.union(match c {
                b'b' => Flags::EMPTY,
                b'c' => Flags::CALL,
                b'r' => Flags::RETURN,
                b'o' => Flags::JCC,
                b's' => Flags::SYSCALL,
                b'y' => Flags::ASYNC,
                b'i' => Flags::INT,
                b'A' => Flags::TX_ABORT,
                b'B' => Flags::TR_START,
                b'E' => Flags::TR_END,
                b'x' | b'g' | b'h' | b'D' | b't' => Flags::UNKNOWN,
                _ => return None,
            });
        }
        Some(f)
    }

    pub fn parse_str(s: &str) -> Flags {
        let mut f = Flags::EMPTY;
        let mut saw_hw = false;
        for tok in s.split_whitespace() {
            match Flags::from_token(tok.as_bytes()) {
                Some(Flags::INT) if saw_hw => f = f.union(Flags::HW_INT),
                Some(x) => f = f.union(x),
                None => {
                    f = f.union(Flags::from_raw_letters(tok.as_bytes()).unwrap_or(Flags::UNKNOWN))
                }
            }
            saw_hw = tok == "hw";
        }
        f
    }

    fn names(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.has(Self::TR_START) {
            out.push("tr strt");
        }
        if self.has(Self::TR_END) {
            out.push("tr end");
        }
        for (bit, name) in [
            (Self::HW_INT, "hw int"),
            (Self::CALL, "call"),
            (Self::RETURN, "return"),
            (Self::JCC, "jcc"),
            (Self::JMP, "jmp"),
            (Self::INT, "int"),
            (Self::IRET, "iret"),
            (Self::SYSCALL, "syscall"),
            (Self::SYSRET, "sysret"),
            (Self::ASYNC, "async"),
            (Self::TX_ABORT, "tx abrt"),
            (Self::VMENTRY, "vmentry"),
            (Self::VMEXIT, "vmexit"),
            (Self::UNKNOWN, "?"),
        ] {
            if self.has(bit) {
                out.push(name);
            }
        }
        out
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.names().join(" "))
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flags({})", self)
    }
}

/// Raw instruction bytes from `insn:`; at most 15 bytes on x86.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct InsnBytes {
    pub len: u8,
    pub bytes: [u8; 15],
}

impl InsnBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len).min(15)]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn hex(&self) -> String {
        self.as_slice()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl fmt::Debug for InsnBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InsnBytes({})", self.hex())
    }
}

/// One synthesized PT sample. `Copy` and allocation-free so millions of them
/// can stream through reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub pid: u32,
    pub tid: u32,
    pub cpu: Option<u32>,
    pub time_ns: Option<u64>,
    pub event: SampleEvent,
    pub ip: Option<u64>,
    pub addr: Option<u64>,
    pub flags: Flags,
    pub insn_len: Option<u8>,
    pub insn: InsnBytes,
}

impl Sample {
    pub fn insn_hex(&self) -> Option<String> {
        (!self.insn.is_empty()).then(|| self.insn.hex())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmapEvent {
    pub pid: u32,
    pub tid: u32,
    pub time_ns: Option<u64>,
    pub start: u64,
    pub len: u64,
    pub pgoff: u64,
    pub prot: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskEvent {
    pub kind: TaskKind,
    pub pid: u32,
    pub tid: u32,
    pub ppid: Option<u32>,
    pub ptid: Option<u32>,
    pub time_ns: Option<u64>,
    pub comm: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    Comm,
    Exec,
    Fork,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LostEvent {
    pub time_ns: Option<u64>,
    pub cpu: Option<u32>,
    pub lost: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderErrorEvent {
    pub time_ns: Option<u64>,
    pub cpu: Option<u32>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub ip: Option<u64>,
    /// perf `code N` when present (5 = failed to get instruction, 6 = trace mismatch).
    pub code: Option<u32>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawRecord {
    Sample(Sample),
    Mmap(MmapEvent),
    Task(TaskEvent),
    Switch {
        pid: u32,
        tid: u32,
        time_ns: Option<u64>,
        out: bool,
    },
    Lost(LostEvent),
    DecoderError(DecoderErrorEvent),
}

/// Tracks which pids belong to the traced target: the exec'd workload
/// (`PERF_RECORD_COMM: perf-exec:PID`) or an attached pid, plus every FORK
/// descendant. Sideband precedes samples in `perf script` output, so the set
/// is complete by the time a task's samples arrive.
#[derive(Debug, Default, Clone)]
pub struct PidTracker {
    pids: crate::decode::reconstruct::FastSet<u32>,
    /// Basename (first 15 bytes, as the kernel stores comm) of the launched
    /// executable. Until a root pid has exec'd it, that pid still runs the
    /// recorder's or the pin shim's image; such samples and mappings are
    /// pre-exec and excluded.
    target_comm: Option<String>,
    exec_done: crate::decode::reconstruct::FastSet<u32>,
    /// Absolute time of the target exec per pid, when known.
    exec_time: crate::decode::reconstruct::FastMap<u32, u64>,
    /// Threads created under a root pid before it exec'd the target (the
    /// launch shim's runtime threads). They die at exec; their samples can
    /// straddle the exec record because PT and sideband clocks differ by
    /// microseconds, so they are excluded by identity rather than by time.
    pre_exec_threads: crate::decode::reconstruct::FastSet<(u32, u32)>,
}

impl PidTracker {
    pub fn with_root(pid: u32) -> Self {
        let mut t = Self::default();
        t.pids.insert(pid);
        t.exec_done.insert(pid);
        t
    }

    /// Launch mode: samples of a root pid count only after it exec'd `exe`.
    pub fn expecting_exec_of(mut self, exe_path: &str) -> Self {
        let base = std::path::Path::new(exe_path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.target_comm = Some(base.chars().take(15).collect());
        self
    }

    pub fn observe(&mut self, rec: &RawRecord) {
        if let RawRecord::Task(t) = rec {
            match t.kind {
                TaskKind::Comm | TaskKind::Exec if t.comm.as_deref() == Some("perf-exec") => {
                    self.pids.insert(t.pid);
                    if self.target_comm.is_none() {
                        self.exec_done.insert(t.pid);
                    }
                }
                TaskKind::Comm | TaskKind::Exec
                    if self.pids.contains(&t.pid)
                        && self
                            .target_comm
                            .as_deref()
                            .is_some_and(|c| t.comm.as_deref() == Some(c)) =>
                {
                    self.exec_done.insert(t.pid);
                    if let Some(ts) = t.time_ns {
                        self.exec_time.insert(t.pid, ts);
                    }
                }
                TaskKind::Fork if t.ppid.is_some_and(|pp| self.pids.contains(&pp)) => {
                    let is_thread = t.ppid == Some(t.pid) && t.tid != t.pid;
                    if is_thread {
                        if self.target_comm.is_some() && !self.exec_done.contains(&t.pid) {
                            self.pre_exec_threads.insert((t.pid, t.tid));
                        }
                    } else {
                        self.pids.insert(t.pid);
                        if t.ppid.is_some_and(|pp| self.exec_done.contains(&pp)) {
                            self.exec_done.insert(t.pid);
                        }
                    }
                }
                TaskKind::Exit => {
                    self.pre_exec_threads.remove(&(t.pid, t.tid));
                }
                _ => {}
            }
        }
    }

    /// True when `pid` is in the tree and (in launch mode) has already
    /// exec'd the target.
    pub fn is_live(&self, pid: u32) -> bool {
        self.pids.contains(&pid) && (self.target_comm.is_none() || self.exec_done.contains(&pid))
    }

    /// `is_live` for a specific thread: also rejects threads the root pid
    /// created before exec (they never run the target's code).
    pub fn is_live_thread(&self, pid: u32, tid: u32) -> bool {
        self.is_live(pid) && !self.pre_exec_threads.contains(&(pid, tid))
    }

    /// A mapping is evidence only if established at or after the target exec
    /// (synthesized pre-exec mappings describe the recorder's image).
    pub fn mapping_is_live(&self, m: &MmapEvent) -> bool {
        if !self.pids.contains(&m.pid) {
            return false;
        }
        if self.target_comm.is_none() {
            return true;
        }
        match (self.exec_time.get(&m.pid), m.time_ns) {
            (Some(&ex), Some(t)) => t >= ex,
            (Some(_), None) => false,
            (None, _) => self.exec_done.contains(&m.pid),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pids.is_empty()
    }

    pub fn contains(&self, pid: u32) -> bool {
        self.pids.contains(&pid)
    }

    pub fn pids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.pids.iter().copied().collect();
        v.sort_unstable();
        v
    }
}

/// Parse `seconds.frac` with integer math. `--ns` uses 9 fractional digits.
pub fn parse_perf_time(token: &str) -> Result<u64> {
    let token = token.trim().trim_end_matches(':');
    let (sec_s, frac_s) = token.split_once('.').unwrap_or((token, "0"));
    let sec: u64 = sec_s
        .parse()
        .map_err(|_| Error::decode_failed(format!("bad time seconds {token}")))?;
    let mut frac = frac_s.as_bytes().to_vec();
    if frac.len() > 9 {
        frac.truncate(9);
    }
    while frac.len() < 9 {
        frac.push(b'0');
    }
    let nsec: u64 = std::str::from_utf8(&frac)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::decode_failed(format!("bad time fraction {token}")))?;
    sec.checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nsec))
        .ok_or_else(|| Error::decode_failed(format!("time overflow {token}")))
}

/// Parse one line. Sample lines take the fast path; anything else falls back
/// to the tolerant parser.
pub fn parse_line(line: &str) -> Result<Option<RawRecord>> {
    let line = line.trim_end();
    if line.is_empty() || line.starts_with('#') || line.starts_with("failed to read") {
        return Ok(None);
    }
    if let Some(s) = fastline::parse_sample(line.as_bytes()) {
        return Ok(Some(RawRecord::Sample(s)));
    }
    parse_line_slow(line)
}

/// Tolerant parser for sideband, errors, and synthetic test dialects.
pub fn parse_line_slow(line: &str) -> Result<Option<RawRecord>> {
    if line.contains("instruction trace error") || line.contains("insn trace error") {
        return Ok(Some(RawRecord::DecoderError(parse_decoder_error(line))));
    }
    if line.contains("PERF_RECORD_LOST") || line.contains(" lost ") && line.contains("LOST") {
        return Ok(Some(RawRecord::Lost(parse_lost(line)?)));
    }
    if line.contains("PERF_RECORD_MMAP") {
        return Ok(Some(RawRecord::Mmap(parse_mmap(line)?)));
    }
    if line.contains("PERF_RECORD_COMM") || line.contains(" PERF_RECORD_EXEC") {
        return Ok(Some(RawRecord::Task(parse_task(line, TaskKind::Comm)?)));
    }
    if line.contains("PERF_RECORD_FORK") {
        return Ok(Some(RawRecord::Task(parse_task(line, TaskKind::Fork)?)));
    }
    if line.contains("PERF_RECORD_EXIT") {
        return Ok(Some(RawRecord::Task(parse_task(line, TaskKind::Exit)?)));
    }
    if line.contains("PERF_RECORD_SWITCH") {
        return Ok(Some(parse_switch(line)?));
    }
    parse_sample_line(line)
}

/// Collect every record. Test/fixture convenience; production paths stream.
pub fn parse_reader<R: Read>(reader: R) -> Result<Vec<RawRecord>> {
    let mut out = Vec::new();
    let mut st = StreamStats::default();
    stream_records(reader, &mut st, |rec| {
        out.push(rec);
        Ok(())
    })?;
    Ok(out)
}

/// Streaming statistics for one `perf script` pass.
#[derive(Debug, Default, Clone)]
pub struct StreamStats {
    pub lines: u64,
    pub bytes: u64,
    pub samples: u64,
    pub unparsed: u64,
    /// Decode streams used (native path: CPU streams).
    pub streams: u32,
}

/// Stream `perf script` output line by line without holding the text.
/// Each parsed record is handed to `sink`. Lines that fail to parse are
/// reported to the sink as [`RawRecord::DecoderError`] so loss is explicit.
pub fn stream_records<R: Read>(
    mut reader: R,
    stats: &mut StreamStats,
    mut sink: impl FnMut(RawRecord) -> Result<()>,
) -> Result<()> {
    const CHUNK: usize = 4 << 20;
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK + fastline::GUARD);
    buf.resize(CHUNK, 0);
    let mut filled = 0usize;
    loop {
        if filled == buf.len() {
            // A single line longer than the buffer: grow.
            buf.resize(buf.len() * 2, 0);
        }
        let n = reader
            .read(&mut buf[filled..])
            .map_err(|e| Error::decode_failed(format!("read perf script: {e}")))?;
        if n == 0 {
            if filled > 0 {
                let line_end = filled;
                stats.bytes += line_end as u64;
                let mut tail = std::mem::take(&mut buf);
                tail.truncate(line_end);
                tail.resize(line_end + fastline::GUARD, 0);
                consume_line(&tail[..line_end], stats, &mut sink)?;
            }
            return Ok(());
        }
        filled += n;
        let Some(last_nl) = buf[..filled].iter().rposition(|&b| b == b'\n') else {
            continue;
        };
        let data_end = last_nl + 1;
        // Guarantee GUARD readable bytes after every line handed out.
        if buf.len() < filled + fastline::GUARD {
            buf.resize(filled + fastline::GUARD, 0);
        }
        let mut start = 0usize;
        while start < data_end {
            let end = start + memchr_nl(&buf[start..data_end]);
            stats.bytes += (end - start + 1) as u64;
            consume_line(&buf[start..end], stats, &mut sink)?;
            start = end + 1;
        }
        buf.copy_within(data_end..filled, 0);
        filled -= data_end;
        if buf.len() > CHUNK * 4 && filled < CHUNK {
            buf.truncate(CHUNK);
        }
        if buf.len() < CHUNK {
            buf.resize(CHUNK, 0);
        }
    }
}

#[inline]
fn memchr_nl(hay: &[u8]) -> usize {
    hay.iter().position(|&b| b == b'\n').unwrap_or(hay.len())
}

/// `line` must be followed by at least [`fastline::GUARD`] readable bytes.
#[inline]
fn consume_line(
    line: &[u8],
    stats: &mut StreamStats,
    sink: &mut impl FnMut(RawRecord) -> Result<()>,
) -> Result<()> {
    stats.lines += 1;
    let line = trim_end_bytes(line);
    if line.is_empty() || line[0] == b'#' {
        return Ok(());
    }
    // SAFETY: caller guarantees GUARD bytes of readable memory past `line`.
    if let Some(s) = unsafe { fastline::parse_sample_guarded(line) } {
        stats.samples += 1;
        return sink(RawRecord::Sample(s));
    }
    let text = String::from_utf8_lossy(line);
    match parse_line_slow(&text) {
        Ok(Some(RawRecord::Sample(s))) => {
            stats.samples += 1;
            sink(RawRecord::Sample(s))
        }
        Ok(Some(rec)) => sink(rec),
        Ok(None) => Ok(()),
        Err(err) => {
            stats.unparsed += 1;
            let (pid, tid) = split_pid_tid(&text)
                .map(|(p, t, _)| (Some(p), Some(t)))
                .unwrap_or((None, None));
            sink(RawRecord::DecoderError(DecoderErrorEvent {
                time_ns: None,
                cpu: None,
                pid,
                tid,
                ip: None,
                code: None,
                message: format!("line {}: {err}: {text}", stats.lines),
            }))
        }
    }
}

fn trim_end_bytes(mut s: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = s.split_last() {
        if last == b'\n' || last == b'\r' || last == b' ' || last == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn parse_sample_line(line: &str) -> Result<Option<RawRecord>> {
    let (pid, tid, rest) = split_pid_tid(line)
        .ok_or_else(|| Error::decode_failed(format!("missing pid/tid: {line}")))?;
    let (cpu, rest) = take_cpu(rest);
    let (time_ns, rest) = take_time(rest)?;
    let rest = rest.trim_start();
    let Some((event, after_event)) = split_event(rest) else {
        return Err(Error::decode_failed(format!("missing event: {line}")));
    };
    let event_name = event.trim_end_matches(':');
    let after = strip_event_modifiers(after_event);

    if event_name.contains("mmap") || event_name.starts_with("PERF_RECORD_MMAP") {
        return Ok(Some(RawRecord::Mmap(parse_mmap(line)?)));
    }
    let event = if event_name.starts_with("branches") {
        SampleEvent::Branches
    } else if event_name.starts_with("instructions") {
        SampleEvent::Instructions
    } else {
        SampleEvent::Other
    };

    let (payload, insn, insn_len) = split_insn_suffix(after);
    let (ip, addr, flags) = parse_ip_addr_flags(payload, event);

    Ok(Some(RawRecord::Sample(Sample {
        pid,
        tid,
        cpu,
        time_ns: nonzero_time(time_ns),
        event,
        ip,
        addr,
        flags,
        insn_len,
        insn,
    })))
}

/// Perf 6.12 Intel PT script prints flags before addresses, and branch
/// transfers as `ip => addr`. Instruction samples print `addr ip` without `=>`.
/// Synthetic tests may still use `ip addr flags` with flags last.
fn parse_ip_addr_flags(payload: &str, event: SampleEvent) -> (Option<u64>, Option<u64>, Flags) {
    let payload = payload.trim();
    if payload.is_empty() {
        return (None, None, Flags::EMPTY);
    }
    if let Some((left, right)) = payload.split_once("=>") {
        let left_toks: Vec<&str> = left.split_whitespace().collect();
        let ip = left_toks
            .iter()
            .rev()
            .find(|t| is_hex_token(t))
            .and_then(|t| parse_address(t).ok());
        let flags = left_toks
            .iter()
            .copied()
            .filter(|t| !is_hex_token(t))
            .collect::<Vec<_>>()
            .join(" ");
        let addr = right
            .split_whitespace()
            .next()
            .and_then(|t| parse_address(t).ok());
        return (ip, addr, Flags::parse_str(&flags));
    }

    let toks: Vec<&str> = payload.split_whitespace().collect();
    let mut hexes = Vec::new();
    let mut flag_parts = Vec::new();
    for t in &toks {
        if is_hex_token(t) {
            hexes.push(parse_address(t).ok().unwrap());
        } else {
            flag_parts.push(*t);
        }
    }
    let flags = Flags::parse_str(&flag_parts.join(" "));
    match (event.is_instruction(), hexes.as_slice()) {
        (true, [addr, ip, ..]) => (Some(*ip), Some(*addr), flags),
        (_, [ip, addr, ..]) => (Some(*ip), Some(*addr), flags),
        (_, [ip]) => (Some(*ip), None, flags),
        _ => (None, None, flags),
    }
}

fn is_hex_token(t: &str) -> bool {
    parse_address(t).is_ok()
}

fn nonzero_time(t: Option<u64>) -> Option<u64> {
    t.filter(|&ns| ns != 0)
}

fn split_insn_suffix(s: &str) -> (&str, InsnBytes, Option<u8>) {
    let idx = ["insn:", "ilen:", "insnlen:"]
        .iter()
        .filter_map(|k| s.find(k))
        .min();
    let Some(idx) = idx else {
        return (s.trim_end(), InsnBytes::default(), None);
    };
    let mut bytes = InsnBytes::default();
    let mut len = None;
    parse_insn_fields(s[idx..].trim_start(), &mut bytes, &mut len);
    (s[..idx].trim_end(), bytes, len)
}

fn parse_insn_fields(s: &str, insn: &mut InsnBytes, len: &mut Option<u8>) {
    if let Some(idx) = s.find("insn:") {
        let mut rest = s[idx + "insn:".len()..].trim_start();
        loop {
            let t = rest.split_whitespace().next().unwrap_or("");
            if t.is_empty() || t.ends_with(':') || t == "ilen" || t == "insnlen" {
                break;
            }
            if t.len() == 2
                && let Ok(v) = u8::from_str_radix(t, 16)
                && usize::from(insn.len) < 15
            {
                insn.bytes[usize::from(insn.len)] = v;
                insn.len += 1;
                rest = rest[t.len()..].trim_start();
            } else {
                break;
            }
        }
    }
    for key in ["ilen:", "insnlen:", "ilen", "insnlen"] {
        if let Some(idx) = s.find(key) {
            let after = s[idx + key.len()..].trim_start().trim_start_matches(':');
            if let Some(n) = after.split_whitespace().next().and_then(|t| t.parse().ok()) {
                *len = Some(n);
            }
        }
    }
}

pub(crate) fn split_pid_tid(line: &str) -> Option<(u32, u32, &str)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'/' {
                let pid: u32 = line[start..i].parse().ok()?;
                i += 1;
                let tstart = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i > tstart {
                    let tid: u32 = line[tstart..i].parse().ok()?;
                    return Some((pid, tid, &line[i..]));
                }
            }
        }
        i += 1;
    }
    None
}

fn take_cpu(s: &str) -> (Option<u32>, &str) {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let cpu = rest[..end].trim().parse().ok();
        return (cpu, rest[end + 1..].trim_start());
    }
    (None, s)
}

fn take_time(s: &str) -> Result<(Option<u64>, &str)> {
    let s = s.trim_start();
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    let tok = &s[..end];
    if tok.chars().next().is_some_and(|c| c.is_ascii_digit()) && tok.contains('.') {
        let ns = parse_perf_time(tok)?;
        Ok((
            Some(ns),
            s[end..].trim_start().trim_start_matches(':').trim_start(),
        ))
    } else {
        Ok((None, s))
    }
}

fn split_event(s: &str) -> Option<(&str, &str)> {
    let colon = s.find(':')?;
    Some((s[..colon].trim(), s[colon + 1..].trim_start()))
}

fn strip_event_modifiers(s: &str) -> &str {
    let s = s.trim_start();
    if let Some(colon) = s.find(':') {
        let prefix = &s[..colon];
        if !prefix.is_empty()
            && prefix.len() <= 8
            && prefix.chars().all(|c| c.is_ascii_alphabetic())
        {
            return s[colon + 1..].trim_start();
        }
    }
    s
}

fn parse_mmap(line: &str) -> Result<MmapEvent> {
    let (pid, tid, rest) = split_pid_tid(line).unwrap_or((0, 0, line));
    let (_, rest) = take_cpu(rest);
    let (time_ns, _) = take_time(rest).unwrap_or((None, rest));
    // Synthesized mappings print as `0/0 0.000000: PERF_RECORD_MMAP2 PID/TID: [...]`;
    // the owning task is the pid/tid after the record name, not the prefix.
    let (pid, tid) = line
        .split("PERF_RECORD_MMAP")
        .nth(1)
        .and_then(|after| split_pid_tid(after.trim_start_matches('2')))
        .map(|(p, t, _)| (p, t))
        .unwrap_or((pid, tid));
    let (start, len, pgoff) = parse_mmap_range(line)
        .ok_or_else(|| Error::decode_failed(format!("mmap range missing: {line}")))?;
    let (prot, path) = mmap_prot_path(line);
    Ok(MmapEvent {
        pid,
        tid,
        time_ns: nonzero_time(time_ns),
        start,
        len,
        pgoff,
        prot,
        path,
    })
}

fn mmap_prot_path(line: &str) -> (String, String) {
    if let Some((_, after)) = line.rsplit_once("]:") {
        let mut parts = after.split_whitespace();
        let prot = parts.next().unwrap_or("").to_string();
        let path = parts.collect::<Vec<_>>().join(" ");
        return (prot, path);
    }
    (
        String::new(),
        line.split_whitespace().last().unwrap_or("").to_string(),
    )
}

fn parse_mmap_range(line: &str) -> Option<(u64, u64, u64)> {
    // CPU is `[000]`; the mapping uses `[0xSTART(LEN) @ PGOFF ...]`.
    let lb = line.find("[0x")?;
    let inner_end = line[lb + 1..].find(']')?;
    let inner = &line[lb + 1..lb + 1 + inner_end];
    let start_s = inner.split('(').next()?.trim();
    let len_s = inner.split('(').nth(1)?.split(')').next()?.trim();
    let pgoff_s = inner
        .split('@')
        .nth(1)
        .unwrap_or("0")
        .split_whitespace()
        .next()
        .unwrap_or("0");
    Some((
        parse_address(start_s).ok()?,
        parse_address(len_s).ok()?,
        parse_address(pgoff_s).ok()?,
    ))
}

fn parse_task(line: &str, kind: TaskKind) -> Result<TaskEvent> {
    let (pid, tid, rest) =
        split_pid_tid(line).ok_or_else(|| Error::decode_failed(line.to_string()))?;
    let (_, rest) = take_cpu(rest);
    let (time_ns, _) = take_time(rest)?;
    let comm = line.split("PERF_RECORD_COMM").nth(1).and_then(|s| {
        let s = s
            .trim()
            .trim_start_matches("exec:")
            .trim_start_matches(':')
            .trim();
        let name = s.split(':').next()?.trim();
        (!name.is_empty()).then(|| name.to_string())
    });
    // `PERF_RECORD_COMM exec: name:PID/TID` names the task whose comm changed,
    // which is the pid/tid at the end of the line, not the line prefix.
    // `PERF_RECORD_FORK(CHILD:CTID):(PARENT:PTID)` likewise.
    let mut ppid = None;
    let mut ptid = None;
    let (pid, tid) = if let Some(after) = line.split("PERF_RECORD_").nth(1) {
        if matches!(kind, TaskKind::Fork | TaskKind::Exit)
            && let Some(open) = after.find('(')
            && let Some(close) = after[open..].find(')')
            && let Some((c, ct)) = after[open + 1..open + close].split_once(':')
            && let (Ok(c), Ok(ct)) = (c.trim().parse::<u32>(), ct.trim().parse::<u32>())
        {
            if let Some(rest) = after[open + close + 1..].strip_prefix(":(")
                && let Some(end) = rest.find(')')
                && let Some((p, pt)) = rest[..end].split_once(':')
            {
                ppid = p.trim().parse().ok();
                ptid = pt.trim().parse().ok();
            }
            (c, ct)
        } else if let Some((p, t, _)) = split_pid_tid(after) {
            (p, t)
        } else {
            (pid, tid)
        }
    } else {
        (pid, tid)
    };
    Ok(TaskEvent {
        kind,
        pid,
        tid,
        ppid,
        ptid,
        time_ns: nonzero_time(time_ns),
        comm,
    })
}

fn parse_switch(line: &str) -> Result<RawRecord> {
    let (pid, tid, rest) =
        split_pid_tid(line).ok_or_else(|| Error::decode_failed(line.to_string()))?;
    let (_, rest) = take_cpu(rest);
    let (time_ns, _) = take_time(rest)?;
    Ok(RawRecord::Switch {
        pid,
        tid,
        time_ns: nonzero_time(time_ns),
        out: line.contains("SWITCH_CPU_WIDE OUT") || line.contains(" out "),
    })
}

fn parse_lost(line: &str) -> Result<LostEvent> {
    let lost = line
        .split_whitespace()
        .find_map(|t| t.parse::<u64>().ok())
        .unwrap_or(0);
    Ok(LostEvent {
        time_ns: None,
        cpu: None,
        lost,
    })
}

/// perf prints
/// ` instruction trace error type 1 time 519322.048962186 cpu 54 pid 1620630 tid 1620631 ip 0x7f82230080c0 code 5: Failed to get instruction`.
fn parse_decoder_error(line: &str) -> DecoderErrorEvent {
    let mut ev = DecoderErrorEvent {
        time_ns: None,
        cpu: None,
        pid: None,
        tid: None,
        ip: None,
        code: None,
        message: line.trim().to_string(),
    };
    let toks: Vec<&str> = line.split_whitespace().collect();
    let mut i = 0;
    while i + 1 < toks.len() {
        match toks[i] {
            "time" => ev.time_ns = parse_perf_time(toks[i + 1]).ok().filter(|&t| t != 0),
            "cpu" => ev.cpu = toks[i + 1].parse().ok(),
            "pid" => ev.pid = toks[i + 1].parse().ok(),
            "tid" => ev.tid = toks[i + 1].parse().ok(),
            "ip" => ev.ip = parse_address(toks[i + 1]).ok(),
            "code" => ev.code = toks[i + 1].trim_end_matches(':').parse().ok(),
            _ => {}
        }
        i += 1;
    }
    if ev.pid.is_none()
        && let Some((p, t, _)) = split_pid_tid(line)
    {
        ev.pid = Some(p);
        ev.tid = Some(t);
    }
    ev
}

pub fn flags_boundary(flags: Flags) -> crate::model::BoundaryFlags {
    crate::model::BoundaryFlags {
        trace_begin: flags.has(Flags::TR_START),
        trace_end: flags.has(Flags::TR_END),
        async_event: flags.has(Flags::ASYNC) || flags.has(Flags::HW_INT),
        transaction: flags.has(Flags::TX_ABORT),
        interrupt: flags.has(Flags::INT) || flags.has(Flags::IRET) || flags.has(Flags::HW_INT),
        syscall: flags.has(Flags::SYSCALL) || flags.has(Flags::SYSRET),
    }
}

pub fn flags_kind(flags: Flags) -> crate::model::FlowKind {
    use crate::model::FlowKind;
    if flags.has(Flags::TR_START) {
        return FlowKind::TraceBegin;
    }
    if flags.has(Flags::TR_END) {
        return FlowKind::TraceEnd;
    }
    if flags.has(Flags::ASYNC)
        || flags.has(Flags::HW_INT)
        || flags.has(Flags::INT)
        || flags.has(Flags::IRET)
        || flags.has(Flags::SYSCALL)
        || flags.has(Flags::SYSRET)
        || flags.has(Flags::TX_ABORT)
        || flags.has(Flags::VMENTRY)
        || flags.has(Flags::VMEXIT)
    {
        return FlowKind::AsyncBoundary;
    }
    if flags.has(Flags::CALL) {
        FlowKind::Call
    } else if flags.has(Flags::RETURN) {
        FlowKind::Return
    } else if flags.has(Flags::JCC) {
        FlowKind::Conditional
    } else {
        FlowKind::Jump
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_integer_arithmetic() {
        assert_eq!(parse_perf_time("1.000000001").unwrap(), 1_000_000_001);
        assert_eq!(parse_perf_time("0.5").unwrap(), 500_000_000);
        assert_eq!(parse_perf_time("12.123456789:").unwrap(), 12_123_456_789);
    }

    #[test]
    fn sample_with_multiword_flags() {
        let line =
            "1234/1234 [001] 10.000000001:  branches:uH:      401000      401200  call tr strt";
        let RawRecord::Sample(s) = parse_line(line).unwrap().unwrap() else {
            panic!("expected sample");
        };
        assert_eq!(s.pid, 1234);
        assert_eq!(s.ip, Some(0x401000));
        assert_eq!(s.addr, Some(0x401200));
        assert_eq!(s.flags.to_string(), "tr strt call");
        assert_eq!(flags_kind(s.flags), crate::model::FlowKind::TraceBegin);
        assert!(flags_boundary(s.flags).trace_begin);
    }

    #[test]
    fn real_branch_flags_then_arrow() {
        let line = "1518114/1518114 [062] 513961.572230317:  branches:u:   call                       7f5459d6c443 =>     7f5459d6d140";
        let RawRecord::Sample(s) = parse_line(line).unwrap().unwrap() else {
            panic!("expected sample");
        };
        assert_eq!(s.ip, Some(0x7f5459d6c443));
        assert_eq!(s.addr, Some(0x7f5459d6d140));
        assert_eq!(s.flags, Flags::CALL);
        assert_eq!(s.cpu, Some(62));
        assert_eq!(s.time_ns, Some(513961_572230317));
        assert_eq!(flags_kind(s.flags), crate::model::FlowKind::Call);
    }

    #[test]
    fn real_trace_start_and_mmap2() {
        let start = "1518114/1518114 [062] 513961.572226468:  branches:u:   tr strt jmp                           0 =>     7f5459d6c440";
        let RawRecord::Sample(s) = parse_line(start).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(s.ip, Some(0));
        assert_eq!(s.addr, Some(0x7f5459d6c440));
        assert!(flags_boundary(s.flags).trace_begin);
        assert!(s.flags.has(Flags::JMP));

        let mmap = "1518114/1518114 [062] 513961.572140369: PERF_RECORD_MMAP2 1518114/1518114: [0x55d5329f8000(0x43000) @ 0x16000 <818137d5a9e8f63162a02db27e7cfd9855cd726d>]: r-xp /tmp/pt_fixture";
        let RawRecord::Mmap(m) = parse_line(mmap).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(m.start, 0x55d5329f8000);
        assert_eq!(m.len, 0x43000);
        assert_eq!(m.pgoff, 0x16000);
        assert_eq!(m.prot, "r-xp");
        assert_eq!(m.path, "/tmp/pt_fixture");
    }

    #[test]
    fn real_instruction_addr_then_ip() {
        let line = "1518114/1518114 [062] 513961.572230317:  instructions:u:   call                      7f5459d6d140     7f5459d6c443 ilen: 5 insn: e8 f8 0c 00 00";
        let RawRecord::Sample(s) = parse_line(line).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(s.ip, Some(0x7f5459d6c443));
        assert_eq!(s.addr, Some(0x7f5459d6d140));
        assert_eq!(s.insn_len, Some(5));
        assert_eq!(s.insn_hex().as_deref(), Some("e8 f8 0c 00 00"));
        assert!(s.event.is_instruction());
    }

    #[test]
    fn real_sequential_instruction_zero_addr() {
        let line = "1518114/1518114 [062] 513961.572230317:  instructions:u:                                        0     7f5459d6c440 ilen: 3 insn: 48 89 e7";
        let RawRecord::Sample(s) = parse_line(line).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(s.ip, Some(0x7f5459d6c440));
        assert_eq!(s.addr, Some(0));
        assert_eq!(s.insn_len, Some(3));
        assert_eq!(s.insn_hex().as_deref(), Some("48 89 e7"));
        assert!(s.flags.is_empty());
    }

    #[test]
    fn truncated_line_is_error() {
        assert!(parse_line("this is not a perf line").is_err());
    }

    #[test]
    fn insn_fields() {
        let line = "1/1 [000] 1.0:  instructions:u:  401000 401000  insn: 48 89 c3 ilen: 3";
        let RawRecord::Sample(s) = parse_line(line).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(s.insn_len, Some(3));
        assert_eq!(s.insn_hex().as_deref(), Some("48 89 c3"));
    }

    #[test]
    fn decoder_error_carries_thread_time_and_code() {
        let line = " instruction trace error type 1 time 519322.048962186 cpu 54 pid 1620630 tid 1620631 ip 0x7f82230080c0 code 5: Failed to get instruction";
        let RawRecord::DecoderError(e) = parse_line(line).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(e.pid, Some(1620630));
        assert_eq!(e.tid, Some(1620631));
        assert_eq!(e.cpu, Some(54));
        assert_eq!(e.code, Some(5));
        assert_eq!(e.ip, Some(0x7f82230080c0));
        assert_eq!(e.time_ns, Some(519322_048962186));
    }

    #[test]
    fn comm_exec_names_the_target_task() {
        let line = "0/0 [000] 0.000000000: PERF_RECORD_COMM: perf-exec:1620630/1620630";
        let RawRecord::Task(t) = parse_line(line).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(t.pid, 1620630);
        assert_eq!(t.comm.as_deref(), Some("perf-exec"));
        let line = "1620630/1620631 519322.048893: PERF_RECORD_COMM: rh-feed-io:1620630/1620631";
        let RawRecord::Task(t) = parse_line(line).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(t.tid, 1620631);
        assert_eq!(t.comm.as_deref(), Some("rh-feed-io"));
    }

    #[test]
    fn synthesized_mmap_uses_record_pid() {
        let line = "      0/0           0.000000: PERF_RECORD_MMAP2 1628569/1628569: [0x55df1ee10000(0x9a53000) @ 0x3006000 <ce01977e9f17c5e8323104ea77396ae310b404ad>]: r-xp /usr/share/cursor/cursor";
        let RawRecord::Mmap(m) = parse_line(line).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!((m.pid, m.tid), (1628569, 1628569));
        assert_eq!(m.start, 0x55df1ee10000);
        assert_eq!(m.pgoff, 0x3006000);
        assert_eq!(m.time_ns, None);
    }

    #[test]
    fn pre_exec_threads_of_the_shim_are_not_live() {
        let mut t = PidTracker::default().expecting_exec_of("/x/pt_fixture");
        let lines = [
            "0/0 [000] 0.000000000: PERF_RECORD_COMM: perf-exec:10/10",
            "10/10 [000] 1.0: PERF_RECORD_COMM exec: trace-mcp:10/10",
            "10/10 [000] 1.1: PERF_RECORD_FORK(10:11):(10:10)",
            "10/11 [000] 1.2: PERF_RECORD_COMM: tokio-rt-worker:10/11",
            "10/10 [000] 2.0: PERF_RECORD_COMM exec: pt_fixture:10/10",
            "10/10 [000] 2.1: PERF_RECORD_FORK(10:12):(10:10)",
        ];
        for l in lines {
            t.observe(&parse_line(l).unwrap().unwrap());
        }
        assert!(t.is_live_thread(10, 10));
        assert!(!t.is_live_thread(10, 11), "shim runtime thread");
        assert!(t.is_live_thread(10, 12), "thread created after exec");
    }

    #[test]
    fn fork_records_carry_parent() {
        let line = "1620630/1620630 [019] 519322.048842562: PERF_RECORD_FORK(1620630:1620631):(1620630:1620630)";
        let RawRecord::Task(t) = parse_line(line).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(t.kind, TaskKind::Fork);
        assert_eq!((t.pid, t.tid), (1620630, 1620631));
        assert_eq!((t.ppid, t.ptid), (Some(1620630), Some(1620630)));
        let line = "1620630/1620632 [021] 519332.160066: PERF_RECORD_EXIT(1620630:1620632):(1620629:1620629)";
        let RawRecord::Task(t) = parse_line(line).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(t.kind, TaskKind::Exit);
        assert_eq!((t.pid, t.tid), (1620630, 1620632));
    }

    #[test]
    fn syscall_and_int_are_boundaries_not_calls() {
        let line = "1620630/1620631 [054] 519323.123597919:  branches:u:   int                        55d0d6ecd7bc =>     7f8222eb8d90";
        let RawRecord::Sample(s) = parse_line(line).unwrap().unwrap() else {
            panic!();
        };
        assert_eq!(flags_kind(s.flags), crate::model::FlowKind::AsyncBoundary);
        assert!(flags_boundary(s.flags).interrupt);
        let f = Flags::parse_str("tr end  syscall");
        assert!(f.has(Flags::TR_END) && f.has(Flags::SYSCALL));
        assert!(flags_boundary(f).syscall);
        let f = Flags::parse_str("hw int");
        assert!(f.has(Flags::HW_INT) && !f.has(Flags::INT));
    }

    #[test]
    fn stream_records_matches_line_parser() {
        let text = include_str!("../../tests/fixtures/perf_script_calls.txt");
        let expect: Vec<RawRecord> = text
            .lines()
            .filter_map(|l| parse_line(l).ok().flatten())
            .collect();
        let got = parse_reader(std::io::Cursor::new(text.as_bytes())).unwrap();
        assert_eq!(expect, got);
        // Same through a tiny reader that splits lines across reads.
        struct Tiny<'a>(&'a [u8]);
        impl Read for Tiny<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.len().min(7).min(buf.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let got2 = parse_reader(Tiny(text.as_bytes())).unwrap();
        assert_eq!(expect, got2);
    }
}
