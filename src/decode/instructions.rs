//! Streaming instruction-level reconstruction for a bounded thread/time region.
//!
//! Every `instructions:` sample is classified with `iced-x86`; conditional
//! outcomes come from the *next* instruction on the same thread in the same
//! continuous segment. A decoder error between them makes the outcome
//! `unknown`. Only instructions inside the selection are retained; the one
//! instruction after the window still resolves the last conditional.

use crate::decode::reconstruct::FastMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

use crate::decode::images::{ArchivedImage, ImageIndex};
use crate::decode::perf_script::{PidTracker, RawRecord, Sample};
use crate::decode::reconstruct::{AnalysisIr, ThreadIds};
use crate::error::{Error, Result};
use crate::model::{
    Address, AnalysisId, BranchOutcome, ClockOrigin, Count, EventTime, InsnKind, InstructionRecord,
    LocalId, MappingRecord, QualityReport, Selection, ThreadId, TimeQuality,
};

#[derive(Debug, Clone)]
pub struct InstructionIr {
    pub analysis_id: AnalysisId,
    pub origin: ClockOrigin,
    pub instructions: Vec<InstructionRecord>,
    pub quality: QualityReport,
    /// All instruction samples seen in the pass, including those outside the selection.
    pub samples_seen: u64,
}

struct PendingCond {
    out_idx: usize,
    target: Option<u64>,
    fallthrough: Option<u64>,
}

const INSN_COST: u64 = 160;

/// (symbol, image-relative address, innermost inlined function).
type Symbolized = (Option<String>, Option<u64>, Option<String>);

pub struct InsnReconstructor<'a> {
    analysis_id: AnalysisId,
    origin: ClockOrigin,
    origin_abs: u64,
    images: &'a [ArchivedImage],
    index: Vec<ImageIndex>,
    mappings: Vec<MappingRecord>,
    sel_thread: Option<ThreadId>,
    sel_abs: (Option<u64>, Option<u64>),
    out: Vec<InstructionRecord>,
    seq_by_thread: FastMap<(u32, u32), u64>,
    pending: FastMap<(u32, u32), PendingCond>,
    sym_cache: FastMap<(u32, u64), Symbolized>,
    /// DWARF loaders per archived image, built lazily.
    loaders: Vec<Option<Option<addr2line::Loader>>>,
    thread_ids: ThreadIds,
    next_id: u32,
    decoder_errors: u64,
    missing: u64,
    samples_seen: u64,
    budget_bytes: u64,
    pid_filter: Option<PidTracker>,
}

impl<'a> InsnReconstructor<'a> {
    pub fn new(
        analysis_id: AnalysisId,
        origin: &ClockOrigin,
        images: &'a [ArchivedImage],
        mappings: Vec<MappingRecord>,
        selection: Option<&Selection>,
    ) -> Self {
        let origin_abs: u64 = origin.abs_perf_time.0.parse().unwrap_or(0);
        let sel_abs = match selection {
            Some(s) => (
                s.start_ns.map(|v| origin_abs.saturating_add(v)),
                s.end_ns.map(|v| origin_abs.saturating_add(v)),
            ),
            None => (None, None),
        };
        Self {
            analysis_id,
            origin: origin.clone(),
            origin_abs,
            images,
            index: images.iter().map(|i| ImageIndex::build(&i.bytes)).collect(),
            mappings,
            sel_thread: selection.and_then(|s| s.thread_id.clone()),
            sel_abs,
            out: Vec::new(),
            seq_by_thread: FastMap::default(),
            pending: FastMap::default(),
            sym_cache: FastMap::default(),
            loaders: images.iter().map(|_| None).collect(),
            thread_ids: ThreadIds::default(),
            next_id: 0,
            decoder_errors: 0,
            missing: 0,
            samples_seen: 0,
            budget_bytes: u64::MAX,
            pid_filter: None,
        }
    }

    pub fn with_budget(mut self, bytes: u64) -> Self {
        self.budget_bytes = bytes;
        self
    }

    pub fn with_pid_filter(mut self, tracker: PidTracker) -> Self {
        self.pid_filter = Some(tracker);
        self
    }

    fn selected(&self, s: &Sample, tid: &ThreadId) -> bool {
        if self.sel_thread.as_ref().is_some_and(|t| t != tid) {
            return false;
        }
        match (self.sel_abs, s.time_ns) {
            ((None, None), _) => true,
            (_, None) => false,
            ((lo, hi), Some(t)) => lo.is_none_or(|l| t >= l) && hi.is_none_or(|h| t < h),
        }
    }

    fn resolve_outcome(&mut self, key: (u32, u32), next_ip: Option<u64>) {
        if let Some(p) = self.pending.remove(&key) {
            let outcome = match (next_ip, p.target, p.fallthrough) {
                (None, _, _) => BranchOutcome::Unknown,
                (Some(_), Some(t), Some(f)) if t == f => BranchOutcome::Unknown,
                (Some(n), Some(t), Some(_)) if n == t => BranchOutcome::Taken,
                (Some(n), Some(_), Some(f)) if n == f => BranchOutcome::NotTaken,
                _ => BranchOutcome::Unknown,
            };
            if let Some(rec) = self.out.get_mut(p.out_idx) {
                rec.outcome = Some(outcome);
            }
        }
    }

    pub fn push(&mut self, rec: &RawRecord) -> Result<()> {
        if let Some(f) = &mut self.pid_filter {
            f.observe(rec);
            match rec {
                RawRecord::Sample(s) if !f.is_live_thread(s.pid, s.tid) => return Ok(()),
                RawRecord::Mmap(m) if !f.mapping_is_live(m) => return Ok(()),
                _ => {}
            }
        }
        match rec {
            RawRecord::Mmap(m) => {
                self.mappings.push(MappingRecord {
                    generation: self.mappings.len() as u32,
                    pid: m.pid,
                    start: Address(m.start),
                    end: Address(m.start.saturating_add(m.len)),
                    pgoff: m.pgoff,
                    prot: m.prot.clone(),
                    path: m.path.clone(),
                    build_id: None,
                    valid_from: EventTime::unknown(),
                    valid_to: None,
                });
                self.sym_cache.retain(|(pid, _), _| *pid != m.pid);
            }
            RawRecord::Task(_) => self.thread_ids.observe(rec),
            RawRecord::DecoderError(e) => {
                self.decoder_errors += 1;
                match (e.pid, e.tid) {
                    (Some(p), Some(t)) => {
                        self.resolve_outcome((p, t), None);
                        if let Some(seq) = self.seq_by_thread.get_mut(&(p, t)) {
                            *seq += 1;
                        }
                    }
                    _ => {
                        let keys: Vec<_> = self.pending.keys().copied().collect();
                        for k in keys {
                            self.resolve_outcome(k, None);
                        }
                        for seq in self.seq_by_thread.values_mut() {
                            *seq += 1;
                        }
                    }
                }
            }
            RawRecord::Sample(s) if s.event.is_instruction() => {
                self.samples_seen += 1;
                let key = (s.pid, s.tid);
                let seq = {
                    let e = self.seq_by_thread.entry(key).or_insert(0);
                    *e += 1;
                    *e
                };
                let ip = s.ip.unwrap_or(0);
                self.resolve_outcome(key, Some(ip));
                if self.thread_ids.take_exited(key) {
                    self.seq_by_thread.insert(key, 1);
                }
                let tid = self.thread_ids.id(s.pid, s.tid);
                if !self.selected(s, &tid) {
                    return Ok(());
                }
                let bytes = self.insn_bytes(s, ip);
                let decoded = decode_one(ip, &bytes);
                let (symbol, image_offset, inlined) = self.symbolize(s.pid, ip);
                let id = LocalId(self.next_id);
                self.next_id += 1;
                let time = match s.time_ns {
                    Some(t) if self.origin_abs > 0 => {
                        EventTime::estimate(t.saturating_sub(self.origin_abs))
                    }
                    Some(t) => EventTime::estimate(t),
                    None => EventTime::unknown(),
                };
                let idx = self.out.len();
                self.out.push(InstructionRecord {
                    id,
                    thread: tid,
                    sequence: seq,
                    time,
                    location: None,
                    virt_ip: Address(ip),
                    symbol,
                    inlined,
                    image_offset: image_offset.map(Address),
                    len: decoded.len,
                    kind: decoded.kind,
                    branch_target: decoded.target.map(Address),
                    fallthrough: decoded.fallthrough.map(Address),
                    outcome: None,
                    bytes_hex: bytes
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" "),
                });
                if decoded.kind == InsnKind::Conditional {
                    self.pending.insert(
                        key,
                        PendingCond {
                            out_idx: idx,
                            target: decoded.target,
                            fallthrough: decoded.fallthrough,
                        },
                    );
                }
                if self.out.len().is_multiple_of(8192)
                    && (self.out.len() as u64) * INSN_COST > self.budget_bytes
                {
                    return Err(Error::limit(format!(
                        "resident decode budget {} exceeded with {} instructions retained",
                        self.budget_bytes,
                        self.out.len()
                    ))
                    .with_next("Narrow start_ns/end_ns for the instruction decode"));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn mapping_for(&self, pid: u32, ip: u64) -> Option<(usize, Option<usize>)> {
        let (mi, m) = self
            .mappings
            .iter()
            .enumerate()
            .rev()
            .find(|(_, m)| m.pid == pid && ip >= m.start.0 && ip < m.end.0)?;
        let img = self.images.iter().position(|i| i.identity.path == m.path);
        Some((mi, img))
    }

    fn symbolize(&mut self, pid: u32, ip: u64) -> Symbolized {
        if let Some(v) = self.sym_cache.get(&(pid, ip)) {
            return v.clone();
        }
        let v = match self.mapping_for(pid, ip) {
            Some((mi, Some(ii))) => {
                let m = &self.mappings[mi];
                let rel = self.index[ii].relative_addr(ip, m.start.0, m.pgoff);
                let sym = rel.and_then(|r| self.index[ii].function(r).map(|f| f.demangled.clone()));
                let inlined = rel.and_then(|r| self.innermost_inline(ii, r));
                let inlined = inlined.filter(|i| sym.as_deref() != Some(i.as_str()));
                (sym, rel, inlined)
            }
            _ => (None, None, None),
        };
        self.sym_cache.insert((pid, ip), v.clone());
        v
    }

    /// Innermost DWARF inline frame at an image-relative address.
    fn innermost_inline(&mut self, image_idx: usize, rel: u64) -> Option<String> {
        if self.loaders[image_idx].is_none() {
            self.loaders[image_idx] =
                Some(addr2line::Loader::new(&self.images[image_idx].archive_path).ok());
        }
        let loader = self.loaders[image_idx].as_ref()?.as_ref()?;
        let mut frames = loader.find_frames(rel).ok()?;
        let first = frames.next().ok()??;
        first
            .function
            .as_ref()
            .and_then(|f| f.demangle().ok().map(|s| s.into_owned()))
    }

    fn insn_bytes(&mut self, s: &Sample, ip: u64) -> Vec<u8> {
        if !s.insn.is_empty() {
            return s.insn.as_slice().to_vec();
        }
        match self.mapping_for(s.pid, ip) {
            Some((mi, Some(ii))) => {
                let m = &self.mappings[mi];
                let Some(off) =
                    crate::decode::images::ImageIndex::file_offset(ip, m.start.0, m.pgoff)
                        .and_then(|o| usize::try_from(o).ok())
                else {
                    return Vec::new();
                };
                let bytes = &self.images[ii].bytes;
                if off >= bytes.len() {
                    return Vec::new();
                }
                bytes[off..bytes.len().min(off + 15)].to_vec()
            }
            _ => {
                self.missing += 1;
                Vec::new()
            }
        }
    }

    pub fn finish(mut self) -> Result<InstructionIr> {
        let keys: Vec<_> = self.pending.keys().copied().collect();
        for k in keys {
            self.resolve_outcome(k, None);
        }
        let unknown = self
            .out
            .iter()
            .filter(|i| i.outcome == Some(BranchOutcome::Unknown))
            .count() as u64;
        let mut notes =
            vec!["taken_fraction is among known outcomes in the selected region only".into()];
        notes.push(format!(
            "{} instruction samples scanned, {} retained in the selection",
            self.samples_seen,
            self.out.len()
        ));
        if unknown > 0 {
            notes.push(format!("{unknown} conditional outcomes unknown"));
        }
        Ok(InstructionIr {
            analysis_id: self.analysis_id,
            origin: self.origin,
            instructions: self.out,
            quality: QualityReport {
                timing: TimeQuality::DecoderEstimate,
                gap_count: Count(0),
                incomplete_span_count: Count(0),
                missing_image_count: Count(self.missing),
                decoder_error_count: Count(self.decoder_errors),
                ring_truncation: false,
                undecodable_prefix: false,
                notes,
                gaps_by_kind: Default::default(),
            },
            samples_seen: self.samples_seen,
        })
    }
}

/// Fixture convenience: whole record list, no selection.
pub fn reconstruct_instructions(
    analysis_id: AnalysisId,
    origin: &ClockOrigin,
    records: &[RawRecord],
    images: &[ArchivedImage],
    mappings: &[MappingRecord],
) -> Result<InstructionIr> {
    let mut r = InsnReconstructor::new(analysis_id, origin, images, mappings.to_vec(), None);
    for rec in records {
        r.push(rec)?;
    }
    r.finish()
}

struct Decoded {
    len: u8,
    kind: InsnKind,
    target: Option<u64>,
    fallthrough: Option<u64>,
}

fn decode_one(ip: u64, bytes: &[u8]) -> Decoded {
    if bytes.is_empty() {
        return Decoded {
            len: 0,
            kind: InsnKind::Other,
            target: None,
            fallthrough: None,
        };
    }
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let insn = decoder.decode();
    let len = insn.len() as u8;
    let fallthrough = ip.checked_add(u64::from(len));
    let (kind, target) = classify(&insn);
    Decoded {
        len,
        kind,
        target,
        fallthrough: if matches!(kind, InsnKind::Return) {
            None
        } else {
            fallthrough
        },
    }
}

fn classify(insn: &Instruction) -> (InsnKind, Option<u64>) {
    match insn.flow_control() {
        FlowControl::Next => (InsnKind::Sequential, None),
        FlowControl::UnconditionalBranch => (InsnKind::Jump, Some(insn.near_branch_target())),
        FlowControl::IndirectBranch => (InsnKind::IndirectJump, None),
        FlowControl::ConditionalBranch => (InsnKind::Conditional, Some(insn.near_branch_target())),
        FlowControl::Call => (InsnKind::Call, Some(insn.near_branch_target())),
        FlowControl::IndirectCall => (InsnKind::IndirectCall, None),
        FlowControl::Return => (InsnKind::Return, None),
        _ => (InsnKind::Other, None),
    }
}

/// Site aggregates for a selected region. `taken_fraction` only when known denominator > 0.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BranchSite {
    pub site: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub taken: Count,
    pub not_taken: Count,
    pub unknown: Count,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taken_fraction: Option<String>,
    pub indirect_targets: Vec<String>,
}

pub fn aggregate_branches(insns: &[InstructionRecord]) -> Vec<BranchSite> {
    use std::collections::BTreeMap;
    #[derive(Default)]
    struct Site {
        taken: u64,
        not_taken: u64,
        unknown: u64,
        targets: Vec<u64>,
        symbol: Option<String>,
    }
    let mut map: BTreeMap<u64, Site> = BTreeMap::new();
    for (i, insn) in insns.iter().enumerate() {
        match insn.kind {
            InsnKind::Conditional => {
                let e = map.entry(insn.virt_ip.0).or_default();
                e.symbol = e.symbol.take().or_else(|| insn.symbol.clone());
                match insn.outcome {
                    Some(BranchOutcome::Taken) => e.taken += 1,
                    Some(BranchOutcome::NotTaken) => e.not_taken += 1,
                    _ => e.unknown += 1,
                }
            }
            InsnKind::IndirectCall | InsnKind::IndirectJump => {
                if let Some(next) = insns
                    .get(i + 1)
                    .filter(|n| n.thread == insn.thread && n.sequence == insn.sequence + 1)
                {
                    let e = map.entry(insn.virt_ip.0).or_default();
                    e.symbol = e.symbol.take().or_else(|| insn.symbol.clone());
                    if !e.targets.contains(&next.virt_ip.0) {
                        e.targets.push(next.virt_ip.0);
                    }
                }
            }
            _ => {}
        }
    }
    let mut sites: Vec<BranchSite> = map
        .into_iter()
        .map(|(ip, s)| {
            let den = s.taken + s.not_taken;
            BranchSite {
                site: format!("0x{ip:x}"),
                symbol: s.symbol,
                taken: Count(s.taken),
                not_taken: Count(s.not_taken),
                unknown: Count(s.unknown),
                taken_fraction: if den == 0 {
                    None
                } else {
                    Some(format!("{:.6}", s.taken as f64 / den as f64))
                },
                indirect_targets: s.targets.into_iter().map(|a| format!("0x{a:x}")).collect(),
            }
        })
        .collect();
    // Most executed sites first; ties by address for determinism.
    sites.sort_by(|a, b| {
        (b.taken.0 + b.not_taken.0 + b.unknown.0)
            .cmp(&(a.taken.0 + a.not_taken.0 + a.unknown.0))
            .then(a.site.cmp(&b.site))
    });
    sites
}

pub fn overlay_calls_quality(calls: &AnalysisIr, insn: &mut InstructionIr) {
    insn.quality.ring_truncation = calls.quality.ring_truncation;
    insn.quality.gap_count = calls.quality.gap_count;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::perf_script::parse_line;

    fn origin() -> ClockOrigin {
        ClockOrigin {
            abs_perf_time: crate::model::AbsTime("0".into()),
            relative_zero_ns: 0,
        }
    }

    fn recs(lines: &[String]) -> Vec<RawRecord> {
        lines
            .iter()
            .map(|l| parse_line(l).unwrap().unwrap())
            .collect()
    }

    #[test]
    fn taken_and_not_taken_from_sequence() {
        // jcc at 0x10, fallthrough 0x12, target 0x20
        let lines: Vec<String> = [
            "1/1 [000] 1.0:  instructions:u:  10 10  insn: 75 0e ilen: 2",
            "1/1 [000] 1.000000001:  instructions:u:  12 12  insn: 90 ilen: 1",
            "1/1 [000] 1.000000002:  instructions:u:  10 10  insn: 75 0e ilen: 2",
            "1/1 [000] 1.000000003:  instructions:u:  20 20  insn: 90 ilen: 1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let ir = reconstruct_instructions(
            AnalysisId::from_raw("a_br").unwrap(),
            &origin(),
            &recs(&lines),
            &[],
            &[],
        )
        .unwrap();
        let cond: Vec<_> = ir
            .instructions
            .iter()
            .filter(|i| i.kind == InsnKind::Conditional)
            .collect();
        assert_eq!(cond.len(), 2);
        assert_eq!(cond[0].outcome, Some(BranchOutcome::NotTaken));
        assert_eq!(cond[1].outcome, Some(BranchOutcome::Taken));
        assert_eq!(cond[0].thread.as_str(), "t_1");
    }

    #[test]
    fn unknown_across_gap() {
        let lines: Vec<String> = [
            "1/1 [000] 1.0:  instructions:u:  10 10  insn: 75 0e ilen: 2",
            " instruction trace error type 1 time 1.1 cpu 0 pid 1 tid 1 ip 0x12 code 6: mismatch",
            "1/1 [000] 1.2:  instructions:u:  20 20  insn: 90 ilen: 1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let ir = reconstruct_instructions(
            AnalysisId::from_raw("a_gap").unwrap(),
            &origin(),
            &recs(&lines),
            &[],
            &[],
        )
        .unwrap();
        let cond = ir
            .instructions
            .iter()
            .find(|i| i.kind == InsnKind::Conditional)
            .unwrap();
        assert_eq!(cond.outcome, Some(BranchOutcome::Unknown));
    }

    #[test]
    fn window_end_still_resolves_last_conditional() {
        let lines: Vec<String> = [
            "1/1 [000] 1.000000000:  instructions:u:  10 10  insn: 75 0e ilen: 2",
            "1/1 [000] 1.000000005:  instructions:u:  20 20  insn: 90 ilen: 1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let sel = Selection {
            thread_id: Some(ThreadId::from_raw("t_1").unwrap()),
            start_ns: Some(1_000_000_000),
            end_ns: Some(1_000_000_003),
        };
        let mut r = InsnReconstructor::new(
            AnalysisId::from_raw("a_win").unwrap(),
            &origin(),
            &[],
            Vec::new(),
            Some(&sel),
        );
        for rec in recs(&lines) {
            r.push(&rec).unwrap();
        }
        let ir = r.finish().unwrap();
        assert_eq!(ir.instructions.len(), 1);
        assert_eq!(ir.instructions[0].outcome, Some(BranchOutcome::Taken));
        assert_eq!(ir.samples_seen, 2);
    }

    #[test]
    fn cond_loop_three_of_four_taken() {
        // Matches `ptfx_cond_loop` assembly: `test $0x3,%sil; jne` (taken when i&3 != 0).
        // jne at 0x104, fallthrough 0x106, target 0x120
        let mut lines = Vec::new();
        for i in 0..4u32 {
            let t = 1.0 + f64::from(i) * 0.000000010;
            lines.push(format!(
                "1/1 [000] {t:.9}:  instructions:u:  100 100  insn: 40 f6 c6 03 ilen: 4"
            ));
            let t2 = t + 0.000000001;
            lines.push(format!(
                "1/1 [000] {t2:.9}:  instructions:u:  104 104  insn: 75 1a ilen: 2"
            ));
            let next = if i & 3 != 0 { 0x120 } else { 0x106 };
            let t3 = t2 + 0.000000001;
            lines.push(format!(
                "1/1 [000] {t3:.9}:  instructions:u:  {next:x} {next:x}  insn: 90 ilen: 1"
            ));
        }
        let ir = reconstruct_instructions(
            AnalysisId::from_raw("a_loop").unwrap(),
            &origin(),
            &recs(&lines),
            &[],
            &[],
        )
        .unwrap();
        let sites = aggregate_branches(&ir.instructions);
        let site = sites.iter().find(|s| s.site == "0x104").expect("jne site");
        assert_eq!(site.taken.0, 3);
        assert_eq!(site.not_taken.0, 1);
        assert_eq!(site.taken_fraction.as_deref(), Some("0.750000"));
    }
}
