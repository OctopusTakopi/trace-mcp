//! Native Intel PT decode with libipt.
//!
//! Reads `perf.data` directly (`capture::perfdata`), runs libipt's block
//! decoder over every CPU's AUX stream on its own thread, attributes blocks
//! to threads from the context-switch sideband, and converts each block's
//! terminating branch into the same [`RawRecord::Sample`] the perf-script
//! path produces. The streaming reconstructor is unchanged; parity with
//! `perf script` is asserted by the hardware suite.
//!
//! Time: libipt reports TSC; `IntelPtInfo::tsc_to_ns` is perf's conversion.
//! Images: one libipt `Image` per pid built from the archived ELF bytes at
//! their recorded mappings; the decoder's image is switched whenever the
//! running task's pid changes.

use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc;

use libipt::block::BlockDecoder;
use libipt::enc_dec_builder::{Cpu, CpuVendor, Frequency, PtEncoderDecoder};
use libipt::event::EventType;
use libipt::image::Image;

use crate::capture::perfdata::{AuxBlob, IntelPtInfo, PerfData, Sideband};
use crate::decode::images::ArchivedImage;
use crate::decode::perf_script::{
    DecoderErrorEvent, Flags, InsnBytes, LostEvent, MmapEvent, RawRecord, Sample, SampleEvent,
    TaskEvent, TaskKind,
};
use crate::error::{Error, Result};

/// Decoder identity recorded in analysis manifests.
pub fn decoder_version() -> String {
    // SAFETY: pt_library_version has no preconditions and returns by value.
    let v = unsafe { libipt_sys::pt_library_version() };
    format!(
        "libipt {}.{}.{} (libipt crate 0.4.0)",
        v.major, v.minor, v.patch
    )
}

/// Host facts needed for errata and timing.
#[derive(Debug, Clone, Copy)]
pub struct CpuModel {
    pub family: u16,
    pub model: u8,
    pub stepping: u8,
}

/// Which samples to synthesize.
#[derive(Debug, Clone)]
pub struct DecodeSelection {
    /// Emit an `instructions` sample per executed instruction (in addition
    /// to branches) for this thread and absolute perf-time window.
    pub instructions: Option<(u32, u32, u64, u64)>,
    /// Decode only these pids (the traced process tree); other tasks sharing
    /// the CPUs get an empty image so their slices are skipped at packet
    /// scan speed instead of being decoded through shared libraries.
    pub pids: Option<std::collections::HashSet<u32>>,
    /// Decode only the newest `1/tail_div` of every ring (cut at a PSB);
    /// 0 or 1 means everything. Used when the derived budget is exceeded.
    pub tail_div: u32,
}

/// One batch of time-stamped records from a decode worker.
pub type Batch = Vec<(Option<u64>, RawRecord)>;
/// (per-worker receivers, worker handles, number of CPU streams).
pub type NativeStreams = (
    Vec<mpsc::Receiver<Batch>>,
    Vec<std::thread::JoinHandle<Result<u64>>>,
    usize,
);
/// Per-CPU run queue: (switch-in time, pid, tid).
type Schedule = Vec<(u64, u32, u32)>;

/// Offsets of PSB packets (16-byte `02 82` pattern) in a trace buffer.
fn psb_offsets(data: &[u8]) -> Vec<usize> {
    const PSB: [u8; 16] = [
        0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02,
        0x82,
    ];
    let mut out = Vec::new();
    let mut i = 0;
    while i + PSB.len() <= data.len() {
        if data[i] == 0x02 && data[i..i + PSB.len()] == PSB {
            out.push(i);
            i += PSB.len();
        } else {
            i += 1;
        }
    }
    out
}

/// Cut a blob into at most `parts` chunks of roughly equal size, each
/// starting at a PSB (the first chunk starts at 0). Blobs under 2 MiB stay
/// whole.
fn split_at_psb(data: &[u8], parts: usize) -> Vec<(usize, usize)> {
    const MIN_CHUNK: usize = 2 << 20;
    if parts <= 1 || data.len() < 2 * MIN_CHUNK {
        return vec![(0, data.len())];
    }
    let target = (data.len() / parts).max(MIN_CHUNK);
    let mut cuts = vec![0usize];
    for off in psb_offsets(data) {
        if off - cuts[cuts.len() - 1] >= target && data.len() - off >= MIN_CHUNK / 2 {
            cuts.push(off);
        }
    }
    cuts.push(data.len());
    cuts.windows(2).map(|w| (w[0], w[1] - w[0])).collect()
}

/// Convert sideband into the reconstructor's record stream (time ordered).
pub fn sideband_records(pd: &PerfData) -> Vec<(Option<u64>, RawRecord)> {
    let mut out = Vec::with_capacity(pd.sideband.len());
    for s in &pd.sideband {
        let rec = match s {
            Sideband::Mmap {
                pid,
                tid,
                time,
                start,
                len,
                pgoff,
                exec,
                path,
            } => {
                if !exec {
                    continue;
                }
                RawRecord::Mmap(MmapEvent {
                    pid: *pid,
                    tid: *tid,
                    time_ns: (*time != 0).then_some(*time),
                    start: *start,
                    len: *len,
                    pgoff: *pgoff,
                    prot: "r-xp".into(),
                    path: path.clone(),
                })
            }
            Sideband::Comm {
                pid,
                tid,
                time,
                comm,
                exec,
            } => RawRecord::Task(TaskEvent {
                kind: if *exec {
                    TaskKind::Exec
                } else {
                    TaskKind::Comm
                },
                pid: *pid,
                tid: *tid,
                ppid: None,
                ptid: None,
                time_ns: (*time != 0).then_some(*time),
                comm: Some(comm.clone()),
            }),
            Sideband::Fork {
                pid,
                ppid,
                tid,
                ptid,
                time,
            } => RawRecord::Task(TaskEvent {
                kind: TaskKind::Fork,
                pid: *pid,
                tid: *tid,
                ppid: Some(*ppid),
                ptid: Some(*ptid),
                time_ns: (*time != 0).then_some(*time),
                comm: None,
            }),
            Sideband::Exit {
                pid,
                ppid,
                tid,
                ptid,
                time,
            } => RawRecord::Task(TaskEvent {
                kind: TaskKind::Exit,
                pid: *pid,
                tid: *tid,
                ppid: Some(*ppid),
                ptid: Some(*ptid),
                time_ns: (*time != 0).then_some(*time),
                comm: None,
            }),
            Sideband::Switch {
                pid,
                tid,
                time,
                out: o,
                ..
            } => RawRecord::Switch {
                pid: *pid,
                tid: *tid,
                time_ns: (*time != 0).then_some(*time),
                out: *o,
            },
            Sideband::Lost { time, cpu, lost } => RawRecord::Lost(LostEvent {
                time_ns: (*time != 0).then_some(*time),
                cpu: Some(*cpu),
                lost: *lost,
            }),
            Sideband::ItraceStart { .. } => continue,
        };
        out.push((s.time().checked_sub(0).filter(|t| *t != 0), rec));
    }
    out
}

/// Per-CPU "who is running" table from switch-in and itrace-start records.
fn schedule_for_cpu(pd: &PerfData, cpu: u32) -> Vec<(u64, u32, u32)> {
    let mut v: Vec<(u64, u32, u32)> = pd
        .sideband
        .iter()
        .filter_map(|s| match s {
            Sideband::Switch {
                pid,
                tid,
                cpu: c,
                time,
                out: false,
            } if *c == cpu => Some((*time, *pid, *tid)),
            Sideband::ItraceStart {
                pid,
                tid,
                cpu: c,
                time,
            } if *c == cpu => Some((*time, *pid, *tid)),
            _ => None,
        })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Mappings per pid in time order (exec'd regions only).
fn mappings_by_pid(pd: &PerfData) -> HashMap<u32, Vec<(u64, u64, u64, String)>> {
    let mut m: HashMap<u32, Vec<(u64, u64, u64, String)>> = HashMap::new();
    for s in &pd.sideband {
        match s {
            Sideband::Mmap {
                pid,
                start,
                len,
                pgoff,
                exec: true,
                path,
                ..
            } => m
                .entry(*pid)
                .or_default()
                .push((*start, *len, *pgoff, path.clone())),
            // exec replaces the address space: the launch shim's own
            // mappings must not shadow the workload's.
            Sideband::Comm {
                pid, exec: true, ..
            } => {
                m.remove(pid);
            }
            _ => {}
        }
    }
    m
}

/// Time of each pid's last exec: before it the pid runs its parent's
/// (unarchived) code, which is skipped like a foreign task.
fn exec_times(pd: &PerfData) -> HashMap<u32, u64> {
    let mut m = HashMap::new();
    for sb in &pd.sideband {
        if let Sideband::Comm {
            pid,
            exec: true,
            time,
            ..
        } = sb
        {
            m.insert(*pid, *time);
        }
    }
    m
}

/// (pid, mapping start) -> libipt section id in the worker's section cache.
type SectionIds = HashMap<(u32, u64), u32>;

/// Register every archived executable mapping of every pid in one section
/// cache (metadata only; sections are mapped on first use and then kept).
fn fill_section_cache(
    maps: &HashMap<u32, Vec<(u64, u64, u64, String)>>,
    images: &[ArchivedImage],
) -> Result<(std::rc::Rc<libipt::image::SectionCache>, SectionIds)> {
    let mut sc = libipt::image::SectionCache::new(None)
        .map_err(|e| Error::decode_failed(format!("libipt section cache: {e}")))?;
    let _ = sc.set_limit(512 << 20);
    let mut ids = SectionIds::new();
    for (pid, ms) in maps {
        for (start, len, pgoff, path) in ms {
            let Some(a) = images.iter().find(|i| &i.identity.path == path) else {
                continue;
            };
            let avail = (a.bytes.len() as u64).saturating_sub(*pgoff);
            let size = (*len).min(avail);
            if size == 0 {
                continue;
            }
            let file = a.archive_path.to_string_lossy().into_owned();
            if let Ok(isid) = sc.add_file(&file, *pgoff, size, *start) {
                ids.insert((*pid, *start), isid);
            }
        }
    }
    Ok((std::rc::Rc::new(sc), ids))
}

fn build_image(
    pid: u32,
    maps: &[(u64, u64, u64, String)],
    images: &[ArchivedImage],
    cache: &std::rc::Rc<libipt::image::SectionCache>,
    ids: &SectionIds,
) -> Result<Image> {
    let mut img = Image::new(Some(&format!("pid{pid}")))
        .map_err(|e| Error::decode_failed(format!("libipt image: {e}")))?;
    for (start, len, pgoff, path) in maps {
        let Some(a) = images.iter().find(|i| &i.identity.path == path) else {
            continue;
        };
        let file = a.archive_path.to_string_lossy().into_owned();
        // Clamp to the file: perf maps whole pages, the file may be shorter.
        let avail = (a.bytes.len() as u64).saturating_sub(*pgoff);
        let size = (*len).min(avail);
        if size == 0 {
            continue;
        }
        // Through the section cache: libipt frees a section's block cache
        // whenever the section is unmapped, and the block decoder maps one
        // section at a time, so uncached sections re-zero tens of MB on
        // every hop between the binary and libc (a third of decode time).
        let _ = file;
        if let Some(isid) = ids.get(&(pid, *start)) {
            let _ = img.add_cached(cache.clone(), *isid, None);
        }
    }
    Ok(img)
}

/// libipt's `pt_insn_class`, read from the raw block because the crate's
/// enum predates libipt 2.1's `ptic_indirect` (10) and panics on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Unknown,
    Other,
    Call,
    Return,
    Jump,
    CondJump,
    FarCall,
    FarReturn,
    FarJump,
    Ptwrite,
    /// Indirect jump (libipt >= 2.1).
    Indirect,
}

/// Size in bytes of the block's last instruction (from the raw block).
fn block_last_size(block: &libipt::block::Block) -> u8 {
    // SAFETY: `Block` is `#[repr(transparent)]` over `pt_block`.
    let raw: &libipt_sys::pt_block =
        unsafe { &*(std::ptr::from_ref(block).cast::<libipt_sys::pt_block>()) };
    raw.size
}

fn block_class(block: &libipt::block::Block) -> Class {
    // SAFETY: `Block` is `#[repr(transparent)]` over `pt_block`.
    let raw: &libipt_sys::pt_block =
        unsafe { &*(std::ptr::from_ref(block).cast::<libipt_sys::pt_block>()) };
    match raw.iclass {
        1 => Class::Other,
        2 => Class::Call,
        3 => Class::Return,
        4 => Class::Jump,
        5 => Class::CondJump,
        6 => Class::FarCall,
        7 => Class::FarReturn,
        8 => Class::FarJump,
        9 => Class::Ptwrite,
        10 => Class::Indirect,
        _ => Class::Unknown,
    }
}

fn class_flags(class: Class) -> Flags {
    match class {
        Class::Call => Flags::CALL,
        Class::Return => Flags::RETURN,
        Class::CondJump => Flags::JCC,
        Class::Jump => Flags::JMP,
        Class::FarCall => Flags::SYSCALL,
        Class::FarReturn => Flags::SYSRET,
        Class::FarJump => Flags::JMP,
        Class::Indirect => Flags::JMP,
        _ => Flags::JMP,
    }
}

/// Decode one CPU blob into samples, pushing batches to `tx`.
#[allow(clippy::too_many_arguments)]
fn decode_blob(
    data: &[u8],
    cpu: u32,
    info: &IntelPtInfo,
    cpu_model: CpuModel,
    mtc_period: u8,
    schedule: &[(u64, u32, u32)],
    maps: &HashMap<u32, Vec<(u64, u64, u64, String)>>,
    images: &[ArchivedImage],
    selection: &DecodeSelection,
    wanted: Option<&std::collections::HashSet<u32>>,
    execs: &HashMap<u32, u64>,
    section_cache: &std::rc::Rc<libipt::image::SectionCache>,
    section_ids: &SectionIds,
    tx: &mpsc::SyncSender<Vec<(Option<u64>, RawRecord)>>,
) -> Result<u64> {
    let mut buf = data.to_vec();
    let builder = BlockDecoder::builder()
        .cpu(Cpu::new(
            CpuVendor::INTEL,
            cpu_model.family,
            cpu_model.model,
            cpu_model.stepping,
        ))
        .freq(Frequency::new(
            mtc_period,
            info.max_nonturbo_ratio as u8,
            info.tsc_ctc_ratio_n as u32,
            info.tsc_ctc_ratio_d as u32,
        ))
        // Direct calls and jumps are deterministic, so libipt would run
        // straight through them; every branch must end a block for the
        // call/return reconstruction to see it (perf's `b` itrace option).
        .set_end_on_call(true)
        .set_end_on_jump(true);
    // SAFETY: `buf` outlives the decoder (both live in this function).
    let builder = unsafe { builder.buffer_from_raw(buf.as_mut_ptr(), buf.len()) };
    let mut decoder = builder
        .build()
        .map_err(|e| Error::decode_failed(format!("libipt decoder: {e}")))?;
    let mut image_cache: HashMap<u32, Image> = HashMap::new();
    let mut batch: Vec<(Option<u64>, RawRecord)> = Vec::with_capacity(2048);
    let mut emitted = 0u64;
    let mut sched_idx = 0usize;
    let mut cur_pid = u32::MAX;
    let mut cur_tid = 0u32;
    let mut set_image_for = u32::MAX;
    // Image keys decoded without code (foreign task or pre-exec phase):
    // their errors are expected and are not reported to the reconstructor.
    let mut foreign_keys: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut cur_foreign = false;
    let mut last_branch_idx: Option<usize> = None;
    // (ip, end_ip, class, time) of the previous block, whose terminating
    // branch is only known once the next block's start ip is seen.
    let mut prev_block: Option<(u64, u64, Class, Option<u64>, u8)> = None;
    let mut last_time: Option<u64> = None;
    let mut last_enable_ip = 0u64;
    // Never-ending loop guard (perf has the same): a self-jump consumes no
    // packets, so the offset stops moving while blocks keep coming.
    let (mut stuck_off, mut stuck_rounds) = (u64::MAX, 0u32);
    let mut len_cache: crate::decode::reconstruct::FastMap<(u32, u64), u8> = Default::default();
    let debug = std::env::var_os("TRACE_MCP_NATIVE_DEBUG").is_some();
    let t_start = std::time::Instant::now();
    let (mut n_sync, mut n_blocks, mut n_errs, mut first_t, mut last_t) =
        (0u64, 0u64, 0u64, None::<u64>, None::<u64>);
    let mut err_codes: HashMap<i32, u64> = HashMap::new();
    let mut n_resync = 0u64;
    let mut last_resync_offset = u64::MAX;
    let mut err_by_pid: HashMap<(u32, i32), u64> = HashMap::new();
    let mut nomap_samples: Vec<(u32, u64)> = Vec::new();
    let trace_cpu: Option<u32> = std::env::var("TRACE_MCP_NATIVE_TRACE")
        .ok()
        .and_then(|v| v.parse().ok());
    let mut trace_left: u32 = 0;
    let mut trace_started = false;
    let dump_window: Option<(u64, u64)> =
        std::env::var("TRACE_MCP_NATIVE_DUMP").ok().and_then(|v| {
            let (a, b) = v.split_once(',')?;
            Some((a.parse().ok()?, b.parse().ok()?))
        });

    let mono = std::cell::Cell::new(0u64);
    let flush = |batch: &mut Vec<(Option<u64>, RawRecord)>| -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut full = std::mem::replace(batch, Vec::with_capacity(2048));
        // Timestamps are monotonic per CPU, as perf's are: an event's own
        // TSC can predate the block time already emitted before it.
        for (t, r) in &mut full {
            if let Some(v) = t {
                let clamped = (*v).max(mono.get());
                mono.set(clamped);
                *v = clamped;
                match r {
                    RawRecord::Sample(sm) => sm.time_ns = Some(clamped),
                    RawRecord::DecoderError(e) => e.time_ns = Some(clamped),
                    RawRecord::Lost(l) => l.time_ns = Some(clamped),
                    _ => {}
                }
            }
        }
        if let Some((lo, hi)) = dump_window {
            for (t, r) in &full {
                if !t.is_some_and(|t| t >= lo && t < hi) {
                    continue;
                }
                match r {
                    RawRecord::Sample(sm) => eprintln!(
                        "  dump cpu{cpu}: {} {}/{} {:?} {:#x} => {:#x}",
                        t.unwrap_or(0),
                        sm.pid,
                        sm.tid,
                        sm.flags,
                        sm.ip.unwrap_or(0),
                        sm.addr.unwrap_or(0)
                    ),
                    RawRecord::DecoderError(e) => eprintln!(
                        "  dump cpu{cpu}: {} {:?}/{:?} ERROR {:?} {}",
                        t.unwrap_or(0),
                        e.pid,
                        e.tid,
                        e.ip,
                        e.message
                    ),
                    other => eprintln!("  dump cpu{cpu}: {} {other:?}", t.unwrap_or(0)),
                }
            }
        }
        tx.send(full)
            .map_err(|_| Error::cancelled("native decode consumer stopped"))
    };

    // PSB index for instruction windows: one cheap pass records every
    // syncpoint's offset and time, then only the regions overlapping the
    // requested window are decoded (a window decode no longer walks the
    // whole CPU buffer).
    let mut plan: Option<std::collections::VecDeque<u64>> = None;
    let mut window_hi = u64::MAX;
    if let Some((_, _, lo, hi)) = selection.instructions {
        window_hi = hi;
        let mut index: Vec<(u64, u64)> = Vec::new();
        while decoder.sync_forward().is_ok() {
            let off = decoder.sync_offset().unwrap_or(0);
            let mut t = None;
            if let Ok((_, mut st)) = decoder.decode_next() {
                while st.event_pending() {
                    let Ok((_, s2)) = decoder.event() else { break };
                    st = s2;
                }
                t = decoder
                    .time()
                    .ok()
                    .filter(|(tsc, _, _)| *tsc != u64::MAX)
                    .map(|(tsc, _, _)| info.tsc_to_ns(tsc));
            }
            index.push((off, t.unwrap_or(0)));
        }
        let mut keep = std::collections::VecDeque::new();
        for (i, (off, t0)) in index.iter().enumerate() {
            let t1 = index.get(i + 1).map_or(u64::MAX, |(_, t)| *t);
            if t1 > lo && *t0 <= hi {
                keep.push_back(*off);
            }
        }
        if debug {
            eprintln!(
                "native cpu{cpu}: psb index {} syncpoints, {} overlap the window",
                index.len(),
                keep.len()
            );
        }
        plan = Some(keep);
    }

    loop {
        // Synchronise on the next PSB (or the next planned syncpoint).
        let sync = match plan.as_mut() {
            Some(q) => match q.pop_front() {
                Some(off) => decoder
                    .set_sync(off)
                    .map(|()| libipt::status::Status::empty()),
                None => break,
            },
            None => decoder.sync_forward(),
        };
        match sync {
            Ok(_) => {
                n_sync += 1;
            }
            Err(e) if e.code() == libipt::error::PtErrorCode::Eos => break,
            Err(e) => {
                n_errs += 1;
                *err_codes.entry(e.code() as i32).or_default() += 1;
                batch.push((
                    None,
                    RawRecord::DecoderError(DecoderErrorEvent {
                        time_ns: None,
                        cpu: Some(cpu),
                        pid: (cur_pid != u32::MAX).then_some(cur_pid),
                        tid: Some(cur_tid),
                        ip: None,
                        code: Some(1),
                        message: format!("libipt sync: {e}"),
                    }),
                ));
                break;
            }
        }
        loop {
            let (block, status) = match decoder.decode_next() {
                Ok(v) => v,
                Err(e) => {
                    let code = match e.code() {
                        libipt::error::PtErrorCode::Nomap => 5,
                        libipt::error::PtErrorCode::Eos => 0,
                        _ => 6,
                    };
                    if code == 0 {
                        break;
                    }
                    n_errs += 1;
                    *err_codes.entry(e.code() as i32).or_default() += 1;
                    if debug {
                        *err_by_pid.entry((cur_pid, e.code() as i32)).or_default() += 1;
                        if code == 5 && wanted.is_none_or(|w| w.contains(&cur_pid)) {
                            if nomap_samples.len() >= 12 {
                                nomap_samples.remove(0);
                            }
                            nomap_samples
                                .push((cur_pid, prev_block.map(|b| b.1).unwrap_or(last_enable_ip)));
                        }
                    }
                    let t = decoder.time().ok().map(|(tsc, _, _)| info.tsc_to_ns(tsc));
                    if !cur_foreign {
                        batch.push((
                            t,
                            RawRecord::DecoderError(DecoderErrorEvent {
                                time_ns: t,
                                cpu: Some(cpu),
                                pid: (cur_pid != u32::MAX).then_some(cur_pid),
                                tid: Some(cur_tid),
                                ip: prev_block.map(|b| b.1),
                                code: Some(code),
                                message: format!("libipt: {e}"),
                            }),
                        ));
                    }
                    prev_block = None;
                    // Scan ahead to the next IP-providing packet (TIP.PGE /
                    // FUP) like perf's intel_pt_sync_ip, instead of giving up
                    // on everything before the next PSB. Unmapped code of an
                    // unrelated task on this CPU ends at its switch-out.
                    let mut resynced = false;
                    let err_offset = decoder.offset().unwrap_or(u64::MAX);
                    let mut stalled = 0u32;
                    for _ in 0..1024 {
                        match decoder.resync() {
                            Ok(st) => {
                                // A resync that lands where the last one did
                                // usually sits on an event-carrying packet:
                                // drain it and scan again (bounded), instead
                                // of giving up on everything before the next
                                // PSB (which in a task-scoped trace may be
                                // the rest of the buffer).
                                let now = decoder.offset().unwrap_or(u64::MAX);
                                if now == last_resync_offset && now <= err_offset {
                                    stalled += 1;
                                    if stalled > 8 {
                                        break;
                                    }
                                    let mut st = st;
                                    while st.event_pending() {
                                        let Ok((_, s2)) = decoder.event() else { break };
                                        st = s2;
                                    }
                                    continue;
                                }
                                last_resync_offset = now;
                                resynced = true;
                                break;
                            }
                            Err(e) if e.code() == libipt::error::PtErrorCode::EventIgnored => {
                                if decoder.event().is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    if resynced {
                        n_resync += 1;
                        if trace_cpu == Some(cpu) && n_resync == 1 && dump_window.is_none() {
                            trace_left = 80;
                        }
                        if trace_left > 0 {
                            trace_left -= 1;
                            eprintln!(
                                "  trace cpu{cpu}: resync ok at offset {:?} time {:?} err {e}",
                                decoder.offset(),
                                decoder.time()
                            );
                        }
                        continue;
                    }
                    break;
                }
            };
            let time = decoder
                .time()
                .ok()
                .filter(|(tsc, _, _)| *tsc != u64::MAX)
                .map(|(tsc, _, _)| info.tsc_to_ns(tsc));
            last_time = time.or(last_time);
            let time = time.or(last_time);
            if debug && n_blocks == 0 {
                eprintln!(
                    "native cpu{cpu}: first raw time {:?} shift {} mult {:#x} zero {:#x} first block ip {:#x}",
                    decoder.time(),
                    info.time_shift,
                    info.time_mult,
                    info.time_zero,
                    block.ip()
                );
            }
            n_blocks += 1;
            if n_blocks & 0xffff == 0 {
                let off = decoder.offset().unwrap_or(u64::MAX);
                if off == stuck_off {
                    stuck_rounds += 1;
                } else {
                    stuck_off = off;
                    stuck_rounds = 0;
                }
                if stuck_rounds >= 8 {
                    n_errs += 1;
                    *err_codes.entry(-1).or_default() += 1;
                    let t = decoder.time().ok().map(|(tsc, _, _)| info.tsc_to_ns(tsc));
                    batch.push((
                        t,
                        RawRecord::DecoderError(DecoderErrorEvent {
                            time_ns: t,
                            cpu: Some(cpu),
                            pid: (cur_pid != u32::MAX).then_some(cur_pid),
                            tid: Some(cur_tid),
                            ip: Some(block.ip()),
                            code: Some(6),
                            message: format!(
                                "never-ending loop at {:#x} (no packet consumed)",
                                block.ip()
                            ),
                        }),
                    ));
                    prev_block = None;
                    stuck_rounds = 0;
                    break; // next PSB
                }
            }
            if trace_cpu == Some(cpu)
                && trace_left == 0
                && !trace_started
                && let Some((lo, _)) = dump_window
                && time.is_some_and(|t| t >= lo)
            {
                trace_started = true;
                trace_left = 120;
            }
            if trace_left > 0 {
                trace_left -= 1;
                eprintln!(
                    "  trace cpu{cpu}: block off {:?} t {:?} pid {cur_pid} ip {:#x} end {:#x} n {} class {:?} st {:?}",
                    decoder.offset(),
                    time,
                    block.ip(),
                    block.end_ip(),
                    block.ninsn(),
                    block_class(&block),
                    status
                );
            }
            if first_t.is_none() {
                first_t = time;
            }
            last_t = time.or(last_t);

            // An empty block carries only events and is not a branch source.
            // The previous block's terminating branch landed at this block's ip.
            let pending_branch =
                |target: u64,
                 prev: Option<(u64, u64, Class, Option<u64>, u8)>,
                 pid: u32,
                 tid: u32,
                 len_cache: &mut crate::decode::reconstruct::FastMap<(u32, u64), u8>,
                 batch: &mut Vec<(Option<u64>, RawRecord)>,
                 emitted: &mut u64,
                 extra: Flags|
                 -> bool {
                    let Some((_pip, pend, pclass, ptime, plen)) = prev else {
                        return false;
                    };
                    let taken = match pclass {
                        Class::CondJump => {
                            let len = if plen != 0 {
                                plen
                            } else {
                                *len_cache.entry((pid, pend)).or_insert_with(|| {
                                    insn_len_at(pend, pid, maps, images).unwrap_or(0)
                                })
                            };
                            len == 0 || target != pend.wrapping_add(u64::from(len))
                        }
                        Class::Unknown | Class::Other | Class::Ptwrite | Class::FarCall => false,
                        _ => true,
                    };
                    if taken {
                        batch.push((
                            ptime,
                            RawRecord::Sample(Sample {
                                pid,
                                tid,
                                cpu: Some(cpu),
                                time_ns: ptime,
                                event: SampleEvent::Branches,
                                ip: Some(pend),
                                addr: Some(target),
                                flags: class_flags(pclass).union(extra),
                                insn_len: None,
                                insn: InsnBytes::default(),
                            }),
                        ));
                        *emitted += 1;
                    }
                    taken
                };
            if block.ninsn() > 0
                && let Some((_pip, pend, pclass, ptime, plen)) = prev_block
            {
                let taken = match pclass {
                    Class::CondJump => {
                        // Not-taken conditionals are not branch samples in
                        // perf. libipt fills the size only for truncated
                        // instructions; otherwise decode it from the image.
                        let len = if plen != 0 {
                            plen
                        } else {
                            *len_cache.entry((cur_pid, pend)).or_insert_with(|| {
                                insn_len_at(pend, cur_pid, maps, images).unwrap_or(0)
                            })
                        };
                        len == 0 || block.ip() != pend.wrapping_add(u64::from(len))
                    }
                    Class::Unknown | Class::Other | Class::Ptwrite => false,
                    _ => true,
                };
                if taken {
                    batch.push((
                        ptime,
                        RawRecord::Sample(Sample {
                            pid: cur_pid,
                            tid: cur_tid,
                            cpu: Some(cpu),
                            time_ns: ptime,
                            event: SampleEvent::Branches,
                            ip: Some(pend),
                            addr: Some(block.ip()),
                            flags: class_flags(pclass),
                            insn_len: None,
                            insn: InsnBytes::default(),
                        }),
                    ));
                    last_branch_idx = Some(batch.len() - 1);
                    emitted += 1;
                }
            }

            // Instruction detail inside the requested window.
            if let Some((spid, stid, lo, hi)) = selection.instructions
                && cur_pid == spid
                && cur_tid == stid
                && time.is_some_and(|t| t >= lo && t < hi)
            {
                emit_instructions(
                    &block, cur_pid, cur_tid, cpu, time, maps, images, &mut batch,
                );
            }

            if block.ninsn() > 0 {
                prev_block = Some((
                    block.ip(),
                    block.end_ip(),
                    block_class(&block),
                    time,
                    block_last_size(&block),
                ));
            }
            // Events bound to this block (a syscall or interrupt ends it) and
            // events preceding the next one (trace enable) come after it.
            let mut st = status;
            while st.event_pending() {
                let Ok((ev, s2)) = decoder.event() else { break };
                st = s2;
                let ev_time = ev.tsc().map(|t| info.tsc_to_ns(t)).or(last_time);
                // A trace enable belongs to whoever the sideband says was
                // switched in by then, not to the task of the previous block.
                if let Some(t) = ev_time {
                    while sched_idx + 1 < schedule.len() && schedule[sched_idx + 1].0 <= t {
                        sched_idx += 1;
                    }
                    if let Some(&(st, pid, tid)) = schedule.get(sched_idx)
                        && st <= t
                    {
                        cur_pid = pid;
                        cur_tid = tid;
                    }
                }
                match ev.event_type() {
                    EventType::Enabled(en) => {
                        last_enable_ip = en.ip();
                        batch.push((
                            ev_time,
                            RawRecord::Sample(Sample {
                                pid: cur_pid,
                                tid: cur_tid,
                                cpu: Some(cpu),
                                time_ns: ev_time,
                                event: SampleEvent::Branches,
                                ip: Some(0),
                                addr: Some(en.ip()),
                                flags: Flags::TR_START.union(Flags::JMP),
                                insn_len: None,
                                insn: InsnBytes::default(),
                            }),
                        ));
                        prev_block = None;
                    }
                    EventType::Disabled(d) => {
                        // The block's terminating branch (or the previous
                        // block's, when this one is empty) landed where the
                        // trace stopped: an interrupt/trap at a call target
                        // must still record the call.
                        // A PGD without an ip after a direct branch: libipt
                        // walks on into the target block before it sees the
                        // disable, perf stops at the branch (`call tr end`).
                        // Fold the branch already emitted for this block.
                        if ev.ip_suppressed()
                            && block.ninsn() > 0
                            && !matches!(
                                block_class(&block),
                                Class::FarCall | Class::FarReturn | Class::FarJump
                            )
                            && let Some(i) = last_branch_idx
                            && let Some((_, RawRecord::Sample(sm))) = batch.get_mut(i)
                            && sm.addr == Some(block.ip())
                        {
                            sm.flags = sm.flags.union(Flags::TR_END);
                            last_branch_idx = None;
                            prev_block = None;
                            continue;
                        }
                        // perf folds a branch that leaves the traced range
                        // (address filter, PGD with an ip) into one
                        // `call tr end` sample; the callee is not entered.
                        let merged = !ev.ip_suppressed()
                            && pending_branch(
                                d.ip(),
                                prev_block,
                                cur_pid,
                                cur_tid,
                                &mut len_cache,
                                &mut batch,
                                &mut emitted,
                                Flags::TR_END,
                            );
                        if merged {
                            prev_block = None;
                            continue;
                        }
                        let class = prev_block.map(|b| b.2).unwrap_or(Class::Unknown);
                        let ip = if ev.ip_suppressed() {
                            prev_block.map(|b| b.1).unwrap_or(0)
                        } else {
                            d.ip()
                        };
                        batch.push((
                            ev_time,
                            RawRecord::Sample(Sample {
                                pid: cur_pid,
                                tid: cur_tid,
                                cpu: Some(cpu),
                                time_ns: ev_time,
                                event: SampleEvent::Branches,
                                ip: Some(ip),
                                addr: Some(0),
                                flags: Flags::TR_END.union(match class {
                                    Class::FarCall => Flags::SYSCALL,
                                    _ => Flags::EMPTY,
                                }),
                                insn_len: None,
                                insn: InsnBytes::default(),
                            }),
                        ));
                        prev_block = None;
                    }
                    EventType::AsnycDisabled(d) => {
                        {
                            pending_branch(
                                d.at(),
                                prev_block,
                                cur_pid,
                                cur_tid,
                                &mut len_cache,
                                &mut batch,
                                &mut emitted,
                                Flags::EMPTY,
                            );
                        }
                        batch.push((
                            ev_time,
                            RawRecord::Sample(Sample {
                                pid: cur_pid,
                                tid: cur_tid,
                                cpu: Some(cpu),
                                time_ns: ev_time,
                                event: SampleEvent::Branches,
                                ip: Some(d.at()),
                                addr: Some(0),
                                flags: Flags::TR_END.union(Flags::ASYNC),
                                insn_len: None,
                                insn: InsnBytes::default(),
                            }),
                        ));
                        prev_block = None;
                    }
                    EventType::AsyncBranch(b) => {
                        batch.push((
                            ev_time,
                            RawRecord::Sample(Sample {
                                pid: cur_pid,
                                tid: cur_tid,
                                cpu: Some(cpu),
                                time_ns: ev_time,
                                event: SampleEvent::Branches,
                                ip: Some(b.from()),
                                addr: Some(b.to()),
                                flags: Flags::HW_INT,
                                insn_len: None,
                                insn: InsnBytes::default(),
                            }),
                        ));
                        prev_block = None;
                    }
                    EventType::Overflow(_) => {
                        batch.push((
                            ev_time,
                            RawRecord::Lost(LostEvent {
                                time_ns: ev_time,
                                cpu: Some(cpu),
                                lost: 1,
                            }),
                        ));
                        prev_block = None;
                    }
                    _ => {}
                }
            }

            // Which task runs next: the time after the events is the time of
            // the next block, and its image must be set before decoding it.
            let time = decoder
                .time()
                .ok()
                .filter(|(tsc, _, _)| *tsc != u64::MAX)
                .map(|(tsc, _, _)| info.tsc_to_ns(tsc))
                .or(last_time);
            // Which task is running on this CPU now.
            if let Some(t) = time {
                while sched_idx + 1 < schedule.len() && schedule[sched_idx + 1].0 <= t {
                    sched_idx += 1;
                }
                if let Some(&(st, pid, tid)) = schedule.get(sched_idx)
                    && st <= t
                {
                    cur_pid = pid;
                    cur_tid = tid;
                }
            }
            // Before its exec a forked child runs the parent's code: key the
            // image on (pid, pre-exec) and give the pre-exec phase no image.
            let pre_exec = execs
                .get(&cur_pid)
                .is_some_and(|t| time.is_some_and(|now| now < *t));
            let image_key = if pre_exec {
                cur_pid | (1 << 31)
            } else {
                cur_pid
            };
            if image_key != set_image_for && cur_pid != u32::MAX {
                if let std::collections::hash_map::Entry::Vacant(slot) =
                    image_cache.entry(image_key)
                {
                    // Foreign: not in the traced tree, or its main executable
                    // (first exec mapping after exec) was never archived, e.g.
                    // the launch shim that forked the workload.
                    let pid_maps_all = maps.get(&cur_pid).map(Vec::as_slice).unwrap_or(&[]);
                    let exe_archived = pid_maps_all.first().is_none_or(|(_, _, _, path)| {
                        images.iter().any(|i| &i.identity.path == path)
                    });
                    let foreign =
                        pre_exec || wanted.is_some_and(|w| !w.contains(&cur_pid)) || !exe_archived;
                    if foreign {
                        foreign_keys.insert(image_key);
                    }
                    let pid_maps = if foreign {
                        &[][..]
                    } else {
                        maps.get(&cur_pid).map(Vec::as_slice).unwrap_or(&[])
                    };
                    slot.insert(build_image(
                        cur_pid,
                        pid_maps,
                        images,
                        section_cache,
                        section_ids,
                    )?);
                }
                // The image must outlive the decoder borrow; keep all images
                // alive in the cache and hand the decoder a fresh pointer.
                let img: *mut Image = image_cache.get_mut(&image_key).unwrap();
                // SAFETY: images live in `image_cache` for the whole decode and
                // are never removed; libipt only reads through the pointer.
                let _ = decoder.set_image(Some(unsafe { &mut *img }));
                set_image_for = image_key;
                cur_foreign = foreign_keys.contains(&image_key);
            }

            if batch.len() >= 2048 {
                flush(&mut batch)?;
                last_branch_idx = None;
            }
            if st.eos() {
                break;
            }
            if plan.is_some() && time.is_some_and(|t| t > window_hi) {
                // Past the window: nothing after this syncpoint is needed.
                plan = Some(std::collections::VecDeque::new());
                break;
            }
        }
    }
    flush(&mut batch)?;
    if debug {
        eprintln!(
            "native cpu{cpu}: {:.2}s {} bytes, {n_sync} psb syncs, {n_blocks} blocks, {emitted} branches, {n_errs} errors {err_codes:?} ({n_resync} resynced), schedule {} entries (first {:?}), time {first_t:?}..{last_t:?}",
            t_start.elapsed().as_secs_f64(),
            data.len(),
            schedule.len(),
            schedule.first()
        );
        let mut by_pid: Vec<_> = err_by_pid.into_iter().collect();
        by_pid.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        eprintln!(
            "native cpu{cpu}: errors by (pid, code) {:?}",
            &by_pid[..by_pid.len().min(10)]
        );
        eprintln!("native cpu{cpu}: nomap samples (pid, prev end ip) {nomap_samples:x?}");
    }
    Ok(emitted)
}

/// Length of the instruction at `ip` from the archived bytes.
fn insn_len_at(
    ip: u64,
    pid: u32,
    maps: &HashMap<u32, Vec<(u64, u64, u64, String)>>,
    images: &[ArchivedImage],
) -> Option<u8> {
    let (ii, rel) = locate(ip, pid, maps, images)?;
    let bytes = &images[ii].bytes;
    let off = usize::try_from(rel).ok()?;
    if off >= bytes.len() {
        return None;
    }
    let mut d = iced_x86::Decoder::with_ip(
        64,
        &bytes[off..bytes.len().min(off + 16)],
        ip,
        iced_x86::DecoderOptions::NONE,
    );
    let i = d.decode();
    (!i.is_invalid()).then_some(i.len() as u8)
}

fn locate(
    ip: u64,
    pid: u32,
    maps: &HashMap<u32, Vec<(u64, u64, u64, String)>>,
    images: &[ArchivedImage],
) -> Option<(usize, u64)> {
    let ms = maps.get(&pid)?;
    let (start, _len, pgoff, path) = ms
        .iter()
        .rev()
        .find(|(s, l, _, _)| ip >= *s && ip < s.saturating_add(*l))?;
    let ii = images.iter().position(|i| &i.identity.path == path)?;
    // File offset of `ip` under this mapping (what perf's pgoff means); the
    // archived bytes are the file, so this indexes them directly.
    Some((ii, ip.checked_sub(*start)?.checked_add(*pgoff)?))
}

#[allow(clippy::too_many_arguments)]
fn emit_instructions(
    block: &libipt::block::Block,
    pid: u32,
    tid: u32,
    cpu: u32,
    time: Option<u64>,
    maps: &HashMap<u32, Vec<(u64, u64, u64, String)>>,
    images: &[ArchivedImage],
    batch: &mut Vec<(Option<u64>, RawRecord)>,
) {
    let Some((ii, rel)) = locate(block.ip(), pid, maps, images) else {
        return;
    };
    let bytes = &images[ii].bytes;
    let Ok(off) = usize::try_from(rel) else {
        return;
    };
    if off >= bytes.len() {
        return;
    }
    let mut d = iced_x86::Decoder::with_ip(
        64,
        &bytes[off..],
        block.ip(),
        iced_x86::DecoderOptions::NONE,
    );
    let mut n = 0u16;
    while n < block.ninsn() && d.can_decode() {
        let ip = d.ip();
        let insn = d.decode();
        if insn.is_invalid() {
            break;
        }
        let len = insn.len();
        let mut ib = InsnBytes::default();
        let start = (ip - block.ip()) as usize + off;
        let raw = &bytes[start..(start + len).min(bytes.len())];
        ib.len = raw.len().min(15) as u8;
        ib.bytes[..usize::from(ib.len)].copy_from_slice(&raw[..usize::from(ib.len)]);
        batch.push((
            time,
            RawRecord::Sample(Sample {
                pid,
                tid,
                cpu: Some(cpu),
                time_ns: time,
                event: SampleEvent::Instructions,
                ip: Some(ip),
                addr: Some(0),
                flags: Flags::EMPTY,
                insn_len: Some(len as u8),
                insn: ib,
            }),
        ));
        n += 1;
        if ip == block.end_ip() {
            break;
        }
    }
}

/// Decode every CPU stream of `perf_data` on its own thread; the returned
/// receivers are one sideband stream (index 0) plus one per CPU, each
/// delivering time-ordered batches for the k-way merge.
#[allow(clippy::too_many_arguments)]
pub fn spawn_native_streams(
    perf_data: &Path,
    images: &[ArchivedImage],
    cpu_model: CpuModel,
    mtc_period: u8,
    selection: DecodeSelection,
    parallelism: u32,
) -> Result<NativeStreams> {
    let pd = crate::capture::perfdata::read_perf_data(perf_data)?;
    if pd.info.time_mult == 0 {
        return Err(Error::decode_failed(
            "perf.data has no Intel PT AUXTRACE_INFO (not a PT capture?)",
        ));
    }
    let file = std::fs::read(perf_data)?;
    let maps = mappings_by_pid(&pd);
    // Sideband stream first (merge takes sideband only from stream 0).
    let (stx, srx) = mpsc::sync_channel::<Vec<(Option<u64>, RawRecord)>>(64);
    let sb = sideband_records(&pd);
    let mut receivers = vec![srx];
    let mut handles = Vec::new();
    handles.push(std::thread::spawn(move || {
        for chunk in sb.chunks(2048) {
            if stx.send(chunk.to_vec()).is_err() {
                break;
            }
        }
        Ok(0)
    }));
    // Group blobs per CPU (a CPU may have several snapshot blobs; decode in order).
    let mut per_cpu: Vec<(u32, Vec<AuxBlob>)> = Vec::new();
    for b in &pd.blobs {
        if b.bytes == 0 {
            continue;
        }
        match per_cpu.iter_mut().find(|(c, _)| *c == b.cpu) {
            Some((_, v)) => v.push(*b),
            None => per_cpu.push((b.cpu, vec![*b])),
        }
    }
    // A big blob (one busy thread, or one CPU) would otherwise be one
    // serial stream: cut it at PSB packets into chunks so the workers
    // share it. A chunk starts at a syncpoint, which is where the decoder
    // resets anyway; the merge re-orders chunks by time.
    let target_chunks = parallelism.max(1) as usize;
    let mut items: Vec<(u32, Vec<AuxBlob>)> = Vec::new();
    for (cpu, blobs) in per_cpu {
        for b in blobs {
            let mut start = b.file_offset as usize;
            let end = start.saturating_add(b.bytes as usize).min(file.len());
            if selection.tail_div > 1 {
                // Keep the newest part: from the first PSB at or after the
                // cut point (the decoder can only start at a syncpoint).
                let keep_from = end - (end - start) / selection.tail_div as usize;
                if let Some(off) = psb_offsets(&file[start..end])
                    .into_iter()
                    .find(|o| start + o >= keep_from)
                {
                    start += off;
                }
            }
            for seg in split_at_psb(&file[start..end], target_chunks) {
                items.push((
                    cpu,
                    vec![AuxBlob {
                        cpu,
                        tid: b.tid,
                        bytes: seg.1 as u64,
                        file_offset: (start + seg.0) as u64,
                    }],
                ));
            }
        }
    }
    let per_cpu = items;
    let streams = per_cpu.len();
    let images: std::sync::Arc<Vec<ArchivedImage>> = std::sync::Arc::new(images.to_vec());
    let maps = std::sync::Arc::new(maps);
    let info = pd.info.clone();
    let wanted = std::sync::Arc::new(selection.pids.clone());
    let execs = std::sync::Arc::new(exec_times(&pd));
    if std::env::var_os("TRACE_MCP_NATIVE_DEBUG").is_some() {
        eprintln!(
            "native: decoding pids {:?}, {} blobs, execs {:?}",
            wanted,
            pd.blobs.len(),
            execs
        );
    }
    let pd = std::sync::Arc::new(pd);
    let file = std::sync::Arc::new(file);
    // Bounded parallelism: CPUs are dealt round-robin to worker threads; a
    // worker decodes its CPUs one after another into its own stream.
    let workers = (parallelism.max(1) as usize).min(per_cpu.len().max(1));
    let mut groups: Vec<Vec<(u32, Vec<AuxBlob>)>> = vec![Vec::new(); workers];
    for (i, item) in per_cpu.into_iter().enumerate() {
        groups[i % workers].push(item);
    }
    for group in groups.into_iter().filter(|g| !g.is_empty()) {
        let (tx, rx) = mpsc::sync_channel::<Vec<(Option<u64>, RawRecord)>>(64);
        receivers.push(rx);
        let schedules: Vec<(u32, Schedule)> = group
            .iter()
            .map(|(cpu, _)| (*cpu, schedule_for_cpu(&pd, *cpu)))
            .collect();
        let (images, maps, info, file, selection, wanted, execs) = (
            images.clone(),
            maps.clone(),
            info.clone(),
            file.clone(),
            selection.clone(),
            wanted.clone(),
            execs.clone(),
        );
        handles.push(std::thread::spawn(move || {
            let mut total = 0u64;
            // One section cache per worker: sections stay mapped (and keep
            // their block caches) across image switches and chunks.
            let (section_cache, section_ids) = fill_section_cache(&maps, &images)?;
            for ((cpu, blobs), (_, schedule)) in group.iter().zip(schedules.iter()) {
                for b in blobs {
                    let start = b.file_offset as usize;
                    let end = start.saturating_add(b.bytes as usize).min(file.len());
                    total += decode_blob(
                        &file[start..end],
                        *cpu,
                        &info,
                        cpu_model,
                        mtc_period,
                        schedule,
                        &maps,
                        &images,
                        &selection,
                        wanted.as_ref().as_ref(),
                        &execs,
                        &section_cache,
                        &section_ids,
                        &tx,
                    )?;
                }
            }
            Ok(total)
        }));
    }
    Ok((receivers, handles, streams))
}

/// `mtc_period` from an `intel_pt/.../u` event spec (default 3).
pub fn mtc_period_from_spec(spec: &str) -> u8 {
    spec.split([',', '/'])
        .find_map(|t| t.strip_prefix("mtc_period="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(3)
}

#[cfg(test)]
mod split_tests {
    use super::*;

    #[test]
    fn split_at_psb_cuts_only_at_syncpoints() {
        let psb: Vec<u8> = [0x02u8, 0x82].repeat(8);
        let mut data = vec![0u8; 5 << 20];
        for off in [0usize, 1 << 20, 3 << 20, (4 << 20) + 17] {
            data[off..off + 16].copy_from_slice(&psb);
        }
        assert_eq!(psb_offsets(&data).len(), 4);
        let parts = split_at_psb(&data, 8);
        assert!(parts.len() >= 2 && parts.len() <= 4, "{parts:?}");
        assert_eq!(parts[0].0, 0);
        let total: usize = parts.iter().map(|p| p.1).sum();
        assert_eq!(total, data.len());
        for p in &parts[1..] {
            assert_eq!(&data[p.0..p.0 + 16], &psb[..], "chunk must start at a PSB");
        }
        assert_eq!(split_at_psb(&data[..1 << 20], 8), vec![(0, 1 << 20)]);
    }
}
