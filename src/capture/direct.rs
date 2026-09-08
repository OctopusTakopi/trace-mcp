//! Direct per-thread Intel PT recorder.
//!
//! One `perf_event_open` Intel PT event per **thread** (`pid = tid`,
//! `cpu = -1`, no inherit): the AUX ring follows the thread across CPUs,
//! nothing foreign is recorded, and ring size is a per-thread budget. Rings
//! are mapped read-only, which is the kernel's snapshot (overwrite) mode.
//! Threads are discovered by the ptrace launch shim (`__launch --report`),
//! which keeps each new thread stopped until its event is open.
//!
//! The snapshot is written as a `perf.data`-compatible bundle (header,
//! one attr, `AUXTRACE_INFO`, synthesized `COMM`/`FORK`/`MMAP2`,
//! `ITRACE_START` per thread, one `AUXTRACE` blob per thread) so the native
//! reader in `perfdata.rs` and the decoder consume it unchanged.

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use crate::error::{Error, ErrorCode, Result};
use crate::model::EffectivePtTerms;

const SYSFS: &str = "/sys/bus/event_source/devices/intel_pt";

/// The Intel PT PMU as described by sysfs: event type and config bit layout.
#[derive(Debug, Clone)]
pub struct PtPmu {
    pub pmu_type: u32,
    /// format name -> (low bit, high bit) in `config`.
    bits: HashMap<String, (u32, u32)>,
    pub mtc_periods: u64,
    pub cycle_thresholds: u64,
    pub psb_periods: u64,
}

impl PtPmu {
    pub fn discover() -> Result<Self> {
        let read = |p: String| std::fs::read_to_string(p).map(|s| s.trim().to_string());
        let pmu_type = read(format!("{SYSFS}/type"))
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::new(ErrorCode::PtUnavailable, "intel_pt PMU not in sysfs"))?;
        let mut bits = HashMap::new();
        for e in std::fs::read_dir(format!("{SYSFS}/format"))
            .map_err(|e| Error::new(ErrorCode::PtUnavailable, format!("intel_pt format: {e}")))?
            .flatten()
        {
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(spec) = std::fs::read_to_string(e.path()) else {
                continue;
            };
            let Some(range) = spec.trim().strip_prefix("config:") else {
                continue;
            };
            let (lo, hi) = match range.split_once('-') {
                Some((a, b)) => (a.parse().unwrap_or(0), b.parse().unwrap_or(0)),
                None => {
                    let v = range.parse().unwrap_or(0);
                    (v, v)
                }
            };
            bits.insert(name, (lo, hi));
        }
        let hex = |n: &str| {
            read(format!("{SYSFS}/caps/{n}"))
                .ok()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0)
        };
        Ok(Self {
            pmu_type,
            bits,
            mtc_periods: hex("mtc_periods"),
            cycle_thresholds: hex("cycle_thresholds"),
            psb_periods: hex("psb_periods"),
        })
    }

    pub fn bit(&self, name: &str) -> Option<u32> {
        self.bits.get(name).map(|(lo, _)| *lo)
    }

    fn field(&self, name: &str, value: u64) -> u64 {
        match self.bits.get(name) {
            Some((lo, hi)) => {
                let width = hi - lo + 1;
                let mask = if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                };
                (value & mask) << lo
            }
            None => 0,
        }
    }

    /// `perf_event_attr.config` for the validated terms.
    pub fn config(&self, t: &EffectivePtTerms) -> u64 {
        let mut c = 0u64;
        let flag = |name: &str| self.bit(name).map_or(0, |b| 1u64 << b);
        // The PMU's own enable bit (`pt`, config:0), implicit in perf's
        // `intel_pt//` event.
        c |= flag("pt");
        if t.tsc {
            c |= flag("tsc");
        }
        if t.mtc {
            c |= flag("mtc");
            c |= self.field("mtc_period", u64::from(t.mtc_period.unwrap_or(3)));
        }
        if t.cyc {
            c |= flag("cyc");
            c |= self.field("cyc_thresh", u64::from(t.cyc_thresh.unwrap_or(0)));
        }
        if t.noretcomp {
            c |= flag("noretcomp");
        }
        if t.branch {
            c |= flag("branch");
        }
        c |= self.field("psb_period", u64::from(t.psb_period));
        c
    }
}

/// `struct perf_event_attr` (kernel ABI, version with `sig_data`/`config3`).
#[repr(C)]
#[derive(Clone, Copy)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    reserved_2: u16,
    aux_sample_size: u32,
    reserved_3: u32,
    sig_data: u64,
    config3: u64,
}

const ATTR_SIZE: u32 = 136;
const FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
const FLAG_EXCLUDE_HV: u64 = 1 << 6;
const FLAG_SAMPLE_ID_ALL: u64 = 1 << 18;
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
/// `_IOW('$', 6, char *)`.
const PERF_EVENT_IOC_SET_FILTER: libc::c_ulong = 0x4008_2406;
/// sample_type written into the bundle attr: TID|TIME|CPU|IDENTIFIER.
pub const BUNDLE_SAMPLE_TYPE: u64 = 0x10087;

// perf_event_mmap_page offsets.
const MP_CAPABILITIES: usize = 40;
const MP_TIME_SHIFT: usize = 50;
const MP_TIME_MULT: usize = 52;
// 56 is `time_offset`; `time_zero` follows it.
const MP_TIME_ZERO: usize = 64;
const MP_AUX_HEAD: usize = 1056;
const MP_AUX_OFFSET: usize = 1072;
const MP_AUX_SIZE: usize = 1080;

/// One thread's Intel PT event with its AUX ring.
pub struct PtEvent {
    fd: OwnedFd,
    base: *mut u8,
    base_len: usize,
    aux: *mut u8,
    aux_len: usize,
    pub pid: u32,
    pub tid: u32,
    /// Thread name at open time (`/proc/<pid>/task/<tid>/comm`).
    pub comm: String,
    /// Raw trace bytes in stream order once taken.
    pub snapshot: Option<Vec<u8>>,
    pub wrapped: bool,
}

// SAFETY: the mappings are only touched from the owning recorder task; the
// kernel writes the AUX area and updates the metadata page concurrently,
// which is read with volatile loads.
unsafe impl Send for PtEvent {}

impl PtEvent {
    /// Open the event on `tid` (stopped or running) and map its rings.
    pub fn open(
        pmu: &PtPmu,
        terms: &EffectivePtTerms,
        pid: u32,
        tid: u32,
        aux_bytes: u64,
        filter: Option<&str>,
    ) -> Result<Self> {
        let page = crate::capture::perf::page_size() as usize;
        let aux_len = (aux_bytes as usize).max(page * 2).next_power_of_two();
        // SAFETY: plain-old-data struct.
        let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
        attr.type_ = pmu.pmu_type;
        attr.size = ATTR_SIZE;
        attr.config = pmu.config(terms);
        attr.sample_type = 0;
        attr.flags = FLAG_EXCLUDE_KERNEL | FLAG_EXCLUDE_HV | FLAG_SAMPLE_ID_ALL;
        // SAFETY: attr is fully initialised; the syscall validates it.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const PerfEventAttr,
                tid as libc::pid_t,
                -1 as libc::c_int,
                -1 as libc::c_int,
                PERF_FLAG_FD_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            let code = match err.raw_os_error() {
                Some(libc::EACCES) | Some(libc::EPERM) => ErrorCode::PermissionDenied,
                _ => ErrorCode::PtUnavailable,
            };
            return Err(
                Error::new(code, format!("perf_event_open(intel_pt, tid {tid}): {err}"))
                    .with_next("check /proc/sys/kernel/perf_event_paranoid and RLIMIT_MEMLOCK"),
            );
        }
        // SAFETY: fd is a fresh, owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        if let Some(f) = filter {
            // perf's clause syntax is `filter 0xoff/0xsize @ file`; the
            // kernel's parser wants `0xoff/0xsize@file` (no blanks around
            // `@`) and resolves file offsets against the task's mappings.
            let kernel_form: String = f
                .split(',')
                .map(|clause| {
                    clause
                        .trim()
                        .replace(" @ ", "@")
                        .replace(" @", "@")
                        .replace("@ ", "@")
                })
                .collect::<Vec<_>>()
                .join(",");
            let c = std::ffi::CString::new(kernel_form.as_str())
                .map_err(|_| Error::invalid_argument("address filter contains NUL"))?;
            // SAFETY: valid fd and NUL-terminated string.
            let rc = unsafe { libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_SET_FILTER, c.as_ptr()) };
            if rc < 0 {
                return Err(Error::new(
                    ErrorCode::UnsupportedPtConfig,
                    format!(
                        "address filter {f:?} rejected: {}",
                        std::io::Error::last_os_error()
                    ),
                ));
            }
        }
        let base_len = page * 2;
        // SAFETY: mmap of the event's metadata + one data page.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                base_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(Error::new(
                ErrorCode::PtUnavailable,
                format!("mmap perf ring: {}", std::io::Error::last_os_error()),
            ));
        }
        let base = base.cast::<u8>();
        // SAFETY: base_len bytes are mapped; these are u64 fields of the page.
        unsafe {
            std::ptr::write_volatile(base.add(MP_AUX_OFFSET).cast::<u64>(), base_len as u64);
            std::ptr::write_volatile(base.add(MP_AUX_SIZE).cast::<u64>(), aux_len as u64);
        }
        // SAFETY: read-only AUX mapping selects snapshot (overwrite) mode.
        let aux = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                aux_len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                base_len as libc::off_t,
            )
        };
        if aux == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            // SAFETY: base was mapped above.
            unsafe {
                libc::munmap(base.cast(), base_len);
            }
            return Err(Error::new(
                ErrorCode::PtUnavailable,
                format!("mmap AUX ring ({aux_len} bytes): {err}"),
            )
            .with_next("lower aux_bytes_per_buffer or raise RLIMIT_MEMLOCK"));
        }
        // SAFETY: valid fd.
        unsafe {
            libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_ENABLE, 0);
        }
        Ok(Self {
            fd,
            base,
            base_len,
            aux: aux.cast::<u8>(),
            aux_len,
            pid,
            tid,
            comm: std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm"))
                .map(|c| c.trim().to_string())
                .unwrap_or_default(),
            snapshot: None,
            wrapped: false,
        })
    }

    fn meta_u64(&self, off: usize) -> u64 {
        // SAFETY: off is within the mapped metadata page.
        unsafe { std::ptr::read_volatile(self.base.add(off).cast::<u64>()) }
    }

    /// (time_shift, time_mult, time_zero, cap_user_time_zero) from the
    /// metadata page, the same values perf stores in `AUXTRACE_INFO`.
    pub fn timing(&self) -> (u16, u32, u64, bool) {
        // SAFETY: offsets are within the mapped metadata page.
        let (shift, mult) = unsafe {
            (
                std::ptr::read_volatile(self.base.add(MP_TIME_SHIFT).cast::<u16>()),
                std::ptr::read_volatile(self.base.add(MP_TIME_MULT).cast::<u32>()),
            )
        };
        let zero = self.meta_u64(MP_TIME_ZERO);
        let caps = self.meta_u64(MP_CAPABILITIES);
        (shift, mult, zero, caps & (1 << 4) != 0)
    }

    /// Stop the event and copy the ring in stream order (oldest first).
    pub fn take_snapshot(&mut self) {
        if self.snapshot.is_some() {
            return;
        }
        // SAFETY: valid fd.
        unsafe {
            libc::ioctl(self.fd.as_raw_fd(), PERF_EVENT_IOC_DISABLE, 0);
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        let head = self.meta_u64(MP_AUX_HEAD);
        let len = self.aux_len as u64;
        let pos = (head % len) as usize;
        // SAFETY: aux_len bytes are mapped read-only.
        let ring = unsafe { std::slice::from_raw_parts(self.aux, self.aux_len) };
        // In snapshot mode aux_head may be reported modulo the ring; the
        // pages start zeroed, so a written tail means the ring wrapped
        // (perf's intel_pt_find_snapshot uses the same observation).
        let wrapped = head >= len || ring[self.aux_len - 64..].iter().any(|b| *b != 0);
        let mut out = Vec::with_capacity(if wrapped { self.aux_len } else { pos });
        if wrapped {
            out.extend_from_slice(&ring[pos..]);
        }
        out.extend_from_slice(&ring[..pos]);
        self.wrapped = wrapped;
        self.snapshot = Some(out);
    }
}

impl Drop for PtEvent {
    fn drop(&mut self) {
        // SAFETY: both regions were mapped by `open` with these lengths.
        unsafe {
            libc::munmap(self.aux.cast(), self.aux_len);
            libc::munmap(self.base.cast(), self.base_len);
        }
    }
}

/// A process the bundle describes: comm, exe and executable mappings as
/// read from `/proc` while the process still existed.
#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    /// (start, len, pgoff, path) executable mappings.
    pub maps: Vec<(u64, u64, u64, String)>,
    /// perf-clock time of the last exec, when one was observed.
    pub exec_ns: Option<u64>,
}

impl ProcInfo {
    /// Read `/proc/<pid>` now (works during a ptrace exit-stop as well).
    pub fn read(pid: u32) -> Option<Self> {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()?
            .trim()
            .to_string();
        let ppid = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|st| {
                st.lines()
                    .find_map(|l| l.strip_prefix("PPid:"))
                    .and_then(|v| v.trim().parse().ok())
            })
            .unwrap_or(0);
        let maps_txt = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
        let mut maps = Vec::new();
        for line in maps_txt.lines() {
            let mut it = line.split_whitespace();
            let (Some(range), Some(perms), Some(off), _dev, _ino) =
                (it.next(), it.next(), it.next(), it.next(), it.next())
            else {
                continue;
            };
            if !perms.contains('x') {
                continue;
            }
            let path = it.next().unwrap_or("").to_string();
            if path.is_empty() || (!path.starts_with('/') && path != "[vdso]") {
                continue;
            }
            let Some((a, b)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end), Ok(pgoff)) = (
                u64::from_str_radix(a, 16),
                u64::from_str_radix(b, 16),
                u64::from_str_radix(off, 16),
            ) else {
                continue;
            };
            maps.push((start, end - start, pgoff, path));
        }
        Some(Self {
            pid,
            ppid,
            comm,
            maps,
            exec_ns: None,
        })
    }
}

/// perf's TSC to perf-clock conversion (`tsc_to_perf_time`).
pub fn tsc_to_ns(tsc: u64, shift: u16, mult: u32, zero: u64) -> u64 {
    let quot = tsc >> shift;
    let rem = tsc & ((1u64 << shift) - 1);
    zero.wrapping_add(quot.wrapping_mul(u64::from(mult)))
        .wrapping_add((rem.wrapping_mul(u64::from(mult))) >> shift)
}

/// The perf-clock time now, as the bundle's trace timestamps will read it.
fn now_ns(ev: &PtEvent) -> u64 {
    let (shift, mult, zero, _) = ev.timing();
    #[cfg(target_arch = "x86_64")]
    // SAFETY: rdtsc has no preconditions on x86_64.
    let tsc = unsafe { std::arch::x86_64::_rdtsc() };
    #[cfg(not(target_arch = "x86_64"))]
    let tsc = 0u64;
    tsc_to_ns(tsc, shift, mult, zero)
}

/// tsc/ctc ratio from CPUID leaf 0x15 (numerator, denominator).
fn tsc_ctc_ratio() -> (u64, u64) {
    #[cfg(target_arch = "x86_64")]
    {
        let r = std::arch::x86_64::__cpuid(0x15);
        (u64::from(r.ebx), u64::from(r.eax))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        (0, 0)
    }
}

fn header(type_: u32, misc: u16, size: usize) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[..4].copy_from_slice(&type_.to_le_bytes());
    h[4..6].copy_from_slice(&misc.to_le_bytes());
    h[6..8].copy_from_slice(&(size as u16).to_le_bytes());
    h
}

/// Sample-id trailer for `BUNDLE_SAMPLE_TYPE`.
fn trailer(pid: u32, tid: u32, time: u64, cpu: u32) -> Vec<u8> {
    let mut t = Vec::with_capacity(32);
    t.extend_from_slice(&pid.to_le_bytes());
    t.extend_from_slice(&tid.to_le_bytes());
    t.extend_from_slice(&time.to_le_bytes());
    t.extend_from_slice(&cpu.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    t.extend_from_slice(&0u64.to_le_bytes());
    t
}

fn record(type_: u32, misc: u16, body: &[u8], trail: Option<Vec<u8>>) -> Vec<u8> {
    let trail = trail.unwrap_or_default();
    let size = 8 + body.len() + trail.len();
    let mut r = Vec::with_capacity(size);
    r.extend_from_slice(&header(type_, misc, size));
    r.extend_from_slice(body);
    r.extend_from_slice(&trail);
    r
}

fn padded(s: &str, min: usize) -> Vec<u8> {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    while b.len() < min || !b.len().is_multiple_of(8) {
        b.push(0);
    }
    b
}

/// Write the snapshot bundle. `events` must have their snapshots taken.
/// Each event becomes one `AUXTRACE` blob on a pseudo CPU (its index) with
/// an `ITRACE_START` at time 0, which is how the decoder attributes it.
pub fn write_bundle(
    path: &Path,
    pmu: &PtPmu,
    terms: &EffectivePtTerms,
    events: &[PtEvent],
    procs: &[ProcInfo],
    root_pid: Option<u32>,
) -> Result<u64> {
    const MISC_USER: u16 = 2;
    const MISC_COMM_EXEC: u16 = 1 << 13;
    let mut data: Vec<u8> = Vec::new();

    // AUXTRACE_INFO (type 70): Intel PT private words.
    let (shift, mult, zero, cap_zero) = events
        .first()
        .map(PtEvent::timing)
        .unwrap_or((0, 0, 0, false));
    let (ratio_n, ratio_d) = tsc_ctc_ratio();
    let words: [u64; 17] = [
        u64::from(pmu.pmu_type),
        u64::from(shift),
        u64::from(mult),
        zero,
        u64::from(cap_zero),
        pmu.bit("tsc").map_or(0, |b| 1u64 << b),
        pmu.bit("noretcomp").map_or(0, |b| 1u64 << b),
        0, // have_sched_switch
        1, // snapshot_mode
        0, // per_cpu_mmaps
        pmu.bit("mtc").map_or(0, |b| 1u64 << b),
        pmu.mtc_periods,
        ratio_n,
        ratio_d,
        pmu.bit("cyc").map_or(0, |b| 1u64 << b),
        0, // max_nonturbo_ratio (needs MSR access; CYC timing unused)
        0, // filter string length
    ];
    let mut body = Vec::with_capacity(8 + 17 * 8);
    body.extend_from_slice(&1u32.to_le_bytes()); // PERF_AUXTRACE_INTEL_PT
    body.extend_from_slice(&0u32.to_le_bytes());
    for w in words {
        body.extend_from_slice(&w.to_le_bytes());
    }
    data.extend(record(70, 0, &body, None));

    // Processes. The pid tracker learns the tree from records, not names:
    // FORK(pid, ppid) for every non-root process, `perf-exec` for the root
    // (what perf record emits for its forked child), then COMM (exec,
    // stamped with the exec time when one was observed) and MMAP2 per
    // mapping.
    for p in procs {
        if Some(p.pid) != root_pid {
            let mut b = Vec::new();
            b.extend_from_slice(&p.pid.to_le_bytes());
            b.extend_from_slice(&p.ppid.to_le_bytes());
            b.extend_from_slice(&p.pid.to_le_bytes());
            b.extend_from_slice(&p.ppid.to_le_bytes());
            b.extend_from_slice(&0u64.to_le_bytes());
            data.extend(record(7, 0, &b, Some(trailer(p.pid, p.pid, 0, 0))));
        } else {
            let mut b = Vec::new();
            b.extend_from_slice(&p.pid.to_le_bytes());
            b.extend_from_slice(&p.pid.to_le_bytes());
            b.extend(padded("perf-exec", 16));
            data.extend(record(3, 0, &b, Some(trailer(p.pid, p.pid, 0, 0))));
        }
        let misc = if p.exec_ns.is_some() {
            MISC_COMM_EXEC
        } else {
            0
        };
        let t = p.exec_ns.unwrap_or(0);
        let mut b = Vec::new();
        b.extend_from_slice(&p.pid.to_le_bytes());
        b.extend_from_slice(&p.pid.to_le_bytes());
        b.extend(padded(&p.comm, 16));
        data.extend(record(3, misc, &b, Some(trailer(p.pid, p.pid, t, 0))));
        for (start, len, pgoff, path) in &p.maps {
            let mut b = Vec::new();
            b.extend_from_slice(&p.pid.to_le_bytes());
            b.extend_from_slice(&p.pid.to_le_bytes());
            b.extend_from_slice(&start.to_le_bytes());
            b.extend_from_slice(&len.to_le_bytes());
            b.extend_from_slice(&pgoff.to_le_bytes());
            b.extend_from_slice(&[0u8; 8]); // maj, min
            b.extend_from_slice(&[0u8; 16]); // ino, ino_generation
            b.extend_from_slice(&5u32.to_le_bytes()); // prot: READ|EXEC
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend(padded(path, 8));
            data.extend(record(10, MISC_USER, &b, Some(trailer(p.pid, p.pid, t, 0))));
        }
    }
    // Threads: FORK (pid tree), COMM, and ITRACE_START (pseudo-CPU
    // attribution).
    for (i, e) in events.iter().enumerate() {
        if e.tid != e.pid {
            let mut b = Vec::new();
            b.extend_from_slice(&e.pid.to_le_bytes());
            b.extend_from_slice(&e.pid.to_le_bytes()); // ppid
            b.extend_from_slice(&e.tid.to_le_bytes());
            b.extend_from_slice(&e.pid.to_le_bytes()); // ptid
            b.extend_from_slice(&0u64.to_le_bytes());
            data.extend(record(7, 0, &b, Some(trailer(e.pid, e.tid, 0, i as u32))));
            if !e.comm.is_empty() {
                let mut b = Vec::new();
                b.extend_from_slice(&e.pid.to_le_bytes());
                b.extend_from_slice(&e.tid.to_le_bytes());
                b.extend(padded(&e.comm, 16));
                data.extend(record(3, 0, &b, Some(trailer(e.pid, e.tid, 0, i as u32))));
            }
        }
        let mut b = Vec::new();
        b.extend_from_slice(&e.pid.to_le_bytes());
        b.extend_from_slice(&e.tid.to_le_bytes());
        data.extend(record(12, 0, &b, Some(trailer(e.pid, e.tid, 0, i as u32))));
    }
    // AUXTRACE blobs.
    let mut raw_total = 0u64;
    for (i, e) in events.iter().enumerate() {
        let Some(blob) = e.snapshot.as_ref() else {
            continue;
        };
        if blob.is_empty() {
            continue;
        }
        raw_total += blob.len() as u64;
        let mut b = Vec::with_capacity(40);
        b.extend_from_slice(&(blob.len() as u64).to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes()); // offset
        b.extend_from_slice(&0u64.to_le_bytes()); // reference
        b.extend_from_slice(&(i as u32).to_le_bytes()); // idx
        b.extend_from_slice(&e.tid.to_le_bytes());
        b.extend_from_slice(&(i as u32).to_le_bytes()); // cpu
        b.extend_from_slice(&0u32.to_le_bytes());
        data.extend(record(71, 0, &b, None));
        data.extend_from_slice(blob);
    }

    // Header + one attr (+ its id list) + data.
    // SAFETY: plain-old-data struct.
    let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
    attr.type_ = pmu.pmu_type;
    attr.size = ATTR_SIZE;
    attr.config = pmu.config(terms);
    attr.sample_type = BUNDLE_SAMPLE_TYPE;
    attr.flags = FLAG_EXCLUDE_KERNEL | FLAG_EXCLUDE_HV | FLAG_SAMPLE_ID_ALL;
    // PerfEventAttr is repr(C) plain data of ATTR_SIZE bytes.
    let attr_bytes: [u8; ATTR_SIZE as usize] =
        // SAFETY: same size, no padding-sensitive reads (all bytes valid).
        unsafe { std::mem::transmute::<PerfEventAttr, [u8; ATTR_SIZE as usize]>(attr) };
    let header_len = 104u64;
    let ids_off = header_len + ATTR_SIZE as u64 + 16;
    let data_off = ids_off + 8;
    let mut out = Vec::with_capacity(data.len() + 512);
    out.extend_from_slice(b"PERFILE2");
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&(ATTR_SIZE as u64 + 16).to_le_bytes());
    out.extend_from_slice(&header_len.to_le_bytes()); // attrs.offset
    out.extend_from_slice(&(ATTR_SIZE as u64 + 16).to_le_bytes()); // attrs.size
    out.extend_from_slice(&data_off.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&[0u8; 16]); // event_types
    out.extend_from_slice(&[0u8; 32]); // adds_features
    out.extend_from_slice(&attr_bytes);
    out.extend_from_slice(&ids_off.to_le_bytes());
    out.extend_from_slice(&8u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // the id
    out.extend_from_slice(&data);
    let mut f = std::fs::File::create(path)?;
    f.write_all(&out)?;
    Ok(raw_total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_layout_is_136_bytes() {
        assert_eq!(std::mem::size_of::<PerfEventAttr>(), ATTR_SIZE as usize);
    }

    #[test]
    fn bundle_round_trips_through_the_reader() {
        let pmu = PtPmu {
            pmu_type: 11,
            bits: [
                ("tsc".to_string(), (10, 10)),
                ("mtc".to_string(), (9, 9)),
                ("mtc_period".to_string(), (14, 17)),
                ("psb_period".to_string(), (24, 27)),
                ("branch".to_string(), (13, 13)),
                ("noretcomp".to_string(), (11, 11)),
                ("cyc".to_string(), (1, 1)),
            ]
            .into_iter()
            .collect(),
            mtc_periods: 0x249,
            cycle_thresholds: 0x3fff,
            psb_periods: 0x3f,
        };
        let caps = crate::model::PtCapabilities {
            mtc: true,
            mtc_periods_mask: 0x249,
            psb_cyc: true,
            psb_periods_mask: 0x3f,
            cycle_thresholds_mask: 0x3fff,
            ptwrite: false,
            tnt_disable: false,
            num_address_ranges: 2,
            event_type: 11,
        };
        let terms =
            EffectivePtTerms::resolve(crate::model::TimingProfile::Balanced, &caps, 1 << 20)
                .unwrap();
        assert_eq!(pmu.config(&terms) & (1 << 13), 1 << 13, "branch bit");
        let procs = vec![
            ProcInfo {
                pid: 42,
                ppid: 7,
                comm: "cargo".into(),
                maps: vec![(0x1000, 0x2000, 0, "/bin/cargo".into())],
                exec_ns: Some(1000),
            },
            ProcInfo {
                pid: 43,
                ppid: 42,
                comm: "pt_fixture".into(),
                maps: vec![(0x1000, 0x2000, 0, "/bin/pt_fixture".into())],
                exec_ns: Some(2000),
            },
        ];
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("perf.data");
        write_bundle(&p, &pmu, &terms, &[], &procs, Some(42)).unwrap();
        let pd = crate::capture::perfdata::read_perf_data(&p).unwrap();
        assert_eq!(pd.sample_type, BUNDLE_SAMPLE_TYPE);
        assert_eq!(pd.info.mtc_bit, 1 << 9);
        assert!(pd.sideband.iter().any(|s| matches!(
            s,
            crate::capture::perfdata::Sideband::Comm {
                pid: 42,
                exec: true,
                ..
            }
        )));
        assert!(pd.sideband.iter().any(|s| matches!(
            s,
            crate::capture::perfdata::Sideband::Mmap {
                pid: 42,
                exec: true,
                ..
            }
        )));
    }
}

/// What a report line asked the session to do besides acknowledging it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportAction {
    /// A thread got its event; `pid` is its process (harvest its maps).
    Opened {
        pid: u32,
    },
    /// A process leader is at its exit stop: its maps are still readable.
    LeaderExit {
        pid: u32,
    },
    None,
}

/// Reader side of the shim's report FIFO.
pub type ReportRx = tokio::io::BufReader<tokio::net::unix::pipe::Receiver>;

/// Next report line; `None` (and the reader dropped) once the FIFO closes.
pub async fn read_report(rx: &mut Option<ReportRx>, line: &mut String) -> Option<String> {
    use tokio::io::AsyncBufReadExt;
    let r = rx.as_mut()?;
    line.clear();
    match r.read_line(line).await {
        Ok(0) | Err(_) => {
            *rx = None;
            None
        }
        Ok(_) => Some(line.trim().to_string()),
    }
}

/// Drives the launch shim in report mode and owns the per-thread events.
pub struct DirectRecorder {
    /// The launch shim (launch targets) or none (attach targets).
    pub child: Option<tokio::process::Child>,
    /// Attached process, polled for new threads and for exit.
    attach: Option<u32>,
    pub pid: u32,
    report_fifo: std::path::PathBuf,
    rx: Option<ReportRx>,
    pmu: PtPmu,
    terms: EffectivePtTerms,
    /// Ring size per thread and the total AUX budget for all threads.
    aux_bytes: u64,
    aux_budget: u64,
    aux_used: u64,
    /// perf-style address filter clauses applied to every event.
    pub filter: Option<String>,
    /// The first exec'd process (launch) or the attached pid: the root of
    /// the traced tree.
    pub root_pid: Option<u32>,
    pub events: Vec<PtEvent>,
    pub procs: HashMap<u32, ProcInfo>,
    pub notes: Vec<String>,
    pub argv: Vec<String>,
}

impl DirectRecorder {
    /// Spawn `trace-mcp __launch --report <fifo> [--cpus] [--symbol/--hits
    /// --notify] -- argv` in its own process group.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        report_fifo: &Path,
        cpus: Option<&[u32]>,
        symbol_trigger: Option<(&str, u32)>,
        notify_fifo: Option<&Path>,
        argv: &[String],
        cwd: Option<&Path>,
        env: &std::collections::BTreeMap<String, String>,
        stdout_path: &Path,
        stderr_path: &Path,
        pmu: PtPmu,
        terms: EffectivePtTerms,
        aux_bytes: u64,
        aux_budget: u64,
    ) -> Result<Self> {
        crate::capture::trigger::make_fifo(report_fifo)?;
        crate::capture::trigger::make_fifo(&crate::capture::trigger::ack_path(report_fifo))?;
        let rx = tokio::net::unix::pipe::OpenOptions::new()
            .read_write(true)
            .open_receiver(report_fifo)
            .map_err(|e| Error::new(ErrorCode::NotReady, format!("open report fifo: {e}")))?;
        let me = std::env::current_exe()
            .map_err(|e| Error::new(ErrorCode::NotFound, format!("current_exe: {e}")))?;
        let mut args: Vec<String> = vec![
            "__launch".into(),
            "--report".into(),
            report_fifo.display().to_string(),
        ];
        if let Some(c) = cpus {
            args.push("--cpus".into());
            args.push(
                c.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some((sym, hits)) = symbol_trigger {
            args.push("--symbol".into());
            args.push(sym.to_string());
            args.push("--hits".into());
            args.push(hits.to_string());
        }
        if let Some(f) = notify_fifo {
            args.push("--notify".into());
            args.push(f.display().to_string());
        }
        args.push("--".into());
        args.extend(argv.iter().cloned());
        let mut cmd = tokio::process::Command::new(&me);
        cmd.args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(std::fs::File::create(
                stdout_path,
            )?))
            .stderr(std::process::Stdio::from(std::fs::File::create(
                stderr_path,
            )?))
            .kill_on_drop(false)
            .process_group(0);
        cmd.envs(env);
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        if let Some(f) = notify_fifo {
            cmd.env(crate::capture::trigger::TRIGGER_ENV, f);
        }
        let child = cmd
            .spawn()
            .map_err(|e| Error::new(ErrorCode::NotReady, format!("spawn launch shim: {e}")))?;
        let pid = child
            .id()
            .ok_or_else(|| Error::new(ErrorCode::NotReady, "launch shim exited early"))?;
        let mut full = vec![me.display().to_string()];
        full.extend(args);
        Ok(Self {
            child: Some(child),
            attach: None,
            pid,
            report_fifo: report_fifo.to_path_buf(),
            rx: Some(tokio::io::BufReader::new(rx)),
            pmu,
            terms,
            aux_bytes,
            aux_budget,
            aux_used: 0,
            filter: None,
            root_pid: None,
            events: Vec::new(),
            procs: HashMap::new(),
            notes: Vec::new(),
            argv: full,
        })
    }

    /// Attach to a running process: one event per thread that exists now;
    /// threads that appear later are picked up by `poll_threads` (their
    /// first moments are not traced, which the diagnostics say).
    pub fn attach(
        pid: u32,
        pmu: PtPmu,
        terms: EffectivePtTerms,
        aux_bytes: u64,
        aux_budget: u64,
    ) -> Result<Self> {
        let mut rec = Self {
            child: None,
            attach: Some(pid),
            pid,
            report_fifo: std::path::PathBuf::new(),
            rx: None,
            pmu,
            terms,
            aux_bytes,
            aux_budget,
            aux_used: 0,
            filter: None,
            root_pid: Some(pid),
            events: Vec::new(),
            procs: HashMap::new(),
            notes: Vec::new(),
            argv: vec![format!("direct-attach pid {pid}")],
        };
        if rec.poll_threads() == 0 {
            return Err(Error::new(
                ErrorCode::NotFound,
                format!("pid {pid}: no threads to trace (is it alive?)"),
            ));
        }
        if let Some(p) = ProcInfo::read(pid) {
            rec.procs.insert(pid, p);
        }
        Ok(rec)
    }

    /// Open events for threads of the attached process not traced yet.
    /// Returns how many are traced afterwards.
    pub fn poll_threads(&mut self) -> usize {
        let Some(pid) = self.attach else {
            return self.events.len();
        };
        let Ok(dir) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
            return self.events.len();
        };
        let late = !self.events.is_empty();
        for e in dir.flatten() {
            let Ok(tid) = e.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if self.events.iter().any(|ev| ev.tid == tid) {
                continue;
            }
            let remaining = self.aux_budget.saturating_sub(self.aux_used);
            let size = self.aux_bytes.min(remaining);
            if size < 65536 {
                self.notes
                    .push(format!("thread {tid} not traced: AUX budget exhausted"));
                continue;
            }
            let size = 1u64 << (63 - size.leading_zeros());
            match PtEvent::open(
                &self.pmu,
                &self.terms,
                pid,
                tid,
                size,
                self.filter.as_deref(),
            ) {
                Ok(ev) => {
                    self.aux_used += ev.aux_len as u64;
                    self.events.push(ev);
                    if late {
                        self.notes.push(format!(
                            "thread {tid} appeared after attach: traced from its discovery, not its start"
                        ));
                    }
                }
                Err(err) => self
                    .notes
                    .push(format!("thread {tid} could not be traced: {err}")),
            }
        }
        self.events.len()
    }

    /// Hand the report FIFO reader to the session loop (it is polled in a
    /// `select!` arm separate from the recorder itself).
    pub fn take_report_rx(&mut self) -> Option<ReportRx> {
        self.rx.take()
    }

    fn tgid_of(tid: u32) -> u32 {
        std::fs::read_to_string(format!("/proc/{tid}/status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Tgid:"))
                    .and_then(|v| v.trim().parse().ok())
            })
            .unwrap_or(tid)
    }

    /// Act on one report line, then acknowledge it so the shim continues
    /// the stopped thread.
    pub fn handle_report(&mut self, line: &str) -> ReportAction {
        let mut it = line.split_whitespace();
        let action = match (it.next(), it.next().and_then(|v| v.parse::<u32>().ok())) {
            (Some("exec"), Some(tid)) if self.events.iter().any(|e| e.tid == tid) => {
                // A later exec of a traced process: from now on its trace
                // is the new image; what came before is decoded as foreign.
                let pid = Self::tgid_of(tid);
                let t = self.events.iter().find(|e| e.tid == tid).map(now_ns);
                if let Some(mut p) = ProcInfo::read(pid) {
                    p.exec_ns = t;
                    self.procs.insert(pid, p);
                }
                ReportAction::Opened { pid }
            }
            (Some(kind @ ("exec" | "thread")), Some(pid)) => {
                let tid = pid;
                let pid = Self::tgid_of(tid);
                if kind == "exec" && self.root_pid.is_none() {
                    self.root_pid = Some(pid);
                }
                // Per-thread ring within the total budget: later threads get
                // what is left (power of two, at least 64 KiB).
                let remaining = self.aux_budget.saturating_sub(self.aux_used);
                let size = self.aux_bytes.min(remaining);
                let size = if size >= 65536 {
                    1u64 << (63 - size.leading_zeros())
                } else {
                    0
                };
                if self.events.iter().any(|e| e.tid == tid) {
                    ReportAction::None
                } else if size == 0 {
                    self.notes.push(format!(
                        "thread {tid} not traced: AUX budget {} exhausted",
                        self.aux_budget
                    ));
                    ReportAction::None
                } else {
                    match PtEvent::open(
                        &self.pmu,
                        &self.terms,
                        pid,
                        tid,
                        size,
                        self.filter.as_deref(),
                    ) {
                        Ok(ev) => {
                            self.aux_used += ev.aux_len as u64;
                            let exec_ns = (kind == "exec").then(|| now_ns(&ev));
                            self.events.push(ev);
                            if let Some(mut p) = ProcInfo::read(pid) {
                                p.exec_ns = exec_ns;
                                self.procs.insert(pid, p);
                            } else if let Some(p) = self.procs.get_mut(&pid) {
                                p.exec_ns = exec_ns.or(p.exec_ns);
                            }
                            ReportAction::Opened { pid }
                        }
                        Err(e) => {
                            self.notes
                                .push(format!("thread {tid} could not be traced: {e}"));
                            ReportAction::None
                        }
                    }
                }
            }
            (Some("exit"), Some(tid)) => {
                if let Some(ev) = self.events.iter_mut().find(|e| e.tid == tid) {
                    ev.take_snapshot();
                }
                // A thread-group leader at its exit stop: maps still readable.
                let leader = (Self::tgid_of(tid) == tid).then_some(tid);
                match leader {
                    Some(pid) => {
                        if let Some(mut p) = ProcInfo::read(pid) {
                            p.exec_ns = self.procs.get(&pid).and_then(|old| old.exec_ns);
                            self.procs.insert(pid, p);
                        }
                        ReportAction::LeaderExit { pid }
                    }
                    None => ReportAction::None,
                }
            }
            (Some("error"), _) => {
                self.notes.push(format!("launch shim: {line}"));
                ReportAction::None
            }
            _ => ReportAction::None,
        };
        crate::capture::trigger::send_ack(&self.report_fifo);
        action
    }

    /// Stop every ring and refresh the maps of processes still alive.
    pub fn finish(&mut self) -> Vec<u32> {
        let mut live = Vec::new();
        for ev in &mut self.events {
            ev.take_snapshot();
        }
        let pids: Vec<u32> = {
            let mut v: Vec<u32> = self.events.iter().map(|e| e.pid).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        for pid in pids {
            if let Some(mut p) = ProcInfo::read(pid) {
                p.exec_ns = self.procs.get(&pid).and_then(|old| old.exec_ns);
                self.procs.insert(pid, p);
                live.push(pid);
            }
        }
        live
    }

    /// Write the bundle; returns raw trace bytes written.
    pub fn write(&self, path: &Path) -> Result<u64> {
        if self.events.is_empty() {
            return Err(Error::new(
                ErrorCode::PtUnavailable,
                format!(
                    "direct recorder traced no thread: {}",
                    if self.notes.is_empty() {
                        "no thread was reported by the launch shim".to_string()
                    } else {
                        self.notes.join("; ")
                    }
                ),
            )
            .with_next("TRACE_MCP_RECORDER=perf falls back to perf record"));
        }
        let mut procs: Vec<ProcInfo> = self.procs.values().cloned().collect();
        procs.sort_by_key(|p| p.pid);
        write_bundle(
            path,
            &self.pmu,
            &self.terms,
            &self.events,
            &procs,
            self.root_pid,
        )
    }

    pub fn traced_threads(&self) -> usize {
        self.events.len()
    }

    pub fn aux_used(&self) -> u64 {
        self.aux_used
    }

    pub fn wrapped_rings(&self) -> usize {
        self.events.iter().filter(|e| e.wrapped).count()
    }

    /// Launch: the shim's exit. Attach: the process disappearing from
    /// `/proc` (polled, picking up new threads on the way).
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        if let Some(child) = self.child.as_mut() {
            return child.wait().await.map_err(Into::into);
        }
        let pid = self.pid;
        loop {
            if !Path::new(&format!("/proc/{pid}")).exists() {
                use std::os::unix::process::ExitStatusExt;
                return Ok(std::process::ExitStatus::from_raw(0));
            }
            self.poll_threads();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    pub fn terminate_group(&self, grace: std::time::Duration) {
        if self.child.is_none() {
            return;
        }
        if let Some(pid) = rustix::process::Pid::from_raw(self.pid as i32) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
            std::thread::sleep(grace);
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
}
