use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorCode, Result};
use crate::model::{
    DEFAULT_META_PAGES, EffectivePtTerms, IntelPtConfig, Limits, PtCapabilities, TimingProfile,
    suggested_aux,
};

const INTEL_PT_SYSFS: &str = "/sys/bus/event_source/devices/intel_pt";
const INTEL_PT_ALIAS: &str = "/sys/devices/intel_pt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Unsupported,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl DoctorCheck {
    pub fn ok(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Ok,
            reason: reason.into(),
            remedy: None,
        }
    }

    pub fn unavailable(
        name: impl Into<String>,
        reason: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Unavailable,
            reason: reason.into(),
            remedy: Some(remedy.into()),
        }
    }

    pub fn unsupported(
        name: impl Into<String>,
        reason: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Unsupported,
            reason: reason.into(),
            remedy: Some(remedy.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub host: HostInfo,
    pub checks: Vec<DoctorCheck>,
    pub supported_profiles: Vec<TimingProfile>,
    pub supported_detail: Vec<String>,
    pub pt_caps: Option<PtCapabilities>,
    pub perf: Option<PerfInfo>,
    pub topology_hint: Option<String>,
    pub probe: Option<ProbeResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub os: String,
    pub arch: String,
    pub kernel: String,
    pub cpu_vendor: String,
    pub cpu_family: String,
    pub cpu_model: String,
    pub cpu_stepping: String,
    pub online_cpus: u64,
    pub page_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfInfo {
    pub path: String,
    pub version: String,
    pub has_snapshot: bool,
    pub has_control: bool,
    pub has_itrace: bool,
    pub has_insn_fields: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub ok: bool,
    pub detail: String,
}

pub fn run_doctor(probe: bool, store: Option<&Path>) -> Result<DoctorReport> {
    let mut checks = Vec::new();
    let host = read_host(&mut checks);
    let pt_caps = read_pt_caps(&mut checks);
    if let Some(caps) = &pt_caps {
        probe_direct_recorder(&mut checks, caps);
    }
    let perf = read_perf(&mut checks);
    let mut supported_profiles = Vec::new();
    let mut topology_hint = None;
    if let Some(caps) = pt_caps.as_ref() {
        for profile in [
            TimingProfile::LowBandwidth,
            TimingProfile::Balanced,
            TimingProfile::Detailed,
        ] {
            match EffectivePtTerms::resolve(profile, caps, 1024 * 1024) {
                Ok(_) => supported_profiles.push(profile),
                Err(err) => checks.push(DoctorCheck::unsupported(
                    format!("profile_{}", profile.as_str()),
                    err.reason,
                    err.next_action.unwrap_or_default(),
                )),
            }
        }
        let mut cfg = IntelPtConfig::default();
        match cfg.fit_aux_topology(host.online_cpus, host.page_size, DEFAULT_META_PAGES) {
            Ok(top) if top.aux_bytes_per_buffer == crate::model::DEFAULT_AUX_BYTES => {
                checks.push(DoctorCheck::ok(
                    "aux_topology_default",
                    format!(
                        "perf record fallback: default 4MiB x {} CPUs = {} AUX plus {} metadata",
                        top.ncpus, top.aux_total, top.meta_total
                    ),
                ));
            }
            Ok(top) => {
                topology_hint = Some(format!("auto_aux={}", top.aux_bytes_per_buffer));
                checks.push(DoctorCheck::ok(
                    "aux_topology_default",
                    format!(
                        "perf record fallback: default 4MiB x {} CPUs exceeds 128MiB; that path auto-selects {} unless aux_bytes_per_buffer is set",
                        host.online_cpus, top.aux_bytes_per_buffer
                    ),
                ));
            }
            Err(err) => {
                checks.push(DoctorCheck::unsupported(
                    "aux_topology_default",
                    err.reason,
                    err.next_action.unwrap_or_else(|| {
                        format!(
                            "Lower aux_bytes_per_buffer; largest power-of-two that fits is {}",
                            suggested_aux(
                                host.online_cpus,
                                IntelPtConfig::default().max_total_aux_bytes,
                                host.page_size,
                            )
                        )
                    }),
                ));
            }
        }
    }

    {
        // The direct recorder (default) sizes rings per traced thread, so
        // aux_bytes_per_buffer is not multiplied by the CPU count there.
        let mut cfg = IntelPtConfig::default();
        let direct_default = std::env::var("TRACE_MCP_RECORDER").map_or(true, |v| v != "perf");
        match cfg.fit_aux_per_thread(host.page_size, DEFAULT_META_PAGES) {
            Ok(top) => checks.push(DoctorCheck::ok(
                "aux_topology_direct",
                format!(
                    "direct recorder ({}): {} per traced thread within a {} total budget; aux_bytes_per_buffer is per thread, not per CPU",
                    if direct_default {
                        "default"
                    } else {
                        "disabled by TRACE_MCP_RECORDER=perf"
                    },
                    top.aux_bytes_per_buffer,
                    cfg.max_total_aux_bytes
                ),
            )),
            Err(err) => checks.push(DoctorCheck::unsupported(
                "aux_topology_direct",
                err.reason,
                err.next_action.unwrap_or_default(),
            )),
        }
    }

    check_access(&mut checks);
    if let Some(dir) = store {
        check_store(dir, &mut checks);
    }

    let mut supported_detail = vec!["calls".to_string()];
    if perf.as_ref().is_some_and(|p| p.has_insn_fields) {
        supported_detail.push("instructions".into());
    } else {
        checks.push(DoctorCheck::unsupported(
            "instruction_detail",
            "perf script does not advertise insn/insnlen fields",
            "Install a perf build with Intel PT instruction synthesis",
        ));
    }

    let probe = if probe {
        Some(run_probe(
            perf.as_ref(),
            pt_caps.as_ref(),
            &host,
            &mut checks,
        ))
    } else {
        checks.push(DoctorCheck::ok(
            "probe",
            "skipped; static checks must not claim PT capture works",
        ));
        None
    };

    Ok(DoctorReport {
        schema_version: crate::model::SCHEMA_VERSION,
        host,
        checks,
        supported_profiles,
        supported_detail,
        pt_caps,
        perf,
        topology_hint,
        probe,
    })
}

fn read_host(checks: &mut Vec<DoctorCheck>) -> HostInfo {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let kernel = read_to_string("/proc/sys/kernel/osrelease")
        .or_else(|_| uname_r())
        .unwrap_or_else(|_| "unknown".into());
    let cpu = parse_cpuinfo();
    let page_size = rustix::param::page_size() as u64;
    let online_cpus = online_cpu_count();

    if os != "linux" || arch != "x86_64" {
        checks.push(DoctorCheck::unsupported(
            "platform",
            format!("{os}/{arch} is not Linux x86-64"),
            "Run trace-mcp on Linux x86-64 with Intel PT",
        ));
    } else {
        checks.push(DoctorCheck::ok(
            "platform",
            format!("linux x86_64 kernel {kernel}, {online_cpus} online CPUs, page {page_size}"),
        ));
    }

    if cpu.vendor != "GenuineIntel" {
        checks.push(DoctorCheck::unsupported(
            "cpu_vendor",
            format!("vendor {} is not GenuineIntel", cpu.vendor),
            "Intel PT requires an Intel CPU",
        ));
    } else {
        checks.push(DoctorCheck::ok(
            "cpu",
            format!(
                "family {} model {} stepping {}",
                cpu.family, cpu.model, cpu.stepping
            ),
        ));
    }

    HostInfo {
        os,
        arch,
        kernel,
        cpu_vendor: cpu.vendor,
        cpu_family: cpu.family,
        cpu_model: cpu.model,
        cpu_stepping: cpu.stepping,
        online_cpus,
        page_size,
    }
}

struct CpuInfo {
    vendor: String,
    family: String,
    model: String,
    stepping: String,
}

fn parse_cpuinfo() -> CpuInfo {
    let text = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut vendor = "unknown".into();
    let mut family = "unknown".into();
    let mut model = "unknown".into();
    let mut stepping = "unknown".into();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim().to_string();
            match k {
                "vendor_id" => vendor = v,
                "cpu family" => family = v,
                "model" => model = v,
                "stepping" => stepping = v,
                _ => {}
            }
        }
        if vendor != "unknown" && family != "unknown" && model != "unknown" && stepping != "unknown"
        {
            break;
        }
    }
    CpuInfo {
        vendor,
        family,
        model,
        stepping,
    }
}

fn online_cpu_count() -> u64 {
    fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|s| parse_cpu_list(s.trim()))
        .or_else(|| {
            std::thread::available_parallelism()
                .ok()
                .map(|n| n.get() as u64)
        })
        .unwrap_or(1)
}

fn parse_cpu_list(s: &str) -> Option<u64> {
    let mut n = 0u64;
    for part in s.split(',') {
        if let Some((a, b)) = part.split_once('-') {
            let a: u64 = a.parse().ok()?;
            let b: u64 = b.parse().ok()?;
            n = n.saturating_add(b.saturating_sub(a).saturating_add(1));
        } else if !part.is_empty() {
            n = n.saturating_add(1);
        }
    }
    Some(n.max(1))
}

fn intel_pt_dir() -> Option<PathBuf> {
    let p = PathBuf::from(INTEL_PT_SYSFS);
    if p.exists() {
        return Some(p);
    }
    let alias = PathBuf::from(INTEL_PT_ALIAS);
    alias.exists().then_some(alias)
}

fn read_pt_caps(checks: &mut Vec<DoctorCheck>) -> Option<PtCapabilities> {
    let Some(dir) = intel_pt_dir() else {
        let flags = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        if flags.contains("intel_pt") {
            checks.push(DoctorCheck::unavailable(
                "intel_pt_pmu",
                "CPU advertises intel_pt but sysfs PMU is missing",
                "Load the kernel intel_pt PMU / boot a kernel with CONFIG_PERF_EVENTS_INTEL_PT",
            ));
        } else {
            checks.push(DoctorCheck::unsupported(
                "intel_pt_pmu",
                "no Intel PT PMU under /sys/bus/event_source/devices/intel_pt",
                "This CPU does not expose Intel PT",
            ));
        }
        return None;
    };

    checks.push(DoctorCheck::ok(
        "intel_pt_pmu",
        format!("PMU at {}", dir.display()),
    ));

    let event_type = read_u32(&dir.join("type")).unwrap_or(0);
    let caps_dir = dir.join("caps");
    let format_dir = dir.join("format");
    if !format_dir.join("tsc").exists() {
        checks.push(DoctorCheck::unavailable(
            "intel_pt_format",
            "missing format/tsc",
            "Kernel Intel PT format sysfs is incomplete",
        ));
    }

    let caps = PtCapabilities {
        mtc: read_bool_cap(&caps_dir.join("mtc")),
        mtc_periods_mask: read_hex_cap(&caps_dir.join("mtc_periods")),
        psb_cyc: read_bool_cap(&caps_dir.join("psb_cyc")),
        psb_periods_mask: read_hex_cap(&caps_dir.join("psb_periods")),
        cycle_thresholds_mask: read_hex_cap(&caps_dir.join("cycle_thresholds")),
        ptwrite: read_bool_cap(&caps_dir.join("ptwrite")),
        tnt_disable: read_bool_cap(&caps_dir.join("tnt_disable")),
        num_address_ranges: read_u32(&caps_dir.join("num_address_ranges")).unwrap_or(0),
        event_type,
    };
    checks.push(DoctorCheck::ok(
        "intel_pt_caps",
        format!(
            "mtc={} psb_cyc={} ptwrite={} addr_ranges={} type={}",
            caps.mtc, caps.psb_cyc, caps.ptwrite, caps.num_address_ranges, caps.event_type
        ),
    ));
    Some(caps)
}

fn read_perf(checks: &mut Vec<DoctorCheck>) -> Option<PerfInfo> {
    let path = match resolve_perf() {
        Ok(p) => p,
        Err(err) => {
            checks.push(DoctorCheck::unavailable(
                "perf",
                err.reason,
                "Install linux-perf / perf tools matching this kernel",
            ));
            return None;
        }
    };
    let version = Command::new(&path)
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let help = Command::new(&path)
        .arg("record")
        .arg("--help")
        .output()
        .ok()
        .map(|o| {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            s
        })
        .unwrap_or_default();
    let script_help = Command::new(&path)
        .arg("script")
        .arg("--help")
        .output()
        .ok()
        .map(|o| {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            s
        })
        .unwrap_or_default();

    let info = PerfInfo {
        path: path.display().to_string(),
        version: version.clone(),
        has_snapshot: help.contains("--snapshot"),
        has_control: help.contains("--control"),
        has_itrace: script_help.contains("itrace"),
        has_insn_fields: script_help.contains("insn") && script_help.contains("insnlen"),
    };
    if !info.has_snapshot || !info.has_control {
        checks.push(DoctorCheck::unsupported(
            "perf_record",
            format!("{version} missing snapshot/control"),
            "Install a perf with Intel PT snapshot and --control",
        ));
    } else {
        checks.push(DoctorCheck::ok(
            "perf_record",
            format!("{version} snapshot+control"),
        ));
    }
    if !info.has_itrace {
        checks.push(DoctorCheck::unsupported(
            "perf_script",
            "perf script missing --itrace",
            "Install perf with Intel PT decoder support",
        ));
    } else {
        checks.push(DoctorCheck::ok("perf_script", "itrace present"));
    }
    Some(info)
}

pub fn resolve_perf() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("PERF") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
        return Err(Error::new(
            ErrorCode::UnsupportedPerf,
            format!("PERF={} is not a file", pb.display()),
        ));
    }
    which::which("perf").map_err(|_| {
        Error::new(ErrorCode::UnsupportedPerf, "perf not found in PATH")
            .with_next("Install linux-perf or set PERF")
    })
}

fn check_access(checks: &mut Vec<DoctorCheck>) {
    match fs::read_to_string("/proc/sys/kernel/perf_event_paranoid") {
        Ok(v) => {
            let n = v.trim().parse::<i32>().unwrap_or(99);
            if n > 1 {
                checks.push(DoctorCheck::unavailable(
                    "perf_event_paranoid",
                    format!("perf_event_paranoid={n} likely blocks userspace PT"),
                    "Ask an admin to set kernel.perf_event_paranoid <= 1 (trace-mcp will not change sysctls)",
                ));
            } else {
                checks.push(DoctorCheck::ok("perf_event_paranoid", format!("{n}")));
            }
        }
        Err(err) => checks.push(DoctorCheck::unavailable(
            "perf_event_paranoid",
            err.to_string(),
            "Cannot read perf_event_paranoid",
        )),
    }

    let lim = rustix::process::getrlimit(rustix::process::Resource::Memlock);
    match lim.current {
        None => checks.push(DoctorCheck::ok("memlock", "RLIMIT_MEMLOCK unlimited")),
        Some(n) if n >= 32 * 1024 * 1024 => {
            checks.push(DoctorCheck::ok("memlock", format!("RLIMIT_MEMLOCK {n}")));
        }
        Some(n) => checks.push(DoctorCheck::unavailable(
            "memlock",
            format!("RLIMIT_MEMLOCK {n} may be too small for AUX buffers"),
            "Raise ulimit -l; trace-mcp will not change limits",
        )),
    }

    if Path::new("/.dockerenv").exists() {
        checks.push(DoctorCheck::unavailable(
            "container",
            "/.dockerenv present; PT may be restricted",
            "Run on the host or a privileged VM with Intel PT",
        ));
    }
}

fn check_store(dir: &Path, checks: &mut Vec<DoctorCheck>) {
    if let Err(err) = fs::create_dir_all(dir) {
        checks.push(DoctorCheck::unavailable(
            "store",
            format!("cannot create {}: {err}", dir.display()),
            "Pass --store to a writable directory",
        ));
        return;
    }
    let probe = dir.join(".write_probe");
    match fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = fs::remove_file(&probe);
            checks.push(DoctorCheck::ok(
                "store",
                format!("writable {}", dir.display()),
            ));
        }
        Err(err) => checks.push(DoctorCheck::unavailable(
            "store",
            err.to_string(),
            "Choose a writable --store",
        )),
    }
}

fn run_probe(
    perf: Option<&PerfInfo>,
    caps: Option<&PtCapabilities>,
    host: &HostInfo,
    checks: &mut Vec<DoctorCheck>,
) -> ProbeResult {
    let Some(perf) = perf else {
        checks.push(DoctorCheck::unavailable(
            "probe",
            "perf missing",
            "Install perf",
        ));
        return ProbeResult {
            ok: false,
            detail: "perf missing".into(),
        };
    };
    let Some(caps) = caps else {
        checks.push(DoctorCheck::unavailable(
            "probe",
            "no PT PMU",
            "Need Intel PT hardware",
        ));
        return ProbeResult {
            ok: false,
            detail: "no PT PMU".into(),
        };
    };
    let aux =
        suggested_aux(host.online_cpus, 128 * 1024 * 1024, host.page_size).max(host.page_size * 64);
    let terms = match EffectivePtTerms::resolve(TimingProfile::LowBandwidth, caps, aux) {
        Ok(t) => t,
        Err(err) => {
            checks.push(DoctorCheck::unsupported("probe", err.reason.clone(), ""));
            return ProbeResult {
                ok: false,
                detail: err.reason,
            };
        }
    };
    // Under the process scratch root, which is removed at exit even if the
    // probe (or perf) is killed half way.
    let tmp = match crate::cleanup::process_dir().and_then(tempfile::tempdir_in) {
        Ok(t) => t,
        Err(err) => {
            return ProbeResult {
                ok: false,
                detail: err.to_string(),
            };
        }
    };
    let out = tmp.path().join("perf.data");
    let mmap = format!("{},{}", Limits::default().meta_pages, format_mmap_size(aux));
    let status = Command::new(&perf.path)
        .env("LC_ALL", "C")
        .args([
            "record",
            "--no-buildid-cache",
            "-e",
            &terms.event_spec,
            "-m",
            &mmap,
            "-o",
            out.to_str().unwrap(),
            "--",
            "/bin/true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();
    match status {
        Ok(output) if output.status.success() && out.is_file() => {
            let script = Command::new(&perf.path)
                .env("LC_ALL", "C")
                .args([
                    "script",
                    "-i",
                    out.to_str().unwrap(),
                    "--ns",
                    "--itrace=be",
                    "-F",
                    "pid,tid,cpu,time,event,ip,addr,flags",
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output();
            match script {
                Ok(s) if s.status.success() => {
                    checks.push(DoctorCheck::ok(
                        "probe",
                        format!("captured and decoded {} bytes", s.stdout.len()),
                    ));
                    ProbeResult {
                        ok: true,
                        detail: format!("perf record+script ok, stdout {} bytes", s.stdout.len()),
                    }
                }
                Ok(s) => {
                    let err = String::from_utf8_lossy(&s.stderr).trim().to_string();
                    checks.push(DoctorCheck::unavailable(
                        "probe",
                        err.clone(),
                        "See perf script stderr",
                    ));
                    ProbeResult {
                        ok: false,
                        detail: err,
                    }
                }
                Err(err) => ProbeResult {
                    ok: false,
                    detail: err.to_string(),
                },
            }
        }
        Ok(output) => {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let (status, remedy) = if err.contains("Permission") || err.contains("paranoid") {
                (
                    CheckStatus::Unavailable,
                    "Permission denied for perf_event_open",
                )
            } else if err.contains("not supported") {
                (CheckStatus::Unsupported, "PT event rejected")
            } else {
                (CheckStatus::Unavailable, "perf record probe failed")
            };
            checks.push(DoctorCheck {
                name: "probe".into(),
                status,
                reason: err.clone(),
                remedy: Some(remedy.into()),
            });
            ProbeResult {
                ok: false,
                detail: err,
            }
        }
        Err(err) => ProbeResult {
            ok: false,
            detail: err.to_string(),
        },
    }
}

fn format_mmap_size(bytes: u64) -> String {
    if bytes.is_multiple_of(1024 * 1024) {
        format!("{}M", bytes / (1024 * 1024))
    } else if bytes.is_multiple_of(1024) {
        format!("{}K", bytes / 1024)
    } else {
        format!("{bytes}B")
    }
}

fn read_to_string(path: &str) -> Result<String> {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(Into::into)
}

fn uname_r() -> Result<String> {
    let o = Command::new("uname").arg("-r").output()?;
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn read_bool_cap(path: &Path) -> bool {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .is_some_and(|v| v != 0)
}

fn read_hex_cap(path: &Path) -> u64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0)
}

fn read_u32(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub fn doctor_summary(report: &DoctorReport) -> String {
    let blocking = report
        .checks
        .iter()
        .filter(|c| c.status != CheckStatus::Ok)
        .count();
    format!(
        "trace-mcp doctor: {} checks, {blocking} not ok, profiles {:?}, detail {:?}",
        report.checks.len(),
        report
            .supported_profiles
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>(),
        report.supported_detail
    )
}

pub fn capture_timeout() -> Duration {
    Duration::from_millis(crate::model::DEFAULT_STARTUP_TIMEOUT_MS)
}

/// Can this user open a per-thread Intel PT event with an AUX ring? The
/// direct recorder needs exactly that, independent of the perf binary.
fn probe_direct_recorder(checks: &mut Vec<DoctorCheck>, caps: &PtCapabilities) {
    let paranoid = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into());
    let pmu = match crate::capture::direct::PtPmu::discover() {
        Ok(p) => p,
        Err(e) => {
            checks.push(DoctorCheck::unavailable(
                "direct_recorder",
                format!("intel_pt PMU format not readable: {e}"),
                "check /sys/bus/event_source/devices/intel_pt".to_string(),
            ));
            return;
        }
    };
    let terms = match EffectivePtTerms::resolve(TimingProfile::Balanced, caps, 64 << 10) {
        Ok(t) => t,
        Err(e) => {
            checks.push(DoctorCheck::unsupported(
                "direct_recorder",
                e.reason,
                e.next_action.unwrap_or_default(),
            ));
            return;
        }
    };
    let tid = rustix::thread::gettid().as_raw_nonzero().get() as u32;
    let pid = std::process::id();
    match crate::capture::direct::PtEvent::open(&pmu, &terms, pid, tid, 64 << 10, None) {
        Ok(ev) => {
            drop(ev);
            checks.push(DoctorCheck::ok(
                "direct_recorder",
                format!("perf_event_open(intel_pt) per thread with a 64KiB AUX ring works (perf_event_paranoid={paranoid})"),
            ));
        }
        Err(e) => checks.push(DoctorCheck::unavailable(
            "direct_recorder",
            format!("{} (perf_event_paranoid={paranoid})", e.reason),
            e.next_action.unwrap_or_else(|| {
                "capture falls back to perf record with TRACE_MCP_RECORDER=perf".into()
            }),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_online_list() {
        assert_eq!(parse_cpu_list("0-79"), Some(80));
        assert_eq!(parse_cpu_list("0,3-5"), Some(4));
    }
}
