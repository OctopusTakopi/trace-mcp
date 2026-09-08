use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use rustix::io::{FdFlags, fcntl_setfd};
use rustix::pipe::{PipeFlags, pipe_with};
use tokio::process::{Child, Command};

use crate::capture::doctor::resolve_perf;
use crate::error::{Error, ErrorCode, Result};
use crate::model::{
    AuxTopology, CaptureReason, DEFAULT_META_PAGES, EffectivePtTerms, IntelPtConfig, Target,
    Trigger,
};

pub const PERF_DIALECT: &str = "perf-script-ns-F-pid-tid-cpu-time-event-ip-addr-flags-v1";

#[derive(Debug, Clone)]
pub struct PerfRecordSpec {
    pub event_spec: String,
    pub output: PathBuf,
    pub mmap: String,
    pub max_size: u64,
    pub target: Target,
    pub cwd: Option<PathBuf>,
    /// Extra environment for the workload; perf passes its own on.
    pub env: std::collections::BTreeMap<String, String>,
    /// Record only these CPUs (`-C`) and pin the workload to them.
    pub cpus: Option<Vec<u32>>,
    pub trigger: Option<Trigger>,
    /// FIFO the launch shim / workload writes to when the trigger fires.
    pub notify_fifo: Option<PathBuf>,
    /// Resolved perf `--filter` clauses (`kind 0xOFF/0xSIZE @ image`).
    pub address_filter: Option<String>,
}

impl PerfRecordSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        config: &IntelPtConfig,
        terms: &EffectivePtTerms,
        topology: &AuxTopology,
        output: PathBuf,
        target: Target,
        cwd: Option<PathBuf>,
        max_size: u64,
        trigger: Option<Trigger>,
        notify_fifo: Option<PathBuf>,
    ) -> Result<Self> {
        config.validate(topology.page_size)?;
        if matches!(trigger, Some(Trigger::Symbol { .. })) && !target.owns_workload() {
            return Err(Error::invalid_argument(
                "symbol triggers require a launch target (the breakpoint is planted at exec)",
            ));
        }
        if config.cpus.is_some() && !target.owns_workload() {
            return Err(Error::invalid_argument(
                "cpus requires a launch target: an attached process cannot be pinned, so restricting CPUs would silently drop its execution elsewhere",
            ));
        }
        let env = match &target {
            Target::Launch { env, .. } => env.clone(),
            Target::Attach { .. } => Default::default(),
        };
        Ok(Self {
            event_spec: terms.event_spec.clone(),
            output,
            mmap: format!(
                "{},{}",
                topology.meta_pages,
                format_size(topology.aux_bytes_per_buffer)
            ),
            max_size,
            target,
            cwd,
            env,
            cpus: config.cpus.clone(),
            trigger,
            notify_fifo,
            address_filter: None,
        })
    }

    pub fn argv(&self, _perf: &Path, ctl: i32, ack: i32) -> Vec<String> {
        let mut args = vec![
            "record".into(),
            "--no-buildid-cache".into(),
            "--buildid-mmap".into(),
            "--synth=all".into(),
            "-e".into(),
            self.event_spec.clone(),
        ];
        if let Some(f) = &self.address_filter {
            args.push("--filter".into());
            args.push(f.clone());
        }
        args.extend([
            "-m".into(),
            self.mmap.clone(),
            "--snapshot=e".into(),
            format!("--control=fd:{ctl},{ack}"),
            "-o".into(),
            self.output.display().to_string(),
            format!("--max-size={}", format_size(self.max_size)),
        ]);
        if let Some(cpus) = &self.cpus {
            args.push("-C".into());
            args.push(
                cpus.iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        match &self.target {
            Target::Launch { argv, .. } => {
                args.push("--".into());
                let symbol = match &self.trigger {
                    Some(Trigger::Symbol { symbol, hits }) => Some((symbol.clone(), *hits)),
                    _ => None,
                };
                if self.cpus.is_some() || symbol.is_some() {
                    // trace-mcp re-execs itself as a small launch shim: it pins
                    // the CPU set (so perf's own threads stay off the recorded
                    // CPUs) and/or supervises the workload for a symbol trigger.
                    if let Ok(me) = std::env::current_exe() {
                        args.push(me.display().to_string());
                        args.push("__launch".into());
                        if let Some(cpus) = &self.cpus {
                            args.push("--cpus".into());
                            args.push(
                                cpus.iter()
                                    .map(|c| c.to_string())
                                    .collect::<Vec<_>>()
                                    .join(","),
                            );
                        }
                        if let Some((sym, hits)) = &symbol {
                            args.push("--symbol".into());
                            args.push(sym.clone());
                            args.push("--hits".into());
                            args.push(hits.to_string());
                        }
                        if let Some(f) = &self.notify_fifo {
                            args.push("--notify".into());
                            args.push(f.display().to_string());
                        }
                        args.push("--".into());
                    }
                }
                args.extend(argv.iter().cloned());
            }
            Target::Attach { pid } => {
                args.push("-p".into());
                args.push(pid.to_string());
            }
        }
        args
    }
}

fn format_size(bytes: u64) -> String {
    if bytes.is_multiple_of(1024 * 1024 * 1024) {
        format!("{}G", bytes / (1024 * 1024 * 1024))
    } else if bytes.is_multiple_of(1024 * 1024) {
        format!("{}M", bytes / (1024 * 1024))
    } else if bytes.is_multiple_of(1024) {
        format!("{}K", bytes / 1024)
    } else {
        format!("{bytes}B")
    }
}

pub struct PerfControl {
    pub child: Child,
    pub pid: u32,
    ctl: File,
    ack: File,
    _inherited: (OwnedFd, OwnedFd),
}

impl PerfControl {
    pub async fn spawn(
        spec: &PerfRecordSpec,
        stdout_path: &Path,
        stderr_path: &Path,
    ) -> Result<Self> {
        let perf = resolve_perf()?;
        let (ctl_r, ctl_w) = pipe_with(PipeFlags::CLOEXEC).map_err(io_err)?;
        let (ack_r, ack_w) = pipe_with(PipeFlags::CLOEXEC).map_err(io_err)?;
        fcntl_setfd(&ctl_r, FdFlags::empty()).map_err(io_err)?;
        fcntl_setfd(&ack_w, FdFlags::empty()).map_err(io_err)?;

        let ctl_r_fd = ctl_r.as_raw_fd();
        let ack_w_fd = ack_w.as_raw_fd();
        let args = spec.argv(&perf, ctl_r_fd, ack_w_fd);

        let stdout = File::create(stdout_path)?;
        let stderr = File::create(stderr_path)?;
        let mut cmd = Command::new(&perf);
        cmd.envs(&spec.env)
            .env("LC_ALL", "C")
            .env("PERF_PAGER", "cat")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(false)
            .process_group(0);
        if let Some(cwd) = spec.cwd.as_ref() {
            cmd.current_dir(cwd);
        }
        if let Some(f) = &spec.notify_fifo {
            cmd.env(crate::capture::trigger::TRIGGER_ENV, f);
        }

        let child = cmd.spawn().map_err(|e| {
            Error::new(
                ErrorCode::UnsupportedPerf,
                format!("failed to spawn perf: {e}"),
            )
            .with_next("Check doctor output")
        })?;
        let pid = child.id().ok_or_else(|| {
            Error::new(
                ErrorCode::UnsupportedPerf,
                "perf exited before pid was available",
            )
        })?;

        Ok(Self {
            child,
            pid,
            ctl: File::from(ctl_w),
            ack: File::from(ack_r),
            _inherited: (ctl_r, ack_w),
        })
    }

    pub async fn ping(&mut self, timeout: Duration) -> Result<String> {
        self.command("ping", timeout).await
    }

    pub async fn stop(&mut self, timeout: Duration) -> Result<String> {
        self.command("stop", timeout).await
    }

    async fn command(&mut self, cmd: &'static str, timeout: Duration) -> Result<String> {
        self.ctl
            .write_all(format!("{cmd}\n").as_bytes())
            .map_err(|e| Error::new(ErrorCode::NotReady, format!("control write {cmd}: {e}")))?;
        self.ctl.flush().ok();
        let mut ack = self.ack.try_clone()?;
        let join = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 128];
            let n = ack.read(&mut buf)?;
            let s = String::from_utf8_lossy(&buf[..n]);
            Ok::<_, std::io::Error>(
                s.trim_matches(|c: char| c.is_whitespace() || c == '\0')
                    .to_string(),
            )
        });
        match tokio::time::timeout(timeout, join).await {
            Ok(Ok(Ok(s))) => Ok(s),
            Ok(Ok(Err(e))) => Err(Error::new(
                ErrorCode::NotReady,
                format!("control ack {cmd}: {e}"),
            )),
            Ok(Err(e)) => Err(Error::new(
                ErrorCode::NotReady,
                format!("control ack join: {e}"),
            )),
            Err(_) => Err(
                Error::new(ErrorCode::NotReady, format!("control {cmd} timed out"))
                    .with_next("Escalate recorder termination"),
            ),
        }
    }

    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        self.child.wait().await.map_err(Into::into)
    }

    pub fn terminate_group(&self, grace: Duration) -> Result<()> {
        let Some(pid) = rustix::process::Pid::from_raw(self.pid as i32) else {
            return Ok(());
        };
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
        std::thread::sleep(grace);
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        Ok(())
    }
}

fn io_err(err: rustix::io::Errno) -> Error {
    Error::new(ErrorCode::PermissionDenied, err.to_string())
}

pub fn calls_script_args(perf_data: &Path) -> Vec<String> {
    calls_script_args_mode(perf_data, false)
}

/// `fast=true` synthesizes only calls and returns (`--itrace=cre`): far
/// less text for perf to print, but inter-function jumps (tail calls, PLT
/// stubs) are not observed.
pub fn calls_script_args_mode(perf_data: &Path, fast: bool) -> Vec<String> {
    vec![
        "script".into(),
        "-i".into(),
        perf_data.display().to_string(),
        "--ns".into(),
        if fast { "--itrace=cre" } else { "--itrace=be" }.into(),
        "-F".into(),
        "pid,tid,cpu,time,event,ip,addr,flags".into(),
        "--show-task-events".into(),
        "--show-mmap-events".into(),
        "--show-lost-events".into(),
    ]
}

pub fn insn_script_args(perf_data: &Path) -> Vec<String> {
    vec![
        "script".into(),
        "-i".into(),
        perf_data.display().to_string(),
        "--ns".into(),
        "--itrace=i1ibe".into(),
        "-F".into(),
        "pid,tid,cpu,time,event,ip,addr,flags,insn,insnlen".into(),
        "--show-task-events".into(),
        "--show-mmap-events".into(),
        "--show-lost-events".into(),
    ]
}

pub fn metadata_script_args(perf_data: &Path) -> Vec<String> {
    vec![
        "script".into(),
        "-i".into(),
        perf_data.display().to_string(),
        "--ns".into(),
        "--itrace=e".into(),
        "-F".into(),
        "pid,tid,cpu,time,event,ip,addr,flags".into(),
        "--show-task-events".into(),
        "--show-mmap-events".into(),
        "--show-lost-events".into(),
    ]
}

pub async fn run_perf_script(
    args: &[String],
    extra_env: &[(&str, &str)],
) -> Result<(Vec<u8>, Vec<u8>, i32)> {
    let perf = resolve_perf()?;
    let mut cmd = Command::new(perf);
    cmd.env("LC_ALL", "C").env("PERF_PAGER", "cat").args(args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().await?;
    Ok((out.stdout, out.stderr, out.status.code().unwrap_or(1)))
}

pub fn resolve_launch_exe(argv: &[String], cwd: Option<&Path>) -> Result<PathBuf> {
    let raw = argv
        .first()
        .ok_or_else(|| Error::invalid_argument("empty argv"))?;
    let path = PathBuf::from(raw);
    let resolved = if path.is_absolute() {
        path
    } else if path.components().count() > 1 {
        cwd.unwrap_or(Path::new(".")).join(path)
    } else {
        which::which(raw)
            .map_err(|_| Error::invalid_argument(format!("cannot resolve executable {raw}")))?
    };
    let resolved = fs::canonicalize(&resolved).unwrap_or(resolved);
    if !resolved.is_file() {
        return Err(Error::invalid_argument(format!(
            "executable is not a file: {}",
            resolved.display()
        )));
    }
    Ok(resolved)
}

pub fn read_start_identity(pid: u32) -> Result<ProcessStartId> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| Error::not_found(format!("pid {pid} does not exist")))?;
    let starttime = parse_stat_starttime(&stat)
        .ok_or_else(|| Error::invalid_argument(format!("cannot parse /proc/{pid}/stat")))?;
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok();
    Ok(ProcessStartId {
        pid,
        starttime,
        exe,
    })
}

#[derive(Debug, Clone)]
pub struct ProcessStartId {
    pub pid: u32,
    pub starttime: u64,
    pub exe: Option<PathBuf>,
}

impl ProcessStartId {
    pub fn still_same(&self) -> bool {
        read_start_identity(self.pid)
            .ok()
            .is_some_and(|now| now.starttime == self.starttime)
    }
}

fn parse_stat_starttime(stat: &str) -> Option<u64> {
    let comm_end = stat.rfind(')')?;
    let rest = stat.get(comm_end + 2..)?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

pub fn page_size() -> u64 {
    rustix::param::page_size() as u64
}

pub fn online_cpus() -> u64 {
    std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .map(|s| {
            let mut n = 0u64;
            for part in s.trim().split(',') {
                if let Some((a, b)) = part.split_once('-') {
                    if let (Ok(a), Ok(b)) = (a.parse::<u64>(), b.parse::<u64>()) {
                        n += b.saturating_sub(a).saturating_add(1);
                    }
                } else if part.parse::<u64>().is_ok() {
                    n += 1;
                }
            }
            n.max(1)
        })
        .unwrap_or(1)
}

/// Fit the AUX ring size for the recorder that will run: one ring per
/// traced thread for the direct recorder (`per_thread`), one per recorded
/// CPU for perf record.
pub fn validate_ready_topology(
    config: &mut IntelPtConfig,
    per_thread: bool,
) -> Result<AuxTopology> {
    if per_thread {
        config.fit_aux_per_thread(page_size(), DEFAULT_META_PAGES)
    } else {
        config.fit_aux_topology(online_cpus(), page_size(), DEFAULT_META_PAGES)
    }
}

/// Recorder startup scales with the number of AUX rings perf must mmap.
pub fn startup_timeout(base_ms: u64, recorded_cpus: u64) -> Duration {
    Duration::from_millis(base_ms.saturating_add(recorded_cpus.saturating_mul(100)))
}

pub fn capture_reason_label(r: CaptureReason) -> &'static str {
    match r {
        CaptureReason::Snapshot => "snapshot",
        CaptureReason::AfterMs => "after_ms",
        CaptureReason::TargetExit => "target_exit",
        CaptureReason::TimeLimit => "time_limit",
        CaptureReason::Stop => "stop",
        CaptureReason::Trigger => "trigger",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_starttime_parses() {
        let line = "1 (systemd) S 0 1 1 0 -1 4194560 1 2 3 4 5 6 7 8 9 10 11 12 13 20 21 12345 1";
        // After ") " fields: state(0) ppid(1) ... starttime is field 20 (0-based 19) of post-comm.
        let parsed = parse_stat_starttime(line);
        assert!(parsed.is_some());
    }
}
