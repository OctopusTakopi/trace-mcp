//! Launch-side snapshot triggers.
//!
//! `trace-mcp __launch` is exec'd by `perf record` in place of the workload.
//! It optionally pins the CPU set, then either execs the workload directly or
//! becomes a tiny ptrace supervisor: fork, `PTRACE_TRACEME`, exec, plant an
//! `int3` at the requested symbol in the freshly mapped executable, count
//! hits, and on the N-th hit write `hit` to a FIFO that the capture task is
//! reading. The breakpoint is then removed and the workload keeps running
//! (still ptraced, but with nothing left to trap on) until it exits; the
//! supervisor exits with the workload's status so perf sees the same lifecycle.
//!
//! After notifying, the supervisor keeps the trapping thread stopped until
//! trace-mcp writes `go` to `<fifo>.ack` (or 30 s pass). With no tail
//! requested trace-mcp only acks after perf has written the snapshot, so a
//! hot loop cannot overwrite the trigger moment while the recorder winds
//! down; with a tail the ack comes immediately.
//!
//! After notifying, the supervisor keeps the trapping thread stopped until
//! trace-mcp writes `go` to `<fifo>.ack` (or 30 s pass). With no tail
//! requested trace-mcp only acks after perf has written the snapshot, so a
//! hot loop cannot overwrite the trigger moment while the recorder winds
//! down; with a tail the ack comes immediately.
//!
//! The FIFO path is also exported as `TRACE_MCP_TRIGGER` so an application can
//! fire the snapshot itself by writing a line to it (no symbol needed).
//!
//! Only x86-64 Linux is supported, matching the rest of the recorder.

use std::ffi::CString;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::decode::images::ImageIndex;
use crate::error::{Error, ErrorCode, Result};

pub const TRIGGER_ENV: &str = "TRACE_MCP_TRIGGER";

/// What the supervisor waits for before notifying.
#[derive(Debug, Clone)]
pub struct SymbolTrigger {
    pub symbol: String,
    /// ELF whose symbol table is searched; defaults to the launched executable.
    pub image: Option<PathBuf>,
    pub hits: u32,
}

/// A resolved code symbol in an ELF image: demangled name, ELF address
/// range, and the file offset of its first byte.
#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub demangled: String,
    pub start: u64,
    pub size: u64,
    pub file_offset: u64,
}

/// Find `symbol` in `image` by exact raw/demangled name, else by unique
/// substring. Inlined functions have no symbol and cannot be resolved.
pub fn resolve_symbol(image: &Path, symbol: &str) -> Result<ResolvedSymbol> {
    let bytes = std::fs::read(image)
        .map_err(|e| Error::not_found(format!("image {}: {e}", image.display())))?;
    let index = ImageIndex::build(&bytes);
    let exact: Vec<_> = index
        .funcs
        .iter()
        .filter(|f| f.name == symbol || f.demangled == symbol)
        .collect();
    let candidates = if exact.is_empty() {
        index
            .funcs
            .iter()
            .filter(|f| f.demangled.contains(symbol) || f.name.contains(symbol))
            .collect::<Vec<_>>()
    } else {
        exact
    };
    let func = match candidates.as_slice() {
        [] => {
            return Err(Error::not_found(format!(
                "symbol {symbol} not found in {}",
                image.display()
            ))
            .with_next("Use the demangled Rust path or a unique substring; inlined functions have no symbol"));
        }
        [one] => (*one).clone(),
        many => {
            let names: Vec<String> = many.iter().take(6).map(|f| f.demangled.clone()).collect();
            return Err(Error::invalid_argument(format!(
                "symbol {symbol} is ambiguous ({} matches): {}",
                many.len(),
                names.join(" | ")
            )));
        }
    };
    let seg = index
        .segments
        .iter()
        .find(|s| func.start >= s.vaddr && func.start < s.vaddr.saturating_add(s.file_size))
        .ok_or_else(|| {
            Error::decode_failed(format!(
                "{} has no segment for {}",
                image.display(),
                func.demangled
            ))
        })?;
    Ok(ResolvedSymbol {
        demangled: func.demangled.clone(),
        start: func.start,
        size: func.end.saturating_sub(func.start).max(1),
        file_offset: seg.file_off + (func.start - seg.vaddr),
    })
}

/// Resolve `symbol` to a runtime address inside `pid`'s mapping of `image`.
/// The image must already be mapped (true for the main executable at the
/// exec stop). Returns the address and the demangled name matched.
pub fn resolve_runtime_address(pid: u32, image: &Path, symbol: &str) -> Result<(u64, String)> {
    let func = resolve_symbol(image, symbol)?;
    let file_off = func.file_offset;
    let canon = std::fs::canonicalize(image).unwrap_or_else(|_| image.to_path_buf());
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| Error::not_found(format!("/proc/{pid}/maps: {e}")))?;
    for line in maps.lines() {
        let mut it = line.split_whitespace();
        let (Some(range), Some(_perms), Some(off), Some(_dev), Some(_ino)) =
            (it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        let path = it.collect::<Vec<_>>().join(" ");
        if Path::new(&path) != canon && Path::new(&path) != image {
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
        if file_off >= pgoff && file_off < pgoff + (end - start) {
            return Ok((start + (file_off - pgoff), func.demangled.clone()));
        }
    }
    Err(Error::not_found(format!(
        "{} is not mapped in pid {pid} at file offset {file_off:#x}",
        image.display()
    )))
}

fn errno_err(what: &str) -> Error {
    Error::new(
        ErrorCode::PermissionDenied,
        format!("{what}: {}", std::io::Error::last_os_error()),
    )
}

fn notify(fifo: &Path, msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(fifo) {
        let _ = f.write_all(msg.as_bytes());
        let _ = f.flush();
    }
}

/// Entry point for `trace-mcp __launch`. Never returns on the exec path;
/// with a symbol trigger it returns the workload's exit code.
pub fn launch(
    cpus: Option<&[u32]>,
    trigger: Option<SymbolTrigger>,
    fifo: Option<&Path>,
    report: Option<&Path>,
    argv: &[String],
) -> Result<i32> {
    use std::os::unix::process::CommandExt;
    if let Some(cpus) = cpus {
        let mut set = rustix::thread::CpuSet::new();
        for c in cpus {
            set.set(*c as usize);
        }
        rustix::thread::sched_setaffinity(None, &set).map_err(|e| {
            Error::new(
                ErrorCode::PermissionDenied,
                format!("sched_setaffinity: {e}"),
            )
        })?;
    }
    let Some((exe, rest)) = argv.split_first() else {
        return Err(Error::invalid_argument("__launch needs a command"));
    };
    if trigger.is_none() && report.is_none() {
        let err = std::process::Command::new(exe).args(rest).exec();
        return Err(Error::new(
            ErrorCode::NotFound,
            format!("exec {exe}: {err}"),
        ));
    }
    if trigger.is_some() && fifo.is_none() {
        return Err(Error::invalid_argument("symbol trigger needs --notify"));
    }
    let image = trigger
        .as_ref()
        .and_then(|t| t.image.clone())
        .unwrap_or_else(|| PathBuf::from(exe));

    // SAFETY: fork/ptrace/exec are the documented Linux APIs; the child only
    // calls async-signal-safe functions before exec.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(errno_err("fork"));
    }
    if pid == 0 {
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) < 0 {
                libc::_exit(126);
            }
            let c_exe = CString::new(exe.as_str()).unwrap_or_default();
            let c_args: Vec<CString> = argv
                .iter()
                .map(|a| CString::new(a.as_str()).unwrap_or_default())
                .collect();
            let mut ptrs: Vec<*const libc::c_char> = c_args.iter().map(|c| c.as_ptr()).collect();
            ptrs.push(std::ptr::null());
            libc::execvp(c_exe.as_ptr(), ptrs.as_ptr());
            libc::_exit(127);
        }
    }
    match trigger.as_ref() {
        Some(t) => supervise(pid, t, &image, fifo.unwrap_or(Path::new("")), report),
        None => {
            // First stop: the SIGTRAP after exec (PTRACE_TRACEME semantics).
            let Some((_, status)) = wait_any() else {
                return Err(errno_err("waitpid"));
            };
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            set_ptrace_options(pid);
            report_and_wait(report, &format!("exec {pid}\n"));
            cont(pid, 0);
            supervise_report_only(pid, report)
        }
    }
}

/// Clone/fork/exit events; exec is not traced because the initial exec is
/// already the first stop the supervisor sees.
fn set_ptrace_options(child: libc::pid_t) {
    let opts = libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEEXIT;
    unsafe {
        libc::ptrace(libc::PTRACE_SETOPTIONS, child, 0, opts as libc::c_long);
    }
}

/// Tell the recorder about a thread/process event and wait until it has
/// acted (opened or snapshotted the thread's PT event) before continuing.
fn report_and_wait(report: Option<&Path>, msg: &str) {
    if let Some(r) = report {
        notify(r, msg);
        wait_for_ack(r);
    }
}

fn wait_any() -> Option<(libc::pid_t, libc::c_int)> {
    let mut status: libc::c_int = 0;
    // SAFETY: plain waitpid on the tracees of this supervisor.
    let r = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
    (r > 0).then_some((r, status))
}

fn cont(tid: libc::pid_t, sig: libc::c_int) {
    // SAFETY: tid is a stopped tracee.
    unsafe {
        libc::ptrace(libc::PTRACE_CONT, tid, 0, sig as libc::c_long);
    }
}

fn peek(tid: libc::pid_t, addr: u64) -> Result<u64> {
    // SAFETY: PEEKTEXT on a stopped tracee; errno distinguishes failure from a -1 word.
    unsafe {
        *libc::__errno_location() = 0;
        let w = libc::ptrace(libc::PTRACE_PEEKTEXT, tid, addr as *mut libc::c_void, 0);
        if w == -1 && *libc::__errno_location() != 0 {
            return Err(errno_err("PTRACE_PEEKTEXT"));
        }
        Ok(w as u64)
    }
}

fn poke(tid: libc::pid_t, addr: u64, word: u64) -> Result<()> {
    // SAFETY: POKETEXT on a stopped tracee.
    let r = unsafe {
        libc::ptrace(
            libc::PTRACE_POKETEXT,
            tid,
            addr as *mut libc::c_void,
            word as *mut libc::c_void,
        )
    };
    if r < 0 {
        return Err(errno_err("PTRACE_POKETEXT"));
    }
    Ok(())
}

fn regs(tid: libc::pid_t) -> Result<libc::user_regs_struct> {
    // SAFETY: GETREGS fills the struct for a stopped tracee.
    let mut r: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ptrace(libc::PTRACE_GETREGS, tid, 0, &mut r as *mut _) };
    if rc < 0 {
        return Err(errno_err("PTRACE_GETREGS"));
    }
    Ok(r)
}

fn set_regs(tid: libc::pid_t, r: &libc::user_regs_struct) -> Result<()> {
    // SAFETY: SETREGS on a stopped tracee.
    let rc = unsafe { libc::ptrace(libc::PTRACE_SETREGS, tid, 0, r as *const _) };
    if rc < 0 {
        return Err(errno_err("PTRACE_SETREGS"));
    }
    Ok(())
}

fn supervise(
    child: libc::pid_t,
    trigger: &SymbolTrigger,
    image: &Path,
    fifo: &Path,
    report: Option<&Path>,
) -> Result<i32> {
    // First stop: the SIGTRAP after exec (PTRACE_TRACEME semantics).
    let Some((_, status)) = wait_any() else {
        return Err(errno_err("waitpid"));
    };
    if libc::WIFEXITED(status) {
        return Ok(libc::WEXITSTATUS(status));
    }
    // Follow threads so no untraced thread can hit the int3 and die.
    // SAFETY: SETOPTIONS on the stopped tracee.
    set_ptrace_options(child);
    report_and_wait(report, &format!("exec {child}\n"));
    let (addr, name) = match resolve_runtime_address(child as u32, image, &trigger.symbol) {
        Ok(v) => v,
        Err(e) => {
            notify(fifo, &format!("error {e}\n"));
            // Let the workload run untriggered; the capture falls back to
            // its other completion paths.
            cont(child, 0);
            return reap_untraced(child);
        }
    };
    eprintln!(
        "trace-mcp trigger: {name} at {addr:#x}, hits={}",
        trigger.hits
    );
    let original = peek(child, addr)?;
    let patched = (original & !0xff) | 0xcc;
    poke(child, addr, patched)?;
    cont(child, 0);

    let mut hits = 0u32;
    let mut armed = true;
    loop {
        let Some((tid, status)) = wait_any() else {
            return Ok(0);
        };
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            if tid == child {
                return Ok(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xff;
        if event != 0 {
            // clone/fork/exit stops: the direct recorder learns threads from
            // them (same as the report-only supervisor).
            handle_ptrace_event(tid, event, report);
            cont(tid, 0);
            continue;
        }
        if sig == libc::SIGSTOP {
            // New thread's initial stop.
            cont(tid, 0);
            continue;
        }
        if sig == libc::SIGTRAP {
            let mut r = match regs(tid) {
                Ok(r) => r,
                Err(_) => {
                    cont(tid, 0);
                    continue;
                }
            };
            if r.rip == addr + 1 && !armed {
                // A trap that was already queued when the last hit disarmed
                // the trigger: the original byte is back in place, so rewind
                // to re-execute it instead of resuming one byte into it.
                r.rip = addr;
                let _ = set_regs(tid, &r);
                cont(tid, 0);
                continue;
            }
            if r.rip == addr + 1 {
                hits += 1;
                r.rip = addr;
                let _ = set_regs(tid, &r);
                let _ = poke(tid, addr, original);
                if hits >= trigger.hits {
                    armed = false;
                    notify(fifo, &format!("hit {tid} {hits} {addr:#x}\n"));
                    eprintln!("trace-mcp trigger: {name} hit #{hits} on tid {tid}");
                    wait_for_ack(fifo);
                    cont(tid, 0);
                } else {
                    // Step over the original instruction, re-arm, continue.
                    // SAFETY: SINGLESTEP on the stopped tracee.
                    unsafe {
                        libc::ptrace(libc::PTRACE_SINGLESTEP, tid, 0, 0);
                    }
                    let mut st: libc::c_int = 0;
                    unsafe {
                        libc::waitpid(tid, &mut st, libc::__WALL);
                    }
                    let _ = poke(tid, addr, patched);
                    cont(tid, 0);
                }
                continue;
            }
            cont(tid, 0);
            continue;
        }
        // Any other signal: deliver it.
        cont(tid, if sig == libc::SIGTRAP { 0 } else { sig });
    }
}

/// Block (bounded) until trace-mcp acks the snapshot on `<fifo>.ack`.
/// Clone/fork/exit stops: report the new or exiting thread and wait for
/// the recorder's ack while it is still stopped.
fn handle_ptrace_event(tid: libc::pid_t, event: libc::c_int, report: Option<&Path>) {
    if report.is_none() {
        return;
    }
    match event {
        libc::PTRACE_EVENT_CLONE | libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK => {
            let mut new: libc::c_ulong = 0;
            let rc = unsafe { libc::ptrace(libc::PTRACE_GETEVENTMSG, tid, 0, &mut new as *mut _) };
            if rc == 0 && new != 0 {
                report_and_wait(report, &format!("thread {new}\n"));
            }
        }
        libc::PTRACE_EVENT_EXIT => {
            report_and_wait(report, &format!("exit {tid}\n"));
        }
        // A later exec (a wrapper such as `cargo run` or a shell script
        // exec'ing the real program): the recorder stamps the exec time and
        // re-reads the new image's mappings.
        libc::PTRACE_EVENT_EXEC => {
            report_and_wait(report, &format!("exec {tid}\n"));
        }
        _ => {}
    }
}

/// Supervise without a trigger: only thread discovery and exit stops.
fn supervise_report_only(child: libc::pid_t, report: Option<&Path>) -> Result<i32> {
    loop {
        let Some((tid, status)) = wait_any() else {
            return Ok(0);
        };
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            if tid == child {
                return Ok(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xff;
        if event != 0 {
            handle_ptrace_event(tid, event, report);
            cont(tid, 0);
            continue;
        }
        cont(
            tid,
            if sig == libc::SIGSTOP || sig == libc::SIGTRAP {
                0
            } else {
                sig
            },
        );
    }
}

fn wait_for_ack(fifo: &Path) {
    let ack = ack_path(fifo);
    if !ack.exists() {
        return;
    }
    let start = std::time::Instant::now();
    // Open read-write so the open never blocks on a missing writer, then
    // poll for a line with a bounded wait.
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&ack)
    else {
        return;
    };
    use std::io::Read;
    let mut f = f;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&f);
    let mut buf = [0u8; 64];
    while start.elapsed() < std::time::Duration::from_secs(30) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on a descriptor this function owns.
        let n = unsafe { libc::poll(&mut pfd, 1, 200) };
        if n > 0
            && let Ok(k) = f.read(&mut buf)
            && k > 0
        {
            return;
        }
    }
    eprintln!("trace-mcp trigger: no snapshot ack within 30 s; continuing the workload");
}

pub fn ack_path(fifo: &Path) -> PathBuf {
    let mut p = fifo.as_os_str().to_owned();
    p.push(".ack");
    PathBuf::from(p)
}

/// Release a thread parked at the trigger (no-op when nothing is waiting).
pub fn send_ack(fifo: &Path) {
    let ack = ack_path(fifo);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(&ack)
    {
        let _ = f.write_all(b"go\n");
    }
}

fn reap_untraced(child: libc::pid_t) -> Result<i32> {
    loop {
        let Some((tid, status)) = wait_any() else {
            return Ok(0);
        };
        if tid == child && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            return Ok(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            });
        }
        if libc::WIFSTOPPED(status) {
            let sig = libc::WSTOPSIG(status);
            cont(
                tid,
                if sig == libc::SIGTRAP || sig == libc::SIGSTOP {
                    0
                } else {
                    sig
                },
            );
        }
    }
}

/// Create the notify FIFO for a session.
pub fn make_fifo(path: &Path) -> Result<()> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::invalid_argument("fifo path contains NUL"))?;
    // SAFETY: mkfifo with a valid C string.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    if rc < 0 {
        return Err(errno_err("mkfifo"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_symbol_in_own_executable() {
        // The test binary maps itself; resolve a symbol known to be present.
        let exe = std::env::current_exe().unwrap();
        let (addr, name) = resolve_runtime_address(
            std::process::id(),
            &exe,
            "trace_mcp::capture::trigger::resolve_runtime_address",
        )
        .expect("resolve");
        assert!(name.contains("resolve_runtime_address"));
        assert_ne!(addr, 0);
        let f = resolve_runtime_address as *const () as usize as u64;
        assert_eq!(addr, f, "runtime address must match the live function");
    }

    #[test]
    fn missing_symbol_is_not_found() {
        let exe = std::env::current_exe().unwrap();
        let err =
            resolve_runtime_address(std::process::id(), &exe, "no_such_symbol_zzz").unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
    }
}
