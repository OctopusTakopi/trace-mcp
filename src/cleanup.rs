//! Self-cleaning: everything transient trace-mcp creates lives under one
//! per-process directory in `$TMPDIR`, removed when the process exits, and
//! the evidence store is swept of its own leftovers (FIFOs, split files,
//! partial analyses, stale staging) on every exit.
//!
//! Directories of crashed earlier runs (`pid-<n>` whose pid is gone) are
//! removed too, so a crash never leaks more than one run's scratch.

use std::path::{Path, PathBuf};

/// What a sweep removed.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sweep {
    pub entries: u64,
    pub bytes: u64,
}

impl Sweep {
    fn add(&mut self, other: Sweep) {
        self.entries += other.entries;
        self.bytes += other.bytes;
    }
}

/// `$TMPDIR/trace-mcp-<uid>`: the root for all of this user's runs.
pub fn tmp_root() -> PathBuf {
    let uid = rustix::process::getuid().as_raw();
    std::env::temp_dir().join(format!("trace-mcp-{uid}"))
}

/// This process's scratch directory (created on first use).
pub fn process_dir() -> std::io::Result<PathBuf> {
    let dir = tmp_root().join(format!("pid-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn dir_size(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.is_dir() {
        std::fs::read_dir(path)
            .map(|rd| rd.flatten().map(|e| dir_size(&e.path())).sum())
            .unwrap_or(0)
    } else {
        meta.len()
    }
}

fn remove(path: &Path) -> Sweep {
    let bytes = dir_size(path);
    let ok = if path.is_dir() {
        std::fs::remove_dir_all(path).is_ok()
    } else {
        std::fs::remove_file(path).is_ok()
    };
    if ok {
        Sweep { entries: 1, bytes }
    } else {
        Sweep::default()
    }
}

fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Remove this process's scratch and the scratch of dead processes.
pub fn sweep_tmp() -> Sweep {
    let mut sw = Sweep::default();
    let root = tmp_root();
    let Ok(rd) = std::fs::read_dir(&root) else {
        return sw;
    };
    let me = std::process::id();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(pid) = name
            .strip_prefix("pid-")
            .and_then(|p| p.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me || !pid_alive(pid) {
            sw.add(remove(&e.path()));
        }
    }
    let _ = std::fs::remove_dir(&root); // only if empty
    sw
}

const FIFOS: [&str; 4] = [
    "trigger.fifo",
    "trigger.fifo.ack",
    "report.fifo",
    "report.fifo.ack",
];

/// Leftovers inside an evidence store that no reader needs:
/// - control FIFOs copied into snapshots with their staging directory,
/// - `split/` per-CPU perf.data copies (a decode-time cache),
/// - `derived/a_*` without a manifest (a decode that did not finish),
/// - `staging/*` and `quarantine/*` older than a day (crashed sessions;
///   fresh ones may belong to a live server, so they are left alone).
pub fn sweep_store(root: &Path) -> Sweep {
    let mut sw = Sweep::default();
    // The store's exclusive lock: a running server (or another command)
    // holding it may be decoding from split/ or writing a derived/a_* right
    // now, so a sweep that cannot take the lock does nothing.
    let Ok(lock) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join("LOCK"))
    else {
        return sw;
    };
    if rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err() {
        tracing::debug!(store = %root.display(), "store in use; skipping the exit sweep");
        return sw;
    }
    if let Ok(rd) = std::fs::read_dir(root.join("snapshots")) {
        for snap in rd.flatten() {
            let p = snap.path();
            for f in FIFOS {
                let fp = p.join(f);
                if fp.exists() {
                    sw.add(remove(&fp));
                }
            }
            let split = p.join("split");
            if split.is_dir() {
                sw.add(remove(&split));
            }
            if let Ok(dd) = std::fs::read_dir(p.join("derived")) {
                for a in dd.flatten() {
                    if a.path().is_dir() && !a.path().join("manifest.json").exists() {
                        sw.add(remove(&a.path()));
                    }
                }
            }
        }
    }
    let day = std::time::Duration::from_secs(24 * 3600);
    for sub in ["staging", "quarantine"] {
        if let Ok(rd) = std::fs::read_dir(root.join(sub)) {
            for e in rd.flatten() {
                let old = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > day);
                if old {
                    sw.add(remove(&e.path()));
                }
            }
        }
    }
    sw
}

/// Run at process exit (normal return, stdin EOF of the MCP server, or a
/// termination signal). `TRACE_MCP_KEEP_WASTE=1` disables it.
pub fn on_exit(store: Option<&Path>) {
    if std::env::var_os("TRACE_MCP_KEEP_WASTE").is_some() {
        return;
    }
    let mut sw = sweep_tmp();
    if let Some(root) = store {
        sw.add(sweep_store(root));
    }
    if sw.entries > 0 {
        tracing::info!(
            entries = sw.entries,
            bytes = sw.bytes,
            "cleaned trace-mcp leftovers on exit"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_sweep_removes_only_waste() {
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().join("snapshots").join("s_1");
        std::fs::create_dir_all(snap.join("derived").join("a_done")).unwrap();
        std::fs::write(
            snap.join("derived").join("a_done").join("manifest.json"),
            b"{}",
        )
        .unwrap();
        std::fs::create_dir_all(snap.join("derived").join("a_partial")).unwrap();
        std::fs::write(
            snap.join("derived").join("a_partial").join("spans.jsonl"),
            b"x",
        )
        .unwrap();
        std::fs::create_dir_all(snap.join("split")).unwrap();
        std::fs::write(snap.join("split").join("cpu0.data"), b"xx").unwrap();
        std::fs::write(snap.join("report.fifo"), b"").unwrap();
        std::fs::write(snap.join("perf.data"), b"keep").unwrap();
        let sw = sweep_store(dir.path());
        assert_eq!(sw.entries, 3);
        assert!(snap.join("perf.data").exists());
        assert!(
            snap.join("derived")
                .join("a_done")
                .join("manifest.json")
                .exists()
        );
        assert!(!snap.join("derived").join("a_partial").exists());
        assert!(!snap.join("split").exists());
        assert!(!snap.join("report.fifo").exists());
    }

    #[test]
    fn store_sweep_skips_a_locked_store() {
        let dir = tempfile::tempdir().unwrap();
        let snap = dir.path().join("snapshots").join("s_1");
        std::fs::create_dir_all(snap.join("split")).unwrap();
        std::fs::write(snap.join("split").join("cpu0.data"), b"xx").unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.path().join("LOCK"))
            .unwrap();
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        let sw = sweep_store(dir.path());
        assert_eq!(sw.entries, 0, "a locked store is left alone");
        assert!(snap.join("split").exists());
        drop(lock);
        assert_eq!(sweep_store(dir.path()).entries, 1);
    }

    #[test]
    fn tmp_sweep_removes_own_and_dead_process_dirs() {
        let own = process_dir().unwrap();
        std::fs::write(own.join("x"), b"1").unwrap();
        let dead = tmp_root().join("pid-4294967295");
        std::fs::create_dir_all(&dead).unwrap();
        let sw = sweep_tmp();
        assert!(sw.entries >= 2);
        assert!(!own.exists() && !dead.exists());
    }
}
