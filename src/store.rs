use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{Error, ErrorCode, Result};
use crate::model::{
    AnalysisId, AnalysisManifest, JobId, JobRecord, Limits, ReportId, SCHEMA_VERSION, SessionId,
    SnapshotId, SnapshotManifest,
};

pub struct Store {
    pub root: PathBuf,
    pub limits: Limits,
    lock: File,
}

impl Store {
    pub fn open(root: PathBuf, limits: Limits) -> Result<Self> {
        fs::create_dir_all(&root)?;
        for sub in ["sessions", "snapshots", "reports", "jobs", "staging"] {
            fs::create_dir_all(root.join(sub))?;
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join("LOCK"))?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            Error::new(
                ErrorCode::Busy,
                format!("store {} is locked by another process", root.display()),
            )
            .with_next("Use a separate --store directory")
        })?;
        recover_staging(&root)?;
        Ok(Self { root, limits, lock })
    }

    pub fn session_path(&self, id: &SessionId) -> PathBuf {
        self.root.join("sessions").join(format!("{id}.json"))
    }

    pub fn snapshot_dir(&self, id: &SnapshotId) -> PathBuf {
        self.root.join("snapshots").join(id.as_str())
    }

    pub fn analysis_dir(&self, snap: &SnapshotId, analysis: &AnalysisId) -> PathBuf {
        self.snapshot_dir(snap)
            .join("derived")
            .join(analysis.as_str())
    }

    pub fn report_dir(&self, id: &ReportId) -> PathBuf {
        self.root.join("reports").join(id.as_str())
    }

    pub fn job_path(&self, id: &JobId) -> PathBuf {
        self.root.join("jobs").join(format!("{id}.json"))
    }

    pub fn staging(&self, name: &str) -> PathBuf {
        self.root.join("staging").join(name)
    }

    pub fn used_bytes(&self) -> Result<u64> {
        dir_size(&self.root)
    }

    pub fn ensure_budget(&self, extra: u64) -> Result<()> {
        let used = self.used_bytes()?;
        if used.saturating_add(extra) > self.limits.store_budget {
            let mut sizes = self.snapshot_sizes().unwrap_or_default();
            sizes.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
            let largest: Vec<String> = sizes
                .iter()
                .take(3)
                .map(|(id, b)| format!("{id} ({} MiB)", b >> 20))
                .collect();
            return Err(Error::new(
                ErrorCode::LimitExceeded,
                format!(
                    "store budget {} exceeded (used {used}, extra {extra}); largest snapshots: {}",
                    self.limits.store_budget,
                    if largest.is_empty() { "none".to_string() } else { largest.join(", ") }
                ),
            )
            .with_next(
                "Delete snapshots you no longer need with trace_prune (or `trace-mcp prune`), or raise TRACE_MCP_STORE_BUDGET",
            ));
        }
        Ok(())
    }

    /// Every snapshot directory with its size in bytes.
    pub fn snapshot_sizes(&self) -> Result<Vec<(SnapshotId, u64)>> {
        let mut out = Vec::new();
        let dir = self.root.join("snapshots");
        if !dir.exists() {
            return Ok(out);
        }
        for e in fs::read_dir(&dir)?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Ok(id) = SnapshotId::from_raw(name)
                && e.path().is_dir()
            {
                let bytes = dir_size(&e.path())?;
                out.push((id, bytes));
            }
        }
        Ok(out)
    }

    /// Remove a snapshot directory (raw capture, images, derived analyses)
    /// and return the bytes freed. Sessions and jobs that referred to it
    /// keep their records; their snapshot lookups report not found.
    pub fn remove_snapshot(&self, id: &SnapshotId) -> Result<u64> {
        let dir = self.snapshot_dir(id);
        if !dir.exists() {
            return Err(Error::not_found(format!("snapshot {id}")));
        }
        let bytes = dir_size(&dir)?;
        fs::remove_dir_all(&dir)?;
        Ok(bytes)
    }

    pub fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        {
            let file = File::create(&tmp)?;
            let mut w = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut w, value)
                .map_err(|e| Error::decode_failed(e.to_string()))?;
            w.flush()?;
            w.get_ref().sync_all().ok();
        }
        fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn publish_dir(&self, staging: &Path, dest: &Path) -> Result<()> {
        if dest.exists() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("destination already exists: {}", dest.display()),
            ));
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(staging, dest)?;
        Ok(())
    }

    pub fn load_snapshot_manifest(&self, id: &SnapshotId) -> Result<SnapshotManifest> {
        let p = self.snapshot_dir(id).join("manifest.json");
        read_json(&p)
    }

    pub fn load_analysis_manifest(
        &self,
        snap: &SnapshotId,
        id: &AnalysisId,
    ) -> Result<AnalysisManifest> {
        let p = self.analysis_dir(snap, id).join("manifest.json");
        read_json(&p)
    }

    pub fn load_job(&self, id: &JobId) -> Result<JobRecord> {
        read_json(&self.job_path(id))
    }

    pub fn list_sessions(&self) -> Result<Vec<(SessionId, serde_json::Value)>> {
        let mut out = Vec::new();
        let dir = self.root.join("sessions");
        let mut ents: Vec<_> = fs::read_dir(&dir)?.flatten().collect();
        ents.sort_by_key(|e| std::cmp::Reverse(e.metadata().and_then(|m| m.modified()).ok()));
        for e in ents {
            if e.path().extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if let Ok(v) = fs::read_to_string(e.path())
                && let Ok(json) = serde_json::from_str::<serde_json::Value>(&v)
                && let Some(id) = json.get("session_id").and_then(|s| s.as_str())
                && let Ok(sid) = SessionId::from_raw(id)
            {
                out.push((sid, json));
            }
        }
        Ok(out)
    }

    pub fn import_bundle(&self, src: &Path) -> Result<SnapshotId> {
        let src = fs::canonicalize(src)?;
        let manifest_path = src.join("manifest.json");
        let manifest: SnapshotManifest = read_json(&manifest_path)?;
        validate_bundle_paths(&src)?;
        let dest = self.snapshot_dir(&manifest.snapshot_id);
        if dest.exists() {
            let existing: SnapshotManifest = read_json(&dest.join("manifest.json"))?;
            if existing.snapshot_id == manifest.snapshot_id {
                return Ok(manifest.snapshot_id);
            }
            return Err(Error::invalid_argument(
                "snapshot id collision with different content",
            ));
        }
        self.ensure_budget(dir_size(&src)?)?;
        copy_dir(&src, &dest)?;
        Ok(manifest.snapshot_id)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = flock(self.lock.as_fd(), FlockOperation::Unlock);
    }
}

pub fn default_store_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(xdg).join("trace-mcp")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".local/state/trace-mcp")
    }
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::not_found(format!("{}", path.display()))
        } else {
            Error::from(e)
        }
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::decode_failed(format!("{}: {e}", path.display())))
}

pub fn dir_size(path: &Path) -> Result<u64> {
    let mut n = 0u64;
    if !path.exists() {
        return Ok(0);
    }
    for e in walk(path)? {
        if e.is_file() {
            n = n.saturating_add(e.metadata()?.len());
        }
    }
    Ok(n)
}

fn walk(path: &Path) -> Result<Vec<PathBuf>> {
    let mut out = vec![path.to_path_buf()];
    if path.is_dir() {
        for e in fs::read_dir(path)? {
            let e = e?;
            out.extend(walk(&e.path())?);
        }
    }
    Ok(out)
}

fn recover_staging(root: &Path) -> Result<()> {
    let staging = root.join("staging");
    let quarantine = root.join("quarantine");
    fs::create_dir_all(&quarantine)?;
    if let Ok(rd) = fs::read_dir(&staging) {
        for e in rd.flatten() {
            let dest = quarantine.join(e.file_name());
            let _ = fs::rename(e.path(), dest);
        }
    }
    Ok(())
}

fn validate_bundle_paths(root: &Path) -> Result<()> {
    let root = fs::canonicalize(root)?;
    for p in walk(&root)? {
        let canon = fs::canonicalize(&p).unwrap_or(p.clone());
        if !canon.starts_with(&root) {
            return Err(Error::invalid_argument(format!(
                "bundle path escapes {}: {}",
                root.display(),
                canon.display()
            )));
        }
    }
    Ok(())
}

fn copy_dir(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let to = dest.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &to)?;
        } else {
            fs::copy(e.path(), to)?;
        }
    }
    Ok(())
}

pub fn write_jsonl<T: Serialize>(path: &Path, rows: &[T]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut w = BufWriter::new(File::create(path)?);
    for row in rows {
        serde_json::to_writer(&mut w, row).map_err(|e| Error::decode_failed(e.to_string()))?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

pub fn cache_key(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    format!("sha256:{}", hex::encode(h.finalize()))
}

pub fn schema_banner() -> u32 {
    SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_and_budget() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_path_buf(), Limits::default()).unwrap();
        assert!(store.ensure_budget(1).is_ok());
        drop(store);
        let _store2 = Store::open(dir.path().to_path_buf(), Limits::default()).unwrap();
    }
}
