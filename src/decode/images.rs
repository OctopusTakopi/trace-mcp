use std::collections::HashMap;
use std::path::{Path, PathBuf};

use object::{Object, ObjectKind, ObjectSegment, ObjectSymbol};
use sha2::{Digest, Sha256};

use crate::error::{Error, ErrorCode, Result};
use crate::model::ImageIdentity;

#[derive(Debug, Clone)]
pub struct ArchivedImage {
    pub identity: ImageIdentity,
    pub archive_path: PathBuf,
    pub bytes: Vec<u8>,
}

pub fn content_hash(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{}", hex::encode(h.finalize()))
}

pub fn hash_file(path: &Path) -> Result<(Vec<u8>, String)> {
    let bytes = std::fs::read(path)?;
    let hash = content_hash(&bytes);
    Ok((bytes, hash))
}

pub fn elf_build_id(bytes: &[u8]) -> Result<Option<String>> {
    let file = object::File::parse(bytes).map_err(|e| Error::decode_failed(e.to_string()))?;
    Ok(file.build_id().ok().flatten().map(hex::encode))
}

pub fn reject_if_not_elf64(bytes: &[u8], path: &Path) -> Result<()> {
    let file = object::File::parse(bytes)
        .map_err(|e| Error::invalid_argument(format!("cannot parse {}: {e}", path.display())))?;
    match file.kind() {
        ObjectKind::Executable | ObjectKind::Dynamic | ObjectKind::Relocatable => {}
        other => {
            return Err(Error::invalid_argument(format!(
                "{} is not a usable ELF image ({other:?})",
                path.display()
            )));
        }
    }
    if !file.is_64() {
        return Err(Error::new(
            ErrorCode::UnsupportedPtConfig,
            format!("{} is not 64-bit ELF", path.display()),
        )
        .with_next("v0.1 supports native 64-bit ELF only"));
    }
    Ok(())
}

/// Convert a runtime virtual address to an image-relative ELF VM address
/// using the mapping's file offset and PT_LOAD segments. Do not use
/// `ip - mapping_start` alone.
pub fn image_relative_addr(ip: u64, map_start: u64, pgoff: u64, bytes: &[u8]) -> Option<u64> {
    let file_off = ip.checked_sub(map_start)?.checked_add(pgoff)?;
    let file = object::File::parse(bytes).ok()?;
    for seg in file.segments() {
        let (off, sz) = seg.file_range();
        if file_off >= off && file_off < off.saturating_add(sz) {
            return Some(seg.address().saturating_add(file_off - off));
        }
    }
    Some(file_off)
}

#[derive(Debug, Clone)]
pub struct FuncRange {
    pub name: String,
    pub demangled: String,
    pub start: u64,
    pub end: u64,
}

/// One `PT_LOAD` segment: file range and its virtual address.
#[derive(Debug, Clone, Copy)]
pub struct Segment {
    pub file_off: u64,
    pub file_size: u64,
    pub vaddr: u64,
}

/// Pre-parsed ELF facts for one archived image so per-sample address
/// resolution never re-parses the file.
#[derive(Debug, Clone)]
pub struct ImageIndex {
    pub segments: Vec<Segment>,
    pub funcs: Vec<FuncRange>,
}

impl ImageIndex {
    pub fn build(bytes: &[u8]) -> Self {
        let segments = object::File::parse(bytes)
            .map(|f| {
                f.segments()
                    .map(|seg| {
                        let (file_off, file_size) = seg.file_range();
                        Segment {
                            file_off,
                            file_size,
                            vaddr: seg.address(),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let funcs = function_ranges(bytes).unwrap_or_default();
        Self { segments, funcs }
    }

    /// Runtime virtual address to image VM address via file offset and
    /// `PT_LOAD` segments. Do not use `ip - mapping_start` alone.
    #[inline]
    pub fn relative_addr(&self, ip: u64, map_start: u64, pgoff: u64) -> Option<u64> {
        let file_off = ip.checked_sub(map_start)?.checked_add(pgoff)?;
        for seg in &self.segments {
            if file_off >= seg.file_off && file_off < seg.file_off.saturating_add(seg.file_size) {
                return Some(seg.vaddr.saturating_add(file_off - seg.file_off));
            }
        }
        Some(file_off)
    }

    /// Runtime virtual address to the offset in the archived file bytes
    /// (`ip - map_start + pgoff`). This, not `relative_addr`, indexes the
    /// bytes: PT_LOAD segments are usually loaded at a different virtual
    /// address than their file offset.
    #[inline]
    pub fn file_offset(ip: u64, map_start: u64, pgoff: u64) -> Option<u64> {
        ip.checked_sub(map_start)?.checked_add(pgoff)
    }

    #[inline]
    pub fn function(&self, rel: u64) -> Option<&FuncRange> {
        lookup_function(&self.funcs, rel)
    }
}

pub fn function_ranges(bytes: &[u8]) -> Result<Vec<FuncRange>> {
    let file = object::File::parse(bytes).map_err(|e| Error::decode_failed(e.to_string()))?;
    let mut out = Vec::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        if !sym.is_definition() {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() || name.starts_with('$') {
            continue;
        }
        let addr = sym.address();
        let size = sym.size().max(1);
        if addr == 0 {
            continue;
        }
        // Alternate form drops the `::h<hash>` / `[<crate-hash>]` disambiguators.
        let demangled = format!("{:#}", rustc_demangle::demangle(name));
        out.push(FuncRange {
            name: name.to_string(),
            demangled,
            start: addr,
            end: addr.saturating_add(size),
        });
    }
    out.sort_by_key(|f| f.start);
    Ok(out)
}

pub fn lookup_function(ranges: &[FuncRange], addr: u64) -> Option<&FuncRange> {
    let i = ranges.partition_point(|f| f.start <= addr);
    if i == 0 {
        return None;
    }
    let f = &ranges[i - 1];
    (addr >= f.start && addr < f.end).then_some(f)
}

pub fn source_location(archive_path: &Path, addr: u64) -> Option<(String, u32)> {
    let loader = addr2line::Loader::new(archive_path).ok()?;
    let loc = loader.find_location(addr).ok()??;
    Some((loc.file.unwrap_or("").to_string(), loc.line.unwrap_or(0)))
}

pub fn archive_image(src: &Path, dest_root: &Path, recorded_path: &str) -> Result<ArchivedImage> {
    let (bytes, hash) = hash_file(src)?;
    if let Err(err) = reject_if_not_elf64(&bytes, src) {
        tracing::debug!(error = %err, path = %src.display(), "image is not 64-bit ELF; archiving bytes anyway");
    }
    let build_id = elf_build_id(&bytes).ok().flatten();
    let dir = dest_root.join(hash.trim_start_matches("sha256:"));
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join(file_name_of(recorded_path));
    if !dest.exists() {
        std::fs::write(&dest, &bytes)?;
    }
    Ok(ArchivedImage {
        identity: ImageIdentity {
            path: recorded_path.to_string(),
            content_hash: hash,
            build_id,
            archived: true,
        },
        archive_path: dest,
        bytes,
    })
}

fn file_name_of(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "image".into())
}

/// Archive bytes that have no source file (the `[vdso]` image read from a
/// process's memory). Identity is by content hash; build id if the ELF has one.
pub fn archive_bytes(
    bytes: Vec<u8>,
    dest_root: &Path,
    recorded_path: &str,
) -> Result<ArchivedImage> {
    let hash = content_hash(&bytes);
    let build_id = elf_build_id(&bytes).ok().flatten();
    let dir = dest_root.join(hash.trim_start_matches("sha256:"));
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join(file_name_of(recorded_path));
    if !dest.exists() {
        std::fs::write(&dest, &bytes)?;
    }
    Ok(ArchivedImage {
        identity: ImageIdentity {
            path: recorded_path.to_string(),
            content_hash: hash,
            build_id,
            archived: true,
        },
        archive_path: dest,
        bytes,
    })
}

/// Read this process's `[vdso]` image. The vdso is identical for every
/// process on a running kernel, so it is valid evidence for a local capture.
pub fn read_own_vdso() -> Option<Vec<u8>> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let line = maps.lines().find(|l| l.ends_with("[vdso]"))?;
    let range = line.split_whitespace().next()?;
    let (a, b) = range.split_once('-')?;
    let (a, b) = (
        u64::from_str_radix(a, 16).ok()?,
        u64::from_str_radix(b, 16).ok()?,
    );
    let len = usize::try_from(b.checked_sub(a)?).ok()?;
    if len == 0 || len > 1 << 20 {
        return None;
    }
    // SAFETY: the range comes from this process's own current mapping table
    // and the vdso stays mapped for the life of the process; only reads happen.
    let bytes = unsafe { std::slice::from_raw_parts(a as *const u8, len) }.to_vec();
    (bytes.starts_with(b"\x7fELF")).then_some(bytes)
}

/// perf's build-id cache layout: `<dir>/.build-id/xx/<rest>` holding the
/// image bytes. `perf --buildid-dir <dir>` reads symbols and instruction
/// bytes from here before it ever looks at the recorded path, and checks the
/// build id, so a rebuilt workspace binary is never silently used. Images
/// without a build id cannot be placed here; the caller reports those.
pub fn build_buildid_cache(images: &[ArchivedImage], dest: &Path) -> Result<Vec<String>> {
    std::fs::create_dir_all(dest)?;
    let mut uncached = Vec::new();
    for img in images {
        let Some(bid) = img.identity.build_id.as_deref().filter(|b| b.len() > 2) else {
            if !img.identity.path.starts_with('[') {
                uncached.push(img.identity.path.clone());
            }
            continue;
        };
        let dir = dest.join(".build-id").join(&bid[..2]);
        std::fs::create_dir_all(&dir)?;
        let target = dir.join(&bid[2..]);
        if !target.exists() {
            std::fs::copy(&img.archive_path, &target)?;
        }
    }
    Ok(uncached)
}

/// Layout a `--symfs` tree so recorded absolute paths resolve into the archive,
/// not the current workspace. Not used for PT decoding any more: perf looks
/// for its own `/tmp/perf-vdso.so-*` copy *inside* the symfs prefix and
/// therefore cannot decode vdso code with `--symfs` set.
pub fn build_symfs(images: &[ArchivedImage], dest: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dest)?;
    for img in images {
        let recorded = Path::new(&img.identity.path);
        let rel = recorded.strip_prefix("/").unwrap_or(recorded);
        let target = dest.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !target.exists() {
            std::fs::copy(&img.archive_path, &target)?;
        }
    }
    Ok(dest.to_path_buf())
}

pub struct ImageSet {
    pub images: Vec<ArchivedImage>,
    pub by_path: HashMap<String, usize>,
}

impl ImageSet {
    pub fn hash(&self) -> String {
        let mut h = Sha256::new();
        for img in &self.images {
            h.update(img.identity.content_hash.as_bytes());
            h.update(img.identity.path.as_bytes());
        }
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    pub fn get(&self, path: &str) -> Option<&ArchivedImage> {
        self.by_path.get(path).and_then(|&i| self.images.get(i))
    }
}

pub fn read_image_at(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    std::io::Read::read_exact(&mut f, &mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_stable() {
        assert_eq!(content_hash(b"abc"), content_hash(b"abc"));
        assert_ne!(content_hash(b"abc"), content_hash(b"abd"));
    }

    #[test]
    fn buildid_cache_layout_and_uncached_report() {
        let dir = tempfile::tempdir().unwrap();
        let with_id = ArchivedImage {
            identity: ImageIdentity {
                path: "/x/a".into(),
                content_hash: "sha256:a".into(),
                build_id: Some("abcdef0123".into()),
                archived: true,
            },
            archive_path: dir.path().join("a"),
            bytes: b"A".to_vec(),
        };
        std::fs::write(&with_id.archive_path, b"A").unwrap();
        let without = ArchivedImage {
            identity: ImageIdentity {
                path: "/x/b".into(),
                content_hash: "sha256:b".into(),
                build_id: None,
                archived: true,
            },
            archive_path: dir.path().join("b"),
            bytes: b"B".to_vec(),
        };
        let cache = dir.path().join("cache");
        let uncached = build_buildid_cache(&[with_id, without], &cache).unwrap();
        assert_eq!(uncached, vec!["/x/b".to_string()]);
        assert_eq!(
            std::fs::read(cache.join(".build-id/ab/cdef0123")).unwrap(),
            b"A"
        );
    }

    #[test]
    fn own_vdso_is_elf() {
        let v = read_own_vdso().expect("vdso");
        assert!(elf_build_id(&v).is_ok());
    }

    #[test]
    fn symfs_serves_archived_bytes_after_path_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let recorded = dir.path().join("workspace").join("pt_fixture");
        std::fs::create_dir_all(recorded.parent().unwrap()).unwrap();
        std::fs::write(&recorded, b"OLD-BYTES").unwrap();
        let archive_root = dir.path().join("images");
        let archived = archive_image(&recorded, &archive_root, recorded.to_str().unwrap()).unwrap();
        std::fs::write(&recorded, b"NEW-REBUILT-AT-SAME-PATH").unwrap();
        let symfs = dir.path().join("symfs");
        build_symfs(&[archived], &symfs).unwrap();
        let rel = recorded.strip_prefix("/").unwrap();
        let served = std::fs::read(symfs.join(rel)).unwrap();
        assert_eq!(served, b"OLD-BYTES");
        assert_eq!(
            std::fs::read(&recorded).unwrap(),
            b"NEW-REBUILT-AT-SAME-PATH"
        );
    }
}
