//! Minimal `perf.data` reader: enough of the file format to locate the
//! Intel PT AUX streams without decoding them. This is the first piece of
//! the native decoder; today it tells the parallel
//! per-CPU `perf script` path which CPUs actually carry trace data.
//!
//! Layout (little-endian, perf 6.12, verified on this host):
//!
//! ```text
//! perf_file_header { magic u64, size u64, attr_size u64,
//!                    attrs {offset u64, size u64}, data {offset, size}, ... }
//! record: perf_event_header { type u32, misc u16, size u16 } + body
//! PERF_RECORD_AUXTRACE (71): size u64, offset u64, reference u64,
//!                            idx u32, tid u32, cpu u32, reserved u32,
//!                            followed by `size` bytes of raw AUX data.
//! ```

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Error, Result};

const PERF_RECORD_AUXTRACE: u32 = 71;
const MAGIC: &[u8; 8] = b"PERFILE2";

/// One raw AUX blob: which CPU wrote it and how many bytes it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxBlob {
    pub cpu: u32,
    pub tid: u32,
    pub bytes: u64,
    /// File offset of the raw trace bytes.
    pub file_offset: u64,
}

/// Walk the data section and list every AUX blob.
pub fn auxtrace_blobs(path: &Path) -> Result<Vec<AuxBlob>> {
    let mut f = std::fs::File::open(path)?;
    let mut hdr = [0u8; 56];
    f.read_exact(&mut hdr)
        .map_err(|e| Error::decode_failed(format!("perf.data header: {e}")))?;
    if &hdr[..8] != MAGIC {
        return Err(Error::decode_failed(
            "perf.data: bad magic (expected PERFILE2)",
        ));
    }
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let data_off = u64_at(&hdr, 40);
    let data_size = u64_at(&hdr, 48);
    let end = data_off.saturating_add(data_size);
    let mut pos = data_off;
    let mut out = Vec::new();
    let mut rec = [0u8; 8];
    while pos + 8 <= end {
        f.seek(SeekFrom::Start(pos))?;
        if f.read_exact(&mut rec).is_err() {
            break;
        }
        let ty = u32::from_le_bytes(rec[0..4].try_into().unwrap());
        let size = u64::from(u16::from_le_bytes(rec[6..8].try_into().unwrap()));
        if size < 8 {
            return Err(Error::decode_failed(format!(
                "perf.data: record of size {size} at offset {pos}"
            )));
        }
        let mut next = pos + size;
        if ty == PERF_RECORD_AUXTRACE {
            let mut body = [0u8; 40];
            f.read_exact(&mut body)
                .map_err(|e| Error::decode_failed(format!("perf.data: auxtrace body: {e}")))?;
            let aux_size = u64_at(&body, 0);
            let cpu = u32::from_le_bytes(body[32..36].try_into().unwrap());
            let tid = u32::from_le_bytes(body[28..32].try_into().unwrap());
            out.push(AuxBlob {
                cpu,
                tid,
                bytes: aux_size,
                file_offset: pos + size,
            });
            next = next.saturating_add(aux_size);
        }
        pos = next;
    }
    Ok(out)
}

/// Write a copy of `src` that keeps every record except the AUX blobs of
/// other CPUs, so `perf script` on it decodes only `cpu`'s stream. The
/// feature-section table that follows the data section is relocated and
/// its offsets rewritten; feature blobs are copied verbatim.
pub fn split_by_cpu(src: &Path, cpu: u32, dest: &Path) -> Result<()> {
    split_by_cpus(src, &[cpu], dest)
}

/// `split_by_cpu` keeping the AUX blobs of every CPU in `cpus`.
pub fn split_by_cpus(src: &Path, cpus: &[u32], dest: &Path) -> Result<()> {
    let file = std::fs::read(src)?;
    if file.len() < 104 || &file[..8] != MAGIC {
        return Err(Error::decode_failed("perf.data: bad header"));
    }
    let u64_at = |o: usize| u64::from_le_bytes(file[o..o + 8].try_into().unwrap());
    let header_size = u64_at(8) as usize;
    let data_off = u64_at(40) as usize;
    let data_size = u64_at(48) as usize;
    let data_end = data_off + data_size;
    if data_end > file.len() {
        return Err(Error::decode_failed("perf.data: data section beyond EOF"));
    }
    // Feature table: one (offset, size) per set bit in adds_features[4].
    let mut nfeat = 0usize;
    for i in 0..4 {
        nfeat += u64_at(72 + i * 8).count_ones() as usize;
    }
    let table_off = data_end;
    let table_len = nfeat * 16;
    if table_off + table_len > file.len() {
        return Err(Error::decode_failed("perf.data: feature table beyond EOF"));
    }

    let mut out: Vec<u8> = Vec::with_capacity(file.len());
    out.extend_from_slice(&file[..data_off]);
    let mut pos = data_off;
    while pos + 8 <= data_end {
        let ty = u32::from_le_bytes(file[pos..pos + 4].try_into().unwrap());
        let size = u16::from_le_bytes(file[pos + 6..pos + 8].try_into().unwrap()) as usize;
        if size < 8 || pos + size > data_end {
            break;
        }
        if ty == PERF_RECORD_AUXTRACE {
            let aux_size = u64::from_le_bytes(file[pos + 8..pos + 16].try_into().unwrap()) as usize;
            let rec_cpu = u32::from_le_bytes(file[pos + 40..pos + 44].try_into().unwrap());
            let total = size + aux_size;
            if pos + total > data_end {
                break;
            }
            if cpus.contains(&rec_cpu) {
                out.extend_from_slice(&file[pos..pos + total]);
            }
            pos += total;
        } else {
            out.extend_from_slice(&file[pos..pos + size]);
            pos += size;
        }
    }
    let new_data_size = out.len() - data_off;
    // Relocate feature blobs after the new table.
    let new_table_off = out.len();
    let mut table = Vec::with_capacity(table_len);
    let mut blobs = Vec::new();
    let mut next_blob = new_table_off + table_len;
    for i in 0..nfeat {
        let e = table_off + i * 16;
        let off = u64_at(e) as usize;
        let size = u64_at(e + 8) as usize;
        if off + size > file.len() {
            return Err(Error::decode_failed("perf.data: feature blob beyond EOF"));
        }
        table.extend_from_slice(&(next_blob as u64).to_le_bytes());
        table.extend_from_slice(&(size as u64).to_le_bytes());
        blobs.extend_from_slice(&file[off..off + size]);
        next_blob += size;
    }
    out.extend_from_slice(&table);
    out.extend_from_slice(&blobs);
    out[48..56].copy_from_slice(&(new_data_size as u64).to_le_bytes());
    let _ = header_size;
    std::fs::write(dest, out)?;
    Ok(())
}

/// Intel PT decoding parameters from `PERF_RECORD_AUXTRACE_INFO`
/// (perf 6.12 `enum intel_pt_info` order, verified on this host).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntelPtInfo {
    pub pmu_type: u64,
    pub time_shift: u64,
    pub time_mult: u64,
    pub time_zero: u64,
    pub cap_user_time_zero: bool,
    pub tsc_bit: u64,
    pub noretcomp_bit: u64,
    pub have_sched_switch: u64,
    pub snapshot_mode: bool,
    pub per_cpu_mmaps: bool,
    pub mtc_bit: u64,
    pub mtc_freq_bits: u64,
    pub tsc_ctc_ratio_n: u64,
    pub tsc_ctc_ratio_d: u64,
    pub cyc_bit: u64,
    pub max_nonturbo_ratio: u64,
}

impl IntelPtInfo {
    /// perf's `tsc_to_perf_time`.
    pub fn tsc_to_ns(&self, tsc: u64) -> u64 {
        let quot = tsc >> self.time_shift;
        let rem = tsc & ((1u64 << self.time_shift) - 1);
        self.time_zero
            .wrapping_add(quot.wrapping_mul(self.time_mult))
            .wrapping_add((rem.wrapping_mul(self.time_mult)) >> self.time_shift)
    }

    /// Inverse of `tsc_to_ns` (approximate, used to seek by time).
    pub fn ns_to_tsc(&self, ns: u64) -> u64 {
        let delta = ns.wrapping_sub(self.time_zero);
        if self.time_mult == 0 {
            return 0;
        }
        ((u128::from(delta) << self.time_shift) / u128::from(self.time_mult)) as u64
    }
}

/// One sideband record with its `sample_id` trailer fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sideband {
    Mmap {
        pid: u32,
        tid: u32,
        time: u64,
        start: u64,
        len: u64,
        pgoff: u64,
        exec: bool,
        path: String,
    },
    Comm {
        pid: u32,
        tid: u32,
        time: u64,
        comm: String,
        exec: bool,
    },
    Fork {
        pid: u32,
        ppid: u32,
        tid: u32,
        ptid: u32,
        time: u64,
    },
    Exit {
        pid: u32,
        ppid: u32,
        tid: u32,
        ptid: u32,
        time: u64,
    },
    /// Task switched in (`out == false`) or out on `cpu`.
    Switch {
        pid: u32,
        tid: u32,
        cpu: u32,
        time: u64,
        out: bool,
    },
    ItraceStart {
        pid: u32,
        tid: u32,
        cpu: u32,
        time: u64,
    },
    Lost {
        time: u64,
        cpu: u32,
        lost: u64,
    },
}

impl Sideband {
    pub fn time(&self) -> u64 {
        match self {
            Sideband::Mmap { time, .. }
            | Sideband::Comm { time, .. }
            | Sideband::Fork { time, .. }
            | Sideband::Exit { time, .. }
            | Sideband::Switch { time, .. }
            | Sideband::ItraceStart { time, .. }
            | Sideband::Lost { time, .. } => *time,
        }
    }
}

/// Everything the native decoder needs from a `perf.data`.
#[derive(Debug, Default)]
pub struct PerfData {
    pub info: IntelPtInfo,
    pub sideband: Vec<Sideband>,
    pub blobs: Vec<AuxBlob>,
    pub sample_type: u64,
}

const SAMPLE_TID: u64 = 1 << 1;
const SAMPLE_TIME: u64 = 1 << 2;
const SAMPLE_ID: u64 = 1 << 6;
const SAMPLE_CPU: u64 = 1 << 7;
const SAMPLE_STREAM_ID: u64 = 1 << 9;
const SAMPLE_IDENTIFIER: u64 = 1 << 16;
const MISC_COMM_EXEC: u16 = 1 << 13;
const MISC_SWITCH_OUT: u16 = 1 << 13;
const MISC_MMAP_BUILD_ID: u16 = 1 << 14;

struct Trailer {
    pid: u32,
    tid: u32,
    time: u64,
    cpu: u32,
}

fn trailer_len(sample_type: u64) -> usize {
    let mut n = 0;
    for (bit, sz) in [
        (SAMPLE_TID, 8),
        (SAMPLE_TIME, 8),
        (SAMPLE_ID, 8),
        (SAMPLE_STREAM_ID, 8),
        (SAMPLE_CPU, 8),
        (SAMPLE_IDENTIFIER, 8),
    ] {
        if sample_type & bit != 0 {
            n += sz;
        }
    }
    n
}

fn parse_trailer(rec: &[u8], sample_type: u64) -> Trailer {
    let mut t = Trailer {
        pid: 0,
        tid: 0,
        time: 0,
        cpu: 0,
    };
    let n = trailer_len(sample_type);
    if rec.len() < n {
        return t;
    }
    let mut o = rec.len() - n;
    let rd32 = |o: usize| u32::from_le_bytes(rec[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(rec[o..o + 8].try_into().unwrap());
    if sample_type & SAMPLE_TID != 0 {
        t.pid = rd32(o);
        t.tid = rd32(o + 4);
        o += 8;
    }
    if sample_type & SAMPLE_TIME != 0 {
        t.time = rd64(o);
        o += 8;
    }
    if sample_type & SAMPLE_ID != 0 {
        o += 8;
    }
    if sample_type & SAMPLE_STREAM_ID != 0 {
        o += 8;
    }
    if sample_type & SAMPLE_CPU != 0 {
        t.cpu = rd32(o);
    }
    t
}

/// Parse header, first attr, sideband records and AUX blob locations.
pub fn read_perf_data(path: &Path) -> Result<PerfData> {
    let file = std::fs::read(path)?;
    if file.len() < 104 || &file[..8] != MAGIC {
        return Err(Error::decode_failed("perf.data: bad header"));
    }
    let u64_at = |o: usize| u64::from_le_bytes(file[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(file[o..o + 4].try_into().unwrap());
    let attr_size = u64_at(16) as usize;
    let attrs_off = u64_at(24) as usize;
    let attrs_size = u64_at(32) as usize;
    let data_off = u64_at(40) as usize;
    let data_size = u64_at(48) as usize;
    if attrs_size < 40 || attrs_off + 40 > file.len() || data_off + data_size > file.len() {
        return Err(Error::decode_failed("perf.data: sections beyond EOF"));
    }
    let _ = attr_size;
    // sample_type sits at attr offset 24 (type u32, size u32, config u64, period u64).
    let sample_type = u64_at(attrs_off + 24);
    let mut out = PerfData {
        sample_type,
        ..Default::default()
    };
    let mut pos = data_off;
    let end = data_off + data_size;
    while pos + 8 <= end {
        let ty = u32_at(pos);
        let misc = u16::from_le_bytes(file[pos + 4..pos + 6].try_into().unwrap());
        let size = u16::from_le_bytes(file[pos + 6..pos + 8].try_into().unwrap()) as usize;
        if size < 8 || pos + size > end {
            break;
        }
        let rec = &file[pos..pos + size];
        let body = &rec[8..];
        let tr = parse_trailer(rec, sample_type);
        match ty {
            2 => out.sideband.push(Sideband::Lost {
                time: tr.time,
                cpu: tr.cpu,
                lost: u64::from_le_bytes(body[8..16].try_into().unwrap()),
            }),
            3 => {
                let pid = u32_at(pos + 8);
                let tid = u32_at(pos + 12);
                let raw = &body[8..body.len().saturating_sub(trailer_len(sample_type))];
                let comm = String::from_utf8_lossy(raw)
                    .trim_end_matches('\0')
                    .to_string();
                out.sideband.push(Sideband::Comm {
                    pid,
                    tid,
                    time: tr.time,
                    comm,
                    exec: misc & MISC_COMM_EXEC != 0,
                });
            }
            4 | 7 => {
                let pid = u32_at(pos + 8);
                let ppid = u32_at(pos + 12);
                let tid = u32_at(pos + 16);
                let ptid = u32_at(pos + 20);
                let time = u64_at(pos + 24);
                out.sideband.push(if ty == 7 {
                    Sideband::Fork {
                        pid,
                        ppid,
                        tid,
                        ptid,
                        time,
                    }
                } else {
                    Sideband::Exit {
                        pid,
                        ppid,
                        tid,
                        ptid,
                        time,
                    }
                });
            }
            10 => {
                let pid = u32_at(pos + 8);
                let tid = u32_at(pos + 12);
                let start = u64_at(pos + 16);
                let len = u64_at(pos + 24);
                let pgoff = u64_at(pos + 32);
                // 24 bytes of maj/min/ino/ino_generation or build id, then prot, flags.
                let prot = u32_at(pos + 64);
                let name_start = pos + 72;
                let name_end = pos + size - trailer_len(sample_type);
                let path = if name_end > name_start {
                    String::from_utf8_lossy(&file[name_start..name_end])
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    String::new()
                };
                let _ = misc & MISC_MMAP_BUILD_ID;
                out.sideband.push(Sideband::Mmap {
                    pid,
                    tid,
                    time: tr.time,
                    start,
                    len,
                    pgoff,
                    exec: prot & 0x4 != 0,
                    path,
                });
            }
            12 => out.sideband.push(Sideband::ItraceStart {
                pid: u32_at(pos + 8),
                tid: u32_at(pos + 12),
                cpu: tr.cpu,
                time: tr.time,
            }),
            14 => out.sideband.push(Sideband::Switch {
                pid: tr.pid,
                tid: tr.tid,
                cpu: tr.cpu,
                time: tr.time,
                out: misc & MISC_SWITCH_OUT != 0,
            }),
            15 => out.sideband.push(Sideband::Switch {
                pid: tr.pid,
                tid: tr.tid,
                cpu: tr.cpu,
                time: tr.time,
                out: misc & MISC_SWITCH_OUT != 0,
            }),
            70 => {
                let kind = u32_at(pos + 8);
                if kind == 1 && size >= 8 + 8 + 17 * 8 {
                    let p = |i: usize| u64_at(pos + 16 + i * 8);
                    out.info = IntelPtInfo {
                        pmu_type: p(0),
                        time_shift: p(1),
                        time_mult: p(2),
                        time_zero: p(3),
                        cap_user_time_zero: p(4) != 0,
                        tsc_bit: p(5),
                        noretcomp_bit: p(6),
                        have_sched_switch: p(7),
                        snapshot_mode: p(8) != 0,
                        per_cpu_mmaps: p(9) != 0,
                        mtc_bit: p(10),
                        mtc_freq_bits: p(11),
                        tsc_ctc_ratio_n: p(12),
                        tsc_ctc_ratio_d: p(13),
                        cyc_bit: p(14),
                        max_nonturbo_ratio: p(15),
                    };
                }
            }
            71 => {
                let aux_size = u64_at(pos + 8);
                let cpu = u32_at(pos + 40);
                let tid = u32_at(pos + 36);
                out.blobs.push(AuxBlob {
                    cpu,
                    tid,
                    bytes: aux_size,
                    file_offset: (pos + size) as u64,
                });
                pos += aux_size as usize;
            }
            _ => {}
        }
        pos += size;
    }
    // Sideband is written per mmap ring; order it by time for the decoders.
    out.sideband.sort_by_key(|s| s.time());
    Ok(out)
}

/// CPUs with non-empty AUX data, ascending and deduplicated.
pub fn auxtrace_cpus(path: &Path) -> Result<Vec<u32>> {
    let mut cpus: Vec<u32> = auxtrace_blobs(path)?
        .into_iter()
        .filter(|b| b.bytes > 0)
        .map(|b| b.cpu)
        .collect();
    cpus.sort_unstable();
    cpus.dedup();
    Ok(cpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ty: u32, body: &[u8]) -> Vec<u8> {
        let size = 8 + body.len() as u16;
        let mut v = Vec::new();
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&size.to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    fn auxtrace(cpu: u32, data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(data.len() as u64).to_le_bytes()); // size
        body.extend_from_slice(&0u64.to_le_bytes()); // offset
        body.extend_from_slice(&0u64.to_le_bytes()); // reference
        body.extend_from_slice(&0u32.to_le_bytes()); // idx
        body.extend_from_slice(&7u32.to_le_bytes()); // tid
        body.extend_from_slice(&cpu.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let mut r = record(PERF_RECORD_AUXTRACE, &body);
        r.extend_from_slice(data);
        r
    }

    #[test]
    fn lists_cpus_with_aux_data_and_skips_blobs() {
        let mut data = Vec::new();
        data.extend(record(1, &[0u8; 24])); // unrelated record
        data.extend(auxtrace(5, &[0xaa; 100]));
        data.extend(record(2, &[0u8; 16]));
        data.extend(auxtrace(3, &[0xbb; 4096]));
        data.extend(auxtrace(9, &[])); // empty blob: not listed
        data.extend(auxtrace(5, &[0xcc; 8]));
        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);
        file.extend_from_slice(&104u64.to_le_bytes()); // header size
        file.extend_from_slice(&0u64.to_le_bytes()); // attr size
        file.extend_from_slice(&[0u8; 16]); // attrs section
        let data_off = 104u64;
        file.extend_from_slice(&data_off.to_le_bytes());
        file.extend_from_slice(&(data.len() as u64).to_le_bytes());
        file.resize(data_off as usize, 0);
        file.extend(data);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("perf.data");
        std::fs::write(&p, &file).unwrap();
        let blobs = auxtrace_blobs(&p).unwrap();
        assert_eq!(blobs.len(), 4);
        assert_eq!(blobs[0].cpu, 5);
        assert_eq!(blobs[0].bytes, 100);
        assert_eq!(blobs[1].cpu, 3);
        assert_eq!(blobs[1].tid, 7);
        assert_eq!(auxtrace_cpus(&p).unwrap(), vec![3, 5]);
    }

    #[test]
    fn split_keeps_one_cpu_and_relocates_features() {
        let mut data = Vec::new();
        data.extend(record(1, &[0u8; 24]));
        data.extend(auxtrace(5, &[0xaa; 100]));
        data.extend(auxtrace(3, &[0xbb; 50]));
        data.extend(record(2, &[0u8; 16]));
        let feat_a = b"FEATURE-A".to_vec();
        let feat_b = b"feature-b-longer".to_vec();
        let data_off = 104usize;
        let table_off = data_off + data.len();
        let blob_a_off = table_off + 32;
        let blob_b_off = blob_a_off + feat_a.len();
        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);
        file.extend_from_slice(&104u64.to_le_bytes());
        file.extend_from_slice(&0u64.to_le_bytes());
        file.extend_from_slice(&[0u8; 16]);
        file.extend_from_slice(&(data_off as u64).to_le_bytes());
        file.extend_from_slice(&(data.len() as u64).to_le_bytes());
        file.extend_from_slice(&[0u8; 16]); // event_types
        file.extend_from_slice(&0b11u64.to_le_bytes()); // two features
        file.extend_from_slice(&[0u8; 24]);
        assert_eq!(file.len(), 104);
        file.extend(&data);
        file.extend_from_slice(&(blob_a_off as u64).to_le_bytes());
        file.extend_from_slice(&(feat_a.len() as u64).to_le_bytes());
        file.extend_from_slice(&(blob_b_off as u64).to_le_bytes());
        file.extend_from_slice(&(feat_b.len() as u64).to_le_bytes());
        file.extend(&feat_a);
        file.extend(&feat_b);
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("perf.data");
        std::fs::write(&src, &file).unwrap();
        let dst = dir.path().join("cpu3.data");
        split_by_cpu(&src, 3, &dst).unwrap();
        let blobs = auxtrace_blobs(&dst).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].cpu, 3);
        assert_eq!(blobs[0].bytes, 50);
        let out = std::fs::read(&dst).unwrap();
        let u64_at = |o: usize| u64::from_le_bytes(out[o..o + 8].try_into().unwrap());
        let new_data_size = u64_at(48) as usize;
        assert_eq!(new_data_size, data.len() - (8 + 40 + 100));
        let t = data_off + new_data_size;
        let a_off = u64_at(t) as usize;
        let a_len = u64_at(t + 8) as usize;
        let b_off = u64_at(t + 16) as usize;
        assert_eq!(&out[a_off..a_off + a_len], &feat_a[..]);
        assert_eq!(&out[b_off..b_off + feat_b.len()], &feat_b[..]);
    }

    #[test]
    fn tsc_conversion_matches_perf_formula() {
        let info = IntelPtInfo {
            time_shift: 31,
            time_mult: 0x3d1879ab,
            time_zero: 0xfffb6d5b6216b6b3,
            ..Default::default()
        };
        // Round trip within the quantisation of the formula.
        let tsc = 0x1234_5678_9abc;
        let ns = info.tsc_to_ns(tsc);
        let back = info.ns_to_tsc(ns);
        assert!(back.abs_diff(tsc) < 8, "{tsc} -> {ns} -> {back}");
    }

    #[test]
    fn rejects_non_perf_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x");
        std::fs::write(&p, b"not a perf file at all, definitely not").unwrap();
        assert!(auxtrace_blobs(&p).is_err());
    }
}
