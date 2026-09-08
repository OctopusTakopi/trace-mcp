//! Dev probe: decode the first packets of one AUX blob with libipt and print
//! what the API returns (status, time, events). Not part of the product.
use libipt::block::BlockDecoder;
use libipt::enc_dec_builder::{Cpu, CpuVendor, Frequency, PtEncoderDecoder};
use std::io::{Read, Seek, SeekFrom};

fn main() {
    let path = std::env::args().nth(1).expect("perf.data");
    let cpu: u32 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let pd = trace_mcp::capture::perfdata::read_perf_data(std::path::Path::new(&path)).unwrap();
    let blob = pd.blobs.iter().find(|b| b.cpu == cpu).expect("blob");
    let mut f = std::fs::File::open(&path).unwrap();
    f.seek(SeekFrom::Start(blob.file_offset)).unwrap();
    let mut buf = vec![0u8; blob.bytes as usize];
    f.read_exact(&mut buf).unwrap();
    let info = &pd.info;
    println!(
        "info tsc_bit {:#x} mtc_bit {:#x} ratio {}/{} nonturbo {}",
        info.tsc_bit,
        info.mtc_bit,
        info.tsc_ctc_ratio_n,
        info.tsc_ctc_ratio_d,
        info.max_nonturbo_ratio
    );
    let b = BlockDecoder::builder()
        .cpu(Cpu::new(CpuVendor::INTEL, 6, 85, 7))
        .freq(Frequency::new(
            3,
            info.max_nonturbo_ratio as u8,
            info.tsc_ctc_ratio_n as u32,
            info.tsc_ctc_ratio_d as u32,
        ));
    let b = unsafe { b.buffer_from_raw(buf.as_mut_ptr(), buf.len()) };
    let mut d = b.build().unwrap();
    for sync in 0..3 {
        let st = d.sync_forward();
        println!(
            "sync {sync}: {st:?} offset {:?} time {:?}",
            d.sync_offset(),
            d.time()
        );
        for i in 0..12 {
            match d.decode_next() {
                Ok((blk, st)) => {
                    println!(
                        "  blk {i}: ip {:#x} end {:#x} ninsn {} class {:?} status {:?} time {:?}",
                        blk.ip(),
                        blk.end_ip(),
                        blk.ninsn(),
                        blk.class(),
                        st,
                        d.time()
                    );
                    let mut s = st;
                    while s.event_pending() {
                        match d.event() {
                            Ok((ev, s2)) => {
                                println!(
                                    "    ev {:?} tsc {:?} status {:?}",
                                    ev.event_type(),
                                    ev.tsc(),
                                    s2
                                );
                                s = s2;
                            }
                            Err(e) => {
                                println!("    ev err {e:?}");
                                break;
                            }
                        }
                    }
                    if s.eos() {
                        break;
                    }
                }
                Err(e) => {
                    println!(
                        "  blk {i}: err {e:?} code {:?} time {:?}",
                        e.code(),
                        d.time()
                    );
                    break;
                }
            }
        }
    }
}
