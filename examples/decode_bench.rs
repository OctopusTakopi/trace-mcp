//! Offline decoder throughput check: stream a saved `perf script` text file
//! through the parser and call reconstruction.
//!
//!   cargo run --profile profiling --example decode_bench -- calls.txt [image ...]
//!
//! Each `image` is an ELF file whose recorded mapping path equals its own
//! path (use the archived copies under `<snapshot>/symfs/`).

use std::time::Instant;

use trace_mcp::decode::images::ArchivedImage;
use trace_mcp::decode::perf_script::{StreamStats, stream_records};
use trace_mcp::decode::reconstruct::Reconstructor;
use trace_mcp::model::{AnalysisId, ImageIdentity};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("perf script text file");
    let symfs = args.next();
    let mut images = Vec::new();
    for img in args {
        let bytes = std::fs::read(&img).expect("image");
        let recorded = match &symfs {
            Some(root) => format!(
                "/{}",
                img.trim_start_matches(root.as_str())
                    .trim_start_matches('/')
            ),
            None => img.clone(),
        };
        images.push(ArchivedImage {
            identity: ImageIdentity {
                path: recorded,
                content_hash: trace_mcp::decode::images::content_hash(&bytes),
                build_id: None,
                archived: true,
            },
            archive_path: img.into(),
            bytes,
        });
    }
    let file = std::fs::File::open(&path).expect("open");
    let t0 = Instant::now();
    let mut stats = StreamStats::default();
    let mut n = 0u64;
    stream_records(&file, &mut stats, |_| {
        n += 1;
        Ok(())
    })
    .expect("parse");
    let parse = t0.elapsed();
    println!(
        "parse only: {} lines {} MB {} records in {:.2}s = {:.0} MB/s, {:.1} M lines/s",
        stats.lines,
        stats.bytes / 1_000_000,
        n,
        parse.as_secs_f64(),
        stats.bytes as f64 / 1e6 / parse.as_secs_f64(),
        stats.lines as f64 / 1e6 / parse.as_secs_f64()
    );

    let file = std::fs::File::open(&path).expect("open");
    let t0 = Instant::now();
    let mut stats = StreamStats::default();
    let mut recon = Reconstructor::new(AnalysisId::from_raw("a_bench").unwrap(), &images);
    stream_records(&file, &mut stats, |rec| recon.push(&rec)).expect("parse");
    let ir = recon.finish().expect("reconstruct");
    let total = t0.elapsed();
    println!(
        "parse+reconstruct: {:.2}s; events {} spans {} functions {} locations {} gaps {} threads {}",
        total.as_secs_f64(),
        ir.events.len(),
        ir.spans.len(),
        ir.functions.len(),
        ir.locations.len(),
        ir.gaps.len(),
        ir.threads.len()
    );
    for t in &ir.threads {
        println!(
            "  {} tid={} comm={:?} branches={} events={} spans={} gaps={} covered_ms={:.3} segments={} {:?}",
            t.id,
            t.tid,
            t.comm,
            t.branch_count.0,
            t.event_count.0,
            t.span_count.0,
            t.gap_count.0,
            t.covered_ns.0 as f64 / 1e6,
            t.segment_count.0,
            t.segments.iter().take(4).collect::<Vec<_>>()
        );
    }
    for n in &ir.quality.notes {
        let n: String = n.chars().take(300).collect();
        println!("  note: {n}");
    }
    println!("  gaps_by_kind: {:?}", ir.quality.gaps_by_kind);
}
