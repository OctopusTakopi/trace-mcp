//! Controlled native workload for Intel PT capture, reconstruction, and
//! hardware acceptance tests.
//!
//! Named functions stay `#[inline(never)]` so decoded traces can find them.
//! Candidate mode inserts a known extra call path without changing I/O
//! correctness. Loop counts in source are not the acceptance test; M0 checks
//! the emitted assembly for the branch-count case.

use std::hint::black_box;
use std::thread;
use std::time::Duration;

const DEFAULT_ITERS: u32 = 100;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut candidate = false;
    let mut threads = 1u32;
    let mut iters = DEFAULT_ITERS;
    let mut sleep_ms = 0u64;
    let mut spin_ms = 0u64;
    let mut trigger_after = 0u64;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--candidate" => candidate = true,
            "--threads" => {
                i += 1;
                threads = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            "--iters" => {
                i += 1;
                iters = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(DEFAULT_ITERS);
            }
            "--sleep-ms" => {
                i += 1;
                sleep_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--spin-ms" => {
                i += 1;
                spin_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--trigger-after" => {
                // Write to $TRACE_MCP_TRIGGER after this many run_once rounds
                // (only meaningful with --spin-ms).
                i += 1;
                trigger_after = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if sleep_ms > 0 {
        thread::sleep(Duration::from_millis(sleep_ms));
    }

    let mut acc = 0u64;
    if spin_ms > 0 {
        let end = std::time::Instant::now() + Duration::from_millis(spin_ms);
        let mut rounds = 0u64;
        while std::time::Instant::now() < end {
            acc = acc.wrapping_add(run_once(iters, candidate, threads));
            rounds += 1;
            if trigger_after > 0
                && rounds == trigger_after
                && let Ok(path) = std::env::var("TRACE_MCP_TRIGGER")
                && let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path)
            {
                use std::io::Write;
                let _ = writeln!(f, "hit fixture round {rounds}");
            }
        }
    } else {
        acc = run_once(iters, candidate, threads);
    }

    // Keep the computed value live and independent of candidate timing.
    println!("pt_fixture ok {acc}");
}

fn run_once(iters: u32, candidate: bool, threads: u32) -> u64 {
    if threads > 1 {
        thread::scope(|scope| {
            let worker = scope.spawn(|| ptfx_worker(iters, candidate));
            let main_acc = ptfx_entry(iters, candidate);
            main_acc.wrapping_add(worker.join().unwrap())
        })
    } else {
        ptfx_entry(iters, candidate)
    }
}

#[inline(never)]
fn ptfx_entry(iters: u32, candidate: bool) -> u64 {
    let nested = ptfx_nested_a(black_box(iters));
    let rec = ptfx_recurse(black_box(6));
    let cond = ptfx_cond_loop(black_box(iters));
    let indirect = ptfx_indirect(ptfx_indirect_target, black_box(3));
    let tail = ptfx_tail_from(black_box(7));
    let path = if candidate {
        ptfx_slow_path(black_box(iters))
    } else {
        ptfx_fast_path(black_box(iters))
    };
    black_box(nested)
        .wrapping_add(rec)
        .wrapping_add(u64::from(cond))
        .wrapping_add(indirect)
        .wrapping_add(tail)
        .wrapping_add(path)
}

#[inline(never)]
fn ptfx_nested_a(iters: u32) -> u64 {
    ptfx_nested_b(black_box(iters)).wrapping_add(ptfx_inlined_helper(black_box(iters)))
}

/// Always inlined into `ptfx_nested_a`: exists only as a DWARF inline
/// range, so inline attribution must name it under `ptfx_nested_a`.
#[inline(always)]
fn ptfx_inlined_helper(n: u32) -> u64 {
    let mut acc = 0u64;
    let mut i = 0u32;
    while i < n {
        acc = acc.wrapping_mul(31).wrapping_add(u64::from(black_box(i)));
        i = i.wrapping_add(1);
    }
    acc
}

#[inline(never)]
fn ptfx_nested_b(iters: u32) -> u64 {
    black_box(u64::from(iters)).wrapping_add(2)
}

#[inline(never)]
fn ptfx_recurse(n: u32) -> u64 {
    if n == 0 {
        return 1;
    }
    black_box(ptfx_recurse(n - 1)).wrapping_add(u64::from(n))
}

/// Four-way split so the inner condition is taken 3/4 of the time.
/// With `--iters 100`: 75 taken, 25 not-taken for the inner `jcc`.
#[inline(never)]
fn ptfx_cond_loop(n: u32) -> u32 {
    let mut taken = 0u32;
    let mut i = 0u32;
    while i < n {
        if i & 3 != 0 {
            taken = taken.wrapping_add(black_box(1));
        } else {
            black_box(i);
        }
        i = i.wrapping_add(1);
    }
    taken
}

#[inline(never)]
fn ptfx_indirect(f: fn(u64) -> u64, x: u64) -> u64 {
    // Keep an indirect call in the profiling binary; without this, LLVM
    // rewrites the call as a direct `call ptfx_indirect_target`.
    let f = black_box(f);
    f(black_box(x))
}

#[inline(never)]
fn ptfx_indirect_target(x: u64) -> u64 {
    black_box(x).wrapping_mul(3)
}

#[inline(never)]
fn ptfx_tail_from(x: u64) -> u64 {
    ptfx_tail_to(x)
}

#[inline(never)]
fn ptfx_tail_to(x: u64) -> u64 {
    black_box(x).wrapping_add(11)
}

#[inline(never)]
fn ptfx_fast_path(iters: u32) -> u64 {
    black_box(u64::from(iters))
}

#[inline(never)]
fn ptfx_slow_path(iters: u32) -> u64 {
    let mut acc = 0u64;
    for i in 0..iters {
        acc = acc.wrapping_add(ptfx_slow_work(black_box(u64::from(i))));
    }
    acc
}

#[inline(never)]
fn ptfx_slow_work(x: u64) -> u64 {
    black_box(x).wrapping_mul(x).wrapping_add(1)
}

#[inline(never)]
fn ptfx_worker(iters: u32, candidate: bool) -> u64 {
    ptfx_entry(iters, candidate).wrapping_add(1000)
}
