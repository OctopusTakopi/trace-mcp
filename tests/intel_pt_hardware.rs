//! Opt-in Intel PT hardware suite. Ordinary CI must not invoke this.
//!
//!   cargo test --release --test intel_pt_hardware -- --ignored --nocapture
//!
//! Use `--release`: the debug-build decoder is an order of magnitude slower
//! and larger captures then exceed the CLI job wait.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trace-mcp")
}

fn fixture() -> PathBuf {
    let target = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
    let profiling = target.join("profiling/examples/pt_fixture");
    if profiling.is_file() {
        return profiling;
    }
    target.join("debug/examples/pt_fixture")
}

fn ensure_fixture() {
    if fixture().is_file() {
        return;
    }
    let status = Command::new("cargo")
        .args(["build", "--profile", "profiling", "--example", "pt_fixture"])
        .status()
        .expect("build fixture");
    assert!(status.success(), "failed to build pt_fixture");
}

fn capture(store: &Path, fixture_bin: &Path, extra: &[&str]) -> (String, String) {
    let mut cmd = Command::new(bin());
    cmd.args([
        "--store",
        store.to_str().unwrap(),
        "run",
        "--after-ms",
        "80",
        "--",
        fixture_bin.to_str().unwrap(),
    ]);
    cmd.args(extra);
    let out = cmd.output().expect("run capture");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    eprintln!("{stderr}");
    let snap = field(&stderr, "snapshot_id=").expect("snapshot_id in stderr");
    let analysis = field(&stderr, "analysis_id=").unwrap_or_default();
    if !out.status.success() {
        panic!("capture failed\n{stdout}\n{stderr}");
    }
    (snap, analysis)
}

fn field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        l.split_whitespace()
            .find_map(|tok| tok.strip_prefix(key).map(|s| s.to_string()))
            .or_else(|| l.strip_prefix(key).map(|s| s.to_string()))
    })
}

fn query_json(store: &Path, snap: &str, kind: &str) -> serde_json::Value {
    query_json_args(store, snap, kind, &[])
}

fn query_json_args(store: &Path, snap: &str, kind: &str, extra: &[&str]) -> serde_json::Value {
    let out = Command::new(bin())
        .args([
            "--store",
            store.to_str().unwrap(),
            "query",
            snap,
            "--kind",
            kind,
            "--json",
        ])
        .args(extra)
        .output()
        .expect("query");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout).unwrap_or_else(|_| {
        panic!(
            "query json failed: {stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
#[ignore]
fn doctor_probe_succeeds_or_explains() {
    let out = Command::new(bin())
        .args(["doctor", "--probe", "--json"])
        .output()
        .expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    println!("{stdout}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("doctor json");
    let probe_ok = report
        .pointer("/probe/ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !probe_ok {
        panic!(
            "doctor --probe did not capture/decode PT on this host:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
#[ignore]
fn cond_loop_not_taken_fraction() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let (snap, _) = capture(dir.path(), &fixture(), &["--iters", "100"]);
    let timeline = query_json_args(
        dir.path(),
        &snap,
        "timeline",
        &["--function", "ptfx_cond_loop"],
    );
    let rows = timeline["data"].as_array().expect("timeline data");
    let row = rows
        .iter()
        .find(|r| {
            r["function"]
                .as_str()
                .is_some_and(|n| n.contains("ptfx_cond_loop"))
        })
        .or_else(|| rows.first())
        .expect("timeline row");
    let thread = row["thread_id"].as_str().expect("thread_id");
    let start = row["start_ns"].as_u64().unwrap_or(0);
    let end = row["end_ns"]
        .as_u64()
        .unwrap_or(start.saturating_add(1_000_000));
    let end = end.max(start + 1);
    let out = Command::new(bin())
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "decode",
            &snap,
            "--detail",
            "instructions",
            "--thread-id",
            thread,
            "--start-ns",
            &start.to_string(),
            "--end-ns",
            &end.to_string(),
        ])
        .output()
        .expect("instruction decode");
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stderr}");
    assert!(out.status.success(), "instruction decode failed: {stderr}");
    let insn_id = field(&stderr, "analysis_id=").expect("instruction analysis_id");
    let branches = Command::new(bin())
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "query",
            &snap,
            "--kind",
            "branches",
            "--analysis-id",
            &insn_id,
            "--json",
        ])
        .output()
        .expect("branches query");
    let stdout = String::from_utf8_lossy(&branches.stdout);
    println!("{stdout}");
    let page: serde_json::Value = serde_json::from_str(&stdout).expect("branches json");
    let sites = page["data"].as_array().cloned().unwrap_or_default();
    let with_known: Vec<_> = sites
        .iter()
        .filter(|s| {
            let t = s["taken"]
                .as_str()
                .and_then(|x| x.parse::<u64>().ok())
                .unwrap_or(0);
            let n = s["not_taken"]
                .as_str()
                .and_then(|x| x.parse::<u64>().ok())
                .unwrap_or(0);
            t + n > 0
        })
        .collect();
    assert!(
        !with_known.is_empty(),
        "expected known taken/not-taken outcomes: {page}"
    );
}

#[test]
#[ignore]
fn rebuild_at_same_path_uses_archive() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let stable = dir.path().join("pt_fixture");
    std::fs::copy(fixture(), &stable).unwrap();
    let store = dir.path().join("store");
    let (snap, _) = capture(&store, &stable, &["--iters", "2000"]);
    let before = query_json_args(&store, &snap, "hotpaths", &["--function", "ptfx_"]);
    std::fs::write(&stable, b"not-an-elf-anymore").unwrap();
    let derived = store.join("snapshots").join(&snap).join("derived");
    let _ = std::fs::remove_dir_all(&derived);
    let dec = Command::new(bin())
        .args([
            "--store",
            store.to_str().unwrap(),
            "decode",
            &snap,
            "--detail",
            "calls",
        ])
        .output()
        .expect("redecode");
    eprintln!("{}", String::from_utf8_lossy(&dec.stderr));
    assert!(
        dec.status.success(),
        "redecode after rebuild must use archived image"
    );
    let after = query_json_args(&store, &snap, "hotpaths", &["--function", "ptfx_"]);
    let before_s = before["data"].to_string();
    let after_s = after["data"].to_string();
    assert!(
        before_s.contains("ptfx_") && after_s.contains("ptfx_"),
        "archived decode should keep fixture symbols after path rebuild\nbefore={before_s}\nafter={after_s}"
    );
}

fn manifest(store: &Path, snap: &str) -> serde_json::Value {
    let p = store.join("snapshots").join(snap).join("manifest.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
#[ignore]
fn symbol_trigger_snapshots_on_nth_hit() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "run",
            "--trigger-symbol",
            "ptfx_slow_path",
            "--trigger-hits",
            "20",
            "--tail-ms",
            "25",
            "--",
            fixture().to_str().unwrap(),
            "--candidate",
            "--spin-ms",
            "150",
            "--iters",
            "2000",
        ])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stderr}");
    let snap = field(&stderr, "snapshot_id=").expect("snapshot_id");
    let m = manifest(dir.path(), &snap);
    assert_eq!(m["capture_reason"], "trigger", "{m}");
    assert_eq!(m["trigger"]["symbol"], "ptfx_slow_path");
    assert!(m["trigger_address"].as_str().is_some(), "{m}");
    let summary = query_json(dir.path(), &snap, "summary");
    let hit = summary["data"][0]["trigger_hit_ns"]
        .as_u64()
        .unwrap_or_else(|| panic!("trigger trap must be located in the trace: {summary}"));
    assert!(
        summary["data"][0]["covered_end_ns"]
            .as_u64()
            .is_some_and(|end| end > hit),
        "tail capture must retain execution after the trigger: {summary}"
    );
    let hot = query_json_args(
        dir.path(),
        &snap,
        "hotpaths",
        &["--function", "ptfx_slow_path", "--group", "function"],
    );
    assert!(hot["data"].to_string().contains("ptfx_slow_path"));
}

#[test]
#[ignore]
fn address_filter_traces_only_the_symbol() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "run",
            "--address-filter",
            "filter:ptfx_slow_path",
            "--after-ms",
            "150",
            "--",
            fixture().to_str().unwrap(),
            "--candidate",
            "--spin-ms",
            "400",
            "--iters",
            "2000",
        ])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stderr}");
    let snap = field(&stderr, "snapshot_id=").expect("snapshot_id");
    let m = manifest(dir.path(), &snap);
    let filters = m["address_filters"].to_string();
    assert!(filters.contains("filter 0x"), "{m}");
    let hot = query_json_args(dir.path(), &snap, "hotpaths", &["--group", "function"]);
    let rows = hot["data"].to_string();
    let summary = query_json(dir.path(), &snap, "summary");
    assert!(
        rows.contains("ptfx_slow_path"),
        "rows={rows}\nsummary={summary}"
    );
    assert!(
        !rows.contains("ptfx_cond_loop") && !rows.contains("ptfx_slow_work"),
        "code outside the filter range must not produce spans: {rows}"
    );
    let summary = query_json(dir.path(), &snap, "summary");
    assert!(
        summary["data"][0]["quality"]["notes"]
            .to_string()
            .contains("address filter active")
    );
}

#[test]
#[ignore]
fn pinned_cpus_capture_is_scoped_to_the_workload() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "run",
            "--cpus",
            "2,3",
            "--aux-bytes",
            "1048576",
            "--after-ms",
            "200",
            "--",
            fixture().to_str().unwrap(),
            "--spin-ms",
            "400",
            "--iters",
            "500",
        ])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stderr}");
    let snap = field(&stderr, "snapshot_id=").expect("snapshot_id");
    let m = manifest(dir.path(), &snap);
    // Direct recorder: `cpus` only pins the workload, the capture stays
    // task scoped. perf record: -C makes it cpu-wide.
    let direct = m["recorder"] == "direct";
    if direct {
        assert_eq!(m["scope"]["kind"], "task", "{m}");
        assert!(m["perf_argv"].to_string().contains("--cpus"), "{m}");
    } else {
        assert_eq!(m["scope"]["kind"], "cpu_wide", "{m}");
        assert_eq!(m["scope"]["cpus"], serde_json::json!([2, 3]));
    }
    let summary = query_json(dir.path(), &snap, "summary");
    let row = &summary["data"][0];
    let threads = row["threads"].as_array().expect("threads");
    assert!(!threads.is_empty(), "{summary}");
    assert!(
        threads.iter().all(|t| t["comm"] == "pt_fixture"),
        "only the workload's threads may appear: {summary}"
    );
    let argv = std::fs::read_to_string(
        dir.path()
            .join("snapshots")
            .join(&snap)
            .join("derived")
            .join(summary["analysis_id"].as_str().unwrap())
            .join("manifest.json"),
    )
    .unwrap();
    assert!(
        direct || argv.contains("--pid="),
        "decode must prefilter by traced pids: {argv}"
    );
    let hot = query_json_args(
        dir.path(),
        &snap,
        "hotpaths",
        &["--function", "ptfx_", "--group", "function"],
    );
    assert!(hot["data"].to_string().contains("ptfx_entry"), "{hot}");
}

#[test]
#[ignore]
fn inline_attribution_names_inlined_helper() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let (snap, _) = capture(
        dir.path(),
        &fixture(),
        &["--iters", "300", "--spin-ms", "200"],
    );
    let hot = query_json_args(
        dir.path(),
        &snap,
        "hotpaths",
        &["--group", "inline", "--function", "ptfx_nested_a"],
    );
    let rows = hot["data"].as_array().expect("rows");
    let helper = rows
        .iter()
        .find(|r| {
            r["path"]
                .as_str()
                .is_some_and(|p| p.contains("ptfx_inlined_helper"))
        })
        .unwrap_or_else(|| panic!("inlined helper row missing: {hot}"));
    let insns: u64 = helper["instructions"].as_str().unwrap().parse().unwrap();
    assert!(insns > 0, "{hot}");
}

/// Native (libipt) decode must reconstruct the same spans as perf script.
#[test]
#[ignore]
fn native_decoder_matches_perf_script() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let (snap, perf_a) = capture(
        dir.path(),
        &fixture(),
        &["--iters", "300", "--spin-ms", "100"],
    );
    let out = Command::new(bin())
        .env("TRACE_MCP_DECODER", "native")
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "decode",
            &snap,
            "--detail",
            "calls",
        ])
        .output()
        .expect("perf decode");
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stderr}");
    let native_a = field(&stderr, "analysis_id=")
        .expect("native analysis_id")
        .replace('"', "");
    let perf_a = perf_a.replace('"', "");
    type SpanKey = (String, Option<u64>, Option<u64>, Option<u64>, String);
    let load = |a: &str| -> Vec<SpanKey> {
        let p = dir
            .path()
            .join("snapshots")
            .join(&snap)
            .join("derived")
            .join(a)
            .join("spans.jsonl");
        let mut v: Vec<_> = std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .map(|l| {
                let s: serde_json::Value = serde_json::from_str(l).unwrap();
                (
                    s["thread"].as_str().unwrap().to_string(),
                    s["function"].as_u64(),
                    s["start"]["relative_ns"].as_u64(),
                    s["end"]["relative_ns"].as_u64(),
                    s["completeness"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        v.sort();
        v
    };
    let native = load(&native_a);
    let perf = load(&perf_a);
    let complete = |v: &Vec<SpanKey>| v.iter().filter(|s| s.4 == "complete").count();
    let (nc, pc) = (complete(&native), complete(&perf));
    eprintln!(
        "native spans {} ({nc} complete), perf spans {} ({pc} complete)",
        native.len(),
        perf.len()
    );
    assert!(nc > 0 && pc > 0);
    let ratio = nc as f64 / pc as f64;
    assert!(
        (0.95..=1.05).contains(&ratio),
        "complete span counts differ by more than 5%: native {nc} vs perf {pc}"
    );
}

#[test]
#[ignore]
fn fifo_trigger_from_workload() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "run",
            "--trigger-fifo",
            "--",
            fixture().to_str().unwrap(),
            "--spin-ms",
            "1000",
            "--iters",
            "500",
            "--trigger-after",
            "50",
        ])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stderr}");
    let snap = field(&stderr, "snapshot_id=").expect("snapshot_id");
    let m = manifest(dir.path(), &snap);
    assert_eq!(m["capture_reason"], "trigger", "{m}");
    assert!(
        m["diagnostics"].to_string().contains("fixture round 50"),
        "{m}"
    );
}

#[test]
#[ignore]
fn compare_identifies_slow_path() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let (base, _) = capture(dir.path(), &fixture(), &["--iters", "8000"]);
    let (cand, _) = capture(dir.path(), &fixture(), &["--iters", "8000", "--candidate"]);
    let out = Command::new(bin())
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "compare",
            &base,
            &cand,
            "--json",
        ])
        .output()
        .expect("compare");
    let stdout = String::from_utf8_lossy(&out.stdout);
    println!("{stdout}");
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(
        stdout.contains("ptfx_slow_path") || stdout.contains("slow_path"),
        "compare should surface the candidate slow path"
    );
}

#[test]
#[ignore]
fn tiny_aux_does_not_claim_complete_history() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(bin())
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "run",
            "--aux-bytes",
            "262144",
            "--after-ms",
            "200",
            "--",
            fixture().to_str().unwrap(),
            "--iters",
            "800000",
        ])
        .output()
        .expect("tiny aux capture");
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stderr}");
    assert!(out.status.success(), "tiny AUX capture failed: {stderr}");
    let snap = field(&stderr, "snapshot_id=").expect("snapshot_id in stderr");
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            dir.path()
                .join("snapshots")
                .join(&snap)
                .join("manifest.json"),
        )
        .expect("snapshot manifest"),
    )
    .expect("snapshot manifest JSON");
    let wrapped = manifest
        .get("wrapped_rings")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0);
    assert!(wrapped > 0, "tiny AUX ring should wrap: {manifest}");
    assert!(
        stderr.contains("AUX ring") && stderr.contains("wrapped"),
        "run summary should report the wrap: {stderr}"
    );
    assert!(
        stderr.contains("--aux-bytes"),
        "run summary should recommend a larger ring: {stderr}"
    );
    assert!(
        stderr.contains("aux=256KiB/thread"),
        "run summary should report a sub-MiB ring exactly: {stderr}"
    );

    let q = query_json(dir.path(), &snap, "quality");
    println!("{}", serde_json::to_string_pretty(&q).unwrap());
    let trunc = q
        .pointer("/data/ring_truncation")
        .and_then(|v| v.as_bool())
        .or_else(|| {
            q.pointer("/quality/ring_truncation")
                .and_then(|v| v.as_bool())
        })
        .unwrap_or(false);
    let incomplete = q
        .pointer("/data/incomplete_span_count")
        .and_then(|v| v.as_str())
        .or_else(|| {
            q.pointer("/data/undecodable_prefix")
                .and_then(|v| v.as_bool().map(|b| if b { "1" } else { "0" }))
        });
    assert!(
        trunc || incomplete.unwrap_or("0") != "0" || q.to_string().contains("incomplete"),
        "tiny AUX wrap should expose incomplete history: {q}"
    );
}

#[test]
#[ignore]
fn timing_profile_wall_times() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    for timing in ["low_bandwidth", "balanced", "detailed"] {
        let start = std::time::Instant::now();
        let out = Command::new(bin())
            .args([
                "--store",
                dir.path().join(timing).to_str().unwrap(),
                "run",
                "--timing",
                timing,
                "--after-ms",
                "80",
                "--",
                fixture().to_str().unwrap(),
                "--iters",
                "8000",
            ])
            .output()
            .expect("profile capture");
        let elapsed = start.elapsed();
        eprintln!(
            "timing={timing} wall={:?} status={} stderr_tail={}",
            elapsed,
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(" | ")
        );
        assert!(out.status.success(), "{timing} capture failed");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A workload started through a wrapper (`sh -c "exec ..."`, `cargo run`,
/// a `python3` symlink) must be traced as the program it becomes, not as
/// the wrapper's comm; the direct bundle names its root and forks.
#[test]
#[ignore]
fn wrapper_launch_traces_the_real_program() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    let cmd = format!("exec {} --iters 200 --spin-ms 100", fixture().display());
    let out = Command::new(bin())
        .env("TRACE_MCP_RECORDER", "direct")
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "run",
            "--",
            "sh",
            "-c",
            &cmd,
        ])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stderr}");
    let snap = field(&stderr, "snapshot_id=").expect("snapshot_id");
    let m = manifest(dir.path(), &snap);
    assert_eq!(m["recorder"], "direct", "{m}");
    assert!(m["root_pid"].as_u64().is_some(), "{m}");
    let hot = query_json_args(dir.path(), &snap, "hotpaths", &["--group", "function"]);
    let rows = hot["data"].to_string();
    assert!(
        rows.contains("ptfx_"),
        "no fixture functions traced: {rows}"
    );
    let summary = query_json(dir.path(), &snap, "summary");
    assert!(
        !summary.to_string().contains("other pids"),
        "the program was treated as foreign: {summary}"
    );
}

/// `fast` is a perf-script option; on a direct bundle the decode must
/// still succeed (natively) and say so, instead of handing the bundle to
/// perf script.
#[test]
#[ignore]
fn fast_decode_on_a_direct_bundle_is_native() {
    ensure_fixture();
    let dir = tempfile::tempdir().unwrap();
    // Captured with the direct recorder whatever the environment says.
    let run = Command::new(bin())
        .env("TRACE_MCP_RECORDER", "direct")
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "run",
            "--",
            fixture().to_str().unwrap(),
            "--iters",
            "200",
            "--spin-ms",
            "50",
        ])
        .output()
        .expect("run");
    let run_err = String::from_utf8_lossy(&run.stderr);
    let snap = field(&run_err, "snapshot_id=").expect("snapshot_id");
    let out = Command::new(bin())
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "decode",
            &snap,
            "--detail",
            "calls",
            "--fast",
        ])
        .output()
        .expect("fast decode");
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stderr}");
    assert!(!stderr.contains("decode failed"), "{stderr}");
    let aid = field(&stderr, "analysis_id=")
        .expect("analysis_id")
        .replace('"', "");
    let am: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            dir.path()
                .join("snapshots")
                .join(&snap)
                .join("derived")
                .join(&aid)
                .join("manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        am["decoder_version"]
            .as_str()
            .unwrap()
            .starts_with("libipt"),
        "{am}"
    );
    assert!(
        am["quality"]["notes"]
            .to_string()
            .contains("perf-script option"),
        "{am}"
    );
}
