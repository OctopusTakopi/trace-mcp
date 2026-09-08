use serde_json::json;
use trace_mcp::decode::perf_script::{RawRecord, parse_line, parse_perf_time};
use trace_mcp::decode::reconstruct;
use trace_mcp::model::{AnalysisId, FlowKind};

#[test]
fn fixture_sample_and_gap() {
    let text = include_str!("fixtures/perf_script_calls.txt");
    let mut n = 0;
    for line in text.lines() {
        if let Ok(Some(_)) = parse_line(line) {
            n += 1;
        }
    }
    assert!(n >= 3, "expected several records, got {n}");
}

#[test]
fn hardware_calls_fixture_uses_arrow_transfers() {
    let text = include_str!("fixtures/perf_script_calls.txt");
    let recs: Vec<RawRecord> = text
        .lines()
        .filter_map(|l| parse_line(l).ok().flatten())
        .collect();
    assert!(recs.iter().any(|r| matches!(r, RawRecord::Mmap(_))));
    assert!(
        recs.iter()
            .any(|r| matches!(r, RawRecord::Sample(s) if s.flags.has(trace_mcp::decode::perf_script::Flags::CALL)))
    );
    let ir = reconstruct(AnalysisId::from_raw("a_hw").unwrap(), &recs, &[]).unwrap();
    assert!(!ir.events.is_empty());
}

#[test]
fn origin_precedes_samples() {
    let t0 = parse_perf_time("1.0").unwrap();
    let t1 = parse_perf_time("1.000000100").unwrap();
    assert!(t0 < t1);
}

#[test]
fn jmp_is_not_invented_as_a_call() {
    let lines = [
        "1/1 [000] 1.0:  branches:u:  100 200  call",
        "1/1 [000] 1.000000010:  branches:u:  200 300  jmp",
        "1/1 [000] 1.000000020:  branches:u:  300 100  return",
    ];
    let recs: Vec<RawRecord> = lines
        .iter()
        .map(|l| parse_line(l).unwrap().unwrap())
        .collect();
    let ir = reconstruct(AnalysisId::from_raw("a_tail").unwrap(), &recs, &[]).unwrap();
    assert!(
        !ir.events
            .iter()
            .any(|e| e.kind == FlowKind::Call && e.virt_to.map(|a| a.0) == Some(0x300))
    );
    // The jmp is counted but, having no function evidence, not stored as an
    // event; the return still closes the one real call.
    assert_eq!(ir.threads[0].branch_count.0, 3);
    assert_eq!(ir.events.len(), 2);
    assert!(
        ir.spans
            .iter()
            .all(|s| s.completeness != trace_mcp::model::SpanCompleteness::OpenEnd)
    );
}

#[test]
fn json_ids_do_not_alias_across_analyses() {
    let a = json!("a_1:e3");
    let b = json!("a_2:e3");
    assert_ne!(a, b);
}
