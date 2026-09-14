use std::collections::HashMap;
use trace_mcp::analysis::hotpaths::{child_index, hotpaths};
use trace_mcp::analysis::timeline::self_elapsed;
use trace_mcp::model::{
    EventRange, EventTime, FunctionSpan, IntelPtConfig, LocalId, P99_MIN_SAMPLES, Selection,
    SpanCompleteness, ThreadId, nearest_rank, relative_delta,
};
use trace_mcp::service::normalize_capture_bound;

fn span(
    id: u32,
    parent: Option<u32>,
    s: u64,
    e: u64,
    complete: bool,
    name_id: u32,
) -> FunctionSpan {
    FunctionSpan {
        id: LocalId(id),
        thread: ThreadId::from_raw("t_0").unwrap(),
        function: Some(LocalId(name_id)),
        parent: parent.map(LocalId),
        start: EventTime::estimate(s),
        end: EventTime::estimate(e),
        completeness: if complete {
            SpanCompleteness::Complete
        } else {
            SpanCompleteness::OpenEnd
        },
        evidence: EventRange {
            start_id: LocalId(0),
            end_id: LocalId(1),
        },
        call_site: None,
    }
}

#[test]
fn no_p99_below_threshold() {
    let mut spans = Vec::new();
    for i in 0..10u32 {
        spans.push(span(i, None, 0, 10 + u64::from(i), true, 1));
    }
    let mut names = HashMap::new();
    names.insert(1, "f".into());
    let rows = hotpaths(
        &spans,
        &names,
        &Selection {
            thread_id: None,
            start_ns: None,
            end_ns: None,
        },
        &child_index(&spans),
    );
    assert!(rows[0].n_eligible.0 < P99_MIN_SAMPLES as u64);
    assert!(rows[0].p99_ns.is_none());
}

#[test]
fn clipped_window_does_not_count_as_complete_contained() {
    let spans = [span(1, None, 0, 100, true, 1)];
    let mut names = HashMap::new();
    names.insert(1, "f".into());
    let rows = hotpaths(
        &spans,
        &names,
        &Selection {
            thread_id: None,
            start_ns: Some(10),
            end_ns: Some(20),
        },
        &child_index(&spans),
    );
    assert_eq!(rows[0].complete_calls.0, 0);
}

#[test]
fn baseline_zero_relative_is_null() {
    assert!(relative_delta(5, 0).is_none());
}

#[test]
fn self_time_union() {
    assert_eq!(self_elapsed(0, 50, &[(0, 10), (20, 30)], true), Some(30));
}

#[test]
fn quantile_policy() {
    let xs = [1u64, 2, 3, 4];
    assert_eq!(nearest_rank(&xs, 50), Some(2));
}

#[test]
fn requested_stop_raises_capture_bound() {
    let mut config = IntelPtConfig::default();
    normalize_capture_bound(&mut config, Some(120_000), Some(50)).unwrap();
    assert_eq!(config.max_capture_ms, 120_000);
    assert!(normalize_capture_bound(&mut config, Some(0), None).is_err());
    let mut tail_config = IntelPtConfig::default();
    normalize_capture_bound(&mut tail_config, None, Some(60_000)).unwrap();
    assert_eq!(tail_config.max_capture_ms, 60_000);
}
