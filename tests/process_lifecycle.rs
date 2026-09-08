use trace_mcp::model::Target;
use trace_mcp::model::{Limits, QueryKind, QueryRequest, QueryTarget, SnapshotId};
use trace_mcp::service::{App, StartRequest, StatusSelect, start_request_hash};
use trace_mcp::store::Store;

#[test]
fn launch_rejects_empty_argv() {
    let t = Target::Launch {
        argv: vec![],
        cwd: None,
    };
    assert!(t.validate().is_err());
}

#[test]
fn attach_rejects_pid_zero() {
    let t = Target::Attach { pid: 0 };
    assert!(t.validate().is_err());
}

#[test]
fn store_budget_refuses_new_work() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        store_budget: 1,
        ..Limits::default()
    };
    let store = Store::open(dir.path().to_path_buf(), limits).unwrap();
    let err = store.ensure_budget(100).unwrap_err();
    assert_eq!(err.code, trace_mcp::ErrorCode::LimitExceeded);
}

#[tokio::test]
async fn request_id_retry_and_restart_rediscovery() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().to_path_buf(), Limits::default()).unwrap();
    let req = StartRequest {
        request_id: trace_mcp::model::RequestId::from_raw("req_lost_start").unwrap(),
        target: Target::Launch {
            argv: vec!["/bin/true".into()],
            cwd: None,
        },
        config: trace_mcp::model::IntelPtConfig::default(),
        after_ms: Some(80),
        workload: None,
        trigger: None,
        tail_ms: None,
    };
    let hash = start_request_hash(&req);
    let sid = trace_mcp::model::SessionId::from_raw("sess_persisted").unwrap();
    store
        .write_json(
            &store.session_path(&sid),
            &serde_json::json!({
                "schema_version": 1,
                "session_id": sid,
                "request_id": req.request_id,
                "request_hash": hash,
                "state": "captured",
                "snapshot_id": null,
                "job_id": null,
                "target": req.target,
                "config": req.config,
                "after_ms": req.after_ms,
            }),
        )
        .unwrap();
    drop(store);

    let store = Store::open(dir.path().to_path_buf(), Limits::default()).unwrap();
    let (app, _h) = App::start(store);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let first = app
        .start_session(req.clone())
        .await
        .expect("retry same body");
    assert_eq!(first.session_id, sid);
    let listed = app
        .status(StatusSelect::Sessions {
            cursor: None,
            limit: Some(10),
        })
        .await
        .unwrap();
    let data = listed["data"].as_array().expect("session list");
    assert!(
        data.iter().any(|s| s["request_id"] == "req_lost_start"),
        "restart list missing request: {listed}"
    );

    let mut other = req.clone();
    other.target = Target::Launch {
        argv: vec!["/bin/false".into()],
        cwd: None,
    };
    let err = app.start_session(other).await.unwrap_err();
    assert_eq!(err.code, trace_mcp::ErrorCode::InvalidArgument);
    app.shutdown().await;
}

#[tokio::test]
async fn compare_queue_and_decode_slots_refuse_when_full() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        max_pending_expensive: 0,
        max_decode_jobs: 0,
        ..Limits::default()
    };
    let store = Store::open(dir.path().to_path_buf(), limits).unwrap();
    let snap = SnapshotId::from_raw("s_queue").unwrap();
    let snap_dir = store.snapshot_dir(&snap);
    std::fs::create_dir_all(&snap_dir).unwrap();
    std::fs::write(
        snap_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "snapshot_id": snap,
            "session_id": "sess_q",
            "capture_reason": "stop",
            "lifecycle": "captured",
            "requested_config": {
                "timing": "balanced",
                "aux_bytes_per_buffer": 1048576,
                "max_total_aux_bytes": 134217728,
                "max_capture_ms": 30000
            },
            "effective_event": "intel_pt/u",
            "cpu_vendor": "test",
            "cpu_model": "test",
            "kernel": "test",
            "perf_version": "test",
            "perf_argv": [],
            "raw_bytes": "0",
            "target": { "kind": "launch", "argv": ["/bin/true"] },
            "observed_threads": [],
            "images": [],
            "missing_images": [],
            "redecode_ready": false,
            "diagnostics": []
        }))
        .unwrap(),
    )
    .unwrap();
    let (app, _h) = App::start(store);
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let cmp = app
        .compare(trace_mcp::model::CompareRequest {
            baseline: trace_mcp::model::CompareSide {
                snapshot_id: snap.clone(),
                analysis_id: None,
                selection: None,
                workload: None,
            },
            candidate: trace_mcp::model::CompareSide {
                snapshot_id: snap.clone(),
                analysis_id: None,
                selection: None,
                workload: None,
            },
            mode: trace_mcp::model::CompareMode::Exploratory,
            function_pairs: Vec::new(),
            group: Default::default(),
            function_contains: None,
        })
        .await
        .unwrap_err();
    assert_eq!(cmp.code, trace_mcp::ErrorCode::Busy);

    let dec = app
        .decode(trace_mcp::service::DecodeRequest {
            snapshot_id: snap,
            detail: trace_mcp::service::DetailSel::Calls { fast: false },
        })
        .await
        .unwrap_err();
    assert_eq!(dec.code, trace_mcp::ErrorCode::Busy);
    app.shutdown().await;
}

#[tokio::test]
async fn query_hotpaths_paginate() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().to_path_buf(), Limits::default()).unwrap();
    let snap = SnapshotId::from_raw("s_page").unwrap();
    let aid = trace_mcp::model::AnalysisId::from_raw("a_page").unwrap();
    let snap_dir = store.snapshot_dir(&snap);
    let derived = store.analysis_dir(&snap, &aid);
    std::fs::create_dir_all(&derived).unwrap();
    std::fs::write(
        snap_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "snapshot_id": snap,
            "session_id": "sess_p",
            "capture_reason": "stop",
            "lifecycle": "captured",
            "requested_config": {
                "timing": "balanced",
                "aux_bytes_per_buffer": 1048576,
                "max_total_aux_bytes": 134217728,
                "max_capture_ms": 30000
            },
            "effective_event": "intel_pt/u",
            "cpu_vendor": "test",
            "cpu_model": "test",
            "kernel": "test",
            "perf_version": "test",
            "perf_argv": [],
            "raw_bytes": "0",
            "target": { "kind": "launch", "argv": ["/bin/true"] },
            "observed_threads": [],
            "images": [],
            "missing_images": [],
            "redecode_ready": false,
            "diagnostics": []
        }))
        .unwrap(),
    )
    .unwrap();
    let mut spans = String::new();
    for i in 0..5u32 {
        spans.push_str(&format!(
            "{{\"id\":{i},\"thread\":\"t_0\",\"function\":{i},\"parent\":null,\"start\":{{\"relative_ns\":{},\"quality\":\"decoder_estimate\"}},\"end\":{{\"relative_ns\":{},\"quality\":\"decoder_estimate\"}},\"completeness\":\"complete\",\"evidence\":{{\"start_id\":0,\"end_id\":0}}}}\n",
            i * 10,
            i * 10 + 5
        ));
    }
    std::fs::write(derived.join("spans.jsonl"), spans).unwrap();
    let mut fns = String::new();
    for i in 0..5u32 {
        fns.push_str(&format!(
            "{{\"id\":{i},\"name\":\"f{i}\",\"demangled\":\"f{i}\",\"image_id\":\"img\",\"start\":\"0x{i}\",\"end\":\"0x{}\"}}\n",
            i + 1
        ));
    }
    std::fs::write(derived.join("functions.json"), fns).unwrap();
    std::fs::write(
        derived.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "ir_version": 1,
            "analysis_id": aid,
            "snapshot_id": snap,
            "detail": "calls",
            "decoder_version": "test",
            "decoder_argv": [],
            "dialect": "test",
            "cache_key": "k",
            "origin": { "abs_perf_time": "0", "relative_zero_ns": 0 },
            "quality": {
                "timing": "decoder_estimate",
                "gap_count": "0",
                "incomplete_span_count": "0",
                "missing_image_count": "0",
                "decoder_error_count": "0",
                "ring_truncation": false,
                "undecodable_prefix": false,
                "notes": []
            },
            "function_count": "5",
            "span_count": "5",
            "event_count": "5",
            "covered_start_ns": 0,
            "covered_end_ns": 100
        }))
        .unwrap(),
    )
    .unwrap();

    let (app, _h) = App::start(store);
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let page1 = app
        .query(QueryRequest {
            target: QueryTarget::Snapshot {
                snapshot_id: snap.clone(),
                analysis_id: Some(aid.clone()),
            },
            query: QueryKind::Hotpaths {
                function_contains: None,
                group: Default::default(),
                sort: Default::default(),
                max_depth: None,
            },
            selection: None,
            cursor: None,
            limit: Some(2),
        })
        .await
        .unwrap();
    assert_eq!(page1["next_cursor"], "2");
    assert_eq!(page1["data"].as_array().unwrap().len(), 2);
    let page2 = app
        .query(QueryRequest {
            target: QueryTarget::Snapshot {
                snapshot_id: snap,
                analysis_id: Some(aid),
            },
            query: QueryKind::Hotpaths {
                function_contains: None,
                group: Default::default(),
                sort: Default::default(),
                max_depth: None,
            },
            selection: None,
            cursor: Some("2".into()),
            limit: Some(2),
        })
        .await
        .unwrap();
    assert_eq!(page2["next_cursor"], "4");
    assert_eq!(page2["data"].as_array().unwrap().len(), 2);
    app.shutdown().await;
}

#[tokio::test]
async fn comparison_report_paginates() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().to_path_buf(), Limits::default()).unwrap();
    let rid = trace_mcp::model::ReportId::from_raw("r_page").unwrap();
    let dest = store.report_dir(&rid);
    std::fs::create_dir_all(&dest).unwrap();
    let mut rows = String::new();
    for i in 0..5 {
        rows.push_str(&format!(
            "{{\"path\":\"p{i}\",\"baseline\":null,\"candidate\":null,\"unit\":\"ns_decoder_estimate\",\"normalization\":\"raw_selected_region\",\"match_kind\":\"unmatched\",\"baseline_evidence\":[],\"candidate_evidence\":[]}}\n"
        ));
    }
    std::fs::write(dest.join("rows.jsonl"), rows).unwrap();
    std::fs::write(
        dest.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "checks": [],
            "comparable": true,
            "mode": "exploratory",
            "warnings": [],
            "baseline_analysis_id": "a_b",
            "candidate_analysis_id": "a_c"
        }))
        .unwrap(),
    )
    .unwrap();
    let (app, _h) = App::start(store);
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let page1 = app
        .query(QueryRequest {
            target: QueryTarget::Report {
                report_id: rid.clone(),
            },
            query: QueryKind::Comparison,
            selection: None,
            cursor: None,
            limit: Some(2),
        })
        .await
        .unwrap();
    assert_eq!(page1["next_cursor"], "2");
    assert_eq!(page1["data"].as_array().unwrap().len(), 2);
    let page2 = app
        .query(QueryRequest {
            target: QueryTarget::Report { report_id: rid },
            query: QueryKind::Comparison,
            selection: None,
            cursor: Some("2".into()),
            limit: Some(2),
        })
        .await
        .unwrap();
    assert_eq!(page2["next_cursor"], "4");
    let page3 = app
        .query(QueryRequest {
            target: QueryTarget::Report {
                report_id: trace_mcp::model::ReportId::from_raw("r_page").unwrap(),
            },
            query: QueryKind::Comparison,
            selection: None,
            cursor: Some("4".into()),
            limit: Some(2),
        })
        .await
        .unwrap();
    assert!(page3["next_cursor"].is_null());
    assert_eq!(page3["data"].as_array().unwrap().len(), 1);
    app.shutdown().await;
}
