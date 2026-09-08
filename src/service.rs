use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::analysis::compare::{compare_hotpaths, cpu_pt_compat, decoder_compat};
use crate::analysis::hotpaths::{
    HotpathOptions, HotpathRow, child_index, hotpaths_with, inline_rows,
};
use crate::analysis::page::{fit_json, paginate, parse_offset_cursor};
use crate::analysis::source::{SourceInfo, dwarf_frames, resolve_source};
use crate::analysis::timeline::{TimelineOptions, timeline_rows_with};
use crate::capture::doctor::{DoctorReport, run_doctor};
use crate::capture::perf::{
    PerfControl, PerfRecordSpec, insn_script_args, metadata_script_args, page_size,
    read_start_identity, resolve_launch_exe, validate_ready_topology,
};
use crate::decode::images::{
    archive_bytes, archive_image, build_buildid_cache, hash_file, read_own_vdso,
    reject_if_not_elf64,
};
use crate::decode::instructions::{InsnReconstructor, aggregate_branches};
use crate::decode::perf_script::{RawRecord, StreamStats, parse_reader, stream_records};
use crate::decode::reconstruct::Reconstructor;
use crate::error::{Error, ErrorCode, Result};
use crate::model::{
    AnalysisId, AnalysisManifest, CaptureReason, CompareRequest, Count, DEFAULT_AUX_BYTES,
    DetailLevel, EffectivePtTerms, IR_VERSION, IntelPtConfig, JobId, JobKind, JobPhase, JobRecord,
    Limits, QueryKind, QueryRequest, QueryTarget, RequestId, SCHEMA_VERSION, Selection, SessionId,
    SessionPhase, SnapshotId, SnapshotManifest, Target, WorkloadMeta,
};
use crate::store::{Store, cache_key, write_jsonl};

const CMD_CAP: usize = 64;

#[derive(Clone, Copy)]
enum StopRequest {
    Finish(CaptureReason),
    Abort,
}

#[derive(Clone)]
pub struct App {
    tx: mpsc::Sender<Op>,
}

enum Op {
    Doctor {
        probe: bool,
        reply: oneshot::Sender<Result<DoctorReport>>,
    },
    Start {
        req: StartRequest,
        reply: oneshot::Sender<Result<StartResponse>>,
    },
    Status {
        sel: StatusSelect,
        reply: oneshot::Sender<Result<serde_json::Value>>,
    },
    Snapshot {
        session: SessionId,
        reason: CaptureReason,
        reply: oneshot::Sender<Result<SnapshotResponse>>,
    },
    Cancel {
        target: CancelTarget,
        reply: oneshot::Sender<Result<serde_json::Value>>,
    },
    Prune {
        req: PruneRequest,
        reply: oneshot::Sender<Result<serde_json::Value>>,
    },
    Decode {
        req: DecodeRequest,
        reply: oneshot::Sender<Result<DecodeResponse>>,
    },
    Query {
        req: QueryRequest,
        reply: oneshot::Sender<Result<serde_json::Value>>,
    },
    Compare {
        req: CompareRequest,
        reply: oneshot::Sender<Result<JobId>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
    Internal(InternalEvt),
}

enum InternalEvt {
    Armed(SessionId),
    Failed {
        session: SessionId,
        error: String,
    },
    Published {
        session: SessionId,
        snapshot: SnapshotId,
    },
    JobFinished {
        rec: JobRecord,
        decode_slot: bool,
        expensive_slot: bool,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    pub request_id: RequestId,
    pub target: Target,
    #[serde(default)]
    pub config: IntelPtConfig,
    #[serde(default)]
    pub after_ms: Option<u64>,
    #[serde(default)]
    pub workload: Option<WorkloadMeta>,
    /// Snapshot on a symbol hit or on a FIFO write from the workload.
    #[serde(default)]
    pub trigger: Option<crate::model::Trigger>,
    /// After the trigger fires, keep recording this long so the ring holds
    /// the trigger's aftermath as well as its history. Bounded by
    /// `max_capture_ms`; a long tail can overwrite the trigger moment.
    #[serde(default)]
    pub tail_ms: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StartResponse {
    pub session_id: SessionId,
    pub state: SessionPhase,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StatusSelect {
    Session {
        id: SessionId,
    },
    Job {
        id: JobId,
    },
    Snapshot {
        id: SnapshotId,
    },
    Sessions {
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default)]
        limit: Option<u32>,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotResponse {
    pub snapshot_id: SnapshotId,
    pub job_id: JobId,
    pub state: SessionPhase,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CancelTarget {
    Session { id: SessionId },
    Job { id: JobId },
}

/// Delete snapshots from the store. `snapshot_ids` are removed if no job is
/// still queued or running on them; `list_only` reports sizes and deletes
/// nothing.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PruneRequest {
    #[serde(default)]
    pub snapshot_ids: Vec<SnapshotId>,
    #[serde(default)]
    pub list_only: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecodeRequest {
    pub snapshot_id: SnapshotId,
    pub detail: DetailSel,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DetailSel {
    /// `fast` synthesizes calls/returns only (much quicker on large
    /// captures; tail calls and PLT stubs unobserved).
    Calls {
        #[serde(default)]
        fast: bool,
    },
    Instructions {
        selection: Selection,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DecodeResponse {
    pub analysis_id: AnalysisId,
    pub job_id: Option<JobId>,
    pub cached: bool,
}

struct Session {
    id: SessionId,
    request_id: RequestId,
    request_hash: String,
    target: Target,
    config: IntelPtConfig,
    after_ms: Option<u64>,
    workload: Option<WorkloadMeta>,
    phase: SessionPhase,
    snapshot_id: Option<SnapshotId>,
    decode_job: Option<JobId>,
    stop: Option<watch::Sender<Option<StopRequest>>>,
    armed_at: Option<Instant>,
    /// Counted in `active_captures` until released exactly once.
    slot_held: bool,
}

struct Coord {
    store: Store,
    limits: Limits,
    sessions: HashMap<SessionId, Session>,
    by_request: HashMap<RequestId, SessionId>,
    jobs: HashMap<JobId, JobRecord>,
    cache_jobs: HashMap<String, JobId>,
    active_captures: u32,
    running_decode: u32,
    pending_expensive: u32,
    reserved_decode: u32,
}

impl App {
    pub fn start(store: Store) -> (Self, JoinHandle<()>) {
        let limits = store.limits.clone();
        let (tx, rx) = mpsc::channel(CMD_CAP);
        let internal_tx = tx.clone();
        let handle = tokio::spawn(async move {
            run_coord(internal_tx, rx, store, limits).await;
        });
        (Self { tx }, handle)
    }

    async fn send<T>(&self, mk: impl FnOnce(oneshot::Sender<Result<T>>) -> Op) -> Result<T> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .try_send(mk(reply))
            .map_err(|_| Error::busy("coordinator is busy"))?;
        rx.await
            .map_err(|_| Error::cancelled("coordinator shut down"))?
    }

    pub async fn doctor(&self, probe: bool) -> Result<DoctorReport> {
        self.send(|reply| Op::Doctor { probe, reply }).await
    }

    pub async fn start_session(&self, req: StartRequest) -> Result<StartResponse> {
        self.send(|reply| Op::Start { req, reply }).await
    }

    pub async fn status(&self, sel: StatusSelect) -> Result<serde_json::Value> {
        self.send(|reply| Op::Status { sel, reply }).await
    }

    pub async fn snapshot(
        &self,
        session: SessionId,
        reason: CaptureReason,
    ) -> Result<SnapshotResponse> {
        self.send(|reply| Op::Snapshot {
            session,
            reason,
            reply,
        })
        .await
    }

    pub async fn cancel(&self, target: CancelTarget) -> Result<serde_json::Value> {
        self.send(|reply| Op::Cancel { target, reply }).await
    }

    pub async fn prune(&self, req: PruneRequest) -> Result<serde_json::Value> {
        self.send(|reply| Op::Prune { req, reply }).await
    }

    pub async fn decode(&self, req: DecodeRequest) -> Result<DecodeResponse> {
        self.send(|reply| Op::Decode { req, reply }).await
    }

    pub async fn query(&self, req: QueryRequest) -> Result<serde_json::Value> {
        self.send(|reply| Op::Query { req, reply }).await
    }

    pub async fn compare(&self, req: CompareRequest) -> Result<JobId> {
        self.send(|reply| Op::Compare { req, reply }).await
    }

    pub async fn shutdown(&self) {
        let (reply, rx) = oneshot::channel();
        let _ = self.tx.send(Op::Shutdown { reply }).await;
        let _ = rx.await;
    }
}

async fn run_coord(tx: mpsc::Sender<Op>, mut rx: mpsc::Receiver<Op>, store: Store, limits: Limits) {
    let mut c = Coord {
        store,
        limits,
        sessions: HashMap::new(),
        by_request: HashMap::new(),
        jobs: HashMap::new(),
        cache_jobs: HashMap::new(),
        active_captures: 0,
        running_decode: 0,
        pending_expensive: 0,
        reserved_decode: 0,
    };
    load_persisted(&mut c);
    while let Some(op) = rx.recv().await {
        match op {
            Op::Shutdown { reply } => {
                for s in c.sessions.values() {
                    if let Some(st) = &s.stop {
                        let _ = st.send(None);
                    }
                }
                let _ = reply.send(());
                break;
            }
            Op::Doctor { probe, reply } => {
                let store = c.store.root.clone();
                tokio::task::spawn_blocking(move || {
                    let r = run_doctor(probe, Some(&store));
                    let _ = reply.send(r);
                });
            }
            Op::Start { req, reply } => {
                let _ = reply.send(handle_start(&mut c, req, tx.clone()).await);
            }
            Op::Status { sel, reply } => {
                let _ = reply.send(handle_status(&c, sel));
            }
            Op::Snapshot {
                session,
                reason,
                reply,
            } => {
                let _ = reply.send(handle_snapshot(&mut c, session, reason));
            }
            Op::Cancel { target, reply } => {
                let _ = reply.send(handle_cancel(&mut c, target));
            }
            Op::Prune { req, reply } => {
                let _ = reply.send(handle_prune(&mut c, req));
            }
            Op::Decode { req, reply } => {
                let _ = reply.send(handle_decode(&mut c, req, tx.clone()).await);
            }
            Op::Query { req, reply } => {
                let store = c.store.root.clone();
                let budget = c.limits.mcp_result_budget;
                tokio::task::spawn_blocking(move || {
                    let _ = reply.send(handle_query_disk(&store, req, budget));
                });
            }
            Op::Compare { req, reply } => {
                let _ = reply.send(handle_compare(&mut c, req, tx.clone()).await);
            }
            Op::Internal(evt) => handle_internal(&mut c, evt, tx.clone()),
        }
    }
}

async fn handle_start(
    c: &mut Coord,
    mut req: StartRequest,
    tx: mpsc::Sender<Op>,
) -> Result<StartResponse> {
    req.target.validate()?;
    req.config.validate(page_size())?;
    if let Some(ms) = req.after_ms
        && (ms == 0 || ms > req.config.max_capture_ms)
    {
        return Err(Error::invalid_argument(
            "after_ms must satisfy 0 < after_ms <= max_capture_ms",
        ));
    }
    if let Some(t) = req.tail_ms
        && t > req.config.max_capture_ms
    {
        return Err(Error::invalid_argument("tail_ms must be <= max_capture_ms"));
    }
    if matches!(req.trigger, Some(crate::model::Trigger::Symbol { .. }))
        && !req.target.owns_workload()
    {
        return Err(Error::invalid_argument(
            "symbol triggers require a launch target",
        ));
    }
    if matches!(req.trigger, Some(crate::model::Trigger::Fifo)) && !req.target.owns_workload() {
        return Err(Error::invalid_argument(
            "fifo triggers require a launch target: only a launched workload inherits $TRACE_MCP_TRIGGER",
        )
        .with_next("Use after_ms or trace_snapshot for an attached process"));
    }
    if let Some(crate::model::Trigger::Symbol { symbol, hits }) = &req.trigger {
        if symbol.trim().is_empty() {
            return Err(Error::invalid_argument("trigger symbol must not be empty"));
        }
        if *hits == 0 {
            return Err(Error::invalid_argument("trigger hits must be >= 1"));
        }
    }
    let hash = start_request_hash(&req);
    if let Some(existing) = c.by_request.get(&req.request_id) {
        let s = c.sessions.get(existing).unwrap();
        if !s.request_hash.is_empty() && s.request_hash != hash {
            return Err(Error::invalid_argument(
                "request_id reused with a different body",
            ));
        }
        return Ok(StartResponse {
            session_id: s.id.clone(),
            state: s.phase,
        });
    }
    if c.active_captures >= c.limits.max_active_captures {
        return Err(
            Error::new(ErrorCode::SessionBusy, "an active capture already exists")
                .with_next("Wait for it to finish or cancel it"),
        );
    }
    c.store.ensure_budget(c.limits.raw_disk_budget)?;
    if c.reserved_decode + c.pending_expensive >= c.limits.max_pending_expensive {
        return Err(Error::busy("expensive job queue is full"));
    }
    validate_ready_topology(&mut req.config, c.limits.direct_recorder)?;

    if let Target::Launch { argv, cwd, .. } = &req.target {
        let exe = resolve_launch_exe(argv, cwd.as_deref().map(Path::new))?;
        let bytes = std::fs::read(&exe)?;
        reject_if_not_elf64(&bytes, &exe)?;
    }
    if let Target::Attach { pid } = &req.target {
        let _id = read_start_identity(*pid)?;
        let exe = format!("/proc/{pid}/exe");
        if let Ok(p) = std::fs::read_link(&exe)
            && let Ok(bytes) = std::fs::read(&p)
        {
            reject_if_not_elf64(&bytes, &p)?;
        }
    }

    let id = SessionId::generate();
    let snap = SnapshotId::generate();
    let (stop_tx, stop_rx) = watch::channel(None);
    let session = Session {
        id: id.clone(),
        request_id: req.request_id.clone(),
        request_hash: hash,
        target: req.target.clone(),
        config: req.config.clone(),
        after_ms: req.after_ms,
        workload: req.workload.clone(),
        phase: SessionPhase::Starting,
        snapshot_id: Some(snap.clone()),
        decode_job: None,
        stop: Some(stop_tx.clone()),
        armed_at: None,
        slot_held: true,
    };
    persist_session(c, &session)?;
    c.by_request.insert(req.request_id.clone(), id.clone());
    c.sessions.insert(id.clone(), session);
    c.active_captures += 1;
    c.reserved_decode += 1;

    let store_root = c.store.root.clone();
    let limits = c.limits.clone();
    let sid = id.clone();
    let app_tx_note = sid.clone();
    let tx_task = tx.clone();
    tokio::spawn(async move {
        let outcome = capture_task(
            store_root,
            limits,
            sid.clone(),
            snap.clone(),
            req,
            stop_rx,
            tx_task.clone(),
        )
        .await;
        match outcome {
            Ok(out) => {
                let _ = tx_task
                    .send(Op::Internal(InternalEvt::Published {
                        session: sid,
                        snapshot: out.snapshot,
                    }))
                    .await;
            }
            Err(e) => {
                tracing::warn!(session = %app_tx_note, error = %e, "capture task failed");
                let _ = tx_task
                    .send(Op::Internal(InternalEvt::Failed {
                        session: sid,
                        error: e.to_string(),
                    }))
                    .await;
            }
        }
    });

    Ok(StartResponse {
        session_id: id,
        state: SessionPhase::Starting,
    })
}

fn handle_internal(c: &mut Coord, evt: InternalEvt, tx: mpsc::Sender<Op>) {
    match evt {
        InternalEvt::Armed(id) => {
            if let Some(s) = c.sessions.get_mut(&id)
                && s.phase == SessionPhase::Starting
            {
                s.phase = SessionPhase::Armed;
                s.armed_at = Some(Instant::now());
            }
            if let Some(s) = c.sessions.get(&id) {
                let _ = persist_session(c, s);
            }
        }
        InternalEvt::Failed { session, error } => {
            if let Some(s) = c.sessions.get_mut(&session)
                && s.phase != SessionPhase::Cancelled
            {
                s.phase = SessionPhase::Failed;
            }
            cancel_queued_session_job(c, &session);
            if let Some(s) = c.sessions.get(&session) {
                let _ = persist_session(c, s);
            }
            release_capture_slot(c, &session);
            c.reserved_decode = c.reserved_decode.saturating_sub(1);
            tracing::warn!(%session, error, "capture failed");
        }
        InternalEvt::Published { session, snapshot } => {
            let blocked = c
                .sessions
                .get(&session)
                .is_some_and(|s| matches!(s.phase, SessionPhase::Cancelled | SessionPhase::Failed));
            if blocked {
                if let Some(s) = c.sessions.get_mut(&session)
                    && s.snapshot_id.is_none()
                {
                    s.snapshot_id = Some(snapshot);
                }
                cancel_queued_session_job(c, &session);
                if let Some(s) = c.sessions.get(&session) {
                    let _ = persist_session(c, s);
                }
                release_capture_slot(c, &session);
                c.reserved_decode = c.reserved_decode.saturating_sub(1);
                return;
            }
            let mut start_decode = None;
            if let Some(s) = c.sessions.get_mut(&session) {
                s.phase = SessionPhase::Captured;
                s.snapshot_id = Some(snapshot.clone());
                if s.decode_job.is_none() {
                    let job = JobId::generate();
                    s.decode_job = Some(job.clone());
                    start_decode = Some((job, s.snapshot_id.clone().unwrap_or(snapshot.clone())));
                } else {
                    start_decode = s.decode_job.clone().zip(s.snapshot_id.clone());
                }
            }
            if let Some(s) = c.sessions.get(&session) {
                let _ = persist_session(c, s);
            }
            release_capture_slot(c, &session);
            if let Some((job, snap)) = start_decode {
                let rec = JobRecord {
                    job_id: job.clone(),
                    kind: JobKind::InitialDecode,
                    phase: JobPhase::Queued,
                    snapshot_id: Some(snap.clone()),
                    analysis_id: None,
                    report_id: None,
                    error: None,
                };
                c.jobs.insert(job.clone(), rec.clone());
                let _ = c.store.write_json(&c.store.job_path(&job), &rec);
                let root = c.store.root.clone();
                let limits = c.limits.clone();
                let jid = job.clone();
                let aid = AnalysisId::generate();
                if let Some(j) = c.jobs.get_mut(&job) {
                    j.analysis_id = Some(aid.clone());
                    j.phase = JobPhase::Running;
                }
                c.running_decode = c.running_decode.saturating_add(1);
                c.reserved_decode = c.reserved_decode.saturating_sub(1);
                let notify = tx.clone();
                tokio::task::spawn_blocking(move || {
                    let r =
                        decode_job(&root, &limits, &snap, &aid, DetailLevel::Calls, None, false);
                    let mut rec = rec;
                    rec.analysis_id = Some(aid);
                    match r {
                        Ok(()) => rec.phase = JobPhase::Succeeded,
                        Err(e) => {
                            rec.phase = JobPhase::Failed;
                            rec.error = Some(e.to_string());
                        }
                    }
                    let _ = std::fs::write(
                        root.join("jobs").join(format!("{jid}.json")),
                        serde_json::to_vec_pretty(&rec).unwrap_or_default(),
                    );
                    let _ = notify.blocking_send(Op::Internal(InternalEvt::JobFinished {
                        rec,
                        decode_slot: true,
                        expensive_slot: false,
                    }));
                });
            }
        }
        InternalEvt::JobFinished {
            rec,
            decode_slot,
            expensive_slot,
        } => {
            if decode_slot {
                c.running_decode = c.running_decode.saturating_sub(1);
            }
            if expensive_slot {
                c.pending_expensive = c.pending_expensive.saturating_sub(1);
            }
            c.jobs.insert(rec.job_id.clone(), rec);
        }
    }
}

pub fn start_request_hash(req: &StartRequest) -> String {
    cache_key(&[
        req.request_id.as_str(),
        &serde_json::to_string(&req.target).unwrap_or_default(),
        &serde_json::to_string(&req.config).unwrap_or_default(),
        &req.after_ms.unwrap_or(0).to_string(),
        &serde_json::to_string(&req.trigger).unwrap_or_default(),
        &req.tail_ms.unwrap_or(0).to_string(),
    ])
}

fn persist_session(c: &Coord, s: &Session) -> Result<()> {
    let v = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": s.id,
        "request_id": s.request_id,
        "request_hash": s.request_hash,
        "state": s.phase,
        "snapshot_id": s.snapshot_id,
        "job_id": s.decode_job,
        "target": s.target,
        "config": s.config,
        "after_ms": s.after_ms,
        "workload": s.workload,
    });
    c.store.write_json(&c.store.session_path(&s.id), &v)
}

fn cancel_queued_session_job(c: &mut Coord, session: &SessionId) {
    let Some(job) = c.sessions.get(session).and_then(|s| s.decode_job.clone()) else {
        return;
    };
    if let Some(j) = c.jobs.get_mut(&job)
        && j.phase == JobPhase::Queued
    {
        j.phase = JobPhase::Cancelled;
        let _ = c.store.write_json(&c.store.job_path(&job), j);
    }
}

fn load_persisted(c: &mut Coord) {
    let Ok(list) = c.store.list_sessions() else {
        return;
    };
    for (id, v) in list {
        let Some(request_id) = v
            .get("request_id")
            .and_then(|s| s.as_str())
            .and_then(|s| RequestId::from_raw(s).ok())
        else {
            continue;
        };
        let request_hash = v
            .get("request_hash")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let mut phase: SessionPhase = v
            .get("state")
            .cloned()
            .and_then(|s| serde_json::from_value(s).ok())
            .unwrap_or(SessionPhase::Failed);
        if matches!(
            phase,
            SessionPhase::Starting | SessionPhase::Armed | SessionPhase::Finalizing
        ) {
            phase = SessionPhase::Failed;
        }
        let snapshot_id = v
            .get("snapshot_id")
            .and_then(|s| s.as_str())
            .and_then(|s| SnapshotId::from_raw(s).ok());
        let decode_job = v
            .get("job_id")
            .and_then(|s| s.as_str())
            .and_then(|s| JobId::from_raw(s).ok());
        let target = v
            .get("target")
            .cloned()
            .and_then(|t| serde_json::from_value(t).ok())
            .unwrap_or(Target::Launch {
                argv: vec!["unknown".into()],
                cwd: None,
                env: Default::default(),
            });
        let config = v
            .get("config")
            .cloned()
            .and_then(|t| serde_json::from_value(t).ok())
            .unwrap_or_default();
        let after_ms = v.get("after_ms").and_then(|x| x.as_u64());
        let workload = v
            .get("workload")
            .cloned()
            .and_then(|w| serde_json::from_value(w).ok());
        let session = Session {
            id: id.clone(),
            request_id: request_id.clone(),
            request_hash,
            slot_held: false,
            target,
            config,
            after_ms,
            workload,
            phase,
            snapshot_id,
            decode_job,
            stop: None,
            armed_at: None,
        };
        let _ = persist_session(c, &session);
        c.by_request.insert(request_id, id.clone());
        c.sessions.insert(id, session);
    }
    if let Ok(rd) = std::fs::read_dir(c.store.root.join("jobs")) {
        for e in rd.flatten() {
            if let Ok(j) = crate::store::read_json::<JobRecord>(&e.path()) {
                c.jobs.insert(j.job_id.clone(), j);
            }
        }
    }
    let snaps = c.store.root.join("snapshots");
    if let Ok(rd) = std::fs::read_dir(snaps) {
        for e in rd.flatten() {
            let derived = e.path().join("derived");
            let Ok(dd) = std::fs::read_dir(derived) else {
                continue;
            };
            for d in dd.flatten() {
                let Ok(am) =
                    crate::store::read_json::<AnalysisManifest>(&d.path().join("manifest.json"))
                else {
                    continue;
                };
                if let Some(jid) = c
                    .jobs
                    .values()
                    .find(|j| j.analysis_id.as_ref() == Some(&am.analysis_id))
                    .map(|j| j.job_id.clone())
                {
                    c.cache_jobs.insert(am.cache_key, jid);
                }
            }
        }
    }
    let reports = c.store.root.join("reports");
    if let Ok(rd) = std::fs::read_dir(reports) {
        for e in rd.flatten() {
            let Ok(v) =
                crate::store::read_json::<serde_json::Value>(&e.path().join("manifest.json"))
            else {
                continue;
            };
            if let (Some(key), Some(jid)) = (
                v.get("cache_key").and_then(|s| s.as_str()),
                v.get("job_id")
                    .and_then(|s| s.as_str())
                    .and_then(|s| JobId::from_raw(s).ok()),
            ) {
                c.cache_jobs.insert(key.to_string(), jid);
            }
        }
    }
}

fn handle_snapshot(
    c: &mut Coord,
    session: SessionId,
    reason: CaptureReason,
) -> Result<SnapshotResponse> {
    let phase = c
        .sessions
        .get(&session)
        .ok_or_else(|| Error::not_found(session.to_string()))?
        .phase;
    match phase {
        SessionPhase::Starting => Err(Error::new(ErrorCode::NotReady, "session is still starting")),
        SessionPhase::Failed => Err(Error::new(ErrorCode::Cancelled, "session failed")),
        SessionPhase::Cancelled => Err(Error::cancelled("session cancelled")),
        SessionPhase::Finalizing | SessionPhase::Captured => {
            let s = c.sessions.get(&session).unwrap();
            let snap = s
                .snapshot_id
                .clone()
                .ok_or_else(|| Error::not_found("snapshot"))?;
            let job = s
                .decode_job
                .clone()
                .ok_or_else(|| Error::not_found("job"))?;
            Ok(SnapshotResponse {
                snapshot_id: snap,
                job_id: job,
                state: s.phase,
            })
        }
        SessionPhase::Armed => {
            let (snap, job) = {
                let s = c.sessions.get_mut(&session).unwrap();
                let snap = s.snapshot_id.clone().unwrap_or_else(SnapshotId::generate);
                s.snapshot_id = Some(snap.clone());
                let job = s.decode_job.clone().unwrap_or_else(JobId::generate);
                s.decode_job = Some(job.clone());
                s.phase = SessionPhase::Finalizing;
                (snap, job)
            };
            persist_session(c, c.sessions.get(&session).unwrap())?;
            if let Some(tx) = c.sessions.get(&session).and_then(|s| s.stop.as_ref()) {
                let _ = tx.send(Some(StopRequest::Finish(reason)));
            }
            let rec = JobRecord {
                job_id: job.clone(),
                kind: JobKind::InitialDecode,
                phase: JobPhase::Queued,
                snapshot_id: Some(snap.clone()),
                analysis_id: None,
                report_id: None,
                error: None,
            };
            c.jobs.insert(job.clone(), rec.clone());
            let _ = c.store.write_json(&c.store.job_path(&job), &rec);
            Ok(SnapshotResponse {
                snapshot_id: snap,
                job_id: job,
                state: SessionPhase::Finalizing,
            })
        }
    }
}

/// Report snapshot sizes and delete the requested ones. A snapshot with a
/// queued or running job, or whose session is still capturing, is skipped
/// with a reason rather than failing the whole call.
fn handle_prune(c: &mut Coord, req: PruneRequest) -> Result<serde_json::Value> {
    let mut sizes = c.store.snapshot_sizes()?;
    sizes.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
    let mut removed = Vec::new();
    let mut skipped = Vec::new();
    if !req.list_only {
        for id in &req.snapshot_ids {
            let busy_job = c.jobs.values().any(|j| {
                j.snapshot_id.as_ref() == Some(id)
                    && matches!(j.phase, JobPhase::Queued | JobPhase::Running)
            });
            let capturing = c.sessions.values().any(|s| {
                s.snapshot_id.as_ref() == Some(id)
                    && matches!(
                        s.phase,
                        SessionPhase::Starting | SessionPhase::Armed | SessionPhase::Finalizing
                    )
            });
            if busy_job || capturing {
                skipped.push(serde_json::json!({
                    "snapshot_id": id,
                    "reason": if busy_job { "a job is queued or running on it" } else { "its capture has not finished" },
                }));
                continue;
            }
            match c.store.remove_snapshot(id) {
                Ok(bytes) => {
                    // Cached analysis jobs point at directories that are gone.
                    c.cache_jobs.retain(|_, job| {
                        c.jobs.get(job).and_then(|j| j.snapshot_id.as_ref()) != Some(id)
                    });
                    removed.push(serde_json::json!({"snapshot_id": id, "bytes": bytes}));
                }
                Err(e) => skipped.push(serde_json::json!({"snapshot_id": id, "reason": e.reason})),
            }
        }
    }
    let used = c.store.used_bytes()?;
    Ok(serde_json::json!({
        "snapshots": sizes.iter().map(|(id, b)| serde_json::json!({"snapshot_id": id, "bytes": b})).collect::<Vec<_>>(),
        "removed": removed,
        "skipped": skipped,
        "used_bytes": used,
        "budget_bytes": c.limits.store_budget,
    }))
}

fn handle_cancel(c: &mut Coord, target: CancelTarget) -> Result<serde_json::Value> {
    match target {
        CancelTarget::Session { id } => {
            let Some(s) = c.sessions.get_mut(&id) else {
                return Err(Error::not_found(id.to_string()));
            };
            match s.phase {
                SessionPhase::Captured => {
                    return Ok(serde_json::json!({"state": s.phase, "session_id": id}));
                }
                SessionPhase::Cancelled | SessionPhase::Failed => {
                    return Ok(serde_json::json!({"state": s.phase, "session_id": id}));
                }
                SessionPhase::Starting | SessionPhase::Armed | SessionPhase::Finalizing => {
                    s.phase = SessionPhase::Cancelled;
                    if let Some(tx) = &s.stop {
                        let _ = tx.send(Some(StopRequest::Abort));
                    }
                }
            }
            // The slot is free now, not when the recorder's startup or
            // finalization eventually returns.
            release_capture_slot(c, &id);
            if let Some(s) = c.sessions.get(&id) {
                let _ = persist_session(c, s);
            }
            Ok(serde_json::json!({"state": "cancelled", "session_id": id}))
        }
        CancelTarget::Job { id } => {
            if let Some(j) = c.jobs.get_mut(&id) {
                if j.phase == JobPhase::Succeeded {
                    return Ok(serde_json::to_value(j).unwrap_or_default());
                }
                j.phase = JobPhase::Cancelled;
                let _ = c.store.write_json(&c.store.job_path(&id), j);
            }
            Ok(serde_json::json!({"state": "cancelled", "job_id": id}))
        }
    }
}

fn handle_status(c: &Coord, sel: StatusSelect) -> Result<serde_json::Value> {
    match sel {
        StatusSelect::Session { id } => {
            if let Some(s) = c.sessions.get(&id) {
                serde_json::to_value(serde_json::json!({
                    "session_id": s.id,
                    "request_id": s.request_id,
                    "state": s.phase,
                    "snapshot_id": s.snapshot_id,
                    "job_id": s.decode_job,
                }))
                .map_err(|e| Error::decode_failed(e.to_string()))
            } else if let Ok(v) =
                crate::store::read_json::<serde_json::Value>(&c.store.session_path(&id))
            {
                Ok(v)
            } else {
                Err(Error::not_found(id.to_string()))
            }
        }
        StatusSelect::Job { id } => {
            if let Ok(j) = c.store.load_job(&id) {
                serde_json::to_value(j).map_err(|e| Error::decode_failed(e.to_string()))
            } else {
                let j = c
                    .jobs
                    .get(&id)
                    .ok_or_else(|| Error::not_found(id.to_string()))?;
                serde_json::to_value(j).map_err(|e| Error::decode_failed(e.to_string()))
            }
        }
        StatusSelect::Snapshot { id } => {
            let m = c.store.load_snapshot_manifest(&id)?;
            let mut v = serde_json::to_value(m).map_err(|e| Error::decode_failed(e.to_string()))?;
            // Keep the status small for the MCP result budget: an image
            // count and the first few paths; `trace_query kind=images` has
            // the full identities (path, content hash, build id).
            if let Some(obj) = v.as_object_mut()
                && let Some(images) = obj.remove("images").and_then(|i| i.as_array().cloned())
            {
                const SHOWN: usize = 8;
                let paths: Vec<serde_json::Value> = images
                    .iter()
                    .take(SHOWN)
                    .filter_map(|i| i.get("path").cloned())
                    .collect();
                obj.insert("image_count".into(), serde_json::json!(images.len()));
                obj.insert("image_paths".into(), serde_json::Value::Array(paths));
                if images.len() > SHOWN {
                    obj.insert(
                        "hint".into(),
                        serde_json::json!(format!(
                            "{} more images: trace_query kind=images lists all with hashes and build ids",
                            images.len() - SHOWN
                        )),
                    );
                }
            }
            Ok(v)
        }
        StatusSelect::Sessions { cursor, limit } => {
            let list = c.store.list_sessions()?;
            let start = cursor.and_then(|c| c.parse::<usize>().ok()).unwrap_or(0);
            let lim = limit.unwrap_or(50).min(200) as usize;
            let page: Vec<_> = list
                .into_iter()
                .skip(start)
                .take(lim)
                .map(|(_, v)| v)
                .collect();
            Ok(serde_json::json!({
                "kind": "sessions",
                "data": page,
                "next_cursor": if page.len() == lim { Some((start + lim).to_string()) } else { None::<String> },
            }))
        }
    }
}

async fn handle_decode(
    c: &mut Coord,
    req: DecodeRequest,
    tx: mpsc::Sender<Op>,
) -> Result<DecodeResponse> {
    let snap = c.store.load_snapshot_manifest(&req.snapshot_id)?;
    let (detail, sel) = match &req.detail {
        DetailSel::Calls { .. } => (DetailLevel::Calls, None),
        DetailSel::Instructions { selection } => {
            selection.validate()?;
            if selection.thread_id.is_none()
                || selection.start_ns.is_none()
                || selection.end_ns.is_none()
            {
                return Err(Error::invalid_argument(
                    "instruction decode requires thread_id and a bounded start_ns/end_ns",
                ));
            }
            (DetailLevel::Instructions, Some(selection.clone()))
        }
    };
    let fast = matches!(req.detail, DetailSel::Calls { fast: true });
    let key = decode_cache_key(
        &snap,
        detail,
        sel.as_ref(),
        fast,
        decoder_kind(&snap, &c.limits),
    );
    if let Some((aid, jid)) = find_analysis_by_key(&c.store.root, &req.snapshot_id, &key) {
        return Ok(DecodeResponse {
            analysis_id: aid,
            job_id: jid,
            cached: true,
        });
    }
    if let Some(jid) = c.cache_jobs.get(&key)
        && let Some(job) = c.jobs.get(jid)
    {
        if let Some(aid) = &job.analysis_id {
            return Ok(DecodeResponse {
                analysis_id: aid.clone(),
                job_id: Some(jid.clone()),
                cached: true,
            });
        }
        return Ok(DecodeResponse {
            analysis_id: job.analysis_id.clone().unwrap_or_else(AnalysisId::generate),
            job_id: Some(jid.clone()),
            cached: false,
        });
    }
    if c.running_decode >= c.limits.max_decode_jobs {
        return Err(Error::busy("decode worker is busy"));
    }
    let job_id = JobId::generate();
    let analysis_id = AnalysisId::generate();
    let rec = JobRecord {
        job_id: job_id.clone(),
        kind: if matches!(detail, DetailLevel::Instructions) {
            JobKind::InstructionDecode
        } else {
            JobKind::InitialDecode
        },
        phase: JobPhase::Queued,
        snapshot_id: Some(req.snapshot_id.clone()),
        analysis_id: Some(analysis_id.clone()),
        report_id: None,
        error: None,
    };
    c.jobs.insert(job_id.clone(), rec.clone());
    c.cache_jobs.insert(key.clone(), job_id.clone());
    let _ = c.store.write_json(&c.store.job_path(&job_id), &rec);
    c.running_decode += 1;
    let root = c.store.root.clone();
    let limits = c.limits.clone();
    let snapshot_id = req.snapshot_id.clone();
    let jid = job_id.clone();
    let aid = analysis_id.clone();
    let notify = tx;
    tokio::task::spawn_blocking(move || {
        let r = decode_job(
            &root,
            &limits,
            &snapshot_id,
            &aid,
            detail,
            sel.as_ref(),
            fast,
        );
        let job_path = root.join("jobs").join(format!("{jid}.json"));
        let mut rec = rec;
        match r {
            Ok(()) => rec.phase = JobPhase::Succeeded,
            Err(e) => {
                rec.phase = JobPhase::Failed;
                rec.error = Some(e.to_string());
            }
        }
        let _ = std::fs::write(
            job_path,
            serde_json::to_vec_pretty(&rec).unwrap_or_default(),
        );
        let _ = notify.blocking_send(Op::Internal(InternalEvt::JobFinished {
            rec,
            decode_slot: true,
            expensive_slot: false,
        }));
    });
    Ok(DecodeResponse {
        analysis_id,
        job_id: Some(job_id),
        cached: false,
    })
}

async fn handle_compare(c: &mut Coord, req: CompareRequest, tx: mpsc::Sender<Op>) -> Result<JobId> {
    let key = cache_key(&[&serde_json::to_string(&req).unwrap_or_default()]);
    if let Some(jid) = c.cache_jobs.get(&key) {
        return Ok(jid.clone());
    }
    if c.pending_expensive >= c.limits.max_pending_expensive {
        return Err(Error::busy("compare queue full"));
    }
    let job_id = JobId::generate();
    let report_id = crate::model::ReportId::generate();
    let rec = JobRecord {
        job_id: job_id.clone(),
        kind: JobKind::Compare,
        phase: JobPhase::Queued,
        snapshot_id: None,
        analysis_id: None,
        report_id: Some(report_id.clone()),
        error: None,
    };
    c.jobs.insert(job_id.clone(), rec.clone());
    c.cache_jobs.insert(key.clone(), job_id.clone());
    c.pending_expensive += 1;
    let root = c.store.root.clone();
    let jid = job_id.clone();
    let notify = tx;
    tokio::task::spawn_blocking(move || {
        let r = compare_job(&root, &req, &report_id, &key, &jid);
        let mut rec = rec;
        match r {
            Ok(()) => rec.phase = JobPhase::Succeeded,
            Err(e) => {
                rec.phase = JobPhase::Failed;
                rec.error = Some(e.to_string());
            }
        }
        let _ = std::fs::write(
            root.join("jobs").join(format!("{jid}.json")),
            serde_json::to_vec_pretty(&rec).unwrap_or_default(),
        );
        let _ = notify.blocking_send(Op::Internal(InternalEvt::JobFinished {
            rec,
            decode_slot: false,
            expensive_slot: true,
        }));
    });
    Ok(job_id)
}

struct CaptureOutcome {
    snapshot: SnapshotId,
}

/// The process that records: perf record with its control pipe, or the
/// direct per-thread recorder driving the launch shim.
enum Rec {
    Perf(Box<PerfControl>),
    Direct(Box<crate::capture::direct::DirectRecorder>),
}

impl Rec {
    async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        match self {
            Rec::Perf(p) => p.wait().await,
            Rec::Direct(d) => d.wait().await,
        }
    }

    fn terminate_group(&self, grace: Duration) -> Result<()> {
        match self {
            Rec::Perf(p) => p.terminate_group(grace),
            Rec::Direct(d) => {
                d.terminate_group(grace);
                Ok(())
            }
        }
    }
}

async fn capture_task(
    store_root: PathBuf,
    limits: Limits,
    session: SessionId,
    snapshot: SnapshotId,
    mut req: StartRequest,
    mut stop: watch::Receiver<Option<StopRequest>>,
    tx: mpsc::Sender<Op>,
) -> Result<CaptureOutcome> {
    let staging = store_root.join("staging").join(session.as_str());
    std::fs::create_dir_all(&staging)?;
    let perf_data = staging.join("perf.data");
    let stdout_p = staging.join("capture.stdout");
    let stderr_p = staging.join("capture.stderr");

    let images_dir = staging.join("images");
    std::fs::create_dir_all(&images_dir)?;
    let mut archived = Vec::new();
    if let Target::Launch { argv, cwd, .. } = &req.target {
        let exe = resolve_launch_exe(argv, cwd.as_deref().map(Path::new))?;
        archived.push(archive_image(
            &exe,
            &images_dir,
            &exe.display().to_string(),
        )?);
    }

    let caps = crate::capture::doctor::run_doctor(false, None)
        .ok()
        .and_then(|d| d.pt_caps);
    let caps =
        caps.ok_or_else(|| Error::new(ErrorCode::PtUnavailable, "Intel PT PMU not available"))?;
    let topology = validate_ready_topology(&mut req.config, limits.direct_recorder)?;
    let terms = EffectivePtTerms::resolve(req.config.timing, &caps, topology.aux_bytes_per_buffer)?;
    // Trigger channel: a FIFO the launch shim (symbol trigger) or the workload
    // itself ($TRACE_MCP_TRIGGER) writes to. Opened read-write so it never
    // reports EOF before a writer appears.
    let fifo_path = staging.join("trigger.fifo");
    let mut trigger_rx = if req.trigger.is_some() {
        crate::capture::trigger::make_fifo(&fifo_path)?;
        crate::capture::trigger::make_fifo(&crate::capture::trigger::ack_path(&fifo_path))?;
        let rx = tokio::net::unix::pipe::OpenOptions::new()
            .read_write(true)
            .open_receiver(&fifo_path)
            .map_err(|e| Error::new(ErrorCode::NotReady, format!("open trigger fifo: {e}")))?;
        Some(tokio::io::BufReader::new(rx))
    } else {
        None
    };
    let mut spec = PerfRecordSpec::build(
        &req.config,
        &terms,
        &topology,
        perf_data.clone(),
        req.target.clone(),
        match &req.target {
            Target::Launch { cwd, .. } => cwd.as_ref().map(PathBuf::from),
            Target::Attach { .. } => None,
        },
        limits.raw_disk_budget,
        req.trigger.clone(),
        req.trigger.as_ref().map(|_| fifo_path.clone()),
    )?;
    let mut effective_filters: Vec<String> = Vec::new();
    if !req.config.address_filters.is_empty() {
        if req.config.address_filters.len() as u32 > caps.num_address_ranges {
            return Err(Error::new(
                ErrorCode::UnsupportedPtConfig,
                format!(
                    "{} address filters requested; this CPU has {} address ranges",
                    req.config.address_filters.len(),
                    caps.num_address_ranges
                ),
            ));
        }
        let default_image: Option<PathBuf> = match &req.target {
            Target::Launch { argv, cwd, .. } => {
                resolve_launch_exe(argv, cwd.as_deref().map(Path::new)).ok()
            }
            Target::Attach { pid } => std::fs::read_link(format!("/proc/{pid}/exe")).ok(),
        };
        for f in &req.config.address_filters {
            let image = f
                .image
                .as_ref()
                .map(PathBuf::from)
                .or_else(|| default_image.clone())
                .ok_or_else(|| Error::invalid_argument("address filter needs an image"))?;
            let sym = crate::capture::trigger::resolve_symbol(&image, &f.symbol)?;
            let clause = if f.kind.needs_size() {
                format!(
                    "{} {:#x}/{:#x} @ {}",
                    f.kind.as_str(),
                    sym.file_offset,
                    sym.size,
                    image.display()
                )
            } else {
                format!(
                    "{} {:#x} @ {}",
                    f.kind.as_str(),
                    sym.file_offset,
                    image.display()
                )
            };
            tracing::info!(filter = %clause, symbol = %sym.demangled, "address filter");
            effective_filters.push(clause);
        }
        spec.address_filter = Some(effective_filters.join(","));
    }

    // Direct per-thread recorder for launched workloads; perf
    // record stays for attach targets and address filters.
    let use_direct = limits.direct_recorder;
    let report_fifo = staging.join("report.fifo");
    let spawned = Instant::now();
    // `validate_ready_topology` already fitted the per-thread size (an
    // explicit request or the 32 MiB default, within the budget).
    let direct_aux = req
        .config
        .aux_bytes_per_buffer
        .unwrap_or(crate::model::config::DEFAULT_DIRECT_AUX_BYTES)
        .min(req.config.max_total_aux_bytes);
    let mut rec = if use_direct && matches!(req.target, Target::Attach { .. }) {
        let Target::Attach { pid } = &req.target else {
            unreachable!()
        };
        let pmu = crate::capture::direct::PtPmu::discover()?;
        // Maps now, while the process is certainly alive.
        harvest_proc_maps(*pid, &images_dir, &mut archived, limits.image_budget);
        Rec::Direct(Box::new(crate::capture::direct::DirectRecorder::attach(
            *pid,
            pmu,
            terms.clone(),
            direct_aux,
            req.config.max_total_aux_bytes,
        )?))
    } else if use_direct {
        let pmu = crate::capture::direct::PtPmu::discover()?;
        let (argv, cwd, env) = match &req.target {
            Target::Launch { argv, cwd, env } => (argv.clone(), cwd.clone(), env.clone()),
            Target::Attach { .. } => unreachable!(),
        };
        let symbol = match &req.trigger {
            Some(crate::model::Trigger::Symbol { symbol, hits }) => Some((symbol.clone(), *hits)),
            _ => None,
        };
        Rec::Direct(Box::new(
            crate::capture::direct::DirectRecorder::spawn(
                &report_fifo,
                req.config.cpus.as_deref(),
                symbol.as_ref().map(|(s, h)| (s.as_str(), *h)),
                req.trigger.as_ref().map(|_| fifo_path.as_path()),
                &argv,
                cwd.as_deref().map(Path::new),
                &env,
                &stdout_p,
                &stderr_p,
                pmu,
                terms.clone(),
                // Per thread, not per CPU: an explicit aux_bytes_per_buffer
                // wins, otherwise 32 MiB, all within max_total_aux_bytes.
                direct_aux,
                req.config.max_total_aux_bytes,
            )
            .await?,
        ))
    } else {
        let mut rec = PerfControl::spawn(&spec, &stdout_p, &stderr_p).await?;
        let ping = rec
            .ping(crate::capture::perf::startup_timeout(
                limits.startup_timeout_ms,
                topology.ncpus,
            ))
            .await;
        if !matches!(ping.as_deref(), Ok(ack) if ack.to_ascii_lowercase().contains("ack")) {
            rec.terminate_group(Duration::from_millis(limits.owned_term_grace_ms))?;
            let _ = rec.wait().await;
            return Err(match ping {
                Ok(ack) => Error::new(
                    ErrorCode::NotReady,
                    format!("perf control ping returned {ack:?}, expected ack"),
                ),
                Err(e) => e,
            });
        }
        Rec::Perf(Box::new(rec))
    };
    if let (Rec::Direct(d), Some(f)) = (&mut rec, spec.address_filter.as_ref()) {
        // Events opened so far (attach) get the filter now; later ones at open.
        d.filter = Some(f.clone());
        if !d.events.is_empty() {
            d.notes.push(format!(
                "address filter applied to threads opened after arming; {} thread(s) opened before it are unfiltered",
                d.events.len()
            ));
        }
    }
    let armed = Instant::now();
    write_session_state(&store_root, &session, SessionPhase::Armed)?;
    let _ = tx
        .send(Op::Internal(InternalEvt::Armed(session.clone())))
        .await;

    let after = req.after_ms.map(|ms| armed + Duration::from_millis(ms));
    let deadline = armed + Duration::from_millis(req.config.max_capture_ms);

    let mut aborted = matches!(*stop.borrow(), Some(StopRequest::Abort));
    let mut report_rx = match &mut rec {
        Rec::Direct(d) => d.take_report_rx(),
        Rec::Perf(_) => None,
    };
    let mut report_line = String::new();
    let mut trigger_note: Option<String> = None;
    let mut trigger_address: Option<u64> = None;
    let mut tail_deadline: Option<Instant> = None;
    let mut trigger_line = String::new();
    let reason = loop {
        if aborted {
            break CaptureReason::Stop;
        }
        let now = Instant::now();
        let until_dead = deadline.saturating_duration_since(now);
        let until_after = after.map(|t| t.saturating_duration_since(now));
        let until_tail = tail_deadline.map(|t| t.saturating_duration_since(now));
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() {
                    aborted = true;
                    break CaptureReason::Stop;
                }
                match *stop.borrow() {
                    Some(StopRequest::Finish(r)) => break r,
                    Some(StopRequest::Abort) => {
                        aborted = true;
                        break CaptureReason::Stop;
                    }
                    None => {}
                }
            }
            status = rec.wait() => {
                let _ = status;
                break CaptureReason::TargetExit;
            }
            line = async {
                if report_rx.is_some() {
                    crate::capture::direct::read_report(&mut report_rx, &mut report_line).await
                } else {
                    std::future::pending().await
                }
            } => {
                if let (Some(line), Rec::Direct(d)) = (line, &mut rec) {
                    match d.handle_report(&line) {
                        crate::capture::direct::ReportAction::Opened { pid }
                        | crate::capture::direct::ReportAction::LeaderExit { pid } => {
                            harvest_proc_maps(pid, &images_dir, &mut archived, limits.image_budget);
                        }
                        crate::capture::direct::ReportAction::None => {}
                    }
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                break CaptureReason::TimeLimit;
            }
            _ = async {
                if let Some(d) = until_after {
                    tokio::time::sleep(d).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                break CaptureReason::AfterMs;
            }
            _ = async {
                if let Some(d) = until_tail {
                    tokio::time::sleep(d).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                break CaptureReason::Trigger;
            }
            line = async {
                match trigger_rx.as_mut() {
                    Some(rx) if tail_deadline.is_none() => {
                        use tokio::io::AsyncBufReadExt;
                        trigger_line.clear();
                        rx.read_line(&mut trigger_line).await
                    }
                    _ => std::future::pending().await,
                }
            } => {
                match line {
                    Ok(0) | Err(_) => {
                        // Writer side closed without a hit; keep the other
                        // completion paths.
                        trigger_rx = None;
                    }
                    Ok(_) => {
                        let msg = trigger_line.trim().to_string();
                        if let Some(err) = msg.strip_prefix("error ") {
                            trigger_note = Some(format!("trigger could not be armed: {err}"));
                            trigger_rx = None;
                        } else {
                            trigger_address = msg
                                .split_whitespace()
                                .find(|t| t.starts_with("0x"))
                                .and_then(|t| crate::model::parse_address(t).ok());
                            trigger_note = Some(format!(
                                "trigger fired {} ms after arming ({msg})",
                                armed.elapsed().as_millis()
                            ));
                            match req.tail_ms {
                                Some(t) if t > 0 => {
                                    // Let the parked thread run for the tail.
                                    crate::capture::trigger::send_ack(&fifo_path);
                                    tail_deadline = Some(Instant::now() + Duration::from_millis(t));
                                }
                                _ => break CaptureReason::Trigger,
                            }
                        }
                    }
                }
            }
        }
        let _ = until_dead;
    };

    let mut recorder_notes: Vec<String> = Vec::new();
    match &mut rec {
        Rec::Perf(p) => {
            let _ = p
                .stop(Duration::from_millis(limits.finalize_timeout_ms))
                .await;
        }
        Rec::Direct(d) => {
            // Rings first (the workload keeps running until the ack), then
            // the maps of whoever is still alive.
            for pid in d.finish() {
                harvest_proc_maps(pid, &images_dir, &mut archived, limits.image_budget);
            }
            let raw = d.write(&perf_data)?;
            recorder_notes.push(format!(
                "direct recorder: {} threads traced, {} rings wrapped, {} of {} AUX bytes used, {raw} raw bytes",
                d.traced_threads(),
                d.wrapped_rings(),
                d.aux_used(),
                req.config.max_total_aux_bytes
            ));
            recorder_notes.extend(d.notes.iter().cloned());
        }
    }
    match tokio::time::timeout(
        Duration::from_millis(limits.finalize_timeout_ms),
        rec.wait(),
    )
    .await
    {
        Ok(_) => {}
        Err(_) => {
            if req.target.owns_workload() {
                rec.terminate_group(Duration::from_millis(limits.owned_term_grace_ms))?;
            }
        }
    }
    // The snapshot is on disk: release a thread the trigger shim parked.
    if req.trigger.is_some() {
        crate::capture::trigger::send_ack(&fifo_path);
    }
    if req.target.owns_workload() {
        rec.terminate_group(Duration::from_millis(50))?;
    }

    if aborted || matches!(*stop.borrow(), Some(StopRequest::Abort)) {
        return Err(Error::cancelled("capture cancelled"));
    }

    if let Target::Attach { pid } = &req.target {
        harvest_proc_maps(*pid, &images_dir, &mut archived, limits.image_budget);
    }
    let launch_exe = archived.first().map(|a| a.identity.path.clone());
    if !use_direct {
        harvest_mapped_images(
            &perf_data,
            &images_dir,
            &mut archived,
            limits.image_budget,
            match &req.target {
                Target::Attach { pid } => Some(*pid),
                Target::Launch { .. } => None,
            },
            match &req.target {
                Target::Launch { .. } => launch_exe.as_deref(),
                Target::Attach { .. } => None,
            },
        );
    }
    if let Some(vdso) = read_own_vdso()
        && !already_have(&archived, "[vdso]")
        && let Ok(img) = archive_bytes(vdso, &images_dir, "[vdso]")
    {
        archived.push(img);
    }

    if matches!(*stop.borrow(), Some(StopRequest::Abort)) {
        return Err(Error::cancelled("capture cancelled"));
    }

    let snap = snapshot;
    let dest = store_root.join("snapshots").join(snap.as_str());
    let host = crate::capture::doctor::run_doctor(false, None).ok();
    let manifest = SnapshotManifest {
        schema_version: SCHEMA_VERSION,
        snapshot_id: snap.clone(),
        session_id: session.clone(),
        capture_reason: reason,
        lifecycle: SessionPhase::Captured,
        requested_config: {
            let mut c = req.config.clone();
            // Topology fitting filled in perf's per-CPU choice; the direct
            // recorder sized per thread, so report the request as made.
            if c.aux_bytes_auto && use_direct {
                c.aux_bytes_per_buffer = None;
            }
            c
        },
        effective_event: terms.event_spec.clone(),
        cpu_vendor: host
            .as_ref()
            .map(|h| h.host.cpu_vendor.clone())
            .unwrap_or_default(),
        cpu_model: host
            .as_ref()
            .map(|h| h.host.cpu_model.clone())
            .unwrap_or_default(),
        cpu_family: host
            .as_ref()
            .map(|h| h.host.cpu_family.clone())
            .unwrap_or_default(),
        cpu_stepping: host
            .as_ref()
            .map(|h| h.host.cpu_stepping.clone())
            .unwrap_or_default(),
        kernel: host
            .as_ref()
            .map(|h| h.host.kernel.clone())
            .unwrap_or_default(),
        perf_version: host
            .as_ref()
            .and_then(|h| h.perf.as_ref().map(|p| p.version.clone()))
            .unwrap_or_default(),
        perf_argv: match &rec {
            Rec::Perf(_) => spec.argv(Path::new("perf"), -1, -1),
            Rec::Direct(d) => d.argv.clone(),
        },
        capture_clock: None,
        raw_bytes: Count(std::fs::metadata(&perf_data).map(|m| m.len()).unwrap_or(0)),
        target: req.target.clone(),
        // The direct recorder is task scoped whatever `cpus` says (pinning
        // only); perf record with -C records every task on those CPUs.
        scope: match (&req.config.cpus, &rec) {
            (Some(cpus), Rec::Perf(_)) => {
                crate::model::CaptureScope::CpuWide { cpus: cpus.clone() }
            }
            _ => crate::model::CaptureScope::Task,
        },
        recorder: Some(match &rec {
            Rec::Perf(_) => "perf".to_string(),
            Rec::Direct(_) => "direct".to_string(),
        }),
        root_pid: match &rec {
            Rec::Direct(d) => d.root_pid,
            Rec::Perf(_) => None,
        },
        trigger: req.trigger.clone(),
        trigger_address: trigger_address.map(crate::model::Address),
        address_filters: effective_filters.clone(),
        workload: req.workload.clone(),
        observed_threads: Vec::new(),
        images: archived.iter().map(|a| a.identity.clone()).collect(),
        missing_images: archived
            .iter()
            .filter(|a| a.identity.build_id.is_none() && !a.identity.path.starts_with('['))
            .map(|a| {
                format!(
                    "{} (no build id: perf will read the recorded path at decode time)",
                    a.identity.path
                )
            })
            .collect(),
        redecode_ready: archived.iter().any(|a| a.identity.archived)
            && archived
                .iter()
                .all(|a| a.identity.build_id.is_some() || a.identity.path.starts_with('[')),
        diagnostics: {
            let mut d = vec![match &rec {
                Rec::Perf(_) => format!(
                    "ncpus={} aux={} aux_per_cpu={} arm_ms={}",
                    topology.ncpus,
                    topology.aux_total,
                    topology.aux_bytes_per_buffer,
                    (armed - spawned).as_millis()
                ),
                Rec::Direct(d) => format!(
                    "direct recorder: aux_per_thread={} aux_budget={} threads={} arm_ms={}",
                    direct_aux,
                    req.config.max_total_aux_bytes,
                    d.traced_threads(),
                    (armed - spawned).as_millis()
                ),
            }];
            d.extend(recorder_notes.iter().cloned());
            if let Some(n) = &trigger_note {
                d.push(n.clone());
            } else if req.trigger.is_some() {
                d.push(format!(
                    "trigger {:?} did not fire before capture ended ({})",
                    req.trigger,
                    crate::capture::perf::capture_reason_label(reason)
                ));
            }
            if let Some(cpus) = &req.config.cpus {
                d.push(format!(
                    "workload pinned to cpus {cpus:?}; PT recorded every user task on those CPUs (cpu_wide scope). Analyses keep only the target process tree; perf.data also holds other tasks' trace bytes"
                ));
            }
            if !use_direct
                && topology.aux_bytes_per_buffer != DEFAULT_AUX_BYTES
                && topology.ncpus.saturating_mul(DEFAULT_AUX_BYTES) > req.config.max_total_aux_bytes
            {
                d.push(format!(
                    "aux auto-selected {} because default {} x {} exceeded {}",
                    topology.aux_bytes_per_buffer,
                    DEFAULT_AUX_BYTES,
                    topology.ncpus,
                    req.config.max_total_aux_bytes
                ));
            }
            d
        },
        target_exit_status: None,
        recorder_exit_status: None,
    };
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| Error::decode_failed(e.to_string()))?;
    std::fs::write(staging.join("manifest.json"), manifest_bytes)?;
    std::fs::create_dir_all(dest.parent().unwrap())?;
    if dest.exists() {
        return Err(Error::decode_failed("snapshot dest exists"));
    }
    // Control FIFOs are useless once the capture is over.
    for f in [
        "trigger.fifo",
        "trigger.fifo.ack",
        "report.fifo",
        "report.fifo.ack",
    ] {
        let _ = std::fs::remove_file(staging.join(f));
    }
    std::fs::rename(&staging, &dest)?;
    write_session_state(&store_root, &session, SessionPhase::Captured)?;
    Ok(CaptureOutcome { snapshot: snap })
}

fn write_session_state(root: &Path, id: &SessionId, phase: SessionPhase) -> Result<()> {
    let p = root.join("sessions").join(format!("{id}.json"));
    if let Some(mut v) = std::fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
    {
        v["state"] = serde_json::json!(phase);
        std::fs::write(p, serde_json::to_vec_pretty(&v).unwrap_or_default())?;
    }
    Ok(())
}

fn archived_bytes(archived: &[crate::decode::images::ArchivedImage]) -> u64 {
    archived.iter().map(|a| a.bytes.len() as u64).sum()
}

fn already_have(archived: &[crate::decode::images::ArchivedImage], path: &str) -> bool {
    archived.iter().any(|a| a.identity.path == path)
}

fn harvest_proc_maps(
    pid: u32,
    images_dir: &Path,
    archived: &mut Vec<crate::decode::images::ArchivedImage>,
    budget: u64,
) {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return;
    };
    let mut used = archived_bytes(archived);
    for line in maps.lines() {
        let Some(path) = line.split_whitespace().last() else {
            continue;
        };
        if !path.starts_with('/') || already_have(archived, path) {
            continue;
        }
        let p = Path::new(path);
        let Ok(meta) = p.metadata() else { continue };
        if used.saturating_add(meta.len()) > budget {
            continue;
        }
        if let Ok(img) = archive_image(p, images_dir, path) {
            used = used.saturating_add(img.bytes.len() as u64);
            archived.push(img);
        }
    }
}

/// Pids belonging to the traced target: the exec'd workload (or attached
/// pid) plus every descendant seen in FORK sideband. With `-C`, perf also
/// synthesizes mappings for unrelated processes on those CPUs; those must
/// not be archived as evidence.
fn traced_tracker(
    recs: &[crate::decode::perf_script::RawRecord],
    attach_pid: Option<u32>,
    launch_exe: Option<&str>,
) -> crate::decode::perf_script::PidTracker {
    let mut t = match attach_pid {
        Some(p) => crate::decode::perf_script::PidTracker::with_root(p),
        None => crate::decode::perf_script::PidTracker::default(),
    };
    if let Some(exe) = launch_exe {
        t = t.expecting_exec_of(exe);
    }
    for _ in 0..2 {
        for rec in recs {
            t.observe(rec);
        }
    }
    t
}

fn harvest_mapped_images(
    perf_data: &Path,
    images_dir: &Path,
    archived: &mut Vec<crate::decode::images::ArchivedImage>,
    budget: u64,
    attach_pid: Option<u32>,
    launch_exe: Option<&str>,
) {
    let Ok(perf) = crate::capture::doctor::resolve_perf() else {
        return;
    };
    let args = metadata_script_args(perf_data);
    let Ok(out) = std::process::Command::new(perf)
        .env("LC_ALL", "C")
        .env("PERF_PAGER", "cat")
        .args(&args)
        .output()
    else {
        return;
    };
    let Ok(recs) = parse_reader(std::io::Cursor::new(out.stdout)) else {
        return;
    };
    let tracker = traced_tracker(&recs, attach_pid, launch_exe);
    let mut seen = HashSet::new();
    let mut used = archived_bytes(archived);
    for rec in recs {
        let crate::decode::perf_script::RawRecord::Mmap(m) = rec else {
            continue;
        };
        if !tracker.is_empty() && !tracker.mapping_is_live(&m) {
            continue;
        }
        if m.path.is_empty() || m.path.starts_with('[') || !seen.insert(m.path.clone()) {
            continue;
        }
        if already_have(archived, &m.path) {
            continue;
        }
        let p = Path::new(&m.path);
        let Ok(meta) = p.metadata() else { continue };
        if used.saturating_add(meta.len()) > budget {
            continue;
        }
        if let Ok(img) = archive_image(p, images_dir, &m.path) {
            used = used.saturating_add(img.bytes.len() as u64);
            archived.push(img);
        }
    }
}

/// Decode into `staging/<analysis>` and publish atomically into
/// `derived/<analysis>` only on success; a failed decode leaves nothing.
fn decode_job(
    root: &Path,
    limits: &Limits,
    snapshot: &SnapshotId,
    analysis: &AnalysisId,
    detail: DetailLevel,
    sel: Option<&Selection>,
    fast: bool,
) -> Result<()> {
    let staging = root.join("staging").join(analysis.as_str());
    let _ = std::fs::remove_dir_all(&staging);
    let result = decode_job_into(
        root, limits, snapshot, analysis, detail, sel, fast, &staging,
    );
    match result {
        Ok(()) => {
            let dest = root
                .join("snapshots")
                .join(snapshot.as_str())
                .join("derived")
                .join(analysis.as_str());
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(&staging, &dest)?;
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_job_into(
    root: &Path,
    limits: &Limits,
    snapshot: &SnapshotId,
    analysis: &AnalysisId,
    detail: DetailLevel,
    sel: Option<&Selection>,
    fast: bool,
    dest: &Path,
) -> Result<()> {
    let snap_dir = root.join("snapshots").join(snapshot.as_str());
    let manifest: SnapshotManifest = crate::store::read_json(&snap_dir.join("manifest.json"))?;
    // A direct-recorder bundle has no perf feature section; perf script
    // cannot read it, so it is always decoded natively.
    let direct_bundle = manifest.recorder.as_deref() == Some("direct");
    let native_pref = limits.native_decoder || direct_bundle;
    let perf_data = snap_dir.join("perf.data");
    let images_root = snap_dir.join("images");
    let mut archived = Vec::new();
    for identity in &manifest.images {
        let hash = identity.content_hash.trim_start_matches("sha256:");
        let dest = images_root
            .join(hash)
            .join(Path::new(&identity.path).file_name().unwrap_or_default());
        if let Ok((bytes, hash)) = hash_file(&dest) {
            archived.push(crate::decode::images::ArchivedImage {
                identity: crate::model::ImageIdentity {
                    path: identity.path.clone(),
                    content_hash: hash,
                    build_id: identity.build_id.clone(),
                    archived: true,
                },
                archive_path: dest,
                bytes,
            });
        }
    }
    if archived.is_empty() && images_root.exists() {
        for e in std::fs::read_dir(&images_root)?.flatten() {
            if e.path().is_dir() {
                for f in std::fs::read_dir(e.path())?.flatten() {
                    if f.path().is_file()
                        && let Ok((bytes, hash)) = hash_file(&f.path())
                    {
                        archived.push(crate::decode::images::ArchivedImage {
                            identity: crate::model::ImageIdentity {
                                path: f.file_name().to_string_lossy().into_owned(),
                                content_hash: hash,
                                build_id: crate::decode::images::elf_build_id(&bytes)
                                    .ok()
                                    .flatten(),
                                archived: true,
                            },
                            archive_path: f.path(),
                            bytes,
                        });
                    }
                }
            }
        }
    }
    // Private build-id cache: perf verifies identities and never reads a
    // rebuilt workspace binary for a cached image. `--symfs` is deliberately
    // not used (it breaks perf's own vdso lookup).
    let cache_dir = snap_dir.join("buildid");
    let uncached = build_buildid_cache(&archived, &cache_dir)?;
    if !uncached.is_empty() {
        tracing::warn!(
            images = ?uncached,
            "images without build id are decoded from their recorded path, not the archive"
        );
    }
    let buildid_prefix = vec!["--buildid-dir".to_string(), cache_dir.display().to_string()];
    let perf = crate::capture::doctor::resolve_perf()?;
    std::fs::create_dir_all(dest)?;
    let key = decode_cache_key(
        &manifest,
        detail,
        sel,
        fast,
        decoder_kind(&manifest, limits),
    );
    let started = Instant::now();

    // CPU-wide captures contain other tasks' PT. Learn the traced process
    // tree from the cheap sideband pass and let perf skip printing everyone
    // else (`--pid=`): measured 48.7 s -> 34.3 s on a 4-CPU capture.
    let cpu_wide = matches!(manifest.scope, crate::model::CaptureScope::CpuWide { .. });
    let (pid_args, seeded_tracker) = if cpu_wide || native_pref {
        let mut tracker = pid_tracker_for(&manifest);
        if native_pref {
            // The sideband is read directly from perf.data; no perf run.
            let pd = crate::capture::perfdata::read_perf_data(&perf_data)?;
            for (_, rec) in crate::decode::native::sideband_records(&pd) {
                tracker.observe(&rec);
            }
        } else {
            let mut meta_args = buildid_prefix.clone();
            meta_args.extend(metadata_script_args(&perf_data));
            run_script_stream(&perf, &meta_args, |rec| {
                tracker.observe(&rec);
                Ok(())
            })?;
        }
        let pids = tracker.pids();
        let args = if pids.is_empty() || !cpu_wide {
            Vec::new()
        } else {
            vec![format!(
                "--pid={}",
                pids.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )]
        };
        (args, Some(tracker))
    } else {
        (Vec::new(), None)
    };
    // CPUs that carry AUX data, from the perf.data record stream (no decode).
    // Per-CPU split files are validated for cpu-wide captures only: on a
    // task-scoped 80-CPU trigger capture the split perf-script path decoded
    // none of the workload (the whole file does), so task captures stay
    // single-stream on the perf path.
    let aux_cpus = if cpu_wide {
        crate::capture::perfdata::auxtrace_cpus(&perf_data).unwrap_or_default()
    } else {
        Vec::new()
    };
    // Native decode only follows the traced process tree (empty images for
    // everyone else on the CPUs); task-scoped captures already contain only it.
    let native_pids: Option<std::collections::HashSet<u32>> = seeded_tracker
        .as_ref()
        .map(|t| t.pids().into_iter().collect())
        .filter(|s: &std::collections::HashSet<u32>| !s.is_empty());
    let tracker_for = |manifest: &SnapshotManifest| {
        seeded_tracker
            .clone()
            .unwrap_or_else(|| pid_tracker_for(manifest))
    };

    match detail {
        DetailLevel::Calls => {
            let mut args = buildid_prefix.clone();
            args.extend(crate::capture::perf::calls_script_args_mode(
                &perf_data, fast,
            ));
            args.extend(pid_args.iter().cloned());
            let native = native_pref && (!fast || direct_bundle) && native_supported(&manifest);
            // When the derived budget cannot hold the whole history, keep
            // the newest part: retry on the last 1/4, 1/16, ... of each ring.
            let mut tail_div: u32 = 1;
            let (stats, decoder_version, decoder_argv, ir) = loop {
                let mut recon = Reconstructor::new(analysis.clone(), &archived)
                    .with_budget(limits.resident_decode_budget)
                    .with_spill(dest, limits.derived_budget)?
                    .with_inline_attribution();
                if tail_div > 1 {
                    recon = recon.with_note(format!(
                    "derived budget {} could not hold the full history: only the newest 1/{tail_div} of each ring was decoded",
                    limits.derived_budget
                ));
                }
                if fast && direct_bundle {
                    recon = recon.with_note(
                        "fast mode is a perf-script option; this direct-recorder bundle was decoded natively in full (native decode is the faster path anyway)".into(),
                    );
                } else if fast {
                    recon = recon.with_note(
                    "fast decode: only calls and returns were synthesized; tail calls and PLT stubs are not observed, so spans may be attributed to the caller and inter-function jumps are missing".into(),
                );
                }
                if !manifest.address_filters.is_empty() {
                    recon = recon.with_note(format!(
                    "hardware address filter active ({}): code outside the filtered ranges was not traced; calls into it appear as trace_boundary gaps and its functions have no spans",
                    manifest.address_filters.join(", ")
                ));
                }
                // Always scope to the traced process tree: CPU-wide captures
                // contain other tasks, and launches through the shim contain the
                // shim's own pre-exec execution under the same pid.
                recon = recon.with_pid_filter(tracker_for(&manifest));
                if let (Some(addr), Some(crate::model::Trigger::Symbol { hits, .. })) =
                    (manifest.trigger_address, &manifest.trigger)
                {
                    recon = recon.with_trigger(addr.0, *hits);
                }
                let attempt = if native {
                    run_native_stream(
                        &perf_data,
                        &archived,
                        &manifest,
                        None,
                        native_pids.clone(),
                        limits.decode_parallelism,
                        tail_div,
                        |rec| recon.push(&rec),
                    )
                    .and_then(|stats| recon.finish().map(|ir| (stats, ir)))
                } else {
                    run_script_stream_parallel(
                        &perf,
                        &args,
                        &aux_cpus,
                        limits.decode_parallelism,
                        limits.decode_timeout_ms,
                        |rec| recon.push(&rec),
                    )
                    .and_then(|stats| recon.finish().map(|ir| (stats, ir)))
                };
                let (stats, ir) = match attempt {
                    Ok(v) => v,
                    Err(e) if native && e.code == ErrorCode::LimitExceeded && tail_div < 64 => {
                        // x4 steps: a failed full pass already cost the most.
                        tail_div *= 4;
                        for f in ["spans.jsonl", "events.jsonl", "inline.jsonl"] {
                            let _ = std::fs::remove_file(dest.join(f));
                        }
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                let (decoder_version, decoder_argv) = if native {
                    (crate::decode::native::decoder_version(), {
                        let mut v =
                            vec!["native".to_string(), "--itrace=be-equivalent".to_string()];
                        v.extend(pid_args.iter().cloned());
                        v
                    })
                } else {
                    (manifest.perf_version.clone(), args.clone())
                };
                break (stats, decoder_version, decoder_argv, ir);
            };
            write_jsonl(&dest.join("functions.json"), &ir.functions)?;
            write_jsonl(&dest.join("locations.json"), &ir.locations)?;
            write_jsonl(&dest.join("inline.jsonl"), &ir.inline_rows)?;
            if ir.spilled.is_none() {
                write_jsonl(&dest.join("spans.jsonl"), &ir.spans)?;
                write_jsonl(&dest.join("events.jsonl"), &ir.events)?;
            }
            write_jsonl(&dest.join("gaps.jsonl"), &ir.gaps)?;
            write_jsonl(&dest.join("threads.jsonl"), &ir.threads)?;
            write_jsonl(&dest.join("mappings.jsonl"), &ir.mappings)?;
            let am = AnalysisManifest {
                schema_version: SCHEMA_VERSION,
                ir_version: IR_VERSION,
                analysis_id: analysis.clone(),
                snapshot_id: snapshot.clone(),
                detail,
                decoder_version,
                decoder_argv,
                dialect: if native {
                    "libipt-block-v1".to_string()
                } else {
                    crate::decode::DIALECT.to_string()
                },
                cache_key: key.clone(),
                origin: ir.origin,
                selection: None,
                quality: ir.quality,
                function_count: Count(ir.functions.len() as u64),
                span_count: Count(ir.span_count),
                event_count: Count(ir.event_count),
                covered_start_ns: ir.threads.iter().filter_map(|t| t.start.relative_ns).min(),
                covered_end_ns: ir
                    .threads
                    .iter()
                    .filter_map(|t| t.end.as_ref().and_then(|e| e.relative_ns))
                    .max(),
                thread_count: Count(ir.threads.len() as u64),
                sample_count: Count(stats.samples),
                script_lines: Count(stats.lines),
                script_bytes: Count(stats.bytes),
                decode_wall_ms: started.elapsed().as_millis() as u64,
                trigger_hit_ns: ir.trigger_hit_ns,
                decode_mode: if fast { "fast".into() } else { "full".into() },
                decode_streams: if native {
                    stats.streams
                } else {
                    cpu_groups(&aux_cpus, limits.decode_parallelism).len() as u32
                },
            };
            std::fs::write(
                dest.join("manifest.json"),
                serde_json::to_vec_pretty(&am).unwrap(),
            )?;
        }
        DetailLevel::Instructions => {
            let calls_origin = find_calls_origin(&snap_dir).ok_or_else(|| {
                Error::new(
                    ErrorCode::DetailNotReady,
                    "initial calls analysis origin is required",
                )
                .with_next("Wait for the initial decode job")
            })?;
            let origin_abs: u64 = calls_origin.abs_perf_time.0.parse().unwrap_or(0);
            // Mappings established before the window are still required inside it:
            // collect them from a sideband-only pass with no time filter.
            let mut mappings = Vec::new();
            let mut push_mapping = |m: crate::decode::perf_script::MmapEvent| {
                mappings.push(crate::model::MappingRecord {
                    generation: mappings.len() as u32,
                    pid: m.pid,
                    start: crate::model::Address(m.start),
                    end: crate::model::Address(m.start.saturating_add(m.len)),
                    pgoff: m.pgoff,
                    prot: m.prot,
                    path: m.path,
                    build_id: None,
                    valid_from: crate::model::EventTime::unknown(),
                    valid_to: None,
                });
            };
            if native_pref {
                // Mappings straight from the perf.data sideband (a direct
                // recorder bundle is not readable by perf script at all).
                let pd = crate::capture::perfdata::read_perf_data(&perf_data)?;
                for (_, rec) in crate::decode::native::sideband_records(&pd) {
                    if let RawRecord::Mmap(m) = rec {
                        push_mapping(m);
                    }
                }
            } else {
                let mut meta_args = buildid_prefix.clone();
                meta_args.extend(metadata_script_args(&perf_data));
                run_script_stream(&perf, &meta_args, |rec| {
                    if let RawRecord::Mmap(m) = rec {
                        push_mapping(m);
                    }
                    Ok(())
                })?;
            }
            let mut args = buildid_prefix.clone();
            args.extend(insn_script_args(&perf_data));
            args.extend(pid_args.iter().cloned());
            if let Some(s) = sel
                && let (Some(a), Some(b)) = (s.start_ns, s.end_ns)
            {
                // perf filters by absolute seconds; extend the end slightly so
                // the instruction after the window can classify its last
                // conditional. Retention still obeys the half-open selection.
                let lo = origin_abs.saturating_add(a);
                let hi = origin_abs.saturating_add(b).saturating_add(1_000_000);
                args.push("--time".into());
                args.push(format!("{},{}", perf_time_arg(lo), perf_time_arg(hi)));
            }
            let mut recon =
                InsnReconstructor::new(analysis.clone(), &calls_origin, &archived, mappings, sel)
                    .with_budget(limits.resident_decode_budget);
            recon = recon.with_pid_filter(tracker_for(&manifest));
            let native_sel = sel.and_then(|s| {
                let tid = s.thread_id.as_ref()?;
                let (pid, tid_num) = thread_pid_tid(&snap_dir, tid)?;
                Some((
                    pid,
                    tid_num,
                    origin_abs.saturating_add(s.start_ns?),
                    origin_abs.saturating_add(s.end_ns?),
                ))
            });
            if direct_bundle && native_sel.is_none() {
                return Err(Error::new(
                    ErrorCode::NotFound,
                    "instruction decode needs a thread of the calls analysis; the selected thread_id is not in it",
                )
                .with_next("Use a thread id from trace_query kind=summary"));
            }
            let native = native_pref && native_sel.is_some() && native_supported(&manifest);
            let stats = if native {
                run_native_stream(
                    &perf_data,
                    &archived,
                    &manifest,
                    native_sel,
                    native_pids.clone(),
                    limits.decode_parallelism,
                    1,
                    |rec| recon.push(&rec),
                )?
            } else {
                run_script_stream_parallel(
                    &perf,
                    &args,
                    &aux_cpus,
                    limits.decode_parallelism,
                    limits.decode_timeout_ms,
                    |rec| recon.push(&rec),
                )?
            };
            let mut ir = recon.finish()?;
            if let Some(cq) = find_calls_analysis(&snap_dir)
                .and_then(|aid| {
                    crate::store::read_json::<AnalysisManifest>(
                        &snap_dir
                            .join("derived")
                            .join(aid.as_str())
                            .join("manifest.json"),
                    )
                    .ok()
                })
                .map(|am| am.quality)
            {
                ir.quality.ring_truncation = cq.ring_truncation;
                ir.quality.gap_count = cq.gap_count;
                ir.quality.gaps_by_kind = cq.gaps_by_kind;
            }
            write_jsonl(&dest.join("instructions.jsonl"), &ir.instructions)?;
            let branches = aggregate_branches(&ir.instructions);
            write_jsonl(&dest.join("branches.jsonl"), &branches)?;
            let am = AnalysisManifest {
                schema_version: SCHEMA_VERSION,
                ir_version: IR_VERSION,
                analysis_id: analysis.clone(),
                snapshot_id: snapshot.clone(),
                detail,
                decoder_version: if native {
                    crate::decode::native::decoder_version()
                } else {
                    manifest.perf_version
                },
                decoder_argv: if native {
                    vec![
                        "native".to_string(),
                        "--itrace=i1ibe-equivalent".to_string(),
                    ]
                } else {
                    args
                },
                dialect: if native {
                    "libipt-block-v1".to_string()
                } else {
                    crate::decode::DIALECT.to_string()
                },
                cache_key: key,
                origin: calls_origin,
                selection: sel.cloned(),
                quality: ir.quality,
                function_count: Count(0),
                span_count: Count(0),
                event_count: Count(ir.instructions.len() as u64),
                covered_start_ns: sel.and_then(|s| s.start_ns),
                covered_end_ns: sel.and_then(|s| s.end_ns),
                thread_count: Count(u64::from(sel.and_then(|s| s.thread_id.as_ref()).is_some())),
                sample_count: Count(ir.samples_seen),
                script_lines: Count(stats.lines),
                script_bytes: Count(stats.bytes),
                decode_wall_ms: started.elapsed().as_millis() as u64,
                trigger_hit_ns: None,
                decode_mode: "full".into(),
                decode_streams: if native {
                    stats.streams
                } else {
                    cpu_groups(&aux_cpus, limits.decode_parallelism).len() as u32
                },
            };
            std::fs::write(
                dest.join("manifest.json"),
                serde_json::to_vec_pretty(&am).unwrap(),
            )?;
        }
    }
    Ok(())
}

/// Process-tree tracker for a snapshot: attach pid, or the launched exe
/// (samples before its exec belong to the pin shim / recorder image).
/// Give back a session's capture slot exactly once.
fn release_capture_slot(c: &mut Coord, session: &SessionId) {
    if let Some(s) = c.sessions.get_mut(session)
        && s.slot_held
    {
        s.slot_held = false;
        c.active_captures = c.active_captures.saturating_sub(1);
    }
}

fn pid_tracker_for(manifest: &SnapshotManifest) -> crate::decode::perf_script::PidTracker {
    use crate::decode::perf_script::PidTracker;
    // Direct bundles name their root; descendants follow from the FORK
    // records, whatever their comm (wrapper launches such as `cargo run`).
    if manifest.recorder.as_deref() == Some("direct")
        && let Some(root) = manifest.root_pid
    {
        return PidTracker::with_root(root);
    }
    match &manifest.target {
        Target::Attach { pid } => PidTracker::with_root(*pid),
        Target::Launch { argv, cwd, .. } => {
            let exe = resolve_launch_exe(argv, cwd.as_deref().map(Path::new))
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| argv.first().cloned().unwrap_or_default());
            PidTracker::default().expecting_exec_of(&exe)
        }
    }
}

/// The native decoder covers every capture kind (plain, cpu-wide, trigger,
/// address-filtered); `Limits.native_decoder` / `TRACE_MCP_DECODER=perf` is
/// the only switch back to perf script.
fn native_supported(_manifest: &SnapshotManifest) -> bool {
    true
}

/// pid/tid for a thread id of the snapshot's calls analysis.
fn thread_pid_tid(snap_dir: &Path, thread: &crate::model::ThreadId) -> Option<(u32, u32)> {
    let aid = find_calls_analysis(snap_dir)?;
    let threads: Vec<crate::model::ThreadLifetime> = read_jsonl(
        &snap_dir
            .join("derived")
            .join(aid.as_str())
            .join("threads.jsonl"),
    )
    .ok()?;
    threads
        .iter()
        .find(|t| &t.id == thread)
        .map(|t| (t.pid, t.tid))
}

/// Decode with libipt in-process: per-CPU streams merged by time through
/// the same k-way merge as the perf-script path.
#[allow(clippy::too_many_arguments)]
fn run_native_stream(
    perf_data: &Path,
    images: &[crate::decode::images::ArchivedImage],
    manifest: &SnapshotManifest,
    instructions: Option<(u32, u32, u64, u64)>,
    pids: Option<std::collections::HashSet<u32>>,
    parallelism: u32,
    tail_div: u32,
    sink: impl FnMut(RawRecord) -> Result<()>,
) -> Result<StreamStats> {
    let cpu_model = crate::decode::native::CpuModel {
        family: manifest.cpu_family.parse().unwrap_or(6),
        model: manifest.cpu_model.parse().unwrap_or(0),
        stepping: manifest.cpu_stepping.parse().unwrap_or(0),
    };
    let mtc = crate::decode::native::mtc_period_from_spec(&manifest.effective_event);
    let (receivers, handles, streams) = crate::decode::native::spawn_native_streams(
        perf_data,
        images,
        cpu_model,
        mtc,
        crate::decode::native::DecodeSelection {
            instructions,
            pids,
            tail_div,
        },
        parallelism,
    )?;
    let merged = merge_records(receivers, sink);
    let mut stats = StreamStats::default();
    let mut first_err = None;
    for h in handles {
        match h.join() {
            Ok(Ok(n)) => stats.samples += n,
            Ok(Err(e)) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
            Err(_) => {
                if first_err.is_none() {
                    first_err = Some(Error::decode_failed("native decode thread panicked"));
                }
            }
        }
    }
    merged?;
    if let Some(e) = first_err {
        return Err(e);
    }
    stats.lines = stats.samples;
    stats.streams = streams as u32;
    Ok(stats)
}

/// `perf script --time` takes absolute seconds with a decimal fraction.
fn perf_time_arg(abs_ns: u64) -> String {
    format!("{}.{:09}", abs_ns / 1_000_000_000, abs_ns % 1_000_000_000)
}

/// Records from one `perf script` child, tagged for merging.
type Tagged = (Option<u64>, RawRecord);
/// Batches cut channel synchronisation to once per BATCH records.
type Batch = Vec<Tagged>;
const BATCH: usize = 2048;

/// Pulls batches from a channel and hands out records one at a time.
struct BatchedRx {
    rx: std::sync::mpsc::Receiver<Batch>,
    cur: std::vec::IntoIter<Tagged>,
}

impl BatchedRx {
    fn new(rx: std::sync::mpsc::Receiver<Batch>) -> Self {
        Self {
            rx,
            cur: Vec::new().into_iter(),
        }
    }

    fn next(&mut self) -> Option<Tagged> {
        loop {
            if let Some(t) = self.cur.next() {
                return Some(t);
            }
            match self.rx.recv() {
                Ok(batch) => self.cur = batch.into_iter(),
                Err(_) => return None,
            }
        }
    }
}

/// Split CPUs into at most `parallelism` groups (round-robin) for `--cpu`.
fn cpu_groups(cpus: &[u32], parallelism: u32) -> Vec<Vec<u32>> {
    let n = (parallelism.max(1) as usize).min(cpus.len().max(1));
    let mut groups: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, c) in cpus.iter().enumerate() {
        groups[i % n].push(*c);
    }
    groups.retain(|g| !g.is_empty());
    groups
}

/// K-way merge of time-ordered record streams. Records carry the perf
/// timestamp; equal timestamps resolve by stream index, so per-CPU input
/// order is preserved. Sideband (mmap/task/switch/lost) is taken only from
/// stream 0: every child prints it, and it must not be applied twice.
fn merge_records(
    receivers: Vec<std::sync::mpsc::Receiver<Batch>>,
    mut sink: impl FnMut(RawRecord) -> Result<()>,
) -> Result<()> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut receivers: Vec<BatchedRx> = receivers.into_iter().map(BatchedRx::new).collect();
    let mut heads: Vec<Option<Tagged>> = receivers.iter_mut().map(|r| r.next()).collect();
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::new();
    for (i, h) in heads.iter().enumerate() {
        if let Some((t, _)) = h {
            heap.push(Reverse((t.unwrap_or(0), i)));
        }
    }
    while let Some(Reverse((_, i))) = heap.pop() {
        let (_, rec) = heads[i].take().expect("head present");
        let sideband = matches!(
            rec,
            RawRecord::Mmap(_) | RawRecord::Task(_) | RawRecord::Switch { .. } | RawRecord::Lost(_)
        );
        if !(sideband && i != 0) {
            sink(rec)?;
        }
        if let Some(next) = receivers[i].next() {
            heap.push(Reverse((next.0.unwrap_or(0), i)));
            heads[i] = Some(next);
        }
    }
    Ok(())
}

/// One `perf script` per CPU group, merged by timestamp. Falls back to the
/// serial path for a single group. `args` must not contain `--cpu`.
fn run_script_stream_parallel(
    perf: &Path,
    args: &[String],
    cpus: &[u32],
    parallelism: u32,
    timeout_ms: u64,
    sink: impl FnMut(RawRecord) -> Result<()>,
) -> Result<StreamStats> {
    let groups = cpu_groups(cpus, parallelism);
    if groups.len() <= 1 {
        return run_script_stream_timed(perf, args, timeout_ms, sink);
    }
    // perf 6.12's `--cpu` drops every PT sample instead of restricting the
    // decode, so each child gets its own perf.data holding one CPU's AUX
    // stream (sideband and features intact).
    let (perf_data, data_pos) = args
        .iter()
        .enumerate()
        .find(|(i, a)| *i > 0 && args[i - 1] == "-i" && !a.starts_with('-'))
        .map(|(i, a)| (PathBuf::from(a), i))
        .ok_or_else(|| Error::decode_failed("perf script args lack -i <perf.data>"))?;
    let split_dir = perf_data.parent().unwrap_or(Path::new(".")).join("split");
    std::fs::create_dir_all(&split_dir)?;
    let mut split_files = Vec::new();
    for g in &groups {
        // One file per group: keep every CPU of the group.
        let name = format!(
            "cpu{}.data",
            g.iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("-")
        );
        let dest = split_dir.join(name);
        crate::capture::perfdata::split_by_cpus(&perf_data, g, &dest)?;
        split_files.push(dest);
    }
    let mut children = Vec::new();
    let mut receivers = Vec::new();
    let mut readers = Vec::new();
    for dest in &split_files {
        let mut a = args.to_vec();
        a[data_pos] = dest.display().to_string();
        let mut child = std::process::Command::new(perf)
            .env("LC_ALL", "C")
            .env("PERF_PAGER", "cat")
            .args(&a)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::decode_failed("perf script stdout missing"))?;
        let (tx, rx) = std::sync::mpsc::sync_channel::<Batch>(64);
        readers.push(std::thread::spawn(move || {
            let mut stats = StreamStats::default();
            let mut batch: Batch = Vec::with_capacity(BATCH);
            let r = stream_records(stdout, &mut stats, |rec| {
                let t = match &rec {
                    RawRecord::Sample(s) => s.time_ns,
                    RawRecord::Mmap(m) => m.time_ns,
                    RawRecord::Task(t) => t.time_ns,
                    RawRecord::Switch { time_ns, .. } => *time_ns,
                    RawRecord::DecoderError(e) => e.time_ns,
                    RawRecord::Lost(l) => l.time_ns,
                };
                batch.push((t, rec));
                if batch.len() >= BATCH {
                    let full = std::mem::replace(&mut batch, Vec::with_capacity(BATCH));
                    tx.send(full)
                        .map_err(|_| Error::cancelled("merge stopped"))?;
                }
                Ok(())
            });
            if !batch.is_empty() {
                let _ = tx.send(batch);
            }
            (stats, r)
        }));
        children.push(child);
        receivers.push(rx);
    }
    let pids: Vec<u32> = children.iter().map(|c| c.id()).collect();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = {
        let done = done.clone();
        let timed_out = timed_out.clone();
        let limit = Duration::from_millis(timeout_ms);
        std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < limit {
                if done.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            timed_out.store(true, std::sync::atomic::Ordering::Relaxed);
            for pid in pids {
                if let Some(p) = rustix::process::Pid::from_raw(pid as i32) {
                    let _ = rustix::process::kill_process(p, rustix::process::Signal::KILL);
                }
            }
        })
    };
    let merged = merge_records(receivers, sink);
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut total = StreamStats::default();
    let mut first_err = None;
    for r in readers {
        match r.join() {
            Ok((st, res)) => {
                total.lines += st.lines;
                total.bytes += st.bytes;
                total.samples += st.samples;
                total.unparsed += st.unparsed;
                if let Err(e) = res
                    && first_err.is_none()
                {
                    first_err = Some(e);
                }
            }
            Err(_) => {
                if first_err.is_none() {
                    first_err = Some(Error::decode_failed("reader thread panicked"));
                }
            }
        }
    }
    for mut c in children {
        let _ = c.wait();
    }
    let _ = watchdog.join();
    let _ = std::fs::remove_dir_all(&split_dir);
    if timed_out.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(Error::limit(format!(
            "decode wall-clock limit {timeout_ms} ms exceeded across {} perf script streams",
            groups.len()
        ))
        .with_next("Capture less history or narrow the instruction window"));
    }
    merged?;
    if let Some(e) = first_err {
        return Err(e);
    }
    Ok(total)
}

/// `run_script_stream` with the decode wall-clock limit enforced: perf is
/// killed when the limit passes and the job fails with `LIMIT_EXCEEDED`.
fn run_script_stream_timed(
    perf: &Path,
    args: &[String],
    timeout_ms: u64,
    sink: impl FnMut(RawRecord) -> Result<()>,
) -> Result<StreamStats> {
    run_script_stream_inner(perf, args, Some(Duration::from_millis(timeout_ms)), sink)
}

/// Run `perf script` and stream its stdout through `sink` without buffering
/// the text. A nonzero exit with no records is a decode failure; stderr is
/// otherwise informational (perf prints error counts there).
fn run_script_stream(
    perf: &Path,
    args: &[String],
    sink: impl FnMut(RawRecord) -> Result<()>,
) -> Result<StreamStats> {
    run_script_stream_inner(perf, args, None, sink)
}

fn run_script_stream_inner(
    perf: &Path,
    args: &[String],
    timeout: Option<Duration>,
    sink: impl FnMut(RawRecord) -> Result<()>,
) -> Result<StreamStats> {
    let mut child = std::process::Command::new(perf)
        .env("LC_ALL", "C")
        .env("PERF_PAGER", "cat")
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::decode_failed("perf script stdout missing"))?;
    let mut stderr = child.stderr.take();
    // Drain stderr concurrently so a chatty perf cannot block on a full pipe.
    let err_reader = std::thread::spawn(move || {
        let mut err = Vec::new();
        if let Some(ref mut e) = stderr {
            let _ = std::io::Read::read_to_end(e, &mut err);
        }
        err
    });
    // Watchdog: kill perf when the decode limit passes; the reader then
    // sees EOF and the limit is reported rather than a partial decode.
    let child_pid = child.id();
    let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = timeout.map(|t| {
        let timed_out = timed_out.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < t {
                if done.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            timed_out.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(pid) = rustix::process::Pid::from_raw(child_pid as i32) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            }
        })
    });
    let mut stats = StreamStats::default();
    let streamed = stream_records(stdout, &mut stats, sink);
    let status = child.wait()?;
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(w) = watchdog {
        let _ = w.join();
    }
    let err = err_reader.join().unwrap_or_default();
    if timed_out.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(Error::limit(format!(
            "decode wall-clock limit {:?} exceeded after {} perf script lines",
            timeout.unwrap_or_default(),
            stats.lines
        ))
        .with_next("Capture less history (smaller aux_bytes_per_buffer / fewer cpus) or narrow the instruction window"));
    }
    if let Err(e) = streamed {
        let _ = status;
        return Err(e);
    }
    if !status.success() && stats.lines == 0 {
        return Err(Error::decode_failed(format!(
            "perf script failed ({status}): {}",
            String::from_utf8_lossy(&err).trim()
        )));
    }
    Ok(stats)
}

fn find_calls_origin(snap_dir: &Path) -> Option<crate::model::ClockOrigin> {
    let aid = find_calls_analysis(snap_dir)?;
    crate::store::read_json::<AnalysisManifest>(
        &snap_dir
            .join("derived")
            .join(aid.as_str())
            .join("manifest.json"),
    )
    .ok()
    .map(|am| am.origin)
}

fn handle_query_disk(root: &Path, req: QueryRequest, budget: usize) -> Result<serde_json::Value> {
    match &req.target {
        QueryTarget::Report { report_id } => query_report(root, report_id, &req, budget),
        QueryTarget::Snapshot {
            snapshot_id,
            analysis_id,
        } => query_snapshot(root, snapshot_id, analysis_id.as_ref(), &req, budget),
    }
}

fn query_snapshot(
    root: &Path,
    snapshot_id: &SnapshotId,
    analysis_id: Option<&AnalysisId>,
    req: &QueryRequest,
    budget: usize,
) -> Result<serde_json::Value> {
    if let QueryKind::Comparison = req.query {
        return Err(Error::invalid_argument(
            "comparison queries require a report target",
        ));
    }
    let snap_dir = root.join("snapshots").join(snapshot_id.as_str());
    let aid = match analysis_id {
        Some(a) => a.clone(),
        None => find_calls_analysis(&snap_dir)
            .ok_or_else(|| Error::new(ErrorCode::DetailNotReady, "calls analysis is not ready"))?,
    };
    let dir = snap_dir.join("derived").join(aid.as_str());
    let manifest: AnalysisManifest = crate::store::read_json(&dir.join("manifest.json"))?;
    if matches!(
        req.query,
        QueryKind::Instructions | QueryKind::Branches | QueryKind::InlineProfile
    ) && manifest.detail != DetailLevel::Instructions
    {
        return Err(Error::new(
            ErrorCode::DetailNotReady,
            "instructions/branches require the instruction analysis_id from trace_decode",
        ));
    }
    if let Some(sel) = &req.selection {
        sel.validate()?;
        if let (Some(cs), Some(ce), Some(ss), Some(se)) = (
            manifest.covered_start_ns,
            manifest.covered_end_ns,
            sel.start_ns,
            sel.end_ns,
        ) && (ss < cs || se > ce)
        {
            return Err(Error::invalid_argument(
                "selection is outside the analysis covered range",
            ));
        }
    }
    let sel = req.selection.clone().unwrap_or(Selection {
        thread_id: None,
        start_ns: None,
        end_ns: None,
    });
    let limit = req.row_limit()? as usize;
    let offset = parse_offset_cursor(req.cursor.as_deref())?;
    let quality = serde_json::json!({
        "timing": manifest.quality.timing,
        "gap_count": manifest.quality.gap_count,
    });

    let (data, next) = match &req.query {
        QueryKind::Summary => {
            let mut threads: Vec<crate::model::ThreadLifetime> =
                read_jsonl(&dir.join("threads.jsonl")).unwrap_or_default();
            let thread_total = threads.len();
            threads.sort_by(|a, b| b.branch_count.cmp(&a.branch_count).then(a.tid.cmp(&b.tid)));
            threads.truncate(MAX_SUMMARY_THREADS);
            let analyses: Vec<serde_json::Value> = list_analyses(&snap_dir);
            let rows = vec![serde_json::json!({
                "covered_start_ns": manifest.covered_start_ns,
                "covered_end_ns": manifest.covered_end_ns,
                "duration_estimate_ns": manifest.covered_end_ns.map(|e| e.saturating_sub(manifest.covered_start_ns.unwrap_or(0))),
                "quality": manifest.quality,
                "function_count": manifest.function_count,
                "span_count": manifest.span_count,
                "event_count": manifest.event_count,
                "sample_count": manifest.sample_count,
                "decode_wall_ms": manifest.decode_wall_ms,
                "trigger_hit_ns": manifest.trigger_hit_ns,
                "detail": manifest.detail,
                "thread_count": thread_total,
                "threads": threads.iter().map(|t| serde_json::json!({
                    "thread_id": t.id,
                    "pid": t.pid,
                    "tid": t.tid,
                    "comm": t.comm,
                    "start_ns": t.start.relative_ns,
                    "end_ns": t.end.as_ref().and_then(|e| e.relative_ns),
                    "branch_count": t.branch_count,
                    "event_count": t.event_count,
                    "span_count": t.span_count,
                    "gap_count": t.gap_count,
                    "covered_ns": t.covered_ns,
                    "segment_count": t.segment_count,
                    "segments": t.segments,
                })).collect::<Vec<_>>(),
                "analyses": analyses,
            })];
            let (page, next) = paginate(&rows, offset, limit);
            (serde_json::to_value(page).unwrap_or_default(), next)
        }
        QueryKind::Quality => (
            serde_json::to_value(&manifest.quality).unwrap_or_default(),
            None,
        ),
        QueryKind::Timeline {
            function_contains,
            min_duration_ns,
        } => {
            let spans: Vec<crate::model::FunctionSpan> = read_jsonl(&dir.join("spans.jsonl"))?;
            let fns: Vec<crate::model::FunctionRecord> = read_jsonl(&dir.join("functions.json"))?;
            let names: HashMap<u32, String> =
                fns.into_iter().map(|f| (f.id.0, f.demangled)).collect();
            let opts = TimelineOptions {
                function_contains: function_contains.clone(),
                min_duration_ns: *min_duration_ns,
            };
            let rows = timeline_rows_with(aid.as_str(), &spans, &names, &sel, &opts);
            let (mut page, next) = paginate(&rows, offset, limit);
            let mut resolver = InlineResolver::new(&snap_dir, &dir);
            for row in &mut page {
                if let Some(cs) = row.call_site {
                    row.call_site_inline = resolver.innermost(cs.0);
                }
            }
            (serde_json::to_value(page).unwrap_or_default(), next)
        }
        QueryKind::AtInstant { at_ns } => {
            let spans: Vec<crate::model::FunctionSpan> = read_jsonl(&dir.join("spans.jsonl"))?;
            let fns: Vec<crate::model::FunctionRecord> = read_jsonl(&dir.join("functions.json"))?;
            let names: HashMap<u32, String> =
                fns.into_iter().map(|f| (f.id.0, f.demangled)).collect();
            let mut resolver = InlineResolver::new(&snap_dir, &dir);
            let rows = at_instant_rows(aid.as_str(), &spans, &names, *at_ns, &sel, &mut resolver);
            let (page, next) = paginate(&rows, offset, limit);
            (serde_json::to_value(page).unwrap_or_default(), next)
        }
        QueryKind::InlineProfile => {
            if manifest.detail != DetailLevel::Instructions {
                return Err(Error::new(
                    ErrorCode::DetailNotReady,
                    "inline_profile needs the instruction analysis_id from trace_decode",
                ));
            }
            let insns: Vec<crate::model::InstructionRecord> =
                read_jsonl(&dir.join("instructions.jsonl"))?;
            let filtered: Vec<_> = insns
                .into_iter()
                .filter(|insn| insn_selected(insn, &sel))
                .collect();
            let rows = inline_profile_rows(&filtered);
            let (page, next) = paginate(&rows, offset, limit);
            (serde_json::to_value(page).unwrap_or_default(), next)
        }
        QueryKind::Hotpaths {
            function_contains,
            group,
            sort,
            max_depth,
        } => {
            let spans: Vec<crate::model::FunctionSpan> = read_jsonl(&dir.join("spans.jsonl"))?;
            let fns: Vec<crate::model::FunctionRecord> = read_jsonl(&dir.join("functions.json"))?;
            let names: HashMap<u32, String> =
                fns.into_iter().map(|f| (f.id.0, f.demangled)).collect();
            let opts = HotpathOptions {
                function_contains: function_contains.clone(),
                group: *group,
                sort: *sort,
                max_depth: max_depth.map(|d| d as usize),
            };
            let rows = if *group == crate::model::HotpathGroup::Inline {
                if sel.start_ns.is_some() || sel.end_ns.is_some() {
                    return Err(Error::invalid_argument(
                        "group inline aggregates a thread's whole history (instruction counts per inline chain carry no timestamps)",
                    )
                    .with_next("Drop start_ns/end_ns (keep thread_id), or use group path/function for a time window"));
                }
                let inl: Vec<crate::model::InlineRow> =
                    read_jsonl(&dir.join("inline.jsonl")).unwrap_or_default();
                if inl.is_empty() {
                    return Err(Error::new(
                        ErrorCode::DetailNotReady,
                        "no inline attribution in this analysis (decoded before inline support, or no archived images)",
                    )
                    .with_next("Re-run trace_decode with kind=calls"));
                }
                inline_rows(&inl, &names, &sel, &opts)
            } else {
                hotpaths_with(&spans, &names, &sel, &child_index(&spans), &opts)
            };
            let (page, next) = paginate(&rows, offset, limit);
            (serde_json::to_value(page).unwrap_or_default(), next)
        }
        QueryKind::Instructions => {
            let rows: Vec<crate::model::InstructionRecord> =
                read_jsonl(&dir.join("instructions.jsonl"))?;
            let filtered: Vec<_> = rows
                .into_iter()
                .filter(|insn| insn_selected(insn, &sel))
                .collect();
            let (page, next) = paginate(&filtered, offset, limit);
            (serde_json::to_value(page).unwrap_or_default(), next)
        }
        QueryKind::Images => {
            let snap_manifest: SnapshotManifest =
                crate::store::read_json(&snap_dir.join("manifest.json"))?;
            let rows: Vec<serde_json::Value> = snap_manifest
                .images
                .iter()
                .map(|i| {
                    serde_json::json!({
                        "path": i.path,
                        "content_hash": i.content_hash,
                        "build_id": i.build_id,
                        "archived": i.archived,
                        "missing": snap_manifest.missing_images.iter().any(|m| m.starts_with(&i.path)),
                    })
                })
                .collect();
            let (page, next) = paginate(&rows, offset, limit);
            (serde_json::to_value(page).unwrap_or_default(), next)
        }
        QueryKind::Branches => {
            let insns: Vec<crate::model::InstructionRecord> =
                read_jsonl(&dir.join("instructions.jsonl"))?;
            let filtered: Vec<_> = insns
                .into_iter()
                .filter(|insn| insn_selected(insn, &sel))
                .collect();
            let rows = aggregate_branches(&filtered);
            let (page, next) = paginate(&rows, offset, limit);
            (serde_json::to_value(page).unwrap_or_default(), next)
        }
        QueryKind::Source {
            location_id,
            function_id,
            evidence_id,
            address,
        } => {
            let locs: Vec<crate::model::CodeLocation> =
                read_jsonl(&dir.join("locations.json")).unwrap_or_default();
            let events: Vec<crate::model::FlowEvent> =
                read_jsonl(&dir.join("events.jsonl")).unwrap_or_default();
            let instructions: Vec<crate::model::InstructionRecord> =
                read_jsonl(&dir.join("instructions.jsonl")).unwrap_or_default();
            let spans: Vec<crate::model::FunctionSpan> =
                read_jsonl(&dir.join("spans.jsonl")).unwrap_or_default();
            let fns: Vec<crate::model::FunctionRecord> =
                read_jsonl(&dir.join("functions.json")).unwrap_or_default();
            let snap_manifest: SnapshotManifest =
                crate::store::read_json(&snap_dir.join("manifest.json"))?;
            let found = if let Some(a) = address {
                let ip = crate::model::parse_address(a)
                    .map_err(|e| Error::invalid_argument(format!("address {a}: {e}")))?;
                let mappings: Vec<crate::model::MappingRecord> =
                    read_jsonl(&dir.join("mappings.jsonl")).unwrap_or_default();
                let map = mappings
                    .iter()
                    .rev()
                    .find(|m| ip >= m.start.0 && ip < m.end.0)
                    .ok_or_else(|| {
                        Error::not_found(format!("no mapping covers address {a} in this analysis"))
                    })?;
                let img = snap_manifest
                    .images
                    .iter()
                    .find(|i| i.path == map.path)
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::MissingImage,
                            format!("mapping {} at {a} has no archived image", map.path),
                        )
                    })?;
                let archive = image_archive_path(&snap_dir, img);
                let bytes = std::fs::read(&archive)?;
                let index = crate::decode::images::ImageIndex::build(&bytes);
                let rel = index
                    .relative_addr(ip, map.start.0, map.pgoff)
                    .unwrap_or(ip.saturating_sub(map.start.0));
                let func = index.function(rel);
                let (file, line, inlined, note) = dwarf_frames(&archive, rel);
                Some(SourceInfo {
                    image_path: img.path.clone(),
                    image_id: img.content_hash.clone(),
                    image_offset: crate::model::Address(rel),
                    virt_ip: Some(crate::model::Address(ip)),
                    location_id: None,
                    function_id: None,
                    function: func.map(|f| f.demangled.clone()),
                    file,
                    line,
                    inlined,
                    note,
                })
            } else {
                resolve_source(
                    &locs,
                    &events,
                    &instructions,
                    &spans,
                    location_id.as_deref(),
                    function_id.as_deref(),
                    evidence_id.as_deref(),
                )
                .map(|loc| {
                    let img = snap_manifest
                        .images
                        .iter()
                        .find(|i| i.content_hash == loc.image_id);
                    let (file, line, inlined, note) = match img {
                        Some(i) => {
                            dwarf_frames(&image_archive_path(&snap_dir, i), loc.image_offset.0)
                        }
                        None => (
                            None,
                            None,
                            Vec::new(),
                            Some("image not archived; no DWARF available".into()),
                        ),
                    };
                    SourceInfo {
                        image_path: img
                            .map(|i| i.path.clone())
                            .unwrap_or_else(|| loc.image_id.clone()),
                        image_id: loc.image_id.clone(),
                        image_offset: loc.image_offset,
                        virt_ip: loc.virt_ip,
                        location_id: Some(format!("{aid}:l{}", loc.id.0)),
                        function_id: loc.function.map(|f| format!("{aid}:f{}", f.0)),
                        function: loc
                            .function
                            .and_then(|f| fns.iter().find(|r| r.id == f))
                            .map(|r| r.demangled.clone()),
                        file,
                        line,
                        inlined,
                        note,
                    }
                })
            };
            if found.is_none() {
                return Err(Error::not_found(
                    "no location matched; give location_id, function_id, evidence_id, or address",
                ));
            }
            (serde_json::to_value(found).unwrap_or_default(), None)
        }
        QueryKind::Comparison => unreachable!(),
    };

    let truncated = next.is_some();
    let hints = empty_result_hints(&req.query, &data, &sel, &dir);
    let envelope = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "analysis_id": aid,
        "selection": sel,
        "quality": quality,
        "data": data,
        "hints": hints,
        "next_cursor": next,
        "truncated": truncated
    });
    Ok(fit_json(envelope, budget, offset))
}

/// Explain an empty timeline/hotpaths page instead of returning `[]`.
fn empty_result_hints(
    query: &QueryKind,
    data: &serde_json::Value,
    sel: &Selection,
    dir: &Path,
) -> Vec<String> {
    let mut hints = Vec::new();
    if !matches!(
        query,
        QueryKind::Timeline { .. } | QueryKind::Hotpaths { .. }
    ) || data.as_array().is_some_and(|a| !a.is_empty())
    {
        return hints;
    }
    let threads: Vec<crate::model::ThreadLifetime> =
        read_jsonl(&dir.join("threads.jsonl")).unwrap_or_default();
    match &sel.thread_id {
        Some(t) => match threads.iter().find(|x| &x.id == t) {
            None => hints.push(format!(
                "thread {t} is not in this analysis; known threads: {}",
                threads
                    .iter()
                    .map(|x| format!("{} ({})", x.id, x.comm.clone().unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            Some(x) if x.span_count.0 == 0 => hints.push(format!(
                "thread {t} has {} branch samples but no function transfers (calls/returns) in its {:.3} ms of decoded history: it stayed inside one function, typically a spin loop. Use trace_decode with kind=instructions on one of its coverage segments to see the loop body.",
                x.branch_count.0,
                x.covered_ns.0 as f64 / 1e6
            )),
            Some(x) => hints.push(format!(
                "thread {t} has {} spans; the filter or time window matched none (coverage {:.3} ms in {} segments: {:?})",
                x.span_count.0,
                x.covered_ns.0 as f64 / 1e6,
                x.segment_count.0,
                x.segments.iter().take(4).collect::<Vec<_>>()
            )),
        },
        None => hints.push(
            "no spans matched; check the function filter (names are demangled Rust paths, inlined functions do not appear) and the time window".into(),
        ),
    }
    if let QueryKind::Timeline {
        function_contains: Some(f),
        ..
    }
    | QueryKind::Hotpaths {
        function_contains: Some(f),
        ..
    } = query
    {
        hints.push(format!(
            "no function name contains {f:?}; with LTO/opt-level=3 it may be inlined. Use query source with an address to see DWARF inline frames."
        ));
    }
    hints
}

fn query_report(
    root: &Path,
    report_id: &crate::model::ReportId,
    req: &QueryRequest,
    budget: usize,
) -> Result<serde_json::Value> {
    if !matches!(req.query, QueryKind::Comparison) {
        return Err(Error::invalid_argument(
            "report targets only support comparison queries",
        ));
    }
    let dir = root.join("reports").join(report_id.as_str());
    let meta: serde_json::Value = crate::store::read_json(&dir.join("manifest.json"))
        .unwrap_or_else(|_| serde_json::json!({}));
    let rows: Vec<crate::model::CompareRow> = read_jsonl(&dir.join("rows.jsonl"))?;
    let limit = req.row_limit()? as usize;
    let offset = parse_offset_cursor(req.cursor.as_deref())?;
    let (page, next) = paginate(&rows, offset, limit);
    let truncated = next.is_some();
    let envelope = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "report_id": report_id,
        "baseline_analysis_id": meta.get("baseline_analysis_id"),
        "candidate_analysis_id": meta.get("candidate_analysis_id"),
        "checks": meta.get("checks"),
        "comparable": meta.get("comparable"),
        "warnings": meta.get("warnings"),
        "quality": { "timing": "decoder_estimate", "gap_count": "0" },
        "data": page,
        "next_cursor": next,
        "truncated": truncated
    });
    Ok(fit_json(envelope, budget, offset))
}

fn insn_selected(insn: &crate::model::InstructionRecord, sel: &Selection) -> bool {
    if sel.thread_id.as_ref().is_some_and(|t| t != &insn.thread) {
        return false;
    }
    match (sel.start_ns, sel.end_ns, insn.time.relative_ns) {
        (None, None, _) => true,
        (_, _, None) => false,
        (_, _, Some(ns)) => sel.contains_instant(ns),
    }
}

fn decode_cache_key(
    snap: &SnapshotManifest,
    detail: DetailLevel,
    sel: Option<&Selection>,
    fast: bool,
    decoder: &str,
) -> String {
    let images = snap
        .images
        .iter()
        .map(|i| i.content_hash.as_str())
        .collect::<Vec<_>>()
        .join(",");
    cache_key(&[
        snap.snapshot_id.as_str(),
        &format!("{detail:?}{}", if fast { "-fast" } else { "" }),
        &serde_json::to_string(&sel).unwrap_or_default(),
        crate::decode::DIALECT,
        decoder,
        &IR_VERSION.to_string(),
        &images,
    ])
}

/// Which decoder a decode of this snapshot would use (part of the cache key
/// so perf-script and native analyses of one snapshot coexist).
fn decoder_kind(manifest: &SnapshotManifest, limits: &Limits) -> &'static str {
    if (limits.native_decoder || manifest.recorder.as_deref() == Some("direct"))
        && native_supported(manifest)
    {
        "native"
    } else {
        "perf"
    }
}

fn find_analysis_by_key(
    root: &Path,
    snap: &SnapshotId,
    key: &str,
) -> Option<(AnalysisId, Option<JobId>)> {
    let derived = root.join("snapshots").join(snap.as_str()).join("derived");
    for e in std::fs::read_dir(derived).ok()?.flatten() {
        let m = e.path().join("manifest.json");
        let Ok(am) = crate::store::read_json::<AnalysisManifest>(&m) else {
            continue;
        };
        if am.cache_key == key {
            let job = std::fs::read_dir(root.join("jobs")).ok().and_then(|rd| {
                rd.flatten().find_map(|f| {
                    let j: JobRecord = crate::store::read_json(&f.path()).ok()?;
                    (j.analysis_id.as_ref() == Some(&am.analysis_id)).then_some(j.job_id)
                })
            });
            return Some((am.analysis_id, job));
        }
    }
    None
}

/// Threads listed in `summary`, most active first; `thread_count` is exact.
const MAX_SUMMARY_THREADS: usize = 32;

/// Resolves virtual addresses of one analysis to the innermost DWARF inline
/// frame, caching loaders per image and results per address.
struct InlineResolver {
    mappings: Vec<crate::model::MappingRecord>,
    images: Vec<crate::model::ImageIdentity>,
    snap_dir: PathBuf,
    loaders: HashMap<String, Option<addr2line::Loader>>,
    indexes: HashMap<String, crate::decode::images::ImageIndex>,
    cache: HashMap<u64, Option<String>>,
}

impl InlineResolver {
    fn new(snap_dir: &Path, analysis_dir: &Path) -> Self {
        let mappings = read_jsonl(&analysis_dir.join("mappings.jsonl")).unwrap_or_default();
        let images = crate::store::read_json::<SnapshotManifest>(&snap_dir.join("manifest.json"))
            .map(|m| m.images)
            .unwrap_or_default();
        Self {
            mappings,
            images,
            snap_dir: snap_dir.to_path_buf(),
            loaders: HashMap::new(),
            indexes: HashMap::new(),
            cache: HashMap::new(),
        }
    }

    fn innermost(&mut self, ip: u64) -> Option<String> {
        if let Some(v) = self.cache.get(&ip) {
            return v.clone();
        }
        let v = self.lookup(ip);
        self.cache.insert(ip, v.clone());
        v
    }

    fn lookup(&mut self, ip: u64) -> Option<String> {
        let map = self
            .mappings
            .iter()
            .rev()
            .find(|m| ip >= m.start.0 && ip < m.end.0)?;
        let img = self.images.iter().find(|i| i.path == map.path)?.clone();
        let path = image_archive_path(&self.snap_dir, &img);
        let key = img.content_hash.clone();
        if !self.indexes.contains_key(&key) {
            let bytes = std::fs::read(&path).ok()?;
            self.indexes.insert(
                key.clone(),
                crate::decode::images::ImageIndex::build(&bytes),
            );
        }
        let rel = self.indexes[&key].relative_addr(ip, map.start.0, map.pgoff)?;
        let symbol = self.indexes[&key]
            .function(rel)
            .map(|f| f.demangled.clone());
        let loader = self
            .loaders
            .entry(key.clone())
            .or_insert_with(|| addr2line::Loader::new(&path).ok())
            .as_ref()?;
        let mut frames = loader.find_frames(rel).ok()?;
        let first = frames.next().ok()??;
        let name = first
            .function
            .as_ref()
            .and_then(|f| f.demangle().ok().map(|s| s.into_owned()))?;
        if symbol.as_deref() == Some(name.as_str()) {
            None
        } else {
            Some(name)
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct AtInstantRow {
    thread_id: crate::model::ThreadId,
    /// Outermost to innermost function names of spans open at the instant.
    stack: Vec<String>,
    innermost_span_id: String,
    innermost_start_ns: Option<u64>,
    innermost_end_ns: Option<u64>,
    innermost_completeness: crate::model::SpanCompleteness,
    #[serde(skip_serializing_if = "Option::is_none")]
    innermost_call_site_inline: Option<String>,
    /// How long the innermost frame had been open at the instant.
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_in_innermost_ns: Option<u64>,
}

/// Per thread, the deepest span open at `at_ns` and its ancestor chain.
fn at_instant_rows(
    analysis: &str,
    spans: &[crate::model::FunctionSpan],
    names: &HashMap<u32, String>,
    at_ns: u64,
    sel: &Selection,
    resolver: &mut InlineResolver,
) -> Vec<AtInstantRow> {
    let by_id: HashMap<u32, usize> = spans.iter().enumerate().map(|(i, s)| (s.id.0, i)).collect();
    let open_at = |s: &crate::model::FunctionSpan| {
        let starts = s.start.relative_ns.is_some_and(|st| st <= at_ns);
        let ends = match s.end.relative_ns {
            Some(e) => e > at_ns,
            None => true,
        };
        starts && ends
    };
    // Deepest open span per thread: the one with the most open ancestors.
    let mut best: HashMap<crate::model::ThreadId, (usize, usize)> = HashMap::new();
    for (i, sp) in spans.iter().enumerate() {
        if let Some(t) = &sel.thread_id
            && &sp.thread != t
        {
            continue;
        }
        if !open_at(sp) {
            continue;
        }
        let mut depth = 0;
        let mut cur = sp.parent;
        while let Some(p) = cur.and_then(|p| by_id.get(&p.0)).map(|&j| &spans[j]) {
            depth += 1;
            cur = p.parent;
            if depth > 64 {
                break;
            }
        }
        let e = best.entry(sp.thread.clone()).or_insert((i, depth));
        if depth > e.1 || (depth == e.1 && sp.start.relative_ns > spans[e.0].start.relative_ns) {
            *e = (i, depth);
        }
    }
    let name = |s: &crate::model::FunctionSpan| {
        s.function
            .and_then(|f| names.get(&f.0).cloned())
            .unwrap_or_else(|| "<unknown>".into())
    };
    let mut rows: Vec<AtInstantRow> = best
        .into_iter()
        .map(|(thread, (i, _))| {
            let sp = &spans[i];
            let mut chain = vec![name(sp)];
            let mut cur = sp.parent;
            while let Some(p) = cur.and_then(|p| by_id.get(&p.0)).map(|&j| &spans[j]) {
                chain.push(name(p));
                cur = p.parent;
                if chain.len() > 64 {
                    break;
                }
            }
            chain.reverse();
            AtInstantRow {
                thread_id: thread,
                stack: chain,
                innermost_span_id: format!("{analysis}:sp{}", sp.id.0),
                innermost_start_ns: sp.start.relative_ns,
                innermost_end_ns: sp.end.relative_ns,
                innermost_completeness: sp.completeness,
                innermost_call_site_inline: sp.call_site.and_then(|c| resolver.innermost(c.0)),
                elapsed_in_innermost_ns: sp.start.relative_ns.map(|st| at_ns.saturating_sub(st)),
            }
        })
        .collect();
    rows.sort_by(|a, b| a.thread_id.as_str().cmp(b.thread_id.as_str()));
    rows
}

#[derive(Debug, Clone, serde::Serialize)]
struct InlineProfileRow {
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    /// Innermost inlined function; `null` when the instruction belongs to
    /// the symbol's own body.
    #[serde(skip_serializing_if = "Option::is_none")]
    inlined: Option<String>,
    instructions: Count,
    /// Share of all instructions in the selection, six decimals.
    fraction: String,
    distinct_addresses: Count,
    first_address: crate::model::Address,
}

/// Executed-instruction counts per (symbol, innermost inlined function).
fn inline_profile_rows(insns: &[crate::model::InstructionRecord]) -> Vec<InlineProfileRow> {
    let total = insns.len().max(1) as f64;
    type Key = (Option<String>, Option<String>);
    type Agg = (u64, HashSet<u64>, u64);
    let mut agg: HashMap<Key, Agg> = HashMap::new();
    for insn in insns {
        let e = agg
            .entry((insn.symbol.clone(), insn.inlined.clone()))
            .or_insert((0, HashSet::new(), insn.virt_ip.0));
        e.0 += 1;
        e.1.insert(insn.virt_ip.0);
        e.2 = e.2.min(insn.virt_ip.0);
    }
    let mut rows: Vec<InlineProfileRow> = agg
        .into_iter()
        .map(|((symbol, inlined), (n, addrs, first))| InlineProfileRow {
            symbol,
            inlined,
            instructions: Count(n),
            fraction: format!("{:.6}", n as f64 / total),
            distinct_addresses: Count(addrs.len() as u64),
            first_address: crate::model::Address(first),
        })
        .collect();
    rows.sort_by(|a, b| {
        b.instructions
            .cmp(&a.instructions)
            .then(a.first_address.0.cmp(&b.first_address.0))
    });
    rows
}

/// Where an archived image's bytes live inside the snapshot bundle.
fn image_archive_path(snap_dir: &Path, img: &crate::model::ImageIdentity) -> PathBuf {
    snap_dir
        .join("images")
        .join(img.content_hash.trim_start_matches("sha256:"))
        .join(
            Path::new(&img.path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "image".into()),
        )
}

/// Every published analysis for a snapshot: id, detail, selection.
fn list_analyses(snap_dir: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(snap_dir.join("derived")) else {
        return out;
    };
    for e in rd.flatten() {
        if let Ok(am) = crate::store::read_json::<AnalysisManifest>(&e.path().join("manifest.json"))
        {
            out.push(serde_json::json!({
                "analysis_id": am.analysis_id,
                "detail": am.detail,
                "decode_mode": am.decode_mode,
                "selection": am.selection,
                "covered_start_ns": am.covered_start_ns,
                "covered_end_ns": am.covered_end_ns,
            }));
        }
    }
    out.sort_by(|a, b| a["analysis_id"].as_str().cmp(&b["analysis_id"].as_str()));
    out
}

/// The default calls analysis: highest IR version, then most recently
/// published. Deterministic regardless of directory order.
fn find_calls_analysis(snap_dir: &Path) -> Option<AnalysisId> {
    // Newest IR first, then a full decode over a fast one (a later fast
    // re-decode must not silently become everyone's default analysis),
    // then the newest file.
    let mut best: Option<(u32, bool, std::time::SystemTime, AnalysisId)> = None;
    for e in std::fs::read_dir(snap_dir.join("derived")).ok()?.flatten() {
        let m = e.path().join("manifest.json");
        if let Ok(am) = crate::store::read_json::<AnalysisManifest>(&m)
            && am.detail == DetailLevel::Calls
        {
            let mtime = std::fs::metadata(&m)
                .and_then(|md| md.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            let full = am.decode_mode == "full";
            let key = (am.ir_version, full, mtime, am.analysis_id);
            if best
                .as_ref()
                .is_none_or(|b| (key.0, key.1, key.2) > (b.0, b.1, b.2))
            {
                best = Some(key);
            }
        }
    }
    best.map(|b| b.3)
}

fn read_jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line).map_err(|e| Error::decode_failed(e.to_string()))?);
    }
    Ok(out)
}

fn compare_job(
    root: &Path,
    req: &CompareRequest,
    report_id: &crate::model::ReportId,
    cache_key_s: &str,
    job_id: &JobId,
) -> Result<()> {
    let b_dir = root
        .join("snapshots")
        .join(req.baseline.snapshot_id.as_str());
    let c_dir = root
        .join("snapshots")
        .join(req.candidate.snapshot_id.as_str());
    let b_aid = req
        .baseline
        .analysis_id
        .clone()
        .or_else(|| find_calls_analysis(&b_dir))
        .ok_or_else(|| Error::new(ErrorCode::DetailNotReady, "baseline analysis missing"))?;
    let c_aid = req
        .candidate
        .analysis_id
        .clone()
        .or_else(|| find_calls_analysis(&c_dir))
        .ok_or_else(|| Error::new(ErrorCode::DetailNotReady, "candidate analysis missing"))?;
    let b_spans: Vec<crate::model::FunctionSpan> = read_jsonl(
        &b_dir
            .join("derived")
            .join(b_aid.as_str())
            .join("spans.jsonl"),
    )?;
    let c_spans: Vec<crate::model::FunctionSpan> = read_jsonl(
        &c_dir
            .join("derived")
            .join(c_aid.as_str())
            .join("spans.jsonl"),
    )?;
    let b_fn: Vec<crate::model::FunctionRecord> = read_jsonl(
        &b_dir
            .join("derived")
            .join(b_aid.as_str())
            .join("functions.json"),
    )?;
    let c_fn: Vec<crate::model::FunctionRecord> = read_jsonl(
        &c_dir
            .join("derived")
            .join(c_aid.as_str())
            .join("functions.json"),
    )?;
    let b_names: HashMap<u32, String> = b_fn.into_iter().map(|f| (f.id.0, f.demangled)).collect();
    let c_names: HashMap<u32, String> = c_fn.into_iter().map(|f| (f.id.0, f.demangled)).collect();
    let bsel = req.baseline.selection.clone().unwrap_or(Selection {
        thread_id: None,
        start_ns: None,
        end_ns: None,
    });
    let csel = req.candidate.selection.clone().unwrap_or(Selection {
        thread_id: None,
        start_ns: None,
        end_ns: None,
    });
    let opts = HotpathOptions {
        function_contains: req.function_contains.clone(),
        group: req.group,
        ..HotpathOptions::default()
    };
    let inline_side =
        |dir: &Path, names: &HashMap<u32, String>, sel: &Selection| -> Result<Vec<HotpathRow>> {
            let inl: Vec<crate::model::InlineRow> =
                read_jsonl(&dir.join("inline.jsonl")).unwrap_or_default();
            if inl.is_empty() {
                return Err(Error::new(
                    ErrorCode::DetailNotReady,
                    format!("no inline attribution in {}", dir.display()),
                )
                .with_next("Re-run trace_decode with kind=calls on both snapshots"));
            }
            Ok(inline_rows(&inl, names, sel, &opts))
        };
    let (brows, crows) = if req.group == crate::model::HotpathGroup::Inline {
        (
            inline_side(&b_dir, &b_names, &bsel)?,
            inline_side(&c_dir, &c_names, &csel)?,
        )
    } else {
        (
            hotpaths_with(&b_spans, &b_names, &bsel, &child_index(&b_spans), &opts),
            hotpaths_with(&c_spans, &c_names, &csel, &child_index(&c_spans), &opts),
        )
    };
    let same_wl = match (&req.baseline.workload, &req.candidate.workload) {
        (Some(a), Some(b)) => {
            a.input_fingerprint.is_some() && a.input_fingerprint == b.input_fingerprint
        }
        _ => false,
    };
    let b_snap: SnapshotManifest = crate::store::read_json(&b_dir.join("manifest.json"))?;
    let c_snap: SnapshotManifest = crate::store::read_json(&c_dir.join("manifest.json"))?;
    let (cpu_ok, pt_ok) = cpu_pt_compat(&b_snap, &c_snap);
    let decoder_ok = match (
        crate::store::read_json::<AnalysisManifest>(
            &b_dir
                .join("derived")
                .join(b_aid.as_str())
                .join("manifest.json"),
        ),
        crate::store::read_json::<AnalysisManifest>(
            &c_dir
                .join("derived")
                .join(c_aid.as_str())
                .join("manifest.json"),
        ),
    ) {
        (Ok(b_am), Ok(c_am)) => decoder_compat(&b_am, &c_am),
        _ => false,
    };
    let mut report = compare_hotpaths(req, &brows, &crows, same_wl, cpu_ok, pt_ok, decoder_ok);
    report.baseline_analysis_id = Some(b_aid.to_string());
    report.candidate_analysis_id = Some(c_aid.to_string());
    if req.mode == crate::model::CompareMode::StrictPerformance && !report.comparable {
        return Err(Error::new(
            ErrorCode::Incomparable,
            report.warnings.join("; "),
        ));
    }
    let dest = root.join("reports").join(report_id.as_str());
    std::fs::create_dir_all(&dest)?;
    write_jsonl(&dest.join("rows.jsonl"), &report.rows)?;
    let mut manifest = serde_json::to_value(&report).unwrap_or_default();
    manifest["cache_key"] = serde_json::json!(cache_key_s);
    manifest["job_id"] = serde_json::json!(job_id);
    manifest["report_id"] = serde_json::json!(report_id);
    std::fs::write(
        dest.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )?;
    std::fs::write(
        dest.join("index.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "row_count": report.rows.len()
        }))
        .unwrap(),
    )?;
    Ok(())
}

pub fn wait_job(store: &Store, id: &JobId, timeout: Duration) -> Result<JobRecord> {
    let start = Instant::now();
    loop {
        if let Ok(j) = store.load_job(id)
            && matches!(
                j.phase,
                JobPhase::Succeeded | JobPhase::Failed | JobPhase::Cancelled
            )
        {
            if j.phase == JobPhase::Failed {
                return Err(Error::decode_failed(
                    j.error.unwrap_or_else(|| "job failed".into()),
                ));
            }
            return Ok(j);
        }
        if start.elapsed() > timeout {
            return Err(Error::new(ErrorCode::NotReady, "job wait timed out"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;
    use crate::model::{Address, EventRange, EventTime, FunctionSpan, LocalId, ThreadId};

    fn span(id: u32, parent: Option<u32>, s: u64, e: Option<u64>, f: u32) -> FunctionSpan {
        FunctionSpan {
            id: LocalId(id),
            thread: ThreadId::from_raw("t_1").unwrap(),
            function: Some(LocalId(f)),
            parent: parent.map(LocalId),
            start: EventTime::estimate(s),
            end: e
                .map(EventTime::estimate)
                .unwrap_or_else(EventTime::unknown),
            completeness: crate::model::SpanCompleteness::Complete,
            evidence: EventRange {
                start_id: LocalId(0),
                end_id: LocalId(0),
            },
            call_site: None,
        }
    }

    #[test]
    fn at_instant_picks_deepest_open_frame_and_chain() {
        let spans = vec![
            span(0, None, 0, Some(100), 1),
            span(1, Some(0), 10, Some(50), 2),
            span(2, Some(1), 20, Some(30), 3),
            span(3, Some(0), 60, None, 4),
        ];
        let names: HashMap<u32, String> = [(1, "main"), (2, "a"), (3, "b"), (4, "c")]
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        let dir = tempfile::tempdir().unwrap();
        let mut resolver = InlineResolver::new(dir.path(), dir.path());
        let sel = Selection {
            thread_id: None,
            start_ns: None,
            end_ns: None,
        };
        let rows = at_instant_rows("a", &spans, &names, 25, &sel, &mut resolver);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].stack, vec!["main", "a", "b"]);
        assert_eq!(rows[0].elapsed_in_innermost_ns, Some(5));
        let rows = at_instant_rows("a", &spans, &names, 70, &sel, &mut resolver);
        assert_eq!(rows[0].stack, vec!["main", "c"]);
        assert_eq!(rows[0].innermost_end_ns, None);
        // An open-ended frame (thread history ended) stays "open" later on;
        // its completeness tells the reader that the end is unknown.
        let rows = at_instant_rows("a", &spans, &names, 200, &sel, &mut resolver);
        assert_eq!(rows[0].stack, vec!["main", "c"]);
        assert_eq!(rows[0].innermost_end_ns, None);
    }

    #[test]
    fn merge_orders_by_time_and_keeps_sideband_from_stream_zero() {
        use crate::decode::perf_script::parse_line;
        let mk = |l: &str| parse_line(l).unwrap().unwrap();
        let (t0, r0) = std::sync::mpsc::sync_channel::<Batch>(8);
        let (t1, r1) = std::sync::mpsc::sync_channel::<Batch>(8);
        for l in [
            "1/1 [000] 1.0: PERF_RECORD_MMAP2 1/1: [0x10(0x100) @ 0]: r-xp /x",
            "1/1 [000] 1.000000010:  branches:u:  10 20  call",
            "1/1 [000] 1.000000030:  branches:u:  20 10  return",
        ] {
            let r = mk(l);
            let t = match &r {
                RawRecord::Sample(s) => s.time_ns,
                RawRecord::Mmap(m) => m.time_ns,
                _ => None,
            };
            t0.send(vec![(t, r)]).unwrap();
        }
        for l in [
            "1/1 [001] 1.0: PERF_RECORD_MMAP2 1/1: [0x10(0x100) @ 0]: r-xp /x",
            "1/2 [001] 1.000000020:  branches:u:  10 20  call",
            "1/2 [001] 1.000000030:  branches:u:  20 10  return",
        ] {
            let r = mk(l);
            let t = match &r {
                RawRecord::Sample(s) => s.time_ns,
                RawRecord::Mmap(m) => m.time_ns,
                _ => None,
            };
            t1.send(vec![(t, r)]).unwrap();
        }
        drop((t0, t1));
        let mut got = Vec::new();
        merge_records(vec![r0, r1], |rec| {
            got.push(rec);
            Ok(())
        })
        .unwrap();
        assert_eq!(got.len(), 5, "second mmap dropped");
        assert!(matches!(got[0], RawRecord::Mmap(_)));
        let times: Vec<u64> = got[1..]
            .iter()
            .map(|r| match r {
                RawRecord::Sample(s) => s.time_ns.unwrap(),
                _ => 0,
            })
            .collect();
        assert_eq!(
            times,
            vec![1_000_000_010, 1_000_000_020, 1_000_000_030, 1_000_000_030]
        );
        // Equal timestamps: stream 0 first.
        if let RawRecord::Sample(s) = &got[3] {
            assert_eq!(s.tid, 1);
        }
        assert_eq!(cpu_groups(&[4, 5, 6, 7], 8).len(), 4);
        assert_eq!(
            cpu_groups(&[1, 2, 3, 4, 5], 2),
            vec![vec![1, 3, 5], vec![2, 4]]
        );
    }

    #[test]
    fn inline_profile_groups_by_symbol_and_inline() {
        let mk = |ip: u64, sym: &str, inl: Option<&str>| crate::model::InstructionRecord {
            id: LocalId(0),
            thread: ThreadId::from_raw("t_1").unwrap(),
            sequence: 0,
            time: EventTime::unknown(),
            location: None,
            virt_ip: Address(ip),
            symbol: Some(sym.into()),
            inlined: inl.map(str::to_string),
            image_offset: None,
            len: 1,
            kind: crate::model::InsnKind::Sequential,
            branch_target: None,
            fallthrough: None,
            outcome: None,
            bytes_hex: String::new(),
        };
        let insns = vec![
            mk(0x10, "outer", Some("inner")),
            mk(0x11, "outer", Some("inner")),
            mk(0x12, "outer", Some("inner")),
            mk(0x20, "outer", None),
        ];
        let rows = inline_profile_rows(&insns);
        assert_eq!(rows[0].inlined.as_deref(), Some("inner"));
        assert_eq!(rows[0].instructions.0, 3);
        assert_eq!(rows[0].fraction, "0.750000");
        assert_eq!(rows[0].distinct_addresses.0, 3);
        assert_eq!(rows[1].inlined, None);
    }
}
