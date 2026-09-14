use std::path::PathBuf;
use std::time::Duration;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo};
use rmcp::service::ServiceExt;
use rmcp::{ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::model::{CaptureReason, CompareRequest, DEFAULT_MCP_RESULT_BUDGET, QueryRequest};
use crate::service::{App, DecodeRequest, PruneRequest, StartRequest, StatusSelect};
use crate::store::{LockMode, Store};

const INSTRUCTIONS: &str = r#"Check PT availability. Capture a reproducible target. Poll until ready.
Read summary and quality first; narrow to a thread, function, or time region.
Request instruction detail only for the narrowed region.
Distinguish observed execution from timing estimates and causal hypotheses.
Use source evidence to propose edits. Run correctness tests independently.
Capture a comparable candidate and inspect deltas and comparability warnings.
Do not claim complete coverage, population tail latency, cache misses, or
behavior preservation when the evidence does not establish them.
Launch targets are owned and will be terminated when capture ends. Attach never signals the target.
"#;

#[derive(Clone)]
pub struct TraceMcp {
    app: App,
    #[allow(dead_code)]
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorParams {
    #[serde(default)]
    pub probe: bool,
}

#[tool_router]
impl TraceMcp {
    fn new(app: App) -> Self {
        Self {
            app,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Diagnose Intel PT hardware, perf, and permissions. Does not change sysctls. Optional probe runs a short owned capture."
    )]
    async fn trace_doctor(&self, Parameters(p): Parameters<DoctorParams>) -> CallToolResult {
        match self.app.doctor(p.probe).await {
            Ok(r) => ok(&r, crate::capture::doctor::doctor_summary(&r)),
            Err(e) => err(&e),
        }
    }

    #[tool(
        description = "Start bounded Intel PT capture. Launch owns the workload and will terminate it when capture ends; attach never signals the target. after_ms is a wall-clock stop that dumps the current ring tail, not guaranteed coverage of the whole interval; max_capture_ms is the absolute hard cap, defaults to 30000, and is raised to after_ms/tail_ms. Returns a session id immediately; poll trace_status. Requires a caller request_id (same id and body is idempotent). Optional trigger {kind:symbol,symbol,hits} snapshots on the N-th call to a real, non-inlined symbol; set max_capture_ms above the expected hit time plus tail_ms, because the tail is clipped by after_ms/max_capture_ms. {kind:fifo} lets the workload write $TRACE_MCP_TRIGGER. config.cpus pins the launch but does not enlarge the direct recorder's default 32 MiB/thread ring; set config.aux_bytes_per_buffer for more history."
    )]
    async fn trace_start(&self, Parameters(p): Parameters<StartRequest>) -> CallToolResult {
        match self.app.start_session(p).await {
            Ok(r) => ok(
                &r,
                format!(
                    "session {} {}",
                    r.session_id,
                    serde_json::to_value(r.state)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default()
                ),
            ),
            Err(e) => err(&e),
        }
    }

    #[tool(description = "Poll session, job, snapshot, or list sessions (newest first).")]
    async fn trace_status(&self, Parameters(p): Parameters<StatusParams>) -> CallToolResult {
        match p.into_select() {
            Ok(sel) => match self.app.status(sel).await {
                Ok(r) => {
                    let summary = status_summary(&r);
                    ok(&r, summary)
                }
                Err(e) => err(&e),
            },
            Err(e) => err(&e),
        }
    }

    #[tool(
        description = "Finalize the one snapshot for a session (reason snapshot). Repeated calls return the same IDs."
    )]
    async fn trace_snapshot(&self, Parameters(p): Parameters<IdParam>) -> CallToolResult {
        match crate::model::SessionId::from_raw(&p.id) {
            Ok(id) => match self.app.snapshot(id, CaptureReason::Snapshot).await {
                Ok(r) => ok(&r, format!("snapshot {} job {}", r.snapshot_id, r.job_id)),
                Err(e) => err(&e),
            },
            Err(e) => err(&e),
        }
    }

    #[tool(
        description = "Graceful completion with reason stop. Same artifact semantics as trace_snapshot."
    )]
    async fn trace_stop(&self, Parameters(p): Parameters<IdParam>) -> CallToolResult {
        match crate::model::SessionId::from_raw(&p.id) {
            Ok(id) => match self.app.snapshot(id, CaptureReason::Stop).await {
                Ok(r) => ok(
                    &r,
                    format!("stop snapshot {} job {}", r.snapshot_id, r.job_id),
                ),
                Err(e) => err(&e),
            },
            Err(e) => err(&e),
        }
    }

    #[tool(
        description = "Cancel a session or job. Idempotent. Does not delete a published snapshot."
    )]
    async fn trace_cancel(&self, Parameters(p): Parameters<CancelParams>) -> CallToolResult {
        match p.into_target() {
            Ok(t) => match self.app.cancel(t).await {
                Ok(r) => ok(&r, r.to_string()),
                Err(e) => err(&e),
            },
            Err(e) => err(&e),
        }
    }

    #[tool(
        description = "List snapshot sizes and delete the ones named in snapshot_ids (their raw capture, images and analyses). Snapshots with a queued or running job are skipped. list_only reports sizes without deleting. Use it when trace_start fails with LIMIT_EXCEEDED on the store budget."
    )]
    async fn trace_prune(&self, Parameters(p): Parameters<PruneRequest>) -> CallToolResult {
        match self.app.prune(p).await {
            Ok(r) => {
                let removed = r
                    .get("removed")
                    .and_then(|v| v.as_array())
                    .map_or(0, |a| a.len());
                let used = r.get("used_bytes").and_then(|v| v.as_u64()).unwrap_or(0) >> 20;
                let budget = r.get("budget_bytes").and_then(|v| v.as_u64()).unwrap_or(0) >> 20;
                ok(
                    &r,
                    format!("removed {removed} snapshots; store uses {used} of {budget} MiB"),
                )
            }
            Err(e) => err(&e),
        }
    }

    #[tool(
        description = "Decode a snapshot. Calls detail is automatic after capture; {kind:calls,fast:true} re-decodes calls/returns only (5x faster on big captures, tail calls unobserved). Instructions detail requires a thread_id and a bounded start_ns/end_ns (tens of microseconds; ~20 s per pass). Returns an analysis_id and, unless cached, a job id to poll."
    )]
    async fn trace_decode(&self, Parameters(p): Parameters<DecodeRequest>) -> CallToolResult {
        match self.app.decode(p).await {
            Ok(r) => ok(
                &r,
                format!("analysis {} cached={}", r.analysis_id, r.cached),
            ),
            Err(e) => err(&e),
        }
    }

    #[tool(
        description = "Query snapshot or report evidence. Bounded page; poll when DETAIL_NOT_READY."
    )]
    async fn trace_query(&self, Parameters(p): Parameters<QueryRequest>) -> CallToolResult {
        match self.app.query(p).await {
            Ok(r) => ok(&r, "evidence page".into()),
            Err(e) => err(&e),
        }
    }

    #[tool(
        description = "Compare two snapshot regions by hotpath (group:path), function, or inline chain. Optional function_contains filters rows; inline max_depth defaults to 3 and 0 keeps full chains. Strict mode needs matching workload fingerprints. Returns a comparison job id; read rows with trace_query on the report."
    )]
    async fn trace_compare(&self, Parameters(p): Parameters<CompareRequest>) -> CallToolResult {
        match self.app.compare(p).await {
            // An object like every other tool result, not a bare string.
            Ok(r) => ok(&serde_json::json!({ "job_id": r }), format!("job {r}")),
            Err(e) => err(&e),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct IdParam {
    id: String,
}

/// Object-shaped MCP input. Internally tagged enums are not valid MCP root schemas.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct StatusParams {
    /// `session`, `job`, `snapshot`, or `sessions`
    kind: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

impl StatusParams {
    fn into_select(self) -> crate::error::Result<StatusSelect> {
        match self.kind.as_str() {
            "session" => {
                Ok(StatusSelect::Session {
                    id: crate::model::SessionId::from_raw(self.id.ok_or_else(|| {
                        Error::invalid_argument("status kind=session requires id")
                    })?)?,
                })
            }
            "job" => Ok(StatusSelect::Job {
                id: crate::model::JobId::from_raw(
                    self.id
                        .ok_or_else(|| Error::invalid_argument("status kind=job requires id"))?,
                )?,
            }),
            "snapshot" => {
                Ok(StatusSelect::Snapshot {
                    id: crate::model::SnapshotId::from_raw(self.id.ok_or_else(|| {
                        Error::invalid_argument("status kind=snapshot requires id")
                    })?)?,
                })
            }
            "sessions" => Ok(StatusSelect::Sessions {
                cursor: self.cursor,
                limit: self.limit,
            }),
            other => Err(Error::invalid_argument(format!(
                "unknown status kind {other}"
            ))),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct CancelParams {
    /// `session` or `job`
    kind: String,
    id: String,
}

impl CancelParams {
    fn into_target(self) -> crate::error::Result<crate::service::CancelTarget> {
        match self.kind.as_str() {
            "session" => Ok(crate::service::CancelTarget::Session {
                id: crate::model::SessionId::from_raw(self.id)?,
            }),
            "job" => Ok(crate::service::CancelTarget::Job {
                id: crate::model::JobId::from_raw(self.id)?,
            }),
            other => Err(Error::invalid_argument(format!(
                "unknown cancel kind {other}"
            ))),
        }
    }
}

#[tool_handler]
impl ServerHandler for TraceMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

/// Short text for a status result; the full object is in structuredContent.
fn status_summary(v: &serde_json::Value) -> String {
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("");
    if v.get("kind").and_then(|k| k.as_str()) == Some("sessions") {
        let n = v
            .get("data")
            .and_then(|d| d.as_array())
            .map_or(0, |a| a.len());
        return format!("{n} sessions");
    }
    if !get("session_id").is_empty() {
        let mut s = format!("session {} {}", get("session_id"), get("state"));
        if !get("snapshot_id").is_empty() {
            s.push_str(&format!(" snapshot {}", get("snapshot_id")));
        }
        if !get("job_id").is_empty() {
            s.push_str(&format!(" job {}", get("job_id")));
        }
        return s;
    }
    if !get("job_id").is_empty() {
        let mut s = format!("job {} {} {}", get("job_id"), get("kind"), get("phase"));
        if !get("analysis_id").is_empty() {
            s.push_str(&format!(" analysis {}", get("analysis_id")));
        }
        if !get("report_id").is_empty() {
            s.push_str(&format!(" report {}", get("report_id")));
        }
        if !get("error").is_empty() {
            s.push_str(&format!(": {}", get("error")));
        }
        return s;
    }
    if !get("snapshot_id").is_empty() {
        return format!(
            "snapshot {} {} reason {}",
            get("snapshot_id"),
            get("lifecycle"),
            get("capture_reason")
        );
    }
    "status".into()
}

fn ok<T: Serialize>(value: &T, summary: String) -> CallToolResult {
    let structured = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    let structured = crate::analysis::fit_json(structured, DEFAULT_MCP_RESULT_BUDGET, 0);
    let mut result = CallToolResult::success(vec![ContentBlock::text(summary)]);
    result.structured_content = Some(structured);
    result
}

fn err(e: &Error) -> CallToolResult {
    let structured = serde_json::json!({
        "code": e.code,
        "reason": e.reason,
        "next_action": e.next_action,
    });
    let mut result = CallToolResult::error(vec![ContentBlock::text(e.to_string())]);
    result.structured_content = Some(structured);
    result
}

pub async fn serve_stdio(store_dir: PathBuf) -> crate::error::Result<()> {
    serve_stdio_with_wait(store_dir, Duration::from_millis(2_000)).await
}

pub async fn serve_stdio_with_wait(
    store_dir: PathBuf,
    store_wait: Duration,
) -> crate::error::Result<()> {
    let store = Store::open_with(
        store_dir,
        crate::model::Limits::default(),
        LockMode::Exclusive,
        store_wait,
    )?;
    let (app, handle) = App::start(store);
    let server = TraceMcp::new(app.clone());
    let running = server.serve(rmcp::transport::stdio()).await.map_err(|e| {
        crate::error::Error::new(crate::error::ErrorCode::DecodeFailed, e.to_string())
    })?;
    let _ = running.waiting().await;
    app.shutdown().await;
    let _ = handle.await;
    Ok(())
}
