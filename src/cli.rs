use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

use crate::error::{Error, Result};
use crate::model::{
    CaptureReason, CompareMode, CompareRequest, CompareSide, IntelPtConfig, QueryKind,
    QueryRequest, QueryTarget, Selection, SnapshotId, Target, TimingProfile, WorkloadMeta,
};
use crate::service::{App, DecodeRequest, DetailSel, StartRequest, StatusSelect};
use crate::store::{Store, default_store_dir};

#[derive(Parser)]
#[command(
    version,
    name = "trace-mcp",
    about = "Intel Processor Trace execution debugger for coding agents",
    after_help = "Launch (`run`) owns the workload process group and terminates remaining owned processes when capture ends. Attach never signals the target."
)]
pub struct Cli {
    /// Evidence store directory (default: $XDG_STATE_HOME/trace-mcp)
    #[arg(long, global = true)]
    pub store: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Diagnose Intel PT, perf, and permission state. Never changes sysctls.
    Doctor {
        #[arg(long)]
        probe: bool,
        #[arg(long)]
        json: bool,
    },
    /// Launch a program, capture one PT snapshot, and decode it.
    Run {
        #[arg(long, value_enum, default_value = "balanced")]
        timing: TimingArg,
        #[arg(
            long,
            help = "Per-CPU AUX bytes (power of two). Omitted uses 4 MiB, auto-shrunk to fit the 128 MiB total budget"
        )]
        aux_bytes: Option<u64>,
        #[arg(long)]
        after_ms: Option<u64>,
        #[arg(long)]
        max_capture_ms: Option<u64>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        input_fingerprint: Option<String>,
        /// Record only these CPUs and pin the workload to them (e.g. `4-7` or `4,5,6,7`).
        /// Fewer AUX rings means more history per ring within the same budget.
        #[arg(long)]
        cpus: Option<String>,
        /// Extra environment for the workload, `KEY=VALUE`, repeatable
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Snapshot when this function (demangled path or unique substring) is hit
        #[arg(long)]
        trigger_symbol: Option<String>,
        /// Fire the symbol trigger on the N-th hit
        #[arg(long, default_value_t = 1)]
        trigger_hits: u32,
        /// Snapshot when the workload writes to $TRACE_MCP_TRIGGER
        #[arg(long)]
        trigger_fifo: bool,
        /// Keep recording this long after the trigger before snapshotting
        #[arg(long)]
        tail_ms: Option<u64>,
        /// Hardware address filter `kind:symbol[@image]` (kind: filter|tracestop|start|stop); repeatable
        #[arg(long = "address-filter")]
        address_filters: Vec<String>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Attach to a PID. Never terminates the target.
    Attach {
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        after_ms: Option<u64>,
        #[arg(long, value_enum, default_value = "balanced")]
        timing: TimingArg,
        #[arg(
            long,
            help = "Per-CPU AUX bytes (power of two). Omitted uses 4 MiB, auto-shrunk to fit the 128 MiB total budget"
        )]
        aux_bytes: Option<u64>,
        #[arg(long)]
        max_capture_ms: Option<u64>,
    },
    /// Decode a snapshot (calls, or instruction detail for one thread and window)
    Decode {
        snapshot_id: String,
        #[arg(long, value_enum, default_value = "calls")]
        detail: DetailArg,
        /// Calls detail: synthesize calls/returns only (faster, tail calls unobserved)
        #[arg(long)]
        fast: bool,
        #[arg(long)]
        thread_id: Option<String>,
        #[arg(long)]
        start_ns: Option<u64>,
        #[arg(long)]
        end_ns: Option<u64>,
    },
    /// Read a decoded snapshot or a comparison report
    Query {
        snapshot_id: Option<String>,
        #[arg(long, value_enum)]
        kind: QueryArg,
        #[arg(long)]
        analysis_id: Option<String>,
        #[arg(long)]
        report: Option<String>,
        #[arg(long)]
        thread_id: Option<String>,
        #[arg(long)]
        start_ns: Option<u64>,
        #[arg(long)]
        end_ns: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
        /// Timeline/hotpaths: keep rows whose function or path contains this text
        #[arg(long)]
        function: Option<String>,
        /// Hotpaths: `path` (caller chain) or `function` (one row per function)
        #[arg(long, value_enum, default_value = "path")]
        group: GroupArg,
        /// Hotpaths: `inclusive`, `self_time`, or `calls`
        #[arg(long, value_enum, default_value = "inclusive")]
        sort: SortArg,
        /// Hotpaths: innermost frames kept per path
        #[arg(long)]
        max_depth: Option<u32>,
        /// Timeline: drop spans shorter than this (and incomplete spans)
        #[arg(long)]
        min_duration_ns: Option<u64>,
        /// Source: virtual address to resolve (hex)
        #[arg(long)]
        address: Option<String>,
        /// Source: location/function/evidence id such as a_x:l3, a_x:f2, a_x:e7
        #[arg(long)]
        id: Option<String>,
        /// at_instant: snapshot-relative instant in ns
        #[arg(long)]
        at_ns: Option<u64>,
        #[arg(long)]
        json: bool,
    },
    /// Compare two snapshots function by function
    Compare {
        baseline_id: String,
        candidate_id: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        fingerprint: Option<String>,
        /// `path` (default) or `function`
        #[arg(long, value_enum, default_value = "path")]
        group: GroupArg,
        /// Keep only rows containing this text
        #[arg(long)]
        function: Option<String>,
    },
    /// Copy a snapshot directory into this store
    Import { bundle: PathBuf },
    /// List snapshot sizes and delete the given snapshot ids from the store
    Prune {
        /// Snapshot ids to delete; none lists sizes only
        snapshot_ids: Vec<String>,
    },
    /// Run the MCP server over stdio
    Serve {
        #[arg(long)]
        stdio: bool,
    },
    /// Internal launch shim: pin CPUs and/or supervise a symbol trigger, then run the workload.
    #[command(name = "__launch", hide = true)]
    Launch {
        #[arg(long)]
        cpus: Option<String>,
        #[arg(long)]
        symbol: Option<String>,
        #[arg(long, default_value_t = 1)]
        hits: u32,
        #[arg(long)]
        notify: Option<PathBuf>,
        /// Report thread/exit stops over this FIFO (direct recorder).
        #[arg(long)]
        report: Option<PathBuf>,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum TimingArg {
    #[value(name = "low_bandwidth")]
    LowBandwidth,
    Balanced,
    Detailed,
}

impl From<TimingArg> for TimingProfile {
    fn from(v: TimingArg) -> Self {
        match v {
            TimingArg::LowBandwidth => Self::LowBandwidth,
            TimingArg::Balanced => Self::Balanced,
            TimingArg::Detailed => Self::Detailed,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum DetailArg {
    Calls,
    Instructions,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum GroupArg {
    Path,
    Function,
    Inline,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum SortArg {
    Inclusive,
    #[value(name = "self_time")]
    SelfTime,
    Calls,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum QueryArg {
    Summary,
    Timeline,
    Hotpaths,
    Instructions,
    Branches,
    Images,
    Source,
    Quality,
    Comparison,
    InlineProfile,
    AtInstant,
}

pub async fn run(cli: Cli) -> Result<i32> {
    let store_dir = cli.store.unwrap_or_else(default_store_dir);
    // The launch shim is a child of a capture: it must not sweep the store
    // the parent is writing to.
    let sweep_store = !matches!(cli.cmd, Cmd::Launch { .. });
    if sweep_store {
        // SIGINT/SIGTERM (an agent host stopping the MCP server, Ctrl-C on
        // a capture): sweep before dying. The capture task's own teardown
        // of the workload happens on the normal path; this handler only makes
        // sure nothing of ours is left behind.
        let store_for_signal = store_dir.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = signal(SignalKind::terminate()).ok();
            let int = tokio::signal::ctrl_c();
            tokio::pin!(int);
            tokio::select! {
                _ = &mut int => {}
                _ = async {
                    match term.as_mut() {
                        Some(t) => { t.recv().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {}
            }
            crate::cleanup::on_exit(Some(&store_for_signal));
            std::process::exit(130);
        });
    }
    let result = run_cmd(cli.cmd, store_dir.clone()).await;
    crate::cleanup::on_exit(sweep_store.then_some(store_dir.as_path()));
    result
}

async fn run_cmd(cmd: Cmd, store_dir: PathBuf) -> Result<i32> {
    match cmd {
        Cmd::Doctor { probe, json } => {
            let report = crate::capture::doctor::run_doctor(probe, Some(&store_dir))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!("{}", crate::capture::doctor::doctor_summary(&report));
                for c in &report.checks {
                    println!("  [{:?}] {}: {}", c.status, c.name, c.reason);
                    if let Some(r) = &c.remedy
                        && !r.is_empty()
                    {
                        println!("           {r}");
                    }
                }
            }
            let bad = report
                .checks
                .iter()
                .any(|c| c.status != crate::capture::doctor::CheckStatus::Ok);
            Ok(if bad { 2 } else { 0 })
        }
        Cmd::Run {
            timing,
            aux_bytes,
            after_ms,
            max_capture_ms,
            label,
            input_fingerprint,
            cpus,
            trigger_symbol,
            trigger_hits,
            trigger_fifo,
            tail_ms,
            address_filters,
            argv,
            env,
        } => {
            let mut config = pt_config(timing, aux_bytes, max_capture_ms);
            config.cpus = cpus.as_deref().map(parse_cpu_list).transpose()?;
            config.address_filters = address_filters
                .iter()
                .map(|s| parse_address_filter(s))
                .collect::<Result<Vec<_>>>()?;
            let trigger = match (trigger_symbol, trigger_fifo) {
                (Some(symbol), _) => Some(crate::model::Trigger::Symbol {
                    symbol,
                    hits: trigger_hits.max(1),
                }),
                (None, true) => Some(crate::model::Trigger::Fifo),
                (None, false) => None,
            };
            run_capture(
                store_dir,
                Target::Launch {
                    argv,
                    cwd: None,
                    env: env
                        .iter()
                        .map(|kv| {
                            kv.split_once('=')
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .ok_or_else(|| {
                                    Error::invalid_argument(format!(
                                        "--env {kv}: expected KEY=VALUE"
                                    ))
                                })
                        })
                        .collect::<Result<_>>()?,
                },
                config,
                after_ms,
                WorkloadMeta {
                    label,
                    input_fingerprint,
                },
                trigger,
                tail_ms,
            )
            .await
        }
        Cmd::Attach {
            pid,
            after_ms,
            timing,
            aux_bytes,
            max_capture_ms,
        } => {
            let config = pt_config(timing, aux_bytes, max_capture_ms);
            run_capture(
                store_dir,
                Target::Attach { pid },
                config,
                after_ms,
                WorkloadMeta {
                    label: None,
                    input_fingerprint: None,
                },
                None,
                None,
            )
            .await
        }
        Cmd::Decode {
            snapshot_id,
            detail,
            fast,
            thread_id,
            start_ns,
            end_ns,
        } => {
            let store = Store::open(store_dir, crate::model::Limits::default())?;
            let (app, _h) = App::start(store);
            let snap = SnapshotId::from_raw(snapshot_id)?;
            let detail = match detail {
                DetailArg::Calls => DetailSel::Calls { fast },
                DetailArg::Instructions => DetailSel::Instructions {
                    selection: Selection {
                        thread_id: thread_id
                            .map(crate::model::ThreadId::from_raw)
                            .transpose()?,
                        start_ns,
                        end_ns,
                    },
                },
            };
            let d = app
                .decode(DecodeRequest {
                    snapshot_id: snap,
                    detail,
                })
                .await?;
            eprintln!("analysis_id={} cached={}", d.analysis_id, d.cached);
            if let Some(j) = d.job_id {
                eprintln!("job_id={j}");
                if !d.cached {
                    wait_decode_job(&app, &j).await;
                }
            }
            app.shutdown().await;
            Ok(0)
        }
        Cmd::Query {
            snapshot_id,
            kind,
            analysis_id,
            report,
            thread_id,
            start_ns,
            end_ns,
            cursor,
            limit,
            function,
            group,
            sort,
            max_depth,
            min_duration_ns,
            address,
            id,
            at_ns,
            json,
        } => {
            let store = Store::open(store_dir, crate::model::Limits::default())?;
            let (app, _h) = App::start(store);
            let target = if let Some(r) = report {
                QueryTarget::Report {
                    report_id: crate::model::ReportId::from_raw(r)?,
                }
            } else {
                QueryTarget::Snapshot {
                    snapshot_id: SnapshotId::from_raw(snapshot_id.ok_or_else(|| {
                        Error::invalid_argument("snapshot_id or --report is required")
                    })?)?,
                    analysis_id: analysis_id
                        .map(crate::model::AnalysisId::from_raw)
                        .transpose()?,
                }
            };
            let q = QueryRequest {
                target,
                query: match kind {
                    QueryArg::Summary => QueryKind::Summary,
                    QueryArg::Timeline => QueryKind::Timeline {
                        function_contains: function.clone(),
                        min_duration_ns,
                    },
                    QueryArg::Hotpaths => QueryKind::Hotpaths {
                        function_contains: function.clone(),
                        group: match group {
                            GroupArg::Path => crate::model::HotpathGroup::Path,
                            GroupArg::Function => crate::model::HotpathGroup::Function,
                            GroupArg::Inline => crate::model::HotpathGroup::Inline,
                        },
                        sort: match sort {
                            SortArg::Inclusive => crate::model::HotpathSort::Inclusive,
                            SortArg::SelfTime => crate::model::HotpathSort::SelfTime,
                            SortArg::Calls => crate::model::HotpathSort::Calls,
                        },
                        max_depth,
                    },
                    QueryArg::Instructions => QueryKind::Instructions,
                    QueryArg::Branches => QueryKind::Branches,
                    QueryArg::Images => QueryKind::Images,
                    QueryArg::Source => {
                        let id_kind = |tag: &str| {
                            id.as_deref()
                                .filter(|i| {
                                    i.rsplit_once(':').is_some_and(|(_, r)| r.starts_with(tag))
                                })
                                .map(str::to_string)
                        };
                        QueryKind::Source {
                            location_id: id_kind("l"),
                            function_id: id_kind("f"),
                            evidence_id: id.clone().filter(|i| {
                                i.rsplit_once(':')
                                    .is_some_and(|(_, r)| r.starts_with('e') || r.starts_with("sp"))
                            }),
                            address: address.clone(),
                        }
                    }
                    QueryArg::Quality => QueryKind::Quality,
                    QueryArg::Comparison => QueryKind::Comparison,
                    QueryArg::InlineProfile => QueryKind::InlineProfile,
                    QueryArg::AtInstant => QueryKind::AtInstant {
                        at_ns: at_ns.ok_or_else(|| {
                            Error::invalid_argument("at_instant requires --at-ns")
                        })?,
                    },
                },
                selection: Some(Selection {
                    thread_id: thread_id
                        .map(crate::model::ThreadId::from_raw)
                        .transpose()?,
                    start_ns,
                    end_ns,
                }),
                cursor,
                limit,
            };
            let page = app.query(q).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&page).unwrap());
            } else {
                print!("{}", render_page_text(&page));
            }
            app.shutdown().await;
            Ok(0)
        }
        Cmd::Compare {
            baseline_id,
            candidate_id,
            json,
            fingerprint,
            group,
            function,
        } => {
            let store = Store::open(store_dir.clone(), crate::model::Limits::default())?;
            let (app, _h) = App::start(store);
            let job = app
                .compare(CompareRequest {
                    baseline: CompareSide {
                        snapshot_id: SnapshotId::from_raw(baseline_id)?,
                        analysis_id: None,
                        selection: None,
                        workload: fingerprint.clone().map(|f| WorkloadMeta {
                            label: None,
                            input_fingerprint: Some(f),
                        }),
                    },
                    candidate: CompareSide {
                        snapshot_id: SnapshotId::from_raw(candidate_id)?,
                        analysis_id: None,
                        selection: None,
                        workload: fingerprint.clone().map(|f| WorkloadMeta {
                            label: None,
                            input_fingerprint: Some(f),
                        }),
                    },
                    mode: if fingerprint.is_some() {
                        CompareMode::StrictPerformance
                    } else {
                        CompareMode::Exploratory
                    },
                    function_pairs: Vec::new(),
                    group: match group {
                        GroupArg::Path => crate::model::HotpathGroup::Path,
                        GroupArg::Function => crate::model::HotpathGroup::Function,
                        GroupArg::Inline => crate::model::HotpathGroup::Inline,
                    },
                    function_contains: function.clone(),
                })
                .await?;
            eprintln!("job_id={job}");
            let deadline = tokio::time::Instant::now()
                + Duration::from_millis(crate::model::DEFAULT_DECODE_TIMEOUT_MS + 30_000);
            let mut report_id = None;
            while tokio::time::Instant::now() < deadline {
                if let Ok(st) = app.status(StatusSelect::Job { id: job.clone() }).await {
                    let phase = st.get("phase").and_then(|p| p.as_str()).unwrap_or("");
                    if phase == "succeeded" {
                        report_id = st
                            .get("report_id")
                            .and_then(|r| r.as_str())
                            .map(|s| s.to_string());
                        break;
                    }
                    if phase == "failed" || phase == "cancelled" {
                        eprintln!("compare {phase}: {st}");
                        app.shutdown().await;
                        return Ok(1);
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if let Some(rid) = report_id {
                eprintln!("report_id={rid}");
                let rid = crate::model::ReportId::from_raw(rid)?;
                let mut cursor = None;
                let mut rows = Vec::new();
                let mut envelope = serde_json::json!({});
                loop {
                    let page = app
                        .query(QueryRequest {
                            target: QueryTarget::Report {
                                report_id: rid.clone(),
                            },
                            query: QueryKind::Comparison,
                            selection: None,
                            cursor,
                            limit: Some(200),
                        })
                        .await?;
                    envelope = page.clone();
                    if let Some(arr) = page.get("data").and_then(|d| d.as_array()) {
                        rows.extend(arr.iter().cloned());
                    }
                    match page.get("next_cursor").and_then(|c| c.as_str()) {
                        Some(c) => cursor = Some(c.to_string()),
                        None => break,
                    }
                }
                envelope["data"] = serde_json::Value::Array(rows);
                envelope["next_cursor"] = serde_json::Value::Null;
                envelope["truncated"] = serde_json::Value::Bool(false);
                if json {
                    println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
                } else {
                    println!("{envelope}");
                }
            } else {
                eprintln!("compare job {job} timed out");
            }
            app.shutdown().await;
            Ok(0)
        }
        Cmd::Prune { snapshot_ids } => {
            let store = Store::open(store_dir, crate::model::Limits::default())?;
            let mut sizes = store.snapshot_sizes()?;
            sizes.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
            for id in &snapshot_ids {
                let id = crate::model::SnapshotId::from_raw(id.as_str())?;
                let bytes = store.remove_snapshot(&id)?;
                println!("removed {id} ({} MiB)", bytes >> 20);
            }
            for (id, bytes) in &sizes {
                if !snapshot_ids.iter().any(|s| s == id.as_str()) {
                    println!("{id} {} MiB", bytes >> 20);
                }
            }
            println!(
                "store uses {} of {} MiB",
                store.used_bytes()? >> 20,
                store.limits.store_budget >> 20
            );
            Ok(0)
        }
        Cmd::Import { bundle } => {
            let store = Store::open(store_dir, crate::model::Limits::default())?;
            let id = store.import_bundle(&bundle)?;
            println!("imported snapshot_id={id}");
            Ok(0)
        }
        Cmd::Serve { stdio } => {
            if !stdio {
                return Err(Error::invalid_argument("only --stdio is supported"));
            }
            crate::mcp::serve_stdio(store_dir).await?;
            Ok(0)
        }
        Cmd::Launch {
            cpus,
            symbol,
            hits,
            notify,
            report,
            argv,
        } => {
            let cpus = cpus.as_deref().map(parse_cpu_list).transpose()?;
            let trigger = symbol.map(|symbol| crate::capture::trigger::SymbolTrigger {
                symbol,
                image: None,
                hits: hits.max(1),
            });
            crate::capture::trigger::launch(
                cpus.as_deref(),
                trigger,
                notify.as_deref(),
                report.as_deref(),
                &argv,
            )
        }
    }
}

async fn run_capture(
    store_dir: PathBuf,
    target: Target,
    config: IntelPtConfig,
    after_ms: Option<u64>,
    workload: WorkloadMeta,
    trigger: Option<crate::model::Trigger>,
    tail_ms: Option<u64>,
) -> Result<i32> {
    let store = Store::open(store_dir, crate::model::Limits::default())?;
    let (app, _h) = App::start(store);
    let start = app
        .start_session(StartRequest {
            request_id: crate::model::RequestId::generate(),
            target,
            config: config.clone(),
            after_ms,
            workload: Some(workload),
            trigger,
            tail_ms,
        })
        .await?;
    eprintln!("session_id={}", start.session_id);
    let deadline = Duration::from_millis(config.max_capture_ms.saturating_add(15_000));
    let start_at = tokio::time::Instant::now();
    let mut snap = None;
    while start_at.elapsed() < deadline {
        let st = app
            .status(StatusSelect::Session {
                id: start.session_id.clone(),
            })
            .await?;
        let state = st.get("state").and_then(|s| s.as_str()).unwrap_or("");
        if state == "captured" || state == "finalizing" {
            if let Some(id) = st.get("snapshot_id").and_then(|s| s.as_str()) {
                snap = Some(id.to_string());
            }
            if state == "captured" {
                break;
            }
        }
        if state == "failed" || state == "cancelled" {
            app.shutdown().await;
            return Err(Error::new(
                crate::error::ErrorCode::Cancelled,
                format!("session {state}"),
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if snap.is_none() {
        let s = app
            .snapshot(start.session_id.clone(), CaptureReason::Stop)
            .await;
        match s {
            Ok(r) => {
                eprintln!("snapshot_id={}", r.snapshot_id);
                eprintln!("job_id={}", r.job_id);
                wait_decode_job(&app, &r.job_id).await;
            }
            Err(e) => eprintln!("snapshot: {e}"),
        }
    } else {
        let snap_id = snap.as_deref().unwrap();
        eprintln!("snapshot_id={snap_id}");
        if let Ok(st) = app
            .status(StatusSelect::Session {
                id: start.session_id.clone(),
            })
            .await
            && let Some(jid) = st.get("job_id").and_then(|s| s.as_str())
            && let Ok(job) = crate::model::JobId::from_raw(jid)
        {
            eprintln!("job_id={job}");
            wait_decode_job(&app, &job).await;
        }
    }
    app.shutdown().await;
    Ok(0)
}

async fn wait_decode_job(app: &App, job: &crate::model::JobId) {
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(crate::model::DEFAULT_DECODE_TIMEOUT_MS + 30_000);
    while tokio::time::Instant::now() < deadline {
        if let Ok(st) = app.status(StatusSelect::Job { id: job.clone() }).await {
            let phase = st.get("phase").and_then(|p| p.as_str()).unwrap_or("");
            if phase == "succeeded" {
                if let Some(a) = st.get("analysis_id") {
                    eprintln!("analysis_id={a}");
                }
                return;
            }
            if phase == "failed" || phase == "cancelled" {
                eprintln!("decode {phase}: {st}");
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!("decode job {job} timed out");
}

/// `filter:my_crate::hot[@/path/to/image]`.
pub fn parse_address_filter(s: &str) -> Result<crate::model::AddressFilter> {
    use crate::model::AddressFilterKind;
    let (kind, rest) = s.split_once(':').ok_or_else(|| {
        Error::invalid_argument(format!("address filter {s}: expected kind:symbol"))
    })?;
    let kind = match kind.trim() {
        "filter" => AddressFilterKind::Filter,
        "tracestop" => AddressFilterKind::Tracestop,
        "start" => AddressFilterKind::Start,
        "stop" => AddressFilterKind::Stop,
        other => {
            return Err(Error::invalid_argument(format!(
                "address filter kind {other}: use filter|tracestop|start|stop"
            )));
        }
    };
    let (symbol, image) = match rest.rsplit_once('@') {
        Some((sym, img)) => (sym.trim().to_string(), Some(img.trim().to_string())),
        None => (rest.trim().to_string(), None),
    };
    Ok(crate::model::AddressFilter {
        kind,
        symbol,
        image,
    })
}

/// `4-7`, `4,5,6,7`, or a mix.
pub fn parse_cpu_list(s: &str) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let a: u32 = a
                .trim()
                .parse()
                .map_err(|_| Error::invalid_argument(format!("bad cpu range {part}")))?;
            let b: u32 = b
                .trim()
                .parse()
                .map_err(|_| Error::invalid_argument(format!("bad cpu range {part}")))?;
            if b < a {
                return Err(Error::invalid_argument(format!("bad cpu range {part}")));
            }
            out.extend(a..=b);
        } else {
            out.push(
                part.parse()
                    .map_err(|_| Error::invalid_argument(format!("bad cpu {part}")))?,
            );
        }
    }
    Ok(out)
}

pub fn default_profiling_note() -> &'static str {
    "Build targets with [profile.profiling] (opt-level=3, debug=2, strip=false). Frame pointers are optional for Intel PT."
}

fn pt_config(
    timing: TimingArg,
    aux_bytes: Option<u64>,
    max_capture_ms: Option<u64>,
) -> IntelPtConfig {
    let def = IntelPtConfig::default();
    IntelPtConfig {
        timing: timing.into(),
        aux_bytes_per_buffer: aux_bytes,
        aux_bytes_auto: false,
        max_total_aux_bytes: def.max_total_aux_bytes,
        max_capture_ms: max_capture_ms.unwrap_or(def.max_capture_ms),
        cpus: None,
        address_filters: Vec::new(),
    }
}

/// Text rendering of a query page: the hints, then one line per row with
/// the row's scalar fields as `key=value` columns (nested values are
/// summarised), then the cursor. The same page the JSON mode prints.
pub fn render_page_text(page: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if let Some(kind) = page.get("kind").and_then(|k| k.as_str()) {
        let _ = writeln!(out, "kind: {kind}");
    }
    for key in ["analysis_id", "snapshot_id", "sort", "group"] {
        if let Some(v) = page.get(key).and_then(|v| v.as_str()) {
            let _ = writeln!(out, "{key}: {v}");
        }
    }
    if let Some(hints) = page.get("hints").and_then(|h| h.as_array()) {
        for h in hints {
            let _ = writeln!(out, "hint: {}", scalar(h));
        }
    }
    let rows = page
        .get("data")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    let _ = writeln!(out, "rows: {}", rows.len());
    for row in &rows {
        match row.as_object() {
            Some(obj) => {
                let cols: Vec<String> = obj
                    .iter()
                    .filter(|(_, v)| !v.is_null())
                    .map(|(k, v)| format!("{k}={}", scalar(v)))
                    .collect();
                let _ = writeln!(out, "  {}", cols.join("  "));
            }
            None => {
                let _ = writeln!(out, "  {}", scalar(row));
            }
        }
    }
    if let Some(c) = page.get("next_cursor").and_then(|c| c.as_str()) {
        let _ = writeln!(out, "next_cursor: {c}");
    }
    out
}

fn scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => format!("[{} items]", a.len()),
        serde_json::Value::Object(o) => {
            let inner: Vec<String> = o
                .iter()
                .filter(|(_, v)| v.is_string() || v.is_number() || v.is_boolean())
                .take(4)
                .map(|(k, v)| format!("{k}:{}", scalar(v)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        other => other.to_string(),
    }
}
