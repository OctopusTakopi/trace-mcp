use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

use crate::error::{Error, Result};
use crate::model::{
    CaptureReason, CompareMode, CompareRequest, CompareSide, IntelPtConfig, QueryKind,
    QueryRequest, QueryTarget, Selection, SnapshotId, Target, TimingProfile, WorkloadMeta,
};
use crate::service::{App, DecodeRequest, DetailSel, StartRequest, StatusSelect};
use crate::store::{LockMode, Store, default_store_dir};

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
    /// Wait this long for the evidence-store lock (0 fails immediately).
    #[arg(long, global = true, default_value_t = 2_000)]
    pub store_wait_ms: u64,
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
            help = "AUX bytes per ring (power of two): per-thread direct, per-CPU perf; default direct ring is 32 MiB"
        )]
        aux_bytes: Option<u64>,
        /// Stop after this many milliseconds of wall time and dump the PT ring tail.
        #[arg(long)]
        after_ms: Option<u64>,
        /// Hard capture cap in milliseconds (default 30000; raised to after-ms/tail-ms).
        #[arg(long)]
        max_capture_ms: Option<u64>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        input_fingerprint: Option<String>,
        /// Pin the workload to these CPUs (e.g. `4-7`). Direct recording still uses 32 MiB/thread.
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
        /// Requested post-trigger recording time, clipped by after-ms/max-capture-ms
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
        /// Stop after this many milliseconds of wall time and dump the PT ring tail.
        #[arg(long)]
        after_ms: Option<u64>,
        #[arg(long, value_enum, default_value = "balanced")]
        timing: TimingArg,
        #[arg(
            long,
            help = "AUX bytes per ring (power of two): per-thread direct, per-CPU perf; default direct ring is 32 MiB"
        )]
        aux_bytes: Option<u64>,
        /// Hard capture cap in milliseconds (default 30000; raised to after-ms).
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
        /// Decimal offset returned as next_cursor (for example, --cursor 40).
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
        /// Timeline/hotpaths: keep rows whose function or path contains this text
        #[arg(long)]
        function: Option<String>,
        /// Hotpaths: `path` (caller chain), `function` (one row/function), or `inline`
        #[arg(long, value_enum, default_value = "path")]
        group: GroupArg,
        /// Hotpaths: `inclusive`, `self_time`, or `calls`
        #[arg(long, value_enum, default_value = "inclusive")]
        sort: SortArg,
        /// Hotpaths: innermost frames kept (inline default 3; 0 is unlimited)
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
        /// Output format. Table is specialized for hotpaths.
        #[arg(long, value_enum)]
        format: Option<OutputFormatArg>,
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
        /// `path` (default), `function`, or `inline`
        #[arg(long, value_enum, default_value = "path")]
        group: GroupArg,
        /// Keep only rows containing this text
        #[arg(long)]
        function: Option<String>,
        /// Innermost frames kept (inline default 3; 0 is unlimited)
        #[arg(long)]
        max_depth: Option<u32>,
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
    #[value(alias = "inlined")]
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
pub enum OutputFormatArg {
    Text,
    Table,
    Csv,
    Json,
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
    let store_wait = Duration::from_millis(cli.store_wait_ms);
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
    let result = run_cmd(cli.cmd, store_dir.clone(), store_wait).await;
    crate::cleanup::on_exit(sweep_store.then_some(store_dir.as_path()));
    result
}

async fn run_cmd(cmd: Cmd, store_dir: PathBuf, store_wait: Duration) -> Result<i32> {
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
            let mut config = pt_config(timing, aux_bytes, max_capture_ms, after_ms, tail_ms);
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
                store_wait,
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
            let config = pt_config(timing, aux_bytes, max_capture_ms, after_ms, None);
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
                store_wait,
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
            let store = Store::open_with(
                store_dir,
                crate::model::Limits::default(),
                LockMode::Exclusive,
                store_wait,
            )?;
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
            format,
            json,
        } => {
            let store = Store::open_with(
                store_dir,
                crate::model::Limits::default(),
                LockMode::Shared,
                store_wait,
            )?;
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
            let page = crate::service::query_store(&store, q)?;
            match if json {
                OutputFormatArg::Json
            } else {
                format.unwrap_or(OutputFormatArg::Text)
            } {
                OutputFormatArg::Json => {
                    println!("{}", serde_json::to_string_pretty(&page).unwrap())
                }
                OutputFormatArg::Text => print!("{}", render_page_text(&page)),
                OutputFormatArg::Table => print!("{}", render_page_table(&page)),
                OutputFormatArg::Csv => print!("{}", render_page_csv(&page)),
            }
            Ok(0)
        }
        Cmd::Compare {
            baseline_id,
            candidate_id,
            json,
            fingerprint,
            group,
            function,
            max_depth,
        } => {
            let store = Store::open_with(
                store_dir.clone(),
                crate::model::Limits::default(),
                LockMode::Exclusive,
                store_wait,
            )?;
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
                    max_depth,
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
            let store = Store::open_with(
                store_dir,
                crate::model::Limits::default(),
                LockMode::Exclusive,
                store_wait,
            )?;
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
            let store = Store::open_with(
                store_dir,
                crate::model::Limits::default(),
                LockMode::Exclusive,
                store_wait,
            )?;
            let id = store.import_bundle(&bundle)?;
            println!("imported snapshot_id={id}");
            Ok(0)
        }
        Cmd::Serve { stdio } => {
            if !stdio {
                return Err(Error::invalid_argument("only --stdio is supported"));
            }
            crate::mcp::serve_stdio_with_wait(store_dir, store_wait).await?;
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
    store_wait: Duration,
) -> Result<i32> {
    let store = Store::open_with(
        store_dir,
        crate::model::Limits::default(),
        LockMode::Exclusive,
        store_wait,
    )?;
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
                if let Some(aid) = wait_decode_job(&app, &r.job_id).await {
                    print_coverage_summary(&app, &r.snapshot_id, &aid, after_ms).await;
                }
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
            if let Some(aid) = wait_decode_job(&app, &job).await
                && let Ok(snapshot_id) = SnapshotId::from_raw(snap_id)
            {
                print_coverage_summary(&app, &snapshot_id, &aid, after_ms).await;
            }
        }
    }
    app.shutdown().await;
    Ok(0)
}

async fn wait_decode_job(app: &App, job: &crate::model::JobId) -> Option<crate::model::AnalysisId> {
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(crate::model::DEFAULT_DECODE_TIMEOUT_MS + 30_000);
    while tokio::time::Instant::now() < deadline {
        if let Ok(st) = app.status(StatusSelect::Job { id: job.clone() }).await {
            let phase = st.get("phase").and_then(|p| p.as_str()).unwrap_or("");
            if phase == "succeeded" {
                if let Some(a) = st.get("analysis_id").and_then(|a| a.as_str()) {
                    eprintln!("analysis_id={a}");
                    return crate::model::AnalysisId::from_raw(a).ok();
                }
                return None;
            }
            if phase == "failed" || phase == "cancelled" {
                eprintln!("decode {phase}: {st}");
                return None;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!("decode job {job} timed out");
    None
}

async fn print_coverage_summary(
    app: &App,
    snapshot_id: &SnapshotId,
    analysis_id: &crate::model::AnalysisId,
    after_ms: Option<u64>,
) {
    let page = app
        .query(QueryRequest {
            target: QueryTarget::Snapshot {
                snapshot_id: snapshot_id.clone(),
                analysis_id: Some(analysis_id.clone()),
            },
            query: QueryKind::Summary,
            selection: None,
            cursor: None,
            limit: Some(1),
        })
        .await;
    let status = app
        .status(StatusSelect::Snapshot {
            id: snapshot_id.clone(),
        })
        .await;
    let (Ok(page), Ok(status)) = (page, status) else {
        return;
    };
    if let Some(summary) = coverage_summary_text(&page, &status, after_ms) {
        eprintln!("{summary}");
    }
}

fn coverage_summary_text(
    page: &serde_json::Value,
    status: &serde_json::Value,
    after_ms: Option<u64>,
) -> Option<String> {
    let Some(row) = page
        .get("data")
        .and_then(|d| d.as_array())
        .and_then(|a| a.first())
    else {
        return None;
    };
    let threads = row
        .get("threads")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let covered_ns = threads
        .iter()
        .filter_map(|t| t.get("covered_ns").and_then(value_u64))
        .max()
        .unwrap_or(0);
    let covered_ns = row
        .get("max_thread_covered_ns")
        .and_then(value_u64)
        .unwrap_or(covered_ns);
    let thread_count = row
        .get("thread_count")
        .and_then(value_u64)
        .unwrap_or(threads.len() as u64);
    let requested: Option<IntelPtConfig> = status
        .get("requested_config")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok());
    let aux = requested
        .as_ref()
        .and_then(|c| c.aux_bytes_per_buffer)
        .or_else(|| {
            (status.get("recorder").and_then(|v| v.as_str()) == Some("direct"))
                .then_some(crate::model::DEFAULT_DIRECT_AUX_BYTES)
        });
    let mut fields = vec![format!("covered {:.3}ms", covered_ns as f64 / 1e6)];
    if let Some(ms) = after_ms {
        fields.push(format!("of after_ms={ms}"));
    }
    if let Some(bytes) = aux {
        fields.push(format!("aux={}MiB/thread", bytes >> 20));
    }
    fields.push(format!("threads={thread_count}"));
    if thread_count != threads.len() as u64 {
        fields.push(format!("shown_threads={}", threads.len()));
    }
    fields.extend(threads.iter().filter_map(|t| {
        Some(format!(
            "{}={:.3}ms",
            t.get("thread_id")?.as_str()?,
            value_u64(t.get("covered_ns")?)? as f64 / 1e6
        ))
    }));
    Some(fields.join("  "))
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
    after_ms: Option<u64>,
    tail_ms: Option<u64>,
) -> IntelPtConfig {
    let def = IntelPtConfig::default();
    IntelPtConfig {
        timing: timing.into(),
        aux_bytes_per_buffer: aux_bytes,
        aux_bytes_auto: false,
        max_total_aux_bytes: def.max_total_aux_bytes,
        max_capture_ms: max_capture_ms
            .unwrap_or(def.max_capture_ms)
            .max(after_ms.unwrap_or(0))
            .max(tail_ms.unwrap_or(0)),
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
    let rows = page_rows(page);
    let _ = writeln!(out, "rows: {}", rows.len());
    let columns = row_columns(page, &rows);
    for row in &rows {
        match row.as_object() {
            Some(obj) => {
                let cols: Vec<String> = columns
                    .iter()
                    .filter_map(|k| obj.get(k).filter(|v| !v.is_null()).map(|v| (k, v)))
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

pub fn render_page_csv(page: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    let rows = page_rows(page);
    let mut columns = row_columns(page, &rows);
    let cursor_pos = columns
        .iter()
        .position(|c| c == "function" || c == "path")
        .unwrap_or(columns.len());
    columns.insert(cursor_pos, "next_cursor".to_string());
    let next_cursor = page
        .get("next_cursor")
        .and_then(|c| c.as_str())
        .unwrap_or("");
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}",
        columns
            .iter()
            .map(|c| csv_cell(c, false))
            .collect::<Vec<_>>()
            .join(",")
    );
    for row in rows {
        let obj = row.as_object();
        let cells = columns
            .iter()
            .map(|column| {
                if column == "next_cursor" {
                    return csv_cell(next_cursor, false);
                }
                let text = obj
                    .and_then(|o| o.get(column))
                    .filter(|v| !v.is_null())
                    .map(scalar)
                    .unwrap_or_default();
                csv_cell(&text, column == "path" || column == "function")
            })
            .collect::<Vec<_>>();
        let _ = writeln!(out, "{}", cells.join(","));
    }
    out
}

pub fn render_page_table(page: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    let rows = page_rows(page);
    let hotpaths = page.get("kind").and_then(|v| v.as_str()) == Some("hotpaths")
        || rows
            .iter()
            .any(|r| r.get("path").is_some() && r.get("complete_calls").is_some());
    if !hotpaths {
        return render_page_text(page);
    }
    let total_self = page
        .pointer("/totals/self_sum_ns")
        .and_then(value_u64)
        .unwrap_or_else(|| {
            rows.iter()
                .filter_map(|r| r.get("self_sum_ns").and_then(value_u64))
                .sum()
        });
    let inline = page.get("group").and_then(|v| v.as_str()) == Some("inline")
        || rows
            .iter()
            .any(|r| r.get("instructions").is_some() && r.get("inclusive_sum_ns").is_none());
    let mut out = String::new();
    if inline {
        let _ = writeln!(
            out,
            "{:>12} {:>7} {:>14} {:>10}  name",
            "self_ms", "self%", "instructions", "blocks"
        );
    } else {
        let _ = writeln!(
            out,
            "{:>12} {:>7} {:>12} {:>10}  name",
            "self_ms", "self%", "incl_ms", "calls"
        );
    }
    for row in &rows {
        let self_ns = row.get("self_sum_ns").and_then(value_u64);
        let self_ms = self_ns
            .map(|ns| format!("{:.3}", ns as f64 / 1e6))
            .unwrap_or_else(|| "-".into());
        let pct = self_ns
            .filter(|_| total_self > 0)
            .map(|ns| format!("{:.2}%", 100.0 * ns as f64 / total_self as f64))
            .unwrap_or_else(|| "-".into());
        let name = row
            .get("path")
            .and_then(|v| v.as_str())
            .map(short_name)
            .unwrap_or("<unknown>");
        if inline {
            let instructions = row.get("instructions").and_then(value_u64).unwrap_or(0);
            let blocks = row.get("observed_entries").and_then(value_u64).unwrap_or(0);
            let _ = writeln!(
                out,
                "{:>12} {:>7} {:14} {:10}  {}",
                self_ms, pct, instructions, blocks, name
            );
        } else {
            let inclusive_ms = row
                .get("inclusive_sum_ns")
                .and_then(value_u64)
                .map(|ns| format!("{:.3}", ns as f64 / 1e6))
                .unwrap_or_else(|| "-".into());
            let calls = row.get("complete_calls").and_then(value_u64).unwrap_or(0);
            let _ = writeln!(
                out,
                "{:>12} {:>7} {:>12} {:10}  {}",
                self_ms, pct, inclusive_ms, calls, name
            );
        }
    }
    if let Some(c) = page.get("next_cursor").and_then(|c| c.as_str()) {
        let _ = writeln!(out, "next_cursor: {c}");
    }
    out
}

fn row_columns(page: &serde_json::Value, rows: &[serde_json::Value]) -> Vec<String> {
    use std::collections::BTreeSet;
    const FIRST: &[&str] = &[
        "self_sum_ns",
        "inclusive_sum_ns",
        "complete_calls",
        "observed_entries",
        "instructions",
        "p50_ns",
        "p95_ns",
        "p99_ns",
        "excluded_incomplete",
        "n_eligible",
    ];
    const LAST: &[&str] = &["function", "path"];
    let mut all: BTreeSet<String> = rows
        .iter()
        .filter_map(|r| r.as_object())
        .flat_map(|o| o.keys().cloned())
        .collect();
    if let Some(columns) = page
        .get("kind")
        .and_then(|v| v.as_str())
        .and_then(fixed_columns)
    {
        let mut ordered: Vec<String> = columns.iter().map(|s| (*s).to_string()).collect();
        for column in &ordered {
            all.remove(column);
        }
        let extra_at = ordered
            .iter()
            .position(|c| LAST.contains(&c.as_str()))
            .unwrap_or(ordered.len());
        ordered.splice(extra_at..extra_at, all);
        return ordered;
    }
    let mut columns = Vec::new();
    for key in FIRST {
        if all.remove(*key) {
            columns.push((*key).to_string());
        }
    }
    for key in LAST {
        all.remove(*key);
    }
    columns.extend(all);
    for key in LAST {
        if rows.iter().any(|r| r.get(*key).is_some()) {
            columns.push((*key).to_string());
        }
    }
    columns
}

fn page_rows(page: &serde_json::Value) -> Vec<serde_json::Value> {
    match page.get("data") {
        Some(serde_json::Value::Array(rows)) => rows.clone(),
        Some(serde_json::Value::Object(row)) => {
            vec![serde_json::Value::Object(row.clone())]
        }
        _ => Vec::new(),
    }
}

fn fixed_columns(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "summary" => Some(&[
            "covered_start_ns",
            "covered_end_ns",
            "duration_estimate_ns",
            "max_thread_covered_ns",
            "thread_count",
            "function_count",
            "span_count",
            "event_count",
            "sample_count",
            "decode_wall_ms",
            "trigger_hit_ns",
            "detail",
            "quality",
            "threads",
            "analyses",
        ]),
        "timeline" => Some(&[
            "start_ns",
            "end_ns",
            "thread_id",
            "span_id",
            "parent",
            "completeness",
            "clipped",
            "evidence",
            "call_site",
            "call_site_inline",
            "function",
        ]),
        "hotpaths" => Some(&[
            "self_sum_ns",
            "inclusive_sum_ns",
            "complete_calls",
            "observed_entries",
            "instructions",
            "p50_ns",
            "p95_ns",
            "p99_ns",
            "excluded_incomplete",
            "n_eligible",
            "path",
        ]),
        "instructions" => Some(&[
            "sequence",
            "time",
            "len",
            "kind",
            "outcome",
            "branch_target",
            "fallthrough",
            "bytes_hex",
            "id",
            "thread",
            "location",
            "virt_ip",
            "image_offset",
            "inlined",
            "symbol",
        ]),
        "branches" => Some(&[
            "taken",
            "not_taken",
            "unknown",
            "taken_fraction",
            "indirect_targets",
            "site",
            "symbol",
        ]),
        "images" => Some(&["archived", "missing", "content_hash", "build_id", "path"]),
        "inline_profile" => Some(&[
            "instructions",
            "fraction",
            "distinct_addresses",
            "first_address",
            "symbol",
            "inlined",
        ]),
        "at_instant" => Some(&[
            "elapsed_in_innermost_ns",
            "innermost_start_ns",
            "innermost_end_ns",
            "innermost_completeness",
            "innermost_span_id",
            "innermost_call_site_inline",
            "stack",
            "thread_id",
        ]),
        "comparison" => Some(&[
            "absolute_delta",
            "relative_delta",
            "unit",
            "normalization",
            "match_kind",
            "baseline",
            "candidate",
            "baseline_evidence",
            "candidate_evidence",
            "path",
        ]),
        "source" => Some(&[
            "image_offset",
            "virt_ip",
            "location_id",
            "function_id",
            "file",
            "line",
            "inlined",
            "note",
            "image_id",
            "image_path",
            "function",
        ]),
        "quality" => Some(&[
            "timing",
            "gap_count",
            "incomplete_span_count",
            "missing_image_count",
            "decoder_error_count",
            "ring_truncation",
            "undecodable_prefix",
            "gaps_by_kind",
            "notes",
        ]),
        _ => None,
    }
}

fn csv_cell(value: &str, force_quote: bool) -> String {
    if force_quote || value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn value_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

fn short_name(path: &str) -> &str {
    path.rsplit(" > ")
        .next()
        .unwrap_or(path)
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .rsplit("::")
        .next()
        .unwrap_or(path)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hotpath_page() -> serde_json::Value {
        serde_json::json!({
            "kind": "hotpaths",
            "data": [{
                "path": "model_9::FastState > model_9::features",
                "complete_calls": "7",
                "observed_entries": "8",
                "inclusive_sum_ns": 20_000_000,
                "self_sum_ns": 10_000_000
            }],
            "totals": { "self_sum_ns": 20_000_000 },
            "next_cursor": "40"
        })
    }

    #[test]
    fn hotpath_text_is_numeric_first_and_path_last() {
        let rendered = render_page_text(&hotpath_page());
        let row = rendered.lines().find(|l| l.starts_with("  ")).unwrap();
        assert!(row.starts_with("  self_sum_ns=10000000"));
        assert!(row.ends_with("path=model_9::FastState > model_9::features"));
    }

    #[test]
    fn csv_quotes_paths_and_table_uses_global_percent() {
        let csv = render_page_csv(&hotpath_page());
        assert!(csv.contains("\"model_9::FastState > model_9::features\""));
        let mut csv_lines = csv.lines();
        let header = csv_lines.next().unwrap();
        let values = csv_lines.next().unwrap();
        let cursor_column = header.split(',').position(|v| v == "next_cursor").unwrap();
        assert_eq!(values.split(',').nth(cursor_column), Some("40"));
        assert!(header.ends_with(",path"));
        let sparse_page = serde_json::json!({
            "kind": "hotpaths",
            "data": [{ "path": "other", "p99_ns": 1, "self_sum_ns": 1 }],
            "next_cursor": null
        });
        assert_eq!(
            header,
            render_page_csv(&sparse_page).lines().next().unwrap()
        );
        let oversized = serde_json::json!({
            "kind": "hotpaths",
            "data": [{ "omitted": "row exceeded result budget" }],
            "next_cursor": "0"
        });
        assert!(render_page_text(&oversized).contains("omitted=row exceeded result budget"));
        let table = render_page_table(&hotpath_page());
        assert!(table.contains("50.00%"));
        assert!(table.contains("features"));
        assert!(table.contains("next_cursor: 40"));
    }

    #[test]
    fn coverage_summary_reads_decimal_string_counts() {
        let page = serde_json::json!({
            "data": [{
                "thread_count": 40,
                "max_thread_covered_ns": "30000000",
                "threads": [
                    { "thread_id": "t_1", "covered_ns": "22100000" },
                    { "thread_id": "t_2", "covered_ns": "10000000" }
                ]
            }]
        });
        let status = serde_json::json!({
            "recorder": "direct",
            "requested_config": IntelPtConfig::default()
        });
        let summary = coverage_summary_text(&page, &status, Some(20_000)).unwrap();
        assert!(summary.contains("covered 30.000ms"));
        assert!(summary.contains("threads=40"));
        assert!(summary.contains("shown_threads=2"));
        assert!(summary.contains("t_1=22.100ms"));
        assert!(summary.contains("t_2=10.000ms"));
    }

    #[test]
    fn inline_table_reports_instructions_and_blocks_not_calls() {
        let page = serde_json::json!({
            "kind": "hotpaths",
            "data": [{
                "path": "outer > inner",
                "complete_calls": "0",
                "observed_entries": "9",
                "self_sum_ns": 10_000_000,
                "instructions": "42"
            }],
            "totals": { "self_sum_ns": 10_000_000 }
        });
        let table = render_page_table(&page);
        assert!(table.contains("instructions"));
        assert!(table.contains("blocks"));
        assert!(!table.contains("calls"));
        assert!(
            table
                .lines()
                .any(|line| line.contains("42") && line.contains("9"))
        );
    }

    #[test]
    fn hotpath_table_keeps_shape_when_self_time_is_unknown() {
        let page = serde_json::json!({
            "kind": "hotpaths",
            "group": "function",
            "data": [{
                "path": "crate::dispatch",
                "complete_calls": "2",
                "observed_entries": "2",
                "inclusive_sum_ns": 5_000_000
            }],
            "totals": { "self_sum_ns": 0 }
        });
        let table = render_page_table(&page);
        assert!(table.lines().next().unwrap().contains("self_ms"));
        assert!(!table.contains("rows:"));
        assert!(table.lines().nth(1).unwrap().contains('-'));
        assert!(table.contains("dispatch"));
    }

    #[test]
    fn object_query_results_render_as_one_row() {
        let source = serde_json::json!({
            "kind": "source",
            "data": {
                "image_path": "/tmp/app",
                "line": 42,
                "function": "crate::run"
            },
            "next_cursor": null
        });
        assert!(render_page_text(&source).contains("image_path=/tmp/app"));
        let source_csv = render_page_csv(&source);
        assert!(source_csv.lines().next().unwrap().contains("image_path"));
        assert!(source_csv.lines().nth(1).unwrap().contains("/tmp/app"));
        let sparse_source = serde_json::json!({
            "kind": "source",
            "data": { "image_path": "/tmp/other", "image_id": "sha256:x" }
        });
        assert_eq!(
            source_csv.lines().next().unwrap(),
            render_page_csv(&sparse_source).lines().next().unwrap()
        );

        let quality = serde_json::json!({
            "kind": "quality",
            "data": { "gap_count": "3", "ring_truncation": true },
            "next_cursor": null
        });
        assert!(render_page_text(&quality).contains("gap_count=3"));
        assert!(
            render_page_csv(&quality)
                .lines()
                .nth(1)
                .unwrap()
                .contains("3")
        );
    }
}
