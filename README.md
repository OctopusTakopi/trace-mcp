# trace-mcp

trace-mcp is an execution debugger for coding agents, built on Intel
Processor Trace. It records every branch a program takes, keeps the most
recent part of that record in memory, and turns it into function calls
with timestamps that an agent can search. It runs as an MCP server over
stdio and also as a plain command line tool.

The idea is simple. Profilers sample, so they miss the one slow call.
Debuggers stop the program, so timing changes. Intel PT records the whole
control flow with almost no overhead, and the hardware keeps writing into
a ring buffer until told to stop. trace-mcp takes a snapshot of that ring
at the right moment (program exit, a timeout, a function being called for
the fifth time, or a line written by the program itself) and decodes it.
The result is an exact history of what ran, thread by thread, going back
as far as the ring reaches.

## What it can answer

- Which functions ran in the last part of a program, how long each call
  took, and what called what.
- Where the time went inside one function, down to the inlined helpers
  that LTO flattened away, with exact instruction counts.
- What one thread was doing at the instant another thread did something.
- Which branches inside a hot loop were taken and how often.
- How two runs differ, function by function.

## Requirements

- Linux with a CPU that has Intel PT (most Intel cores since Broadwell).
  Check with `grep intel_pt /proc/cpuinfo` or `ls /sys/bus/event_source/devices/intel_pt`.
- Permission to open per-thread perf events: `perf_event_paranoid` of 2
  or lower for the current user works on most systems, and enough
  `RLIMIT_MEMLOCK` for the trace buffers (32 MiB per thread by default).
  `trace-mcp doctor` reports both.
- `perf` from the same kernel series is optional. It is only used as the
  fallback recorder and as the parity oracle in the test suite.
- A Rust toolchain with edition 2024 support, plus `cmake` and a C
  compiler. The Intel PT decoder library (libipt) is built from the
  vendored source under `vendor/`, so no system libipt is needed.

## Build

```sh
cargo build --release
./target/release/trace-mcp doctor
```

`doctor` lists what works on the machine: the PT capabilities, the
permission state, the direct recorder check, and which timing profiles the
CPU supports. Nothing it does changes system settings.

## Quick start on the command line

Record a program until it exits and decode the snapshot:

```sh
trace-mcp --store /path/to/store run -- ./my_program --arg value
```

The output ends with a snapshot id and an analysis id. Then look at it:

```sh
trace-mcp --store /path/to/store query <snapshot_id> --kind summary
trace-mcp --store /path/to/store query <snapshot_id> --kind hotpaths --group function
trace-mcp --store /path/to/store query <snapshot_id> --kind timeline --function decode
```

Other capture shapes:

```sh
# run for 500 ms, then dump whatever history remains in each PT ring
trace-mcp --store S run --after-ms 500 -- ./server

# snapshot on the 5th call of a function (needs a symbol, so not inlined)
trace-mcp --store S run --trigger-symbol my_crate::decode_batch --trigger-hits 5 -- ./my_program

# only trace inside one function's address range
trace-mcp --store S run --address-filter filter:my_crate::hot_loop -- ./my_program

# attach to something already running; it is never signalled
trace-mcp --store S attach --pid 12345 --after-ms 1000
```

`--after-ms` is a wall-clock stop, not a promise to retain that entire
interval. Each ring overwrites old trace data, so a hot thread may retain
only the final tens of milliseconds. `--max-capture-ms` is the absolute
hard cap (default 30000) and is raised automatically for a longer
`--after-ms` or `--tail-ms`.

For a later point in a long replay, use a symbol trigger rather than a
long timer:

```sh
trace-mcp --store S run \
  --max-capture-ms 90000 \
  --trigger-symbol my_crate::engine::step --trigger-hits 1000000 --tail-ms 50 \
  -- ./replay
```

The trigger counts calls to a real executable symbol (not an inlined-only
DWARF function). Estimate the hit count from a shorter run's hotpaths or
timeline. Set `--max-capture-ms` above the expected trigger time plus the
requested tail; `--tail-ms` is clipped by that cap (and by `--after-ms`).

Every command cleans up after itself when it exits: leftover control
FIFOs, decode caches, unfinished analyses, and its own scratch directory
under `$TMPDIR/trace-mcp-<uid>`. Set `TRACE_MCP_KEEP_WASTE=1` to keep
them while debugging.

## Use from an agent

The MCP server is the same binary:

```sh
trace-mcp --store /path/to/store serve --stdio
```

Registration commands for the common agent hosts, and a walk-through of
the tool calls an agent makes, are in [docs/agent-setup.md](docs/agent-setup.md).
The ten tools are `trace_doctor`, `trace_start`, `trace_status`,
`trace_snapshot`, `trace_stop`, `trace_cancel`, `trace_decode`,
`trace_query`, `trace_compare`, and `trace_prune`. Every result is JSON with a short
text summary, sized to fit an agent's context budget; long lists page
with a cursor.

## How a capture works

1. The workload is started through a small launch shim that pins it to
   CPUs if asked, arms the trigger if there is one, and reports every new
   thread before it runs its first instruction.
2. Each thread gets its own Intel PT event and its own ring (32 MiB by
   default, inside a 128 MiB total budget). The ring follows the thread
   across CPUs, so there are no holes from migration and nothing from
   other processes ends up in the trace.
3. When the capture ends, every ring is copied out together with the
   process's memory map and the program images, into a self-contained
   snapshot directory. The images are archived by content hash, so a
   snapshot can be decoded again after the binary was rebuilt.
4. The decoder (libipt, in process, one worker per ring chunk) turns the
   packets back into blocks of instructions, and the reconstructor turns
   the branches into spans: one span per function call with start, end,
   caller, and completeness. Gaps are labelled with their cause (a
   syscall boundary, a ring that did not reach back far enough, a decoder
   error) rather than hidden.
5. Queries read the decoded files. Instruction level detail is decoded on
   demand for one thread and one time window, because it is much bigger.

A perf-record based recorder and a perf-script based decoder are kept as
fallbacks (`TRACE_MCP_RECORDER=perf`, `TRACE_MCP_DECODER=perf`). They are
also what the hardware tests compare the native path against.

## Queries

| kind | what it returns |
|---|---|
| `summary` | coverage per thread, quality counters, the list of analyses |
| `timeline` | individual spans, filter by function name and minimum duration |
| `hotpaths` | totals per call path, per function, or per inlined function |
| `at_instant` | every thread's open call chain at one point in time |
| `instructions`, `branches` | instruction level detail of a decoded window |
| `inline_profile` | instruction counts per inlined function inside a window |
| `source` | file and line, with the inline chain, for an address or evidence id |
| `images` | every program image in the snapshot with its hash and build id |
| `comparison` | the result of `trace_compare` between two snapshots |

For an agent-friendly hotpath view:

```sh
trace-mcp --store S query <snapshot_id> --kind hotpaths \
  --group inline --sort self_time --format table --limit 40
# Fetch page 2 using the prior result's `next_cursor: 40`.
trace-mcp --store S query <snapshot_id> --kind hotpaths \
  --group inline --sort self_time --format table --limit 40 --cursor 40
```

Formats are `text` (stable `key=value` columns with the path last),
`table`, `csv`, and `json`; `--json` remains an alias for JSON output.
CSV uses a fixed schema for each query kind and repeats `next_cursor` in
each row so another page can be fetched without changing formats.
For function hotpaths, `self_sum_ns=0` with nonzero inclusive time means
the observed interval was entirely covered by callees.

## Store layout

```
<store>/
  snapshots/<snapshot_id>/
    manifest.json        what was captured, how, and with which images
    perf.data            the trace bundle (perf.data shaped)
    images/<hash>/       archived program images
    derived/<analysis_id>/
      manifest.json      decoder, quality counters, coverage
      spans.jsonl, events.jsonl, threads.jsonl, gaps.jsonl, inline.jsonl
  reports/               comparison reports
  sessions/, jobs/       bookkeeping for the MCP server
```

Everything is JSON or JSON lines, so a snapshot can be inspected with
ordinary tools, and `trace-mcp import <dir>` copies one into another store.

## Configuration

Most settings travel with the request (`config` in `trace_start`, flags on
`run`). Environment variables cover the rest:

| variable | effect |
|---|---|
| `TRACE_MCP_RECORDER=perf` | record with perf instead of per-thread events |
| `TRACE_MCP_DECODER=perf` | decode with perf script instead of libipt |
| `TRACE_MCP_DECODE_PARALLELISM=n` | number of decode workers (default 8) |
| `TRACE_MCP_KEEP_WASTE=1` | skip the cleanup at exit |
| `TRACE_MCP_NATIVE_DEBUG=1` | per-ring decoder counters on stderr |

## Limits worth knowing

- History is bounded by the ring. Depending on branch density, a tight
  loop can fill the default 32 MiB in tens of milliseconds; an I/O-bound
  thread keeps much longer. The run summary and summary query report
  covered time per thread.
- The direct recorder uses one 32 MiB ring per thread within the 128 MiB
  budget. `--cpus` pins the workload but does not enlarge a single
  thread's ring; use `--aux-bytes` to request more history. With the perf
  fallback, restricting CPUs does allow larger per-CPU rings.
- Timestamps come from the PT timing packets, a few hundred nanoseconds
  apart. Durations shorter than that are quantized, not measured.
- Only user space is traced. Time inside the kernel shows up as a gap
  between a trace end and a trace start at the syscall.
- Decoding a full 32 MiB ring of a busy thread takes tens of seconds.
  Fast mode (`fast: true`) exists for the perf decoder; the native decoder
  is already the faster path.

## Tests

```sh
cargo test                                   # unit and offline tests
cargo test --release --test intel_pt_hardware -- --ignored --test-threads=1
```

The second line needs a machine with Intel PT and takes a few minutes. It
records the fixture program in `examples/pt_fixture.rs` under every
capture shape and checks the decoded results, including a parity check
between the native decoder and perf script. `docs/hardware-validation.md`
lists what each test proves.

## License

MIT. See [LICENSE](LICENSE).
