# Agent setup

trace-mcp speaks MCP over stdio. Any host that can start a local command
as an MCP server can use it. The server needs a store directory to keep
snapshots in; give every host its own directory, because a store is locked
by the process that has it open.

Build first, then note the absolute path of the binary:

```sh
cargo build --release
realpath target/release/trace-mcp
```

Below, `/abs/trace-mcp` stands for that path and `/abs/store` for a
writable directory.

## Claude Code

```sh
claude mcp add --transport stdio trace-mcp -- /abs/trace-mcp --store /abs/store serve --stdio
```

## Codex CLI

```sh
codex mcp add trace-mcp -- /abs/trace-mcp --store /abs/store serve --stdio
```

## Cursor and other JSON configured hosts

Add an entry to the host's MCP configuration (for Cursor that is
`.cursor/mcp.json` in the project or `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "trace-mcp": {
      "command": "/abs/trace-mcp",
      "args": ["--store", "/abs/store", "serve", "--stdio"]
    }
  }
}
```

The same shape works for any host that takes a command and an argument
list. No environment variables are required. `TRACE_MCP_RECORDER=perf`
or `TRACE_MCP_DECODER=perf` can be added to the entry's `env` to force the
fallback paths.

## Check the installation

Ask the agent to call `trace_doctor`. The report lists the PT
capabilities of the CPU, the permission state, and a `direct_recorder`
check that actually opens a small per-thread PT event. `probe: true` adds
a short real capture and decode. Every check comes with a reason and a
remedy, so a failing one says what to change.

## A first session, tool by tool

1. `trace_start` with a caller supplied `request_id`, a `target`
   (`{"kind":"launch","argv":["./my_program","--flag"]}` or
   `{"kind":"attach","pid":1234}`), and a bounded `max_capture_ms`. A
   launch target takes optional `cwd` and `env` (a map of extra
   environment variables for the workload).
   Retrying with the same `request_id` and body returns the same session,
   which matters when a response was lost.

   Optional parts of the request:
   - `after_ms`: stop after that many milliseconds of wall time and dump
     the current PT ring tail. It does not retain the whole interval when
     a hot thread wraps its ring. `max_capture_ms` defaults to 30000 and
     is raised automatically to cover a larger `after_ms` or `tail_ms`.
     After decode, `trace_query kind: summary` reports `covered_ns` per
     thread; that is the history that is really there. A 32 MiB ring of a
     1-thread busy loop is on the order of 20 ms. Snapshot status reports
     `wrapped_rings` for the direct recorder. Use
     `config.aux_bytes_per_buffer` for more history, or a symbol trigger
     plus `tail_ms` for a later window.
   - `trigger`: `{"kind":"symbol","symbol":"my_crate::decode_batch","hits":5}`
     snapshots on the fifth call of that function (an exact demangled
     path, a raw symbol, or a unique substring; the function needs a
     symbol, so inlined functions do not qualify). The hit counter starts
     once that symbol is resolved and armed in the launched image. Estimate
     a later replay's hit number from an earlier hotpaths/timeline query.
     `{"kind":"fifo"}` lets
     the program fire the snapshot by writing a line to the path in
     `$TRACE_MCP_TRIGGER`. Without `tail_ms` the triggering thread is
     paused until the snapshot is written, so the trace ends exactly at
     the trigger. Set `max_capture_ms` above the expected hit time plus
     the desired tail. With `tail_ms` it runs on until that tail or an
     earlier `after_ms`/`max_capture_ms` cap; the aftermath lands in the
     ring and can overwrite the trigger itself in a hot loop.
   - `config.address_filters`: `[{"kind":"filter","symbol":"my_crate::hot"}]`
     makes the hardware trace only inside that function. Up to the CPU's
     number of address ranges, usually 2. Code outside the range is not
     observed at all and appears as `trace_boundary` gaps.
   - `config.cpus`: pin the launched program to those CPUs. Under the
     default direct recorder this does not enlarge a single thread's ring;
     under the perf fallback it permits larger per-CPU rings.
   - `config.aux_bytes_per_buffer`: ring size per thread; the default is
     32 MiB within a 128 MiB total. Set it explicitly to buy more history.

2. Poll `trace_status` with `kind: session` until the state is
   `captured`, then `kind: job` on the initial decode job until it says
   `succeeded`. `kind: sessions` lists everything the server knows.

3. `trace_query` with `kind: summary` first. The `threads` list has each
   thread's `covered_ns` and coverage `segments`; that is the history that
   is really there. `quality.gaps_by_kind` separates syscall and timer
   boundaries from actual loss.

4. `hotpaths` with `group: function` and `sort: self_time` is the profile
   view. `group: path` with `max_depth` and `function_contains` follows a
   caller chain. `group: inline` breaks a function down into the inlined
   functions it was compiled from, with exact instruction counts.
   `timeline` with `function_contains` or `min_duration_ns` finds single
   calls and their `[start_ns, end_ns)`.

5. `at_instant` with `at_ns` lists what every thread was doing at that
   time. This is the tool for producer and consumer questions.

6. For instruction level detail, call `trace_decode` with
   `{"kind":"instructions"}`, one `thread_id`, and a window of some tens
   of microseconds. Then `trace_query` with `instructions`, `branches`
   (taken fractions per site), `inline_profile`, or `source` with an
   address for file and line plus the inline chain.

7. To compare two runs, capture the second one, call `trace_compare`
   (optionally `group: function` with `function_contains`; inline comparison
   defaults to `max_depth: 3`, while `max_depth: 0` keeps full chains), poll its job,
   and read the report with `trace_query` using `target.kind: report` and
   `query.kind: comparison`.

Pages carry `next_cursor` (a decimal offset) and `hints` that say why a
page is empty. Thread ids look like `t_<tid>`; a tid reused after a thread
exited becomes `t_<tid>_g<n>`.

For CLI paging, pass the returned offset back directly: `--limit 40`,
then `--limit 40 --cursor 40` when the first page says
`next_cursor: 40`. Hotpaths also support `--format table` and
`--format csv`.

A `trace_status` call on a snapshot returns its manifest with an image
count and the first few image paths; `trace_query` with `kind: images`
lists all of them with hashes and build ids.

## Keeping the store small

Every capture stays in the store until deleted; the server refuses a new
capture once the store would exceed its budget (4 GiB by default,
`TRACE_MCP_STORE_BUDGET` in bytes overrides it). `trace_prune` with
`list_only: true` reports each snapshot's size; with `snapshot_ids` it
deletes those snapshots, skipping any that still have a queued or running
job. A detailed-timing capture with large rings can take several hundred
megabytes, so prune the runs you have finished comparing.

## Offline use

The store can be read without the server:

```sh
trace-mcp --store /abs/store query <snapshot_id> --kind summary --json
trace-mcp --store /abs/store query --report <report_id> --kind comparison --json
```

Without `--json` the query prints the same page as text, one row per
line. `trace-mcp import <snapshot-dir>` copies a snapshot from another
store, and `trace-mcp prune [snapshot_id...]` lists sizes and deletes
snapshots when no server holds the store.
