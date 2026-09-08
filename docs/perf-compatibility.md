# Recording and decoding details

This page covers the parts that are easy to get wrong when working on
trace-mcp or when reading a snapshot by hand: the two recorders, the
bundle format, the perf script dialect used by the fallback decoder, how
program images are looked up, and how triggers and address filters are
wired.

## The direct recorder

The default recorder opens one Intel PT event per thread with
`perf_event_open` (`pid = tid`, `cpu = -1`, no inherit) and maps its AUX
area read only, which is the kernel's snapshot mode: the hardware keeps
overwriting the ring and nothing has to drain it. When the capture ends
each event is disabled and its ring is copied out in stream order. A ring
has wrapped when `aux_head` passed its size or when the last bytes of the
mapping are no longer zero.

Threads are discovered by the launch shim, `trace-mcp __launch --report`.
It forks, calls `PTRACE_TRACEME`, and execs the program. From then on it
reports every exec, clone, fork, and exit stop over a FIFO and waits for
an acknowledgement before letting the thread continue. That is how every
thread's event is open before the thread runs a single user instruction,
and how a process's memory map can still be read at its exit stop. Later
execs (a shell script or a build tool exec'ing the real program) are
reported too, and the time of the exec is stamped from the TSC so the
decoder knows where the old image ends.

Attached processes get one event per thread found in `/proc/<pid>/task`
at attach time; threads that appear later are picked up by polling and
marked as traced from their discovery.

Ring size is per thread: `aux_bytes_per_buffer` if given, otherwise
32 MiB, all inside `max_total_aux_bytes` (128 MiB by default). When the
budget is used up, later threads get what is left, down to 64 KiB, and a
diagnostic says which threads got nothing.

Address filters use the kernel's own filter syntax through
`PERF_EVENT_IOC_SET_FILTER`: `filter 0x<offset>/0x<size>@<file>`, where
the offset is a file offset that the kernel resolves against the task's
mappings. Note the missing blanks around `@`; perf's own `--filter`
option accepts blanks and rewrites the string, the kernel does not.

## The bundle

A snapshot's `perf.data` is written by trace-mcp itself in the shape of a
perf.data file: the header, one event attribute, then a data section with

- `AUXTRACE_INFO` carrying the timing parameters from the mmap metadata
  page (`time_shift`, `time_mult`, `time_zero`; the TSC to CTC ratio comes
  from CPUID leaf 0x15),
- a `FORK` record per process with its parent, a `perf-exec` `COMM` for
  the root of the traced tree, then a `COMM` (with the exec flag and exec
  time when an exec was observed) and one `MMAP2` per executable mapping
  read from `/proc`,
- a `FORK`, `COMM`, and `ITRACE_START` per thread on a pseudo CPU number
  (one per thread), which is what the decoder uses to attribute a ring,
- one `AUXTRACE` record per thread with the raw trace bytes.

There is no feature section, so perf script cannot read these files. The
native reader in `src/capture/perfdata.rs` and the decoder consume them
directly. Bundles written by perf record (the fallback recorder) have the
real thing and can be read by both.

The mmap metadata page has `time_offset` at byte 56 and `time_zero` at
byte 64. Reading the wrong one gives timestamps that are off by the
machine's uptime.

## The native decoder

`src/decode/native.rs` decodes each ring with libipt's block decoder,
built from the vendored libipt source (a pinned master snapshot, version
2.3.0, chosen for `pt_blk_resync`). Large rings are cut at PSB packets
into chunks that the decode workers share; a chunk starts at a sync point,
where the decoder resets anyway, and the merge step orders the records by
time again.

Things that were learned the hard way and are now handled:

- The block time is only valid after the pending events of a block are
  drained; before that libipt reports no time.
- Events are bound to the end of the block they arrive with. A syscall's
  trace end belongs to the block that ends in the syscall instruction.
- libipt only fills `pt_block.size` for truncated instructions, so the
  length of a conditional jump comes from the image bytes.
- The decoder walks straight through direct calls and jumps unless
  `end_on_call` and `end_on_jump` are set. Both are set.
- A trace disable without an IP after a direct branch is folded into that
  branch record (a `call` that is also a `tr end`), which is how perf
  reports it, except at syscalls.
- Only the traced process tree gets code images. Everything else that ran
  on the same CPU decodes against an empty image and is skipped at packet
  scan speed. A forked child before its exec is treated the same way.
- The block decoder maps one image section at a time and libipt drops a
  section's block cache when it is unmapped, so every hop between the
  program and libc used to re-zero tens of megabytes. Sections now live in
  a per-worker section cache with a memory limit.
- After an undecodable stretch the decoder resynchronises at the next IP
  packet, like perf does, instead of the next PSB, which in a per-thread
  ring can be the end of the buffer.

Records are the same as the ones the perf script parser produces, so the
reconstructor is shared. `TRACE_MCP_DECODER=perf` forces the perf script
path for perf-recorded snapshots; the hardware suite compares the two.

Debugging aids: `TRACE_MCP_NATIVE_DEBUG=1` prints per-ring counters and
errors by process, `TRACE_MCP_NATIVE_DUMP=<lo_ns>,<hi_ns>` prints every
emitted record in an absolute time window, and `examples/native_probe.rs`
walks the first packets of one ring.

## The perf fallback

With `TRACE_MCP_RECORDER=perf` the capture runs

```text
LC_ALL=C PERF_PAGER=cat perf record \
  --no-buildid-cache --buildid-mmap --synth=all \
  -e intel_pt/tsc=1,branch=1,mtc=1,mtc_period=3,cyc=0,noretcomp=0,psb_period=5/u \
  -m 16,<size> --snapshot=e --control=fd:<ctl>,<ack> \
  -o perf.data --max-size=<n> -- <shim> -- <program>
```

perf's rings are per CPU, not per thread. On a machine with many CPUs the
default 4 MiB per CPU exceeds the 128 MiB budget and the capture picks
the largest power of two that fits (1 MiB on 80 CPUs). A thread that
migrates leaves its older history in the previous CPU's ring, and if the
new ring does not reach back far enough the summary reports a
`ring_truncation` gap. With `cpus` set, perf's `-C` makes the capture CPU
wide: every task on those CPUs is recorded and the analysis keeps only the
traced process tree, reporting how many foreign samples were dropped.

The control handshake is `ping` then `ack`, and `stop` then `ack`. With
`--snapshot=e` the snapshot is taken at exit; no separate `snapshot`
command is sent.

Image lookup goes through a private build id cache
(`perf --buildid-dir <snapshot>/buildid`) rather than `--symfs`. With
`--symfs`, perf copies its own vdso to a temporary file and then looks for
that path under the symfs prefix, which does not exist, and every
`clock_gettime` turns into a decoder error.

The decode dialect the parser understands:

```text
perf script -i perf.data --ns --itrace=be \
  -F pid,tid,cpu,time,event,ip,addr,flags \
  --show-task-events --show-mmap-events --show-lost-events
```

```text
PID/TID [CPU] TIME:  branches:u:   FLAGS  IP => ADDR
1518114/1518114 [062] 513961.572230317:  branches:u:   call  7f5459d6c443 => 7f5459d6d140
1518114/1518114 [062] 513961.572226468:  branches:u:   tr strt jmp  0 => 7f5459d6c440
1518114/1518114 [062] 513961.572227109:  branches:u:   tr end  async  7f5459d6c440 => 0
```

Flags are multi word (`tr strt jmp`, `tr end async`, `call`, `return`,
`jcc`, `jmp`) and come before the addresses. Instruction samples from
`--itrace=i1ibe` print the address before the ip and do not use `=>`:

```text
1518114/1518114 [062] 513961.572230317:  instructions:u:  0  7f5459d6c440 ilen: 3 insn: 48 89 e7
```

Sideband lines name the owning task after the record name
(`PERF_RECORD_COMM exec: name:PID/TID`, `PERF_RECORD_MMAP2 PID/TID: [...]`).
A timestamp of `0.000000000` is not a usable origin. Decoder errors look
like `instruction trace error ... code 5: Failed to get instruction`;
code 5 is a missing image and code 6 a mismatch between the trace and the
instruction bytes. Sample files of both dialects are under
`tests/fixtures/`.

Fast mode (`fast: true`, `--itrace=cre`) decodes calls and returns only.
It is several times faster than the full perf script pass but loses
inter-function jumps, so tail called functions are attributed to their
caller and PLT stubs stand in for their targets. It only applies to the
perf decoder; a direct recorder bundle is always decoded natively.

## Symbol triggers

`trace-mcp __launch --symbol S --hits N --notify <fifo> -- <program>`
resolves `S` in the launched executable through its `PT_LOAD` segments
and `/proc/<pid>/maps`, writes `0xCC` over the first byte, and traces
clones so later threads are covered too. Hits 1 to N-1 are single stepped
over the original instruction. On hit N the byte is restored, the hit is
reported over the FIFO, and the trapping thread stays stopped until the
snapshot has been written, so the ring ends exactly at the trigger. A trap
that was already queued in another thread when the trigger was disarmed
is rewound to the restored instruction. With `tail_ms` the thread is
released at once and runs for the tail.

The decoder finds the trap in the trace (the last trace boundary at that
address) and reports it as `trigger_hit_ns` together with how much
history follows it.

## Timing

Timestamps are decoder estimates from the PT timing packets (MTC with the
`balanced` profile, a few hundred nanoseconds apart). Durations below one
step are quantized. `covered_ns` and `segments` per thread are the real
lookback of a snapshot; the difference between the covered end and start
is not.
