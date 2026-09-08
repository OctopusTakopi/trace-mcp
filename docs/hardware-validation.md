# Hardware validation

The unit tests run anywhere. The hardware suite needs Intel PT and real
captures, so it is ignored by default:

```sh
cargo build --profile profiling --example pt_fixture
cargo test --release --test intel_pt_hardware -- --ignored --test-threads=1
```

Release mode matters: the debug build of the decoder is too slow for the
job timeouts. The suite takes two to three minutes and records the
fixture program in `examples/pt_fixture.rs`, which has a spin loop, a
conditional loop with a known taken ratio, a tail call, an indirect call,
a recursive function, an always-inlined helper, and a slow path that can
be switched on with `--candidate`.

## What each test proves

| test | checks |
|---|---|
| `doctor_probe_succeeds_or_explains` | the probe capture and decode work, or every failing check names a remedy |
| `timing_profile_wall_times` | all three timing profiles capture and decode |
| `tiny_aux_does_not_claim_complete_history` | a 256 KiB ring reports gaps and incomplete spans instead of a complete history |
| `cond_loop_not_taken_fraction` | instruction detail reports the loop's `jne` as taken 3 out of 4 times |
| `rebuild_at_same_path_uses_archive` | a snapshot decodes from its archived images after the binary on disk was overwritten |
| `compare_identifies_slow_path` | comparing a baseline with a `--candidate` run names `ptfx_slow_path` |
| `pinned_cpus_capture_is_scoped_to_the_workload` | only the workload's threads appear and pinning is recorded |
| `symbol_trigger_snapshots_on_nth_hit` | the trigger fires on the requested hit and the trap is located in the trace |
| `fifo_trigger_from_workload` | a line written by the program to `$TRACE_MCP_TRIGGER` ends the capture |
| `address_filter_traces_only_the_symbol` | with a filter only the filtered function appears |
| `inline_attribution_names_inlined_helper` | `group: inline` shows the always-inlined helper under its caller |
| `native_decoder_matches_perf_script` | the native decoder and perf script produce the same spans |
| `wrapper_launch_traces_the_real_program` | a program started through `sh -c "exec ..."` is traced as itself |
| `fast_decode_on_a_direct_bundle_is_native` | fast mode on a direct recorder bundle decodes natively and says so |

Every test runs with both recorders when the suite is run twice, once with
the default and once with `TRACE_MCP_RECORDER=perf`.

## Reference machine

The numbers below were taken on an Intel Xeon Gold 6230 (family 6, model
85, stepping 7, 80 logical CPUs, 2.1 GHz) with a 6.12 kernel and the
matching perf, `perf_event_paranoid` at -1 and no memlock limit. PT
capabilities on that CPU: `mtc`, `psb_cyc`, `mtc_periods=0x249`,
`psb_periods=0x3f`, `cycle_thresholds=0x3fff`, two address ranges, no
`ptwrite`.

## Measurements

Fixture, 1 MiB ring, direct recorder against perf record on the same
program:

| | direct | perf record |
|---|---:|---:|
| branches decoded | 3.45 M | 3.43 M |
| spans | 111.8 k | 111.3 k |
| gaps | 4 | 5 |
| returns that did not land in their caller | 5 | 4613 |

The 4613 come from perf's per-CPU rings: a thread that migrates leaves
part of its history in the old ring.

A WebSocket market data client with a spinning consumer thread and a
tokio I/O thread, default settings (32 MiB per thread), 4 seconds of run:

| thread | branches | history | coverage segments |
|---|---:|---:|---:|
| consumer (spin loop) | 123 M | 1.57 s | 1 |
| I/O | 3.7 M | 3.65 s | 1 |
| tokio worker | 9 k | 138 ms (its whole life) | 1 |

No foreign samples, no ring holes. Decoding that snapshot (127 M branches
in total) takes about 25 s with 8 workers on a loaded host: 81 s serial
before the rings were chunked at PSB boundaries, 45 s after, 31 s with
the libipt section cache, 25 s with fast hashed maps in the
reconstructor. An instruction window of 34 us in a 4 MiB ring decodes in
about 9 s; the PSB index only helps as much as the PSB density allows.

perf script on a 92 MB, 4 CPU capture of the same client: 118 s for the
full pass, 21.5 s in fast mode. The native decoder does the same capture
in 16 s with results within 0.1 percent on span counts and identical
branch and function transfer counts.

Symbol trigger on the fixture: fires 30 to 50 ms after arming; without the
parked-thread acknowledgement the 1 MiB ring (about 4 ms of the fixture's
loop) was overwritten during perf's 11 ms stop, and the trap was lost in
three runs out of three.

## Things the numbers do not claim

- Overhead on the traced program was not measured separately. PT itself
  is cheap; the launch shim's ptrace stops only happen at thread creation
  and exit.
- Durations are decoder estimates, not cycle counts.
- Kernel time is invisible; it appears as a gap at the syscall.
