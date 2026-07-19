# Resilience / wire-loss testing (dedicated, isolated)

> Status: the client tools were hardened to xrootdfs-level resilience — see
> "Client resilience (libbrix)" below. This harness is both the regression proof
> and the way to measure the loss-vs-time curve.

Self-contained fault-injection tests for the native client over **`root://` + GSI**,
against **both** backends — this repo's nginx module **and** the official `xrootd`
daemon — with the in-repo TCP fault proxy spliced in front.

Everything here runs on a **dedicated high port block (13901 / 13902)** with its
own data root and PKI under `/tmp/xrd-resilience`, completely **isolated from the
main test suite** (which owns 11094–12126 under `/tmp/xrd-test`). It never calls
`manage_test_servers.sh`; each server and the fault proxy is a context manager
that brings itself up and tears itself down.

## Files

| File | Role |
|---|---|
| `servers.py` | Dedicated `NginxGsi`, `XrootdGsi`, and `FaultProxy` context managers + PKI/seed helpers. No fleet dependency. |
| `run_loss_sweep.py` | Standalone sweep runner — records per-transfer time + success across a loss/jitter matrix; writes CSV + summary table. |
| `run_mount_sweep.py` | Mounts the **xrootdfs FUSE driver** through the proxy and runs WRITE + READ round-trips under a chosen `--fault` (`loss`/`reorder`/`jitter`), reporting byte-exact ok/N + throughput per level (anonymous by default; `--gsi` opt-in; per-op watchdog). |
| `test_loss_sweep_gsi.py` | Fast pytest smoke test (small file): 0% byte-exact + clean-fast failure under loss, both backends. |
| `run_xrdcp_loss.py` | xrdcp download loss sweep comparing the repo client+module vs the official client+xrootd (anonymous; `--matrix` for cross pairs). |
| `results-packet-loss-mount-2026-06-23.md` | Recorded sweep results: xrootdfs mount read/write under 0–20% loss + 0–3% reorder, with interpretation. |
| `results-xrdcp-loss-comparison-2026-06-23.md` | Recorded comparison: repo `xrdcp`+nginx vs official `xrdcp`+xrootd under 0–1% loss. |

## Prerequisites

- `client/bin/xrdfs` and `client/bin/brix-fault-proxy` built
  (`make -C client xrdfs brix-fault-proxy` — brix-fault-proxy is also built by a
  bare `make -C client`, as a first-class shipped tool).
- The module's nginx at `/tmp/nginx-1.28.3/objs/nginx` (override `RESIL_NGINX_BIN`).
- Official `xrootd` on `PATH` and `libXrdSec-5.so` present (for the GSI reference server).

## Run the sweep

```bash
# From repo root. Defaults: loss 0,1,5,10,12,15,20 / 5 reps / 256 MiB / 240s timeout.
PYTHONPATH=tests python3 tests/resilience/run_loss_sweep.py

# Out-of-order / reordering sweep (jitter ms per level), see note below:
PYTHONPATH=tests python3 tests/resilience/run_loss_sweep.py --fault jitter

# Custom matrix (a lossy AND reordering link at each level):
PYTHONPATH=tests python3 tests/resilience/run_loss_sweep.py \
    --fault both --levels 0,1,5,10,12,15,20 --reps 5 --size-mib 256 --timeout 240
```

`--fault` selects what the proxy injects at each `--levels` value:
`loss` (sever %/chunk, the default), `jitter` (random 0..level-ms delay per chunk),
or `both`. `--losses` is kept as a back-compat alias for `--levels`.

Per-rep results are written to `/tmp/xrd-resilience/loss_sweep_results.csv`.

## Run the smoke test

```bash
PYTHONPATH=tests python3 -m pytest tests/resilience/test_loss_sweep_gsi.py -v
```

Selecting the test file by name skips the main-suite fleet (the file is in
`conftest.py`'s `no_server_files` allowlist, like `test_official_brix_resilience.py`).

## What the fault proxy's loss models

The proxy's `lossy <pct>` lever **severs the TCP connection** with `<pct>%`
probability per forwarded chunk — an *application-visible reset*, harsher than
packet-level loss (where TCP would retransmit transparently). See
`brix-fault-proxy --help` (source `client/apps/diag/brix_fault_proxy.c`) for the
full lever set (`latency`, `chunk`, `drip`, `lossy`, `jitter`, `reorder`, `drop`,
`block`).

## What the `jitter` lever models (out-of-order delivery)

Out-of-order **packet** delivery cannot be reproduced by re-ordering bytes in a
userspace TCP proxy: TCP reassembles segments in order *below* the proxy, so the
peer's socket only ever yields the in-order byte stream. Re-ordering bytes here
would be stream corruption the client could never see on a real network — not
reordering. What IP-packet reordering actually does to a TCP application is add
**variable latency** (early/late segments, dup-ACKs, the odd fast-retransmit).

Two levers inject that variable latency, faithfully and **without root**:

- `jitter <ms>` — a uniform-random `0..ms` delay on *every* forwarded chunk
  (a magnitude). Run via `run_loss_sweep.py --fault jitter` (levels read as ms).
- `reorder <pct> [ms]` — with probability `<pct>%` per chunk, hold *that* chunk
  back by `<ms>` ms (default 50) while later chunks go straight through, so a
  `<pct>%` fraction arrives late relative to its neighbours. This is the app-layer
  analog of `tc qdisc … netem reorder <pct>% delay <ms>` — a *percentage* of
  segments delivered out of order. Used by `run_mount_jitter.py`.

Combined with `chunk <bytes>` (+ egress `TCP_NODELAY`) each segment is delivered
as its own TCP segment after an independent gap, so inter-segment arrival times
vary the way a reordering link makes them vary. A correct, resilient client
returns the file **byte-exact, only slower** (these levers never sever). True
IP-packet reordering would need `tc qdisc … netem reorder` (CAP_NET_ADMIN), which
this root-free proxy avoids by design.

### FUSE mount read/write under reorder

`run_mount_sweep.py` mounts the `xrootdfs` FUSE driver through the proxy and runs
a WRITE round-trip (write → read back → verify on-disk md5) and a READ round-trip
(stream a seeded file → verify md5) at each level, for a chosen `--fault`:

```bash
# packet-loss sweep (default), 0/1/5/10/12/15/20 %:
PYTHONPATH=tests python3 tests/resilience/run_mount_sweep.py
# out-of-order sweep, reorder 0,1,2,3% with a 50 ms hold-back:
PYTHONPATH=tests python3 tests/resilience/run_mount_sweep.py --fault reorder --levels 0,1,2,3 --reorder-ms 50
```

Representative result (anon nginx, 32 MiB read / 8 MiB write, byte-exact at every
level — the driver only slows down; reads are more latency-sensitive than the
write-back-buffered writes):

| reorder% | write MB/s | read MB/s |
|---:|---:|---:|
| 0 | ~365 | ~630 |
| 1 | ~380 | ~96 |
| 2 | ~68 | ~75 |
| 3 | ~38 | ~48 |

## Client resilience (libbrix)

The synchronous client tools are now network-resilient like the `xrootdfs` FUSE
driver: on a sever they reconnect, re-authenticate (full GSI/token re-login),
reopen the handle, and resume at the same offset, bounded by a patience window
with backoff. This lives in `client/lib/resilient.c` (`brix_rfile` for streaming,
`brix_with_resilience` / `brix_roundtrip_resilient` for stateless ops) and is
wired into the high-level library ops, so every tool inherits it.

- **On by default** (window `XRDC_DEFAULT_MAX_STALL_MS` = 30 s).
- `XRDC_MAX_STALL_MS=<ms>` widens/narrows the window; `=0` (or `--no-retry` on
  tools that parse the common flags) restores the legacy **fail-fast** path.
- Recovery pays a full re-handshake per sever, so **higher loss needs a wider
  window**. Measured `xrdfs cat` (this sweep): 0%≈0.05 s, 1%≈0.1 s, 3%≈11 s,
  5%≈30 s (all byte-exact), versus the pre-change result of `0/N` at any loss>0.
  Set `--client-max-stall` on the sweep to widen the window for higher loss.

The pre-change baseline (fail-fast) is reproducible with `--client-max-stall 0`.
The FUSE driver (`client/bin/xrootdfs`) remains the reference; see
`tests/test_xrootdfs_resilience.py` and `tests/test_official_brix_resilience.py`.
