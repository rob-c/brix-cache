# Resilience / wire-loss testing (dedicated, isolated)

> Status: the client tools were hardened to xrootdfs-level resilience — see
> "Client resilience (libxrdc)" below. This harness is both the regression proof
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
| `run_loss_sweep.py` | Standalone sweep runner — records per-transfer time + success across a loss matrix; writes CSV + summary table. |
| `test_loss_sweep_gsi.py` | Fast pytest smoke test (small file): 0% byte-exact + clean-fast failure under loss, both backends. |

## Prerequisites

- `client/bin/xrdfs` and `client/bin/fault_proxy` built (`make -C client xrdfs`;
  `cc -O2 -pthread tests/c/fault_proxy.c -o client/bin/fault_proxy`).
- The module's nginx at `/tmp/nginx-1.28.3/objs/nginx` (override `RESIL_NGINX_BIN`).
- Official `xrootd` on `PATH` and `libXrdSec-5.so` present (for the GSI reference server).

## Run the sweep

```bash
# From repo root. Defaults: losses 0,1,5,10,12,15 / 5 reps / 256 MiB / 120s timeout.
PYTHONPATH=tests python3 tests/resilience/run_loss_sweep.py

# Custom matrix:
PYTHONPATH=tests python3 tests/resilience/run_loss_sweep.py \
    --losses 0,1,5,10,12,15 --reps 5 --size-mib 256 --timeout 120
```

Per-rep results are written to `/tmp/xrd-resilience/loss_sweep_results.csv`.

## Run the smoke test

```bash
PYTHONPATH=tests python3 -m pytest tests/resilience/test_loss_sweep_gsi.py -v
```

Selecting the test file by name skips the main-suite fleet (the file is in
`conftest.py`'s `no_server_files` allowlist, like `test_official_xrootd_resilience.py`).

## What the fault proxy's loss models

The proxy's `lossy <pct>` lever **severs the TCP connection** with `<pct>%`
probability per forwarded chunk — an *application-visible reset*, harsher than
packet-level loss (where TCP would retransmit transparently). See
`tests/c/fault_proxy.c` for the full lever set (`latency`, `chunk`, `drip`,
`lossy`, `drop`, `block`).

## Client resilience (libxrdc)

The synchronous client tools are now network-resilient like the `xrootdfs` FUSE
driver: on a sever they reconnect, re-authenticate (full GSI/token re-login),
reopen the handle, and resume at the same offset, bounded by a patience window
with backoff. This lives in `client/lib/resilient.c` (`xrdc_rfile` for streaming,
`xrdc_with_resilience` / `xrdc_roundtrip_resilient` for stateless ops) and is
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
`tests/test_xrootdfs_resilience.py` and `tests/test_official_xrootd_resilience.py`.
