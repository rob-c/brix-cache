# Lifecycle speed: faster startup & shutdown

**Date:** 2026-06-27
**Status:** approved (design) — Stage 1 in progress
**Driver:** general "make the whole lifecycle tighter"; **measure-first** (no specific
observed bottleneck yet). Scope covers all four lifecycle events.

## Goal

Make the nginx-xrootd module measurably faster across the full process lifecycle:
cold start (boot → accepting), reload (SIGHUP: bring up new workers + retire old),
full shutdown (SIGTERM/SIGQUIT drain), and worker respawn after crash.

The reload/teardown side already has heavy prior work (fast-teardown Phases 1–3:
`ngx_exiting`-guarded timer quiescing, idiomatic idle-connection close,
upload/download resume across restart). This effort does **not** regress that; it
extends measurement to the *startup* side, which is comparatively un-instrumented,
and removes whatever costs the data exposes.

## Strategy (two stages)

### Stage 1 — Instrument & measure (this spec's deliverable, low risk, no behavior change)

1. **Permanent, low-overhead phase logging** baked into the module. A shared
   monotonic-clock + phase-accumulator helper (`src/core/compat/lifecycle_timing.{c,h}`)
   emits **one summary line per lifecycle event**, e.g. at the end of per-worker
   `init_process`:
   `xrootd startup[w0]: uring=Xms servers=Yms gsi_keypool=Zms total=Wms`
   and at the end of the master `postconfiguration` pass:
   `xrootd postconfig: prepare=Xms total=Yms`.
   Cost is effectively zero in the request hot path — it fires once per
   boot/reload, never per request. Two `clock_gettime(CLOCK_MONOTONIC)` calls
   (vDSO-backed, ~20 ns) per marked phase.

2. **Throwaway profiling harness** (`tests/profile_lifecycle.sh`, ships in tests/
   but is a measurement tool, not a module feature): boots, reloads (SIGHUP),
   stops (SIGTERM), and kills+respawns a worker, capturing:
   - wall-clock per event,
   - **time-to-first-accept** by polling each test port (the true cold-start SLO),
   - `strace -c -f` syscall summary on master + a worker,
   - phase deltas parsed from the module's own monotonic summary lines.
   Emits a one-screen costs report.

### Stage 2 — Fix the top costs (scoped *after* Stage 1 numbers)

Only fixes the data justifies. Pre-identified candidates (not commitments):
- **Cert / CA / CRL load + PKI startup audit** — prime suspect (X509_STORE build,
  CA bundle parse at postconfiguration). Candidate: defer/parallelize.
- **OCSP / Pelican-register** — currently do blocking network at startup
  (`BIO_do_connect`, `curl_easy_perform`). Candidate: move off the boot path to a
  background timer so the server accepts traffic without waiting on them.
  **Confirmed acceptable** by the operator (they do not depend on these completing
  synchronously before first accept).
- **SHM zone init** (~18 zones) — slab init / slot zeroing. Candidate: lazy init.
- **Worker respawn** — trim redundant per-worker work re-run on every respawn.

## Phase boundaries timed

| Phase | Hook | Suspected cost |
|---|---|---|
| postconfig pass | `postconfiguration` enter/exit | per-server prepare, path validation |
| Cert/CA/CRL + PKI audit | server prepare / `pki_load` | X509_STORE build, CA parse |
| OCSP / JWKS / Pelican | startup | blocking network |
| SHM zone alloc + init | ~18 `init` callbacks | slab init |
| Worker `init_process` | enter/exit | uring init, timer registration |
| Time-to-first-accept | first connect per port | the cold-start SLO |
| Reload retire | old-worker exit | already fast — confirm, don't regress |
| Full shutdown | SIGTERM → gone | drain window |

## Testing

- The harness is itself the before/after regression check (timing deltas).
- Permanent logging gets a parse-assert test (summary line present + well-formed).
- Each Stage-2 fix gets the standard 3 tests (success + error + security-neg) plus a
  before/after timing delta.
- `tests/test_shutdown_resume.py` must stay green — no teardown regression.

## Results (Stage 1 + Stage 2 — implemented)

**Stage 1 (instrumentation):** `src/core/compat/lifecycle_timing.{c,h}` emits one NOTICE
line per lifecycle event; `tests/profile_lifecycle.sh` self-provisions and reports
cold-start / reload / respawn / shutdown plus the parsed phase breakdown.

**Baseline → after (2 workers, WSL2, GSI + thread pool):**

| phase | before | after |
|---|---|---|
| per-worker `init_process` total | ~16–18 ms | **~1.4 ms** |
| └ GSI keypool warm-up | ~16 ms | **~1.2 ms** (seed only; rest off-thread) |
| worker respawn | ~28 ms | **~16 ms** |
| master `postconfig` total | ~2–3 ms | ~2 ms (unchanged; see below) |

**Stage 2a — lazy GSI keypool (the dominant win):** `xrootd_gsi_keypool_init` now
generates only `gsi_keypool_seed` (default 4) keys synchronously at worker start and
fills the pool to `gsi_keypool_size` (default 64) off the event thread via the GSI
server's thread pool. New directives `xrootd_gsi_keypool_size` / `_seed`. **Safety
fallback:** with no thread pool the full target is warmed synchronously (unchanged
behaviour) — correctness over latency. A one-shot "warmed to N/N" NOTICE confirms the
off-thread fill completed. Regression: `test_gsi_handshake.py` + `test_gsi_concurrency.py`
= **79 passed** (real stock `xrdfs`/`xrdcp` GSI clients); `test_lifecycle_speed.py` =
**4 passed** (lazy path, sync fallback, configurable size, phase lines).

**Stage 2b — master `prepare`:** investigated. The cost is the GSI `X509_STORE` build
(`xrootd_rebuild_gsi_store`, CA + CRL PEM parsing) which **cannot be safely deferred**
(needed before the first GSI handshake) and scales with CA-bundle size. In typical
configs it is ~2 ms and the store build itself is sub-100 µs (the residual is fixed
RSA-key/TLS-context init). Rather than a risky deferral of an auth-path object, the
store-build is now **independently timed** (`xrootd: GSI trust store built from "…" in
N us`) so a slow startup on a full grid CA distribution is attributable at a glance.
Future (not done, low priority): de-duplicate the store build across server blocks that
share a CA path within one config pass.

## Non-goals

- No Prometheus startup-histogram as a centerpiece (revisit only if ops want it).
- No unrelated refactoring of the config or crypto subsystems.
- No change to the existing fast-teardown / resume machinery beyond confirming it.
