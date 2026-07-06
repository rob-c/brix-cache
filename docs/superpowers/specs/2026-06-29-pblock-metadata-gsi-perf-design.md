# pblock Metadata Performance / Reliability Test Suite (root:// + GSI)

**Date:** 2026-06-29
**Status:** Design — approved for plan
**Topic:** Concurrent metadata-storm reliability + performance proof for the pblock
storage backend, driven over `root://` with GSI authentication, across three test
layers (libxrdc code-level, `xrdfs` CLI chain, `xrddiag` client validation).

---

## 1. Goal

Prove the **reliability and performance of the pblock storage backend** under a
rapid-fire concurrent metadata workload — ~1000 metadata operations (create /
chmod / stat / remove of folders and files) issued in rapid succession over
GSI-authenticated `root://` sessions — and ship it as a reusable **test tool**.

The suite must answer two questions with evidence:

1. **Does pblock stay correct under concurrency?** No op failures, the block
   catalog and data dir exactly reflect the namespace the ops produced, and the
   server survives the storm (no worker crash, no SHM corruption, no conn-table
   leak).
2. **Does pblock perform?** Aggregate ops/sec and per-op latency percentiles
   (p50/p95/p99) are reported, and a pathological-tail ceiling (p99) gates pass.

## 2. Scope

**In scope:**
- A single shared **pblock + GSI server fixture** (stream-only nginx, high port).
- A single deterministic **op manifest** reused by every layer so the expected
  post-storm namespace is identical and exactly checkable.
- Three test layers against that fixture (see §4).
- A new **`xrddiag metabench`** subcommand (shipped client capability).
- Four pass criteria enforced by the harness (see §5).

**Out of scope (YAGNI):**
- Data-plane (PUT/GET byte) throughput — covered by `run_pblock_root.sh`.
- Non-GSI auth modes (anon/token/SSS) — this suite is GSI-specific by request.
- WebDAV / S3 metadata — `root://` only.
- Mesh / redirector topologies — single standalone fileserver.

## 3. Shared Fixture

`tests/run_pblock_meta_gsi.sh` is the umbrella. It is self-contained and
skip-clean (skips if `client/libxrdc.a`, `client/bin/xrdfs`, `client/bin/xrddiag`,
or the nginx binary is absent), matching the `run_pblock_*.sh` family.

**Server config** (generated into a `mktemp -d` prefix):
```nginx
stream {
  server {
    listen 127.0.0.1:11498;
    brix_root on;
    xrootd_root            $PFX/root;
    xrootd_auth            gsi;
    xrootd_certificate     $PFX/conf/host.crt;
    xrootd_certificate_key $PFX/conf/host.key;
    xrootd_allow_write     on;
    xrootd_upload_resume   off;          # pblock requirement
    xrootd_storage_backend pblock;
    xrootd_pblock_block_size 1m;
    xrootd_access_log $PFX/logs/access.log;
  }
}
```
A thread pool is configured (GSI keypool warm-up) as in `profile_lifecycle.sh`.

**Credentials:** the script generates a self-signed host cert/key and a GSI
**proxy**, exporting `X509_USER_PROXY` (and `X509_CERT_DIR`) — the single env path
that `libxrdc`, `xrdfs`, and `xrddiag check` all already consume
(`client/lib/conn.c:631`, `client/apps/diag_check.c:233`). One credential setup
drives all three layers.

**Tunables (env, with defaults):** `WORKERS=8`, `OPS_PER_WORKER=125`
(→ ~1000 total), `PBLOCK_BLOCK_SIZE=1m`, `P99_CEIL_MS=50`, `PORT=11498`.

## 4. Op Manifest (shared, deterministic)

Each worker `w` operates inside its **own subtree** `/w<id>/` so workers never
contend on the same namespace entry (concurrency stresses the catalog's internal
locking, not application-level conflicts). The per-worker program is deterministic:

```
mkdir   /w<id>                       (dir)
chmod   /w<id> 0755
for d in 0..D-1:
    mkdir   /w<id>/d<d>              (dir)
    chmod   /w<id>/d<d> 0700
    for f in 0..F-1:
        truncate /w<id>/d<d>/f<f> 0  (create empty file)
        chmod    /w<id>/d<d>/f<f> 0640
        stat     /w<id>/d<d>/f<f>    (assert mode + size)
teardown (separately timed, NOT counted in the storm op total):
    rm      every file
    rmdir   every dir bottom-up
```

`D` and `F` are derived from `OPS_PER_WORKER` so the op count lands near the
target. Because the program is fixed, the **expected namespace** (set of paths +
their modes) is known exactly — this is what makes catalog integrity (§5.2) a
strict equality check rather than a loose smoke test.

The manifest is expressed once (a small generator) and consumed by all three
layers: the C harness calls it via `xrdc_*` ops, the `xrdfs` layer renders it as
a batch script, and `xrddiag metabench` embeds the same generator.

libxrdc op signatures used (already public, `client/lib/xrdc_ops.h`):
- `xrdc_mkdir(conn, path, mode, parents, st)`
- `xrdc_chmod(conn, path, mode, st)`
- `xrdc_truncate(conn, path, size, st)`  (create-by-truncate of a 0-byte file)
- `xrdc_stat(conn, path, &statinfo, st)`
- `xrdc_rm(conn, path, st)` / `xrdc_rmdir(conn, path, st)`
- `xrdc_connect(conn, &url, &opts, st)` — full GSI handshake+login per worker.

## 5. Pass Criteria (all four enforced)

1. **Zero op failures.** Every op returns `kXR` success (or the expected errno for
   the teardown idempotency edge). Any unexpected error, hang, or dropped
   connection ⇒ FAIL. Surfaced as harness non-zero exit + JSON `failures == 0`.
2. **Catalog integrity post-storm.** After the create/chmod/stat phase (before
   teardown), the script walks the pblock **block catalog + data dir** and asserts
   it matches the manifest's expected namespace exactly: no orphaned blocks, no
   leaked or missing entries, and each `chmod` mode persisted (verified by
   stat-back). The deterministic manifest makes this exact.
3. **Server health after storm.** A fresh GSI login + `stat` against the server
   succeeds post-storm — proves no worker crash, SHM corruption, or conn-table
   leak under concurrency.
4. **Latency bounds.** Report p50/p95/p99 per-op latency; **FAIL if p99 >
   `P99_CEIL_MS`** (default 50 ms) to catch catalog lock-contention tails.

## 6. The Three Layers

### Layer (a) — Direct code test (libxrdc)
`tests/tools/pblock_meta_bench.c`, compiled on the fly by the umbrella script
against `client/libxrdc.a` + `client/libxrdproto*` + `LDLIBS` (mirrors the client
`Makefile` link line `apps/%.o + CLIENT_LIB + PROTO_LIB + LDLIBS`). Skip if the
static lib is absent.

- Spawns `WORKERS` pthreads. **Each thread owns one persistent GSI connection**
  (`xrdc_connect` once, kept for the worker's lifetime) — NOT the per-op checkout
  model of `xrdc_pool` (which reconnects), because the test point is sustained
  ops over a held session. (`xrdc_conn` is one-request-in-flight and not
  thread-safe, so one conn per thread is correct; `client/lib/pool.c` documents
  this contract.)
- Times every op with `xrdc_mono_ns()`; merges per-worker arrays into a global
  latency set.
- Emits JSON to stdout: `{total_ops, failures, ops_per_sec, p50_ms, p95_ms,
  p99_ms, per_worker:[{id, ops, failures, ops_per_sec}]}` and exits non-zero on
  any failure or p99 breach.
- This is the **thinnest client surface** — it isolates the pblock backend code.

### Layer (b) — Full `xrdfs` CLI chain test
Drives the real `client/bin/xrdfs` binary over GSI in `WORKERS` concurrent
sessions, each running the manifest rendered as an `xrdfs` batch script (one
process per worker, GSI auth once via `X509_USER_PROXY`, ops streamed over the
held interactive session). Validates the **entire user-facing CLI → wire → pblock
chain** under concurrency.

- Verifies criteria 1 (every `xrdfs` op returns success), 2 (catalog integrity),
  3 (server health). Latency here is coarse per-session wall-clock only — Layer
  (a) owns precise percentiles, so (b) reports aggregate ops/sec but does not gate
  on p99.

### Layer (c) — `xrddiag` client validation
Asserts the client stack is 100% correct and performant against pblock:
- `xrddiag check root://127.0.0.1:11498/` — the existing conformance battery
  (`auth`, `authenticated`, `namespace`, `dirlist`, `locate`, `checksum-works`,
  `files`, …) must come back **all-green** against the pblock backend. Any check
  failure ⇒ layer FAIL.
- **New `xrddiag metabench` subcommand** (see §7) — runs the metadata storm and
  reports ops/sec + p50/p95/p99 + pass/fail, non-zero exit on any failure or p99
  breach. Proves the clients *perform*, not just *work*.

## 7. New `xrddiag metabench` subcommand

A shipped client capability paralleling the existing `bench` (`diag_bench.c`).

- **File:** `client/apps/diag_metabench.c`; declared in `diag_internal.h`;
  dispatched in `client/apps/xrddiag.c` (`if (strcmp(sub,"metabench")==0) return
  do_metabench(&a);`) and listed in `usage()`.
- **Build:** register `apps/diag_metabench.o` alongside the other `diag_*.o`
  siblings in the client `Makefile` (the umbrella `xrddiag` link rule already
  pulls the `diag_*` siblings — see `Makefile` §“that also links the extracted
  apps/*.o siblings”).
- **Behavior:** reuses the shared op-manifest generator and the same per-thread
  persistent-GSI-conn model as Layer (a) (the manifest generator + latency
  histogram are factored into a small shared unit so the harness and the
  subcommand don't duplicate logic). Honors `xrddiag`'s standard arg/opts/cred
  parsing (`a->conn`), so `--auth`/`X509_USER_PROXY` work exactly as for `check`.
- **Output (human):**
  ```
  xrddiag metabench root://host:port/
    1000 ops, 0 fail, 4200 ops/s
    p50=1.1ms p95=3.2ms p99=6.8ms  PASS
  ```
  Exit non-zero on any failure or p99 breach (operator-runnable health gate).
- **Flags:** `--workers N`, `--ops-per-worker N`, `--p99-ceil-ms N` (defaults
  matching §3).

## 8. Code Organization

- `tests/run_pblock_meta_gsi.sh` — umbrella: fixture up, runs (a)/(b)/(c),
  catalog + health verification, combined pass/fail, cleanup on EXIT trap.
- `tests/tools/pblock_meta_bench.c` — Layer (a) harness (compiled by the script).
- `client/apps/diag_metabench.c` + `diag_internal.h` + `xrddiag.c` dispatch —
  Layer (c) subcommand.
- A small shared **op-manifest + latency** unit (header + .c) used by both the
  Layer (a) harness and `diag_metabench.c` to avoid duplicating the program and
  the percentile math. Lives under `client/lib/` (so both the test tool and the
  shipped binary can link it) or `client/apps/` if test-only linkage is cleaner —
  resolved in the plan.

Each unit has one purpose, a clear interface (manifest generator → list of ops;
latency collector → percentiles), and is testable in isolation.

## 9. Testing the Tests

Per project rule (3 tests per change: success + error + security-neg), the
umbrella script itself asserts:
- **Success:** clean run on a healthy server ⇒ all three layers green, all four
  criteria pass.
- **Error:** an injected fault (e.g. `P99_CEIL_MS=0`, or pointing at a stopped
  server) ⇒ the harness FAILS loudly (non-zero exit), proving it detects rather
  than silently passes.
- **Security-neg:** running a layer with **no/invalid `X509_USER_PROXY`** against
  the GSI-required server ⇒ auth is rejected (no ops succeed), proving the GSI
  gate is real and the suite would catch an auth regression.

## 10. Open Questions / Resolved Defaults

- Shared op-manifest unit home (`client/lib/` vs `client/apps/`) — decide in plan
  based on whether the test harness should link a production lib object.
- Exact `D`/`F` factors for `OPS_PER_WORKER` — pick in implementation to land the
  total near 1000 with a small balanced tree.

## 11. Non-Goals Recap

No data-plane benchmarking, no non-GSI auth, no WebDAV/S3, no mesh. This suite is
narrowly the **pblock metadata reliability + performance proof over GSI**, in
three layers, sharing one fixture and one deterministic op manifest.
