# Phase 33 — Performance Optimization (post feature-complete)

**Status:** P2 + P3-B2 + P4-D1 IMPLEMENTED (2026-06-13); P0/P1/P3-B1,B3/P5 still open
**Author:** perf audit, 2026-06-13
**Predecessors:** [phase-29 read-throughput bottlenecks](../_archive/refactor/phase-29-read-throughput-bottlenecks.md),
[phase-32 data-plane perf-parity](phase-32-data-plane-perf-parity.md)

---

## GSI "host-load flakiness" — root cause (2026-06-13): an ENVIRONMENT collision

`test_concurrent.py` GSI/GSI-TLS tests fail (only when batched) with "No protocols
left to try" / "TLS error: resource temporarily unavailable". After a full
investigation (parallel diagnosis workflow + adversarial critic + live reproduction)
the **proven** root cause is NOT a server bug and NOT a concurrency wedge:

> **`tests/run_load_test.sh` does `rm -rf /tmp/xrd-test/pki` and always regenerates
> the PKI + restarts the shared fleet. When it runs concurrently with the pytest
> suite (whose conftest fleet serves GSI from that same `/tmp/xrd-test/pki` on the
> same fixed ports), the sweep wipes the certs out from under the running GSI
> servers mid-handshake** → cert-generation mismatch → `tlsv1 alert unknown ca`
> (:11096), "No protocols left to try" (:11095), and `[emerg] hostcert.pem ... No
> such file`.

Proof: the `emerg-hostcert` timestamps coincide with the sweep's regen cycles during
the failing batch; **`test_baseline_single_gsi` (N=1) fails** (rules out any
concurrency wedge); and a focused N=16 plain-GSI + N=16 GSI-TLS handshake burst
(`tests/test_gsi_concurrency.py`) **passes** in a standalone run that doesn't overlap
a sweep regen. The earlier "deterministic 2/2 batch failure" reported by the
diagnosis workflow/critic was measured with this sweep running the whole time — i.e.
the reproduction was the collision, not an intrinsic defect.

**Operator guidance (the fix, by decision):** run the `run_load_test.sh` sweep OR the
pytest functional suite — never both against `/tmp/xrd-test` at once. Documented in
the `run_load_test.sh` header and `test_gsi_concurrency.py`.

### Server hardening landed alongside (correct on its own merits; NOT the flake cure)

These were built while chasing a (mis)hypothesized server concurrency bug; the N=1
failure later proved that wasn't the cause. They are kept because each is a genuine
latent improvement, and are validated (build clean; GSI 13/13; N=16 bursts pass):

- **GSI ephemeral-DH key pool** (`src/gsi/keypool.c` + `keypool.h`, registered in
  `config`): a per-worker warm pool of pre-generated ffdhe2048 keys, refilled
  off-thread (`ngx_thread_task` into task-local storage; only the event thread
  mutates the pool), so `kXGC_certreq` no longer runs `EVP_PKEY_keygen` on the nginx
  event thread (head-of-line blocking removed). Warmed in
  `ngx_stream_xrootd_init_process` (gated on gsi/both); popped with inline fallback
  in `cert_response.c`. Tunables `XROOTD_GSI_KEYPOOL_{SIZE,REFILL_LOW,REFILL_BATCH}`
  (64/32/32). Keygen is only ~0.3 ms (`openssl speed ffdh2048`), so this is robustness
  under load, not a single-stream win.
- **`ERR_clear_error()`** at the top of `xrootd_handle_auth` (`src/gsi/auth.c`) and
  `xrootd_start_tls` (`src/connection/tls.c`): closes the OpenSSL per-thread
  error-queue leak (there were zero `ERR_clear_error` in `src/`) that can make nginx
  misreport benign TLS closes as handshake failures under mixed GSI+TLS traffic.

---

## Implementation status (2026-06-13)

Landed this pass — the per-request fixed-cost cuts (P2) + the two cheap config/build
items, all gated by the correctness suites (throughput validation is deferred to a
real perf host per P0; none of these is throughput-validatable on WSL2):

| Item | Status | Where |
|---|---|---|
| **P4-D1** build default | **DONE** | `config`: `XROOTD_OPTIMIZE` defaults to `-O3 -march=x86-64-v2 -fno-plt` (RHEL-9 baseline ISA); `v3`/`native` opt-in; `none/off/0` escape hatch. Hardening flags still unconditional. |
| **P3-B2** output_buffers | **DONE (already in place)** | `tests/configs/nginx_shared.conf` already sets `output_buffers 2 256k` at `http{}` (inherited by WebDAV/S3). `nginx.perf.conf`'s `1 128k` is an intentional TLS match — left as-is. No `config/` sample dir exists. |
| **P2-C4** rate-limit key memo | **DONE** | `XROOTD_RL_RULE_CACHE_MAX` (`tunables.h`); `rl_key_cache`/`rl_key_cache_valid` on `xrootd_ctx_t`; `xrootd_rl_stream_gate` caches identity-stable keys (IP/VO/ISSUER/DN), never VOLUME; skips `rl_request_path` when no VOLUME rule. 3 tests in `test_phase25_ratelimit.py`. |
| **P2-C2** bound-handle cache | **DONE** | `xrootd_file_t.shared_handle_slot_hint`; `xrootd_session_handle_lookup_hint` (handles.c) checks the cached slot under the lock before scanning — O(1), full `in_use`+key revocation check preserved. 3 tests in `test_session_bind.py` (incl. primary-close revocation). |
| **P2-C1** access-log batching | **DONE** | Per-worker buffer in `path/access_log.c`; flush on buffer-full/fd-switch/1s timer/`xrootd_on_disconnect`/worker-exit-via-disconnect. 4 tests in `test_access_log_batch.py` (incl. control-byte sanitisation). |

**Premise corrections (verified in code during implementation):**
- **C1 off-case was already free** — `read.c` gates the format work behind
  `access_log_fd != NGX_INVALID_FILE` *before* the `snprintf`. The only remaining
  C1 win was batching the *on* case (done).
- **C3 was already gated** — the dashboard slot updates are already skipped by
  `dashboard_slot >= 0 && shm_zone != NULL`. No early-out work was needed; the
  residual atomic-collapse is low-value and **was dropped**.

**Still open (need the P0 perf host):** P0 (perf host + regression gate), P1
(`XROOTD_PIPELINE_MAX` raise + the deferred concurrent-AIO recv flip — the highest
leverage item, but unvalidatable for throughput on WSL2), P3-B1/B3 (sendfile span /
`SO_SNDBUF`), P5 (TLS path / kTLS-on-HW-offload). These remain hypotheses until
measured on real hardware.

---

## Context

The project is now feature-complete (root:// / WebDAV / S3 / CMS / TPC / auth / rate-limit /
metrics / mirror, plus the Phase-28 security hardening). The historical claim is that this
module out-performed native XRootD by **~2×** on the same hardware; current n=1 benchmarks
show only **parity**. This document audits where that lead eroded and proposes a prioritized
optimization roadmap.

### Two honest framing points first

1. **The "2× → parity" story is partly real and partly a measurement artifact.** Phase-29
   already established that the original "nginx 0.5× slower" reading was a TLS-vs-cleartext
   apples-to-oranges error, and that cleartext n=1 single-stream is **at parity** today
   (sendfile pipelining + warm-cache `preadv2(RWF_NOWAIT)` landed in Phase 32 WS2/WS4). So the
   single-stream cleartext read path is *not* 2× behind — it's even. The 2× lead, where it
   existed, was about **sustained / concurrent** throughput and a **leaner per-request hot
   path**, both of which feature accretion has dented.

2. **Every recent benchmark on this box is suspect.** The dev host is WSL2 loopback
   (`6.18.6-WSL2`), OOM-prone, virtualised networking, and was running 4–6 server cycles
   back-to-back. Absolute numbers drifted 1500→900 MiB/s across runs for *both* servers, and
   kTLS was outright broken here. **No throughput conclusion from this host is trustworthy.**
   A real perf host is a prerequisite for this whole phase (P0 below), not an afterthought.

---

## What is already done (don't redo)

From Phase 29 / Phase 32 (verified in code):

- **Cleartext sendfile + single/multi-chunk pipelining** — `src/read/read.c:131`,
  `src/aio/buffers.c:332,550`; `resp_pipelinable=1` for ≤16 MiB and >16 MiB sendfile reads.
- **Warm-cache inline fast path** — `read.c:312` `preadv2(…,RWF_NOWAIT)`; full page-cache hit
  completes inline without the thread-pool hop.
- **Per-slot response headers** (WS2) — `XROOTD_SLOT_HDR_MAX`, multi-chunk byte-exact.
- **Fair benchmark posture** — `--data-tls {on,off}`, cleartext-vs-cleartext default.
- **reuseport teardown** reaps the worker process group (no orphaned listeners).
- **Build hardening at no measured hot-path cost** — `-D_FORTIFY_SOURCE=2`,
  `-fstack-protector-strong`, `-fstack-clash-protection`, `-fcf-protection=full` (`config:16`);
  opt-in `-O3 -march=x86-64-v{2,3}` via `XROOTD_OPTIMIZE` (`config:33-43`).
- **kTLS** implemented but correctly **off by default** — regresses on software TLS and is
  broken on this WSL2 kernel.

The per-read hot path is already fairly lean: **auth/ACL/token checks and the
`openat2(RESOLVE_BENEATH)` confinement run at OPEN, not per read** (`auth_gate.c`,
`open_request.c:416`; `read.c` has no auth calls). So Phase-28 security did **not** tax the
steady-state read.

---

## Root-cause analysis: where the lead eroded

Ranked by estimated leverage on sustained throughput.

### A. Structural — concurrency path is the dominant ceiling

- **A1. Pipeline depth capped at 4.** `XROOTD_PIPELINE_MAX = 4` (`tunables.h:70`); the recv
  gate (`recv.c:404-408`) keeps reading the next request only while `out_count < 4`. Native
  XRootD keeps far more reads in flight. On any non-trivial RTT this caps single-stream
  bandwidth well below line rate. **Highest-leverage structural item.**
- **A2. Concurrent-AIO recv flip deferred (Phase 32 WS3).** The per-connection pool of read
  buffers/tasks landed, but the recv state-machine flip that would let multiple cold reads
  execute concurrently was deferred (unvalidatable on WSL2). This is the change that turns
  the 4-slot pipeline from "4 sequential sendfiles" into "4 overlapping disk reads + sends".
- **A3. Pipelineability gate is narrow.** Any non-`kXR_read` opcode arriving mid-stream defers
  recv (`recv.c:368-372`), collapsing the pipeline to depth 1 for mixed-opcode workloads
  (readv interleaved with stat/close, multi-file clients).

### B. Constant-factor — fewer, larger syscalls

- **B1. 16 MiB sendfile chunk split.** `XROOTD_READ_CHUNK_MAX = 16 MiB` (`tunables.h:31`);
  a 64 MiB read becomes 4 `sendfile(2)` calls (`buffers.c:525`). XRootD issues one. Minor per
  read, but it compounds at high op rates.
- **B2. `output_buffers 1 128k`** in the WebDAV location vs the documented `2 256k` bundle —
  more `pread`/`sendfile` syscalls per bulk GET on the HTTP path.
- **B3. No `SO_SNDBUF` sizing / `sendfile_max_chunk`** (Phase-29 R4, never implemented).

### C. Per-request fixed cost — the "lean hot path" tax

These are small individually but are exactly the kind of accretion that turns a 2× lead into
parity, and several lack a cheap "feature-off" early-out:

- **C1. Access logging formats + `write(2)` synchronously per read** when enabled
  (`read.c:180-186`): stack buffer + `snprintf` + per-read `write`. No batching, no
  precomputed "logging off" skip before formatting.
- **C2. Bound-secondary handle validation takes a mutex + SHM lookup *per read***
  (`fd_table.c:358-386` → `session/registry.c:203`, `ngx_shmtx_lock`). Fine for the common
  unbound case (array check), expensive for `xrdcp --sources` parallel streams.
- **C3. Always-on metric atomics + dashboard slot updates** (`read.c:103,166-177`): 1–4
  atomics/read; the dashboard block has no early-out when the dashboard is disabled.
- **C4. Rate-limit gate** is cheap when no rules (`ratelimit_stream.c:83`), but when rules
  exist it re-extracts the path and re-hashes the key **per request** with no per-connection
  memoization.

### D. Build / TLS posture

- **D1. Redistributable builds don't get `-O3 -march` by default** (opt-in only); no LTO/PGO.
- **D2. TLS reads** without kTLS go through the memory path + thread-pool hop
  (`vfs_read.c:199` forces the memory chain when `is_tls`); fine functionally, but the per-read
  thread hop is the TLS path's main constant cost (Phase-29 R5, never modernized).

---

## The plan

### P0 — Trustworthy measurement (prerequisite, blocks everything)

Nothing below can be validated on WSL2 loopback. Stand up a **bare-metal / proper-VM perf
host** and make perf a gated, repeatable signal:

- Run the existing `tests/run_load_test.sh` matrix there: cleartext root:// and S3 (data-plane
  truth), plus userspace-TLS WebDAV, at n = 1, 8, 32, 128, both read and write, ≥10 samples →
  medians + variance.
- Add a **perf regression gate**: capture a baseline JSON (`load_test.py --json`), fail CI if
  median throughput drops > X% vs baseline. This is what would have caught the erosion as it
  happened.
- Record the **native-XRootD baseline on the same host** for every protocol so "2×" is a
  measured target, not a memory.

**Until P0 exists, treat A2/B1 effects as hypotheses.**

### P1 — Concurrency path (the structural lead) — *highest leverage*

1. **Raise `XROOTD_PIPELINE_MAX` 4 → 16 (tunable), measure 8/16/32.** One-line change
   (`tunables.h:70`) but it widens `out_count` ring use; verify the slot-header array
   (`XROOTD_SLOT_HDR_MAX`) and per-connection scratch backstop (`XROOTD_CONN_XFER_HEAP_MAX`,
   8 MiB) scale with it — raising depth must not blow the per-connection heap cap.
2. **Complete Phase-32 WS3: the recv state-machine flip for concurrent AIO.** Let up to N cold
   reads be submitted to the thread pool and their sendfiles complete out-of-order into the
   response ring, instead of strictly serializing. This is the change that makes depth>1
   actually overlap disk + network. Touches `recv.c` (state machine), `aio/reads.c`,
   `aio/buffers.c`. Highest risk; do it behind the P0 harness with the readv/pgread integrity
   matrix as the gate. **Mandatory full recompile after any `context.h`/`tunables.h` struct
   change** (the phase-29 mixed-ABI blocker — `find src -name '*.c' -exec touch {} +`).
3. **Widen the pipelineability gate (A3):** allow recv to continue across a bounded number of
   cheap interleaved opcodes (stat/close) without collapsing the read pipeline, where ordering
   is safe.

### P2 — Per-request fixed-cost reduction (reclaim the lean hot path)

Precompute one-time per-connection booleans at open/login and branch on them, so a fully-
featured build pays nothing for features a given server block doesn't use:

1. **C1 access log:** add a `ctx`-level `access_log_on` flag; skip the `snprintf`/format
   entirely when off. When on, **batch** to a per-worker buffer flushed on event-loop idle
   instead of a per-read `write(2)` (Phase-29 R4 / Phase-32 WS5 follow-up).
2. **C2 bound-secondary handle cache:** cache the resolved handle metadata on the ctx after
   the first lookup so steady-state reads on a bound stream skip the `ngx_shmtx_lock` + SHM
   scan (`fd_table.c:358`).
3. **C3 dashboard/metrics:** add an early-out before the dashboard slot block when the
   dashboard zone is absent; keep the op-counter atomic (cheap, useful) but collapse the
   read-path atomics to one where possible.
4. **C4 rate-limit memoization:** when rules exist, cache the extracted key/path on the ctx for
   the connection's lifetime (identity is fixed per connection) instead of re-extracting per
   request.

Each item is independently shippable, low-risk, and individually small — but collectively they
are the "death by a thousand cuts" that a feature-complete build accumulated.

### P3 — Larger I/O spans / fewer syscalls

1. **B1:** issue a single `sendfile` span per read where the wire framing allows (treat the
   16 MiB chunk as a *framing* boundary, not an *I/O* boundary) — or raise
   `XROOTD_READ_CHUNK_MAX` and measure. 
2. **B2:** apply `output_buffers 2 256k` to the HTTP/WebDAV+S3 locations (currently `1 128k`),
   matching the documented WS5 bundle.
3. **B3:** add `SO_SNDBUF` sizing and evaluate `sendfile_max_chunk`; size send buffers to the
   bandwidth-delay product for the deployment.

### P4 — Build: redistributable performance defaults

1. **D1:** make `-O3 -march=x86-64-v2 -fno-plt` the **default** for release builds (it's the
   RHEL-9 baseline ISA; keep `v3`/`native` opt-in), since the audit shows the hardening flags
   cost nothing measurable on the hot path.
2. Evaluate **LTO** (`-flto=auto`) and a **PGO** profile from the load-test workload — both are
   plausible single-digit-% wins on a syscall-light, branch-heavy event loop; measure under P0
   before adopting.

### P5 — TLS path

1. **Keep kTLS off unless NIC TLS offload is verified** (`ethtool -k | grep tls` →
   `TlsTxDevice`). Gate the `xrootd_ktls` directive / `Options KTLS` behind a documented
   "HW-offload only" note; software kTLS regresses and is broken on WSL2.
2. **D2 (optional, larger):** modernize the TLS memory-read path with batched / `io_uring`
   submission so a multi-window TLS read doesn't pay a per-window thread-pool hop
   (Phase-29 R5). Only worth it if P0 shows the TLS path is a real deployment bottleneck;
   userspace TLS already measured ~1620 MiB/s (ahead of XrdHttp) in the isolated A/B.

---

## Sequencing

1. **P0** (perf host + regression gate) — *blocks meaningful work on the rest.*
2. **P2** (per-request fixed-cost) — low risk, individually shippable, reclaims the lean path;
   safe to land incrementally even before P0 is perfect.
3. **P3 + P4** (syscall spans, build defaults) — cheap, measurable wins.
4. **P1** (pipeline depth + concurrent-AIO recv flip) — highest leverage *and* highest risk;
   do it last, gated by the P0 harness and the full read/readv/pgread integrity matrix.
5. **P5** — situational; only if P0 shows TLS is a deployment-relevant bottleneck.

## Expected outcome

If P0 confirms the hypotheses, the recoverable lead is concentrated in **P1** (concurrency
depth + AIO overlap → the sustained/concurrent throughput where the 2× originally lived) and
**P2** (restoring the lean per-request path). P3/P4 are steady single-digit-% gains. The
write-side advantage already observed (nginx WebDAV PUT ≈ 2.5× XrdHttp) suggests the
architecture is sound; the read lead is reclaimable by finishing the deferred concurrency work
rather than by a rewrite.

## Risks & invariants

- **Struct-layout recompile rule:** any edit to `context.h` / `tunables.h` requires a full
  `make` (touch all `.c`) — the phase-29 readv/read_scratch "corruption" was a stale-ABI build,
  not a bug.
- **Security invariants hold:** P1/P2/P3 must not move auth/confinement off the open path or
  weaken the `RESOLVE_BENEATH` boundary; per-read fast paths operate on already-authorized open
  handles only.
- **Correctness gate:** the read/readv/pgread byte-exact + conformance suites are the
  non-negotiable gate for any P1 change.
