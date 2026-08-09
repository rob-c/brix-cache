# `src/fs/xfer/` — unified durable-transfer engine

One state machine that the four durable write/transfer paths are thin
configurations of: **normal staging**, **tape stage-out**, **proxy
write-through**, and **TPC**. It collapses four commit/abort implementations, two
external-process execution models (only one crash-safe), four metric families,
and a single access-log schema into one envelope.

Design spec:
[`docs/superpowers/specs/2026-06-28-unified-durable-transfer-engine-design.md`](../../../docs/superpowers/specs/2026-06-28-unified-durable-transfer-engine-design.md).

## Where it sits

This engine **composes** the VFS/SD seam — it is not an SD backend. All file byte
I/O still flows through `src/fs/backend/` per the
zero-data-POSIX-outside-the-backend invariant; the engine orchestrates *which*
objects move, *when* (sync/async/deny), *how* (pump vs agent), and *records the
audit*.

```
caller (S3/WebDAV/root PUT · tape RECALL · WT close FLUSH · TPC COPY)
  -> brix_stage_submit(kind, src, src_key, dst, dst_key, opts)
       policy   (../cache/writethrough_decision.c) -> SYNC | ASYNC | DENY
       move     (xfer_mover_*.c)  -> PUMP (in-proc) | AGENT (reparented argv)
       commit   (xfer_core.c)     -> atomic rename NOREPLACE (beneath-confined)
       ledger   (xfer_ledger.c)   -> existing per-kind metric + ONE access-log line
       journal  (stage_engine_journal.c)   -> durable record for async/resumable xfers
       reconcile(stage_engine_reconcile.c) -> on restart: adopt / re-drive / resume
```

## Files

| File | Role | Status |
|---|---|---|
| `xfer.h` | public contract (kinds, movers, dispositions, results) | landed |
| `xfer_mover_pump.c` | in-process SD pump (`brix_xfer_pump_objects`) | **Phase 1 ✓** |
| `xfer_mover_agent.c` | the single crash-safe reparented-agent harness | **Phase 1 ✓** |
| `xfer_spawn.c` | crash-safe synchronous reparented command runner | **Phase 4a ✓** |
| `xfer_ledger.c` | unified audit line (one record per terminal transfer) | **Phase 2 ✓** |
| `xfer_core.c` | terminal chokepoint (`brix_xfer_finish`); full envelope pending | **Phase 4b (chokepoint ✓)** |
| `stage_engine.c` / `.h` | the one async-staging front door `brix_stage_submit()` — four kinds (RECALL / FLUSH / UPLOAD / MULTIPART), generic promote loop between two SD instances | **phase-64 ✓** |
| `stage_engine_journal.c` | the durable request journal (subsumes the FRM reqfile; kind-aware records survive restart) | **phase-64 ✓** |
| `stage_engine_scheduler.c` | per-worker tick draining the queued FIFO through the mover (thread-pool offload when available) | **phase-64 ✓** |
| `stage_engine_reconcile.c` | startup recovery: replays journalled FLUSH records, resets crashed INFLIGHT→QUEUED | **phase-64 ✓** |
| `stage_request_registry.c` (+ `_mutate.c`, `_query.c`) | the SHM-backed durable request registry (request ids; QUEUED / INFLIGHT / DONE / FAILED / EXPIRED) | **phase-64 ✓** |
| `stage_waiter.c` | parks a client open on an async stage request id and wakes it on completion | **phase-64 ✓** |
| `backend_async_queue.c` | durable write-behind queue for backend **namespace** mutations (`brix_backend_async`: unlink/rmdir/rename/mkdir coalesced + journalled) — deliberately separate from the byte-transfer engine | landed |
| `xfer_resume_sweep.c` | worker-0 TTL sweep of abandoned `*.xrdresume.part` partials | landed |

The SYNC/ASYNC/DENY policy decision stayed in `../cache/writethrough_decision.c`
(a planned `xfer_policy.c` lift was overtaken by the phase-64 stage engine).

**Phase 4b-2 → phase-64 (durable core, landed).** The FRM durable queue became a
**kind-aware multi-transfer journal** and was then subsumed whole by the stage
engine: records carry `brix_stage_kind_t` (`stage_engine.h`, stable wire values
lining up 1:1 with the legacy `frm_xfer_kind_t`), dedup is per-kind, and each
consumer claims only its own records — so all transfer kinds share the one
crash-durable journal.

**Phase 4b-2b (✓ — WT async is now durable & crash-recoverable).**
- *Producer:* WT async flush enqueues a `wt` journal record before posting (gated
  on the shared journal) and marks it terminal on completion — deleted on
  success, left `FAILED` on failure (today: the FLUSH submit in
  `src/protocols/root/read/close.c` → `brix_stage_submit`).
- *Consumer (replay):* the per-worker scheduler tick (`stage_engine_scheduler.c`,
  armed from `src/core/config/process.c`) requeues `FAILED` and claims `QUEUED`
  records on startup and re-drives the flush, with a bounded attempt cap;
  `stage_engine_reconcile.c` resets crashed `INFLIGHT`→`QUEUED` generically, so a
  flush interrupted by a crash reaches the origin after a restart.

Tests: `test_xfer_wt_journal.py` (dead origin → `kind=wt, status=FAILED` record
persists) and `test_xfer_wt_replay.py` (restart re-drives it → `attempts`
increments). The "one durable file + recovery path" vision is realized for WT —
it shares the FRM queue, kind-aware.

**Phase 5 (✓ — TPC joins the unified ledger).** Correction to the original plan:
TPC runs the transfer with **in-process libcurl in a thread pool** (`src/protocols/webdav/tpc_curl.c`,
`src/protocols/webdav/tpc_thread.c`) — it does *not* fork/exec a curl binary, so there is no
SIGCHLD/SHM external-process hazard and the agent migration does not apply. The
real unification is the audit line: `tpc_thread_done` (async) and the sync
fallback (`src/protocols/webdav/tpc.c`) now call `brix_xfer_finish(BRIX_XFER_TPC, …)` — `dir=out`
for push, `dir=in` for pull, result mapped from the HTTP status. With this, **all
four kinds (stage/tape/wt/tpc) flow through the one terminal chokepoint and the
one audit log.** (TPC is client-retryable at the protocol level, so async-TPC
journaling is intentionally skipped — YAGNI. The OIDC credential `fork` in
`src/protocols/webdav/tpc_cred.c` is credential acquisition, not a transfer, and needs a
stdout-capturing primitive — out of the engine's scope.) Verified by
`tests/test_webdav_tpc.py` (kind=tpc lines: push/pull, ok/src_err).

**Phase 6 (✓ — client-driven STAGE resume + full STAGE audit coverage).** The
resume feature itself already existed: `brix_staged_open_resume` keeps an
identity-keyed, deterministically-named `.part` (`brix_make_resume_path`) that
survives a restart, so a reconnecting client (same path + principal) resumes at
the durable offset, and the final checksum is correct because it is computed at
commit from the committed file (`test_shutdown_resume.py`). The engine's
contribution was closing an **audit gap**: root:// uploads commit via
`brix_commit_staged` in `src/protocols/root/read/close.c` — *not* the `vfs_staged` path Phase 2
wired — so they (and resumed uploads, which commit there too) were invisible in
the unified log. `src/protocols/root/read/close.c` now calls `brix_xfer_finish(BRIX_XFER_STAGE,
…)` on commit (success + failure), with `principal = ctx->dn`. **All STAGE
uploads on all three protocols (S3, WebDAV, root://) now emit the unified audit
line.** `tests/test_xfer_ledger.py::test_root_upload_logs_stage_publish`.

**Polish — all done:**

- **TTL sweep (`xfer_resume_sweep.c`).** A worker-0 timer removes abandoned
  `*.xrdresume.part` partials from the stage dir once older than
  `$BRIX_UPLOAD_RESUME_TTL` (default 1 day; 0 disables), preserving fresh ones
  (age < TTL) and ignoring non-resume files. Only the flat stage dir is swept (the
  adjacent-to-destination naming is intentionally left). `tests/test_xfer_resume_sweep.py`.
- **One reconcile scan (`stage_engine_reconcile.c`).** A single shared
  journal-recovery scan (state + kind → per-record action); WT replay (requeue +
  re-drive) and the tape in-flight count run through it. The tape QUEUED *claim*
  loop stays bespoke by design — it carries a copymax budget + early-break that a
  visit-every-record helper shouldn't.

## STAGE audit coverage — every upload mode

`brix_xfer_finish(BRIX_XFER_STAGE, …)` now fires for **every** upload commit:

| Upload mode | Commit path | Wired in |
|---|---|---|
| S3 `POST` / WebDAV `PUT` | `vfs_staged_commit` | Phase 2 |
| root:// (incl. resume) | `src/protocols/root/read/close.c` | Phase 6 |
| S3 `PUT` (chunked / aio) | `s3_commit_put` (`src/protocols/s3/put_finalize.c`) | follow-on |

The S3 chunked/aio `PUT` path committed via the raw `brix_staged_commit`
without an audit line (only S3 `POST` used the audited `vfs_staged` path); that
gap is now closed — `s3_commit_put` emits the unified line (success +
`commit_err`), byte count from a confined stat of the published object (the
staged fd is closed by the body handler before commit).
`tests/test_s3_checksums.py::test_put_emits_unified_stage_audit`.

## Reload contract (§8b)

Reload is safe because the durable state is on disk and the SHM is a rebuildable
cache:

- **Journal survives reload/restart.** The reqfile is the source of truth; the
  SHM index is rebuilt from it by `frm_reconcile` at each (re)start. The index
  mutex is created via `brix_shm_table_alloc()` — the spin+yield mutex
  (invariant #10), **never** the lost-wakeup-prone POSIX-semaphore mode — so it is
  safe across reload and a stage child's exit.
- **In-flight is drained, not dropped.** nginx's standard drain finishes in-flight
  transfers on the old workers; new connections get the new config. A delegated
  transfer interrupted by the bounce is recovered exactly as after a crash
  (reconcile `STAGING`→`QUEUED` + the per-kind re-drive).
- **Config/creds re-read on reload.** New transfers use the reloaded server conf
  (origin host/port, GSI proxy for the WT origin client, policy prefixes);
  in-flight transfers stay pinned to the conf snapshot they were admitted with.
- **Observability.** In-flight delegated transfers are visible as `STAGING`
  journal records and via the existing per-kind gauges (FRM stage in-flight, WT
  flush-pending); a separate unified gauge was judged redundant.

**Phase 4a (done).** Write-through's GSI origin upload moved off `posix_spawn`
onto `xfer_spawn.c`'s reparented runner (nginx never reaps the child — closing the
same SIGCHLD/SHM master-crash hazard the FRM agent was built for), and WT joined
the unified ledger (`kind=wt`, sync + async). `tests/test_xfer_spawn.py` +
`tests/test_cache_write_through.py`.

**Phase 4b (landed, superseded by phase-64).** `xfer_core.c`'s
`brix_xfer_finish()` is the single terminal chokepoint all kinds call
(consolidated 7 inline ledger-emit blocks). The durable core planned here as
`xfer_journal`/`xfer_reconcile`/`xfer_policy` landed instead as the phase-64
stage engine (`stage_engine_{journal,scheduler,reconcile}.c` +
`stage_request_registry*`), with the policy decision staying in
`../cache/writethrough_decision.c`. See
[`docs/refactor/phase-64-fully-tiered-composable-storage.md`](../../../docs/refactor/phase-64-fully-tiered-composable-storage.md) §11.

### The audit line (Phase 2)

Sink: `$BRIX_XFER_AUDIT_LOG`, else `<prefix>/logs/xfer_audit.log`. One
append-only line per terminal transfer, atomic across workers (O_APPEND,
sub-PIPE_BUF):

```
<ts> kind=stage dir=in result=ok bytes=29 errno=0 principal=- path="/data/obj"
```

Wired into STAGE commit (`src/fs/vfs/vfs_staged.c`): `result=ok` on publish,
`result=commit_err` on a failed publish. Metrics are unchanged (each caller still
books its own — STAGE still books `OP_WRITE`); the ledger adds only the unified
line. `principal=` is `-` until identity threading lands; abort-line emission
lands with `xfer_core` in Phase 3 (proper terminal-cause vocabulary). Covered by
`tests/test_xfer_ledger.py` (ok / commit_err / control-byte-escaping).

## Durability (spec §7–§8)

- **Server-driven** (TAPE/WT/TPC): reqfile = truth; full crash → autonomous
  re-drive on restart. The agent writes its terminal result durably so a restart
  can always recover the outcome.
- **Client-driven** (STAGE uploads): the partial `.part` + a fsync'd resume
  sidecar survive; resume is client-initiated and validated; the server never
  publishes a partial object and never zeroes a resumable `.part`.
- The journal and staging dirs must live on storage that survives
  crash/restart/container recreation; ephemeral storage degrades durability to
  best-effort (startup WARN).

### Other files

| File | Responsibility |
|---|---|
| `stage_engine_internal.h` | Declares the module-private durable-request vocabulary (the in-memory pending item, the per-worker journal directory) and the cross-file entry points — reqid minting, journal write/remove, and the generic inline mover —. |
| `xfer_spawn_unittest.c` | standalone unit test for the reparented command runner. |
