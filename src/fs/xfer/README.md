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
caller (S3/WebDAV/root PUT · FRM stage · WT close · TPC COPY)
  -> xrootd_xfer_begin(ctx, kind, src, dst, policy)
       policy   (xfer_policy.c)   -> SYNC | ASYNC | DENY
       move     (xfer_mover_*.c)  -> PUMP (in-proc) | AGENT (reparented argv)
       commit   (xfer_core.c)     -> atomic rename NOREPLACE (beneath-confined)
       ledger   (xfer_ledger.c)   -> existing per-kind metric + ONE access-log line
       journal  (xfer_journal.c)  -> durable record for async/agent/resumable xfers
       reconcile(xfer_reconcile.c)-> on restart: adopt / re-drive / register-resume
```

## Files

| File | Role | Status |
|---|---|---|
| `xfer.h` | public contract (kinds, movers, dispositions, results) | landed |
| `xfer_mover_pump.c` | in-process SD pump (`xrootd_xfer_pump_objects`) | **Phase 1 ✓** |
| `xfer_mover_agent.c` | the single crash-safe reparented-agent harness | **Phase 1 ✓** |
| `xfer_spawn.c` | crash-safe synchronous reparented command runner | **Phase 4a ✓** |
| `xfer_ledger.c` | unified audit line (one record per terminal transfer) | **Phase 2 ✓** |
| `xfer_core.c` | terminal chokepoint (`xrootd_xfer_finish`); full envelope pending | **Phase 4b (chokepoint ✓)** |
| `xfer_policy.c` | SYNC/ASYNC/DENY decision (from writethrough_decision) | Phase 4b |
| `xfer_journal.c` | durable reqfile + SHM cache (from frm/queue) | Phase 4b-2 (substrate ✓) |
| `xfer_reconcile.c` | startup recovery across all kinds (from frm/reconcile) | Phase 4b-2 |

**Phase 4b-2 (durable core, in progress).** The FRM durable queue is now a
**kind-aware multi-transfer journal**: each record carries `frm_xfer_kind_t`
(`frm_format.h`, carved from reserved → no format bump, old records read as
tape), dedup is per-kind, and the tape drain claims only tape records — so other
transfer kinds can share the one crash-durable file. Behaviour-preserving for
tape (29 FRM tests green).

**Phase 4b-2b (✓ — WT async is now durable & crash-recoverable).**
- *Producer:* WT async flush enqueues a `wt` journal record before posting (gated
  on the shared FRM queue) and marks it terminal on completion — deleted on
  success, left `FAILED` on failure (`writethrough_flush.c`).
- *Consumer (replay):* a per-worker scheduler (`writethrough_replay.c`, armed from
  `config/process.c`) requeues `FAILED` and claims `QUEUED` `wt` records on
  startup and re-drives the flush via the existing async machinery, with a bounded
  attempt cap. master-side `frm_reconcile` already resets crashed `STAGING`→
  `QUEUED` generically, so a flush interrupted by a crash reaches the origin after
  a restart.

Tests: `test_xfer_wt_journal.py` (dead origin → `kind=wt, status=FAILED` record
persists) and `test_xfer_wt_replay.py` (restart re-drives it → `attempts`
increments). The "one durable file + recovery path" vision is realized for WT —
it shares the FRM queue, kind-aware.

**Phase 5 (✓ — TPC joins the unified ledger).** Correction to the original plan:
TPC runs the transfer with **in-process libcurl in a thread pool** (`tpc_curl.c`,
`tpc_thread.c`) — it does *not* fork/exec a curl binary, so there is no
SIGCHLD/SHM external-process hazard and the agent migration does not apply. The
real unification is the audit line: `tpc_thread_done` (async) and the sync
fallback (`tpc.c`) now call `xrootd_xfer_finish(XROOTD_XFER_TPC, …)` — `dir=out`
for push, `dir=in` for pull, result mapped from the HTTP status. With this, **all
four kinds (stage/tape/wt/tpc) flow through the one terminal chokepoint and the
one audit log.** (TPC is client-retryable at the protocol level, so async-TPC
journaling is intentionally skipped — YAGNI. The OIDC credential `fork` in
`tpc_cred.c` is credential acquisition, not a transfer, and needs a
stdout-capturing primitive — out of the engine's scope.) Verified by
`tests/test_webdav_tpc.py` (kind=tpc lines: push/pull, ok/src_err).

**Phase 6 (✓ — client-driven STAGE resume + full STAGE audit coverage).** The
resume feature itself already existed: `xrootd_staged_open_resume` keeps an
identity-keyed, deterministically-named `.part` (`xrootd_make_resume_path`) that
survives a restart, so a reconnecting client (same path + principal) resumes at
the durable offset, and the final checksum is correct because it is computed at
commit from the committed file (`test_shutdown_resume.py`). The engine's
contribution was closing an **audit gap**: root:// uploads commit via
`xrootd_commit_staged` in `read/close.c` — *not* the `vfs_staged` path Phase 2
wired — so they (and resumed uploads, which commit there too) were invisible in
the unified log. `read/close.c` now calls `xrootd_xfer_finish(XROOTD_XFER_STAGE,
…)` on commit (success + failure), with `principal = ctx->dn`. **All STAGE
uploads on all three protocols (S3, WebDAV, root://) now emit the unified audit
line.** `tests/test_xfer_ledger.py::test_root_upload_logs_stage_publish`.

**Polish — all done:**

- **TTL sweep (`xfer_resume_sweep.c`).** A worker-0 timer removes abandoned
  `*.xrdresume.part` partials from the stage dir once older than
  `$XROOTD_UPLOAD_RESUME_TTL` (default 1 day; 0 disables), preserving fresh ones
  (age < TTL) and ignoring non-resume files. Only the flat stage dir is swept (the
  adjacent-to-destination naming is intentionally left). `tests/test_xfer_resume_sweep.py`.
- **One reconcile scan (`xfer_reconcile.c`).** `xrootd_xfer_journal_foreach`
  (status + kind → per-record callback) is the single shared journal-recovery
  scan; WT replay (requeue + re-drive) and the tape in-flight count run through
  it. The tape QUEUED *claim* loop stays bespoke by design — it carries a copymax
  budget + early-break that a visit-every-record helper shouldn't.

## STAGE audit coverage — every upload mode

`xrootd_xfer_finish(XROOTD_XFER_STAGE, …)` now fires for **every** upload commit:

| Upload mode | Commit path | Wired in |
|---|---|---|
| S3 `POST` / WebDAV `PUT` | `vfs_staged_commit` | Phase 2 |
| root:// (incl. resume) | `read/close.c` | Phase 6 |
| S3 `PUT` (chunked / aio) | `s3_commit_put` (`s3/put_finalize.c`) | follow-on |

The S3 chunked/aio `PUT` path committed via the raw `xrootd_staged_commit`
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
  mutex is created via `xrootd_shm_table_alloc()` — the spin+yield mutex
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

**Phase 4b (in progress).** `xfer_core.c`'s `xrootd_xfer_finish()` now is the
single terminal chokepoint all kinds call (consolidated 7 inline ledger-emit
blocks). Remaining 4b — the durable core — is the deepest, riskiest work and is
sequenced as its own cycle (touches the on-disk reqfile format + master-crash
recovery, needs kill-9 crash tests): generalize `frm/queue`→`xfer_journal` and
`frm/reconcile`→`xfer_reconcile` **with WT async as the second consumer** (making
WT async flush durable/crash-recoverable, today it is fire-and-forget), lift
`writethrough_decision`→`xfer_policy`, and the reload contract.

**Sequencing (consumer-driven).** The audit chokepoint landed first (Phases 2–3:
STAGE + TAPE on the unified ledger). The durable core — `xfer_core`,
`xfer_policy`, `xfer_journal` (from `frm/queue`), `xfer_reconcile` (from
`frm/reconcile`) — is built in **Phase 4**, when WT migration provides the
*second* consumer that validates each abstraction (FRM already has working
versions). This avoids generalizing the master-crash / crash-recovery path around
a single consumer. See the spec §9.

### The audit line (Phase 2)

Sink: `$XROOTD_XFER_AUDIT_LOG`, else `<prefix>/logs/xfer_audit.log`. One
append-only line per terminal transfer, atomic across workers (O_APPEND,
sub-PIPE_BUF):

```
<ts> kind=stage dir=in result=ok bytes=29 errno=0 principal=- path="/data/obj"
```

Wired into STAGE commit (`fs/vfs_staged.c`): `result=ok` on publish,
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
