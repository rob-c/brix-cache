# Unified Durable-Transfer Engine (`xrootd_xfer`) — Design Spec

**Date:** 2026-06-28
**Status:** Implemented (phases 1–6) + polish complete. Three core goals
delivered — one crash-safe external-exec path, one unified audit log over
stage/tape/wt/tpc, one durable journal + crash recovery shared by tape +
write-through. Polish done: TTL sweep of abandoned resume partials
(`xfer_resume_sweep.c`), the single shared recovery scan (`xfer_reconcile.c`), and
an explicit reload contract (§8b, documented in `src/fs/xfer/README.md` — the SHM
index already uses the safe spin+yield mutex, file=truth + reconcile rebuilds it,
nginx drains in-flight). See `src/fs/xfer/README.md` for the per-component state.
**Author:** Rob Currie (brainstormed with Claude)

## 1. Problem

Four parallel subsystems each re-implement the same "durable write/transfer"
shape — a begin → move-bytes → commit/abort lifecycle that should be crash-safe
and auditable — with their own confinement, error mapping, async scheduling, and
(critically) their own audit surface:

| Path | Source → Dest | Commit primitive | Audit |
|---|---|---|---|
| Normal staging (`fs/vfs_staged.c`, `compat/staged_file.c`) | client stream → local object | temp `O_EXCL` → `rename` NOREPLACE (beneath-confined) | `OP_WRITE` on commit (added retroactively) |
| Tape staging (`frm/stage.c`, `fs/vfs_scratch.c`) | tape copycmd → local (via scratch) | claim `QUEUED→STAGING` → copycmd → ONLINE/FAILED | `frm/metrics.c` |
| Proxy write-through (`cache/writethrough_*.c`) | local cache file → remote origin | open-time DENY/SYNC/ASYNC → close-time `posix_spawn` client | `writethrough_metrics.h` + `xrootd_log_access "WT"` |
| TPC (`webdav/tpc*.c`) | remote → local/remote | curl COPY | `tpc.c` counters |

Costs: four commit/abort/rollback implementations (four places crash-safety can
be wrong); four metric families with inconsistent labels and only one path
emitting an access-log line (fragmented auditing); and **two distinct
external-process execution models** — FRM's double-fork/reparent/self-reap
stage-agent vs write-through's `posix_spawn`-at-close — where only the former is
protected against the SIGCHLD/SHM master-crash hazard (see
`docs/09-developer-guide/postmortem-shmtx-semaphore-stall.md` and the FRM fork
postmortem). The `posix_spawn` path is a latent recurrence of that crash.

The substrate is *already* partly shared: `stage_move_objects` (SD backend↔backend
mover, `compat/staged_file.c`) and `vfs_scratch` both reuse `xrootd_commit_staged`.
What is fragmented is the **lifecycle envelope, the audit record, the async
durability, and the external-exec safety**.

## 2. Goal

One first-class transfer engine, `src/fs/xfer/`, that all four paths are thin
configurations of. Reduces support burden (one commit/abort, one fork/reap, one
reconcile path) and auditing burden (one access-log schema). Survives full
nginx/system/container restart or crash, and **resumes** in-flight transfers when
the client cooperates.

Honors the project HARD BLOCKS: no `goto`; functional/modular (one job per
function, explicit `ctx`, no new globals, table/descriptor-driven dispatch);
3 tests per change (success + error + security-neg); helpers reused never
reimplemented; SHM tables via `xrootd_shm_table_alloc()` (spin+yield, never the
POSIX-semaphore mode — invariant #10).

## 3. Architecture & core state machine

New home `src/fs/xfer/` composes the VFS/SD seam (it is **not** an SD backend;
data byte I/O still routes through `src/fs/backend/` per the
zero-data-POSIX-outside-the-backend invariant). Public contract:

```c
typedef enum { XFER_STAGE, XFER_TAPE, XFER_WT, XFER_TPC } xrootd_xfer_kind_t;
typedef enum { XFER_MOVE_PUMP, XFER_MOVE_AGENT }          xrootd_xfer_mover_t;
typedef enum { XFER_SYNC, XFER_ASYNC, XFER_DENY }         xrootd_xfer_disp_t;
typedef enum { XFER_OK, XFER_DEFERRED, XFER_DENIED,
               XFER_SRC_ERR, XFER_DST_ERR, XFER_COMMIT_ERR,
               XFER_AGENT_FAIL } xrootd_xfer_result_t;

typedef struct {
    xrootd_xfer_kind_t   kind;
    xrootd_xfer_endpt_t  src;        /* SD object | external-source argv spec */
    xrootd_xfer_endpt_t  dst;        /* SD object | final confined path       */
    xrootd_xfer_mover_t  mover;
    void                *principal;  /* who — for the ledger line             */
} xrootd_xfer_t;
```

State machine — one function per state, explicit data flow, table-driven kind/
mover dispatch (no `goto`, early-return):

```
xrootd_xfer_begin(ctx, *xfer)
   → policy (§5): disposition = SYNC | ASYNC | DENY
   → DENY?   ledger + return XFER_DENIED
   → ASYNC?  journal-enqueue (§4) + return XFER_DEFERRED
   → MOVE (§2): pump | agent
   → COMMIT: atomic publish (rename NOREPLACE, beneath-confined) | ABORT: cleanup
   → LEDGER (§3): one metric (existing name) + one access-log line
```

`xfer_core.c` owns BEGIN/COMMIT/ABORT and maps internal failures to the single
`xrootd_xfer_result_t`; each protocol edge maps that to its wire status via the
existing errno→kXR→HTTP table — no new error vocabulary at the edges.

**Files (new):** `src/fs/xfer/xfer.h`, `xfer_core.c`, `xfer_mover_pump.c`,
`xfer_mover_agent.c`, `xfer_ledger.c`, `xfer_policy.c`, `xfer_journal.c`,
`xfer_reconcile.c` + `README.md`. Registered in top-level `./config`
(`$ngx_addon_dir/src/fs/xfer/*.c`), not `src/config/config.h`.

## 4. Movers — the crash-safety unification

- **`xfer_mover_pump.c`** — thin wrapper over existing `stage_move_objects`
  (SD `pread→pwrite`). Used by sync STAGE and any SD↔SD case. Extracted, not
  rewritten.
- **`xfer_mover_agent.c`** — the **crown-jewel extraction**: FRM's
  double-fork → reparent-to-init → socketpair → self-reap harness (today inside
  `frm/stage.c`) lifted into a reusable mover that runs an arbitrary argv and
  reports a terminal result. TAPE `copycmd`, write-through origin client
  (migrated off `posix_spawn`), and TPC `curl` all become argv specs fed to this
  one harness. Result: **exactly one fork/reap path in the codebase**; the
  `posix_spawn` SIGCHLD/SHM hazard is erased by construction.

  The agent additionally writes its **terminal result durably to the journal
  (result file keyed by reqid)**; the socketpair is the low-latency path for the
  no-restart common case, not the only path to the outcome.

## 5. Policy unification

`cache/writethrough_decision.c`'s DENY / ALLOW_SYNC / ALLOW_ASYNC prefix/size
engine is already a generic "where/when does this write land" decision. It moves
to `xfer_policy.c` and becomes the disposition source for all kinds: write-through
= dst is remote origin; tape stage-out = dst is tape; normal staging = dst is
local, always SYNC. Prefix-matching helpers reused unchanged. A custom decision
fn remains pluggable via config (as today).

## 6. Ledger — the auditing win

`xfer_ledger.c`. Every COMMIT/ABORT (sync or async, including reconcile-completed)
funnels here and does two things:

- **Metric** — dispatches to a per-kind callback that books the *existing*
  counter (`frm_*`, `wt_*`, `tpc_*`, `OP_WRITE`). Zero dashboard/alert breakage;
  metric unification deferred to a later phase.
- **Audit line** — one consistent line for **all four** paths:
  `ts kind direction result bytes errno principal path`. This becomes the single
  audit chokepoint for "what was published, by whom, by which path".

  **Sink (corrected during Phase 2):** the existing `xrootd_log_access` is
  *stream-only* (it dereferences the stream session's srv conf), so it cannot
  serve the HTTP S3/WebDAV callers. The ledger instead owns a dedicated,
  transport-agnostic append-only sink: `$XROOTD_XFER_AUDIT_LOG`, else
  `<prefix>/logs/xfer_audit.log`. A process-global fd, lazy-opened per worker;
  O_APPEND makes the sub-PIPE_BUF lines atomic across workers without a lock.
  Wire-sourced fields are escaped with `xrootd_sanitize_log_string`. Metric labels
  stay low-cardinality (invariant #8) — `kind`, `direction`, `result` only.

## 7. Durability split (server-driven vs client-driven)

"Resume after full nginx/system/container restart or crash, provided the client
is happy" means different things per kind. The split is the core correctness
boundary.

### 7a. Server-driven — TAPE / WT / TPC (delegated agent)

No live client byte-stream during the move (client issued `kXR_prepare` and
polls, or finished its PUT and the origin flush is server-internal). The reqfile
**is** the transfer; the agent is ephemeral. A full crash kills every reparented
agent, but the on-disk reqfile survives, so `xfer_reconcile` **re-drives
autonomously on restart** — no client involvement (TAPE client re-polls prepare
and sees completion). This is FRM's reqfile=truth model extended to WT and TPC.
Resume granularity = whatever the agent command supports (copycmd/curl restart,
ranged re-upload if the origin allows); correctness never depends on it — worst
case is re-drive from zero, since the destination is never published until COMMIT.

### 7b. Client-driven — STAGE (S3 / WebDAV / root:// uploads)

The client **is** the byte source; the server cannot resume unilaterally. It
durably retains the partial plus enough state for a reconnecting client to prove
continuity and resume. Generalizes the existing `upload_resume` / `.part`
machinery and respects the `conf_inplace_update_dataloss` fix (never trust an
un-fsync'd tail):

- On crash, the `.part` and a sidecar resume-record survive on persistent
  storage: final path, owner, **durable (fsync'd) offset**, running-checksum
  state, upload-id/etag, TTL.
- Startup **does not blind-sweep** `.part` files — it registers unexpired
  resumable partials and sweeps only expired / non-resumable ones.
- Resume is **client-initiated and validated**: same path + owner + upload-id/etag
  + offset continuity. "Client happy" = client reconnects within TTL and proves
  continuity → engine re-opens the partial; the protocol's own resume handler
  continues at its native granularity (S3 per-part, WebDAV ranged-PUT byte-offset,
  root:// `kXR_open` append). No match / TTL expiry / client gives up → rollback
  + sweep. The server never blocks forever and never publishes a partial object.
- Running-checksum state is persisted in the sidecar (or recomputed from the
  durable prefix on resume) so a resumed upload's final checksum is correct —
  never derived from an un-fsync'd tail.

### 7c. Journal scope

The journal records every transfer past BEGIN and not yet COMMIT/ABORT, scaled
to what needs recovery: full reqfile records for **delegated-agent** (7a) and
**async** transfers; lightweight resume-records for **client-driven resumable
uploads** (7b). Pure sync in-process PUMP transfers that are *not* resumable need
no record — correct by construction (`O_EXCL` temp, only `rename`d on commit;
crash leaves an orphan temp swept at startup), keeping the hot PUT path free of
journal I/O.

## 8. Reconcile & reload

### 8a. `xfer_reconcile.c` (generalizes `frm/reconcile.c` to all kinds)

On worker startup, walk the journal; per non-terminal record, split by driver:

- **Server-driven**: **adopt** (reparented agent alive + result file present →
  book result through ledger, finalize) / **re-drive** (no result, retries remain
  → re-enqueue, bounded retry as FRM today) / **roll back** (exhausted/poisoned →
  ABORT + sweep).
- **Client-driven**: **register-and-wait** (unexpired partial → index for
  client-initiated resume) / **sweep** (expired/non-resumable).
- **Startup temp sweep** for orphaned `O_EXCL` temps / `.scratch` from sync pumps,
  respecting the `upload_resume` partial-resume fix (never zero a resumable
  `.part`).

### 8b. Reload contract (folds into existing nginx drain semantics)

- Journal SHM cache created via `xrootd_shm_table_alloc()` (spin+yield, never the
  POSIX-semaphore mode — invariant #10); survives reload. Slot-count change resets
  the cache from on-disk reqfiles with a WARN (same as other module tables).
- Policy prefixes (§5) and delegated-agent credentials (GSI proxy / keytab for WT
  origin client + TPC) re-read on reload; in-flight transfers stay pinned to the
  disposition and creds they were admitted with; new transfers get new settings.
- New `xrootd_xfer_inflight` gauge (alongside existing `config_generation` /
  `xrootd_config_generation`) so operators confirm in-flight transfers drained or
  were re-adopted across a bounce.

### 8c. Deployment / durable-state contract

Two state dirs are the durability boundary: the **journal/reqfile dir** and the
**staging/`.part` dir**. Both must live on storage that survives crash / restart /
container recreation (named volume or host mount). On ephemeral storage,
durability degrades to best-effort and the engine logs a startup WARN if it
cannot confirm the state dir is persistent. All state transitions are
fsync-durable before they are acted on (reqfile fsync-before-rename as FRM already
does; partial offset/checksum sidecar fsync'd before the offset is advertised as
resumable) so post-crash state never over-claims durable bytes.

## 9. Phased implementation plan (each phase independently shippable & bisectable)

1. **Pure extractions (behaviour-identical).** Extract `xfer_mover_pump` from
   `stage_move_objects` and `xfer_mover_agent` from `frm/stage.c`. FRM remains the
   only caller; verify against existing FRM tests — no behaviour change.
2. **Ledger (audit win).** Land `xfer_ledger` + wire it into **STAGE** commit
   (`vfs_staged.c`): one unified audit line per publish (`result=ok` /
   `commit_err`), transport-agnostic sink. Metrics unchanged. *Resequenced:*
   `xfer_core` + `xfer_policy` moved to Phase 3 — for STAGE they are no-ops
   (unconditional SYNC, caller-driven move), so they earn their keep only once
   TAPE (async, engine-driven) joins. **DONE.**
3. **TAPE joins the unified ledger.** Wire `xrootd_xfer_ledger_record` into
   `frm_stage_commit`: one audit log now covers staged uploads AND tape recalls
   (`kind=tape`, `result=ok` / `agent_fail`, principal = recall requester).
   **DONE.** *Sequencing decision (consumer-driven):* `xfer_core` / `xfer_policy`
   / `xfer_journal` / `xfer_reconcile` are NOT built here. FRM already has working
   durable-queue + reconcile + (Phase 1b) the shared agent; their validating
   *second* consumer is WT, so generalizing the crash-recovery core is deferred to
   Phase 4 where two real consumers (FRM + WT) validate each abstraction. Building
   single-consumer shells around the master-crash path would be speculative.
4. **Write-through migration — drives the durable-core generalization.** WT async
   flush → agent (retire `posix_spawn`-at-close) + a durable journal. With WT as
   the second consumer, now generalize: `frm/queue.c` → `xfer_journal.c` (reqfile
   schema version bump, back-compat read of old TAPE records), `frm/reconcile.c` →
   `xfer_reconcile.c` (server-driven adopt/re-drive/rollback + reload contract),
   `writethrough_decision.c` → `xfer_policy.c`, and the `xfer_core`
   BEGIN/MOVE/COMMIT/ABORT envelope (+ deferred STAGE abort-line). WT joins the
   unified ledger.
5. **TPC migration → ledger only (scope corrected).** TPC runs the transfer with
   *in-process libcurl* in a thread pool, not a forked curl binary — so there is
   no external-process SIGCHLD/SHM hazard and no agent migration applies. TPC
   instead joins the unified ledger (`xrootd_xfer_finish(XROOTD_XFER_TPC, …)` in
   `tpc_thread_done` + the sync fallback in `tpc.c`; `dir=out` push / `dir=in`
   pull). Async-TPC journaling is dropped (TPC is client-retryable at the protocol
   level — YAGNI). The OIDC credential `fork` in `tpc_cred.c` is credential
   acquisition (needs stdout capture), not a transfer — out of scope. **DONE.**
   Result: all four kinds flow through one chokepoint + one audit log.
6. **Client-driven resume + full STAGE audit coverage.** The resume feature was
   found to already exist (`xrootd_staged_open_resume`: identity-keyed,
   deterministically-named `.part`, restart-surviving, checksum-correct because it
   is computed at commit from the committed file — `test_shutdown_resume.py`). The
   engine work was closing an audit gap: root:// uploads commit via
   `xrootd_commit_staged` in `read/close.c` (not the `vfs_staged` path Phase 2
   wired), so they and resumed uploads were unaudited; `read/close.c` now calls
   `xrootd_xfer_finish(XROOTD_XFER_STAGE, …)` on commit. **All STAGE uploads on
   S3, WebDAV, and root:// now emit the unified line. DONE.** Optional remaining
   polish: a TTL sweep of abandoned `.part` files; persisting the running checksum
   is unnecessary given commit-time recomputation.

## 10. Testing

Per change: success + error + security-neg (mandated). Plus engine-wide:

- **Cross-path audit invariant**: all four kinds emit the unified access-log
  schema on commit and abort.
- **Crash recovery per delegated kind**: kill-9 mid-transfer then restart →
  exercises adopt, re-drive, and rollback branches (extends the FRM SIGCHLD-crash
  regression test to WT + TPC now that they share the harness).
- **Reload-during-in-flight**: in-flight pinned to admitted disposition + creds;
  new transfers get new policy.
- **Client-driven resume**: crash mid-upload → reconnect within TTL resumes at
  native granularity with correct final checksum; expired/mismatched → rollback;
  never publishes a partial object; never zeroes a resumable `.part`.
- **Persistent-state contract**: ephemeral-storage startup logs the WARN.

## 11. Out of scope (YAGNI)

- Unified metric family / dashboard cutover (deferred; compat via existing names).
- Cross-host transfer coordination beyond existing CMS/redirector behaviour.
- New protocols beyond the four existing kinds.
