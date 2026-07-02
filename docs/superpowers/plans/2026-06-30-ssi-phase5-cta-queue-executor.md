# SSI Phase 5 — CTA request queue + executor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the flagship `cta` SSI service: decode CTA-protobuf requests, run them through an archive/retrieve/cancel/query state machine, and report progress (alerts) + final result (async response) — retrieve wired to the real `fs/tier` + `stage_engine` + `frm`, archive behind a pluggable executor (simulated in test).

**Architecture:** `cta_queue` owns per-request lifecycle (`SUBMITTED→QUEUED→ACTIVE→{COMPLETE|FAILED|CANCELED}`), per-worker in-memory with an optional journal. `cta_exec` is a vtable: `retrieve` drives the tier/stage engine, `archive` calls a hook (test = simulated timer transitions). The `cta` provider glues `cta_pb` (Phase 4) decode → queue submit → async responder (Phase 2) → alerts/streamed `Data` (Phase 3).

**Tech Stack:** C (nginx stream), `cta_pb` (Phase 4), SSI async/streaming (Phases 2–3), `fs/tier` + `fs/xfer/stage_engine.c` + `frm/`, pytest end-to-end (raw-wire CTA-protobuf client we control).

## Global Constraints

- NO `goto`; functional + modular; explicit state; no new globals (queue is a passed/looked-up context, not a global singleton — see Task 1).
- Stream allocation `ngx_palloc(c->pool,…)`; journal I/O is svc-owned raw-as-worker (`/* vfs-seam-allow: cta journal, svc-owned control file */`), consistent with `frm/` journals.
- All executor→responder delivery in event-loop context (Phase-2 contract); blocking stage calls go through the thread pool (`aio/`), completions posted back.
- Security: record owner identity per request; gate `cancel`/`query` to owner-or-admin via existing `acc/` checks.
- 3 tests per change: lifecycle success + cancel + unauthorized-cancel rejected.
- Build: register new `.c` in `./config`; clean reconfigure.

## Consumed interfaces

- `cta_pb_decode_request` / `cta_pb_encode_response` / `cta_pb_encode_data_record` (Phase 4)
- `xrootd_ssi_deliver(... SSI_DLV_RESPONSE/ALERT/PEND/ERROR)` + deferred responder (Phase 2)
- streaming `respbuf` + alert delivery (Phase 3)
- `fs/tier` + `fs/xfer/stage_engine.c` recall entry points (read `src/fs/xfer/stage_engine.c` + `src/fs/tier/tier.h` for the exact recall API before Task 3)

---

### Task 1: Request-queue state machine

**Files:**
- Create: `src/protocols/ssi/svc_cta/cta_queue.{c,h}`
- Create: `src/protocols/ssi/svc_cta/cta_queue_unittest.c`
- Modify: `config`

**Interfaces:**
- `typedef enum { CTA_ST_SUBMITTED, CTA_ST_QUEUED, CTA_ST_ACTIVE, CTA_ST_COMPLETE, CTA_ST_FAILED, CTA_ST_CANCELED } cta_state_t;`
- `typedef struct cta_req_s { cta_request_t req; cta_state_t state; char owner[64]; uint64_t id; /* ... timestamps, next ptr */ } cta_req_t;`
- `typedef struct cta_queue_s xrootd_cta_queue_t;`
- `xrootd_cta_queue_t *cta_queue_create(ngx_pool_t *pool);`
- `cta_req_t *cta_queue_submit(xrootd_cta_queue_t *q, const cta_request_t *r, const char *owner);`
- `cta_req_t *cta_queue_find(xrootd_cta_queue_t *q, uint64_t id);`
- `int cta_queue_transition(cta_req_t *e, cta_state_t to);` → 0 if the transition is legal, -1 otherwise.
- `int cta_queue_cancel(xrootd_cta_queue_t *q, uint64_t id, const char *requester, int is_admin);` → 0 ok, -EACCES if not owner/admin, -ENOENT if absent.

- [ ] **Step 1: Failing unit test** (standalone, libc shim): submit → `SUBMITTED`; legal transitions advance; an illegal transition (e.g. `COMPLETE→ACTIVE`) returns -1; cancel by owner → `CANCELED`; cancel by a different non-admin → -EACCES; cancel by admin → ok.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the queue (linked list or fixed table under the pool) + a transition matrix (table-driven, not a branch ladder). Register `cta_queue.c`.
- [ ] **Step 4: Run → PASS.** Commit.

---

### Task 2: Executor vtable + simulated archive

**Files:**
- Create: `src/protocols/ssi/svc_cta/cta_exec.{c,h}`
- Create: `src/protocols/ssi/svc_cta/cta_exec_unittest.c`

**Interfaces:**
- `typedef struct { int (*archive)(cta_req_t*, void *cb); int (*retrieve)(cta_req_t*, void *cb); int (*cancel)(cta_req_t*); } cta_exec_vtbl_t;`
- A progress callback type that the executor invokes to emit alerts and the terminal result (wired to `xrootd_ssi_deliver` by the provider in Task 3).
- `const cta_exec_vtbl_t *cta_exec_test_vtbl(void);` (simulated transitions on a timer)
- `const cta_exec_vtbl_t *cta_exec_prod_vtbl(void);` (retrieve→tier/frm; archive→documented hook)

- [ ] **Step 1: Failing test** — drive the test vtbl's `archive` over a fake clock: it advances `QUEUED→ACTIVE→COMPLETE` and invokes the progress callback at each step; `cancel` mid-flight yields `CANCELED` and no further callbacks.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the test vtbl (deterministic transitions driven by an injected step function, so it is unit-testable without nginx timers) + the prod vtbl skeleton whose `retrieve` calls the tier/stage-engine recall API (read the real signature first) and whose `archive` is the documented hook.
- [ ] **Step 4: Run → PASS.** Commit.

---

### Task 3: The `cta` provider — glue decode → queue → async deliver

**Files:**
- Create: `src/protocols/ssi/svc_cta/cta_service.{c,h}`
- Modify: `src/protocols/ssi/provider.c` (register `cta`)
- Modify: `src/protocols/ssi/ssi_service.c` if the provider needs a process-fn shim
- Test: `tests/test_ssi_cta.py` (end-to-end raw-wire CTA-protobuf client)

**Interfaces:** the `cta` `xrootd_ssi_process_fn`: decode request bytes via `cta_pb_decode_request`; on decode error → `responder->error` (→ `cta.xrd.Response` error via `cta_pb_encode_response`); else `cta_queue_submit`, mark the responder deferred, kick the executor; executor progress → `alert` (Phase 3) with a `cta.xrd.Response` progress message; terminal → final response (`cta_pb_encode_response`); `query` → stream `cta.xrd.Data` rows (Phase 3 PEND/read).

- [ ] **Step 1: Failing end-to-end test** — `tests/test_ssi_cta.py`: a Python CTA-protobuf client (build request bytes matching the Phase-4 pinned field numbers) opens `/.ssi/cta`, submits an archive request, asserts `kXR_waitresp`, then ≥1 alert `kXR_attn` and a final `cta.xrd.Response` success (decode the pushed bytes). A `query` submit streams ≥1 `cta.xrd.Data` row. A `cancel` of another identity's request is rejected. (Server fixture enables `xrootd_ssi on` + `xrootd_ssi_service cta`.)
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement `cta_service.c`** wiring the pieces; the executor's event-loop progress callback resolves the session via the Phase-2 registry (generation-guarded) and calls `xrootd_ssi_deliver`. Use the **test** executor vtbl by default (no real tape in CI); the prod vtbl is selected by config (Phase 6).
- [ ] **Step 4: Run → PASS;** all earlier SSI tests still green. Commit.

---

### Task 4: Optional journal (restart recovery)

**Files:** Modify `cta_queue.{c,h}` (append-on-transition journal + replay on create); Test `cta_queue_unittest.c` (journal round-trip).

- [ ] Append each transition to a journal file (svc-owned raw, `vfs-seam-allow` marker, `frm/`-style); on `cta_queue_create` with a journal path, replay to rebuild in-flight requests. Test: write N transitions, recreate, assert state restored. Commit. (ADR: per-worker only; cross-worker SHM deferred.)

---

### Task 5: Docs

- [ ] Extend `src/protocols/ssi/svc_cta/README.md`: the lifecycle state machine, executor vtable (test vs prod), the tier/frm recall wiring, the journal, and the owner/admin authorization rule. Commit.

---

## Self-Review

- Queue/state machine (1) + executor (2) + provider glue (3) + journal (4) cover the spec's CTA service. ✓
- Retrieve→tier/frm, archive→simulated/hook (Task 2/3). ✓
- Security: owner/admin gate in `cta_queue_cancel` (Task 1) + unauthorized-cancel test (Tasks 1,3). ✓
- Event-loop delivery + registry generation guard reused from Phase 2 (Task 3). ✓
- No TBDs in structure; the one genuine external dependency (the tier/stage-engine recall signature) is explicitly "read the real API first" in Consumed-interfaces + Task 2/3.

## Execution Handoff

Phase 5 of 6. Depends on Phases 2, 3, 4. Phase 6 wires config directives, metrics, and the conformance pass.
