# SSI Phase 2 — Async server-push (`kXR_attn`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an SSI service complete a request *later* (off the synchronous write/query path) and have the server **push** the response to the client via an unsolicited `kXR_attn + kXR_asynresp` frame — what stock `libXrdSsi` expects — instead of requiring the client to poll.

**Architecture:** A request slot can become *deferred*: when the service does not respond inline, the server captures the submit's stream id, replies `kXR_waitresp`, and arms an event-loop timer that the service's executor fires to deliver the result. All delivery runs in event-loop context (the timer handler) and is guarded by `ctx->destroyed` plus a session generation counter, so a completion targeting a closed connection is dropped. A new built-in `echo-async` service proves the path end-to-end.

**Tech Stack:** C (nginx stream module), `ngx_event_t` timers, `xrootd_send_waitresp` / `xrootd_send_attn_asynresp` (`src/response/`), `ctx->destroyed` guard pattern (`src/core/aio/resume.c`), standalone-gcc + pytest raw-wire + real `libXrdSsi` client tests.

## Global Constraints

- **NO `goto`**; functional + modular; one responsibility per function; pass state explicitly, no new globals.
- Stream allocation `ngx_pcalloc`/`ngx_palloc(c->pool,…)`; never raw `malloc`. `ngx_str_t` uses `.len`.
- Use existing helpers — `xrootd_send_waitresp`, `xrootd_send_attn_asynresp`, `xrootd_queue_response`; never hand-assemble frames.
- **All async delivery runs only in event-loop context** (timer handler or thread-pool completion), never from a raw worker thread.
- 3 tests per change: success + error + security/edge (close-mid-flight UAF).
- Build: new `.c` files register in `./config`, then clean `rm -rf objs && ./configure && make`; incremental `make` otherwise.
- **Behaviour invariant:** synchronous services (Phase 1 `echo`/`meta`/`stream`/`err`) keep their exact current behaviour; only services that defer use the new path.

## Consumed Phase-1 interfaces (already in tree)

- `xrootd_ssi_session_t { char service[64]; xrootd_ssi_provider_t provider; ngx_pool_t *pool; xrootd_ssi_req_t rr[8]; }` (`src/protocols/ssi/session.h`)
- `xrootd_ssi_req_t` (`src/protocols/ssi/ssi_req.h`) — extended in Task 1
- `xrootd_ssi_session_req(s, req_id, create)` / `_drop` / `_create`
- responder ABI `xrootd_ssi_responder_t { set_metadata, set_response, alert, error, state }` (`src/protocols/ssi/ssi_service.h`)
- `xrootd_send_waitresp(ctx,c)`, `xrootd_send_attn_asynresp(ctx,c,deferred_streamid,resp_status,body,bodylen)` (`src/response/`)

---

### Task 1: Per-request deferral state + session generation

Add the fields a deferred request needs and a per-session generation that a delivery uses to detect a recycled/closed session.

**Files:**
- Modify: `src/protocols/ssi/ssi_req.h` (add deferral fields)
- Modify: `src/protocols/ssi/session.h` (add `generation`, `conn_id`; bump on create)
- Modify: `src/protocols/ssi/session.c` (init generation)
- Test: `src/protocols/ssi/session_unittest.c` (generation increments per create)

**Interfaces:**
- Produces (in `xrootd_ssi_req_t`): `unsigned deferred:1;`, `unsigned waiting:1;`, `u_char defer_streamid[2];`
- Produces (in `xrootd_ssi_session_t`): `uint64_t generation;`, `uintptr_t conn_id;`

- [ ] **Step 1: Extend `xrootd_ssi_req_t`** — in `src/protocols/ssi/ssi_req.h`, after `streaming:1;` add:

```c
    unsigned        deferred:1;        /* service will respond later (async) */
    unsigned        waiting:1;         /* kXR_waitresp sent; client awaits push */
    unsigned char   defer_streamid[2]; /* streamid of the submit, for asynresp */
```

- [ ] **Step 2: Extend the session** — in `src/protocols/ssi/session.h`, add to `xrootd_ssi_session_t` (after `pool`):

```c
    uint64_t               generation;  /* bumped each create; delivery guard key */
    uintptr_t              conn_id;     /* stable connection id for the registry */
```

- [ ] **Step 3: Write the failing test** — add to `src/protocols/ssi/session_unittest.c`:

```c
static void test_generation_increments(void)
{
    xrootd_ssi_provider_t prov = { "echo", (xrootd_ssi_process_fn) 0x1 };
    xrootd_ssi_session_t *a = xrootd_ssi_session_create(NULL, "echo", 4, &prov);
    xrootd_ssi_session_t *b = xrootd_ssi_session_create(NULL, "echo", 4, &prov);
    CHECK(a->generation != 0);
    CHECK(b->generation == a->generation + 1);
    free(a); free(b);
}
```
Add `test_generation_increments();` to `main()`.

- [ ] **Step 4: Run it, expect FAIL** — `gcc -Wall -Wextra -Werror -DSSI_UT_STANDALONE -I src -o /tmp/ssi_session_ut src/protocols/ssi/session_unittest.c src/protocols/ssi/session.c && /tmp/ssi_session_ut` → FAIL (`generation` unset/0).

- [ ] **Step 5: Implement** — in `src/protocols/ssi/session.c`, add a file-static monotonic counter and assign in `xrootd_ssi_session_create` after alloc:

```c
static uint64_t ssi_gen_seq;   /* per-worker; sessions are connection-bound */
/* ... in create(), after zeroing s: */
    s->generation = ++ssi_gen_seq;
```
(Functional note: this is a per-worker counter, not a global shared state across responsibilities — it is the session factory's own sequence. Acceptable; documented.)

- [ ] **Step 6: Run it, expect PASS.** Commit (the implementer's normal commit step).

---

### Task 2: The deliver primitive + session registry

A per-worker registry maps `conn_id → session`, and `ssi_deliver` resolves `{conn_id, generation, reqId}` to a live slot and pushes the frame. This is the single place async results reach the socket.

**Files:**
- Create: `src/protocols/ssi/registry.{c,h}`
- Create: `src/protocols/ssi/deliver.{c,h}`
- Create: `src/protocols/ssi/registry_unittest.c`
- Modify: `config`

**Interfaces:**
- Produces (`registry.h`):
  - `void xrootd_ssi_registry_add(uintptr_t conn_id, xrootd_ssi_session_t *s);`
  - `void xrootd_ssi_registry_remove(uintptr_t conn_id);`
  - `xrootd_ssi_session_t *xrootd_ssi_registry_find(uintptr_t conn_id, uint64_t generation);` — NULL if absent or generation moved.
- Produces (`deliver.h`):
  - `typedef enum { SSI_DLV_RESPONSE, SSI_DLV_PEND, SSI_DLV_ALERT, SSI_DLV_ERROR } xrootd_ssi_dlv_kind;`
  - `void xrootd_ssi_deliver(xrootd_ctx_t *ctx, ngx_connection_t *c, xrootd_ssi_session_t *s, uint32_t req_id, xrootd_ssi_dlv_kind kind);`

- [ ] **Step 1: Registry test (standalone)** — `registry_unittest.c`: add a session, find with right generation → non-NULL; find with wrong generation → NULL; remove → find NULL. (Mirror `session_unittest.c` harness; the registry stores a fixed-size `conn_id→{session,generation}` table — size `XROOTD_SSI_REGISTRY_SLOTS`, e.g. 256 — keyed by `conn_id`.)

```c
#include "registry.h"
#include <stdio.h>
static int g_fail; /* CHECK macro as in the other unit tests */
int main(void){
    xrootd_ssi_session_t s; s.generation = 5;
    xrootd_ssi_registry_add(1234, &s);
    CHECK(xrootd_ssi_registry_find(1234, 5) == &s);
    CHECK(xrootd_ssi_registry_find(1234, 6) == NULL); /* generation moved */
    xrootd_ssi_registry_remove(1234);
    CHECK(xrootd_ssi_registry_find(1234, 5) == NULL);
    printf(g_fail?"FAILED\n":"OK\n"); return g_fail?1:0;
}
```

- [ ] **Step 2: Run → FAIL** (registry files absent). Build line:
`gcc -Wall -Wextra -Werror -DSSI_UT_STANDALONE -I src -o /tmp/ssi_reg_ut src/protocols/ssi/registry_unittest.c src/protocols/ssi/registry.c && /tmp/ssi_reg_ut`

- [ ] **Step 3: Implement `registry.{c,h}`** — a `static` fixed array of `{ uintptr_t conn_id; uint64_t generation; xrootd_ssi_session_t *s; int in_use; }`. `add` stores `{conn_id, s->generation, s}`; `find` linear-scans for a matching `conn_id` and equal `generation`; `remove` clears the slot. No nginx types needed (compiles under `SSI_UT_STANDALONE` with `xrootd_ssi_session_t` from `session.h`). Per-worker; no SHM.

- [ ] **Step 4: Implement `deliver.{c,h}`** — `xrootd_ssi_deliver` looks up `xrootd_ssi_session_req(s, req_id, 0)`; if NULL returns. Then by kind:
  - `SSI_DLV_RESPONSE` → build the full reply (`xrootd_ssi_reply_build(XROOTD_SSI_ATTN_FULL,…)` into a `c->pool` buffer) and `xrootd_send_attn_asynresp(ctx, c, rq->defer_streamid, kXR_ok, buf, len)`.
  - `SSI_DLV_PEND` → `xrootd_send_attn_asynresp(... PEND reply meta-only ...)` (client then `kXR_read`s the stream).
  - `SSI_DLV_ALERT` → `xrootd_send_attn(ctx, c, kXR_asyncms-style, buf, len)` (Phase 3 wires real alert bytes; here deliver a metadata blob).
  - `SSI_DLV_ERROR` → `xrootd_send_attn_asynresp(ctx, c, rq->defer_streamid, kXR_error, errbody, errlen)`.
  Caller guarantees event-loop context + liveness (Task 3/4). Register both `.c` in `./config`; clean rebuild.

- [ ] **Step 5: Run registry unit test → PASS.** Commit.

---

### Task 3: Wire open/close to the registry; defer on `kXR_waitresp`

`open` registers the session and stamps `conn_id`; close/teardown removes it (bumping liveness via `ctx->destroyed`). The write hook, when the service defers, captures the submit streamid, sends `kXR_waitresp`, and marks the slot `waiting`.

**Files:**
- Modify: `src/protocols/ssi/ssi.c` (open register, write defer path)
- Modify: the SSI handle free path — find where `ctx->files[idx].ssi` is cleared (`grep -n "files\[.*\].ssi" src/connection/fd_table.c src/read/close.c`) and call `xrootd_ssi_registry_remove(sess->conn_id)` there.

**Interfaces:**
- Consumes: Task 2 registry; `xrootd_send_waitresp`; the responder's new `deferred` signal (Task 4).

- [ ] **Step 1:** In `xrootd_ssi_open`, after `xrootd_ssi_session_create`, set `sess->conn_id = (uintptr_t) c;` and `xrootd_ssi_registry_add(sess->conn_id, sess);`.

- [ ] **Step 2:** In the SSI handle teardown (the close/free site), before freeing, `xrootd_ssi_registry_remove(((xrootd_ssi_session_t*)ssi)->conn_id);`. (Connection-pool memory is reclaimed by nginx; the registry entry must be removed explicitly so a recycled `conn_id` cannot resolve a stale session — the generation check is the backstop.)

- [ ] **Step 3:** In `xrootd_ssi_write`, after `ssi_dispatch(...)`, branch on the slot being deferred (set by Task 4's responder): if `rq->deferred && !rq->responded`, capture `ngx_memcpy(rq->defer_streamid, ctx->cur_streamid, 2); rq->waiting = 1;` and `return xrootd_send_waitresp(ctx, c);` instead of the plain `kXR_ok`.

- [ ] **Step 4:** Build the module (clean reconfigure — new files). Existing Phase-1 tests must still pass (`pytest tests/test_ssi*.py` with `TEST_SKIP_SERVER_SETUP=1`). Commit.

---

### Task 4: Async responder + `echo-async` service (timer-driven proof)

Give the responder an async mode: a service marks the request deferred and arms an event-loop timer; on fire (event-loop context, `ctx->destroyed`-guarded), it fills the response and calls `xrootd_ssi_deliver(... SSI_DLV_RESPONSE)`.

**Files:**
- Modify: `src/protocols/ssi/ssi.c` (responder: a `defer()` op or a deferred flag; the timer handler)
- Modify: `src/protocols/ssi/ssi_service.c` (register `echo-async`)
- Test: `tests/test_ssi_async.py` (raw-wire: submit → `kXR_waitresp` → `kXR_attn` asynresp carries the echo)

**Interfaces:**
- Consumes: `xrootd_ssi_deliver` (Task 2), `ctx->destroyed`, the per-req `defer_streamid`/`waiting`.
- Produces: built-in service name `echo-async`.

- [ ] **Step 1: Write the failing wire test** — `tests/test_ssi_async.py`: open `/.ssi/echo-async`, submit `reqId=1` with a payload, assert the first reply is `kXR_waitresp` (status `kXR_waitresp`), then read the next frame and assert it is a `kXR_attn` whose inner `asynresp` body decodes (via `_parse_ssi_reply`) to the echoed payload. Add an `ssi_async` server fixture (reuse `test_ssi_wire.py`'s `ssi_server`, which already enables `xrootd_ssi on`). Also a **UAF test**: submit then immediately close the socket before the timer fires; assert the server does not crash (the fixture stays up for a follow-up request).

- [ ] **Step 2: Run → FAIL** (no `echo-async`, no defer path).

- [ ] **Step 3: Implement the deferred responder + timer** — add to `src/protocols/ssi/ssi.c`:
  - A `svc_echo_async` handler in `ssi_service.c` that copies the request into a small pool struct, marks the responder deferred (e.g. responder gains `void (*defer)(xrootd_ssi_responder_t*)` that sets `rq->deferred=1`), arms `ngx_add_timer(&rq_timer_event, 10)`, and returns 0 without calling `set_response`.
  - The timer event's `data` is a small struct `{ xrootd_ctx_t *ctx; ngx_connection_t *c; uintptr_t conn_id; uint64_t generation; uint32_t req_id; }` (pool-allocated; NOT a raw `rq` pointer).
  - Timer handler: `if (ctx->destroyed) return;` then `s = xrootd_ssi_registry_find(conn_id, generation); if (!s) return;` then `rq = xrootd_ssi_session_req(s, req_id, 0); if(!rq) return;` fill `rq->resp` from the saved request, `rq->responded = 1`, and `xrootd_ssi_deliver(ctx, c, s, req_id, SSI_DLV_RESPONSE);`.
  - Store the timer `ngx_event_t` in the req slot (add `ngx_event_t defer_timer;` to a stream-only companion — since `ssi_req.h` is nginx-free, keep the timer in a parallel per-slot array in the session under `#ifndef SSI_UT_STANDALONE`, or in a small heap struct referenced by `void *defer_ctx;` in `ssi_req.h`). Use `void *defer_ctx;` to keep `ssi_req.h` nginx-free.

- [ ] **Step 4: Run the wire test + UAF test → PASS.** Run the real client too if a streaming/async variant exists; otherwise the raw-wire asynresp test is the proof. Commit.

- [ ] **Step 5: Regression** — `pytest tests/test_ssi.py tests/test_ssi_wire.py tests/test_ssi_multiplex.py` all green; all standalone unit tests green. Commit.

---

### Task 5: Docs

- [ ] Update `src/protocols/ssi/README.md`: move "server-pushed async responses via `kXR_attn`" from *upcoming* to *implemented*; document `echo-async`, the registry + generation guard, and the event-loop-only delivery contract. Commit.

---

## Self-Review

- **Async push** → Tasks 2–4 (`deliver` + `asynresp` + timer). ✓
- **Event-loop-only + UAF guard** → registry generation + `ctx->destroyed` (Tasks 2–4); UAF test (Task 4). ✓
- **`kXR_waitresp` arm** → Task 3 Step 3. ✓
- **Sync services unchanged** → only the `deferred` slot takes the new path; Phase-1 services never set it (regression in Task 4 Step 5). ✓
- **Placeholder scan:** the only deliberately open choice is timer-storage location (Task 4 Step 3 gives the concrete `void *defer_ctx` resolution). No TBDs.
- **Type consistency:** `xrootd_ssi_deliver(ctx,c,s,req_id,kind)` and the `conn_id`/`generation` registry keys are used identically in Tasks 2–4.

## Execution Handoff

Phase 2 of 6. Depends on Phase 1 (landed). Phase 3 (streaming + alerts) builds on `xrootd_ssi_deliver` and the deferred responder established here.
