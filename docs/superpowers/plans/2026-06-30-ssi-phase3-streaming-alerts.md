# SSI Phase 3 — Streamed responses + delivered alerts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `set_response(last=0)` truly stream — incremental chunks produced over time, drained by the client via `kXR_read` against a growable buffer — and actually deliver `alert()` to the client as a pushed `kXR_attn`, instead of dropping it (Phase-1 behaviour).

**Architecture:** The per-request response becomes a growable chunk list instead of a fixed 1 MiB buffer. A streaming service pushes chunks asynchronously; when a chunk arrives and the client is draining, the server emits a `PEND` attn so the client issues `kXR_read`. Alerts are delivered through `xrootd_ssi_deliver(SSI_DLV_ALERT)` (Phase 2). The synchronous read-pull path (Phase 1) is preserved as the simple case.

**Tech Stack:** C (nginx stream), growable buffer (`ngx_pool` chunks), `xrootd_ssi_deliver` (Phase 2), `ssi_reply` PEND framing, pytest raw-wire + real `libXrdSsi` client (`tests/ssi_client.cc` already exercises the `stream` service).

## Global Constraints

- NO `goto`; functional + modular; explicit state; no new globals.
- Stream allocation via `ngx_palloc(c->pool,…)`; never `malloc`; `ngx_str_t` `.len`.
- All async chunk/alert delivery runs in event-loop context (Phase-2 contract).
- 3 tests per change: multi-chunk success + alert delivered + oversize/backpressure reject.
- Build: register new `.c` in `./config`; clean reconfigure when files added.
- **Invariant:** existing `stream` service (3 inline chunks) and `meta` still pass byte-identically via the poll path.

## Consumed interfaces (Phases 1–2, landed by then)

- `xrootd_ssi_req_t` with `resp`/`resp_len`/`read_cursor`/`streaming`/`deferred`/`waiting` (`ssi_req.h`)
- responder ABI; `xrootd_ssi_deliver(ctx,c,s,req_id,kind)` with `SSI_DLV_PEND`/`SSI_DLV_ALERT`
- `xrootd_ssi_reply_build(tag, meta, meta_len, data, data_len, out)` + `XROOTD_SSI_ATTN_PEND/ALRT`

---

### Task 1: Growable response buffer

Replace the fixed `XROOTD_SSI_RESP_MAX` block with an append-grow buffer so a streaming service can produce more than one chunk over time without pre-sizing.

**Files:**
- Create: `src/protocols/ssi/respbuf.{c,h}` (a tiny grow-on-append byte buffer over an `ngx_pool_t`)
- Create: `src/protocols/ssi/respbuf_unittest.c`
- Modify: `src/protocols/ssi/ssi_req.h` (response becomes `respbuf` instead of `u_char* + len`)
- Modify: `src/protocols/ssi/ssi.c` (responder `set_response` appends; read serves from the buffer)
- Modify: `config`

**Interfaces:**
- Produces: `typedef struct { unsigned char *data; size_t len, cap; ngx_pool_t *pool; } xrootd_ssi_respbuf_t;`
  - `int xrootd_ssi_respbuf_append(xrootd_ssi_respbuf_t *b, const unsigned char *p, size_t n, size_t cap_max);` → 0 ok, -1 over cap.

- [ ] **Step 1: Failing unit test** — `respbuf_unittest.c`: append "ab" then "cd" → `data`=="abcd", `len`==4; appending past `cap_max` returns -1 and leaves `len` unchanged. Build standalone (`-DSSI_UT_STANDALONE`, libc `realloc` shim like `session.c`).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement `respbuf.{c,h}`** — `append` grows `cap` (doubling, capped at `cap_max`) via `ngx_palloc`+copy (pool has no realloc; allocate a new block and copy, or use a chunk list — choose copy-grow for read-cursor simplicity). Under `SSI_UT_STANDALONE` use `realloc`.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Swap into `ssi_req.h`/`ssi.c`** — `resp`/`resp_len` become `xrootd_ssi_respbuf_t resp;`; `ssi_resp_set_response` calls `append(&rq->resp, buf, len, XROOTD_SSI_RESP_MAX)`; `xrootd_ssi_read` serves `rq->resp.data + read_cursor`. Keep `XROOTD_SSI_RESP_MAX` as the cap. Register `respbuf.c`; clean rebuild. Phase-1/2 tests green. Commit.

---

### Task 2: Incremental streaming with PEND push

When a deferred/streaming service appends a non-final chunk and the client is waiting, push a `PEND` attn so the client issues `kXR_read`; on the final chunk, push the terminal response (or let the read drain to EOF).

**Files:**
- Modify: `src/protocols/ssi/ssi.c` (`ssi_resp_set_response`: on `last=0` while `waiting`, `xrootd_ssi_deliver(SSI_DLV_PEND)`; on `last=1`, mark responded)
- Modify: `src/protocols/ssi/ssi_service.c` (`stream-async` service: emit 3 chunks on successive timers)
- Test: `tests/test_ssi_stream.py`

**Interfaces:** consumes Phase-2 `deliver`; produces built-in `stream-async`.

- [ ] **Step 1: Failing wire test** — open `/.ssi/stream-async`, submit, expect `kXR_waitresp`, then a sequence of `kXR_attn` PEND notifications, draining each with `kXR_read`, concatenated == `part-A|part-B|part-C`; final read returns EOF (empty `kXR_ok`).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — `stream-async` arms a repeating timer (3 ticks) appending one chunk per tick (`last` on the 3rd); each non-final append while `waiting` calls `xrootd_ssi_deliver(SSI_DLV_PEND)`. Read serves from the growable buffer cursor (Task 1).
- [ ] **Step 4: Run → PASS;** real client `stream` test (poll path) still green. Commit.

---

### Task 3: Delivered alerts

Make `alert()` push a `kXR_attn` alert (`XROOTD_SSI_ATTN_ALRT`, tag `!`) instead of dropping it.

**Files:**
- Modify: `src/protocols/ssi/ssi.c` (`ssi_resp_alert` → `xrootd_ssi_deliver(SSI_DLV_ALERT)` with the alert bytes; for a deferred req only — sync services still drop, documented)
- Modify: `src/protocols/ssi/deliver.c` (`SSI_DLV_ALERT` builds an `ALRT`-tagged attn carrying the alert payload as metadata)
- Modify: `src/protocols/ssi/ssi_service.c` (`alert-async` service: push 2 alerts then a final response)
- Test: `tests/test_ssi_alerts.py`

- [ ] **Step 1: Failing wire test** — open `/.ssi/alert-async`, submit, expect `kXR_waitresp`, then ≥2 `kXR_attn` frames whose attn tag is `!` (alert) carrying the alert bytes, then a final response attn. Use `_parse_ssi_reply` extended to read the tag byte.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the `ALRT` delivery + `alert-async` service.
- [ ] **Step 4: Run → PASS;** regression across all SSI tests. Commit.

---

### Task 4: Docs

- [ ] Update `src/protocols/ssi/README.md`: streaming + alerts move to *implemented*; document `stream-async`/`alert-async`, the growable `respbuf`, and the PEND-on-chunk rule. Commit.

---

## Self-Review

- Growable buffer → Task 1; streaming PEND push → Task 2; alerts delivered → Task 3. ✓
- Backpressure (cap) → Task 1 `cap_max` + over-cap reject test. ✓
- Sync services unchanged → poll path preserved; only `*-async` services use push (regression each task). ✓
- No TBDs; the grow strategy (copy-grow vs chunk list) is decided in Task 1 Step 3 (copy-grow, for read-cursor simplicity).
- Types: `xrootd_ssi_respbuf_t` + `append(...,cap_max)` consistent across Task 1 definition and `ssi.c` use.

## Execution Handoff

Phase 3 of 6. Depends on Phases 1–2. Phase 4 (CTA protobuf codec) is independent of 3 and can proceed in parallel; Phase 5 (CTA service) consumes streaming (3), async (2), and protobuf (4).
