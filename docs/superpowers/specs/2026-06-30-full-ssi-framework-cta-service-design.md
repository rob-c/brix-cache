# Full XrdSsi framework + CTA-compatible tape service — design

**Date:** 2026-06-30
**Status:** IMPLEMENTED (all 6 phases, 2026-06-30) — see `docs/superpowers/plans/2026-06-30-ssi-phase{1..6}-*.md` and `src/ssi/README.md`.
**Subsystem:** `src/ssi/`
**Wire spec:** `/tmp/xrootd-src/src/XProtocol/XProtocol.hh`, `/tmp/xrootd-src/src/XrdSsi/`, CTA `cta_frontend.proto` / `eos_cta.proto`

---

## 1. Goal & scope

Grow `src/ssi/` from its current **unary-only** request/response engine into a
**full XrdSsi framework** carried over the ordinary `root://` protocol, and ship
one **flagship real service** — a CERN-CTA-compatible tape archive/retrieve
request service — as the proof.

"Full" here means the SSI capabilities that a stock `libXrdSsi` client exercises,
**excluding** the two things that are inherently plugin/clustering infrastructure
and out of scope for this module:

- **Out of scope (plugin/clustering layer):** `XrdSsiProvider` C++ plugin ABI,
  `XrdSsiCluster`/`XrdSsiCms` service clustering, `XrdSsiShMam`/`XrdSsiShMap`
  shared-memory service maps, `XrdSsiScale`. These are the dlopen-plugin and
  multi-node-clustering machinery the project deliberately does not implement.
- **Out of scope (this module's standing exclusion):** UDP `XrdMon` monitoring.

**In scope (the tractable "full SSI" core):**

1. **Session multiplexing** — many concurrent requests (distinct `reqId`s) on one
   open SSI handle.
2. **Streamed responses** — incremental response production drained by the client
   via `kXR_read`.
3. **Alerts** — out-of-band progress messages pushed to the client.
4. **Server-pushed async responses** — unsolicited `kXR_attn` delivery (the client
   does not poll), matching what stock `libXrdSsi` expects.
5. **Cancellation** — `RRInfo{Can}` cancels an in-flight request.
6. **A flagship service** — CTA-protobuf-compatible tape archive/retrieve/cancel/
   query, backed by a request-queue state machine with `fs/tier` + `frm` hooks.

### Starting point (already present)

`src/ssi/` already implements, byte-exact:

- The `XrdSsiRRInfo` offset codec (`ssi_rrinfo.c`) — `Rxq`/`Rwt`/`Can`, `reqId`, size.
- A per-handle unary request buffer, metadata, error path.
- An `RRInfoAttn`-framed reply (`ssi_reply.c`) and a `kXR_read` cursor for large
  responses.
- A native responder ABI (`ssi_service.h`: `set_metadata`/`set_response(last)`/
  `alert`/`error`) — but `alert` is **dropped**, "streaming" is single-buffer
  accumulation, and delivery is **synchronous / client-poll only**.

### Reused existing primitives (the two hard pieces already exist)

- **`xrootd_send_attn_asynresp()`** (`src/response/async.c`) — builds and sends a
  deferred `kXR_attn + kXR_asynresp` frame for a previously `kXR_waitresp`-acked
  request. This is exactly the unsolicited-response push SSI needs. Companions:
  `xrootd_send_attn_asyncms` (notification → alert) and generic `xrootd_send_attn`.
- **`src/core/aio/resume.c`** — posts thread-pool completions back onto the worker event
  loop via `ngx_post_event` and guards re-entry with `ctx->destroyed`. This is the
  cross-thread-wakeup + use-after-free discipline async SSI delivery requires.

Because both exist and are proven on hot paths, full SSI is **composable** from the
module's existing parts; the new work is the session/RRTable, wiring the responder
to the push primitive, the protobuf codec, and the tape state machine.

---

## 2. Architecture

Three layers, each independently testable, with the hard async concern isolated
behind a single delivery primitive.

```
   wire / session            framework                      service
  ┌────────────────┐   ┌───────────────────────┐   ┌────────────────────┐
  │ session.c      │   │ responder ABI (ext)   │   │ ssi/svc_cta/       │
  │ deliver.c      │──▶│ provider.c            │──▶│ cta_pb.c (protobuf)│
  │ ssi_rrinfo.c   │   │ (echo + cta registry) │   │ cta_queue.c (FSM)  │
  │ ssi_reply.c    │   └───────────────────────┘   │ cta_exec.c (vtable)│
  └────────────────┘                               └────────────────────┘
        ▲  reuses src/response/async.c (kXR_attn) + src/core/aio/resume.c (event-loop post)
```

### Approach decision

**Approach A (chosen): session-centric framework, all delivery posted to the event
loop.** All response/alert/error delivery runs only in event-loop context (a
thread-pool completion posted via `aio/resume.c`, or a timer) and is guarded by a
session registry with a generation counter. Faithful to XrdSsi, isolates the hard
async part behind one primitive, and reuses the existing `kXR_attn` builders.

**Rejected — Approach B: poll-only extension.** Keep the client-poll (`kXR_query`)
model and extend it to streaming/multiplex. Simpler, stays in the current rhythm,
but the stock `libXrdSsi` client will not drive true async cases. Ruled out by the
interop goal. (The poll path is retained as a *fallback* for the native test
client, not as the primary delivery mechanism.)

**Rejected — Approach C: thread-per-session blocking bridge.** A dedicated thread
per session owning blocking I/O + a write-back queue. Violates nginx's event-loop
model, does not scale, contradicts the module's whole async architecture.

---

## 3. Wire / session layer

### Session object

`src/ssi/session.{c,h}` — hangs off the virtual handle (`ctx->files[idx].ssi`),
replacing the single `xrootd_ssi_req_t`:

```
xrootd_ssi_session_t
  ├─ provider*            resolved at kXR_open from /.ssi/<service>
  ├─ rrtable[N]           reqId → xrootd_ssi_req_t   (N = xrootd_ssi_max_inflight)
  ├─ uint64 generation    bumped on close; copied into every responder handle
  ├─ conn_id              stable id for registry lookup (not a raw pointer)
  └─ ngx_connection_t *c  + cur streamid, used only from event-loop context
```

The per-request `xrootd_ssi_req_t` keeps today's fields, plus: `reqId`, a growable
response chunk list (replacing the fixed 1 MiB buffer), the deferred streamid of
the submit (for `asynresp`), a `waiting_read` flag, and executor state.

### Wire event map

All handled in the existing stream dispatch, keyed on the handle being an SSI
session (clean early-return; non-SSI handles byte-for-byte unchanged):

| Wire op | Offset / body | Action |
|---|---|---|
| `kXR_open /.ssi/<svc>` | options | provider lookup → bind session; `kXR_ok` + fhandle. Unknown service → `kXR_NotFound`. |
| `kXR_write` | `RRInfo{Rxq, reqId, size}` | find-or-create req in rrtable; append bytes; on complete → `provider->process(req, responder)`. Ack with `kXR_ok`; if async, also `kXR_waitresp` to arm push. |
| `kXR_read` | `RRInfo{Rxq, reqId}` | serve streamed response bytes from that req's cursor. |
| `kXR_query(Qopaqug)` | `RRInfo{Rwt, reqId}` | **poll fallback** — return ready data, or `kXR_waitresp`. |
| `kXR_query(Qopaqug)` | `RRInfo{Can, reqId}` | cancel → executor cancel + drop req. |
| `kXR_close` | — | bump generation; cancel all inflight; free session. |

### Multiplexing

The `rrtable` keys requests by `reqId`, so one open handle carries many concurrent
requests. Capacity is `xrootd_ssi_max_inflight`; exceeding it returns `kXR_wait` or
an over-quota error. Each `reqId` has independent lifecycle, cursor, and executor.

---

## 4. Async delivery primitive

`src/ssi/deliver.{c,h}` — the **only** place threads meet the socket:

```
void ssi_deliver(conn_id, generation, reqId, kind, buf, len);
   kind ∈ { RESPONSE, RESPONSE_PEND, ALERT, ERROR }
```

Contract and behaviour:

- **Event-loop only.** Called from a thread-pool completion (posted via
  `aio/resume.c`) or a timer — never from a raw worker thread. Asserted.
- **Generation-guarded lookup.** Resolves the session via the registry by
  `{conn_id, generation}`. If the connection is gone or the generation has moved
  (session closed/reused), the delivery is **dropped silently**. This is the
  `ctx->destroyed` guard lifted to session scope and is the single UAF invariant.
- **Frame selection:**
  - `RESPONSE` → `xrootd_send_attn_asynresp(deferred_streamid, kXR_ok, body, len)`.
  - `RESPONSE_PEND` (streamed) → push a "response-ready, pull via read" `RRInfoAttn`
    (PEND); the client then drains with `kXR_read` against the cursor.
  - `ALERT` → `xrootd_send_attn` / asyncms-style notification frame.
  - `ERROR` → `asynresp` with inner status `kXR_error` + SSI error code/text.

### Session registry

`src/ssi/registry.{c,h}` — per-worker map `conn_id → session*` with a monotonic
generation per slot. Open inserts; close bumps generation and removes. Lookups are
the guard above. Per-worker only (SSI sessions are connection-bound to one worker);
no SHM needed.

---

## 5. Framework: responder + provider

### Responder ABI (extend `ssi_service.h`)

Keep the struct shape; change semantics and backing:

- `set_response(buf, len, last)` — `last=1` completes the response; `last=0` appends
  a stream chunk to a growable chunk list and, if a reader is waiting, triggers a
  `RESPONSE_PEND` delivery.
- `alert(buf, len)` — **now delivered** via `ssi_deliver(ALERT)` (was dropped).
- `error(code, text)` — terminal; delivered via `ssi_deliver(ERROR)`.
- `set_metadata(md, len)` — unchanged (delivered with/before the response).
- **Handle, not pointer.** The responder carries `{conn_id, generation, reqId}` so
  an async service finishing later resolves the live session through the registry —
  it never dereferences a freed connection.
- **Event-loop contract.** Synchronous services call the responder inline (on the
  event loop). Async services hand work to a thread-pool job or timer; their
  responder calls execute when that completion is posted back, keeping delivery
  event-loop-safe.

### Provider registry

`src/ssi/provider.{c,h}` — compiled-in table `name → { provision?, process }`,
replacing `ssi_service_lookup`. The no-plugin-ABI substitute for `XrdSsiProvider` /
`XrdSsiService`. Ships:

- `echo` — test fixture (sync + an async variant that proves the push path).
- `cta` — the flagship service (section 6).

---

## 6. Flagship CTA service (`src/ssi/svc_cta/`)

### Protobuf wire codec — `cta_pb.{c,h}`

A *minimal* hand-written protobuf codec (varint, length-delimited, fixed64). **No
external library.** Only the fields actually used, pinned by number in one table,
each carrying a `// CTA proto: <file> field <n>` comment — this file is the entire
external-contract surface.

- **Decode** `cta.xrd.Request` → `{ notification | admincmd }`. For archive/retrieve
  read the `cta.eos.Notification` workflow event:
  - `CLOSEW` → archive
  - `PREPARE` → retrieve
  - `ABORT_PREPARE` → cancel
  plus file identifiers, transport URLs, and owner identity fields.
- **Encode** `cta.xrd.Response` (`type`, `message_txt`, optional `xattr`) and, for
  admin `query`, a stream of `cta.xrd.Data` records (header + rows).

**Conformance note:** byte-compat is verified against captured golden vectors (real
`cta.xrd.*` bytes). CTA's `.proto` evolves; the pinned field table is the contract
and the maintenance point.

### Request-queue state machine — `cta_queue.{c,h}`

States: `SUBMITTED → QUEUED → ACTIVE → {COMPLETE | FAILED | CANCELED}`. Each request
carries op, paths, archive-id, owner identity, timestamps. Per-worker in-memory with
an optional journal file for restart recovery (mirrors `frm/` journal style).

**ADR:** cross-worker shared-memory queue is a deliberate follow-on, not in this
spec. Single-worker / per-worker semantics are sufficient for the framework proof
and for the common deployment.

### Executor — `cta_exec.{c,h}` (pluggable vtable)

- **retrieve / recall** → drives `fs/tier` + `fs/xfer/stage_engine` + `frm` to bring
  a nearline object online. Progress → `responder->alert`; completion → final
  `Response`.
- **archive** → pluggable hook. The **test executor** simulates tape transitions on
  a timer; the **prod hook** is a documented seam (no real tape library in-tree).
- **query** → reads queue state, streams `cta.xrd.Data` rows.
- **cancel** → executor cancel + state transition.

Async throughout: submit acks immediately (`kXR_waitresp`); lifecycle transitions
push alerts; terminal state pushes the response — exercising every framework
feature.

---

## 7. Errors, lifecycle, config, observability, security

### errno → SSI → CTA mapping

One table: internal `errno` → SSI error code (responder `error()` path) → CTA
`Response.type` (`RSP_ERR_*`). Follows the module's existing `errno → kXR` pattern
(`ENOENT`→NotFound, `EACCES`→NotAuthorized, `EINVAL`→ArgInvalid, …).

### Lifecycle / UAF

The generation-guarded registry is the single invariant: connection close bumps the
generation and cancels in-flight executors; any late completion that fails the
`{conn_id, generation}` check is dropped. Mirrors the documented deferred-teardown
UAF guard already used on the write path.

### Caps & backpressure

- `xrootd_ssi_max_inflight` — concurrent reqs per session.
- Per-request request/response size caps (existing 1 MiB defaults, now configurable).
- Queue depth cap → `kXR_wait` / over-quota error.

### Config directives (`src/core/config/`, per the directive recipe)

- `xrootd_ssi on|off` (exists).
- `xrootd_ssi_service <name> [args]` — enable a provider.
- `xrootd_ssi_cta_journal <path>` — CTA queue journal.
- `xrootd_ssi_max_inflight <n>`, request/response size caps.

### Metrics (low-cardinality, `XROOTD_*_METRIC_INC`)

- SSI requests by `{service, op, terminal-status}`.
- Inflight gauge, alerts pushed, attn-push failures.
- **No** paths/reqIds/archive-ids in labels (cardinality invariant).

### Security

SSI inherits the session's authenticated identity. The CTA service records owner
identity per request and gates `cancel`/`query` to owner-or-admin (reuses `acc/`
checks). No new auth surface; unauthenticated submit is rejected.

---

## 8. Testing

Three tests per change (success + error + security-neg):

- **Unit (standalone gcc, existing `ssi_*_unittest.c` style):** `cta_pb` round-trip
  vs golden CTA bytes; queue state machine; RRTable multiplex; generation-guard drop.
- **Integration (native test client we control):** submit → `waitresp` → alert →
  response; streamed read-pull; concurrent multiplex; cancel; **close-mid-flight
  (UAF)**. This is the authoritative end-to-end harness.
- **Conformance vs stock `libXrdSsi`:** best-effort where the real client is
  buildable (via the existing pyxrootd-isolation pattern). Because there is no
  standalone `xrdssi` CLI, byte-level golden vectors are the fallback proof of
  wire-compat. This limitation is explicit.
- **Security-neg:** unauthenticated submit rejected; cancel/query of another
  identity's request denied; oversized / over-quota rejected.

---

## 9. Phasing

Each phase builds + tests green before the next.

1. **Session + RRTable multiplex** (poll path only) — refactor existing code, no new
   wire features.
2. **Async push** — `ssi_deliver` + generation registry + `kXR_waitresp`/`asynresp`
   wiring; `echo` async variant proves it.
3. **Streaming responses + alerts** delivered.
4. **`cta_pb` protobuf codec** + golden vectors.
5. **CTA queue + executor** (retrieve→tier/frm, archive→simulated), wired end-to-end.
6. **Config, metrics, docs, conformance** pass.

**Build:** new `.c`/`.h` files register in the top-level `./config`
(`$ngx_addon_dir/src/...` lists) then `./configure`; incremental `make` otherwise.
A new source file added without re-running `./configure` over a clean `objs/` risks
mixed-ABI garbage — rebuild clean when the source list changes.

---

## 10. File inventory (new / changed)

| File | Status | Responsibility |
|---|---|---|
| `src/ssi/session.{c,h}` | new | Session object + RRTable multiplex |
| `src/ssi/deliver.{c,h}` | new | Event-loop-only async delivery primitive |
| `src/ssi/registry.{c,h}` | new | Generation-guarded session registry |
| `src/ssi/provider.{c,h}` | new | Service-name → implementation registry |
| `src/ssi/ssi.{c,h}` | changed | Wire hooks → session/provider; drop one-req-per-handle |
| `src/ssi/ssi_service.h` | changed | Responder ABI: real alerts, streaming, handle-not-pointer |
| `src/ssi/ssi_reply.{c,h}` | changed | Streamed/PEND reply framing |
| `src/ssi/svc_cta/cta_pb.{c,h}` | new | Minimal CTA protobuf codec |
| `src/ssi/svc_cta/cta_queue.{c,h}` | new | Request-queue state machine + journal |
| `src/ssi/svc_cta/cta_exec.{c,h}` | new | Pluggable executor (tier/frm + simulated archive) |
| `src/core/config/*` | changed | New directives |
| `src/ssi/README.md` | changed | Document the full framework + CTA service |
| `tests/test_ssi_*.py`, `src/ssi/*_unittest.c`, native test client | new | Per section 8 |

---

## 11. Open questions / deferred

- **Cross-worker SSI queue** (SHM) — deferred; per-worker is sufficient for now.
- **Real tape executor** — out of tree; the archive executor ships a simulated
  transition path + a documented prod hook.
- **CTA `.proto` drift** — the pinned field table is the maintenance contract;
  re-capture golden vectors when CTA's schema bumps.
