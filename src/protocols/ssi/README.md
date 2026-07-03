# `src/protocols/ssi/` — XrdSsi request/response service over `root://`

## Overview

An `XrdSsi`-style request/response service carried over the ordinary `root://`
file protocol. A client opens an SSI resource path (`/.ssi/<service>`), submits a
request via `kXR_write` whose offset carries an `XrdSsiRRInfo{Rxq, reqId, size}`,
waits for the response via `kXR_query(kXR_Qopaqug)` (or pulls a large/streamed
response with `kXR_read`), and closes. Requests are dispatched to a compiled-in
native service handler.

It exists for **wire parity** with `XrdSsi` without requiring a C++ plugin ABI:
services are built in (the reference one is `echo`). The transport is the
unmodified XRootD open/write/query/read/close path — an SSI handle is a *virtual*
handle that carries no real fd, and the hooks are clean early-returns keyed on
`ctx->files[idx].ssi`, so the normal file data path is **byte-for-byte unchanged
for every non-SSI handle**.

## Phase 1: session multiplexing (implemented)

One open `/.ssi/<service>` handle is an `brix_ssi_session_t` that multiplexes up
to `BRIX_SSI_MAX_INFLIGHT` (8) concurrent requests, each keyed by the `reqId`
carried in the `XrdSsiRRInfo`. The session holds the resolved service provider and
a fixed table (`rrtable`) of per-`reqId` request slots:

- `kXR_open /.ssi/<svc>` → resolve the provider, bind a session.
- `kXR_write` → find-or-create the slot for `reqId`, accumulate the request,
  dispatch the service when complete. A ninth concurrent `reqId` is rejected
  (`kXR_Overloaded`).
- `kXR_query{Rwt}` / `kXR_read` → serve that `reqId`'s response (poll path).
- `kXR_query{Can}` / `kXR_write{Can}` → drop that `reqId`'s slot (cancel).
- `kXR_close` → free the session.

Service resolution goes through `provider.c` — the no-plugin-ABI stand-in for
`XrdSsiProvider`/`XrdSsiService`.

## Phase 2: async server-push via `kXR_attn` (implemented)

A service can answer **later** instead of inline. It calls `responder->defer()`;
the submit is acked with `kXR_waitresp` (capturing its streamid), and the response
is pushed unsolicited as a `kXR_attn + kXR_asynresp` frame — what a real
`libXrdSsi` client awaits — built by `deliver.c` on top of
`brix_send_attn_asynresp`. The reference deferred service is `echo-async` (the
`defer`-or-respond shape every async service follows).

**Delivery is event-loop only and use-after-free safe:**
- A deferral arms a heap-allocated timer (`ssi_defer_t`) carrying the session key +
  generation — never a raw connection/session pointer.
- `registry.c` maps `{session-address → session}` validated by a per-session
  `generation`; `deliver`/the timer resolve a *live* session through it or drop.
- `brix_ssi_handle_cleanup` (called from `brix_free_fhandle` on both
  `kXR_close` and disconnect, before the pool is freed) cancels armed timers and
  unregisters the session, so no completion can run against freed memory.

## Phase 3: streamed responses + delivered alerts (implemented)

- **Streaming.** The response lives in a grow-on-append buffer (`respbuf.c`), so a
  service can emit it in chunks (`set_response(..., last=0)`). A streamed async
  response is signalled to the client as `pendResp` (`*`) and drained via
  `kXR_read`. Reference service: `stream-async`.
- **Alerts.** `responder->alert()` is now delivered (was dropped) as an out-of-band
  `alrtResp` (`!`) push via `brix_ssi_deliver_alert`; the client handles it and
  keeps awaiting the response. Alerts are pushed only when a push channel exists
  (the deferred completion phase); the synchronous core still drops them.
  Reference service: `alert-async`.

The responder carries an `ssi_resp_state_t` (`rq` + optional `ctx`/`c`): the
submit phase has no push channel (alerts drop), the completion phase does (alerts
deliver live, before the terminal response).

## Phases 4–5: CTA flagship service (implemented)

The `cta` provider (`svc_cta/`) is a byte-compatible CERN Tape Archive frontend: a
minimal C protobuf codec (`pb_wire` + `cta_pb`, real CTA field numbers) over a
request-queue state machine (`cta_queue`) and a pluggable executor (`cta_exec`,
simulated tape backend + tier/frm production seam). Archive/retrieve defer and push
progress alerts + a `cta.xrd.Response`; query answers synchronously. See
[`svc_cta/README.md`](svc_cta/README.md).

## Phase 6: config, metrics, conformance (implemented)

### Directives (`NGX_STREAM_SRV_CONF`)

| Directive | Default | Purpose |
|---|---|---|
| `brix_ssi on\|off` | off | Enable the SSI engine on the listener. |
| `brix_ssi_service <name>` | — | Enable a non-default provider. `cta` is the only gated service (it exposes a storage-control surface); built-in test services always resolve. Unknown name → `nginx -t` error. |
| `brix_ssi_max_inflight <n>` | 8 | Concurrent requests per session (capped at the compile-time table size). |
| `brix_ssi_request_max <size>` | 1m | Per-request byte cap (≤ compile-time ceiling). |
| `brix_ssi_response_max <size>` | 1m | Per-response byte cap. |
| `brix_ssi_cta_journal <path>` | — | CTA restart journal path (empty = disabled). |
| `brix_ssi_cta_executor test\|prod` | test | CTA executor backend (simulated vs real tier/frm). |

### Metrics (low-cardinality — `{port,auth}` only)

`brix_ssi_requests_total`, `brix_ssi_errors_total`,
`brix_ssi_alerts_pushed_total`, `brix_ssi_attn_push_failures_total` — exported
per listener via the `/metrics` endpoint.

### Conformance

The gold-standard proof is the real `libXrdSsi` C++ client
(`tests/ssi_client.cc`, driven by `test_ssi_wire.py::TestSsiRealClient`):
echo / metadata / stream / error all round-trip against the module. Async push,
streaming, alerts, multiplex, and the CTA protocol are proven with raw-wire +
golden-vector tests (`test_ssi_async/stream/alerts/multiplex/cta.py`). Limitation:
there is no standalone `xrdssi` CLI, so byte-level golden vectors back the cases the
stock client cannot drive directly.

The full XrdSsi framework + CTA tape service is complete. Design spec:
[`docs/superpowers/specs/2026-06-30-full-ssi-framework-cta-service-design.md`](../../docs/superpowers/specs/2026-06-30-full-ssi-framework-cta-service-design.md);
per-phase plans in `docs/superpowers/plans/`.

## RRInfo wire layout

`XrdSsiRRInfo` serializes (verified against live `libXrdSsi` traffic) as:

| bytes | field |
|---|---|
| 0 | `reqCmd` — `Rxq`=0 / `Rwt`=1 / `Can`=2 |
| 1–3 | `reqId`, big-endian (24-bit; `idMask` 0x00ffffff) |
| 4–7 | `reqSize`, little-endian |

The codec lives in `ssi_rrinfo.c` (golden-validated in `ssi_rrinfo_unittest.c`).
The reply prefix `XrdSsiRRInfoAttn` is built in `ssi_reply.c`.

## Files

| File | Responsibility |
|---|---|
| `ssi.h` / `ssi.c` | Resource-path matching + the open/write/query/read wire hooks; the synchronous responder + dispatch. |
| `ssi_req.h` | `brix_ssi_req_t` — the per-`reqId` request slot (nginx-free data type, so the table logic is unit-testable standalone). |
| `respbuf.h` / `respbuf.c` | Grow-on-append response buffer (streamed responses). |
| `session.h` / `session.c` | `brix_ssi_session_t` + RRTable (`reqId`-keyed find-or-create / drop) + per-session generation. |
| `provider.h` / `provider.c` | Service-name → implementation registry. |
| `registry.h` / `registry.c` | Per-worker session registry (`{session-address, generation}` guard) for safe async delivery. |
| `deliver.h` / `deliver.c` | The single async push primitive — `kXR_attn + kXR_asynresp` response/alert/error/pend. |
| `ssi_service.h` / `ssi_service.c` | Built-in service handlers (`echo`/`meta`/`stream`/`err`) + the responder ABI. |
| `ssi_rrinfo.h` / `ssi_rrinfo.c` | `XrdSsiRRInfo` / `RRInfoAttn` byte codec. |
| `ssi_reply.h` / `ssi_reply.c` | `kXR_query` reply framing (`[RRInfoAttn][metadata][data]`). |

## See also

- `../connection/fd_table.h` — the virtual-handle slot the SSI session hangs off.
- `../read/open_request.c` — the `kXR_open` interception that routes SSI paths here.
- `tests/test_ssi.py`, `tests/test_ssi_wire.py` (incl. the real `libXrdSsi` client),
  `tests/test_ssi_multiplex.py`, `tests/test_ssi_async.py`, `tests/test_ssi_stream.py`,
  `tests/test_ssi_alerts.py`, `tests/test_ssi_cta.py`, `tests/test_ssi_config.py`,
  `tests/test_ssi_metrics.py`.
