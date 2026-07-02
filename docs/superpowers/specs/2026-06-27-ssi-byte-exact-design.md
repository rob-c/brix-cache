# SSI byte-exact (Tier C) — Design Spec

**Date:** 2026-06-27
**Status:** approved design → implementation
**Scope:** `src/protocols/ssi/` (replaces the echo stub), root:// open/write/read/truncate glue, tests, docs
**Hard requirement:** **byte-exact wire interop** with a real `libXrdSsi` client over `root://` — framing matches `XrdSsi/XrdSsiRRInfo.hh` + `XrdSsiFileSess.cc` exactly.

Separate cycle from the CMS manager-breadth spec.

---

## 1. Motivation

Today `src/protocols/ssi/ssi.c` is a fake unary echo: it does **not** implement the
`XrdSsiRRInfo` offset encoding or the `kXR_attn` push, so it is not interoperable
with a real XrdSsi client. This spec implements the full (Tier C) XrdSsi-over-xroot
protocol natively (no C++ plugin ABI).

## 2. Wire protocol (from XrdSsiFileSess.cc + XrdSsiRRInfo.hh)

- **open** `/<service>` (SFS_O_RDWR) → session; service `prepare`.
- **kXR_write**, offset = `XrdSsiRRInfo{Cmd=Rxq, reqId(24b), size(32b)}` → request bytes; `writeAdd` accumulates.
- **kXR_read**, offset = `XrdSsiRRInfo{Cmd=Rxq/Rwt, reqId}` → pull response/stream bytes (`SendData`).
- **kXR_attn** (unsolicited) carrying `XrdSsiRRInfoAttn{tag=fullResp ':' / pendResp '*' / alrtResp '!', flags, pfxLen, mdLen}` + metadata + data → response-ready / pending / alert push.
- **kXR_truncate**, length = `XrdSsiRRInfo{Cmd=Can, reqId}` → cancel.
- **fctl** → request control (prepare/bind).

`XrdSsiRRInfo` packs into the 8-byte offset: `reqCmd` (low byte of reqId word),
`reqId` (24-bit, masked 0x00ffffff), `reqSize` (32-bit). `XrdSsiRRInfoAttn` is
`{char tag; char flags; u16 pfxLen; u32 mdLen; int rsvd1; rsvd2}` (big-endian on
the wire).

## 3. Architecture

The root:// open/write/read/truncate handlers decode the `XrdSsiRRInfo` from the
request offset and drive a per-handle SSI request state machine; responses and
alerts are pushed as unsolicited `kXR_attn` frames, bulk/streamed payloads pulled
via `kXR_read`. Long-running/streaming services run on the existing thread pool
(`src/core/aio`) and feed a native responder; the event loop owns all socket writes.

## 4. Components

| File | Responsibility |
|---|---|
| `src/protocols/ssi/ssi_rrinfo.{c,h}` | Pure codec for `XrdSsiRRInfo` (offset ⇄ Cmd/reqId/size) and `XrdSsiRRInfoAttn` (attn prefix). Unit-tested standalone. |
| `src/protocols/ssi/ssi_session.{c,h}` | Per-handle request state: service, accumulated request, reqId, response state (pending/ready/streaming/error), metadata, response cursor, stream chunks, cancel flag. |
| `src/protocols/ssi/ssi_attn.{c,h}` | Build + send byte-exact `kXR_attn` frames (header + `XrdSsiRRInfoAttn` + metadata + data). |
| `src/protocols/ssi/ssi_service.{c,h}` | Native `xrootd_ssi_responder_t` (`set_metadata`/`set_response(buf,len,last)`/`alert`/`error`/`finish`) + service registry; thread-pool handoff for async/streaming. |
| `src/protocols/ssi/ssi.{c,h}` | Wire glue invoked from the open/write/read/truncate handlers (replaces the echo). |

## 5. Data flow

open `/<service>` → bind session + service `prepare`. write(`RRInfo{Rxq,reqId,
size}`)+writeAdd → accumulate → on complete, `process`. Service responds via the
responder: **sync** → push `kXR_attn fullResp` (metadata + head); **async** →
`pendResp`, later `fullResp`; **streaming** → emit chunks the client pulls via
`kXR_read(RRInfo{Rxq,reqId})`, end-of-stream flagged. Alerts → `alrtResp`. Cancel
→ `truncate(RRInfo{Can,reqId})` aborts the request/stream + thread job.

## 6. Service-handler interface (Approach 1 — native responder callback)

`xrootd_ssi_responder_t` ops: `set_metadata(md,len)`, `set_response(buf,len,last)`,
`alert(buf,len)`, `error(code,text)`, `finish()`. A compiled-in service implements
`process(request, len, responder)`. Sync services call `set_response` inline;
async/streaming services retain the responder and drive it from a thread-pool job.
A name→service registry resolves the open path; `echo` is retained as a built-in,
plus a streaming demo service for tests.

## 7. Error handling & invariants

RRInfo decode bounds-checked; request-size cap (`XROOTD_SSI_REQ_MAX`); reqId
validated against the handle (no cross-request spoofing); service errors → SSI
error response encoding; attn-on-closed-connection guarded; thread→event-loop
handoff via the existing safe-post pattern (no cross-thread socket writes); cancel
races handled (job marked aborted, late responder calls dropped). No filesystem
paths (service names validated; no traversal surface).

## 8. Testing

- **Unit (gcc, pure):** RRInfo + RRInfoAttn codec round-trip; malformed/oversize
  rejection. Matches the `csi_unittest`/`cms rrdata_unittest` pattern.
- **Raw-wire conformance (pytest, like the CMS suite):** drive open/write/read/
  truncate with real RRInfo offsets; assert `kXR_attn` bytes for fullResp/pendResp/
  alrtResp + metadata + streaming + cancel. success + error + security-neg
  (oversize request, malformed RRInfo, reqId spoof, cancel).
- **Real interop:** drive the module with a real `libXrdSsi` client (XrdSsi test
  app `xrdssi`/`XrdSsiTest`, or pyxrootd SSI bindings) out-of-process if available;
  and where an `xrootd` build with the SSI plugin exists, run our raw-wire client
  against the *real* server to capture golden frames and assert our server emits
  the same bytes. Feasibility is gated on SSI tooling being present (see §10).

## 9. Build governance

New `.c` files register in top-level `./config`; `./configure` once. Standalone
unit tests compile with `gcc` against the pure-C codec.

## 10. Tooling dependency (real-SSI interop)

Real-client/real-server interop tests require an XRootD build with SSI
(`libXrdSsi` + the `xrdssi`/`XrdSsiTest` apps, or pyxrootd SSI bindings). If those
are not present in the environment, the raw-wire conformance suite (golden frames
hand-derived from `XrdSsiRRInfo.hh`/`XrdSsiFileSess.cc`) is the verification floor,
and real-peer tests skip cleanly until the tooling is installed.

---

## 11. Implementation status (live — 2026-06-27)

**Engine implemented + interop-proven against the real XRootD client stack.**

| Capability | State |
|---|---|
| RRInfo / RRInfoAttn codec | ✅ done, golden-validated vs real XrdSsiRRInfo (`ssi_rrinfo`, 18 unit checks) |
| Native service registry + responder | ✅ `ssi_service` (echo/meta/stream/err), unit-tested |
| kXR_query reply builder | ✅ `ssi_reply` (13 unit checks) |
| Wire glue: open(+retstat)/write(RRInfo)/query(Qopaqug)/read | ✅ `ssi.c`, wired in write/query/read/open paths |
| Unary request→response | ✅ real libXrdSsi client round-trips |
| Metadata | ✅ real client receives metadata |
| Streaming (pendResp → kXR_read pulls) | ✅ real client receives chunked response |
| Error response | ✅ real client surfaces the SSI error |
| Cancel (RRInfo Can) | ✅ raw-wire verified |

**Tests:** 33 standalone unit checks + `tests/test_ssi_wire.py` (8: 4 raw-wire + 4
real `libXrdSsi` C++ client via `tests/ssi_client.cc`). Clean `-Werror` build.

**Remaining (two increments):** genuinely-async services (kXR_waitresp + deferred
kXR_attn `asynresp` push — helper exists, needs a safe deferred trigger) and
out-of-band alerts (`alrtResp` push; responder hook is currently a no-op).
