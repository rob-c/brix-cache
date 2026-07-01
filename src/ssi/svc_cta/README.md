# `src/ssi/svc_cta/` — flagship CTA tape service

The `/.ssi/cta` service: a byte-compatible CERN Tape Archive (CTA) frontend over
the SSI framework. A client submits a `cta.xrd.Request` (archive / retrieve /
cancel / query); the service queues it, runs an executor that drives the lifecycle
(pushing progress alerts), and answers with a `cta.xrd.Response`. Pure C — no
`protobuf-c`, no generated code, no nginx coupling (it uses only the responder ABI).

## Layers

| File | Responsibility |
|---|---|
| `pb_wire.{c,h}` | Generic protobuf wire primitives — varint, tag (`field<<3 \| wiretype`), length-delimited, fixed32/64 skip. Bounds-checked readers (untrusted input → `-1` on overrun), buffer-overflow-safe writers. |
| `cta_pb.{c,h}` | Message codec: decode `cta.xrd.Request` (→ op + path + archive-id + owner + instance), encode `cta.xrd.Response` and the `cta.xrd.StreamResponse` header. |
| `cta_queue.{c,h}` | Per-worker request-queue state machine + owner/admin-gated cancel + optional restart journal. |
| `cta_exec.{c,h}` | Pluggable executor vtable (archive/retrieve/cancel) — a simulated test backend and a production (tier/frm) seam. |
| `cta_service.{c,h}` | The `xrootd_ssi_process_fn` glue (registered as `cta` in `provider.c`). |

## Request lifecycle

```
   submit (decode + queue)          completion (executor + respond)
  ┌───────────────────────┐        ┌──────────────────────────────────┐
  │ cta.xrd.Request bytes │        │ run executor: transitions + alerts │
  │  → cta_pb_decode      │  defer │   QUEUED → ACTIVE → COMPLETE        │
  │  → cta_queue_submit   │ ─────▶ │ → cta_pb_encode_response (SUCCESS)  │
  │  → r->defer()         │ kXR_   │ → pushed via kXR_attn              │
  └───────────────────────┘ wait   └──────────────────────────────────┘
                            resp
```

- **archive** (`CLOSEW`) / **retrieve** (`PREPARE`) defer → `kXR_waitresp` →
  progress alerts → pushed `cta.xrd.Response`.
- **cancel** (`ABORT_PREPARE`) transitions the request to CANCELED.
- **query** (`admincmd`) answers synchronously with a queue summary (full
  `cta.xrd.Data` item streaming is deferred — see Scope notes).
- A malformed or unsupported request answers with an error `ResponseType`
  (`RSP_ERR_PROTOBUF` / `RSP_ERR_USER`) — CTA reports errors in the Response, not
  as a transport error.

Submit and completion are correlated by the responder's `svc_slot` cookie (the
queue entry), so the completion advances the *same* entry the submit created.

### State machine

`SUBMITTED → QUEUED → ACTIVE → {COMPLETE | FAILED | CANCELED}`, with cancel allowed
from any non-terminal state. Transitions are validated by a table in `cta_queue.c`.

### Executor

`cta_exec_test_vtbl()` simulates tape transitions deterministically (used in CI and
where no nearline backend exists). `cta_exec_prod_vtbl()` is the documented seam:
`retrieve` should drive `fs/tier` + `fs/xfer/stage_engine` + `frm` to recall an
object online and `archive` the tape-write hook, driving the same queue transitions
+ alerts. Without a configured nearline backend the prod executor fails cleanly. The
executor is selected in `cta_service.c` (test by default; Phase-6 config switches).

### Security

The queue records each request's owner; `cta_queue_cancel` permits cancel only by
the owner or an admin (`CTA_QUEUE_EACCES` otherwise). The owner identity comes from
the request's `Client.user.username`.

### Journal (restart recovery)

`cta_queue_open_journal(q, path)` replays a tab-delimited journal of
`id\top\tstate\towner\tpath` records (latest state per id wins) and keeps the file
open so submit/transition calls append. Per-worker only; the config directive that
supplies the path lands in Phase 6. ADR: cross-worker SHM queue is deferred.

## External contract — the pinned field table

CTA byte-compat depends entirely on the **field numbers**, which are pinned in one
table at the top of `cta_pb.c` (`F_*` macros). That table is the whole external
surface; nothing else in the codec is CTA-specific.

The numbers are taken verbatim from CTA's real `.proto`:

> **Source:** CERN GitLab `eos/xrootd-ssi-protobuf-interface`,
> `eos_cta/protobuf/` — `cta_frontend.proto` (`cta.xrd.Request`/`Response`/
> `StreamResponse`/`Data`), `cta_eos.proto` (`cta.eos.Notification`/`Workflow`/
> `Client`/`Metadata`), `cta_common.proto` (`cta.common.Service`/`RequesterId`).
> Fetched via the GitLab API (anonymous read) on 2026-06-30.

Key mappings (see `cta_pb.c` for the full list):

- `Request.notification`=1, `.admincmd`=2
- `Notification.wf`=1, `.cli`=2, `.file`=4
- `Workflow.event`=1 (`CLOSEW`=4 → archive, `PREPARE`=6 → retrieve,
  `ABORT_PREPARE`=8 → cancel), `.instance`=5
- `Metadata.lpath`=11, `.archive_file_id`=15, `.request_objectstore_id`=999
- `Client.user`=1; `RequesterId.username`=1, `.groupname`=2; `Service.name`=1
- `Response.type`=1 (`RSP_SUCCESS`=1, `RSP_ERR_PROTOBUF`=2, `RSP_ERR_CTA`=3,
  `RSP_ERR_USER`=4), `.message_txt`=3, `.archive_file_id`=5
- `StreamResponse.header`=1

**When CTA's schema bumps:** re-fetch the three `.proto` files, reconcile the `F_*`
table, and re-run the unit test (the golden vectors are regenerated from the field
numbers, so they track the table).

## Golden-vector provenance

The unit test (`cta_pb_unittest.c`) builds golden `cta.xrd.Request` messages
**bottom-up with the `pb_wire` writers**, using the pinned real field numbers, then
decodes them — a build→decode round-trip that proves the decoder against
byte-compatible CTA wire bytes. `pb_wire` itself is independently golden-tested
(`pb_wire_unittest.c`: e.g. varint `300` = `ac02`, tag `field 11/LEN` = `0x5A`).

Because `protoc` is not available in this environment, the vectors are not produced
by `protoc --encode`; the field numbers (from the real `.proto`) are the
correctness anchor. A `protoc`-based cross-check against the real frontend is the
recommended additional verification where CTA tooling is available.

## Scope notes

- The full `cta.admin.AdminCmd` parse is deferred: a `Request.admincmd` is detected
  (→ `CTA_OP_QUERY`) for routing, but its sub-fields are not yet decoded.
- `cta.xrd.Data` items are a `oneof` of 30+ typed `cta.admin.*` listing messages;
  encoding a specific item is deferred to Phase 5 (where the `query` response type
  is chosen). The `StreamResponse.header` wrapper is provided here.
