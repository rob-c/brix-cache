# response — XRootD wire-response framing helpers

## Overview

This subsystem is the single, shared toolbox every `root://` stream handler uses to
turn a finished operation into bytes on the wire. It owns the layout of the 8-byte
`ServerResponseHdr` and the bodies that follow it: success (`kXR_ok`), error
(`kXR_error`), control-flow hints (`kXR_redirect`, `kXR_wait`, `kXR_waitresp`),
server-push notifications (`kXR_attn`), and the CRC32c-protected `kXR_status`
frames required by paged read/write. Handlers never hand-assemble these headers —
they call one of the `xrootd_send_*` helpers here, which guarantees correct
big-endian field order, correct `dlen` accounting, and consistent stream-ID echo.

It sits at the very end of the stream request lifecycle. After
`handshake/dispatch.c` routes an opcode to its handler (in `read/`, `write/`,
`query/`, `dirlist/`, `fattr/`, `manager/`, `cms/`, `proxy/`, `tpc/`), and after
any blocking I/O has been offloaded to and resumed from `../aio/`, the handler
produces an answer by calling a helper in this directory. Every helper allocates
its frame from the connection pool (`ngx_palloc(c->pool, …)`), fills it, and then
delegates the actual socket write — including partial-write/`EAGAIN` stalling — to
`xrootd_queue_response()` in `../connection/write_helpers.c`. Nothing in this
directory performs raw `write()`/`send()` or touches the socket directly.

Only the binary XRootD protocol uses these helpers. WebDAV and S3 build their
responses with nginx's HTTP machinery (`ngx_http_send_header` + output filter chain)
and never enter this subsystem; the CMS cluster protocol has its own framing in
`../cms/`. The one piece shared more broadly is CRC32c (`crc32c.c`), which is a thin
wire-facing wrapper over `../compat/`.

The functions are intentionally tiny, pure-ish builders so the same response can be
constructed identically from the synchronous path and from an AIO completion
callback running on the event loop — this is why, for example,
`xrootd_build_pgread_status()` builds into a caller-provided struct rather than
queueing, letting the read path prepend it to a data chain.

## Files

| File | Responsibility |
|------|----------------|
| `response.h` | Public API for the whole subsystem: header builder, `send_ok`/`send_error`, redirect/wait helpers, pgread/pgwrite status builders, and the CRC32c family. Included by every stream handler that emits a response. |
| `async.h` | API for native `kXR_attn` server-push generation (`asyncms`, `asynresp`, generic `attn`) plus the retired async-opcode (5000–5007) handler declarations. |
| `basic.c` | `xrootd_build_resp_hdr()` (fill an 8-byte `ServerResponseHdr`, all fields big-endian), `xrootd_send_ok()` (kXR_ok + optional body), `xrootd_send_error()` (kXR_error: 4-byte errnum + NUL-terminated message). The lowest-level building blocks. |
| `control.c` | Control-flow frames: `xrootd_send_redirect()` (port+host), `xrootd_send_redirect_tpc()` (redirect with `?tpc.key=<key>` opaque appended), `xrootd_send_wait()` (retry-after seconds), `xrootd_send_waitresp()` (header-only deferral ack). |
| `status.c` | `kXR_status` (4007) integrity frames for paged I/O: `xrootd_send_pgwrite_status()` (builds + queues a pgwrite completion) and `xrootd_build_pgread_status()` (builds a pgread status header into a caller buffer; caller queues it ahead of the page-data chain). |
| `async.c` | Native `kXR_attn` (4001) generation: `xrootd_send_attn_asyncms()` (unsolicited text push), `xrootd_send_attn_asynresp()` (deferred response after `kXR_waitresp`), generic `xrootd_send_attn()`, the `_frame_len`/`_build_…_frame` size+layout helpers, and stub handlers for the eight deprecated async opcodes — all of which return `kXR_Unsupported`. |
| `crc32c.c` | Wire-facing CRC32c API: `xrootd_crc32c()` (one-shot), `xrootd_crc32c_copy()` (fused checksum+copy), and `xrootd_crc32c_file()` (pread loop over an open fd, `(uint32_t)-1` on I/O error). All are thin wrappers over `../compat/crc32c.c` (where the SSE4.2 / software-table `xrootd_crc32c_value()` and `xrootd_crc32c_extend()` actually live) and `../compat/checksum.c` (`xrootd_checksum_u32_fd`). Used for per-page integrity on pgread/pgwrite and whole-file checksum verification. |

> Note: these `.c`/`.h` files are registered for the build in the top-level nginx
> addon `config` script (lines ~136–137 for headers, ~475–479 for sources), not in
> `src/config/config.h`. `xrootd_crc32c_extend()` is *declared* in `response.h` but
> *defined* in `../compat/crc32c.c`; only the other three CRC entry points are
> bodied here.

## Key types & data structures

These are defined in `../protocol/wire_core_requests.h` and `../protocol/opcodes.h`;
this subsystem is their primary producer.

- **`ServerResponseHdr` (8 bytes)** — `streamid[2]`, `status` (BE `uint16`),
  `dlen` (BE `uint32`, body length only, *not* including the header). Built by
  `xrootd_build_resp_hdr()`; every frame in this directory starts with one.
- **`ServerResponseBody_Status` (16 bytes)** — the `kXR_status` body, with
  `crc32c` as the *leading* field (so it can be excluded from its own coverage):
  then echoed `streamID[2]`, `requestid` (`requestcode − kXR_1stRequest`),
  `resptype` (0 = `kXR_FinalResult`, 1 = `kXR_PartialResult`), `reserved[4]`, and
  `dlen` (bad-page-list size: 0 for pgwrite-success; for pgread it carries
  `total_with_crcs`, the page+CRC bytes the client reads next).
- **`ServerStatusResponse_pgRead` / `ServerStatusResponse_pgWrite` (32 bytes)** —
  full status frames = `hdr` + `bdy` (Status) + `pgr`/`pgw` (an 8-byte BE
  `offset`). pgwrite is sent as one contiguous buffer; pgread is a header-only
  frame followed by the page+CRC data chain.
- **kXR_attn action codes** — carried in the leading 4-byte `actnum` of an attn
  body. Only `kXR_asyncms` (5002) and `kXR_asynresp` (5008) are active; the rest
  are retired. See the wire layouts documented in `async.h` / `async.c`.
- **`xrootd_ctx_t`** (`../types/context.h`) — supplies `ctx->cur_streamid`, the
  2-byte stream ID echoed into every outgoing header so concurrent ops on one
  connection stay distinguishable.

## Control & data flow

**Entry:** a stream operation handler finishes its work and calls a single
`xrootd_send_*` helper. There is no dispatcher in this directory — it is a leaf
utility layer called from many places:

- success/error/data: `../read/`, `../write/`, `../query/`, `../dirlist/`,
  `../fattr/`, `../session/` all call `xrootd_send_ok` / `xrootd_send_error`.
- redirects: `../manager/` and `../cms/` (server selection / locate) call
  `xrootd_send_redirect`; `../tpc/` uses `xrootd_send_redirect_tpc` to carry the
  SHM key-registry key across the redirect.
- backpressure: `../ratelimit/` and overloaded handlers call `xrootd_send_wait`.
- paged I/O: `../read/` (pgread) calls `xrootd_build_pgread_status` then queues it
  ahead of the page-data chain; `../write/` (pgwrite) calls
  `xrootd_send_pgwrite_status`. Per-page CRCs come from `crc32c.c`.
- async/push: `kXR_prepare` notify and deferred-response paths call the `async.c`
  attn helpers.

**Exit / call-out:** every helper ends by calling
`xrootd_queue_response(ctx, c, buf, total)` in
`../connection/write_helpers.c`, which performs the actual non-blocking send and
handles partial-write stalling. `crc32c.c` calls down into `../compat/`
(`crc32c.c`, `checksum.c`). Frame buffers come from the per-connection pool, so
they are valid until the request completes and require no manual free.

See `../read/README.md`, `../write/README.md`, `../aio/README.md`,
`../connection/README.md`, `../manager/README.md`, `../tpc/README.md`,
`../cms/README.md`, and `../protocol/README.md`.

## Invariants, security & gotchas

- **All multi-byte fields are big-endian.** `status`/`dlen` use `htons`/`htonl`;
  64-bit offsets use `htobe64`; the attn `actnum` is `htonl`'d. Build only through
  `xrootd_build_resp_hdr()` — never write header fields by hand.
- **`dlen` is body length, not total.** The header carries body bytes only
  (`XRD_RESPONSE_HDR_LEN` = 8 is added separately for the allocation). For
  `kXR_status` there are *two* lengths: `hdr.dlen = sizeof(bdy)+sizeof(pgr) = 24`
  (the status header the client reads first), while `bdy.dlen = total_with_crcs`
  (the page-data the client reads next). Confusing the two corrupts the stream
  (`status.c`).
- **kXR_error bodies must be NUL-terminated.** `xrootd_send_error()` sends
  `strlen(msg)+1` bytes because several XRootD clients parse the message as a C
  string with no explicit length; dropping the NUL causes client-side over-reads
  (`basic.c:77`).
- **CRC32c coverage is exact and non-obvious.** The pgread/pgwrite CRC covers
  `bdy.streamID` through the end of the `pgr`/`pgw` offset (20 bytes) and
  explicitly *excludes* the `crc32c` field itself and the page data. The client
  validates `Calc32C(msg+12, hdr.dlen−4) == Calc32C(bdy.streamID, 20)`; this
  mirrors the upstream `XrdXrootdResponse::srsComplete()` and must not be
  "simplified" (`status.c:57-69`).
- **Stream-ID echo is mandatory.** Helpers copy `ctx->cur_streamid` into the
  outgoing header (and into the inner `streamID` for status frames) so the client
  can demultiplex concurrent ops. The two attn variants differ deliberately:
  `asyncms` uses `{0,0}` (unsolicited), while `asynresp` echoes the *deferred*
  request's stream ID so the late answer is matched to the original request
  (`async.c`).
- **No I/O, no blocking, event-loop safe.** These helpers only allocate and fill
  buffers; the socket write happens in `xrootd_queue_response`. Builders are pure
  enough to run identically from a synchronous handler or from an AIO completion
  on the event loop — which is why `xrootd_build_pgread_status` returns a built
  struct instead of queueing.
- **Allocation discipline.** Frames use `ngx_palloc(c->pool, …)` (never raw
  malloc) and are pool-lifetime; `xrootd_queue_response` is passed `NULL` for the
  owned-base, signalling a pool-borrowed (no-free) buffer.
- **Retired opcodes fail closed.** Async opcodes 5000–5007 (except the still-live
  5002/5008 *action* codes used inside attn frames) are handled by the
  `xrootd_handle_async_*` stubs, which all return `kXR_Unsupported` rather than
  silently accepting (`async.c`).
- **`crc32c_file` sentinel.** `xrootd_crc32c_file()` returns `(uint32_t)-1` on
  read error; callers must check the sentinel rather than treating it as a valid
  checksum (`crc32c.c:39`).
- **`xrootd_send_redirect_tpc` opaque buffer is fixed-size.** The `?tpc.key=…`
  qualifier is formatted into a 160-byte stack buffer via `snprintf`; very long
  keys would truncate (`control.c:118`).

## Entry points / extending

**Add a new control/status response type** (e.g. a new server-push or
backpressure frame):
1. Declare the helper in `response.h` (or `async.h` for attn-family frames),
   documenting the exact wire layout in the header comment.
2. Implement it in the matching `.c` (`basic.c` for ok/error,
   `control.c` for redirect/wait, `status.c` for `kXR_status`, `async.c` for
   `kXR_attn`). Build the header with `xrootd_build_resp_hdr()`, set every
   multi-byte field big-endian, compute `dlen` as body-only, and finish with
   `return xrootd_queue_response(ctx, c, buf, total);`.
3. If you add a new `.c` file, register it in the top-level addon `config`
   script's source list and re-run `./configure` (incremental `make` will not pick
   up a new file).
4. Add the three required tests (success + error + security-negative) exercising
   the new opcode through a real handler.

**Add a new opcode that returns an existing frame type:** just call the existing
helper from the handler in its own subsystem — nothing changes here.

## See also

- `../connection/README.md` — `xrootd_queue_response` send path and stall handling
- `../protocol/README.md` — `ServerResponseHdr`, `kXR_status` structs, opcode constants
- `../read/README.md`, `../write/README.md` — primary producers of ok/error and pgread/pgwrite status
- `../aio/README.md` — async completion path that rebuilds responses on the event loop
- `../manager/README.md`, `../cms/README.md`, `../tpc/README.md` — redirect producers
- `../compat/README.md` — underlying CRC32c / checksum implementation
- `../README.md` — master subsystem index
