# connection — TCP connection lifecycle, framing, and the async I/O state machine for `root://`

## Overview

This subsystem is the stream-side spine of the module: every `root://`/`roots://`
request passes through it. When nginx accepts a TCP connection on an XRootD
listener, `ngx_stream_xrootd_handler()` (`handler.c`) is the per-connection entry
point. It allocates the per-connection `xrootd_ctx_t`, marks all file-handle
slots free, mints an opaque 16-byte session ID, assigns the shared-memory metrics
slot, and arms the read/write event handlers. From that point on the connection
is driven entirely by the nginx event loop through this directory — there is no
blocking I/O and no thread per connection.

The heart of the subsystem is the **recv state machine** in `recv.c`. It frames
the raw byte stream into discrete XRootD protocol units — the 20-byte client
hello, the 24-byte `ClientRequestHdr`, then `dlen` bytes of opcode payload — and
only once a complete, size-validated request is buffered does it hand off to
`xrootd_dispatch()` (in [../handshake/README.md](../handshake/README.md)). The
machine is a single explicit `xrootd_state_t` enum (`../types/state.h`): the
"active" framing states (`HANDSHAKE`/`REQ_HEADER`/`REQ_PAYLOAD`) interleave with
"suspend" states (`SENDING`/`AIO`/`UPSTREAM`/`PROXY`/`WAITING_CMS`/`TLS_HANDSHAKE`)
that hand the connection to another subsystem and return to the event loop until
that subsystem re-arms an event. This is how blocking file reads, redirector
queries, proxy forwarding, CMS locate waits, and TLS upgrades all coexist on a
single-threaded event loop without ever blocking it.

The rest of the directory supplies the machinery the state machine leans on:
`send.c` drains queued responses on write-ready events; `write_helpers.c`
implements the send/spin/park/resume logic and the per-connection **response
ring** (`out_ring`) that makes read pipelining safe; `tls.c` performs the
in-protocol `kXR_ableTLS` upgrade; `fd_table.c` owns the per-session open-file
slot table (the array index *is* the on-wire file handle) plus the bound-secondary
shared-handle validation; `disconnect.c` is the single teardown path that releases
every heap buffer, crypto object, registry slot, and metric on any close;
`event_sched.c` re-arms and posts events after async work; `chain_helpers.c` and
`budget.h` are small accounting helpers (pending-bytes counting and the SHM-global
transfer-heap budget).

Only `root://` (stream) traffic flows through this subsystem. WebDAV, S3, and the
`/metrics`/dashboard endpoints are HTTP-side and use nginx's HTTP request
machinery instead — but they share `fd_table.c` indirectly only through the VFS,
not through this directory.

## Files

| File | Responsibility |
|------|----------------|
| `handler.c` | `ngx_stream_xrootd_handler()` — per-connection entry point: alloc `xrootd_ctx_t`, init identity, free all fd slots, mint session ID, bind metrics slot (auth label, port, proxy-upstream labels, `connections_active++`), arm read/write handlers, fire first recv. |
| `recv.c` | The read-event state machine. Frames hello/header/payload, enforces the per-opcode payload cap **before allocation** (`xrootd_max_payload_for_request`), grows the reusable heap payload buffer (`xrootd_ensure_payload_buffer`), calls `xrootd_dispatch()`, and manages all suspend-state transitions, the Phase 29 read-pipelining/drain-barrier logic, and timeout handling (CMS-wait retry vs. disconnect). |
| `handler.h` | Prototypes for the three event entry points: `ngx_stream_xrootd_handler`, `ngx_stream_xrootd_recv`, `ngx_stream_xrootd_send`. |
| `send.c` | `ngx_stream_xrootd_send()` — write-event handler. Calls `xrootd_flush_pending()`; on full drain either pumps the next read window (`xrootd_read_window_pump`), starts a pending TLS upgrade, or returns to `REQ_HEADER` and re-enters recv. Disconnect on write timeout. |
| `write_helpers.c` | Response queue/flush engine: `xrootd_queue_response[_base]` (flat buffer), `xrootd_queue_response_chain` (sendfile/chain), `xrootd_flush_pending` (resume parked sends). Owns the `out_ring` FIFO so pipelined responses never interleave on the wire; spins up to `XROOTD_SEND_CHAIN_SPIN_MAX`; clears `TCP_CORK` + sets `TCP_NODELAY` after final segment; accounts `wire_bytes_tx_total`. |
| `write_helpers.h` | Prototypes + contract for the queue/flush API (parked-send semantics, `owned_base` ownership rules, `NGX_OK`/`NGX_AGAIN`/`NGX_ERROR` returns). |
| `tls.c` | In-protocol `kXR_ableTLS` upgrade: `xrootd_start_tls()` (clears stale OpenSSL error queue, creates SSL connection, runs handshake) and `xrootd_tls_handshake_done()` (success → resume at `REQ_HEADER`; failure → disconnect). |
| `tls.h` | Prototypes + preconditions for the TLS upgrade pair. |
| `fd_table.c` | Per-session open-file slot table. Alloc/free/validate handles; heap-owned path storage; **bound-secondary** shared-handle revalidation and lazy reopen (`xrootd_ensure_read_handle`); per-op capability re-checks (`xrootd_validate_{file,read,write}_handle`); teardown of checkpoint/POSC/TPC/write-through state on free. |
| `fd_table.h` | Documents the fhandle model (wire handle = slot index), the slot lifecycle, and the bound-secondary scope rule; prototypes for all table operations. |
| `disconnect.c` | `xrootd_on_disconnect()` — the single close path. Sets `destroyed=1` (AIO guard), releases budget + concurrency slot, cleans upstream/proxy/mirror, frees heap buffers + crypto state, finalizes metrics, emits "interrupted"/`DISCONNECT` access-log lines, unregisters the session, flushes the access log. |
| `disconnect.h` | Documents the 8-step teardown contract; note that it does **not** close fds (caller pairs it with `xrootd_close_all_files`). |
| `event_sched.c` | `xrootd_schedule_read_resume` / `xrootd_schedule_write_resume` — re-arm and post read/write events to `ngx_posted_events` so the loop resumes immediately after AIO/upstream completion instead of waiting for the next epoll cycle. |
| `event_sched.h` | Prototypes + duplicate-post-guard semantics for the resume helpers. |
| `chain_helpers.c` | `xrootd_chain_pending_bytes()` — sum `ngx_buf_size()` over a chain (NULL-safe); the single source of truth for "unsent bytes" used by all send/flush accounting. |
| `chain_helpers.h` | Prototype for the chain pending-bytes helper. |
| `budget.h` | Inline SHM-global transfer-heap budget (Phase 31 W4): `xrootd_budget_sync` (idempotent reconcile of this connection's scratch footprint), `xrootd_budget_release` (disconnect), `xrootd_budget_admit` (kXR_wait backpressure when the global cap would be exceeded). |

## Key types & data structures

- **`xrootd_ctx_t`** (`../types/context.h`) — the per-TCP-connection session
  context that lives for the whole connection (`ngx_pcalloc` on `c->pool`). It
  carries the framing cursors (`hdr_buf`/`hdr_pos`, parsed `cur_streamid`/
  `cur_reqid`/`cur_body`/`cur_dlen`), the reusable heap `payload_buf`, the open
  `files[XROOTD_MAX_FILES]` table, the `out_ring` send FIFO, the reusable scratch
  buffers, auth/identity state, the `metrics` SHM pointer, the `destroyed` AIO
  guard, and `tls_pending`. Nearly every function here takes `ctx` as its first
  argument.
- **`xrootd_state_t`** (`../types/state.h`) — the connection state enum that
  `recv.c`/`send.c`/`tls.c` switch on. Active framing states vs. suspend states
  (see Overview). The enum's header comment is the canonical narrative of the
  normal flow and each suspend state's event-arming behavior.
- **`xrootd_resp_slot_t`** + the `out_ring` (`../types/context.h`) — the
  per-connection response ring. Each slot parks one in-flight response (either a
  flat `wbuf` tail or a `wchain` of links plus its `wchain_pending` count and
  optional `owned_base`). `out_head`/`out_tail`/`out_count` make it a FIFO;
  `XROOTD_PIPELINE_MAX` (4, `../types/tunables.h`) bounds in-flight reads.
  `write_helpers.c` is the only writer; it guarantees only the head slot ever
  touches the socket so frames never interleave.
- **`xrootd_file_t`** (`../types/file.h`) — one open-file slot; the array index
  is the XRootD wire fhandle (0..`XROOTD_MAX_FILES`-1). Holds `fd`, resolved
  `path` (heap-owned), `readable`/`writable` capability bits, `device`/`inode`
  (validated on bound reopen), read-ahead/checkpoint/POSC/TPC/write-through state.
  `fd_table.c` is the owner of this struct's lifecycle.
- **`ngx_xrootd_srv_metrics_t`** (`../metrics/`) — the SHM per-server metrics
  block `ctx->metrics` points at; `handler.c` binds it and `disconnect.c`
  finalizes it.

## Control & data flow

**Entry.** A new TCP connection enters at `handler.c::ngx_stream_xrootd_handler`,
installed by postconfiguration. It sets `state = XRD_ST_HANDSHAKE` and calls
`ngx_stream_xrootd_recv(c->read)` to start framing.

**Inbound (recv loop).** `recv.c` accumulates bytes per the current state:
- `HANDSHAKE` (20 bytes) → `xrootd_process_handshake()` in
  [../handshake/README.md](../handshake/README.md) (`handshake/client_hello.c`) →
  `REQ_HEADER`.
- `REQ_HEADER` (24 bytes) → parse `ClientRequestHdr`, enforce the per-opcode
  payload cap, then either `REQ_PAYLOAD` (if `dlen > 0`) or dispatch immediately.
- `REQ_PAYLOAD` (`dlen` bytes) → dispatch.
- Dispatch goes to `xrootd_dispatch()`
  ([../handshake/README.md](../handshake/README.md)), which fans out to the opcode
  handlers in [../read/README.md](../read/README.md),
  [../write/README.md](../write/README.md), [../session/README.md](../session/README.md),
  and others.

**Outbound (responses).** Opcode handlers build responses and hand them to
`write_helpers.c` (`xrootd_queue_response*`). Bulk file reads come from
[../read/README.md](../read/README.md) and the thread-pool in
[../aio/README.md](../aio/README.md): cleartext reads use file-backed
chains + `sendfile`; TLS reads use memory-backed buffers (see invariants). When
`c->send`/`c->send_chain` returns `EAGAIN`, the unsent tail is parked in an
`out_ring` slot, the connection moves to `XRD_ST_SENDING`, and `send.c` resumes
it on the next write-ready event via `xrootd_flush_pending`.

**Suspend / resume to siblings.** Each suspend state hands the connection to a
sibling and returns to the event loop:
- `XRD_ST_AIO` → [../aio/README.md](../aio/README.md) thread pool; the completion
  callback re-arms via `event_sched.c`.
- `XRD_ST_UPSTREAM` → [../upstream/README.md](../upstream/README.md) redirector query.
- `XRD_ST_PROXY` → [../proxy/README.md](../proxy/README.md) transparent forwarding.
- `XRD_ST_WAITING_CMS` → manager locate via the CMS pending table
  ([../manager/README.md](../manager/README.md), [../cms/README.md](../cms/README.md));
  on timeout `recv.c` replies `kXR_wait` so the client retries.
- `XRD_ST_TLS_HANDSHAKE` → `tls.c`.

**Path & confinement.** This subsystem itself never resolves client paths for
I/O — dispatch and the op handlers do, always through
[../path/README.md](../path/README.md) before any syscall. The one place
`fd_table.c` opens a path directly is the bound-secondary reopen, and it does so
via `xrootd_open_beneath(conf->rootfd, rel, ...)` (RESOLVE_BENEATH) for exactly
that reason.

**Teardown.** Every close path (read EOF, write error, timeout, handshake
rejection, fatal dispatch error) funnels through `disconnect.c::xrootd_on_disconnect`
+ `fd_table.c::xrootd_close_all_files`, then `ngx_stream_finalize_session`.

## Invariants, security & gotchas

1. **Payload cap before allocation.** `recv.c::xrootd_max_payload_for_request`
   (recv.c:20) is the first defense against memory-exhaustion: untrusted `dlen`
   is rejected (`oversized_payloads_total++`, connection closed) *before*
   `xrootd_ensure_payload_buffer` allocates anything. Per-opcode limits:
   write/pgwrite/writev/chkpoint → `XROOTD_MAX_WRITE_PAYLOAD`; readv → segs ×
   segsize; auth → 32 KB; prepare → 64 KB; everything else → path + 64.
2. **Single-threaded ownership.** All functions here run on the nginx event
   thread and own the connection exclusively — no locking. The only cross-thread
   actor is the AIO thread pool, and the `ctx->destroyed = 1` flag set first in
   `xrootd_on_disconnect` is the guard a late AIO completion checks before
   touching freed state. Do not introduce blocking calls (`sleep`/blocking
   `read`/`pread`) in any handler — offload to [../aio/README.md](../aio/README.md).
3. **Heap (not pool) for cross-request buffers.** `payload_buf`, `prepare_paths`,
   the read/write scratch buffers, the `rd_pool` read buffers, and per-slot
   `owned_base` are raw `ngx_alloc`/`ngx_free` (so repeated large requests don't
   grow the connection pool). They are freed **only** in `disconnect.c`
   (`xrootd_release_disconnect_owned_buffers`) and on slot retire — missing one
   leaks for the connection's lifetime *and* mis-charges the SHM budget (see #7).
   This is exactly the class of bug fixed when `write_scratch` cleanup was added.
4. **Response frames must not interleave.** Only the **head** `out_ring` slot ever
   touches the socket (`xrootd_flush_pending` drains strictly head-first; queue
   functions park in the tail when `out_count > 0`). The drain-barrier logic in
   `recv.c` enforces that only `kXR_read` is pipelinable: any other opcode arriving
   while reads are still draining is deferred (`recv_deferred`) until the queue is
   quiescent, because e.g. a `kXR_close` could free a handle an in-flight sendfile
   chain still references.
5. **TLS vs. cleartext buffers never mix.** The cleartext read path parks
   file-backed chains for `sendfile`; the TLS path must use memory-backed buffers
   (that distinction lives in [../read/README.md](../read/README.md) /
   [../aio/README.md](../aio/README.md), but `recv.c`'s `resp_pipelinable` /
   `rd_win_active` gating depends on it — windowed/TLS reads are kept
   non-pipelinable because their data lives in shared scratch).
6. **TLS upgrade hygiene.** `xrootd_start_tls` calls `ERR_clear_error()` first
   (tls.c:60): the module never clears the per-thread OpenSSL error queue
   elsewhere, and a dirty queue makes nginx misreport a benign close as
   "SSL_do_handshake() failed", inflating spurious `kXR_ableTLS` failures. TLS is
   started only after the `kXR_haveTLS` response has fully drained (`tls_pending`
   checked in both `recv.c` and `send.c`). No cleartext fallback after
   `kXR_haveTLS`.
7. **SHM-global transfer-heap budget.** `budget.h` charging is **idempotent
   reconciliation**, never paired inc/dec: `xrootd_budget_sync` (called after any
   scratch grow/trim in `recv.c`) applies only the delta vs. `budget_charged`, so
   it can't drift negative or double-count; `xrootd_budget_release` zeroes it on
   disconnect. Admission (`xrootd_budget_admit`) returns 0 → caller sends
   `kXR_wait` rather than suspending server-side, and never deadlocks a lone
   transfer when the pool is otherwise empty.
8. **fhandle = slot index, one wire byte.** `xrootd_alloc_fhandle` returns a slot
   in `[0, XROOTD_MAX_FILES)` (16); the value is sent verbatim as the wire handle.
   Validate before every I/O — `xrootd_validate_{read,write}_handle` re-check the
   `readable`/`writable` capability bit set at open time (capability-drift
   defense) rather than re-resolving the path per read.
9. **Bound secondaries are read-only and revocable.** A `kXR_bind` secondary may
   only *read* the primary's published handle, never open/close/write its own.
   `xrootd_ensure_read_handle` re-checks the primary's shared-memory slot on every
   read; if the primary closed/reused/teared-down the slot, the secondary's local
   fd is revoked (`NGX_DECLINED`). Stale-but-published handles are lazily reopened
   via `xrootd_open_beneath` with `device`/`inode` revalidation — a changed
   filesystem object revokes access.
10. **Disconnect is the only place fd-less cleanup happens.** POSC temp files,
    checkpoint files, and TPC registry entries are unlinked/removed in
    `xrootd_free_fhandle` when a session ends without a clean `kXR_close`. The
    `destroyed` guard plus the access-log flush (`xrootd_access_log_flush`) at the
    end of `xrootd_on_disconnect` make interrupted-transfer records durable
    immediately.
11. **Non-XRootD clients are dropped fast.** In `HANDSHAKE`, a nonzero first byte
    (`hdr_buf[0] != 0`) means a non-XRootD client and the connection is closed
    immediately (recv.c:288).

## Entry points / extending

- **New stream opcode:** you do **not** edit this subsystem — register the opcode
  in [../handshake/README.md](../handshake/README.md) (`dispatch_*.c`) and add the
  handler under the relevant op directory. Touch `recv.c` only if the opcode needs
  a new payload-size class (add a branch to `xrootd_max_payload_for_request`) or
  is safe to pipeline behind in-flight reads (extend the drain-barrier conditions).
- **New per-connection field:** add it to `xrootd_ctx_t` (`../types/context.h`),
  initialize it in `handler.c`, and — critically — release it in `disconnect.c`
  if it owns heap or crypto state (and reconcile it into `budget.h` if it holds
  transfer scratch).
- **New suspend state:** add it to `xrootd_state_t` (`../types/state.h`), give
  `recv.c` (and `send.c` if it can complete on a write event) a branch that
  re-arms the read event and returns, and have the owning subsystem call
  `xrootd_schedule_read_resume`/`_write_resume` on completion.
- **New response shape:** queue it through `write_helpers.c`
  (`xrootd_queue_response` for a flat buffer, `xrootd_queue_response_chain` for
  sendfile/chains); pass `owned_base` if the backing buffer is raw-heap so it is
  freed on completion/disconnect.

## See also

- [../handshake/README.md](../handshake/README.md) — opcode dispatcher this loop hands off to.
- [../read/README.md](../read/README.md), [../write/README.md](../write/README.md) — opcode bodies that build responses.
- [../aio/README.md](../aio/README.md) — thread-pool offload that drives `XRD_ST_AIO`.
- [../path/README.md](../path/README.md) — RESOLVE_BENEATH confinement used by dispatch + bound reopen.
- [../session/README.md](../session/README.md) — login/auth/bind + the shared session registry `disconnect.c` unregisters from.
- [../upstream/README.md](../upstream/README.md), [../proxy/README.md](../proxy/README.md) — drive `XRD_ST_UPSTREAM`/`XRD_ST_PROXY`.
- [../manager/README.md](../manager/README.md), [../cms/README.md](../cms/README.md) — drive `XRD_ST_WAITING_CMS` (locate/redirect).
- [../metrics/README.md](../metrics/README.md) — SHM counters `handler.c` binds and `disconnect.c` finalizes.
- [../types/README.md](../types/README.md) — `xrootd_ctx_t`, `xrootd_state_t`, `xrootd_file_t`, `xrootd_resp_slot_t`, tunables.
- [../README.md](../README.md) — master subsystem index.
