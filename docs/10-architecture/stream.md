# Native XRootD stream architecture

How the nginx stream module becomes an XRootD server: connection accept, handshake, dispatch, and the hot read/write paths.

[← Architecture overview](index.md)

## Overview

```
TCP connect
    │
    ▼
ngx_stream_xrootd_handler()        connection/handler.c
  Allocate xrootd_ctx_t, arm events
    │
    ▼
ngx_stream_xrootd_recv()           connection/recv.c
  ┌─────────────────────────────────────────────────────────┐
  │  HANDSHAKE: accumulate 20 bytes                         │
  │      → xrootd_process_handshake()  handshake/client_hello.c  │
  │      → send 16-byte handshake response                  │
  │      → transition to REQ_HEADER                         │
  │                                                         │
  │  REQ_HEADER: accumulate 24 bytes                        │
  │      parse: streamid[2] reqid[2] body[16] dlen[4]       │
  │      if dlen > 0 → allocate payload_buf → REQ_PAYLOAD   │
  │      if dlen == 0 → call xrootd_dispatch() immediately   │
  │                                                         │
  │  REQ_PAYLOAD: accumulate dlen bytes                     │
  │      → call xrootd_dispatch()                           │
  └─────────────────────────────────────────────────────────┘
    │
    ▼
xrootd_dispatch()                  handshake/dispatch.c
  1. verify pending kXR_sigver and enforce configured security level
  2. xrootd_dispatch_session_opcode()  dispatch_session.c
       kXR_protocol, kXR_login, kXR_auth, kXR_ping,
       kXR_set, kXR_endsess, kXR_bind
  3. xrootd_dispatch_read_opcode()    dispatch_read.c
       kXR_stat, kXR_open, kXR_read, kXR_close,
       kXR_dirlist, kXR_readv, kXR_query, kXR_prepare,
       kXR_pgread, kXR_locate, kXR_statx, kXR_fattr, kXR_clone
  4. xrootd_dispatch_write_opcode()   dispatch_write.c
       kXR_write, kXR_pgwrite, kXR_writev, kXR_sync,
       kXR_truncate, kXR_mkdir, kXR_rm, kXR_rmdir,
       kXR_mv, kXR_chmod, kXR_chkpoint
  5. xrootd_dispatch_signing_opcode() dispatch_signing.c
       kXR_sigver
    │
    ▼
  handler (session/, read/, write/, query/, fattr/, dirlist/)
    │
    ▼
  response path (see below)
```

---

## State machine

`xrootd_ctx_t.state` controls which code path `recv.c` takes on each event.

```
         ┌──────────────────────────────────────────┐
         │             (new connection)              │
         ▼                                          │
    HANDSHAKE  ──20 bytes──►  REQ_HEADER            │
                                  │                 │
               ┌──────────────────┤                 │
               │ dlen > 0         │ dlen == 0       │
               ▼                  ▼                 │
          REQ_PAYLOAD ──► dispatch() ───────────────┘
               │              │
               │         ┌────┴──────────┬────────────────┐
               │         ▼               ▼                ▼
               │      SENDING          AIO          TLS_HANDSHAKE
               │      (socket        (thread         (SSL accept
               │      backpressure)   pool I/O)       in progress)
               │         │               │                │
               └─────────┴───────────────┴────────────────┘
                                   ▼
                             REQ_HEADER  (next request)
```

**SENDING** — `xrootd_queue_response()` got EAGAIN from `c->send()`. The write
event is armed; `send.c` drains the buffer then re-arms the read event.

**AIO** — a handler posted a `pread`/`pwrite` to the nginx thread pool. Both
events are disarmed. The `_done` callback (still on the main thread) queues the
response and calls `xrootd_aio_resume()`, which re-arms the write event.

**TLS_HANDSHAKE** — `kXR_protocol` replied with `kXR_gotoTLS`. After the
handshake, `xrootd_tls_handshake_done()` restores the recv handler and normal
framing resumes.

**UPSTREAM** — a `kXR_locate` or redirect triggered an outbound query to the
upstream redirector. The client-side read event is disarmed while
`upstream/` drives the redirector connection.

---

## File handle lifecycle

Native XRootD is handle-oriented after `kXR_open`. The path is resolved and
authorized once at open time; later read/write operations mostly operate on the
cached handle state.

```text
kXR_open(path, flags)
    |
    +-- manager map says redirect?
    |       |
    |       +-- yes -> kXR_redirect(host, port)
    |       +-- no  -> continue locally
    |
    +-- resolve path under configured root
    +-- check token scopes / VO ACL / write gate
    +-- open(2) or stat(2) as needed
    |
    v
ctx->files[handle]
    |
    +-- fd
    +-- canonical path for logging/query/checksum
    +-- open flags and write/read permissions
    +-- cached size when safe
    +-- counters used for close-time logging
    |
    +-- kXR_read / kXR_pgread / kXR_readv
    +-- kXR_write / kXR_pgwrite / kXR_writev
    +-- handle stat/checksum/sync
    |
    v
kXR_close or disconnect -> close fd and clear slot
```

This is why adding path resolution, `stat()`, or authorization work to every
handle-based I/O request can be both a correctness change and a performance
regression.

---

## Inside a handler: the common path

Every protocol handler (e.g., `xrootd_handle_read` in `read/read.c`) follows
this skeleton:

```
1. Cast ctx->hdr_buf → ClientXxxRequest* for typed field access
2. Validate the file handle or path (connection/fd_table.c)
3. Resolve the path to a real filesystem path (path/resolve.c)
4. Check VO ACL and token scope (path/acl.c, token/scopes.c)
5. Perform the operation (syscall: open/pread/pwrite/stat/…)
6. Log the result (path/access_log.c: xrootd_log_access)
7. Increment the metric counter (XROOTD_OP_OK / XROOTD_OP_ERR)
8. Send the response (response/basic.c: xrootd_send_ok / xrootd_send_error)
```

Steps 6–8 must always run together and in that order. If a handler sends a
body larger than a small flat buffer (e.g., read data or dirlist chunks), it
uses `xrootd_queue_response_chain()` instead of `xrootd_send_ok()`.

Response construction is usually one of these shapes:

```text
small metadata response
    [XRootD response header + small body in memory]
                    |
                    v
              xrootd_send_ok()

cleartext regular-file read
    [small XRootD header buf] -> [file-backed ngx_buf_t slice]
                    |
                    v
          xrootd_queue_response_chain()
                    |
                    v
       nginx send chain / possible sendfile path

TLS, readv, pgread, or packed response
    [worker or thread pool fills memory buffer]
                    |
                    v
          [memory-backed ngx_buf_t chain]
                    |
                    v
          xrootd_queue_response_chain()
```

---

## Backpressure and response draining

nginx send calls may write only part of a response. The module keeps the
remaining chain on the connection context and waits for the next writable event.

```text
handler builds response chain
        |
        v
xrootd_queue_response_chain()
        |
        +-- send all bytes now?
        |       |
        |       +-- yes -> free transient chain state
        |                -> re-arm read event
        |                -> state = REQ_HEADER
        |
        +-- no, socket returned EAGAIN / partial write
                |
                v
          state = SENDING
          remember pending chain + pending byte count
          arm write event
                |
                v
          write event fires
                |
                v
          continue from saved chain position
```

The worker must not spin forever on one large response. The send path uses
posted continuations and pending-byte tracking to make forward progress without
starving other ready connections.

---

## The AIO detour (thread-pool reads and writes)

When nginx is built with `--with-threads`, file I/O is offloaded to avoid
blocking the event loop:

```
handler (read/read.c, write/write.c, …)
    │
    ├─ xrootd_try_post_read_aio()  ──►  ngx_thread_task_post(pool, task)
    │                                        ctx->state = XRD_ST_AIO
    │                                        [recv/send events disarmed]
    │                                              │
    │                              [worker thread] ▼
    │                              xrootd_read_aio_thread()
    │                                  pread(fd, buf, len, offset)
    │                                              │
    │                           [main event loop] ▼
    │                              xrootd_read_aio_done()  aio/read.c
    │                                  check ctx->destroyed
    │                                  build response chain
    │                                  xrootd_aio_resume()  connection/event_sched.c
    │                                      ▼
    │                                  schedule_write_resume()
    │                                  [write event fires → flush response]
    │                                  [read event re-armed → next request]
    │
    └─ (no thread pool) → synchronous pread/pwrite inline
```

Each I/O type (read, pgread, readv, write) has a separate `_thread` /  `_done`
pair in `aio/`. The pattern is identical for all four.

---

## Authentication flow

XRootD uses a two-step model: login then auth.

```
kXR_login  (session/login.c)
    │ sets logged_in = 1, issues sessid, may issue GSI/token challenge
    ▼
kXR_auth   (session/auth.c → gsi/auth.c or token/validate.c or sss/auth.c)
    │ validates credentials, sets auth_done = 1, extracts DN/VOs/scopes
    ▼
All subsequent opcodes check logged_in && auth_done via
xrootd_dispatch_require_auth() in handshake/policy.c
```

For GSI, `kXR_auth` may require multiple round-trips (DH key exchange):
the handler returns `kXR_authmore` until all GSI phases complete.

---

## Key source files quick-reference

| What you want to understand | Where to look |
|---|---|
| How a new TCP connection starts | `connection/handler.c` |
| How bytes become a parsed request | `connection/recv.c` |
| How an opcode gets routed to its handler | `handshake/dispatch*.c` |
| How a response is queued and flushed | `connection/write_helpers.c`, `connection/send.c` |
| How paths are resolved and checked | `path/resolve.c`, `path/acl.c` |
| How file handles are tracked | `connection/fd_table.c`, `ngx_xrootd_module.h` (`xrootd_file_t`) |
| How AIO works | `aio/resume.c`, `aio/read.c`, `aio/write.c` |
| How metrics are counted | `metrics/metrics.h` (`XROOTD_OP_OK`, `XROOTD_OP_ERR`) |
| What every xrootd_ctx_t field means | `ngx_xrootd_module.h`, `docs/types.md` |
| How to add a new opcode | `docs/contributing.md` |
| How a WebDAV request is routed | `src/protocols/webdav/dispatch.c` |
| How an S3 request is routed | `src/protocols/s3/handler.c` |

---
