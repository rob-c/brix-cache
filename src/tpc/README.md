# tpc — Third-Party Copy

This directory implements the native XRootD destination-side pull path used
when a write-mode `kXR_open` carries TPC opaque parameters such as
`tpc.src=root://source//path`. The server connects to the remote `root://`
source, fetches the file, and writes it to the local filesystem before
returning the open response.

HTTP-TPC for WebDAV `COPY` lives separately under `src/webdav/tpc*.c`.

## Protocol sequence

```
Client                 nginx-xrootd              Remote root:// origin
  |                        |                          |
  |--kXR_open dst?tpc.src->|                          |
  |                        |--connect + handshake---->|
  |                        |--kXR_login + kXR_open--->|
  |                        |--kXR_read (loop)-------->|
  |                        |<-file data---------------|
  |                        |--kXR_close-------------->|
  |<-kXR_open response-----|                          |
```

The fetch loop runs inside a thread-pool worker so that blocking socket I/O
does not stall the nginx event loop.

## Files

| File | Runs on | Purpose |
|---|---|---|
| `parse.c` | event thread | Parse `root://` source URL into host, port, and path. |
| `launch.c` | event thread | nginx entry point — validates the destination open, allocates the `xrootd_tpc_pull_t` task struct, and posts the work to the thread pool. |
| `thread.c` | thread pool | Orchestrates the full pull: connect → bootstrap → open source → read loop → close. |
| `connect.c` | thread pool | Blocking TCP connect to the remote origin (with configurable timeout). |
| `bootstrap.c` | thread pool | Anonymous XRootD source setup: handshake frame → kXR_protocol → kXR_login. Authenticated source fetch/delegation is not implemented here. |
| `source.c` | thread pool | Remote file open (`kXR_open`), streaming read loop (`kXR_read`), and remote close (`kXR_close`). |
| `io.c` | thread pool | Low-level socket helpers: `send_all`, `recv_all`, and the XRootD response framer `xrootd_tpc_read_response`. |
| `done.c` | event thread | Completion callback — sends the deferred `kXR_open` success response or error after the thread finishes. |
| `tpc_internal.h` | — | Shared types (`xrootd_tpc_params_t`, `xrootd_tpc_pull_t`, `xrootd_tpc_conn_t`) and internal API declarations. |
| `gsi_outbound_certreq.c` | GSI outbound certificate request: build and send XrdSutBuffer cert chain |
| `gsi_outbound_common.c` | Shared GSI outbound helpers: buffer allocation, step sequencing |
| `gsi_outbound_dh_helpers.c` | Diffie-Hellman key exchange: DH parameter generation and shared secret derivation |
| `gsi_outbound_exchange.c` | GSI certificate/DH exchange protocol between source and destination |
| `gsi_outbound_finish.c` | Finalize GSI handshake with source server |
| `key_registry.c` | SHM-based TPC key registry — cross-process zero-copy file handle coordination |
| `key_registry.h` | Key registry types and prototypes |
| `tpc_token.c` | Token-authenticated TPC: JWT credential forwarding to remote source |

## Thread-safety note

Everything under `#if (NGX_THREADS)` in this directory runs inside a detached
thread-pool worker. **`ngx_palloc` is not thread-safe here** — all allocations
in `thread.c`, `connect.c`, `bootstrap.c`, `source.c`, and `io.c` use
`malloc`/`free` intentionally. Only `launch.c` and `done.c` (event-thread
code) may use `ngx_palloc(c->pool, ...)`.

## See also

- `docs/webdav.md` §TPC for the separate WebDAV HTTP-TPC implementation.
- `src/aio/` for the simpler local-read async pattern.
- `src/cache/` for the read-through cache, which follows the same thread/done
  split but for origin fetches.
