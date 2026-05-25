# connection — TCP connection lifecycle and I/O state machine

Core connection machinery that every XRootD request passes through.

| File | Responsibility |
|------|----------------|
| `handler.c` | Entry point for new stream connections; allocates `xrootd_ctx_t` and arms the read event |
| `recv.c` | Read-event loop: frames handshake / request header / payload bytes, then calls `xrootd_dispatch` |
| `send.c` | Write-event drain: flushes the pending response chain; triggers TLS upgrade when `tls_pending` is set |
| `tls.c` | kXR_ableTLS in-protocol TLS upgrade: `xrootd_start_tls` / `xrootd_tls_handshake_done` |
| `disconnect.c` | `xrootd_on_disconnect` — metrics, access-log, and session cleanup on any close path |
| `fd_table.c` | Per-session open-file slot table plus shared read/write handle validation |
| `event_sched.c` | `xrootd_schedule_read_resume` / `xrootd_schedule_write_resume` — re-arm events after AIO |
| `chain_helpers.c` | `xrootd_chain_pending_bytes` — count bytes still in a response chain |
| `write_helpers.c` | `xrootd_queue_response` / `xrootd_queue_response_chain` — append to the pending write chain |
| `chain_helpers.h` | Chain helper types and prototypes |
| `disconnect.h` | Disconnect handler types and prototypes |
| `event_sched.h` | Event scheduler types and prototypes |
| `fd_table.h` | File descriptor table types and prototypes |
| `handler.h` | Connection handler types and prototypes |
| `tls.h` | TLS upgrade types and prototypes |
| `write_helpers.h` | Write helper types and prototypes |

The `recv.c` state machine cycles through these states (defined in
`ngx_xrootd_module.h`):

```
XRD_ST_HANDSHAKE → XRD_ST_REQ_HEADER → XRD_ST_REQ_PAYLOAD
                                       → XRD_ST_SENDING
                                       → XRD_ST_AIO
                                       → XRD_ST_TLS_HANDSHAKE
                                       → XRD_ST_UPSTREAM
```

## Data flow

A new TCP connection enters the module at `handler.c`, which allocates the
per-connection `xrootd_ctx_t` and arms the read event.  All subsequent I/O
is driven by `recv.c` and `send.c` until the connection closes.

```
kernel: new TCP connection
    └─ connection/handler.c: ngx_stream_xrootd_handler()
           allocates xrootd_ctx_t, sets state = XRD_ST_HANDSHAKE
           arms the read event → ngx_stream_xrootd_recv

connection/recv.c: ngx_stream_xrootd_recv()   [fires on each read-ready event]
    ├─ HANDSHAKE: accumulate 20 bytes
    │       → handshake/client_hello.c: xrootd_process_handshake()
    │         sends 12-byte handshake reply, sets state = XRD_ST_REQ_HEADER
    ├─ REQ_HEADER: accumulate 24 bytes
    │       parse streamid / reqid / body / dlen from hdr_buf
    │       if dlen > 0  → allocate payload_buf, set state = XRD_ST_REQ_PAYLOAD
    │       if dlen == 0 → call xrootd_dispatch() immediately
    └─ REQ_PAYLOAD: accumulate dlen bytes
            → call xrootd_dispatch()
            → reset state = XRD_ST_REQ_HEADER for next request

[when a response is queued and c->send() returns EAGAIN]
    state = XRD_ST_SENDING, write event armed
    connection/send.c: xrootd_send_pending()
        drains wbuf / wchain, re-arms read event when complete
```

After `xrootd_dispatch()` returns, `recv.c` checks the new state: if
`XRD_ST_SENDING` or `XRD_ST_AIO`, it returns to the event loop; otherwise
it loops immediately to read the next request header.
