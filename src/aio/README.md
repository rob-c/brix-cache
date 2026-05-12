# aio — Thread-pool async I/O for read and write handlers

Implements the nginx thread-pool offload layer for file I/O operations.
Every file in this directory follows the same two-function pattern:

| File | Thread function | Completion callback |
|------|----------------|---------------------|
| `config.c` | nginx directive parser for `xrootd_thread_pool` (resolves the named nginx thread-pool handle) | — |
| `read.c` | `xrootd_read_aio_thread` | `xrootd_read_aio_done` |
| `pgread.c` | `xrootd_pgread_aio_thread` | `xrootd_pgread_aio_done` |
| `readv.c` | `xrootd_readv_aio_thread` | `xrootd_readv_aio_done` |
| `write.c` | `xrootd_write_aio_thread` | `xrootd_write_aio_done` |

The `_thread` function runs inside an nginx worker thread and performs the
blocking `pread`/`pwrite` syscall.  The `_done` callback fires on the main
event loop once the thread completes; it queues the response and reschedules
the connection for the next request.

`resume.c` — shared callback plumbing: restore request identity, post AIO
tasks, and re-enter the recv loop when more data is waiting on the socket.

`buffers.c` — `xrootd_release_read_buffer` and the shared buffer-allocation
helpers used by both the synchronous and the AIO read paths so that the
response chain is built the same way regardless of which code path runs.

All code in this directory is compiled only when nginx is built with thread
support (`NGX_THREADS`).

## Data flow

The AIO detour keeps blocking file I/O off the event-loop thread.  Every
opcode that uses it follows the same three-phase pattern.

```
[main event loop thread]
read/read.c (or write/write.c, etc.)
    └─ aio/read.c: xrootd_try_post_read_aio()
           allocates xrootd_aio_ctx_t (heap)
           sets ctx->state = XRD_ST_AIO
           disarms recv and send events
           ngx_thread_task_post(pool, task)
                │
                │       [nginx worker thread — blocking]
                ▼
           aio/read.c: xrootd_read_aio_thread()
               pread(fd, buf, count, offset)
               stores n / errno in aio_ctx
                │
                │       [main event loop thread — completion callback]
                ▼
           aio/read.c: xrootd_read_aio_done()
               if ctx->destroyed → ngx_free(aio), return
               build response chain (aio/buffers.c)
               aio/resume.c: xrootd_aio_resume()
                   restores cur_streamid / cur_reqid in ctx
                   connection/event_sched.c: xrootd_schedule_write_resume()
                       arms write event → connection/send.c flushes response
                       re-arms read event → recv.c reads next request
```

The completion callback always fires on the main event loop (nginx's
`ngx_post_event` mechanism), so it is safe to touch `ctx` and `c` after the
`destroyed` check — the connection cannot be torn down between the check and
the rest of the callback because the event loop is single-threaded per worker.

`aio/buffers.c` provides `xrootd_release_read_buffer()` and the shared
buffer-allocation helpers so that both the synchronous and AIO paths build
response chains in exactly the same way.  The caller does not need to know
which path ran.
