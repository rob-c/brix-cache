# Handler reference

The internal building blocks every handler uses — quick reference to keep open while writing code. For fuller context read
`docs/architecture.md` first.

---

## Response helpers

All response helpers are declared in `src/protocols/root/response/response.h` and
implemented in `src/protocols/root/response/`.

### `brix_send_ok`

```c
ngx_int_t brix_send_ok(brix_ctx_t *ctx, ngx_connection_t *c,
    const void *body, uint32_t bodylen);
```

Sends a `kXR_ok` response. Pass `NULL, 0` for zero-body responses (the
common case). For responses with a body (stat results, read data, open
handles) pass a pointer and byte count; the function copies the bytes into
a pool-allocated wire buffer.

### `brix_send_error`

```c
ngx_int_t brix_send_error(brix_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *msg);
```

Sends a `kXR_error` response. `errcode` is one of the `kXR_*` constants from
`src/protocols/root/protocol/opcodes.h` (e.g. `kXR_NotFound`, `kXR_NotAuthorized`,
`kXR_IOError`). `msg` is a human-readable string; it is NUL-terminated on the
wire so clients can treat it as a C string.

### `brix_queue_response`

```c
ngx_int_t brix_queue_response(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf, size_t len);
```

Low-level send for pre-built wire buffers. Use this when the response header
and body are already assembled (e.g. kXR_open returns handle + stat string in
one allocation). The buffer must be pool-allocated from `c->pool`; ownership
passes to the send machinery.

### `brix_send_redirect` / `brix_send_wait` / `brix_send_waitresp`

```c
ngx_int_t brix_send_redirect(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *host, uint16_t port);

ngx_int_t brix_send_wait(brix_ctx_t *ctx, ngx_connection_t *c,
    uint32_t seconds);

ngx_int_t brix_send_waitresp(brix_ctx_t *ctx, ngx_connection_t *c);
```

Used by the upstream redirect and CMS manager paths. Rarely needed for new
opcodes.

### `brix_send_error_sid` (Phase 80+)

```c
ngx_int_t brix_send_error_sid(brix_ctx_t *ctx, ngx_connection_t *c,
    const u_char sid[2], uint16_t errcode, const char *msg);
```

**Streamid-specific error** — sends `kXR_error` with explicit streamid. Use when:
- Answering a request on a bound SECONDARY channel (not `ctx->recv.cur_streamid`)
- Sending terminating error for chunked pgread with partial frames already committed
- Error must ride the same channel under the original request's sid

**Source**: `src/protocols/root/response/response.h:28-32`

---

## CMS Answer Functions (Phase 105+)

### `brix_cms_answer_selected`

```c
ngx_int_t brix_cms_answer_selected(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *host, int port);
```

**CMS manager answer** — sends selected upstream host after `kYR_locate`/`kYR_select`.
Used by cluster membership service (CMS) redirector path.

**Source**: `src/net/cms/cms_select.c`

---

## pgwrite Status Functions (Phase 88+)

### `brix_send_pgwrite_status`

```c
ngx_int_t brix_send_pgwrite_status(brix_ctx_t *ctx, ngx_connection_t *c,
    uint16_t status, const u_char sid[2]);
```

**pgwrite status frame** — sends `kXR_pgwrite` status answer. Used for
checksummed write acknowledgments (CRC32c verified writes).

**Source**: `src/protocols/root/response/pgwrite_status.c`

### `brix_send_pgwrite_cse`

```c
ngx_int_t brix_send_pgwrite_cse(brix_ctx_t *ctx, ngx_connection_t *c,
    const u_char sid[2], int64_t offset, uint32_t dlen);
```

**pgwrite checksum-error (CSE) frame** — signals uncorrected CRC32c error on
specific page. The page is recorded in the per-handle "Fob" (uncorrected-page
registry); `kXR_close` fails with `kXR_ChkSumErr` while any page remains.

**Source**: `src/protocols/root/response/pgwrite_cse.c`

---

## TPC Functions (Phase 57+)

### `brix_send_redirect_tpc`

```c
ngx_int_t brix_send_redirect_tpc(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *host, int port, const char *path);
```

**TPC redirect frame** — sends third-party copy redirect answer. Used when
native `root://` TPC destination arms rendezvous and redirects source.

**Source**: `src/protocols/root/response/redirect_tpc.c`

---

## Response Builders (Phase 29+)

### `brix_build_resp_hdr`

```c
ngx_int_t brix_build_resp_hdr(brix_ctx_t *ctx, u_char *buf,
    uint16_t opcode, uint16_t status, uint32_t dlen);
```

**Response header builder** — assembles 24-byte XRootD response header.
Used by all response helpers; call directly only for custom frame layouts.

**Source**: `src/protocols/root/response/response_builders.c`

### `brix_open_ok_frame`

```c
ngx_int_t brix_open_ok_frame(brix_ctx_t *ctx, u_char *buf, uint32_t size);
```

**kXR_open OK frame builder** — assembles complete open-OK response
(handle + stat info + flags). Used by `kXR_open` handler after successful
open.

**Source**: `src/protocols/root/response/open_ok.c`

### `brix_build_pgread_status_*` (Phase 88+)

```c
ngx_int_t brix_build_pgread_status_ok(brix_ctx_t *ctx, u_char *buf, size_t len);

ngx_int_t brix_build_pgread_status_cse(brix_ctx_t *ctx, u_char *buf,
    size_t len, int64_t offset, uint32_t dlen);
```

**pgread status builders** — assemble `kXR_pgread` status frames:
- `ok`: Checksummed read completed successfully
- `cse`: Checksum error on specific page (offset, dlen)

**Source**: `src/protocols/root/response/pgread_status.c`

---

## CRC32c Helpers (Phase 88+)

```c
uint32_t brix_crc32c_init(void);
uint32_t brix_crc32c_update(uint32_t crc, const u_char *buf, size_t len);
uint32_t brix_crc32c_finish(uint32_t crc);
uint32_t brix_crc32c(const u_char *buf, size_t len);
```

**Hardware-accelerated CRC32c** — ARM64 CRC32C instructions (10-20x speedup),
x86 SSE4.2 fallback, pure software fallback. Used by `kXR_pgread`/`kXR_pgwrite`
checksum verification.

**Source**: `src/platform/linux/crc32c_arm64.c`, `src/core/compat/crc32c_fallback.c`

---

## Shortcut macros

Defined in `src/core/types/tunables.h`. Use these when the error message in the
access log and in the wire response are identical and the handler returns
immediately.

### `BRIX_RETURN_OK`

```c
BRIX_RETURN_OK(ctx, c, op, verb, path, detail, bytes)
```

Equivalent to:
```c
brix_log_access(ctx, c, verb, path, detail, 1, kXR_ok, NULL, bytes);
BRIX_OP_OK(ctx, op);
return brix_send_ok(ctx, c, NULL, 0);
```

**Constraint**: only for zero-body responses. Handlers that send a body (read
data, stat results, query output) must keep the three lines explicit.

### `BRIX_RETURN_ERR`

```c
BRIX_RETURN_ERR(ctx, c, op, verb, path, detail, code, msg)
```

Equivalent to:
```c
brix_log_access(ctx, c, verb, path, detail, 0, code, msg, 0);
BRIX_OP_ERR(ctx, op);
return brix_send_error(ctx, c, code, msg);
```

The `detail` string goes to the access log; `msg` goes to the wire. They can
differ when the access log needs more context than the client should see.

---

## Access logging

```c
void brix_log_access(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *verb, const char *path, const char *detail,
    ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg, size_t bytes);
```

Declared in `src/fs/path/path.h`, implemented in `src/observability/accesslog/access_log.c`.

| Parameter | Meaning |
|---|---|
| `verb` | uppercase opcode name, e.g. `"READ"`, `"OPEN"`, `"STAT"` |
| `path` | the resolved filesystem path, or `"-"` for non-path ops |
| `detail` | free-form context string shown in the log line |
| `xrd_ok` | `1` for success, `0` for error |
| `errcode` | XRootD error code (ignored when `xrd_ok == 1`) |
| `errmsg` | error message for the log (may differ from wire message) |
| `bytes` | bytes transferred (use `0` for non-data ops) |

**Rule**: every handler code path — both success and error — must call
`brix_log_access` before returning. Missing log calls produce silent gaps
in the audit trail.

---

## AIO dispatch pattern (Phase 1-31)

Use async I/O for reads and writes so the nginx event loop is not blocked by
filesystem calls. The pattern is always a `_thread` / `_done` pair.

**Note**: This is the Phase 1-31 single-AIO pattern. Phase 32+ uses concurrent-AIO
pipeline (see "Concurrent-AIO Read Pipeline (Phase 32+)" below).

### Posting a task

```c
/* In the synchronous handler (event-loop side): */
task = ngx_thread_task_alloc(c->pool, sizeof(brix_read_aio_t));
t = task->ctx;
t->ctx = ctx;
t->c = c;
/* ... fill in t->fd, t->offset, t->rlen, etc. */

task->handler = brix_read_aio_thread;   /* blocking syscall */
task->event.handler = brix_read_aio_done; /* completion callback */
task->event.data = task;

ctx->state = XRD_ST_AIO;
if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
    /* post failed — handle synchronously or return error */
}
```

### Thread function

```c
void brix_read_aio_thread(void *data, ngx_log_t *log)
{
    brix_read_aio_t *t = data;
    t->nread = pread(t->fd, t->databuf, t->rlen, t->offset);
    if (t->nread < 0) { t->io_errno = errno; }
    /* Do NOT touch ctx, c->pool, or any nginx structure here. */
}
```

The thread function may only touch fields stored in the task struct itself.
`ctx`, `c->pool`, and all nginx internals are off-limits.

### Completion callback (done function)

```c
void brix_read_aio_done(ngx_event_t *ev)
{
    brix_read_aio_t *t = ((ngx_thread_task_t *) ev->data)->ctx;
    brix_ctx_t      *ctx = t->ctx;
    ngx_connection_t  *c = t->c;

    /* ALWAYS check destroyed first — connection may have closed. */
    if (!brix_aio_restore_stream(ctx, t->streamid)) {
        return;   /* connection gone; nothing to do */
    }

    /* Now safe to use ctx, c, c->pool. */
    if (t->nread < 0) { /* handle error */ }
    /* ... send response, resume event loop ... */
}
```

`brix_aio_restore_stream` (in `src/core/aio/resume.c`) checks `ctx->destroyed`
and restores `ctx->cur_streamid`. If it returns `0` the connection was torn
down while the thread was running — return immediately without touching any
connection state.

---

## Pool allocation rules

| Context | Allocator | Freed |
|---|---|---|
| nginx event loop handler | `ngx_palloc(c->pool, n)` | When connection closes |
| nginx event loop, reused buffer | `ngx_alloc(n, log)` / `ngx_free(p)` | Explicitly by the handler |
| AIO `_thread` function | `malloc(n)` / `free(p)` | Explicitly; never use ngx_palloc |
| TPC / cache thread | `malloc(n)` / `free(p)` | Explicitly; never use ngx_palloc |

`ngx_palloc` is **not thread-safe**. All allocations inside `#if (NGX_THREADS)`
thread functions must use `malloc`/`free`.

---

## Handler skeleton

The eight-step pattern followed by every opcode handler:

```c
ngx_int_t
brix_handle_newop(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    ClientNewOpRequest *req = (ClientNewOpRequest *) ctx->hdr_buf;
    char                path[BRIX_MAX_PATH];
    char                resolved[BRIX_MAX_PATH];
    ngx_int_t           rc;

    /* 1. Validate wire fields (payload present, options recognised, etc.) */
    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_NEWOP, "NEWOP",
                          "-", "newop", kXR_ArgMissing, "path required");
    }

    /* 2. Extract and NUL-terminate the path from the payload */
    ngx_memcpy(path, ctx->payload, ctx->cur_dlen);
    path[ctx->cur_dlen] = '\0';

    /* 3. Resolve the path (canonicalise + check jail root) */
    rc = brix_resolve_path(ctx, c, conf, path, resolved, sizeof(resolved));
    if (rc != NGX_OK) { return rc; }

    /* 4. Check ACL (read-only vs read-write, path rules) */
    if (brix_acl_check_read(ctx, c, conf, resolved) != NGX_OK) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_NEWOP, "NEWOP",
                          resolved, "acl", kXR_NotAuthorized, "permission denied");
    }

    /* 5. Stamp request start time for latency logging */
    ctx->req_start = ngx_current_msec;

    /* 6. Perform the operation */
    /* ... */

    /* 7. Success path: log + metric + respond */
    BRIX_RETURN_OK(ctx, c, BRIX_OP_NEWOP, "NEWOP", resolved, "", 0);
}
```

Steps 6–8 (log + metric + send) must always run together in that order.
`BRIX_RETURN_OK` / `BRIX_RETURN_ERR` enforce this on the common paths;
complex handlers that send a body keep the three lines explicit.

---

## WebDAV handler building blocks

All WebDAV helpers are declared in `src/protocols/webdav/webdav.h`.

### Path resolution

```c
/* Resolve request URI to absolute path under export root.
 * Returns NGX_OK or an HTTP error code (400, 403, 404, etc.).
 * Never bypasses this — it prevents path traversal. */
ngx_int_t ngx_http_brix_webdav_resolve_path(
    ngx_http_request_t *r,
    const char *root_canon,
    char *out, size_t outsz);

/* Resolve a Destination: header URL (may be scheme://host/path)
 * to an absolute path under the export root.
 * op_label is used in log messages ("COPY" or "MOVE"). */
ngx_int_t webdav_resolve_destination_path(
    ngx_log_t *log, const char *op_label,
    const char *root_canon,
    const char *decoded_path,
    char *out, size_t outsz);
```

### Lock enforcement

```c
/* Check if path is locked by a different WebDAV lock token.
 * write=1 for write-intent operations (PUT, DELETE, MOVE, COPY).
 * Returns NGX_OK if not locked, NGX_HTTP_LOCKED (423) if locked. */
ngx_int_t webdav_check_locks(ngx_http_request_t *r,
    const char *path, int write);
```

### Auth checks

```c
/* Verify TLS client certificate as a proxy cert.
 * Returns NGX_OK on success, error on failure. */
ngx_int_t webdav_verify_proxy_cert(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf);

/* Verify Authorization: Bearer <token>.
 * Returns NGX_OK on success, error on failure. */
ngx_int_t webdav_verify_bearer_token(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf);

/* Check that the verified token includes a write scope for the given
 * method. Returns NGX_OK or NGX_HTTP_FORBIDDEN (403). */
ngx_int_t webdav_check_token_write_scope(ngx_http_request_t *r,
    const char *method);
```

### HTTP header helpers

```c
/* Find a request header by name (case-insensitive linear scan).
 * Returns NULL if absent. */
ngx_table_elt_t *webdav_tpc_find_header(ngx_http_request_t *r,
    const char *name, size_t name_len);

/* Typical usage: */
ngx_table_elt_t *dest_hdr = webdav_tpc_find_header(r,
    "Destination", sizeof("Destination") - 1);
if (dest_hdr == NULL) {
    return webdav_metrics_return(r, NGX_HTTP_BAD_REQUEST);
}

/* Add CORS response headers (call at entry, before any early return). */
ngx_int_t webdav_add_cors_headers(ngx_http_request_t *r);
```

### Metrics wrapper

```c
/* Record a request entry in method/request counters (call once per request). */
void webdav_metrics_request(ngx_http_request_t *r);

/* Record the HTTP status code in the status counter and return rc.
 * Wrap every return from the handler: return webdav_metrics_return(r, rc); */
ngx_int_t webdav_metrics_return(ngx_http_request_t *r, ngx_int_t rc);
```

### I/O engine

```c
/* Copy src_fd bytes to dst_fd using copy_file_range(2), falling back to
 * pread/pwrite. scratch must be 1 MB, allocated from r->pool.
 * Returns 0 on success, -1 on error (sets errno). */
int webdav_copy_fds(ngx_log_t *log,
    int src_fd, int dst_fd,
    off_t src_size, const char *dst_path,
    char *scratch);
```

### Per-connection fd cache

```c
/* Get or open a cached fd for path. fd belongs to the fd_cache;
 * do not close it directly. Returns -1 on failure. */
int webdav_fd_table_get(webdav_fd_table_t *fdt, const char *path);

/* Evict a path from the cache (call after rename or overwrite). */
void webdav_fd_table_evict(webdav_fd_table_t *fdt, const char *path);

/* Get fd_table from request (access via request context). */
webdav_fd_table_t *webdav_get_fd_table(ngx_http_request_t *r);
```

---

## S3 handler building blocks

All S3 helpers are in `src/protocols/s3/`.

### SigV4 auth

```c
/* Verify AWS Signature Version 4.
 * conf->access_key and conf->secret_key must be set.
 * Returns NGX_OK if valid or auth disabled; error code otherwise. */
ngx_int_t s3_verify_signature(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *conf);
```

### XML response helpers

```c
/* Send a simple XML response body.
 * content_type is typically "application/xml".
 * body is a null-terminated string. */
ngx_int_t s3_send_xml_response(ngx_http_request_t *r,
    ngx_int_t status, const char *body);

/* Send a minimal S3 error response (XML):
 * <Error><Code>code</Code><Message>msg</Message></Error> */
ngx_int_t s3_send_error(ngx_http_request_t *r,
    ngx_int_t http_status,
    const char *code, const char *msg);
```

### Path construction helpers

```c
/* Extract bucket and key from the request URI.
 * Returns NGX_OK; bucket and key are NUL-terminated. */
ngx_int_t s3_parse_uri(ngx_http_request_t *r,
    char *bucket, size_t bucket_sz,
    char *key, size_t key_sz);

/* Validate a part number string: decimal integer 1–10000.
 * Returns the part number or -1 if invalid. */
long s3_parse_partnum(const char *str);
```

---

## Concurrent-AIO Read Pipeline (Phase 32+)

**Location**: `src/protocols/root/connection/read_pipeline.c`, `src/protocols/root/read/readv_window.c`

Phase 32 introduced a **concurrent-AIO read pipeline** that allows multiple
read requests to be in-flight simultaneously, improving throughput on
high-latency storage.

### Pipeline Architecture

```c
/* Read pipeline sub-struct (ctx->rd) — Phase 32+ */
typedef struct {
    brix_read_slot_t  window[BRIX_READ_WINDOW_SLOTS]; /* 8-16 slots */
    int               head;      /* next slot to allocate for kXR_read */
    int               tail;      /* next slot to drain to client */
    int               count;     /* valid slots in window */
    size_t            bytes_pending; /* total bytes in-flight */
    off_t             read_ahead_end; /* farthest byte hinted with WILLNEED */
    unsigned          active:1;  /* 1 = pipeline active */
} brix_ctx_rd_t;
```

### Pipeline Flow

1. **Allocate slot** — kXR_read allocates slot from `ctx->rd.window[]`
2. **Post AIO** — `ngx_thread_task_post()` to thread pool
3. **Completion** — On AIO done, slot moves to drain queue
4. **Drain in-order** — `brix_send_readv()` drains to client in original order

### Key Benefits

- **Parallelism**: 8-16 concurrent reads in-flight
- **Read-ahead**: `read_ahead_end` tracks farthest byte for WILLNEED hints
- **In-order delivery**: Slots drain in original request order despite variable completion times
- **Backpressure**: `bytes_pending` caps in-flight bytes

**Source**: `src/protocols/root/connection/read_pipeline.c`, `src/protocols/root/read/readv_window.c`

---

## Response Pipelining (Phase 29+)

**Location**: `src/protocols/root/connection/write_helpers.c`, `src/protocols/root/connection/out_ring.c`

Phase 29 introduced **response pipelining** via a ring buffer that queues
responses for ordered delivery, enabling:

- Multiple responses in-flight before client acknowledges
- Ordered delivery despite variable processing times
- Efficient batching of small responses

### Ring Buffer Architecture

```c
/* Output queue sub-struct (ctx->out) — Phase 29+ */
typedef struct {
    brix_resp_slot_t  ring[BRIX_RESP_RING_SLOTS]; /* 256 slots */
    int               head;      /* next slot to allocate */
    int               tail;      /* next slot to drain */
    int               count;     /* valid slots in ring */
    size_t            bytes_queued; /* total bytes pending */
    ngx_event_t      *write_ev;  /* write event for draining */
    unsigned          draining:1; /* 1 = actively draining ring */
} brix_ctx_out_t;
```

### Pipeline Flow

1. **Handler calls** `brix_queue_response()` → allocates slot from `ctx->out.ring[]`
2. **Slot holds** response buffer, streamid, state
3. **Write event drains** ring FIFO via `brix_drain_out_ring()`
4. **On completion**, slot freed, `ctx->out.count--`

### Key Benefits

- **256 slots** — Large enough for burst handling
- **FIFO ordering** — Responses delivered in queue order
- **Backpressure** — `bytes_queued` caps pending bytes
- **Efficient** — Single write event drains entire ring

**Source**: `src/protocols/root/connection/write_helpers.c`, `src/protocols/root/connection/out_ring.c`
