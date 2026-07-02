# Handler reference

The internal building blocks every handler uses — quick reference to keep open while writing code. For fuller context read
`docs/architecture.md` first.

---

## Response helpers

All response helpers are declared in `src/response/response.h` and
implemented in `src/response/`.

### `xrootd_send_ok`

```c
ngx_int_t xrootd_send_ok(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const void *body, uint32_t bodylen);
```

Sends a `kXR_ok` response. Pass `NULL, 0` for zero-body responses (the
common case). For responses with a body (stat results, read data, open
handles) pass a pointer and byte count; the function copies the bytes into
a pool-allocated wire buffer.

### `xrootd_send_error`

```c
ngx_int_t xrootd_send_error(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *msg);
```

Sends a `kXR_error` response. `errcode` is one of the `kXR_*` constants from
`src/protocol/opcodes.h` (e.g. `kXR_NotFound`, `kXR_NotAuthorized`,
`kXR_IOError`). `msg` is a human-readable string; it is NUL-terminated on the
wire so clients can treat it as a C string.

### `xrootd_queue_response`

```c
ngx_int_t xrootd_queue_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf, size_t len);
```

Low-level send for pre-built wire buffers. Use this when the response header
and body are already assembled (e.g. kXR_open returns handle + stat string in
one allocation). The buffer must be pool-allocated from `c->pool`; ownership
passes to the send machinery.

### `xrootd_send_redirect` / `xrootd_send_wait` / `xrootd_send_waitresp`

```c
ngx_int_t xrootd_send_redirect(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *host, uint16_t port);

ngx_int_t xrootd_send_wait(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint32_t seconds);

ngx_int_t xrootd_send_waitresp(xrootd_ctx_t *ctx, ngx_connection_t *c);
```

Used by the upstream redirect and CMS manager paths. Rarely needed for new
opcodes.

---

## Shortcut macros

Defined in `src/core/types/tunables.h`. Use these when the error message in the
access log and in the wire response are identical and the handler returns
immediately.

### `XROOTD_RETURN_OK`

```c
XROOTD_RETURN_OK(ctx, c, op, verb, path, detail, bytes)
```

Equivalent to:
```c
xrootd_log_access(ctx, c, verb, path, detail, 1, kXR_ok, NULL, bytes);
XROOTD_OP_OK(ctx, op);
return xrootd_send_ok(ctx, c, NULL, 0);
```

**Constraint**: only for zero-body responses. Handlers that send a body (read
data, stat results, query output) must keep the three lines explicit.

### `XROOTD_RETURN_ERR`

```c
XROOTD_RETURN_ERR(ctx, c, op, verb, path, detail, code, msg)
```

Equivalent to:
```c
xrootd_log_access(ctx, c, verb, path, detail, 0, code, msg, 0);
XROOTD_OP_ERR(ctx, op);
return xrootd_send_error(ctx, c, code, msg);
```

The `detail` string goes to the access log; `msg` goes to the wire. They can
differ when the access log needs more context than the client should see.

---

## Access logging

```c
void xrootd_log_access(xrootd_ctx_t *ctx, ngx_connection_t *c,
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
`xrootd_log_access` before returning. Missing log calls produce silent gaps
in the audit trail.

---

## AIO dispatch pattern

Use async I/O for reads and writes so the nginx event loop is not blocked by
filesystem calls. The pattern is always a `_thread` / `_done` pair.

### Posting a task

```c
/* In the synchronous handler (event-loop side): */
task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_read_aio_t));
t = task->ctx;
t->ctx = ctx;
t->c = c;
/* ... fill in t->fd, t->offset, t->rlen, etc. */

task->handler = xrootd_read_aio_thread;   /* blocking syscall */
task->event.handler = xrootd_read_aio_done; /* completion callback */
task->event.data = task;

ctx->state = XRD_ST_AIO;
if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
    /* post failed — handle synchronously or return error */
}
```

### Thread function

```c
void xrootd_read_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_read_aio_t *t = data;
    t->nread = pread(t->fd, t->databuf, t->rlen, t->offset);
    if (t->nread < 0) { t->io_errno = errno; }
    /* Do NOT touch ctx, c->pool, or any nginx structure here. */
}
```

The thread function may only touch fields stored in the task struct itself.
`ctx`, `c->pool`, and all nginx internals are off-limits.

### Completion callback (done function)

```c
void xrootd_read_aio_done(ngx_event_t *ev)
{
    xrootd_read_aio_t *t = ((ngx_thread_task_t *) ev->data)->ctx;
    xrootd_ctx_t      *ctx = t->ctx;
    ngx_connection_t  *c = t->c;

    /* ALWAYS check destroyed first — connection may have closed. */
    if (!xrootd_aio_restore_stream(ctx, t->streamid)) {
        return;   /* connection gone; nothing to do */
    }

    /* Now safe to use ctx, c, c->pool. */
    if (t->nread < 0) { /* handle error */ }
    /* ... send response, resume event loop ... */
}
```

`xrootd_aio_restore_stream` (in `src/core/aio/resume.c`) checks `ctx->destroyed`
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
xrootd_handle_newop(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientNewOpRequest *req = (ClientNewOpRequest *) ctx->hdr_buf;
    char                path[XROOTD_MAX_PATH];
    char                resolved[XROOTD_MAX_PATH];
    ngx_int_t           rc;

    /* 1. Validate wire fields (payload present, options recognised, etc.) */
    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_NEWOP, "NEWOP",
                          "-", "newop", kXR_ArgMissing, "path required");
    }

    /* 2. Extract and NUL-terminate the path from the payload */
    ngx_memcpy(path, ctx->payload, ctx->cur_dlen);
    path[ctx->cur_dlen] = '\0';

    /* 3. Resolve the path (canonicalise + check jail root) */
    rc = xrootd_resolve_path(ctx, c, conf, path, resolved, sizeof(resolved));
    if (rc != NGX_OK) { return rc; }

    /* 4. Check ACL (read-only vs read-write, path rules) */
    if (xrootd_acl_check_read(ctx, c, conf, resolved) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_NEWOP, "NEWOP",
                          resolved, "acl", kXR_NotAuthorized, "permission denied");
    }

    /* 5. Stamp request start time for latency logging */
    ctx->req_start = ngx_current_msec;

    /* 6. Perform the operation */
    /* ... */

    /* 7. Success path: log + metric + respond */
    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_NEWOP, "NEWOP", resolved, "", 0);
}
```

Steps 6–8 (log + metric + send) must always run together in that order.
`XROOTD_RETURN_OK` / `XROOTD_RETURN_ERR` enforce this on the common paths;
complex handlers that send a body keep the three lines explicit.

---

## WebDAV handler building blocks

All WebDAV helpers are declared in `src/webdav/webdav.h`.

### Path resolution

```c
/* Resolve request URI to absolute path under export root.
 * Returns NGX_OK or an HTTP error code (400, 403, 404, etc.).
 * Never bypasses this — it prevents path traversal. */
ngx_int_t ngx_http_xrootd_webdav_resolve_path(
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
    ngx_http_xrootd_webdav_loc_conf_t *conf);

/* Verify Authorization: Bearer <token>.
 * Returns NGX_OK on success, error on failure. */
ngx_int_t webdav_verify_bearer_token(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf);

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

All S3 helpers are in `src/s3/`.

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
