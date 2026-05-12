[← Contributing overview](index.md)

## 5. Dispatch routing

`xrootd_dispatch()` in `src/handshake/dispatch.c` routes every request
through four dispatch functions in a fixed cascade:

```
xrootd_dispatch()
  ├── xrootd_dispatch_session_opcode   → src/handshake/dispatch_session.c
  ├── xrootd_dispatch_read_opcode      → src/handshake/dispatch_read.c
  ├── xrootd_dispatch_write_opcode     → src/handshake/dispatch_write.c
  └── xrootd_dispatch_signing_opcode   → src/handshake/dispatch_signing.c
```

Each function returns `XROOTD_DISPATCH_CONTINUE` if the opcode is not its
responsibility, or an actual `ngx_int_t` result (success or error) if it
handled the request. The cascade stops at the first non-CONTINUE return.

### Which file does my opcode go in?

| Category | File | Opcodes |
|---|---|---|
| Session lifecycle | `dispatch_session.c` | `kXR_protocol`, `kXR_login`, `kXR_auth`, `kXR_bind`, `kXR_endsess`, `kXR_ping`, `kXR_set` |
| Reads, queries, and mixed handle ops | `dispatch_read.c` | `kXR_open` (read), `kXR_stat`, `kXR_statx`, `kXR_read`, `kXR_readv`, `kXR_pgread`, `kXR_close`, `kXR_dirlist`, `kXR_locate`, `kXR_query`, `kXR_prepare`, `kXR_fattr`, `kXR_clone` |
| Writes and namespace mutations | `dispatch_write.c` | `kXR_open` (write), `kXR_write`, `kXR_pgwrite`, `kXR_writev`, `kXR_sync`, `kXR_truncate`, `kXR_mkdir`, `kXR_rm`, `kXR_rmdir`, `kXR_mv`, `kXR_chmod`, `kXR_chkpoint` |
| Request signing | `dispatch_signing.c` | `kXR_sigver` |

**Rule of thumb**: if the opcode mutates the namespace directly it usually goes
in `dispatch_write.c`; if it reads, queries metadata, or is a mixed handle
operation with its own sub-operation checks, it usually goes in
`dispatch_read.c`; if it belongs to the connection or session lifecycle it goes
in `dispatch_session.c`. `kXR_sigver` is special — it wraps other requests and
must always be dispatched last.

### Auth guards

Every case in `dispatch_read.c` and `dispatch_write.c` calls an auth guard
before the handler:

```c
case kXR_stat:
    rc = xrootd_dispatch_require_auth(ctx, c);
    if (rc != XROOTD_DISPATCH_CONTINUE) { return rc; }
    return xrootd_handle_stat(ctx, c, conf);

case kXR_write:
    rc = xrootd_dispatch_require_write(ctx, c);
    if (rc != XROOTD_DISPATCH_CONTINUE) { return rc; }
    return xrootd_handle_write(ctx, c, conf);
```

`xrootd_dispatch_require_auth` rejects unauthenticated connections.
`xrootd_dispatch_require_write` additionally enforces read-only mode.
Session-lifecycle opcodes handle their own auth checks internally.

---

## 6. Worked example — tracing `kXR_ping`

`kXR_ping` is the simplest real opcode: zero-payload request, zero-payload
response, no filesystem access. Tracing it through the seven checklist steps
shows the full contribution path concretely.

### Step 1 — Opcode constant

`src/protocol/opcodes.h`:
```c
#define kXR_ping    3021  /* liveness check — zero payload in, zero payload out */
```

### Step 2 — Wire struct

No new struct needed. `kXR_ping` uses the generic `ClientRequestHdr` (24
bytes: 2-byte stream ID, 2-byte request ID, 16-byte body, 4-byte dlen) with
`dlen == 0`.

### Step 3 — Metrics slot

`src/metrics/metrics.h`:
```c
#define XROOTD_OP_PING  16
```
`src/metrics/export.c` — `xrootd_op_names[]` has `"ping"` at index 16.

### Step 4 — Handler

`src/session/lifecycle.c` — `xrootd_handle_ping`:
```c
ngx_int_t
xrootd_handle_ping(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_PING, "PING", "-", "", 0);
}
```
Three lines. `XROOTD_RETURN_OK` handles log + metric + send in one call.

### Step 5 — Dispatch case

`src/handshake/dispatch_session.c`:
```c
case kXR_ping:
    return xrootd_handle_ping(ctx, c, conf);
```
No auth guard needed — ping is valid before login (used by health checkers).

### Step 6 — Build system

`config` already lists `src/session/lifecycle.c`. No change needed because
`kXR_ping` shares the file with other lifecycle handlers.

For a new opcode in a new file, add entries to both the deps and srcs lists
in `config` and re-run `./configure`.

### Step 7 — Subsystem README

`src/session/README.md` lists `lifecycle.c` in its file table with a row for
each handler including `kXR_ping`. Update the row if you change the handler.

### Step 8 — Test

`tests/test_conformance.py::test_ping` sends a raw ping and asserts `kXR_ok`.
For a new opcode, add equivalent success and error-path tests.

---

## 7. Adding a new WebDAV method

Use `src/webdav/copy.c` or `src/webdav/move.c` as a template — they are both
recent, clean, and follow all current conventions.

### Step 1 — Create the handler file

Create `src/webdav/mymethod.c`. The handler signature must match:

```c
ngx_int_t
webdav_handle_mymethod(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char  src_path[WEBDAV_MAX_PATH];
    ngx_int_t rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    /* 1. Resolve the request URI to an absolute confined path */
    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon,
                                              src_path, sizeof(src_path));
    if (rc != NGX_OK) {
        return webdav_metrics_return(r, rc);
    }

    /* 2. Perform the operation */
    /* ... */

    /* 3. Return HTTP status */
    return webdav_metrics_return(r, NGX_HTTP_OK);
}
```

### Step 2 — Declare in webdav.h

Add to the "HTTP methods" section of `src/webdav/webdav.h`:

```c
ngx_int_t webdav_handle_mymethod(ngx_http_request_t *r);
```

### Step 3 — Add dispatch routing

In `src/webdav/dispatch.c`, before the final `return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED)`:

```c
if (r->method_name.len == 8
    && ngx_strncmp(r->method_name.data, "MYMETHOD", 8) == 0)
{
    if (!conf->allow_write) {
        return webdav_metrics_return(r, NGX_HTTP_FORBIDDEN);
    }
    rc = webdav_check_token_write_scope(r, "MYMETHOD");
    if (rc != NGX_OK) {
        return webdav_metrics_return(r, rc);
    }
    return webdav_metrics_return(r, webdav_handle_mymethod(r));
}
```

Read-only methods (like GET, HEAD, PROPFIND) skip the `allow_write` and scope
checks. Write-mutating methods (PUT, DELETE, MKCOL, MOVE, COPY, LOCK, UNLOCK)
require both.

### Step 4 — Update the Allow header

In `src/webdav/methods_basic.c`, add the new method name to the
`conf->allow_write` branch of the Allow header value.

### Step 5 — Add to the build system

In the `config` file (project root), add to the webdav source list:

```sh
$ngx_addon_dir/src/webdav/mymethod.c \
```

### Step 6 — Re-run ./configure

After editing `config`, **always** re-run `./configure` in the nginx source
tree before `make`. Skipping this step silently ignores the new source file.

```bash
cd /tmp/nginx-1.28.3
./configure --with-stream --with-http_ssl_module --with-threads \
    --add-module=/path/to/nginx-xrootd
make -j$(nproc)
```

### Step 7 — Add tests

Add a `_mymethod()` helper and a `TestMyMethod` class to **both**:
- `tests/test_http_webdav_status_codes.py`
- `tests/test_https_webdav_status_codes.py`

Minimum test coverage for any WebDAV method:

| Test | What to assert |
|---|---|
| `test_success` | 2xx on valid input |
| `test_forbidden_without_write` | 403 when `allow_write` is off (write methods only) |
| `test_not_found_source` | 404 when source path does not exist |
| `test_missing_header` | 400 when a required header is absent |
| `test_method_not_allowed_wrong_method` | 405 for an unrelated method hitting this path |
| `test_path_traversal_rejected` | Path with `..` returns 400 or 403, never escapes root |

For write methods: also add a token scope negative test:
`test_missing_write_scope` — send a request with a read-only token and assert 403.

### Key API helpers

```c
/* Resolve request URI → absolute confined path */
ngx_int_t ngx_http_xrootd_webdav_resolve_path(
    ngx_http_request_t *r, const char *root_canon,
    char *out, size_t outsz);

/* Resolve Destination: header URL → absolute confined path */
ngx_int_t webdav_resolve_destination_path(
    ngx_log_t *log, const char *op_label, const char *root_canon,
    const char *decoded_path, char *out, size_t outsz);

/* Find a request header by name (case-insensitive) */
ngx_table_elt_t *webdav_tpc_find_header(ngx_http_request_t *r,
    const char *name, size_t name_len);

/* Check write locks (returns NGX_HTTP_LOCKED = 423 if locked) */
ngx_int_t webdav_check_locks(ngx_http_request_t *r,
    const char *path, int write);

/* Check token write scope for a method */
ngx_int_t webdav_check_token_write_scope(ngx_http_request_t *r,
    const char *method);

/* Wrap the final return value in metrics recording */
ngx_int_t webdav_metrics_return(ngx_http_request_t *r, ngx_int_t rc);
```

---

## 8. Adding a new S3 endpoint

Use `src/s3/multipart.c` as a template for POST-body handlers and
`src/s3/put.c` for PUT-body handlers.

### Step 1 — Identify the routing key

S3 endpoints are distinguished by HTTP method + query string combination.
The main handler in `src/s3/handler.c` checks in this order:

1. Query string presence: `?uploads`, `?partNumber=N&uploadId=ID`, `?uploadId=ID`
2. HTTP method: GET, HEAD, PUT, POST, DELETE
3. Presence of a key component (vs. bucket-root requests)

Decide where your new operation fits in this routing tree.

### Step 2 — Add the handler function

For simple operations, add the handler directly in `src/s3/handler.c` or
`src/s3/put.c`. For operations with a body (POST-based like CompleteMultipart),
add in `src/s3/multipart.c` and use the `ngx_http_read_client_request_body`
+ callback pattern:

```c
static void
s3_myop_body_handler(ngx_http_request_t *r)
{
    /* r->request_body is now populated */
    /* ... parse body, perform operation, send response ... */
    ngx_http_finalize_request(r, NGX_HTTP_OK);
}

ngx_int_t
s3_handle_myop(ngx_http_request_t *r, ...)
{
    ngx_int_t rc;
    r->request_body_in_single_buf = 1;
    rc = ngx_http_read_client_request_body(r, s3_myop_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    return NGX_DONE;
}
```

### Step 3 — Add routing in handler.c

In `ngx_http_s3_handler()` in `src/s3/handler.c`, add a routing case
before the generic method checks:

```c
/* Check for ?myop query parameter */
if (/* condition */) {
    return s3_handle_myop(r, ...);
}
```

### Step 4 — Add XML response helpers (if needed)

S3 XML responses follow the pattern in `src/s3/util.c`. Use `ngx_snprintf`
or a simple string buffer to build the XML, then send with
`ngx_http_send_header` + response body chain.

### Step 5 — Add to build if a new file

If you created a new `.c` file, add it to `config` and re-run `./configure`.

### Step 6 — Add tests

Add tests to `tests/test_s3_multipart.py` (for multipart-related ops) or
`tests/test_s3_status_codes.py` (for status code coverage). Minimum:

| Test | What to assert |
|---|---|
| `test_success_lifecycle` | Complete operation returns expected status |
| `test_not_found` | Missing key/bucket returns 404 |
| `test_invalid_params` | Bad parameters (e.g. part numbers out of range) return 400 |
| `test_path_traversal` | `..` in key names are rejected |

### Part number and uploadId safety rules

Part numbers must be validated as decimal integers in the range 1–10,000
before appearing in any filesystem path. UploadIds must match the pattern
`[0-9a-f]{8}` or similar fixed-format before use. Never construct filesystem
paths from unvalidated user-controlled strings.

```c
/* Part number validation (always do this before building a path) */
long partnum = strtol(partnum_str, &endp, 10);
if (*endp != '\0' || partnum < 1 || partnum > 10000) {
    return NGX_HTTP_BAD_REQUEST;
}
```

All filesystem paths must go through the confined-open helpers:
`xrootd_open_confined_canon`, `xrootd_rename_confined_canon`,
`xrootd_unlink_confined_canon`.
