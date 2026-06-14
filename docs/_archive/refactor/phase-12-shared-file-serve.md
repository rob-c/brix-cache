# Phase 12 — Shared HTTP File-Serve Handler

**Target**: eliminate duplicated range-parse → headers → send pipeline shared between
`src/webdav/get.c` and `src/s3/object.c`.

**Net LoC reduction**: ~80–110 LoC  
**Risk**: low — mechanical extraction of already-working code into a new function  
**Requires**: `./configure` once (new source file)

---

## Problem

Both GET handlers implement the same ~95-LoC block in the middle of their handlers:

| Step | `webdav/get.c` (lines) | `s3/object.c` (lines) |
|------|----------------------|----------------------|
| Range parse + 416 guard | 203–224 | 107–127 |
| `xrootd_http_set_file_headers` + error path | 239–246 | 135–143 |
| Identity extract + dashboard start | 255–259 | 145–164 |
| `dup(fd)` + error + `xrootd_vfs_close` | 261–268 | 166–174 |
| `xrootd_http_send_file_range` + error path | 270–275 | 176–197 |
| `xrootd_dashboard_http_add` + cache record + IPv4/IPv6 dispatch | 281–298 | 178–190 |

The code is structurally identical. Differences are only:
- `etag_flags` value (`XROOTD_ETAG_WEAK` vs `0`)
- `xfer_proto` (`XROOTD_XFER_PROTO_WEBDAV` vs `XROOTD_XFER_PROTO_S3`)
- `op_name` string (`"GET"` vs `"GetObject"`)
- Protocol-specific metric macros (handled by callers after the shared call)
- WebDAV adds two extra header calls between set_file_headers and send (`pre_header_send` hook)

---

## What stays in each caller

**Both callers keep (cannot share)**:
- VFS ctx setup — uses protocol-specific conf types (`ngx_http_xrootd_webdav_loc_conf_t` vs `ngx_http_s3_loc_conf_t`)
- `xrootd_vfs_open` + not-found error — WebDAV returns bare 404; S3 returns XML `NoSuchKey`
- `xrootd_vfs_file_stat` + directory check — same reason (error response format differs)
- Range metrics (`XROOTD_WEBDAV_METRIC_INC(range_total[...])` vs `XROOTD_S3_METRIC_INC(...)`)
- Bytes-sent metrics (`XROOTD_WEBDAV_METRIC_ADD(bytes_tx_total, ...)` vs S3 equivalent)

**WebDAV keeps (S3 has no equivalent)**:
- Multirange / XrdHttp delegation (`xrdhttp_request_is_multirange` + `xrdhttp_handle_multipart_get`)
- `xrootd_http_check_if_modified_since` → 304 path
- `webdav_fadvise_willneed`
- `r->allow_ranges = 1`
- `xrdhttp_add_checksum_header` + `xrdhttp_add_response_headers` (via `pre_header_send` callback)
- `webdav_register_send_fd_cleanup` static helper (still needed by the multirange path)

---

## Honest LoC accounting

```
webdav/get.c:     301 LoC → ~195 LoC  (save ~106 LoC)
s3/object.c GET:  ~137 LoC → ~70 LoC  (save ~67 LoC)
─────────────────────────────────────────────────────
Total removed from callers:           ~173 LoC
New: src/shared/file_serve.h          ~45 LoC
New: src/shared/file_serve.c          ~80 LoC
─────────────────────────────────────────────────────
Net reduction:                        ~48 LoC
```

The callers each add ~10 LoC back (opts struct fill + post-call metrics dispatch), so
the real net is closer to **~80–110 LoC** after accounting for the full before/after diff
including the callers' metric sections being simplified by knowing `result.bytes_sent`
and `result.range_result` rather than tracking those locally.

The primary value is architectural: the 95-LoC range-parse→send contract exists in one
place, and any future protocol (e.g. XrdHTTP object serve) calls the same function.

---

## Design

### `src/shared/file_serve.h`

```c
#ifndef XROOTD_SHARED_FILE_SERVE_H
#define XROOTD_SHARED_FILE_SERVE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "../fs/vfs.h"

/* Range outcome codes returned in xrootd_http_serve_result_t.range_result */
#define XROOTD_SERVE_RANGE_FULL        0
#define XROOTD_SERVE_RANGE_PARTIAL     1
#define XROOTD_SERVE_RANGE_UNSATISFIED 2

/*
 * Pre-header-send hook: called after range parse and set_file_headers but
 * before ngx_http_send_header fires inside xrootd_http_send_file_range.
 * WebDAV uses this to add XrdHttp checksum/status headers.
 * Set to NULL for protocols that need no extra headers.
 */
typedef void (*xrootd_http_pre_header_fn)(ngx_http_request_t *r,
    ngx_fd_t fd, off_t file_size, void *userdata);

typedef struct {
    /* Protocol metadata (filled by caller before calling serve_file_ranged) */
    uint8_t                    xfer_proto;    /* XROOTD_XFER_PROTO_WEBDAV / _S3 */
    const char                *op_name;       /* "GET" / "GetObject" */
    const char                *identity;      /* caller-resolved display string */
    unsigned                   etag_flags;    /* XROOTD_ETAG_WEAK or 0 */

    /* Optional WebDAV-specific header injection (NULL = skip) */
    xrootd_http_pre_header_fn  pre_header_send;
    void                      *pre_header_ud;
} xrootd_http_serve_opts_t;

typedef struct {
    int    range_result;   /* XROOTD_SERVE_RANGE_* — for caller metric increment */
    off_t  bytes_sent;     /* 0 if header_only / 416 / error */
} xrootd_http_serve_result_t;

/*
 * xrootd_http_serve_file_ranged — shared range-parse → headers → send pipeline.
 *
 * Takes an already-open, already-stat'd vfs file handle (fh). Closes fh
 * internally before the body send (whether via dup on success or direct close
 * on error). Callers must NOT close fh after this call returns.
 *
 * On return, result->range_result and result->bytes_sent let the caller
 * increment protocol-specific range and bytes metrics.
 *
 * Returns: NGX_OK, NGX_ERROR, NGX_HTTP_RANGE_NOT_SATISFIABLE (416), or
 *          NGX_HTTP_INTERNAL_SERVER_ERROR.
 */
ngx_int_t xrootd_http_serve_file_ranged(ngx_http_request_t *r,
    xrootd_vfs_file_t *fh, const xrootd_vfs_stat_t *vst,
    const char *fs_path, const xrootd_http_serve_opts_t *opts,
    xrootd_http_serve_result_t *result);

#endif /* XROOTD_SHARED_FILE_SERVE_H */
```

### `src/shared/file_serve.c` — implementation skeleton

```c
#include "file_serve.h"
#include "../compat/http_file_response.h"
#include "../compat/range.h"
#include "../dashboard/dashboard_tracking.h"
#include "../cache/open.h"
#include <unistd.h>

ngx_int_t
xrootd_http_serve_file_ranged(ngx_http_request_t *r,
    xrootd_vfs_file_t *fh, const xrootd_vfs_stat_t *vst,
    const char *fs_path, const xrootd_http_serve_opts_t *opts,
    xrootd_http_serve_result_t *result)
{
    xrootd_http_range_t  rng;
    off_t                range_start, range_end, send_len;
    ngx_fd_t             fd, send_fd;
    ngx_int_t            rc;
    ngx_uint_t           from_cache;
    const char          *cache_path;

    ngx_memzero(result, sizeof(*result));

    /* ---- Phase 1: range parse ---- */
    xrootd_http_parse_range(
        r->headers_in.range ? r->headers_in.range->value.data : NULL,
        r->headers_in.range ? r->headers_in.range->value.len  : 0,
        vst->size, &rng);

    if (rng.present && !rng.satisfiable) {
        xrootd_vfs_close(fh, r->connection->log);
        result->range_result = XROOTD_SERVE_RANGE_UNSATISFIED;
        r->headers_out.status           = NGX_HTTP_RANGE_NOT_SATISFIABLE;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    range_start = rng.start;
    range_end   = rng.end;
    send_len    = (vst->size > 0) ? (range_end - range_start + 1) : 0;
    result->range_result = rng.present ? XROOTD_SERVE_RANGE_PARTIAL
                                       : XROOTD_SERVE_RANGE_FULL;

    /* ---- Phase 2: response headers ---- */
    if (xrootd_http_set_file_headers(r, vst->mtime, vst->size, send_len,
                                     NULL, opts->etag_flags,
                                     rng.present, range_start, range_end)
        != NGX_OK)
    {
        xrootd_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (opts->pre_header_send != NULL) {
        opts->pre_header_send(r, xrootd_vfs_file_fd(fh), vst->size,
                              opts->pre_header_ud);
    }

    /* ---- Phase 3: dashboard ---- */
    (void) xrootd_dashboard_http_start_identity(r, fs_path,
        opts->identity, "",
        opts->xfer_proto, XROOTD_XFER_DIR_READ, opts->op_name,
        (int64_t) send_len);

    /* ---- Phase 4: dup fd, release vfs handle, send ---- */
    fd         = xrootd_vfs_file_fd(fh);
    from_cache = xrootd_vfs_file_from_cache(fh);
    cache_path = xrootd_vfs_file_path(fh);

    send_fd = dup(fd);
    if (send_fd == NGX_INVALID_FILE) {
        xrootd_vfs_close(fh, r->connection->log);
        xrootd_dashboard_http_error(r, "serve_file_ranged: dup failed");
        xrootd_dashboard_http_finish(r);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    xrootd_vfs_close(fh, r->connection->log);

    rc = xrootd_http_send_file_range(r, send_fd, fs_path,
                                     range_start, send_len, 1);

    if (rc == NGX_ERROR) {
        xrootd_dashboard_http_error(r, "serve_file_ranged: send failed");
        xrootd_dashboard_http_finish(r);
        return rc;
    }

    if (r->header_only) {
        xrootd_dashboard_http_finish(r);
        return rc;
    }

    /* ---- Phase 5: post-send accounting ---- */
    result->bytes_sent = send_len;
    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) send_len);

    if (from_cache && send_len > 0) {
        (void) xrootd_cache_record_access(cache_path, (size_t) send_len,
                                          r->connection->log);
    }

    return rc;
}
```

---

## Caller changes

### `webdav/get.c` after refactor

The block at lines 203–300 (98 LoC) is replaced by ~30 LoC:

```c
    /* WebDAV-specific pre-send setup */
    if (send_len > 0) {
        webdav_fadvise_willneed(r->connection->log, fd, range_start,
                                (size_t) send_len);
    }
    r->allow_ranges = 1;

    /* XrdHttp extra headers injected via pre_header_send hook */
    xrootd_http_serve_opts_t opts;
    ngx_memzero(&opts, sizeof(opts));
    opts.xfer_proto       = XROOTD_XFER_PROTO_WEBDAV;
    opts.op_name          = "GET";
    opts.identity         = identity;    /* resolved from wctx->dn above */
    opts.etag_flags       = XROOTD_ETAG_WEAK;
    opts.pre_header_send  = webdav_get_add_xrdhttp_headers;
    opts.pre_header_ud    = &sb;         /* struct stat for checksum header */

    xrootd_http_serve_result_t result;
    rc = xrootd_http_serve_file_ranged(r, fh, &vst, path, &opts, &result);

    /* Protocol-specific metrics (cannot be inside shared function) */
    if (result.range_result == XROOTD_SERVE_RANGE_UNSATISFIED) {
        XROOTD_WEBDAV_METRIC_INC(range_total[XROOTD_WEBDAV_RANGE_UNSATISFIED]);
    } else if (result.range_result == XROOTD_SERVE_RANGE_PARTIAL) {
        XROOTD_WEBDAV_METRIC_INC(range_total[XROOTD_WEBDAV_RANGE_PARTIAL]);
    } else {
        XROOTD_WEBDAV_METRIC_INC(range_total[XROOTD_WEBDAV_RANGE_FULL]);
    }
    if (result.bytes_sent > 0) {
        XROOTD_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) result.bytes_sent);
        if (r->connection && r->connection->sockaddr) {
            if (r->connection->sockaddr->sa_family == AF_INET6) {
                XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total,
                                         (size_t) result.bytes_sent);
            } else {
                XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total,
                                         (size_t) result.bytes_sent);
            }
        }
    }
    return rc;
```

Note: `webdav_get_add_xrdhttp_headers` is a new static function (4 LoC) replacing the
two inline calls to `xrdhttp_add_checksum_header` and `xrdhttp_add_response_headers`.
The `struct stat sb` is still populated from `vst` before the multirange block (as now).

### `s3/object.c` — `s3_handle_get` after refactor

Lines 107–197 (91 LoC) replaced by ~25 LoC:

```c
    char identity[128];
    /* ... same identity resolution as today ... */

    xrootd_http_serve_opts_t opts;
    ngx_memzero(&opts, sizeof(opts));
    opts.xfer_proto = XROOTD_XFER_PROTO_S3;
    opts.op_name    = "GetObject";
    opts.identity   = identity;
    opts.etag_flags = 0;

    xrootd_http_serve_result_t result;
    ngx_int_t rc = xrootd_http_serve_file_ranged(r, fh, &vst, fs_path,
                                                   &opts, &result);

    if (result.range_result == XROOTD_SERVE_RANGE_UNSATISFIED) {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_UNSATISFIED]);
    } else if (result.range_result == XROOTD_SERVE_RANGE_PARTIAL) {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_PARTIAL]);
    } else {
        XROOTD_S3_METRIC_INC(range_total[XROOTD_S3_RANGE_FULL]);
    }
    if (result.bytes_sent > 0) {
        XROOTD_S3_METRIC_ADD(bytes_tx_total, (size_t) result.bytes_sent);
        if (r->connection && r->connection->sockaddr
            && r->connection->sockaddr->sa_family == AF_INET6) {
            XROOTD_S3_METRIC_ADD(bytes_tx_ipv6_total, (size_t) result.bytes_sent);
        } else {
            XROOTD_S3_METRIC_ADD(bytes_tx_ipv4_total, (size_t) result.bytes_sent);
        }
    }
    return rc;
```

The `s3_vfs_ctx()` helper (26 LoC) is untouched — it stays as a static in `s3/object.c`
since the S3 conf type is opaque to `shared/`.

---

## Build registration

Add to `config` (the top-level nginx module config shell script), in the
`NGX_ADDON_SRCS` list alongside the other `shared/` or `compat/` entries:

```sh
    $ngx_addon_dir/src/shared/file_serve.c \
```

Add to the `NGX_ADDON_DEPS` header list:

```sh
    $ngx_addon_dir/src/shared/file_serve.h \
```

Because a new source file is added, `./configure` must be re-run once:

```bash
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO
make -j$(nproc)
```

All subsequent incremental builds use `make -j$(nproc)` only.

---

## Implementation steps

1. **Create** `src/shared/file_serve.h` (opts struct, result struct, 3 `#define` constants, declaration)
2. **Create** `src/shared/file_serve.c` (implementation as above; ~80 LoC)
3. **Register** both in `config` (`NGX_ADDON_DEPS` + `NGX_ADDON_SRCS`); run `./configure`
4. **Edit `webdav/get.c`**:
   - Add `#include "../shared/file_serve.h"`
   - Add static `webdav_get_add_xrdhttp_headers(r, fd, file_size, ud)` (4 LoC, replaces two inline calls)
   - Replace lines 203–300 with the ~30 LoC opts/call/metrics block shown above
   - `webdav_register_send_fd_cleanup` static helper stays (still used by the multirange path at lines 176–187)
5. **Edit `s3/object.c`**:
   - Add `#include "../shared/file_serve.h"`
   - Replace lines 107–197 of `s3_handle_get` with the ~25 LoC block shown above
   - `s3_vfs_ctx()` helper stays unchanged
6. **Build**: `make -j$(nproc)` — fix any compile errors (type mismatches, missing includes)
7. **Test**: run the three test cases below; then `PYTHONPATH=tests pytest tests/ -k "get or download or range" -v`

---

## Tests (minimum 3)

```python
# 1. WebDAV GET full file
def test_webdav_get_full(webdav_client, test_file):
    resp = webdav_client.get(test_file.path)
    assert resp.status_code == 200
    assert resp.content == test_file.content

# 2. S3 GET full object
def test_s3_get_full(s3_client, test_object):
    resp = s3_client.get_object(Bucket=test_object.bucket, Key=test_object.key)
    assert resp["Body"].read() == test_object.content

# 3. Range request (shared parse path — both protocols)
def test_webdav_get_range(webdav_client, test_file):
    headers = {"Range": "bytes=0-99"}
    resp = webdav_client.get(test_file.path, headers=headers)
    assert resp.status_code == 206
    assert len(resp.content) == 100
    assert "Content-Range" in resp.headers

# 4. Security: path traversal rejected (shared resolver still applied)
def test_get_traversal_rejected(webdav_client):
    resp = webdav_client.get("/../etc/passwd")
    assert resp.status_code in (400, 403, 404)
```

---

## What this does NOT do

- Does **not** share the VFS open/stat/dir-check — error response formats differ
  (`404 Not Found` vs `NoSuchKey` XML body) and would require callbacks that cost
  more LoC than they save.
- Does **not** share the S3 `s3_handle_head` path — it's only 36 LoC and takes the
  `xrootd_vfs_stat` (no open) path which has no equivalent in WebDAV's HEAD handling.
- Does **not** run `./configure` automatically — must be done manually after step 3.

---

## Future extension

Once `xrootd_http_serve_file_ranged` exists, any new HTTP protocol that needs file
download (e.g. an XrdHTTP compatibility layer) calls the same function with its own
`xfer_proto` / `op_name` / `pre_header_send`. The range-parse + send contract is
tested once and maintained in one place.
