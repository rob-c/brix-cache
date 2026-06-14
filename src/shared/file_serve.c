/*
 * file_serve.c — shared HTTP file-body serving pipeline (WebDAV + S3).
 *
 * WHAT: Implements xrootd_http_serve_file_ranged(), the single code path that
 *       turns an already-open, already-stat'd VFS file handle into an HTTP
 *       response body. It parses the Range request header, emits the matching
 *       full-body / 206-partial / 416-unsatisfied response headers, fires the
 *       optional pre-header hook, opens a dashboard transfer record, dups the
 *       fd and streams the requested byte range, then records bytes-sent and
 *       cache-access accounting.
 *
 * WHY:  WebDAV GET (src/webdav/get.c) and S3 GetObject (src/s3/object.c) need
 *       byte-for-byte identical range handling, ETag/Last-Modified header
 *       emission, dashboard transfer tracking, and cache hit accounting. This
 *       file is the one authoritative implementation so both protocols stay
 *       consistent and bugfixes land once. Callers supply only protocol-specific
 *       knobs (op_name, xfer_proto, identity, ETag flags, pre-header hook) via
 *       xrootd_http_serve_opts_t and read back metric inputs via
 *       xrootd_http_serve_result_t.
 *
 * HOW:  Five sequential phases over the supplied fh:
 *         1. range parse  — xrootd_http_parse_range() against vst->size; an
 *            unsatisfiable range short-circuits to a 416 (fh closed first).
 *         2. headers      — xrootd_http_set_file_headers() sets status,
 *            content-length, Content-Range, ETag/Last-Modified.
 *         3. dashboard    — xrootd_dashboard_http_start_identity() opens a READ
 *            transfer record for live monitoring.
 *         4. send         — the fd is dup()'d so xrootd_http_send_file_range()
 *            owns its own descriptor; the VFS handle is closed immediately
 *            after the dup so the cache/handle slot is released before the body
 *            (which may block on a slow client) is streamed.
 *         5. accounting   — on success, bytes_sent is reported back and, for
 *            cache-backed files, xrootd_cache_record_access() updates LRU/hit
 *            stats. header_only (HEAD) requests skip phases 5.
 *       INVARIANT: fh is always closed inside this function (success or error);
 *       callers must never close it afterwards.
 */
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

    /* Phase 1: range parse */
    xrootd_http_parse_range(
        r->headers_in.range ? r->headers_in.range->value.data : NULL,
        r->headers_in.range ? r->headers_in.range->value.len  : 0,
        vst->size, &rng);

    if (rng.present && !rng.satisfiable) {
        xrootd_vfs_close(fh, r->connection->log);
        result->range_result           = XROOTD_SERVE_RANGE_UNSATISFIED;
        r->headers_out.status           = NGX_HTTP_RANGE_NOT_SATISFIABLE;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    range_start          = rng.start;
    range_end            = rng.end;
    send_len             = (vst->size > 0) ? (range_end - range_start + 1) : 0;
    result->range_result = rng.present ? XROOTD_SERVE_RANGE_PARTIAL
                                       : XROOTD_SERVE_RANGE_FULL;

    /* Phase 2: response headers */
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

    /* Phase 3: dashboard */
    (void) xrootd_dashboard_http_start_identity(r, fs_path,
        opts->identity, "",
        opts->xfer_proto, XROOTD_XFER_DIR_READ, opts->op_name,
        (int64_t) send_len);

    /* Phase 4: dup fd, release vfs handle, send */
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

    /* Phase 5: post-send accounting */
    result->bytes_sent = send_len;
    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) send_len);

    if (from_cache && send_len > 0) {
        (void) xrootd_cache_record_access(cache_path, (size_t) send_len,
                                          r->connection->log);
    }

    return rc;
}
