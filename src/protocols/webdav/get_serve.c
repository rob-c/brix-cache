/*
 * get_serve.c — GET open/stat + serve phases: VFS open error mapping,
 * multi-range (multipart/byteranges), conditional (304) and full/single-range
 * serving.  Split from the 793-line get.c at phase-103; every body is lifted
 * verbatim, so the serve semantics (including the FROZEN TLS-memory vs
 * cleartext-sendfile split inside the shared helpers) are unchanged.
 */

#include "webdav.h"
#include "xrdhttp.h"
#include "core/compat/error_mapping.h"
#include "core/http/etag.h"
#include "core/http/http_conditionals.h"
#include "fs/cache/open.h"
#include "observability/dashboard/dashboard_tracking.h"  /* BRIX_XFER_PROTO_* */
#include "fs/vfs/vfs.h"
#include "protocols/shared/file_serve.h"
#include "get_internal.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static ngx_int_t
webdav_register_send_fd_cleanup(ngx_http_request_t *r, ngx_fd_t fd,
    const char *path)
{
    ngx_pool_cleanup_t      *cln;
    ngx_pool_cleanup_file_t *clnf;
    size_t                   path_len;
    u_char                  *name;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    path_len = ngx_strlen(path);
    name = ngx_pnalloc(r->pool, path_len + 1);
    if (name == NULL) {
        return NGX_ERROR;
    }
    ngx_cpystrn(name, (u_char *) path, path_len + 1);

    cln->handler = ngx_pool_cleanup_file;
    clnf = cln->data;
    clnf->fd = fd;
    clnf->name = name;
    clnf->log = r->pool->log;

    return NGX_OK;
}

static void
webdav_get_add_xrdhttp_headers(ngx_http_request_t *r, ngx_fd_t fd,
    off_t file_size, void *ud)
{
    struct stat *sb = ud;
    webdav_fadvise_willneed(r->connection->log, fd, 0, (size_t) file_size);
    xrdhttp_add_checksum_header(r, fd, sb);
    xrdhttp_add_response_headers(r, r->headers_out.status);
}

/*
 * get_open_map_error — map a failed VFS open to its terminal HTTP status.
 *
 * WHAT: translate `vfs_err` from a NULL `brix_vfs_open` into the exact response
 *   the historical inline code produced.
 * WHY: the open error mapping carries security-load-bearing decisions
 *   (confinement rejections are 403, never 500) and a special-cased 202 tape
 *   recall — keeping it in one helper preserves those byte-for-byte.
 * HOW: early-return per errno class: ENOENT/ENOTDIR/ENAMETOOLONG → 404 (with
 *   xrdhttp headers), confinement/permission (EACCES/EPERM/EXDEV/ELOOP) → 403,
 *   EAGAIN → 202 + Retry-After, otherwise log and route through the shared
 *   errno→status table.
 */
static ngx_int_t
get_open_map_error(ngx_http_request_t *r, int vfs_err, const char *path)
{
    ngx_table_elt_t *ra;

    if (vfs_err == ENOENT || vfs_err == ENOTDIR
        || vfs_err == ENAMETOOLONG)
    {
        xrdhttp_add_response_headers(r, NGX_HTTP_NOT_FOUND);
        return NGX_HTTP_NOT_FOUND;
    }

    /* EXDEV (".." escape) / ELOOP (escaping or magic symlink) are the
     * kernel RESOLVE_BENEATH confinement rejections — forbidden, never a
     * 500.  EACCES/EPERM map the same way.  Route the whole errno set
     * through the shared table so the codes stay consistent with S3. */
    if (vfs_err == EACCES || vfs_err == EPERM
        || vfs_err == EXDEV || vfs_err == ELOOP)
    {
        return NGX_HTTP_FORBIDDEN;
    }

    /* EAGAIN ⇒ a nearline (tape) recall is in flight (sd_frm/sd_cache, §9.2).
     * Answer 202 "staging" with a Retry-After so the client polls until the
     * object is recalled into the cache tier and served — never block the
     * worker for a minutes-to-hours MSS recall. */
    if (vfs_err == EAGAIN) {
        ngx_http_brix_webdav_loc_conf_t *wlcf =
            ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

        ra = ngx_list_push(&r->headers_out.headers);
        if (ra != NULL) {
            ra->hash = 1;
            ngx_str_set(&ra->key, "Retry-After");
            ngx_str_set(&ra->value, "10");     /* default staging poll interval */
            /* §6.11 http.maxdelay: tighten (never lengthen) the poll wait when a
             * deployment caps it below the 10 s default. */
            if (wlcf != NULL && wlcf->common.max_delay > 0
                && wlcf->common.max_delay < 10)
            {
                u_char *rv = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
                if (rv != NULL) {
                    ra->value.len  = ngx_sprintf(rv, "%T", wlcf->common.max_delay) - rv;
                    ra->value.data = rv;
                }
            }
        }
        r->headers_out.status           = NGX_HTTP_ACCEPTED;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, vfs_err,
                  ngx_open_file_n " \"%s\" failed", path);
    return (ngx_int_t) brix_http_errno_to_status(vfs_err);
}

/*
 * webdav_get_resolve_and_stat — open the target and produce serve-ready state.
 *
 * WHAT: open `path` through the VFS, stat it, reject directories, and populate
 *   `st` (open handle + POSIX stat + VFS stat + fd-cache bookkeeping).
 * WHY: the serving phases need an open, statted, non-directory regular-file
 *   handle plus the derived metadata; concentrating open+stat+validation here
 *   keeps the orchestrator flat and each error path owning its own close.
 * HOW: open (mapping any failure via get_open_map_error), stat (500 on
 *   failure), directory guard (403), then fill `st.sb` from the VFS stat and
 *   capture the sendfile fd cache bookkeeping.  Returns NGX_OK with `st`
 *   populated and the handle open, or a terminal status with nothing to close.
 */
ngx_int_t
webdav_get_resolve_and_stat(ngx_http_request_t *r, brix_vfs_ctx_t *vctx,
    const char *path, get_serve_state_t *st)
{
    int vfs_err = 0;

    st->fh = brix_vfs_open(vctx, BRIX_VFS_O_READ, &vfs_err);
    if (st->fh == NULL) {
        return get_open_map_error(r, vfs_err, path);
    }

    if (brix_vfs_file_stat(st->fh, &st->vst) != NGX_OK) {
        brix_vfs_close(st->fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (st->vst.is_directory) {
        brix_vfs_close(st->fh, r->connection->log);
        /* §6.6: signal "directory" to the orchestrator, which owns the
         * listingredir / HTML-listing / listingdeny decision (get_serve_
         * directory). Kept side-effect-free here so no response is sent from
         * inside the open-and-stat helper. */
        return NGX_DECLINED;
    }

    ngx_memzero(&st->sb, sizeof(st->sb));
    st->sb.st_size  = st->vst.size;
    st->sb.st_mtime = st->vst.mtime;
    st->sb.st_ctime = st->vst.ctime;
    st->sb.st_mode  = (mode_t) st->vst.mode;
    st->sb.st_ino   = st->vst.ino;

    /* Zero-copy (sendfile) serve fd, gated on the backend's CAP_SENDFILE; a
     * non-sendfile backend returns NGX_INVALID_FILE and the dup in the
     * multirange path fails closed instead of serving a bogus descriptor. */
    st->from_cache = brix_vfs_file_from_cache(st->fh);
    st->cache_path = brix_vfs_file_path(st->fh);
    return NGX_OK;
}

/*
 * webdav_get_serve_range — serve a multi-range (multipart/byteranges) GET.
 *
 * WHAT: handle the XrdHttp multi-range vector read by duplicating the sendfile
 *   fd, registering its cleanup, and delegating to the multipart handler.
 * WHY: multi-range is the kXR_readv-over-HTTP path; the TLS-memory vs
 *   cleartext-sendfile split lives inside xrdhttp_handle_multipart_get and is
 *   FROZEN — this helper only owns the dup + cleanup + cache accounting around
 *   it.  The dup lets the multipart handler own an independent fd while the VFS
 *   handle is closed here.
 * HOW: dup the sendfile fd (500 on failure), register a pool cleanup that owns
 *   the dup, close the VFS handle, run the multipart serve, and record cache
 *   access on a successful full body.
 */
ngx_int_t
webdav_get_serve_range(ngx_http_request_t *r, get_serve_state_t *st, const char *path)
{
    ngx_fd_t  fd;
    ngx_fd_t  send_fd;
    ngx_int_t rc;

    fd = brix_vfs_file_sendfile_fd(st->fh);

    send_fd = dup(fd);
    if (send_fd == NGX_INVALID_FILE) {
        brix_vfs_close(st->fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (webdav_register_send_fd_cleanup(r, send_fd, path) != NGX_OK) {
        ngx_close_file(send_fd);
        brix_vfs_close(st->fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    brix_vfs_close(st->fh, r->connection->log);

    rc = xrdhttp_handle_multipart_get(r, send_fd, &st->sb, 1);
    if (st->from_cache && rc == NGX_OK && !r->header_only) {
        (void) brix_cache_record_access(st->cache_path,
                    (size_t) st->sb.st_size, r->connection->log);
    }
    return rc;
}

/*
 * webdav_get_eval_conditionals — apply the If-Modified-Since precondition.
 *
 * WHAT: evaluate the conditional GET via the shared eval and, on a 304, emit
 *   the not-modified response.
 * WHY: a matching precondition must short-circuit the serve with an empty 304
 *   body; the check owns closing the VFS handle on every terminal outcome.
 * HOW: NGX_HTTP_NOT_MODIFIED → close, send 304 headers + special last; any
 *   other non-OK → close and propagate; NGX_OK → return NGX_OK (handle stays
 *   open for the serve phase).
 */
ngx_int_t
webdav_get_eval_conditionals(ngx_http_request_t *r, get_serve_state_t *st)
{
    ngx_int_t rc = brix_http_check_if_modified_since(r, st->sb.st_mtime);

    if (rc == NGX_HTTP_NOT_MODIFIED) {
        brix_vfs_close(st->fh, r->connection->log);
        r->headers_out.status           = NGX_HTTP_NOT_MODIFIED;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }
    if (rc != NGX_OK) {
        brix_vfs_close(st->fh, r->connection->log);
        return rc;
    }
    return NGX_OK;
}

/*
 * webdav_get_serve_full — serve the file with single-range (206) / full (200) body.
 *
 * WHAT: run the shared ranged file serve and report the range/bytes metrics.
 * WHY: this is the common whole-file / single-range path; the TLS-memory vs
 *   cleartext-sendfile split is FROZEN inside brix_http_serve_file_ranged.
 * HOW: disable the core range filter (the shared serve does its own range
 *   parse and emits 206/416 itself; leaving allow_ranges on lets nginx
 *   re-parse the same header and 416 a body already served — and ledgered —
 *   as a full 200 when the Range is malformed, which RFC 9110 §14.2 says to
 *   ignore), advertise Accept-Ranges explicitly, build the serve opts (weak
 *   ETag, compress flag, xrdhttp pre-header hook carrying `sb`), serve, then
 *   feed the result to the shared metrics reporter.
 */
ngx_int_t
webdav_get_serve_full(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *wctx, get_serve_state_t *st,
    const char *path)
{
    const char              *identity =
        (wctx != NULL && wctx->dn[0] != '\0') ? wctx->dn : "anonymous";
    brix_http_serve_opts_t   opts;
    brix_http_serve_result_t result;
    ngx_int_t                rc;

    r->allow_ranges = 0;
    (void) brix_http_set_header(r, "Accept-Ranges", "bytes", NULL);

    ngx_memzero(&opts, sizeof(opts));
    opts.xfer_proto      = BRIX_XFER_PROTO_WEBDAV;
    opts.op_name         = "GET";
    opts.identity        = identity;
    opts.etag_flags      = BRIX_ETAG_WEAK;
    opts.compress        = conf->common.compress;
    opts.pre_header_send = webdav_get_add_xrdhttp_headers;
    opts.pre_header_ud   = &st->sb;

    rc = brix_http_serve_file_ranged(r, st->fh, &st->vst, path, &opts, &result);
    webdav_serve_metrics(r, &result);
    return rc;
}
