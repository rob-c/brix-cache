/*
 * get.c - WebDAV GET with Range support, sendfile, and fd-cache fast path.
 */

#include "webdav.h"
#include "xrdhttp.h"
#include "core/compat/error_mapping.h"
#include "core/http/etag.h"
#include "core/http/http_conditionals.h"
#include "fs/cache/open.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "fs/vfs/vfs.h"
#include "protocols/shared/file_serve.h"
#include "protocols/shared/http_cache_fill.h"     /* phase-64 SP2: off-loop cache fill */
#include "protocols/shared/http_serve_offload.h"  /* phase-64 SP3: off-loop remote serve */
#include "protocols/root/zip/zip_http.h"   /* phase-57 W2: shared HTTP ZIP member serving */
#include "get_internal.h"

/* GET range/bytes metrics — shared by the serve phases (get_serve.c) and the
 * off-loop serve completion (brix_http_serve_offload), so all report
 * identically.  Prototype in get_internal.h. */
void
webdav_serve_metrics(ngx_http_request_t *r,
    const brix_http_serve_result_t *result)
{
    if (result->range_result == BRIX_SERVE_RANGE_UNSATISFIED) {
        BRIX_WEBDAV_METRIC_INC(range_total[BRIX_WEBDAV_RANGE_UNSATISFIED]);
    } else if (result->range_result == BRIX_SERVE_RANGE_PARTIAL) {
        BRIX_WEBDAV_METRIC_INC(range_total[BRIX_WEBDAV_RANGE_PARTIAL]);
    } else {
        BRIX_WEBDAV_METRIC_INC(range_total[BRIX_WEBDAV_RANGE_FULL]);
    }
    if (result->bytes_sent > 0) {
        BRIX_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) result->bytes_sent);
        if (r->connection && r->connection->sockaddr) {
            if (r->connection->sockaddr->sa_family == AF_INET6) {
                BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total,
                                         (size_t) result->bytes_sent);
            } else {
                BRIX_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total,
                                         (size_t) result->bytes_sent);
            }
        }
    }
}

/* Re-entry trampoline for the off-event-loop cache fill: after the fill lands the
 * completion event re-runs the GET handler, which now finds a cache HIT and serves
 * it zero-copy. The fill helper carries no per-handler state (the request re-
 * resolves from r), so `data` is unused.
 *
 * The result goes back through webdav_metrics_return for the same reason the
 * synchronous dispatch does: the first pass parked with NGX_DONE, and
 * webdav_metrics_response deliberately books nothing for a request that has not
 * finished.  Without this the ONE request that actually paid for a cache fill
 * was the one missing from brix_webdav_responses_total and from
 * brix_io_ops_total{proto="webdav",op="read"} — its bytes still landed (they
 * come from the scrape-time ledger fold), so ops and bytes disagreed on exactly
 * the remote-backed exports where fills happen. */
static ngx_int_t
webdav_get_reenter(ngx_http_request_t *r, void *data)
{
    (void) data;
    return webdav_metrics_return(r, webdav_handle_get(r));
}

/* Failure tail of the same park: a fill that ends 404/403/502 never re-enters
 * the handler, so this is the only place the parked request can book its
 * response.  Books and returns the status unchanged (the hook also exists to
 * re-drive against another source; that is not this handler's policy). */
static ngx_int_t
webdav_get_fill_failed(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    (void) data;
    webdav_metrics_response(r, rc);
    return rc;
}

/*
 * get_zip_member_serve — Phase-57 W2 ZIP member access over HTTP GET.
 *
 * WHAT: when the location is a ZIP-archive export, serve the requested member
 *   of the archive at `path` rather than the whole archive file.
 * WHY: archive auth already ran in the access phase; a GET on a zip export
 *   selects one member by argument, and this must short-circuit the normal
 *   file-serving pipeline.
 * HOW: parse the member argument; a negative result is a malformed request
 *   (400), a positive result serves the member and yields a terminal status,
 *   and zero means "no member requested" — signalled by NGX_DECLINED so the
 *   caller falls through to the normal whole-file path.
 */
static ngx_int_t
get_zip_member_serve(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path)
{
    char member[WEBDAV_MAX_PATH];
    int  zr;

    if (!conf->common.zip_access) {
        return NGX_DECLINED;
    }

    zr = brix_zip_http_member_arg(r, member, sizeof(member));
    if (zr < 0) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (zr > 0) {
        return brix_zip_http_serve(r, conf->common.root_canon,
                                     conf->common.zip_cd_max_bytes, path, member);
    }
    return NGX_DECLINED;
}

/*
 * get_offload_or_fill — run the off-loop serve/fill fast paths.
 *
 * WHAT: give the socket-wire serve offload (SP3) and the remote cache-fill
 *   offload (SP2) a chance to handle the request off the event loop.
 * WHY: a root://-backed or remote-store export cannot open/read on the worker
 *   loop, and a remote cache MISS fill would stall it; both are pushed to the
 *   thread pool and completed (or re-entered) asynchronously.
 * HOW: returns NGX_DONE when a path took over (async in flight), a terminal
 *   HTTP status on error, or NGX_DECLINED when neither applies and the caller
 *   should open inline.  EACCES/EPERM from the offload is the per-user backend
 *   credential gate → 403; any other offload error → 500.
 */
static ngx_int_t
get_offload_or_fill(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *wctx, const char *path,
    brix_vfs_ctx_t *vctx)
{
    const char             *identity =
        (wctx != NULL && wctx->dn[0] != '\0') ? wctx->dn : "anonymous";
    brix_http_serve_opts_t  sopts;
    ngx_int_t               sr;
    ngx_int_t               fr;

    ngx_memzero(&sopts, sizeof(sopts));
    sopts.xfer_proto = BRIX_XFER_PROTO_WEBDAV;
    sopts.op_name    = "GET";
    sopts.identity   = identity;
    sopts.etag_flags = BRIX_ETAG_WEAK;
    sopts.compress   = conf->common.compress;

    sr = brix_http_serve_offload_remote(r, vctx->sd,
        brix_vfs_export_relative(vctx, path), path, &sopts,
        &conf->common, vctx, webdav_serve_metrics);
    if (sr == NGX_DONE) {
        return NGX_DONE;
    }
    if (sr == NGX_ERROR) {
        return (errno == EACCES || errno == EPERM)
               ? NGX_HTTP_FORBIDDEN : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    fr = brix_http_cache_fill_if_needed(r, vctx->sd,
        brix_vfs_export_relative(vctx, path), &conf->common,
        webdav_get_reenter, NULL, webdav_get_fill_failed);
    if (fr == NGX_DONE) {
        return NGX_DONE;
    }
    if (fr == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return NGX_DECLINED;
}

/*
 * webdav_handle_get — serve a file via HTTP GET with Range support.
 *
 * Fast path: if the fd-cache already holds an open fd for the requested URI
 * hash, the stat and open system calls are skipped entirely.  The cached fd
 * remains owned by the fd-cache; the cleanup handler registered below uses
 * NGX_INVALID_FILE so it does not close it a second time.
 *
 * Range handling: a single "bytes=start-end" or "bytes=-suffix" range is
 * parsed and served as 206 Partial Content.  Multi-range requests and
 * overlapping ranges are not supported; clients that send them receive the
 * full file (200 OK).
 *
 * ngx_http_send_header + r->header_only: after calling ngx_http_send_header(),
 * always check r->header_only.  If true, the client sent HEAD — return
 * immediately without sending a body.  The check inside the serve phases
 * handles this.
 *
 * Pool allocation: ngx_pcalloc(r->pool, ...) for ngx_buf_t and ngx_file_t —
 *   both are freed when the request pool is destroyed after the response
 *   is sent.
 *
 * Ownership of fd:
 *   - If fd came from the fd-cache (fd_from_table=1), the cleanup handler
 *     stores NGX_INVALID_FILE so the fd-cache retains ownership.
 *   - If fd was opened here (fd_from_table=0), the cleanup handler closes it.
 *
 * Flow: resolve path → (zip member?) → build VFS ctx → off-loop serve/fill →
 * open+stat (webdav_get_resolve_and_stat) → multi-range (webdav_get_serve_range) or
 * conditional (webdav_get_eval_conditionals) + full/single-range (webdav_get_serve_full).
 */
ngx_int_t
webdav_handle_get(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                             path[WEBDAV_MAX_PATH];
    ngx_int_t                        rc;
    ngx_http_brix_webdav_req_ctx_t  *wctx;
    brix_vfs_ctx_t                   vctx;
    get_serve_state_t                st = {0};

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon, path,
                                             sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

    /* Phase-57 W2: ZIP member access over HTTP GET.  Auth on the archive ran in
     * the access phase; serve the requested member instead of the whole file. */
    rc = get_zip_member_serve(r, conf, path);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    webdav_vfs_ctx_build_data(r, conf, path, &vctx);
    /* Route through the export's selected storage backend (NULL ⇒ default POSIX). */
    vctx.sd = brix_webdav_backend_instance(conf, r->connection->log);

    /* phase-64 SP3/SP2: socket-wire serve offload and remote cache-fill offload
     * (both off the event loop).  NGX_DONE ⇒ async took over; a terminal HTTP
     * status ⇒ error; NGX_DECLINED ⇒ open inline below. */
    rc = get_offload_or_fill(r, conf, wctx, path, &vctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = webdav_get_resolve_and_stat(r, &vctx, path, &st);
    if (rc == NGX_DECLINED) {
        /* §6.6: the target is a directory — listingredir / HTML listing /
         * listingdeny per config. This owns the response. */
        return webdav_get_serve_directory(r, conf, path);
    }
    if (rc != NGX_OK) {
        return rc;
    }

    /* XrdHttp: multi-range vector read (kXR_readv equivalent over HTTP).
     * A comma in the Range: value indicates multiple byte ranges — delegate
     * to the multipart/byteranges handler rather than the single-range path. */
    if (xrdhttp_request_is_multirange(r)) {
        return webdav_get_serve_range(r, &st, path);
    }

    rc = webdav_get_eval_conditionals(r, &st);
    if (rc != NGX_OK) {
        return rc;
    }

    return webdav_get_serve_full(r, conf, wctx, &st, path);
}
