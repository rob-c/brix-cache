/*
 * rpm_mirror.c — the content handler for a brix_rpm_mirror location.
 *
 * WHAT: the entry point for every request on an RPM/dnf pull-through mirror:
 *       ctx + observer → gate → offloaded serve → coalesced fill → open +
 *       ranged response.
 * WHY:  a package mirror is a cache with a repository layout on top of it.
 *       Everything below the layout — request coalescing so a hundred
 *       simultaneous `dnf install`s of the same package cause ONE upstream
 *       GET, digest verify at the edge, ranged/conditional serving, bounded
 *       stale-if-error — is machinery this tree already runs for CVMFS and
 *       for the OCI mirror. The job of this file is to compose those pieces
 *       in the order the shared plane pins, and to add nothing of its own
 *       that could drift from them.
 * HOW:  the same wiring the OCI mirror uses, verbatim:
 *       brix_http_serve_offload_remote → brix_http_cache_fill_if_needed →
 *       brix_vfs_open → brix_http_serve_file_ranged. Never
 *       brix_cache_open_or_fill (it fills inline on the event loop), and
 *       never a raw open/read/sendfile in this directory (INVARIANT #12).
 */

#include "rpm.h"

#include "core/http/etag.h"                    /* BRIX_ETAG_WEAK */
#include "core/http/http_headers.h"            /* brix_http_request_is_tls */
#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_backend_registry.h"
#include "observability/dashboard/dashboard.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"
#include "protocols/shared/file_serve.h"
#include "protocols/shared/http_cache_fill.h"
#include "protocols/shared/http_serve_offload.h"
#include "protocols/shared/mirror_common.h"

#include <limits.h>

/* The serve options this plane publishes. Weak ETags because the validator is
 * derived from mtime+size: a refill of byte-identical metadata is a new file
 * on disk, and a strong ETag would be claiming byte-identity we did not check
 * (for the digest-named routes the cache tier verified the bytes, but the
 * validator a client compares is still the local file's). */
static void
rpm_serve_opts(brix_http_serve_opts_t *opts)
{
    ngx_memzero(opts, sizeof(*opts));
    opts->xfer_proto = BRIX_XFER_PROTO_RPM;
    opts->op_name    = "GET";
    opts->identity   = "anonymous";
    opts->etag_flags = BRIX_ETAG_WEAK;
}


/* Re-entry trampoline: the completed fill re-runs the whole handler, which
 * now takes the hit path. The disposition stays FILL — the bytes came from a
 * fresh upstream pull, and an operator reading $rpm_cache wants to know. */
static ngx_int_t
rpm_reenter(ngx_http_request_t *r, void *data)
{
    (void) data;
    return ngx_http_brix_rpm_handler(r);
}


/* Fill-failure interceptor. The tier has already exhausted its own
 * stale-serve window by the time it calls this, so there is nothing left to
 * salvage: report the upstream's own verdict where it is meaningful to a
 * package client (a 404 is a missing package, which dnf reports as such) and
 * 502 for everything else — the failure is ours-to-upstream, not the
 * client's. An upstream 401/403 becomes 403: relaying the challenge would
 * make dnf prompt for credentials THIS mirror cannot use. */
static ngx_int_t
rpm_fill_fail(ngx_http_request_t *r, void *data, ngx_int_t status)
{
    ngx_http_brix_rpm_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_rpm_module);

    (void) data;

    if (ctx != NULL) {
        ctx->disp = BRIX_RPM_OUT_ERROR;
    }
    if (status == NGX_HTTP_NOT_FOUND) {
        return NGX_HTTP_NOT_FOUND;
    }
    if (status == NGX_HTTP_UNAUTHORIZED || status == NGX_HTTP_FORBIDDEN) {
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_HTTP_BAD_GATEWAY;
}


/* The two off-loop steps: a socket-wire serve, then a coalesced miss fill.
 * NGX_DECLINED means the bytes are local now and the caller should open. */
static ngx_int_t
rpm_serve_or_fill(ngx_http_request_t *r, ngx_http_brix_rpm_loc_conf_t *lcf,
    ngx_http_brix_rpm_ctx_t *ctx, brix_sd_instance_t *sd, const char *path)
{
    brix_http_serve_opts_t  sopts;
    ngx_int_t               rc;

    rpm_serve_opts(&sopts);

    rc = brix_http_serve_offload_remote(r, sd, ctx->key, path, &sopts,
                                        &lcf->common, NULL, NULL);
    if (rc == NGX_DONE) {
        return NGX_DONE;
    }
    if (rc == NGX_ERROR) {
        ctx->disp = BRIX_RPM_OUT_ERROR;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = brix_http_cache_fill_if_needed(r, sd, ctx->key, &lcf->common,
                                        rpm_reenter, NULL, rpm_fill_fail);
    if (rc == NGX_DONE) {
        ctx->disp = BRIX_RPM_OUT_FILL;
        return NGX_DONE;
    }
    if (rc == NGX_ERROR) {
        ctx->disp = BRIX_RPM_OUT_ERROR;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_DECLINED;
}


/* Open the now-local object and answer. A directory-shaped hit is a 404 here:
 * the classifier already refused directory-shaped REQUESTS, so this is the
 * cache store answering with something that is not the file we asked for. */
static ngx_int_t
rpm_open_respond(ngx_http_request_t *r, ngx_http_brix_rpm_loc_conf_t *lcf,
    ngx_http_brix_rpm_ctx_t *ctx, brix_vfs_ctx_t *vctx, const char *path)
{
    brix_http_serve_opts_t    opts;
    brix_http_serve_result_t  result;
    brix_vfs_file_t          *fh;
    brix_vfs_stat_t           vst;
    int                       vfs_err = 0;

    fh = brix_vfs_open(vctx, BRIX_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        ctx->disp = BRIX_RPM_OUT_ERROR;
        return (vfs_err == NGX_ENOENT) ? NGX_HTTP_NOT_FOUND
             : (vfs_err == NGX_EACCES) ? NGX_HTTP_FORBIDDEN
                                       : NGX_HTTP_BAD_GATEWAY;
    }
    if (brix_vfs_file_stat(fh, &vst) != NGX_OK) {
        brix_vfs_close(fh, r->connection->log);
        ctx->disp = BRIX_RPM_OUT_ERROR;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (vst.is_directory) {
        brix_vfs_close(fh, r->connection->log);
        ctx->disp = BRIX_RPM_OUT_ERROR;
        return NGX_HTTP_NOT_FOUND;
    }

    /* A freshly pulled index names the two files this client asks for next,
     * so warm them while this response is still being written (D15.10).
     * Advisory in both directions: nothing below reads its result, and it
     * refuses itself on every route but a repomd FILL. */
    brix_rpm_prefetch_repomd(r, lcf, ctx, fh, vst.size, vctx->sd);

    /* A resumed package download is the one range a repository client asks
     * for, and dnf's own delta/resume logic depends on it being honoured. */
    r->allow_ranges = 1;

    rpm_serve_opts(&opts);
    return brix_http_serve_file_ranged(r, fh, &vst, path, &opts, &result);
}


static ngx_int_t
rpm_tier_get(ngx_http_request_t *r, ngx_http_brix_rpm_loc_conf_t *lcf,
    ngx_http_brix_rpm_ctx_t *ctx)
{
    char             path[PATH_MAX];
    const char      *root = lcf->common.root_canon;
    brix_vfs_ctx_t   vctx;
    int              is_tls = 0;
    ngx_int_t        rc;

    rc = brix_http_mirror_key_path(root, ctx->key, ctx->key_len,
                                   path, sizeof(path));
    if (rc != NGX_OK) {
        ctx->disp = BRIX_RPM_OUT_REFUSED;
        return rc;
    }

    is_tls = brix_http_request_is_tls(r);
    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_RPM,
                      root, "", BRIX_VFS_MUTATION_READ_ONLY, is_tls, NULL, path);

    vctx.sd = brix_vfs_backend_resolve(root, r->connection->log);
    if (vctx.sd == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "rpm: no storage backend registered for \"%s\" — check "
            "brix_rpm_mirror / brix_cache_store", root);
        ctx->disp = BRIX_RPM_OUT_ERROR;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    (void) brix_dashboard_http_start_identity(r, ctx->key, "anonymous", "",
        BRIX_XFER_PROTO_RPM, BRIX_XFER_DIR_READ, "GET", -1);

    rc = rpm_serve_or_fill(r, lcf, ctx, vctx.sd, path);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    return rpm_open_respond(r, lcf, ctx, &vctx, path);
}


/* ---- accounting ---------------------------------------------------------- */

void
brix_rpm_finalize_observe(void *data)
{
    ngx_http_request_t      *r = data;
    ngx_http_brix_rpm_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_rpm_module);

    if (ctx == NULL || ctx->counted) {
        return;
    }
    ctx->counted = 1;

    /* One request, one row. Both indices are enums (INVARIANT #8): no
     * repository path, package name or digest is ever a metric label. */
    BRIX_RPM_METRIC_INC(requests_total[ctx->req.cls][ctx->disp]);
}


/* ---- entry point --------------------------------------------------------- */

static ngx_http_brix_rpm_ctx_t *
rpm_handler_ctx(ngx_http_request_t *r)
{
    ngx_http_brix_rpm_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_rpm_module);
    ngx_pool_cleanup_t      *cln;

    if (ctx != NULL) {
        return ctx;                        /* re-entry after a parked fill */
    }
    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_brix_rpm_module);

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NULL;
    }
    cln->handler = brix_rpm_finalize_observe;
    cln->data    = r;

    return ctx;
}


ngx_int_t
ngx_http_brix_rpm_handler(ngx_http_request_t *r)
{
    ngx_http_brix_rpm_loc_conf_t *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_rpm_module);
    ngx_http_brix_rpm_ctx_t      *ctx;
    ngx_int_t                     rc;

    ctx = rpm_handler_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* GET/HEAD only, so no request body is ever meaningful; the gate still
     * polices the method itself, because discarding a body must not make an
     * upload look like it was accepted. */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = brix_rpm_gate(r, ctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    return rpm_tier_get(r, lcf, ctx);
}
