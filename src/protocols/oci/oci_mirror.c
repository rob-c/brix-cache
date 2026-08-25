/*
 * oci_mirror.c — the /v2/ content handler (Appendix J).
 *
 * WHAT: the entry point for every request on a brix_oci_mirror location:
 *       ctx + observer → gate → canonical key → offloaded serve → coalesced
 *       fill → open + ranged response with the registry's two headers.
 * WHY:  a pull-through registry mirror is a cache with a URL grammar bolted
 *       on. Everything below the grammar — request coalescing so a hundred
 *       simultaneous `podman pull`s of the same layer cause ONE upstream GET,
 *       digest verify at the edge, ranged/conditional serving, bounded
 *       stale-if-error — is machinery this tree already runs for CVMFS. The
 *       job of this file is therefore to compose those pieces in the exact
 *       order Appendix J pins, and to add nothing of its own that could drift
 *       from them.
 * HOW:  the J-wiring, verbatim: brix_http_serve_offload_remote →
 *       brix_http_cache_fill_if_needed → brix_vfs_open →
 *       brix_http_serve_file_ranged. Never brix_cache_open_or_fill (it fills
 *       inline on the event loop), never a direct open/read/sendfile in this
 *       directory, and never `Accept` in the cache key — a manifest is one
 *       object, and content negotiation on it would fragment the cache along
 *       a dimension the upstream does not.
 */

#include "oci.h"
#include "oci_module_internal.h"
#include "oci_registry.h"

#include "core/http/http_conditionals.h"
#include "core/http/http_file_response.h"     /* brix_http_add_etag_header */
#include "core/http/http_headers.h"           /* brix_http_set_header      */
#include "core/http/etag.h"
#include "fs/backend/cache/sd_cache.h"        /* brix_sd_cache_fill_needs_offload */
#include "fs/cache/cstore.h"                  /* brix_cstore_local_root    */
#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_backend_registry.h"
#include "observability/dashboard/dashboard.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"
#include "observability/metrics/unified.h"
#include "protocols/shared/file_serve.h"
#include "protocols/shared/http_cache_fill.h"
#include "protocols/shared/http_serve_offload.h"
#include "protocols/shared/mirror_common.h"

#include <limits.h>

/* ---- the fill-failure map (Appendix J.4) --------------------------------- */

/* Seconds a client is told to wait after the upstream rate-limited us. Long
 * enough that a pull farm backing off in lockstep does not immediately re-form
 * the burst, short enough that a transient limit does not stall a deployment. */
#define OCI_RATE_LIMIT_HOLDOFF  "5"

/* Translate the tier's fill verdict into the registry's own vocabulary. The
 * tier reports HTTP statuses because that is what its origin spoke; a registry
 * client reads the ERROR CODE, and "MANIFEST_UNKNOWN" vs "BLOB_UNKNOWN" is the
 * difference between `podman pull` reporting a missing tag and reporting a
 * corrupt image. */
static brix_oci_err_t
oci_fill_err(const ngx_http_brix_oci_ctx_t *ctx, ngx_int_t status)
{
    switch (status) {
    case NGX_HTTP_NOT_FOUND:
        return (ctx->req.cls == BRIX_OCI_REQ_MANIFEST)
               ? BRIX_OCI_ERR_MANIFEST_UNKNOWN : BRIX_OCI_ERR_BLOB_UNKNOWN;
    case NGX_HTTP_FORBIDDEN:
    case NGX_HTTP_UNAUTHORIZED:
        return BRIX_OCI_ERR_DENIED;
    case NGX_HTTP_TOO_MANY_REQUESTS:
        return BRIX_OCI_ERR_TOOMANYREQUESTS;
    default:
        return BRIX_OCI_ERR_UNAVAILABLE;
    }
}

/* Fill-failure interceptor. The tier has already exhausted its own stale-serve
 * window by the time it calls this, so there is nothing left to salvage — the
 * job here is to say WHY in the shape the client parses, and to charge the
 * upstream-error bucket an operator alerts on. */
static ngx_int_t
oci_fill_fail(ngx_http_request_t *r, void *data, ngx_int_t status)
{
    ngx_http_brix_oci_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_oci_module);
    ngx_uint_t                out;

    (void) data;

    if (ctx == NULL) {
        return status;
    }
    ctx->disp = BRIX_OCI_OUT_ERROR;

    /* An upstream 401 that survived the token dance is a genuine denial, not a
     * challenge to relay: relaying it would make the client believe OUR mirror
     * wants credentials it has no way to mint. */
    out = (status == NGX_HTTP_UNAUTHORIZED) ? NGX_HTTP_FORBIDDEN
                                            : (ngx_uint_t) status;
    if (out < 400) {
        out = NGX_HTTP_BAD_GATEWAY;
    }

    BRIX_OCI_METRIC_INC(upstream_errors_total[brix_oci_uperr_bucket(out)]);

    /* A 429 without a Retry-After is a refusal the client can only answer by
     * guessing, and a guessing client retries immediately — the exact traffic
     * the upstream limit exists to stop. This is OUR hold-off, not the
     * origin's: the upstream header does not survive the fill's thread-pool
     * boundary (DRIFT vs D1.5's "echoed"), and a mirror-local constant is the
     * honest thing to publish anyway, since our next attempt is what the
     * client's retry actually costs. */
    if (out == NGX_HTTP_TOO_MANY_REQUESTS
        && brix_http_set_header(r, "Retry-After", OCI_RATE_LIMIT_HOLDOFF, NULL)
           != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return brix_oci_error(r, out, oci_fill_err(ctx, status), NULL);
}

/* Re-entry trampoline: the completed fill re-runs the whole handler, which now
 * takes the hit path. The disposition stays FILL — the bytes came from a fresh
 * upstream pull, and an operator reading $oci_cache wants to know that. */
static ngx_int_t
oci_reenter(ngx_http_request_t *r, void *data)
{
    (void) data;
    return ngx_http_brix_oci_handler(r);
}

/* ---- the tier read ------------------------------------------------------- */


/* The two off-loop steps: a socket-wire serve, then a coalesced miss fill.
 * NGX_DECLINED means the bytes are local now and the caller should open. */
static ngx_int_t
oci_serve_or_fill(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx, brix_sd_instance_t *sd, const char *path)
{
    brix_http_serve_opts_t  sopts;
    ngx_int_t               rc;

    /* No presentation record yet: the offload path re-serves through the same
     * ranged pipeline, but the object is not open here and the digest cannot
     * be derived without it. The offload only ever fires for socket-wire
     * backends, which an OCI mirror (http upstream) is not — so this stays a
     * correctness guard rather than a live path. */
    brix_oci_present_serve_opts(&sopts, NULL);

    rc = brix_http_serve_offload_remote(r, sd, ctx->key, path, &sopts,
                                        &lcf->common, NULL, NULL);
    if (rc == NGX_DONE) {
        return NGX_DONE;
    }
    if (rc == NGX_ERROR) {
        return brix_oci_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                              BRIX_OCI_ERR_UNAVAILABLE, NULL);
    }

    rc = brix_http_cache_fill_if_needed(r, sd, ctx->key, &lcf->common,
                                        oci_reenter, NULL, oci_fill_fail);
    if (rc == NGX_DONE) {
        ctx->disp = BRIX_OCI_OUT_FILL;
        return NGX_DONE;
    }
    if (rc == NGX_ERROR) {
        return brix_oci_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                              BRIX_OCI_ERR_UNAVAILABLE, NULL);
    }

    return NGX_DECLINED;
}

/* Where this object's sidecar goes: beside the cached body, in the cache
 * STORE's own directory. The mirror's export root is the pure-cache anchor "/",
 * so the request path is the key and nothing more — the bytes physically live
 * under the store, and asking the store where that is (rather than assuming the
 * advertised root) is the same discipline the reaper follows. A non-local store
 * (s3/rados) answers NULL: it has no directory to put a memo in, and the caller
 * then derives the pair on every hit, which is correct but not free.
 * 0 = written, -1 = no sidecar is possible for this object. */
static int
oci_meta_base(brix_sd_instance_t *sd, const ngx_http_brix_oci_ctx_t *ctx,
    char *out, size_t outsz)
{
    const char  *store_root = brix_cstore_local_root(brix_sd_cache_cstore(sd));
    size_t       rn;

    if (store_root == NULL) {
        return -1;
    }
    rn = ngx_strlen(store_root);
    while (rn > 0 && store_root[rn - 1] == '/') {
        rn--;                                  /* the key carries the slash */
    }
    if (rn + ctx->key_len >= outsz) {
        return -1;
    }
    ngx_memcpy(out, store_root, rn);
    ngx_memcpy(out + rn, ctx->key, ctx->key_len);
    out[rn + ctx->key_len] = '\0';

    return 0;
}


/* Conditional evaluation against the validator this surface actually
 * publishes. When the object's digest is known that IS the ETag (App. B.1),
 * and it must be the one compared: the generic evaluator derives its own
 * from mtime+size, which a refill of byte-identical bytes changes — so a
 * client revalidating an unchanged tag past its TTL would be handed the whole
 * manifest again. Everything else (If-Match, the date forms) stays with the
 * shared RFC 9110 §13.2.2 evaluator. */
static ngx_int_t
oci_eval_conditional(ngx_http_request_t *r, const brix_oci_present_t *pres,
    const brix_vfs_stat_t *vst)
{
    char  etag[BRIX_OCI_DIGEST_STRLEN + 3];

    if (r->headers_in.if_none_match != NULL
        && r->headers_in.if_match == NULL
        && brix_oci_present_etag(pres, etag, sizeof(etag)))
    {
        return (brix_http_etag_list_contains(
                    &r->headers_in.if_none_match->value, etag,
                    BRIX_HTTP_COND_WEAK_EQUIV) == NGX_OK)
               ? NGX_HTTP_NOT_MODIFIED : NGX_OK;
    }

    return brix_http_eval_preconditions(r, 1, vst->mtime, vst->size,
                                        BRIX_ETAG_WEAK,
                                        BRIX_HTTP_COND_READ
                                        | BRIX_HTTP_COND_TIME
                                        | BRIX_HTTP_COND_WEAK_EQUIV);
}


/* Open the now-local object and answer. Errors map through J.5, not through
 * the generic table: an ENOSPC on a read surface is an upstream/store problem
 * (502), and an EACCES is the containment check refusing a path escape. */
static ngx_int_t
oci_open_respond(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx, brix_vfs_ctx_t *vctx, const char *path)
{
    brix_oci_present_t       *pres;
    brix_http_serve_opts_t    opts;
    brix_http_serve_result_t  result;
    brix_vfs_file_t          *fh;
    brix_vfs_stat_t           vst;
    char                      meta_base[PATH_MAX];
    int                       vfs_err = 0;
    ngx_int_t                 rc;

    fh = brix_vfs_open(vctx, BRIX_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        ngx_uint_t status = brix_oci_errno_status(r, vfs_err);

        ctx->disp = BRIX_OCI_OUT_ERROR;
        return brix_oci_error(r, status, oci_fill_err(ctx, (ngx_int_t) status),
                              NULL);
    }
    if (ctx->disp == BRIX_OCI_OUT_HIT || ctx->disp == BRIX_OCI_OUT_LOCAL) {
        /* pcalloc'd zero == BRIX_OCI_OUT_HIT; only a fill overrides it. */
        ctx->disp = BRIX_OCI_OUT_HIT;
    }

    if (brix_vfs_file_stat(fh, &vst) != NGX_OK) {
        brix_vfs_close(fh, r->connection->log);
        return brix_oci_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                              BRIX_OCI_ERR_UNAVAILABLE, NULL);
    }
    if (vst.is_directory) {
        brix_vfs_close(fh, r->connection->log);
        return brix_oci_error(r, NGX_HTTP_NOT_FOUND,
                              oci_fill_err(ctx, NGX_HTTP_NOT_FOUND), NULL);
    }

    pres = ngx_pcalloc(r->pool, sizeof(*pres));
    if (pres == NULL) {
        brix_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (oci_meta_base(vctx->sd, ctx, meta_base, sizeof(meta_base)) != 0) {
        meta_base[0] = '\0';
    }
    if (brix_oci_present_prepare(r, lcf, ctx, fh, &vst,
                                 (meta_base[0] != '\0') ? meta_base : NULL,
                                 pres) != NGX_OK)
    {
        brix_vfs_close(fh, r->connection->log);
        return brix_oci_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                              BRIX_OCI_ERR_UNAVAILABLE, NULL);
    }

    rc = oci_eval_conditional(r, pres, &vst);
    if (rc == NGX_HTTP_NOT_MODIFIED) {
        brix_vfs_close(fh, r->connection->log);
        ctx->disp = BRIX_OCI_OUT_LOCAL;         /* answered with no bytes */
        r->headers_out.status             = NGX_HTTP_NOT_MODIFIED;
        r->headers_out.content_length_n   = 0;
        r->headers_out.last_modified_time = vst.mtime;
        (void) brix_http_add_etag_header(r, vst.mtime, vst.size,
                                         BRIX_ETAG_WEAK, 1);
        /* RFC 9110 §15.4.5: a 304 carries the validators — and, for a
         * registry, the digest the 200 would have carried, because a client
         * revalidating a manifest still needs to pin what it holds. */
        brix_oci_present_headers(r, (ngx_fd_t) -1, 0, pres);
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }
    if (rc != NGX_OK) {
        brix_vfs_close(fh, r->connection->log);
        return rc;
    }

    /* Blobs are the only route a client ever ranges (a resumed layer pull);
     * a manifest is fetched whole, but allowing ranges on it costs nothing and
     * keeps one code path. */
    r->allow_ranges = 1;

    brix_oci_present_serve_opts(&opts, pres);
    return brix_http_serve_file_ranged(r, fh, &vst, path, &opts, &result);
}

static ngx_int_t
oci_tier_get(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx)
{
    char             path[PATH_MAX];
    const char      *root = lcf->common.root_canon;
    brix_vfs_ctx_t   vctx;
    int              is_tls = 0;
    ngx_int_t        rc;

    rc = brix_http_mirror_key_path(root, ctx->key, ctx->key_len,
                                   path, sizeof(path));
    if (rc != NGX_OK) {
        return brix_oci_error(r, (ngx_uint_t) rc, BRIX_OCI_ERR_NAME_INVALID,
                              NULL);
    }

    is_tls = brix_http_request_is_tls(r);
    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_OCI,
                      root, "", /* allow_write */ 0, is_tls, NULL, path);

    vctx.sd = brix_vfs_backend_resolve(root, r->connection->log);
    if (vctx.sd == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "oci: no storage backend registered for \"%s\" — check "
            "brix_oci_mirror / brix_storage_backend", root);
        return brix_oci_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                              BRIX_OCI_ERR_UNAVAILABLE, NULL);
    }

    /* Per-worker one-shot: the upstream token supplier can only be attached
     * once the instance exists, and instances are built lazily post-fork. */
    brix_oci_bind_bearer(lcf, vctx.sd, r->connection->log);

    (void) brix_dashboard_http_start_identity(r, ctx->key,
        (ctx->deleg_user != NULL) ? ctx->deleg_user : "anonymous", "",
        BRIX_XFER_PROTO_OCI, BRIX_XFER_DIR_READ, "GET", -1);

    rc = oci_serve_or_fill(r, lcf, ctx, vctx.sd, path);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    return oci_open_respond(r, lcf, ctx, &vctx, path);
}

/* ---- accounting ---------------------------------------------------------- */

void
brix_oci_finalize_observe(void *data)
{
    ngx_http_request_t       *r = data;
    ngx_http_brix_oci_ctx_t  *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_oci_module);

    if (ctx == NULL || ctx->counted) {
        return;
    }
    ctx->counted = 1;

    /* One request, one row. The surface is fixed per location and the class /
     * disposition are enum indices — invariant #8 holds by construction: no
     * repository name, tag or digest is ever a label. */
    BRIX_OCI_METRIC_INC(
        requests_total[BRIX_OCI_SURFACE_MIRROR][ctx->mclass][ctx->disp]);
}

/* ---- entry point --------------------------------------------------------- */

static ngx_http_brix_oci_ctx_t *
oci_handler_ctx(ngx_http_request_t *r)
{
    ngx_http_brix_oci_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_oci_module);
    ngx_pool_cleanup_t       *cln;

    if (ctx != NULL) {
        return ctx;                        /* re-entry after a parked fill */
    }
    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_brix_oci_module);

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NULL;
    }
    cln->handler = brix_oci_finalize_observe;
    cln->data    = r;

    return ctx;
}

ngx_int_t
ngx_http_brix_oci_handler(ngx_http_request_t *r)
{
    ngx_http_brix_oci_loc_conf_t *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_oci_module);
    ngx_http_brix_oci_ctx_t      *ctx;
    ngx_int_t                     rc;

    ctx = oci_handler_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* The registry surface reads bodies (a PATCH IS the layer), so it must
     * take the request BEFORE the body is discarded. The two surfaces are
     * mutually exclusive per location — the merge refuses both directives on
     * one location — so this is a branch, not a fallthrough. */
    if (lcf->registry) {
        return brix_oci_registry_handle(r, lcf, ctx);
    }

    /* The mirror is GET/HEAD-only, so no request body is ever meaningful; the
     * gate still polices the method itself, because a discarded body must not
     * make a push look like it was accepted. */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Delegated pull (D16): establish WHO is asking before any route is
     * dispatched — the listing routes answered inside the gate need the
     * identity too — then, for the object routes, require the per-
     * (credential, repository) proof before any byte is served, hit or
     * miss alike. Re-entries (parked fill, granted proof) pass straight
     * through on ctx->deleg_proved. */
    rc = brix_oci_delegate_ident(r, lcf, ctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = brix_oci_gate(r, lcf, ctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = brix_oci_delegate_gate(r, lcf, ctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    return oci_tier_get(r, lcf, ctx);
}
