/* handler.c — the cvmfs:// content handler.
 *
 * WHAT: entry point for every request on an brix_cvmfs-enabled location:
 *       ctx setup → gate (method/class/reject/geo) → cache-tier open-or-fill
 *       → file response.
 * WHY:  cvmfs:// is a dedicated protocol — this handler owns the request
 *       end-to-end; nothing routes through the WebDAV dispatch.
 * HOW:  everything below the protocol seam is shared machinery: the serve
 *       step is the same offload → coalesced-fill → brix_vfs_open →
 *       brix_http_serve_file_ranged composition the WebDAV GET path
 *       drives, with Range/HEAD/conditional semantics from the shared
 *       helpers. The proxy-mode (T14) per-upstream override rides on the
 *       request ctx (convention #2).
 */
#include "cvmfs.h"
#include "fs/path/path.h"                  /* brix_sanitize_log_string */
#include "core/compat/error_mapping.h"
#include "core/http/etag.h"
#include "core/http/http_file_response.h"      /* brix_http_add_etag_header */
#include "core/http/http_conditionals.h"
#include "core/http/http_headers.h"
#include "core/http/sesslog_conn.h"
#include "fs/backend/cache/sd_cache.h"     /* brix_sd_cache_fill_needs_offload */
#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_backend_registry.h"
#include "observability/dashboard/dashboard.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "observability/metrics/unified.h"
#include "protocols/shared/file_serve.h"
#include "protocols/shared/http_cache_fill.h"
#include "protocols/shared/http_serve_offload.h"
#include "core/compat/cstr.h"

#include <limits.h>

/* CVMFS-flavoured errno → HTTP status: origin-side trouble is a GATEWAY
 * error (convention #3 — the origin transfer was bad, not the client
 * request), everything else follows the shared table. */
static ngx_uint_t
cvmfs_errno_status(int err)
{
    if (err == ENOENT || err == ENOTDIR || err == ENAMETOOLONG) {
        return NGX_HTTP_NOT_FOUND;
    }
    if (err == EACCES || err == EPERM || err == EXDEV || err == ELOOP) {
        return NGX_HTTP_FORBIDDEN;
    }
    if (err == EIO) {
        return NGX_HTTP_BAD_GATEWAY;
    }
    return brix_http_errno_to_status(err);
}

/* Re-entry trampoline for the off-loop cache fill: after the fill lands the
 * completion event re-runs the whole handler, which now takes the HIT path
 * (the disposition stays FILL — the bytes came via a fresh origin fill). */
static ngx_int_t
cvmfs_reenter(ngx_http_request_t *r, void *data)
{
    (void) data;
    return ngx_http_brix_cvmfs_handler(r);
}

/* Resolve which storage instance serves this request (convention #2):
 * the T14 proxy-mode per-upstream override wins, else the location's
 * statically registered backend. */
static brix_sd_instance_t *
cvmfs_resolve_sd(ngx_http_request_t *r, ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);

    if (ctx != NULL && ctx->sd_override != NULL) {
        return ctx->sd_override;
    }
    return brix_vfs_backend_resolve(lcf->common.root_canon,
                                      r->connection->log);
}

/* WHAT: build the on-disk fs path (export root + request uri) into `path`.
 * WHY:  a "/" root is the pure-cache-node anchor that contributes nothing, so
 *       the path IS the uri; every other root prefixes it. One place keeps the
 *       two overflow checks and the anchor special-case together.
 * HOW:  returns NGX_OK, or NGX_HTTP_REQUEST_URI_TOO_LARGE if the join would
 *       overflow the caller's PATH_MAX buffer. */
static ngx_int_t
cvmfs_build_fs_path(ngx_http_request_t *r, const char *root,
    char *path, size_t path_size)
{
    if (root[0] == '/' && root[1] == '\0') {
        if (brix_str_cbuf(path, path_size, &r->uri) == NULL) {
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }
        return NGX_OK;
    }

    {
        size_t rn = ngx_strlen(root);

        if (rn + r->uri.len >= path_size) {
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }
        ngx_memcpy(path, root, rn);
        ngx_memcpy(path + rn, r->uri.data, r->uri.len);
        path[rn + r->uri.len] = '\0';
    }
    return NGX_OK;
}

/* WHAT: fill a shared serve-opts struct with the fixed cvmfs GET descriptor
 *       (anonymous public read, weak etag) plus the per-location compress flag.
 * WHY:  both serve sites (offload and ranged) need the identical options; one
 *       initializer keeps them in lockstep and the values frozen. The compress
 *       flag (phase-85 F12) is the shared `brix_compress` that WebDAV/S3 already
 *       thread into their serve opts — cvmfs simply never opted in, so cvmfs
 *       GETs never transcoded. Off by default => byte-frozen parity; on => the
 *       shared negotiate path serves the client's best Accept-Encoding codec.
 *       Integrity is untouched: F1's CAS verify runs at fill time against the
 *       stored object, and this outbound Content-Encoding is a transparent,
 *       reversible wire transform that never alters the bytes on disk.
 * HOW:  zeroes then sets the constant fields and the caller's compress flag. */
static void
cvmfs_serve_opts_init(brix_http_serve_opts_t *opts, ngx_flag_t compress)
{
    ngx_memzero(opts, sizeof(*opts));
    opts->xfer_proto = BRIX_XFER_PROTO_CVMFS;
    opts->op_name    = "GET";
    opts->identity   = "anonymous";
    opts->etag_flags = BRIX_ETAG_WEAK;
    opts->compress   = compress;
}

/* WHAT: run the two off-loop steps of a tier read — socket-wire serve, then a
 *       coalesced miss-fill — and report whether the request is already
 *       resolved.
 * WHY:  socket-wire backends can't open/read on the event loop, so a serve
 *       that dispatches (NGX_DONE) or a fill that parks (NGX_DONE) both end
 *       the current call; only a fall-through means the bytes are now local
 *       and the caller should open + respond. Stale-serve semantics and the
 *       coalescing hold are owned by the shared fill helper, untouched here.
 * HOW:  returns NGX_DECLINED when the caller must proceed to open; otherwise
 *       the terminal rc (NGX_DONE, or an HTTP error status) to return as-is.
 *       On a parked fill it records the FILL disposition for $cvmfs_cache. */
static ngx_int_t
cvmfs_tier_serve_or_fill(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, brix_sd_instance_t *sd,
    const char *key, const char *path)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    brix_http_serve_opts_t     sopts;
    ngx_int_t                   rc;

    /* socket-wire backends can't open/read on the event loop */
    cvmfs_serve_opts_init(&sopts, lcf->common.compress);

    /* cvmfs is a transparent, anonymous public cache (no per-user
     * identity or backend credential concept applies) - vctx passed as
     * NULL skips the phase-2 credential gate entirely, unchanged from
     * before that gate existed. */
    rc = brix_http_serve_offload_remote(r, sd, key, path, &sopts,
                                          &lcf->common, NULL, NULL);
    if (rc == NGX_DONE) {
        return NGX_DONE;
    }
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* remote miss → the fill would hit the origin; charge the requester's
     * QoS class first (phase-85 F9). Local hits never reach this gate. */
    if (lcf->qos != NULL && brix_sd_cache_fill_needs_offload(sd, key)) {
        rc = brix_cvmfs_qos_check(r, lcf);
        if (rc != NGX_DECLINED) {
            return rc;                       /* 429 - fill budget exhausted */
        }
    }

    /* miss → one coalesced off-loop fill, re-entering this handler on land */
    rc = brix_http_cache_fill_if_needed(r, sd, key, &lcf->common,
                                          cvmfs_reenter, NULL);
    if (rc == NGX_DONE) {
        if (ctx != NULL) {
            ctx->cache_status = BRIX_CVMFS_CACHE_FILL;   /* $cvmfs_cache */
        }
        return NGX_DONE;
    }
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_DECLINED;
}

/* WHAT: open the now-local object, run stat + conditional checks, and serve it
 *       through the shared ranged-file pipeline.
 * WHY:  this is the HIT tail of a tier read (bytes are on disk, whether they
 *       were always there or a fill just landed). Marking HIT here — only when
 *       the disposition is still NONE — preserves a FILL disposition set by a
 *       just-completed fill on the re-entry pass.
 * HOW:  early-return on every open/stat/conditional failure with the mapped
 *       status; closes the handle on each exit that doesn't hand it to the
 *       serve pipeline. */
static ngx_int_t
cvmfs_tier_open_respond(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    brix_vfs_ctx_t *vctx, const char *path)
{
    brix_vfs_file_t *fh;
    brix_vfs_stat_t  vst;
    int               vfs_err = 0;
    ngx_int_t         rc;

    fh = brix_vfs_open(vctx, BRIX_VFS_O_READ, &vfs_err);
    if (fh == NULL) {
        return (ngx_int_t) cvmfs_errno_status(vfs_err);
    }
    if (ctx != NULL && ctx->cache_status == BRIX_CVMFS_CACHE_NONE) {
        ctx->cache_status = BRIX_CVMFS_CACHE_HIT;        /* $cvmfs_cache */
    }
    if (brix_vfs_file_stat(fh, &vst) != NGX_OK) {
        brix_vfs_close(fh, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (vst.is_directory) {
        brix_vfs_close(fh, r->connection->log);
        return NGX_HTTP_FORBIDDEN;
    }

    rc = brix_http_check_if_modified_since(r, vst.mtime);
    if (rc == NGX_HTTP_NOT_MODIFIED) {
        brix_vfs_close(fh, r->connection->log);
        r->headers_out.status           = NGX_HTTP_NOT_MODIFIED;
        r->headers_out.content_length_n = 0;
        /* RFC 9110 §15.4.5: a 304 must carry the same validators the 200 would
         * (the serve pipeline's weak ETag + Last-Modified from vst), else a
         * cache cannot update its stored representation's metadata. Mirror the
         * BRIX_ETAG_WEAK path brix_http_set_file_headers takes on the 200. */
        r->headers_out.last_modified_time = vst.mtime;
        (void) brix_http_add_etag_header(r, vst.mtime, vst.size,
                                          BRIX_ETAG_WEAK, 1);
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }
    if (rc != NGX_OK) {
        brix_vfs_close(fh, r->connection->log);
        return rc;
    }

    r->allow_ranges = 1;

    {
        brix_http_serve_opts_t   opts;
        brix_http_serve_result_t result;

        cvmfs_serve_opts_init(&opts, lcf->common.compress);
        rc = brix_http_serve_file_ranged(r, fh, &vst, path, &opts, &result);
    }
    return rc;
}

/* Serve a classified CAS GET/HEAD from the tier: offload a socket-wire
 * serve, coalesce a miss into one off-loop fill, then open + respond via
 * the shared ranged-file pipeline. */
static ngx_int_t
cvmfs_tier_get(ngx_http_request_t *r, ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    char                path[PATH_MAX];
    const char         *root, *key;
    brix_vfs_ctx_t    vctx;
    int                 is_tls = 0;
    ngx_int_t           rc;

    root = (ctx != NULL && ctx->up_root != NULL) ? ctx->up_root
                                                 : lcf->common.root_canon;

    /* fs path = export root + uri */
    rc = cvmfs_build_fs_path(r, root, path, sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log,
        BRIX_PROTO_CVMFS, root, "", /* allow_write */ 0, is_tls, NULL,
        path);
    vctx.sd = cvmfs_resolve_sd(r, lcf);
    if (vctx.sd == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "cvmfs: no storage backend registered for \"%s\" - check "
            "brix_storage_backend", root);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    key = brix_vfs_export_relative(&vctx, path);

    /* Dashboard live-transfer record from TIER ENTRY, not serve time: the
     * record then spans a cold fill's whole origin wait, so in-flight cvmfs
     * fills are visible in the transfer table (the serve pipeline's own
     * start is idempotent and rebinds this same slot; rejects never got
     * here, so they never occupy one). Auto-freed with the request pool.
     * `key` is the client-visible /cvmfs/... path — the synthetic proxy-mode
     * registry root must not leak into the operator display. */
    (void) brix_dashboard_http_start_identity(r, key, "anonymous", "",
        BRIX_XFER_PROTO_CVMFS, BRIX_XFER_DIR_READ, "GET", -1);

    rc = cvmfs_tier_serve_or_fill(r, lcf, vctx.sd, key, path);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    return cvmfs_tier_open_respond(r, lcf, ctx, &vctx, path);
}

/* WHAT: close out the session-log record for this request — result line plus,
 *       for a GET whose transfer started, the byte tally + terminal disposition.
 * WHY:  a success (<400) logs no error; a failure maps the HTTP status to a
 *       sesslog error string. The xfer end classifies COMPLETE vs ABORTED off
 *       the same threshold. Only runs when an attempt was actually logged.
 * HOW:  side-effecting edge helper; guards on sess_attempt_logged and clears
 *       sess_xfer_started so re-entry can't double-count. */
static void
cvmfs_finalize_sesslog(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    ngx_uint_t status)
{
    brix_sess_t *sess;
    char         path[BRIX_SESSLOG_PATH_MAX];
    char         errscratch[BRIX_SESSLOG_ERR_MAX];

    if (lcf == NULL || ctx == NULL || !ctx->sess_attempt_logged) {
        return;
    }

    sess = brix_http_sess(r, &lcf->common, BRIX_SESS_PROTO_CVMFS,
                          BRIX_SESS_AM_ANON);
    brix_sess_result(sess, status < NGX_HTTP_BAD_REQUEST,
                     brix_http_sess_uri(r, path, sizeof(path)),
                     BRIX_SESS_MODE_READ,
                     status < NGX_HTTP_BAD_REQUEST ? NULL
                         : brix_sesslog_err_from_http((int) status,
                                                       errscratch,
                                                       sizeof(errscratch)));
    if (ctx->sess_xfer_started) {
        if (r->headers_out.content_length_n > 0) {
            brix_sess_xfer_add(&ctx->sess_xfer,
                (uint64_t) r->headers_out.content_length_n);
        }
        brix_sess_xfer_end(sess, &ctx->sess_xfer,
            status < NGX_HTTP_BAD_REQUEST ? BRIX_SESS_XFER_COMPLETE
                                           : BRIX_SESS_XFER_ABORTED);
        ctx->sess_xfer_started = 0;
    }
}

/* WHAT: emit the optional one-line client-op trace naming traffic class,
 *       repository, path and final cache disposition + status.
 * WHY:  DEBUG normally (visible under error_log … debug), promoted to INFO by
 *       brix_cvmfs_trace. Correlates with the upstream-request line by path.
 * HOW:  bounds the class/cache indices, sanitizes the non-NUL-terminated uri
 *       span into a stack buffer, and skips the whole build below the level. */
static void
cvmfs_finalize_trace(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    ngx_uint_t status)
{
    static const char *cls_names[] = { "cas", "manifest", "geo", "reject" };
    static const char *cache_names[] = { "-", "hit", "fill", "neg" };
    ngx_uint_t         level;
    char               safe[1024];
    char               raw[1024];
    size_t             n;

    if (ctx == NULL || lcf == NULL) {
        return;
    }

    level = lcf->cvmfs.trace ? NGX_LOG_INFO : NGX_LOG_DEBUG;
    if (r->connection->log->log_level < level) {
        return;
    }

    /* r->uri.data is NOT NUL-terminated (points into the request
     * buffer); copy the exact uri span before sanitizing. */
    n = ngx_min(r->uri.len, sizeof(raw) - 1);
    ngx_memcpy(raw, r->uri.data, n);
    raw[n] = '\0';
    brix_sanitize_log_string(raw, safe, sizeof(safe));
    ngx_log_error(level, r->connection->log, 0,
        "cvmfs-trace: client id=%uA class=%s repo=%*s path=%s "
        "cache=%s status=%ui",
        r->connection->number,
        cls_names[ctx->url.cls <= CVMFS_URL_REJECT ? ctx->url.cls : 3],
        ctx->url.repo != NULL ? ctx->url.repo_len : (size_t) 0,
        ctx->url.repo != NULL ? ctx->url.repo : "",
        safe,
        cache_names[ctx->cache_status <= BRIX_CVMFS_CACHE_NEG
                    ? ctx->cache_status : 0],
        status);
}

/* WHAT: record the fill-side T16 metrics for a request that missed the cache
 *       and drove an off-loop fill — success counts + bytes, or a fill failure.
 * WHY:  a 200/206 means the fill landed and served; a 502 is a definitive fill
 *       failure. A 504 hold-expiry is NOT counted as a failure — the detached
 *       fill may still publish for the client's retry.
 * HOW:  bumps global + per-repo counters; byte adds use content_length_n which
 *       the serve pipeline set before headers went out. */
static void
cvmfs_finalize_metrics_fill(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_ctx_t *ctx, ngx_uint_t status)
{
    if (status == NGX_HTTP_OK || status == NGX_HTTP_PARTIAL_CONTENT) {
        BRIX_CVMFS_METRIC_INC(fills_total);
        if (r->headers_out.content_length_n > 0) {
            BRIX_CVMFS_METRIC_ADD(bytes_served_fill_total,
                (ngx_atomic_uint_t) r->headers_out.content_length_n);
        }
        brix_metric_cache_result(BRIX_PROTO_CVMFS, 0, 0);
        if (ctx->repo != NULL) {
            BRIX_ATOMIC_INC(&ctx->repo->fills_total);
            BRIX_ATOMIC_INC(&ctx->repo->cache_misses_total);
            if (ctx->url.cls == CVMFS_URL_CAS) {
                BRIX_ATOMIC_INC(&ctx->repo->files_accessed_total);
            }
            if (r->headers_out.content_length_n > 0) {
                BRIX_ATOMIC_ADD(&ctx->repo->bytes_served_fill_total,
                    (ngx_atomic_uint_t) r->headers_out.content_length_n);
            }
        }
    } else if (status == NGX_HTTP_BAD_GATEWAY) {
        BRIX_CVMFS_METRIC_INC(fill_failures_total);
        if (ctx->repo != NULL) {
            BRIX_ATOMIC_INC(&ctx->repo->fill_failures_total);
        }
    }
    /* a 504 hold-expiry is NOT a definitive fill failure — the
     * detached fill may still publish for the client's retry */
}

/* WHAT: record the hit-side T16 metrics for a request served from a warm cache
 *       (bytes + hit counters) on a 200/206.
 * WHY:  a cache HIT that actually delivered bytes is the success case; other
 *       statuses (e.g. a conditional 304) add nothing.
 * HOW:  bumps global + per-repo hit counters and byte tallies off
 *       content_length_n. */
static void
cvmfs_finalize_metrics_hit(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_ctx_t *ctx)
{
    if (r->headers_out.content_length_n > 0) {
        BRIX_CVMFS_METRIC_ADD(bytes_served_hit_total,
            (ngx_atomic_uint_t) r->headers_out.content_length_n);
    }
    brix_metric_cache_result(BRIX_PROTO_CVMFS, 1, 0);
    if (ctx->repo != NULL) {
        BRIX_ATOMIC_INC(&ctx->repo->cache_hits_total);
        if (ctx->url.cls == CVMFS_URL_CAS) {
            BRIX_ATOMIC_INC(&ctx->repo->files_accessed_total);
        }
        if (r->headers_out.content_length_n > 0) {
            BRIX_ATOMIC_ADD(&ctx->repo->bytes_served_hit_total,
                (ngx_atomic_uint_t) r->headers_out.content_length_n);
        }
    }
}

/* WHAT: dispatch the T16 fill/byte accounting off the FINAL cache disposition.
 * WHY:  the two dispositions (FILL, HIT) have distinct counter families; a
 *       single decision point keeps the accounting off the terminal status.
 * HOW:  routes to the fill- or hit-side helper; NONE/NEG account nothing. */
static void
cvmfs_finalize_metrics(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_ctx_t *ctx, ngx_uint_t status)
{
    if (ctx->cache_status == BRIX_CVMFS_CACHE_FILL) {
        cvmfs_finalize_metrics_fill(r, ctx, status);
    } else if (ctx->cache_status == BRIX_CVMFS_CACHE_HIT
               && (status == NGX_HTTP_OK
                   || status == NGX_HTTP_PARTIAL_CONTENT))
    {
        cvmfs_finalize_metrics_hit(r, ctx);
    }
}

/* Request-finalization observer: fires once when the request pool is torn
 * down, with the FINAL response status — the one place every serve path
 * (inline open, off-loop fill, passthrough) converges, so the negative
 * memo (T13) sees every 404 regardless of which path produced it. */
static void
cvmfs_finalize_observe(void *data)
{
    ngx_http_request_t               *r = data;
    ngx_http_brix_cvmfs_loc_conf_t *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_cvmfs_module);
    ngx_http_brix_cvmfs_ctx_t      *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    ngx_uint_t                        status =
        brix_http_effective_status(r, NGX_OK);

    cvmfs_finalize_sesslog(r, lcf, ctx, status);

    if (lcf != NULL) {
        brix_cvmfs_notify_status(r, lcf, status);
    }

    cvmfs_finalize_trace(r, lcf, ctx, status);

    if (ctx == NULL) {
        return;
    }
    cvmfs_finalize_metrics(r, ctx, status);
}

ngx_int_t
ngx_http_brix_cvmfs_handler(ngx_http_request_t *r)
{
    ngx_http_brix_cvmfs_loc_conf_t *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_cvmfs_module);
    ngx_http_brix_cvmfs_ctx_t      *ctx;
    ngx_int_t                         rc;

    /* Re-entry after an off-loop fill runs the handler again on the same
     * request — the existing ctx marks the observer as already registered. */
    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    if (ctx == NULL) {
        ngx_pool_cleanup_t *cln;

        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_brix_cvmfs_module);

        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        cln->handler = cvmfs_finalize_observe;
        cln->data    = r;
    }

    if (!ctx->sess_attempt_logged) {
        brix_sess_t *sess;
        char         path[BRIX_SESSLOG_PATH_MAX];

        sess = brix_http_sess(r, &lcf->common, BRIX_SESS_PROTO_CVMFS,
                              BRIX_SESS_AM_ANON);
        brix_sess_auth_once(sess, BRIX_SESS_AM_ANON, "-", "-");
        brix_sess_attempt(sess, brix_http_sess_uri(r, path, sizeof(path)),
                          BRIX_SESS_MODE_READ);
        ctx->sess_attempt_logged = 1;
        if (r->method == NGX_HTTP_GET) {
            brix_sess_xfer_start(sess, &ctx->sess_xfer,
                brix_http_sess_uri(r, path, sizeof(path)),
                BRIX_SESS_MODE_READ, -1);
            ctx->sess_xfer_started = ctx->sess_xfer.active ? 1 : 0;
        }
    }

    rc = ngx_http_discard_request_body(r);          /* GET/HEAD only proto */
    if (rc != NGX_OK) {
        return rc;
    }

    if (lcf->scvmfs) {
        rc = brix_scvmfs_preamble(r, lcf);        /* T22: TLS + authz    */
        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

    rc = brix_cvmfs_gate(r, lcf);                 /* classify + police  */
    if (rc != NGX_DECLINED) {
        return rc;               /* reject status, passthrough NGX_DONE … */
    }
    return cvmfs_tier_get(r, lcf);
}
