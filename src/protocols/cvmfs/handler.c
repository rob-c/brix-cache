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
#include "core/http/http_conditionals.h"
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
    brix_vfs_file_t  *fh;
    brix_vfs_stat_t   vst;
    int                 vfs_err = 0;
    int                 is_tls = 0;
    ngx_int_t           rc;

    root = (ctx != NULL && ctx->up_root != NULL) ? ctx->up_root
                                                 : lcf->common.root_canon;

    /* fs path = export root + uri; a "/" root (the pure-cache-node anchor)
     * contributes nothing so the path IS the uri. */
    if (root[0] == '/' && root[1] == '\0') {
        if (brix_str_cbuf(path, sizeof(path), &r->uri) == NULL) {
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }
    } else {
        size_t rn = ngx_strlen(root);

        if (rn + r->uri.len >= sizeof(path)) {
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }
        ngx_memcpy(path, root, rn);
        ngx_memcpy(path + rn, r->uri.data, r->uri.len);
        path[rn + r->uri.len] = '\0';
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

    /* socket-wire backends can't open/read on the event loop */
    {
        brix_http_serve_opts_t sopts;

        ngx_memzero(&sopts, sizeof(sopts));
        sopts.xfer_proto = BRIX_XFER_PROTO_CVMFS;
        sopts.op_name    = "GET";
        sopts.identity   = "anonymous";
        sopts.etag_flags = BRIX_ETAG_WEAK;

        rc = brix_http_serve_offload_remote(r, vctx.sd, key, path, &sopts,
                                              &lcf->common, NULL);
        if (rc == NGX_DONE) {
            return NGX_DONE;
        }
        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* miss → one coalesced off-loop fill, re-entering this handler on land */
    rc = brix_http_cache_fill_if_needed(r, vctx.sd, key, &lcf->common,
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

    fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, &vfs_err);
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

        ngx_memzero(&opts, sizeof(opts));
        opts.xfer_proto = BRIX_XFER_PROTO_CVMFS;
        opts.op_name    = "GET";
        opts.identity   = "anonymous";
        opts.etag_flags = BRIX_ETAG_WEAK;

        rc = brix_http_serve_file_ranged(r, fh, &vst, path, &opts, &result);
    }
    return rc;
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
    ngx_uint_t                        status = r->headers_out.status;

    if (lcf != NULL) {
        brix_cvmfs_notify_status(r, lcf, status);
    }

    /* Optional client-op trace: one line per classified request naming the
     * traffic class, repository, path and final cache disposition + status.
     * DEBUG normally (visible under error_log … debug), promoted to INFO by
     * brix_cvmfs_trace. Correlates with the upstream-request line by path. */
    if (ctx != NULL && lcf != NULL) {
        static const char *cls_names[] = { "cas", "manifest", "geo", "reject" };
        static const char *cache_names[] = { "-", "hit", "fill", "neg" };
        ngx_uint_t level = lcf->cvmfs.trace ? NGX_LOG_INFO : NGX_LOG_DEBUG;

        if (r->connection->log->log_level >= level) {
            char   safe[1024];
            char   raw[1024];
            size_t n = ngx_min(r->uri.len, sizeof(raw) - 1);

            /* r->uri.data is NOT NUL-terminated (points into the request
             * buffer); copy the exact uri span before sanitizing. */
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
    }

    /* T16: fill/byte accounting off the FINAL disposition + status. The
     * byte counts use the response body length (content_length_n) — the
     * serve pipeline set it before headers went out. */
    if (ctx == NULL) {
        return;
    }
    if (ctx->cache_status == BRIX_CVMFS_CACHE_FILL) {
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
    } else if (ctx->cache_status == BRIX_CVMFS_CACHE_HIT
               && (status == NGX_HTTP_OK
                   || status == NGX_HTTP_PARTIAL_CONTENT))
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
