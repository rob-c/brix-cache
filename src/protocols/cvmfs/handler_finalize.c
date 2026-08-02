/* handler_finalize.c — the cvmfs:// request-finalization observer.
 *
 * WHAT: the pool-cleanup observer handler.c registers on every request, plus
 *       its edge helpers: session-log close-out, the optional one-line client
 *       trace, and the T16 fill/hit metric accounting — all keyed off the
 *       FINAL response status.
 * WHY:  handler.c grew past the file-size gate; the finalize family is a
 *       self-contained tail (nothing here touches the serve path) so it moved
 *       here whole. The observer stays the one place every serve path (inline
 *       open, off-loop fill, passthrough) converges — the negative memo (T13)
 *       and the G15 attest observer see every terminal status regardless of
 *       which path produced it.
 * HOW:  cvmfs_finalize_observe is the only cross-file symbol (declared in
 *       cvmfs_module_internal.h; handler.c wires it into the pool cleanup);
 *       everything else is static.
 */
#include "cvmfs.h"
#include "cvmfs_module_internal.h"
#include "fs/path/path.h"                  /* brix_sanitize_log_string */
#include "core/http/http_headers.h"        /* brix_http_effective_status */
#include "core/http/sesslog_conn.h"
#include "observability/metrics/unified.h"

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
    static const char *cls_names[] = { "cas", "manifest", "geo", "bundle",
                                        "dict", "reject" };
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
        cls_names[ctx->url.cls <= CVMFS_URL_REJECT ? ctx->url.cls
                                                   : CVMFS_URL_REJECT],
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
 * memo (T13) sees every 404 regardless of which path produced it.
 * Non-static: handler.c registers it as the request's pool cleanup. */
void
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

    if (lcf != NULL) {
        brix_cvmfs_attest_observe(r, lcf, ctx, status);   /* G15 */
    }
}
