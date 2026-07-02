/* gate.c — CVMFS protocol dispatch gate.
 *
 * WHAT: first step of the dedicated cvmfs:// content handler: restricts
 *       methods to GET/HEAD, classifies the URI, rejects non-CVMFS shapes,
 *       routes the geo API (and, until T12 lands manifest TTLs, the signed
 *       metadata) to the uncached passthrough, and lets CAS objects fall
 *       through (NGX_DECLINED) to the cache-tier serve path.
 * WHY:  a CVMFS cache must not be an open proxy or a generic HTTP endpoint;
 *       class routing here keeps every downstream layer (tier, admission,
 *       verify) free of CVMFS-specific branching.
 * HOW:  pure classifier (classify.c) + early returns; rejects emit one
 *       stable single-line WARN ("cvmfs-reject:") that the httpguard
 *       log-phase classifier and the fail2ban filter (T17) both key on,
 *       with the URI sanitized before logging.
 */
#include "cvmfs.h"
#include "fs/path/path.h"

/* One stable, single-line, guard-parsable WARN per reject (convention #4).
 * The URI is wire-supplied: sanitize before logging. */
static ngx_int_t
cvmfs_reject(ngx_http_request_t *r, ngx_uint_t status, const char *cause)
{
    char safe_uri[512];

    xrootd_sanitize_log_string((const char *) r->uri.data, safe_uri,
                               sizeof(safe_uri));
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
        "cvmfs-reject: method=%V uri=\"%s\" client=%V class=reject "
        "cause=\"%s\" "
        "fix=\"only /cvmfs/<repo>/{data/…,.cvmfspublished,.cvmfswhitelist,"
        ".cvmfsreflog,api/v1.0/geo/…} are served\"",
        &r->method_name, safe_uri, &r->connection->addr_text, cause);

    XROOTD_CVMFS_METRIC_INC(XROOTD_CVMFS_M_REJECT);
    return (ngx_int_t) status;
}

ngx_int_t
xrootd_cvmfs_gate(ngx_http_request_t *r, ngx_http_xrootd_cvmfs_loc_conf_t *lcf)
{
    ngx_http_xrootd_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_cvmfs_module);

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return cvmfs_reject(r, NGX_HTTP_NOT_ALLOWED, "method not allowed");
    }

    /* classify the unescaped, query-stripped path nginx already produced */
    if (cvmfs_classify_url((const char *) r->uri.data, r->uri.len, &ctx->url)
        != 0)
    {
        return cvmfs_reject(r, NGX_HTTP_FORBIDDEN,
                            "path is not a CVMFS traffic shape");
    }

    switch (ctx->url.cls) {
    case CVMFS_URL_CAS:
        XROOTD_CVMFS_METRIC_INC(XROOTD_CVMFS_M_CAS);
        return NGX_DECLINED;              /* tier serve path (handler.c) */
    case CVMFS_URL_MANIFEST:
        XROOTD_CVMFS_METRIC_INC(XROOTD_CVMFS_M_MANIFEST);
        /* T12: signed metadata caches WITH a TTL — the fill stamps
         * expires_at (= now + xrootd_cvmfs_manifest_ttl) in the cinfo, an
         * expired entry refills, and a failed refill serves the stale copy
         * within the bounded 10x-TTL stale-if-error window. */
        return NGX_DECLINED;
    case CVMFS_URL_GEO:
        XROOTD_CVMFS_METRIC_INC(XROOTD_CVMFS_M_GEO);
        return xrootd_cvmfs_geo_passthrough(r, lcf);
    case CVMFS_URL_REJECT:
    default:
        return cvmfs_reject(r, NGX_HTTP_FORBIDDEN,
                            "path is not a CVMFS traffic shape");
    }
}
