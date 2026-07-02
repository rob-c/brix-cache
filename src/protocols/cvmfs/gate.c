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

/* --- negative cache (T13) --------------------------------------------------
 * Per-worker fixed-size direct-mapped memo of recent 404s (the deliberate
 * worker-local exception to the no-globals rule: each worker absorbing its
 * own 404 storm is sufficient and avoids SHM). A slot collision simply
 * overwrites (false eviction = one extra origin round-trip); false HITS are
 * impossible short of a full 64-bit hash collision, and even that only
 * mis-404s one object for negative_ttl seconds — acceptable for a cache
 * whose entries are retried by design.
 */
#define CVMFS_NEG_SLOTS 512u            /* power of two: mask, don't mod   */

typedef struct {
    uint64_t path_hash;                 /* FNV-1a of the full URI, 0=empty */
    time_t   until;
} cvmfs_neg_slot;

static cvmfs_neg_slot  cvmfs_neg[CVMFS_NEG_SLOTS];

static uint64_t
cvmfs_neg_hash(const ngx_str_t *uri)
{
    uint64_t h = 0xcbf29ce484222325ull;
    size_t   i;

    for (i = 0; i < uri->len; i++) {
        h = (h ^ uri->data[i]) * 0x100000001b3ull;
    }
    return (h != 0) ? h : 1;            /* 0 is the empty-slot marker      */
}

static int
cvmfs_neg_check(const ngx_str_t *uri, time_t now)
{
    uint64_t        h = cvmfs_neg_hash(uri);
    cvmfs_neg_slot *s = &cvmfs_neg[h & (CVMFS_NEG_SLOTS - 1)];

    return (s->path_hash == h && now < s->until);
}

static void
cvmfs_neg_store(const ngx_str_t *uri, time_t now, time_t ttl)
{
    uint64_t        h = cvmfs_neg_hash(uri);
    cvmfs_neg_slot *s = &cvmfs_neg[h & (CVMFS_NEG_SLOTS - 1)];

    s->path_hash = h;
    s->until = now + ttl;
}

/* Called by the handler's finalization observer when a request on a cvmfs
 * location has produced its final status. Records 404s in the memo. */
void
xrootd_cvmfs_notify_status(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf, ngx_uint_t status)
{
    if (status == NGX_HTTP_NOT_FOUND && lcf->cvmfs.negative_ttl > 0) {
        cvmfs_neg_store(&r->uri, ngx_time(), lcf->cvmfs.negative_ttl);
    }
}

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

    XROOTD_CVMFS_METRIC_INC(requests_total[XROOTD_CVMFS_CLASS_REJECT]);
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

    /* proxy mode (T14): an absolute-form request line names its upstream —
     * allowlist it, then serve against that upstream's per-worker backend
     * (convention #2: the override rides the request ctx). */
    if (r->host_start != NULL) {
        ngx_str_t   up_host;
        in_port_t   up_port;
        ngx_int_t   rc;

        rc = xrootd_cvmfs_proxy_target(r, &lcf->cvmfs, &up_host, &up_port);
        if (rc == NGX_HTTP_FORBIDDEN) {
            return cvmfs_reject(r, NGX_HTTP_FORBIDDEN,
                                "upstream authority not allowlisted");
        }
        if (rc == NGX_HTTP_BAD_REQUEST) {
            return cvmfs_reject(r, NGX_HTTP_BAD_REQUEST,
                                "malformed proxy target");
        }
        if (rc == NGX_OK) {
            ngx_uint_t status = NGX_HTTP_INTERNAL_SERVER_ERROR;

            ctx->sd_override = xrootd_cvmfs_upstream_get(r, lcf, &up_host,
                                                         up_port,
                                                         &ctx->up_root,
                                                         &status);
            if (ctx->sd_override == NULL) {
                return (ngx_int_t) status;
            }
        }
        /* rc == NGX_DECLINED: origin-form on this listener — fall through */
    }

    /* classify the unescaped, query-stripped path nginx already produced */
    if (cvmfs_classify_url((const char *) r->uri.data, r->uri.len, &ctx->url)
        != 0)
    {
        return cvmfs_reject(r, NGX_HTTP_FORBIDDEN,
                            "path is not a CVMFS traffic shape");
    }

    /* per-repository accounting (bounded slot table — metrics.h) */
    ctx->repo = xrootd_cvmfs_repo_slot(ctx->url.repo, ctx->url.repo_len);

    switch (ctx->url.cls) {
    case CVMFS_URL_CAS:
        XROOTD_CVMFS_METRIC_INC(requests_total[XROOTD_CVMFS_CLASS_CAS]);
        if (ctx->repo != NULL) {
            XROOTD_ATOMIC_INC(&ctx->repo->requests_total[XROOTD_CVMFS_CLASS_CAS]);
        }
        if (lcf->cvmfs.negative_ttl > 0
            && cvmfs_neg_check(&r->uri, ngx_time()))
        {
            XROOTD_CVMFS_METRIC_INC(negative_hits_total);
            if (ctx->repo != NULL) {
                XROOTD_ATOMIC_INC(&ctx->repo->negative_hits_total);
            }
            ctx->cache_status = XROOTD_CVMFS_CACHE_NEG;
            return NGX_HTTP_NOT_FOUND;    /* absorbed 404 storm (T13)    */
        }
        return NGX_DECLINED;              /* tier serve path (handler.c) */
    case CVMFS_URL_MANIFEST:
        XROOTD_CVMFS_METRIC_INC(requests_total[XROOTD_CVMFS_CLASS_MANIFEST]);
        if (ctx->repo != NULL) {
            XROOTD_ATOMIC_INC(
                &ctx->repo->requests_total[XROOTD_CVMFS_CLASS_MANIFEST]);
        }
        /* T12: signed metadata caches WITH a TTL — the fill stamps
         * expires_at (= now + xrootd_cvmfs_manifest_ttl) in the cinfo, an
         * expired entry refills, and a failed refill serves the stale copy
         * within the bounded 10x-TTL stale-if-error window. */
        return NGX_DECLINED;
    case CVMFS_URL_GEO:
        XROOTD_CVMFS_METRIC_INC(requests_total[XROOTD_CVMFS_CLASS_GEO]);
        if (ctx->repo != NULL) {
            XROOTD_ATOMIC_INC(&ctx->repo->requests_total[XROOTD_CVMFS_CLASS_GEO]);
        }
        return xrootd_cvmfs_geo_passthrough(r, lcf);
    case CVMFS_URL_REJECT:
    default:
        return cvmfs_reject(r, NGX_HTTP_FORBIDDEN,
                            "path is not a CVMFS traffic shape");
    }
}
