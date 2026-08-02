/* gate.c — CVMFS protocol dispatch gate.
 *
 * WHAT: first step of the dedicated cvmfs:// content handler: restricts
 *       methods to GET/HEAD, classifies the URI, rejects non-CVMFS shapes,
 *       routes the geo API to the uncached passthrough (or answers it
 *       locally), and lets CAS objects and TTL-stamped signed metadata (T12)
 *       fall through (NGX_DECLINED) to the cache-tier serve path.
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
#include "net/guard/guard.h"
#include "core/fnv.h"

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
    uint64_t h = BRIX_FNV1A64_OFFSET_BASIS;
    size_t   i;

    for (i = 0; i < uri->len; i++) {
        h = (h ^ uri->data[i]) * BRIX_FNV1A64_PRIME;
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
brix_cvmfs_notify_status(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_uint_t status)
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
    char   safe_uri[512];
    char   raw[512];
    size_t n;

    /* r->uri.data is NOT NUL-terminated (points into the request buffer);
     * copy the exact uri span before sanitizing, or the sanitizer over-reads
     * past uri.len (info-leak / log-injection). */
    n = ngx_min(r->uri.len, sizeof(raw) - 1);
    ngx_memcpy(raw, r->uri.data, n);
    raw[n] = '\0';
    brix_sanitize_log_string(raw, safe_uri, sizeof(safe_uri));
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
        "cvmfs-reject: method=%V uri=\"%s\" client=%V class=reject "
        "cause=\"%s\" "
        "fix=\"only /cvmfs/<repo>/{data/…,.cvmfspublished,.cvmfswhitelist,"
        ".cvmfsreflog,api/v1.0/geo/…} are served\"",
        &r->method_name, safe_uri, &r->connection->addr_text, cause);

    BRIX_CVMFS_METRIC_INC(requests_total[BRIX_CVMFS_CLASS_REJECT]);
    return (ngx_int_t) status;
}

/* Emit one unified guard-core audit line (the fail2ban contract, proto=cvmfs)
 * for this request.  `raw` is the wire-supplied span to ride the path field
 * (sanitized here); it rides alongside, not instead of, the human-readable
 * cvmfs-reject WARN. */
static void
cvmfs_guard_emit(ngx_http_request_t *r, guard_reason_t reason,
    ngx_uint_t status, const char *raw, size_t rawlen, int cred_present)
{
    guard_request_t req;
    char            ipbuf[64];
    char            rawbuf[256];
    char            san[256];
    char            line[512];
    char            ts[sizeof("YYYY-MM-DDThh:mm:ss+00:00")];
    size_t          n, ts_len;

    n = ngx_min(r->connection->addr_text.len, sizeof(ipbuf) - 1);
    ngx_memcpy(ipbuf, r->connection->addr_text.data, n);
    ipbuf[n] = '\0';

    n = ngx_min(rawlen, sizeof(rawbuf) - 1);
    ngx_memcpy(rawbuf, raw, n);
    rawbuf[n] = '\0';

    req.ip           = ipbuf;
    req.proto        = "cvmfs";
    req.op           = GUARD_OP_READ;
    req.path         = san;
    req.path_len     = brix_sanitize_log_string(rawbuf, san, sizeof(san));
    req.cred_present = cred_present;
    req.outcome      = OUTCOME_PENDING;
    req.status_code  = (int) status;

    ts_len = ngx_cached_http_log_iso8601.len;
    if (ts_len >= sizeof(ts)) {
        ts_len = sizeof(ts) - 1;
    }
    ngx_memcpy(ts, ngx_cached_http_log_iso8601.data, ts_len);
    ts[ts_len] = '\0';

    if (guard_audit_format(&req, reason, ts, line, sizeof(line)) > 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "%s", line);
    }
}

/* signal=proxyabuse — a forward-proxy request tried to reach a non-allowlisted
 * / wrong-scheme / malformed remote (the open-proxy / SSRF signal), banned by
 * the [xrootd-guard-proxyabuse] jail.  The attempted upstream authority
 * (host[:port], straight off the parsed absolute-form request line) rides the
 * path field so the operator sees which arbitrary remote resource the actor
 * was reaching for. */
static void
cvmfs_guard_proxyabuse(ngx_http_request_t *r, ngx_uint_t status)
{
    char            raw_auth[256];
    const u_char   *auth_end;
    size_t          alen;

    /* host_start..host_end is the host; a ':' at host_end extends the span to
     * uri_start to fold in the ":port".  Absent host_start can't happen here
     * (this only runs on an absolute-form target), but guard it anyway. */
    alen = 0;
    if (r->host_start != NULL && r->host_end != NULL
        && r->host_end > r->host_start)
    {
        auth_end = r->host_end;
        if (r->uri_start != NULL && r->uri_start > r->host_end
            && *r->host_end == ':')
        {
            auth_end = r->uri_start;
        }
        alen = ngx_min((size_t) (auth_end - r->host_start),
                       sizeof(raw_auth) - 1);
        ngx_memcpy(raw_auth, r->host_start, alen);
    }

    cvmfs_guard_emit(r, GUARD_R_PROXYABUSE, status, raw_auth, alen, 0);
}

/* Proxy mode (T14): an absolute-form request line names its upstream — allowlist
 * it, then (non-unified origin) bind that upstream's per-worker backend on the
 * request ctx.  NGX_DECLINED to proceed; otherwise the response rc (reject/status). */
static ngx_int_t
cvmfs_gate_proxy_bind(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx)
{
    ngx_str_t   up_host;
    in_port_t   up_port;
    ngx_int_t   rc;

    rc = brix_cvmfs_proxy_target(r, &lcf->cvmfs, &up_host, &up_port);
    if (rc == NGX_HTTP_FORBIDDEN) {
        cvmfs_guard_proxyabuse(r, NGX_HTTP_FORBIDDEN);
        return cvmfs_reject(r, NGX_HTTP_FORBIDDEN,
                            "upstream authority not allowlisted");
    }
    if (rc == NGX_HTTP_BAD_REQUEST) {
        cvmfs_guard_proxyabuse(r, NGX_HTTP_BAD_REQUEST);
        return cvmfs_reject(r, NGX_HTTP_BAD_REQUEST, "malformed proxy target");
    }
    if (rc == NGX_OK && !lcf->cvmfs.unified_origin) {
        ngx_uint_t status = NGX_HTTP_INTERNAL_SERVER_ERROR;

        ctx->sd_override = brix_cvmfs_upstream_get(r, lcf, &up_host, up_port,
                                                     &ctx->up_root, &status);
        if (ctx->sd_override == NULL) {
            return (ngx_int_t) status;
        }
    }
    /* rc == NGX_OK && unified_origin: authority allowlisted (above) but no
     * per-host backend bound — leaving sd_override/up_root NULL routes to the
     * location's ONE multi-endpoint origin backend (ranked failover + shared
     * cache), so a dead origin is hidden by internal failover and the client
     * never marks this proxy bad.  rc == NGX_DECLINED: origin-form — proceed. */
    return NGX_DECLINED;
}

/* CVMFS_URL_CAS accounting + T13 negative-404 absorption.  NGX_DECLINED for the
 * tier serve path; NGX_HTTP_NOT_FOUND when an absorbed-404 storm is short-circuited. */
static ngx_int_t
cvmfs_gate_cas(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx)
{
    BRIX_CVMFS_METRIC_INC(requests_total[BRIX_CVMFS_CLASS_CAS]);
    if (ctx->repo != NULL) {
        BRIX_ATOMIC_INC(&ctx->repo->requests_total[BRIX_CVMFS_CLASS_CAS]);
    }

    if (lcf->cvmfs.negative_ttl > 0 && cvmfs_neg_check(&r->uri, ngx_time())) {
        char   neg_uri[512];
        char   raw[512];
        size_t n;

        BRIX_CVMFS_METRIC_INC(negative_hits_total);
        if (ctx->repo != NULL) {
            BRIX_ATOMIC_INC(&ctx->repo->negative_hits_total);
        }
        ctx->cache_status = BRIX_CVMFS_CACHE_NEG;
        /* One NOTICE per absorbed 404: a client hammering missing objects shows
         * as a stream of these (bounded by its own request rate). r->uri.data is
         * NOT NUL-terminated — copy the exact span before sanitizing. */
        n = ngx_min(r->uri.len, sizeof(raw) - 1);
        ngx_memcpy(raw, r->uri.data, n);
        raw[n] = '\0';
        brix_sanitize_log_string(raw, neg_uri, sizeof(neg_uri));
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "cvmfs-neg: event=absorbed-404 client=%V uri=\"%s\" "
            "hint=\"repeated lines from one client = it is retrying a "
            "missing object instead of backing off\"",
            &r->connection->addr_text, neg_uri);
        return NGX_HTTP_NOT_FOUND;    /* absorbed 404 storm (T13) */
    }
    return NGX_DECLINED;             /* tier serve path (handler.c) */
}

/* Pre-classification metadata-plane endpoints.
 *
 * Phase-87 G12: the swarm roster endpoint is membership-plane metadata, not
 * CVMFS traffic — intercept BEFORE classification (classify would 403 it as
 * "not a CVMFS traffic shape").  Phase-87 G15: the attestation record
 * endpoint is likewise metadata-plane (".cvmfs-attest" is not a CVMFS
 * traffic shape); a non-endpoint request has its X-Brix-Attest session
 * label captured here.  NGX_DECLINED = proceed with normal gating. */
static ngx_int_t
cvmfs_gate_meta(ngx_http_request_t *r, ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    if (lcf->cvmfs.swarm == 1) {
        ngx_int_t src = brix_cvmfs_swarm_roster_serve(r, lcf);
        if (src != NGX_DECLINED) {
            return src;
        }
    }

    if (lcf->attest_pkey != NULL) {
        ngx_int_t arc = brix_cvmfs_attest_gate(r, lcf);
        if (arc != NGX_DECLINED) {
            return arc;
        }
    }

    return NGX_DECLINED;
}

/* GET/HEAD only, with the ONE non-GET carve-out: the phase-87 G2 batch
 * fetch is a POST (it carries a want-list body). Gated on the flag so an
 * off location keeps the exact pre-phase-87 405 behavior. */
static ngx_int_t
cvmfs_gate_method(ngx_http_request_t *r, ngx_http_brix_cvmfs_loc_conf_t *lcf,
    ngx_http_brix_cvmfs_ctx_t *ctx)
{
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        if (!(lcf->cvmfs.bundle
              && r->method == NGX_HTTP_POST
              && ctx->url.cls == CVMFS_URL_BUNDLE))
        {
            return cvmfs_reject(r, NGX_HTTP_NOT_ALLOWED, "method not allowed");
        }
    }
    return NGX_DECLINED;
}

/* Token-gated repos (phase-85 F3) — evaluated BEFORE class routing so a
 * gated repo's CAS, metadata, and geo traffic are all behind the gate.
 * NGX_DECLINED = pass (also when no authz is configured). */
static ngx_int_t
cvmfs_gate_authz(ngx_http_request_t *r, ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_int_t arc;

    if (lcf->repo_authz == NULL) {
        return NGX_DECLINED;
    }

    arc = brix_cvmfs_repo_authz_eval(r, lcf);
    if (arc == NGX_HTTP_UNAUTHORIZED) {
        /* the guard-core authfail signal ([xrootd-guard-authfail] jail):
         * unauthenticated probing of a private repo is the same actor
         * shape as a credential brute-force elsewhere. */
        cvmfs_guard_emit(r, GUARD_R_AUTHFAIL, NGX_HTTP_UNAUTHORIZED,
                         (const char *) r->uri.data, r->uri.len,
                         r->headers_in.authorization != NULL);
        return cvmfs_reject(r, NGX_HTTP_UNAUTHORIZED,
                            "repo requires a valid read-scope bearer token");
    }
    if (arc == NGX_HTTP_BAD_REQUEST) {
        return cvmfs_reject(r, NGX_HTTP_BAD_REQUEST,
                            "token-gated repo requires TLS");
    }
    return arc;                             /* 414/500 plumbing failures */
}

/* Per-class accounting (global counter + bounded per-repo slot). */
static void
cvmfs_gate_count(ngx_http_brix_cvmfs_ctx_t *ctx, ngx_uint_t cls)
{
    BRIX_CVMFS_METRIC_INC(requests_total[cls]);
    if (ctx->repo != NULL) {
        BRIX_ATOMIC_INC(&ctx->repo->requests_total[cls]);
    }
}

/* Class routing — the accounted per-class dispatch tail of the gate. */
static ngx_int_t
cvmfs_gate_route(ngx_http_request_t *r, ngx_http_brix_cvmfs_loc_conf_t *lcf,
    ngx_http_brix_cvmfs_ctx_t *ctx)
{
    switch (ctx->url.cls) {
    case CVMFS_URL_CAS:
        return cvmfs_gate_cas(r, lcf, ctx);
    case CVMFS_URL_MANIFEST:
        cvmfs_gate_count(ctx, BRIX_CVMFS_CLASS_MANIFEST);
        /* T12: signed metadata caches WITH a TTL — the fill stamps
         * expires_at (= now + brix_cvmfs_manifest_ttl) in the cinfo, an
         * expired entry refills, and a failed refill serves the stale copy
         * within the bounded 10x-TTL stale-if-error window. */
        return NGX_DECLINED;
    case CVMFS_URL_GEO:
        cvmfs_gate_count(ctx, BRIX_CVMFS_CLASS_GEO);
        /* Answer locally (RTT-ranked from this proxy's vantage) when enabled,
         * bypassing a mis-ordering upstream GeoAPI; else relay verbatim. */
        if (lcf->cvmfs.geo_answer == BRIX_CVMFS_GEO_RTT) {
            return brix_cvmfs_geo_answer(r, lcf);
        }
        return brix_cvmfs_geo_passthrough(r, lcf);
    case CVMFS_URL_BUNDLE:
        cvmfs_gate_count(ctx, BRIX_CVMFS_CLASS_BUNDLE);
        /* Batch fetch (phase-87 G2) is strictly opt-in and POST-only; a
         * GET/HEAD on the endpoint name is not CVMFS client traffic. */
        if (!lcf->cvmfs.bundle) {
            return cvmfs_reject(r, NGX_HTTP_FORBIDDEN,
                                "bundle endpoint disabled "
                                "(brix_cvmfs_bundle off)");
        }
        if (r->method != NGX_HTTP_POST) {
            return cvmfs_reject(r, NGX_HTTP_NOT_ALLOWED,
                                "bundle endpoint is POST-only");
        }
        return brix_cvmfs_bundle_handle(r, lcf);
    case CVMFS_URL_DICT:
        cvmfs_gate_count(ctx, BRIX_CVMFS_CLASS_DICT);
        /* Shared-dictionary endpoint (phase-87 G3) is strictly opt-in; off
         * keeps the exact pre-phase-87 reject (403) for this path shape.
         * GET/HEAD-only is already enforced by the early method check. */
        if (!lcf->cvmfs.dict) {
            return cvmfs_reject(r, NGX_HTTP_FORBIDDEN,
                                "dict endpoint disabled "
                                "(brix_cvmfs_dict off)");
        }
        return brix_cvmfs_dict_handle(r, lcf);
    case CVMFS_URL_REJECT:
    default:
        return cvmfs_reject(r, NGX_HTTP_FORBIDDEN,
                            "path is not a CVMFS traffic shape");
    }
}

ngx_int_t
brix_cvmfs_gate(ngx_http_request_t *r, ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_int_t rc;
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);

    rc = cvmfs_gate_meta(r, lcf);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Classify FIRST (a pure parse of the query-stripped path): every later
     * reject — wrong method, malformed proxy target, authority not
     * allowlisted — then carries the request's TRUE class in $cvmfs_class.
     * (The allowlist 403 used to precede classification, so every rejected
     * geo/manifest request was logged class=cas — the zero value.) */
    if (cvmfs_classify_url((const char *) r->uri.data, r->uri.len, &ctx->url)
        != 0)
    {
        return cvmfs_reject(r, NGX_HTTP_FORBIDDEN,
                            "path is not a CVMFS traffic shape");
    }

    /* Virtual / composed repos (phase-87 G16): a request naming a virtual
     * fqrn is rewritten in place to its first member (declaration-order
     * precedence; the handler advances to the next member on 404 only).
     * Rewriting HERE — before per-repo accounting, F3 repo authz, and class
     * routing — means each member attempt is policed exactly as a direct
     * request for that member would be: composition never elevates. */
    if (lcf->virtual_repos != NULL) {
        ngx_int_t vrc = brix_cvmfs_virtual_enter(r, lcf);
        if (vrc != NGX_DECLINED) {
            return vrc;
        }
    }

    rc = cvmfs_gate_method(r, lcf, ctx);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* proxy mode (T14): an absolute-form request line names its upstream —
     * allowlist it, then serve against that upstream's per-worker backend
     * (convention #2: the override rides the request ctx). */
    if (r->host_start != NULL) {
        ngx_int_t prc = cvmfs_gate_proxy_bind(r, lcf, ctx);
        if (prc != NGX_DECLINED) {
            return prc;
        }
    }

    /* per-repository accounting (bounded slot table — metrics.h) */
    ctx->repo = brix_cvmfs_repo_slot(ctx->url.repo, ctx->url.repo_len);

    rc = cvmfs_gate_authz(r, lcf);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    return cvmfs_gate_route(r, lcf, ctx);
}
