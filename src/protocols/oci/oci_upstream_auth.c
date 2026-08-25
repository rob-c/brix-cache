/*
 * oci_upstream_auth.c — the D1 upstream Bearer token dance.
 *
 * WHAT: mint (and cache) the bearer an upstream registry demands, and attach
 *       the supplier to the http storage instance so a cache fill can complete
 *       its own 401 retry without knowing any of this exists.
 * WHY:  every public registry answers an anonymous pull with a 401 and a
 *       challenge naming a token endpoint; the pull only proceeds after a
 *       second, differently-authenticated request to that endpoint. That is
 *       one extra round-trip per object — unacceptable per BLOB on a cold
 *       image pull, which is why the minted token is cached in SHM keyed by
 *       (upstream, scope) and shared across workers. It is also the single
 *       most dangerous instruction the plane accepts: a `realm=` is the
 *       upstream telling us which host to go hand a credential to. So the
 *       realm is checked against the upstream it claims to speak for before
 *       any credential leaves this process, and the Authorization header is
 *       dropped the moment a redirect crosses a host boundary.
 * HOW:  challenge → cache probe → (allowlisted) token GET → JSON extract →
 *       cache store, all on the fill worker thread over the same blocking
 *       libcurl transport the cache origin uses. The SHM zone is the shared
 *       brix_kv table (invariant #10: spin+yield, no I/O under the lock).
 */

#include "oci.h"
#include "oci_module_internal.h"

#include "core/compat/json_min.h"
#include "fs/backend/cache/sd_cache.h"
#include "fs/backend/http/sd_http.h"
#include "fs/cache/origin/s3_transport.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"
#include "oci/challenge.h"
#include "oci/url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>                       /* strcasecmp */

#define OCI_TOKEN_TIMEOUT_MS   10000
#define OCI_TOKEN_MAX_HOPS     3
/* The spec's default when `expires_in` is absent. */
#define OCI_TOKEN_DEFAULT_S    60

/* ---- the token GET ------------------------------------------------------ */

typedef struct {
    char        host[256];
    int         port;
    int         tls;
    char        path[2048];        /* path + query                       */
    const char *basic;             /* "user:pass" this leg presents, or
                                    * NULL for an anonymous mint         */
    int         send_basic;        /* 0 once a redirect crosses a host   */
} oci_token_leg_t;

/* Percent-encode `s` as a single query-parameter value. ngx_escape_uri does
 * not NUL-terminate and does not bounds-check, so the two-pass form (measure,
 * then write) is the only correct one: a scope is upstream-chosen text and a
 * raw ':' or '&' surviving into the query would let it forge parameters. */
static int
oci_query_escape(const char *s, u_char *out, size_t outsz)
{
    size_t     len = strlen(s);
    uintptr_t  esc;
    u_char    *end;

    esc = ngx_escape_uri(NULL, (u_char *) s, len, NGX_ESCAPE_URI_COMPONENT);
    if (len + 2 * esc >= outsz) {
        return -1;
    }
    end = (u_char *) ngx_escape_uri(out, (u_char *) s, len,
                                    NGX_ESCAPE_URI_COMPONENT);
    *end = '\0';
    return 0;
}

/* Point `leg` at the Location of a redirect. Absolute URLs are re-parsed in
 * full (and drop the Basic credential when the host changes); a relative one
 * keeps the current destination and replaces only the path. */
static int
oci_token_follow(oci_token_leg_t *leg, const char *loc)
{
    brix_oci_url_t  u;
    const char     *query;
    size_t          path_len;

    if (loc[0] == '/') {
        return (snprintf(leg->path, sizeof(leg->path), "%s", loc)
                < (int) sizeof(leg->path)) ? 0 : -1;
    }

    if (brix_oci_url_parse(loc, strlen(loc), &u) != 0) {
        return -1;
    }
    if (strcasecmp(u.host, leg->host) != 0) {
        /* The next leg is a different principal's endpoint, so our Basic
         * credential does not travel with it. */
        leg->send_basic = 0;
    }
    (void) snprintf(leg->host, sizeof(leg->host), "%s", u.host);
    leg->port = u.port;
    leg->tls  = u.tls;

    /* brix_oci_url_parse stops the path at '?'; carry the query across so a
     * token endpoint may redirect while preserving service/scope. */
    query    = strchr(loc, '?');
    path_len = (size_t) snprintf(leg->path, sizeof(leg->path), "%s%s",
                                 u.path[0] ? u.path : "/",
                                 (query != NULL) ? query : "");

    return (path_len < sizeof(leg->path)) ? 0 : -1;
}

/* Build "Authorization: Basic <b64>\r\n" for the token endpoint, or "" when
 * the mint is anonymous. The Basic credential authenticates a principal to
 * the TOKEN service only — it is never sent to the registry data endpoints,
 * and never survives a cross-host redirect. */
static void
oci_token_basic_header(const char *basic, char *out, size_t outsz)
{
    ngx_str_t  src, dst;
    u_char     b64[684];           /* base64 of the 512-byte basic buffer */

    out[0] = '\0';
    if (basic == NULL || basic[0] == '\0') {
        return;
    }
    src.data = (u_char *) basic;
    src.len  = strlen(basic);
    dst.data = b64;
    ngx_encode_base64(&dst, &src);

    (void) snprintf(out, outsz, "Authorization: Basic %.*s\r\n",
                    (int) dst.len, dst.data);
}

/* One leg of the token request. Returns the HTTP status, or -1 on a transport
 * failure. On a 3xx the Location is resolved into *leg for the next hop; a 3xx
 * without a usable Location is a failure, not a hop we could repeat. */
static int
oci_token_leg(const brix_oci_upstream_t *up, oci_token_leg_t *leg,
    char *body, size_t bodysz, size_t *body_len)
{
    const brix_s3_transport_t  *tr = &brix_s3_origin_curl_transport;
    brix_s3_resp_t              resp;
    char                        hdrs[1024];
    char                        loc[1024];
    const void                 *rb;
    size_t                      blen = 0;
    char                        errbuf[256];
    int                         status;

    hdrs[0] = '\0';
    if (leg->send_basic) {
        oci_token_basic_header(leg->basic, hdrs, sizeof(hdrs));
    }

    if (tr->request(NULL, leg->host, leg->port, leg->tls, "GET", leg->path,
                    hdrs[0] ? hdrs : NULL, NULL, 0, OCI_TOKEN_TIMEOUT_MS,
                    &resp, errbuf, sizeof(errbuf)) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, up->log, 0,
            "oci: token endpoint unreachable host=%s: %s", leg->host, errbuf);
        return -1;
    }
    status = resp.status;

    if (status >= 300 && status < 400) {
        int rc = tr->resp_header(&resp, "location", loc, sizeof(loc));

        tr->resp_free(&resp);
        if (rc != 0 || oci_token_follow(leg, loc) != 0) {
            ngx_log_error(NGX_LOG_ERR, up->log, 0,
                "oci: token endpoint host=%s redirected without a usable "
                "Location", leg->host);
            return -1;
        }
        return status;
    }

    rb = tr->resp_body(&resp, &blen);
    if (rb != NULL && blen > 0 && blen < bodysz) {
        memcpy(body, rb, blen);
        body[blen] = '\0';
        *body_len  = blen;
    } else {
        body[0]   = '\0';
        *body_len = 0;
    }
    tr->resp_free(&resp);

    return status;
}

/* Turn a parsed WWW-Authenticate challenge into the one HTTP leg that mints
 * the bearer: realm → host/port/tls/path, with the service and scope escaped
 * into the query. 0 = `leg` is ready to run; -1 = the realm is unusable or
 * off-boundary (already logged). */
static int
oci_token_leg_init(brix_oci_upstream_t *up, const brix_oci_challenge_t *ch,
    const char *scope, const char *basic, oci_token_leg_t *leg)
{
    brix_oci_url_t  realm;
    u_char          enc_scope[1024];
    u_char          enc_svc[768];

    if (brix_oci_url_parse(ch->realm, strlen(ch->realm), &realm) != 0) {
        ngx_log_error(NGX_LOG_ERR, up->log, 0,
            "oci: challenge realm is not an absolute http(s) URL");
        return -1;
    }

    /* THE gate: an upstream may only send us to its own token service, or to
     * a host the operator named with brix_oci_upstream_auth_realm (§D15.11). */
    if (!brix_oci_url_realm_allowed_ex(up->host, realm.host, &up->realms)) {
        ngx_log_error(NGX_LOG_ERR, up->log, 0,
            "oci: refusing token realm host=%s for upstream=%s "
            "signal=oci_realm_refused", realm.host, up->host);
        return -1;
    }

    /* A realm reached only because it was allowlisted is worth one line: the
     * dance is cached per scope, so this is rare, and it is the audit record
     * that the widened boundary is the one actually being used. */
    if (up->realms.n > 0 && !brix_oci_url_realm_allowed(up->host, realm.host)) {
        ngx_log_error(NGX_LOG_INFO, up->log, 0,
            "oci: token realm host=%s is off-domain for upstream=%s and was "
            "honoured by brix_oci_upstream_auth_realm", realm.host, up->host);
    }

    if (oci_query_escape(scope, enc_scope, sizeof(enc_scope)) != 0
        || oci_query_escape(ch->service, enc_svc, sizeof(enc_svc)) != 0)
    {
        return -1;
    }

    memset(leg, 0, sizeof(*leg));
    (void) snprintf(leg->host, sizeof(leg->host), "%s", realm.host);
    leg->port       = realm.port;
    leg->tls        = realm.tls;
    leg->basic      = basic;
    leg->send_basic = 1;

    return (snprintf(leg->path, sizeof(leg->path), "%s?service=%s&scope=%s",
                     realm.path[0] ? realm.path : "/", enc_svc, enc_scope)
            >= (int) sizeof(leg->path)) ? -1 : 0;
}


/* Walk the token endpoint's redirects to the first non-3xx answer. The HTTP
 * status, or -1 when a leg failed, a redirect tried to leave the upstream's
 * trust boundary — a token minted off-boundary is a credential handed to a
 * host the operator never named — or the chain never terminated within
 * OCI_TOKEN_MAX_HOPS. */
static int
oci_token_run(brix_oci_upstream_t *up, oci_token_leg_t *leg,
    char *body, size_t bodysz, size_t *body_len)
{
    int  hop, status;

    for (hop = 0; hop <= OCI_TOKEN_MAX_HOPS; hop++) {
        status = oci_token_leg(up, leg, body, bodysz, body_len);
        if (status < 0) {
            return -1;
        }
        if (status < 300 || status >= 400) {
            return status;
        }
        if (!brix_oci_url_realm_allowed_ex(up->host, leg->host, &up->realms)) {
            ngx_log_error(NGX_LOG_ERR, up->log, 0,
                "oci: refusing token redirect host=%s for upstream=%s "
                "signal=oci_realm_refused", leg->host, up->host);
            return -1;
        }
    }

    /* Ran out of hops with a 3xx still on the wire. Returning the last status
     * would hand the caller a redirect as though it were the token endpoint's
     * answer; an unterminated chain is a failure, and the only status the
     * contract above admits for one is -1. */
    ngx_log_error(NGX_LOG_ERR, up->log, 0,
        "oci: token redirect chain exceeded %d hops for upstream=%s "
        "signal=oci_token_redirect_loop", OCI_TOKEN_MAX_HOPS, up->host);
    return -1;
}


/* Lift the bearer and its lifetime out of the token endpoint's JSON. */
static int
oci_token_parse(brix_oci_upstream_t *up, const char *host, const char *body,
    size_t body_len, char *tok, size_t toklen, long *expires_in)
{
    char  expbuf[32];
    long  v;

    /* Both spellings are in the wild: the Distribution spec says "token",
     * OAuth2 says "access_token", and GitLab/Harbor emit both. */
    if (!brix_json_get_str(body, body_len, "token", tok, toklen)
        && !brix_json_get_str(body, body_len, "access_token", tok, toklen))
    {
        ngx_log_error(NGX_LOG_ERR, up->log, 0,
            "oci: token response from %s carried no token", host);
        return -1;
    }
    if (tok[0] == '\0') {
        return -1;
    }

    *expires_in = OCI_TOKEN_DEFAULT_S;
    if (brix_json_get_str(body, body_len, "expires_in", expbuf,
                          sizeof(expbuf)))
    {
        v = strtol(expbuf, NULL, 10);
        if (v > 0) {
            *expires_in = v;
        }
    }

    return 0;
}


/* Mint one bearer: build the token leg from the challenge, walk it, and read
 * the answer. Every failure path is a single counter here, so the three halves
 * above can each fail plainly and stay readable. A 401/403 from the token
 * endpoint itself sets *denied — the D16 gate needs "this credential was
 * refused" kept apart from "the endpoint was unreachable", because only the
 * former is a verdict about the principal. */
static int
oci_token_fetch(brix_oci_upstream_t *up, const brix_oci_challenge_t *ch,
    const char *scope, const char *basic, char *tok, size_t toklen,
    long *expires_in, int *denied)
{
    oci_token_leg_t  leg;
    char             body[16384];
    size_t           body_len = 0;
    int              status;

    if (oci_token_leg_init(up, ch, scope, basic, &leg) != 0) {
        BRIX_OCI_METRIC_INC(token_fetch_total[BRIX_OCI_TOKEN_FAILED]);
        return -1;
    }

    status = oci_token_run(up, &leg, body, sizeof(body), &body_len);
    if (status != NGX_HTTP_OK || body_len == 0) {
        if (status >= 0) {
            ngx_log_error(NGX_LOG_ERR, up->log, 0,
                "oci: token endpoint host=%s answered %d", leg.host, status);
        }
        if (denied != NULL
            && (status == NGX_HTTP_UNAUTHORIZED
                || status == NGX_HTTP_FORBIDDEN))
        {
            *denied = 1;
        }
        BRIX_OCI_METRIC_INC(token_fetch_total[BRIX_OCI_TOKEN_FAILED]);
        return -1;
    }

    if (oci_token_parse(up, leg.host, body, body_len, tok, toklen,
                        expires_in) != 0)
    {
        BRIX_OCI_METRIC_INC(token_fetch_total[BRIX_OCI_TOKEN_FAILED]);
        return -1;
    }

    BRIX_OCI_METRIC_INC(token_fetch_total[BRIX_OCI_TOKEN_FETCHED]);
    return 0;
}


int
brix_oci_token_get_cred(brix_oci_upstream_t *up, const char *path,
    const char *challenge, const char *basic, const u_char *cred,
    char *tok, size_t toklen, long *expires_in, int *denied)
{
    brix_oci_challenge_t  ch;
    char                  scope[1024];
    long                  expires = 0;

    if (denied != NULL) {
        *denied = 0;
    }
    if (up == NULL || challenge == NULL || toklen == 0) {
        return -1;
    }
    if (brix_oci_challenge_parse(challenge, strlen(challenge), &ch) != 0) {
        /* Not a Bearer challenge (Basic, Negotiate, junk): nothing this
         * function can mint, and guessing would send a credential to a
         * scheme that never asked for one. */
        return -1;
    }

    if (ch.scope[0] != '\0') {
        (void) snprintf(scope, sizeof(scope), "%s", ch.scope);

    } else if (brix_oci_pull_scope(path, scope, sizeof(scope)) != 0) {
        return -1;
    }

    if (brix_oci_token_cache_get(up, scope, cred, tok, toklen) == 0) {
        if (expires_in != NULL) {
            *expires_in = -1;              /* cached: lifetime unknown here */
        }
        return 0;
    }

    if (oci_token_fetch(up, &ch, scope, basic, tok, toklen, &expires,
                        denied) != 0)
    {
        return -1;
    }

    brix_oci_token_cache_put(up, scope, cred, tok, expires);
    if (expires_in != NULL) {
        *expires_in = expires;
    }
    return 0;
}


int
brix_oci_token_get(brix_oci_upstream_t *up, const char *path,
    const char *challenge, char *tok, size_t toklen)
{
    /* The mirror's own identity: the configured service credential, under
     * the credential-blind cache entry the fill provider has always used. */
    return brix_oci_token_get_cred(up, path, challenge,
                                   (up != NULL && up->basic[0] != '\0')
                                       ? up->basic : NULL,
                                   NULL, tok, toklen, NULL, NULL);
}


/* ---- the sd_http seam --------------------------------------------------- */

/* The supplier the http driver calls when its own GET came back 401. The
 * driver owns the retry; all it wants back is a token string. */
static int
oci_bearer_provider(void *ctx, const char *host, int port, int tls,
    const char *path, const char *challenge, char *tok, size_t toklen)
{
    brix_oci_upstream_t *up = ctx;

    (void) host;
    (void) port;
    (void) tls;

    return brix_oci_token_get(up, path, challenge, tok, toklen);
}

void
brix_oci_up_log_ensure(ngx_http_brix_oci_loc_conf_t *lcf)
{
    /* bind_bearer binds this on the first fill, but a tags or delegate task
     * can be the FIRST thread onto a cold worker, and every log call on the
     * thread side dereferences it. Same lifetime argument as bind_bearer:
     * config-pool upstream, cycle log, never the connection's. */
    if (lcf->up != NULL && lcf->up->log == NULL) {
        lcf->up->log = ngx_cycle->log;
    }
}

void
brix_oci_bind_bearer(ngx_http_brix_oci_loc_conf_t *lcf,
    brix_sd_instance_t *inst, ngx_log_t *log)
{
    if (lcf->bearer_bound || lcf->up == NULL || inst == NULL) {
        return;
    }

    /* The instance handed in is the composed stack (cache decorators over the
     * http source); the supplier belongs on the source that actually speaks
     * to the registry. */
    while (inst != NULL && ngx_strcmp(inst->driver->name, "http") != 0) {
        inst = brix_sd_cache_source_instance(inst);
    }
    if (inst == NULL) {
        return;
    }

    /* The fill runs on a worker thread long after this request is gone: the
     * upstream descriptor is config-pool-owned (process lifetime) and the log
     * is the cycle's, never the connection's. */
    lcf->up->log = ngx_cycle->log;
    sd_http_set_bearer_provider(inst, oci_bearer_provider, lcf->up);
    lcf->bearer_bound = 1;

    ngx_log_error(NGX_LOG_INFO, log, 0,
        "oci: bearer supplier bound to upstream %s", lcf->up->base_url);
}
