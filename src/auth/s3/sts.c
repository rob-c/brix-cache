/*
 * sts.c — AWS STS AssumeRole / GetSessionToken client (phase-70 §5.5).
 *
 * WHAT: exchange the node's long-lived backend S3 *service* credential for
 *       short-lived temporary credentials scoped to the inbound principal.
 * WHY:  an inbound S3 request proves knowledge of a secret via SigV4 but never
 *       transmits it, so the origin cannot be handed the caller's key. The node
 *       instead calls STS with its own service key, tagging the call with the
 *       caller's identity (RoleSessionName), and forwards the resulting
 *       temporary (ak, sk, session) to the origin. Pure passthrough is
 *       impossible by design; this is the EXCHANGE path.
 * HOW:  this file is the orchestrator — it validates the config, derives the
 *       identity/timestamps, then drives the pure request builder (sts_sign.c)
 *       and the transport + XML parser (sts_http.c) in a flat phase sequence:
 *       prepare → perform → finish. Secrets and session tokens are copied into
 *       the caller's pool and never logged. The SigV4 signing and the HTTP/XML
 *       work live in the sibling files (declared in sts_internal.h).
 *
 * File split (phase-79):
 *   - sts.c        — this orchestrator + small identity/URL/TTL helpers
 *   - sts_sign.c   — canonical query construction + SigV4 signing
 *   - sts_http.c   — libcurl transport + libxml2 response parsing
 *   - sts_internal.h — the structs, size cap and seam entry points they share
 */
#include "sts_internal.h"

#include <string.h>
#include <time.h>

#define BRIX_STS_TTL_MIN   900       /* AWS floor:  15 min */
#define BRIX_STS_TTL_MAX   43200     /* AWS ceiling: 12 h  */


/* ------------------------------------------------------------------------- *
 * Small pure helpers                                                        *
 * ------------------------------------------------------------------------- */

/*
 * Copy a NUL-terminated C string into `dst` as a pool-allocated ngx_str_t.
 * A NULL source yields an empty (but non-NULL .data) string so callers can
 * always treat *session as valid. Returns NGX_OK / NGX_ERROR (OOM).
 */
static ngx_int_t
sts_pool_cstr(ngx_pool_t *pool, ngx_str_t *dst, const char *src)
{
    size_t   len = (src != NULL) ? ngx_strlen(src) : 0;
    u_char  *p;

    p = ngx_pnalloc(pool, len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }
    if (len > 0) {
        ngx_memcpy(p, src, len);
    }
    p[len] = '\0';
    dst->data = p;
    dst->len  = len;
    return NGX_OK;
}


/*
 * Clamp the requested lifetime to the STS-permitted [900, 43200] window; a
 * zero/negative request defaults to one hour.
 */
static int
sts_clamp_ttl(int ttl)
{
    if (ttl <= 0) {
        return 3600;
    }
    if (ttl < BRIX_STS_TTL_MIN) {
        return BRIX_STS_TTL_MIN;
    }
    if (ttl > BRIX_STS_TTL_MAX) {
        return BRIX_STS_TTL_MAX;
    }
    return ttl;
}


/*
 * sts_rsn_char_ok — is `c` a byte AWS permits verbatim in a RoleSessionName?
 *
 * WHAT: predicate for the AWS-permitted RoleSessionName alphabet
 *       ([A-Za-z0-9+=,.@:/-]); every other byte is mapped to '_' by the caller.
 * WHY:  isolating the alphabet check keeps the sanitising loop's cyclomatic
 *       complexity low and puts the (byte-frozen) allowed set in one place.
 * HOW:  a punctuation lookup string plus the three alphanumeric ranges; returns
 *       1 for permitted bytes, 0 otherwise. Semantics identical to the former
 *       inline `||` chain.
 */
static int
sts_rsn_char_ok(char c)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9'))
    {
        return 1;
    }
    return strchr("+=,.@:/-", c) != NULL && c != '\0';
}


/*
 * sts_rsn_source — pick the RoleSessionName source string from the identity:
 * prefer the subject (JWT sub or S3 access key), fall back to the DN, else
 * "anonymous". Returns a NUL-terminated C string (never NULL).
 */
static const char *
sts_rsn_source(const brix_identity_t *id)
{
    if (id != NULL && id->subject.len > 0) {
        return (const char *) id->subject.data;
    }
    if (id != NULL && id->dn.len > 0) {
        return (const char *) id->dn.data;
    }
    return "anonymous";
}


/*
 * Derive a RoleSessionName from the inbound identity, sanitised to the
 * AWS-permitted alphabet with everything else mapped to '_', and truncated to
 * 64 chars. Written NUL-terminated into out[65].
 */
static void
sts_role_session_name(const brix_identity_t *id, char out[65])
{
    const char *src = sts_rsn_source(id);
    size_t      i;

    for (i = 0; i < 64 && src[i] != '\0'; i++) {
        out[i] = sts_rsn_char_ok(src[i]) ? src[i] : '_';
    }
    if (i == 0) {
        ngx_memcpy(out, "anonymous", 9);
        i = 9;
    }
    out[i] = '\0';
}


/*
 * Parse a URL of the form "scheme://host[:port][/...]" into a pool-copied,
 * NUL-terminated host[:port] authority for the SigV4 "host" header. Returns
 * NGX_OK / NGX_ERROR on a malformed endpoint.
 */
static ngx_int_t
sts_host_from_url(ngx_pool_t *pool, const ngx_str_t *url, char **host_out)
{
    const char *s = (const char *) url->data;
    const char *p;
    const char *end;
    size_t      n;
    char       *h;

    p = strstr(s, "://");
    p = (p != NULL) ? p + 3 : s;
    for (end = p; *end != '\0' && *end != '/'; end++) { /* to path or NUL */ }
    n = (size_t) (end - p);
    if (n == 0) {
        return NGX_ERROR;
    }
    h = ngx_pnalloc(pool, n + 1);
    if (h == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(h, p, n);
    h[n] = '\0';
    *host_out = h;
    return NGX_OK;
}


/* ------------------------------------------------------------------------- *
 * Public entry point                                                        *
 * ------------------------------------------------------------------------- */

/*
 * Format the current UTC time as SigV4's "YYYYMMDDTHHMMSSZ" into amzdate[17]
 * and its "YYYYMMDD" datestamp prefix into datestamp[9]. Returns NGX_OK, or
 * NGX_ERROR if the clock cannot be read.
 */
static ngx_int_t
sts_now(char amzdate[17], char datestamp[9])
{
    time_t    t = time(NULL);
    struct tm g;

    if (gmtime_r(&t, &g) == NULL) {
        return NGX_ERROR;
    }
    if (strftime(amzdate, 17, "%Y%m%dT%H%M%SZ", &g) != 16) {
        return NGX_ERROR;
    }
    ngx_memcpy(datestamp, amzdate, 8);
    datestamp[8] = '\0';
    return NGX_OK;
}


/*
 * sts_validate — reject a NULL/incomplete request before doing any work.
 *
 * WHAT: check the mandatory pointers and the config completeness the exchange
 *       needs (endpoint/region/service key). WHY: fail closed with the exact
 *       pre-refactor error string. HOW: two early-return guards; NGX_OK when
 *       everything required is present.
 */
static ngx_int_t
sts_validate(ngx_pool_t *pool, const brix_s3_sts_conf_t *cf,
    const brix_s3_sts_out_t *out, ngx_log_t *log)
{
    if (pool == NULL || cf == NULL || out->ak == NULL || out->sk == NULL
        || out->session == NULL)
    {
        return NGX_ERROR;
    }
    if (cf->endpoint.len == 0 || cf->region.len == 0
        || cf->svc_ak.len == 0 || cf->svc_sk.len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix_sts: incomplete STS config (endpoint/region/service key)");
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * sts_prepare — populate `req` and render the fully-signed request URL.
 *
 * WHAT: derive the clamped TTL, timestamps, host, RoleSessionName and encoded
 *       X-Amz-Credential, then build+sign the canonical query and format the
 *       final "<endpoint>?<signed-query>" into url[urlsz].
 * WHY:  isolates all pure request construction from transport, keeping the
 *       entry point a linear phase sequence. Byte output is unchanged — the same
 *       calls in the same order, only the {cf,host,...} cluster now travels in
 *       `req` instead of as loose args.
 * HOW:  clock/host/credential each early-return on overflow or failure with the
 *       original error string; then sts_build_action_qs → sts_sign_query →
 *       url. NGX_OK / NGX_ERROR.
 */
static ngx_int_t
sts_prepare(ngx_pool_t *pool, sts_req_t *req, char *url, size_t urlsz,
    ngx_log_t *log)
{
    const brix_s3_sts_conf_t *cf = req->cf;
    char  action_qs[2048];
    char  signed_qs[2560];
    char *host = NULL;
    int   n;

    req->ttl = sts_clamp_ttl(cf->ttl_secs);

    if (sts_now(req->amzdate, req->datestamp) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "brix_sts: clock read failed");
        return NGX_ERROR;
    }
    if (sts_host_from_url(pool, &cf->endpoint, &host) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix_sts: malformed STS endpoint");
        return NGX_ERROR;
    }
    req->host = host;

    sts_role_session_name(req->id, req->rsn);

    /* X-Amz-Credential value with the scope slashes percent-encoded (%2F). */
    n = ngx_snprintf((u_char *) req->credential, sizeof(req->credential),
            "%V%%2F%s%%2F%V%%2Fsts%%2Faws4_request%Z",
            &cf->svc_ak, req->datestamp, &cf->region)
        - (u_char *) req->credential;
    if (n <= 0 || (size_t) n >= sizeof(req->credential)) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "brix_sts: credential too long");
        return NGX_ERROR;
    }

    if (sts_build_action_qs(req, action_qs, sizeof(action_qs)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "brix_sts: query build overflow");
        return NGX_ERROR;
    }

    if (sts_sign_query(req, action_qs, signed_qs, sizeof(signed_qs)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "brix_sts: SigV4 signing failed");
        return NGX_ERROR;
    }

    n = ngx_snprintf((u_char *) url, urlsz, "%V?%s%Z",
            &cf->endpoint, signed_qs) - (u_char *) url;
    if (n <= 0 || (size_t) n >= urlsz) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "brix_sts: URL too long");
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * sts_perform — fetch the signed URL and capture a successful (HTTP 200) body.
 *
 * WHAT: allocate the bounded response buffer, GET the URL, and require a 200.
 * WHY:  separates transport + status policy from parsing; the non-200 branch
 *       keeps the original "AssumeRole for <rsn> returned HTTP <n>" message.
 * HOW:  fills `resp` (its buffer pool-allocated) and early-returns NGX_ERROR on
 *       transport failure or a non-200 status; NGX_OK leaves the body in `resp`.
 */
static ngx_int_t
sts_perform(ngx_pool_t *pool, const char *url, const char *rsn,
    sts_resp_t *resp, ngx_log_t *log)
{
    long http_status = 0;

    resp->buf = ngx_pnalloc(pool, BRIX_STS_RESP_MAX);
    if (resp->buf == NULL) {
        return NGX_ERROR;
    }
    resp->len = 0;
    resp->cap = BRIX_STS_RESP_MAX;

    if (sts_http_get(url, resp, &http_status, log) != NGX_OK) {
        return NGX_ERROR;
    }
    if (http_status != 200) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix_sts: STS AssumeRole for \"%s\" returned HTTP %l",
            rsn, http_status);
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * sts_finish — parse the STS XML body and pool-copy the credentials out.
 *
 * WHAT: extract AccessKeyId/SecretAccessKey/SessionToken and copy each into the
 *       caller's ngx_str_t out slots. WHY: the last phase — parse then persist,
 *       failing closed on either. HOW: sts_parse_response into fixed buffers,
 *       then sts_pool_cstr for each; NGX_OK / NGX_ERROR. Secrets never logged.
 */
static ngx_int_t
sts_finish(ngx_pool_t *pool, const sts_resp_t *resp,
    const brix_s3_sts_out_t *out, ngx_log_t *log)
{
    char r_ak[256];
    char r_sk[512];
    char r_session[8192];
    sts_creds_buf_t creds = {
        r_ak, sizeof(r_ak),
        r_sk, sizeof(r_sk),
        r_session, sizeof(r_session)
    };

    if (sts_parse_response(resp->buf, resp->len, &creds, log) != NGX_OK) {
        return NGX_ERROR;
    }

    if (sts_pool_cstr(pool, out->ak, r_ak) != NGX_OK
        || sts_pool_cstr(pool, out->sk, r_sk) != NGX_OK
        || sts_pool_cstr(pool, out->session, r_session) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


ngx_int_t
brix_s3_sts_assume(ngx_pool_t *pool, const brix_identity_t *id,
    const brix_s3_sts_conf_t *cf, const brix_s3_sts_out_t *out, ngx_log_t *log)
{
    sts_req_t  req = { 0 };
    sts_resp_t resp = { 0 };
    char       url[3072];

    if (sts_validate(pool, cf, out, log) != NGX_OK) {
        return NGX_ERROR;
    }

    req.cf = cf;
    req.id = id;

    if (sts_prepare(pool, &req, url, sizeof(url), log) != NGX_OK) {
        return NGX_ERROR;
    }
    if (sts_perform(pool, url, req.rsn, &resp, log) != NGX_OK) {
        return NGX_ERROR;
    }
    if (sts_finish(pool, &resp, out, log) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
        "brix_sts: exchanged service cred for temp cred (session=\"%s\", "
        "ttl=%d, ak=%V)", req.rsn, req.ttl, out->ak);
    return NGX_OK;
}
