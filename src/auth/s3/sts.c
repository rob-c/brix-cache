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
 * HOW:  build the AssumeRole (or GetSessionToken) canonical GET query, derive
 *       the SigV4 signing key with the shared brix_sigv4_signing_key() kernel
 *       over the "sts" service, sign the request, fetch it with libcurl (same
 *       pattern as webdav/tpc_curl.c), and parse the XML response with libxml2
 *       for AccessKeyId / SecretAccessKey / SessionToken. Secrets and session
 *       tokens are copied into the caller's pool and never logged.
 *
 * The reused building blocks:
 *   - SigV4 signing key:  brix_sigv4_signing_key()  (core/compat/sigv4.h)
 *   - HMAC / SHA-256:      brix_hmac_sha256/brix_sha256 (core/compat/crypto.h)
 *   - outbound HTTP:       libcurl, mirroring src/protocols/webdav/tpc_curl.c
 */
#include "sts.h"

#include "core/compat/sigv4.h"
#include "core/compat/crypto.h"

#include <curl/curl.h>
#include <string.h>
#include <time.h>

#if (BRIX_HAVE_LIBXML2)
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif

#define BRIX_STS_TTL_MIN   900       /* AWS floor:  15 min */
#define BRIX_STS_TTL_MAX   43200     /* AWS ceiling: 12 h  */
#define BRIX_STS_RESP_MAX  (64 * 1024)


/*
 * sts_req_t — file-local request-construction state for one STS exchange.
 *
 * WHAT: bundles the immutable inputs (config, timestamps, derived identity) and
 *       the derived host/credential strings that the query-building and signing
 *       helpers all read, so those helpers take one struct pointer instead of a
 *       loose 5-7 argument tail.
 * WHY:  sts_build_action_qs() and sts_sign_query() previously each carried the
 *       same {cf, host, amzdate, datestamp, ...} argument cluster; promoting it
 *       removes the parameter bloat with zero behaviour change (identical values,
 *       identical evaluation order — the caller fills the struct once).
 * HOW:  brix_s3_sts_assume() zero-initialises one on its stack, populates it in
 *       the prepare phase, and threads a const pointer through the pure builders.
 *
 *   cf         — validated STS target config (borrowed, not owned)
 *   id         — inbound identity mapped to RoleSessionName (may be NULL)
 *   host       — NUL-terminated authority for the SigV4 "host" header
 *   amzdate    — "YYYYMMDDTHHMMSSZ"
 *   datestamp  — "YYYYMMDD" (amzdate prefix)
 *   rsn        — sanitised RoleSessionName
 *   credential — pre-encoded X-Amz-Credential value ("AKID%2F...%2Faws4_request")
 *   ttl        — clamped DurationSeconds
 */
typedef struct {
    const brix_s3_sts_conf_t *cf;
    const brix_identity_t    *id;
    const char               *host;
    char                      amzdate[17];
    char                      datestamp[9];
    char                      rsn[65];
    char                      credential[512];
    int                       ttl;
} sts_req_t;


/* ------------------------------------------------------------------------- *
 * Small pure helpers                                                        *
 * ------------------------------------------------------------------------- */

/*
 * Lowercase-hex-encode `n` bytes of `in` into `out` (needs 2*n+1 bytes, incl.
 * NUL). Used for the payload hash and the final signature, both of which SigV4
 * carries as hex.
 */
static void
sts_hex(const uint8_t *in, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i]     = hx[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hx[in[i] & 0xf];
    }
    out[2 * n] = '\0';
}


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
 * SigV4 request signing                                                     *
 * ------------------------------------------------------------------------- */

/*
 * sts_sign_query — build and SigV4-sign the STS request query string.
 *
 * WHAT: given the sorted action query (`action_qs`, already canonical and
 *       percent-encoded, WITHOUT the trailing X-Amz-Signature) and the target
 *       host, compute the SigV4 signature and return the full signed query.
 * WHY:  the STS endpoint authenticates the node by SigV4 over its service
 *       credentials; this is the exact string AWS/MinIO recomputes and checks.
 * HOW:  canonical request = "GET\n/\n<qs>\nhost:<h>\n\nhost\nUNSIGNED?..." with an
 *       empty-body SHA-256; string-to-sign wraps it with the credential scope;
 *       signing key from brix_sigv4_signing_key over "sts"; signature =
 *       HMAC(key, string_to_sign). Result "<qs>&X-Amz-Signature=<hex>" is
 *       written NUL-terminated into `out` (size `outsz`). NGX_OK / NGX_ERROR.
 *
 * The timestamps, host and config are read from `req` (amzdate is
 * "YYYYMMDDTHHMMSSZ", datestamp its "YYYYMMDD" prefix).
 */
static ngx_int_t
sts_sign_query(const sts_req_t *req, const char *action_qs,
    char *out, size_t outsz)
{
    const brix_s3_sts_conf_t *cf        = req->cf;
    const char               *host      = req->host;
    const char               *amzdate   = req->amzdate;
    const char               *datestamp = req->datestamp;
    uint8_t  empty_hash[32];
    char     empty_hex[65];
    char     canonical[4096];
    uint8_t  canon_hash[32];
    char     canon_hex[65];
    char     scope[128];
    char     to_sign[512];
    uint8_t  key[32];
    uint8_t  sig[32];
    char     sig_hex[65];
    int      n;

    /* Empty request body — STS AssumeRole carries all params in the query. */
    if (!brix_sha256((const uint8_t *) "", 0, empty_hash)) {
        return NGX_ERROR;
    }
    sts_hex(empty_hash, 32, empty_hex);

    n = ngx_snprintf((u_char *) canonical, sizeof(canonical),
            "GET\n/\n%s\nhost:%s\nx-amz-date:%s\n\nhost;x-amz-date\n%s",
            action_qs, host, amzdate, empty_hex) - (u_char *) canonical;
    if (n <= 0 || (size_t) n >= sizeof(canonical)) {
        return NGX_ERROR;
    }
    if (!brix_sha256((const uint8_t *) canonical, (size_t) n, canon_hash)) {
        return NGX_ERROR;
    }
    sts_hex(canon_hash, 32, canon_hex);

    ngx_snprintf((u_char *) scope, sizeof(scope), "%s/%V/sts/aws4_request%Z",
        datestamp, &cf->region);

    n = ngx_snprintf((u_char *) to_sign, sizeof(to_sign),
            "AWS4-HMAC-SHA256\n%s\n%s\n%s",
            amzdate, scope, canon_hex) - (u_char *) to_sign;
    if (n <= 0 || (size_t) n >= sizeof(to_sign)) {
        return NGX_ERROR;
    }

    if (!brix_sigv4_signing_key(cf->svc_sk.data, cf->svc_sk.len,
            datestamp, (const char *) cf->region.data, "sts", key)) {
        return NGX_ERROR;
    }
    if (!brix_hmac_sha256(key, 32, (const uint8_t *) to_sign, (size_t) n, sig)) {
        return NGX_ERROR;
    }
    sts_hex(sig, 32, sig_hex);

    n = ngx_snprintf((u_char *) out, outsz, "%s&X-Amz-Signature=%s%Z",
            action_qs, sig_hex) - (u_char *) out;
    if (n <= 0 || (size_t) n >= outsz) {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* ------------------------------------------------------------------------- *
 * Query construction                                                        *
 * ------------------------------------------------------------------------- */

/*
 * sts_build_action_qs — build the canonical (sorted, encoded) STS query string,
 * WITHOUT the trailing X-Amz-Signature.
 *
 * Parameters appear in SigV4 canonical (byte-sorted-by-name) order. When a role
 * ARN is configured we emit Action=AssumeRole (+ RoleArn/RoleSessionName);
 * otherwise Action=GetSessionToken. `req->credential` is the pre-encoded
 * "AKID%2FDATE%2Fregion%2Fsts%2Faws4_request" X-Amz-Credential value.
 */
static ngx_int_t
sts_build_action_qs(const sts_req_t *req, char *out, size_t outsz)
{
    const brix_s3_sts_conf_t *cf         = req->cf;
    const char               *rsn        = req->rsn;
    const char               *credential = req->credential;
    const char               *amzdate    = req->amzdate;
    int                       ttl        = req->ttl;
    int n;

    if (cf->role_arn.len > 0) {
        n = ngx_snprintf((u_char *) out, outsz,
                "Action=AssumeRole"
                "&DurationSeconds=%d"
                "&RoleArn=%V"
                "&RoleSessionName=%s"
                "&Version=2011-06-15"
                "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
                "&X-Amz-Credential=%s"
                "&X-Amz-Date=%s"
                "&X-Amz-SignedHeaders=host%%3Bx-amz-date%Z",
                ttl, &cf->role_arn, rsn, credential, amzdate)
            - (u_char *) out;
    } else {
        n = ngx_snprintf((u_char *) out, outsz,
                "Action=GetSessionToken"
                "&DurationSeconds=%d"
                "&Version=2011-06-15"
                "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
                "&X-Amz-Credential=%s"
                "&X-Amz-Date=%s"
                "&X-Amz-SignedHeaders=host%%3Bx-amz-date%Z",
                ttl, credential, amzdate)
            - (u_char *) out;
    }

    if (n <= 0 || (size_t) n >= outsz) {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* ------------------------------------------------------------------------- *
 * HTTP transport (libcurl, mirroring webdav/tpc_curl.c)                     *
 * ------------------------------------------------------------------------- */

typedef struct {
    u_char *buf;
    size_t  len;
    size_t  cap;
} sts_resp_t;


/*
 * libcurl write callback: append the response body into a growable pool buffer,
 * bounded by BRIX_STS_RESP_MAX so a hostile/huge response cannot exhaust memory.
 * Returns 0 (short write → curl aborts) on overflow or OOM.
 */
static size_t
sts_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    sts_resp_t *r  = userdata;
    size_t      n  = size * nmemb;

    if (n == 0) {
        return 0;
    }
    if (r->len + n > BRIX_STS_RESP_MAX) {
        return 0;
    }
    ngx_memcpy(r->buf + r->len, ptr, n);
    r->len += n;
    return n;
}


/*
 * sts_http_get — GET the signed STS URL and capture the response body.
 *
 * Restricts the transfer to http/https, enforces TLS verification, and streams
 * the body into `resp` (a pre-sized pool buffer). Returns NGX_OK with the HTTP
 * status in *http_status, or NGX_ERROR on a transport error (logged, no
 * secrets). Mirrors the curl setup in webdav_tpc_run_curl_core().
 */
static ngx_int_t
sts_http_get(const char *url, sts_resp_t *resp, long *http_status,
    ngx_log_t *log)
{
    CURL     *curl;
    CURLcode  res;
    char      errbuf[CURL_ERROR_SIZE];
    ngx_int_t rc = NGX_ERROR;

    curl = curl_easy_init();
    if (curl == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "brix_sts: curl_easy_init failed");
        return NGX_ERROR;
    }

    errbuf[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url);
#ifdef CURLOPT_PROTOCOLS_STR
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS,
        (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sts_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_status);
        rc = NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_WARN, log, 0, "brix_sts: STS request failed: %s",
            errbuf[0] ? errbuf : curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    return rc;
}


/* ------------------------------------------------------------------------- *
 * Response parsing (libxml2)                                                *
 * ------------------------------------------------------------------------- */

/*
 * sts_creds_buf_t — the three fixed output buffers sts_parse_response fills.
 *
 * WHAT: bundles each destination buffer with its capacity — AccessKeyId,
 *       SecretAccessKey and (optional) SessionToken — so the parser takes one
 *       struct pointer instead of three loose (char *, size_t) argument pairs.
 * WHY:  keeps sts_parse_response within the ≤5-argument budget with zero
 *       behaviour change; the buffers are the caller's stack storage (borrowed,
 *       written NUL-terminated by the parser).
 * HOW:  sts_finish declares r_ak/r_sk/r_session, points each field+size at them,
 *       and reads the extracted credentials back after NGX_OK.
 *
 *   ak / aksz            — AccessKeyId buffer and its capacity
 *   sk / sksz            — SecretAccessKey buffer and its capacity
 *   session / sesssz     — SessionToken buffer and its capacity (may stay empty)
 */
typedef struct {
    char   *ak;
    size_t  aksz;
    char   *sk;
    size_t  sksz;
    char   *session;
    size_t  sesssz;
} sts_creds_buf_t;

#if (BRIX_HAVE_LIBXML2)

/*
 * Recursively search the parse tree for the first element named `name` and copy
 * its text content into out[outsz]. Returns 1 if found, 0 otherwise. The STS
 * AssumeRole/GetSessionToken responses nest <Credentials> under result and
 * response wrappers, so a name-directed descent is simpler than a fixed path.
 */
static int
sts_xml_find(xmlNodePtr node, const char *name, char *out, size_t outsz)
{
    xmlNodePtr n;

    for (n = node; n != NULL; n = n->next) {
        if (n->type == XML_ELEMENT_NODE
            && xmlStrcmp(n->name, (const xmlChar *) name) == 0)
        {
            xmlChar *txt = xmlNodeGetContent(n);
            if (txt != NULL) {
                ngx_snprintf((u_char *) out, outsz, "%s%Z", (char *) txt);
                xmlFree(txt);
                return 1;
            }
        }
        if (n->children != NULL
            && sts_xml_find(n->children, name, out, outsz))
        {
            return 1;
        }
    }
    return 0;
}


/*
 * sts_parse_response — extract AccessKeyId / SecretAccessKey / SessionToken
 * from the STS XML body into the caller's fixed buffers. Returns NGX_OK when at
 * least AccessKeyId and SecretAccessKey are present; NGX_ERROR (with the fault
 * logged, secrets excluded) otherwise. SessionToken is optional.
 */
static ngx_int_t
sts_parse_response(const u_char *body, size_t len,
    const sts_creds_buf_t *creds, ngx_log_t *log)
{
    xmlDocPtr  doc;
    xmlNodePtr root;
    ngx_int_t  rc = NGX_ERROR;

    creds->ak[0] = creds->sk[0] = creds->session[0] = '\0';

    doc = xmlReadMemory((const char *) body, (int) len, "sts.xml", NULL,
            XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix_sts: unparseable STS response");
        return NGX_ERROR;
    }

    root = xmlDocGetRootElement(doc);
    if (root != NULL
        && sts_xml_find(root, "AccessKeyId", creds->ak, creds->aksz)
        && sts_xml_find(root, "SecretAccessKey", creds->sk, creds->sksz)
        && creds->ak[0] != '\0' && creds->sk[0] != '\0')
    {
        (void) sts_xml_find(root, "SessionToken", creds->session,
            creds->sesssz);
        rc = NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix_sts: STS response missing credential fields");
    }

    xmlFreeDoc(doc);
    return rc;
}

#else  /* !BRIX_HAVE_LIBXML2 */

static ngx_int_t
sts_parse_response(const u_char *body, size_t len,
    const sts_creds_buf_t *creds, ngx_log_t *log)
{
    (void) body; (void) len; (void) creds;
    ngx_log_error(NGX_LOG_ERR, log, 0,
        "brix_sts: built without libxml2; STS exchange unavailable");
    return NGX_ERROR;
}

#endif /* BRIX_HAVE_LIBXML2 */


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
