/*
 * exchange.c — RFC 8693 OAuth2 token-exchange HTTP client.
 *
 * WHAT: brix_token_exchange() POSTs an RFC 8693 token-exchange grant to an
 *       OAuth2 token endpoint and returns the minted access_token.
 * WHY:  Phase-70 §5.4 — mint an origin-audienced token instead of replaying
 *       the client's token when a backend audience is node-bound. This mirrors
 *       the TPC capture path (webdav/tpc_cred.c BRIX_TPC_CRED_TOKEN_EXCHANGE)
 *       but is a pool-based, in-process helper reusable by the storage plane.
 * HOW:  Build a x-www-form-urlencoded body (grant_type / subject_token /
 *       subject_token_type / audience / resource / scope), authenticate the
 *       client via HTTP Basic (client_id:client_secret) when configured, drive
 *       it with libcurl over HTTPS-only (same in-process pattern as
 *       fs/cache/origin/pelican_register.c and webdav/tpc_curl.c), then parse
 *       the JSON response with jansson for `access_token`. Tokens and the
 *       client secret are never logged.
 *
 * NOTE: No result cache is kept here — the integration layer owns caching
 *       keyed on (sub,aud,scope)/exp; this helper returns a fresh pool copy.
 */

#include <ngx_core.h>

#include "auth/token/exchange.h"

#include <curl/curl.h>

#if BRIX_HAVE_JANSSON
#include <jansson.h>
#endif

#define BRIX_TX_GRANT "urn:ietf:params:oauth:grant-type:token-exchange"
#define BRIX_TX_SUBJECT_TYPE "urn:ietf:params:oauth:token-type:access_token"
#define BRIX_TX_CONNECT_TIMEOUT 10L
#define BRIX_TX_TIMEOUT 30L
#define BRIX_TX_MAX_RESPONSE (64 * 1024)


/*
 * WHAT: bounded response accumulator for the libcurl write callback.
 * WHY:  cap the endpoint's reply so a hostile/broken issuer can't grow memory
 *       without limit; the buffer is caller-pool allocated.
 */
typedef struct {
    u_char *buf;
    size_t  len;
    size_t  cap;
} brix_tx_sink_t;


/*
 * WHAT: libcurl CURLOPT_WRITEFUNCTION sink — append body bytes, drop overflow.
 * HOW:  copy up to remaining capacity; always report the full size consumed so
 *       curl does not abort the transfer, but never write past `cap`.
 */
static size_t
brix_tx_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    brix_tx_sink_t *sink = userdata;
    size_t          incoming = size * nmemb;
    size_t          room;

    room = sink->cap - sink->len;
    if (room > 0) {
        size_t take = incoming < room ? incoming : room;
        ngx_memcpy(sink->buf + sink->len, ptr, take);
        sink->len += take;
    }

    return incoming;
}


/*
 * WHAT: NUL-terminate an ngx_str_t into a fresh pool C-string (or "" if empty).
 * WHY:  curl_easy_escape / curl_easy_setopt need C-strings; wire strings are
 *       not NUL-terminated.
 */
static char *
brix_tx_cstr(ngx_pool_t *pool, const ngx_str_t *s)
{
    char *z;

    if (s == NULL || s->len == 0 || s->data == NULL) {
        z = ngx_pnalloc(pool, 1);
        if (z != NULL) {
            z[0] = '\0';
        }
        return z;
    }

    z = ngx_pnalloc(pool, s->len + 1);
    if (z == NULL) {
        return NULL;
    }
    ngx_memcpy(z, s->data, s->len);
    z[s->len] = '\0';
    return z;
}


/*
 * WHAT: URL-encode an ngx_str_t via curl and append "name=<enc>" to `body`.
 * HOW:  skip empty values entirely; prefix "&" when the body is non-empty.
 *       Returns NGX_OK on success, NGX_ERROR on allocation/encode failure.
 */
static ngx_int_t
brix_tx_append_field(CURL *curl, ngx_pool_t *pool, ngx_str_t *body,
    const char *name, const ngx_str_t *value)
{
    char   *raw;
    char   *enc;
    size_t  name_len;
    size_t  enc_len;
    u_char *dst;
    size_t  total;

    if (value == NULL || value->len == 0 || value->data == NULL) {
        return NGX_OK;
    }

    raw = brix_tx_cstr(pool, value);
    if (raw == NULL) {
        return NGX_ERROR;
    }

    enc = curl_easy_escape(curl, raw, (int) value->len);
    if (enc == NULL) {
        return NGX_ERROR;
    }

    name_len = ngx_strlen(name);
    enc_len = ngx_strlen(enc);
    total = body->len + (body->len ? 1 : 0) + name_len + 1 + enc_len;

    dst = ngx_pnalloc(pool, total + 1);
    if (dst == NULL) {
        curl_free(enc);
        return NGX_ERROR;
    }

    {
        u_char *p = dst;

        p = ngx_cpymem(p, body->data, body->len);
        if (body->len) {
            *p++ = '&';
        }
        p = ngx_cpymem(p, name, name_len);
        *p++ = '=';
        p = ngx_cpymem(p, enc, enc_len);
        *p = '\0';
        body->data = dst;
        body->len = (size_t) (p - dst);
    }

    curl_free(enc);
    return NGX_OK;
}


/*
 * WHAT: build the RFC 8693 form body for this exchange.
 * HOW:  grant_type + subject_token + subject_token_type are mandatory;
 *       audience is emitted as both `audience` and `resource`; scope optional.
 */
static ngx_int_t
brix_tx_build_body(CURL *curl, ngx_pool_t *pool,
    const ngx_str_t *subject_token, const ngx_str_t *audience,
    const ngx_str_t *scope, ngx_str_t *out_body)
{
    ngx_str_t grant = ngx_string(BRIX_TX_GRANT);
    ngx_str_t subject_type = ngx_string(BRIX_TX_SUBJECT_TYPE);
    ngx_str_t body = ngx_null_string;

    body.data = (u_char *) "";

    if (brix_tx_append_field(curl, pool, &body, "grant_type", &grant)
            != NGX_OK
        || brix_tx_append_field(curl, pool, &body, "subject_token",
               subject_token) != NGX_OK
        || brix_tx_append_field(curl, pool, &body, "subject_token_type",
               &subject_type) != NGX_OK
        || brix_tx_append_field(curl, pool, &body, "audience", audience)
               != NGX_OK
        || brix_tx_append_field(curl, pool, &body, "resource", audience)
               != NGX_OK
        || brix_tx_append_field(curl, pool, &body, "scope", scope) != NGX_OK)
    {
        return NGX_ERROR;
    }

    *out_body = body;
    return NGX_OK;
}


/*
 * WHAT: extract access_token from the JSON reply into a pool copy.
 * WHY:  a successful RFC 8693 response is a JSON object with a string
 *       `access_token`; anything else is a failure we must not treat as a token.
 */
static ngx_int_t
brix_tx_parse_response(ngx_pool_t *pool, const u_char *doc, size_t len,
    ngx_str_t *out_token, ngx_log_t *log)
{
#if BRIX_HAVE_JANSSON
    json_t       *root;
    json_t       *tok;
    json_error_t  jerr;
    const char   *val;
    size_t        vlen;
    u_char       *copy;

    root = json_loadb((const char *) doc, len, JSON_REJECT_DUPLICATES, &jerr);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "token-exchange: malformed JSON response: %s", jerr.text);
        return NGX_ERROR;
    }

    tok = json_object_get(root, "access_token");
    if (!json_is_string(tok)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "token-exchange: response has no access_token");
        json_decref(root);
        return NGX_ERROR;
    }

    val = json_string_value(tok);
    vlen = json_string_length(tok);
    if (val == NULL || vlen == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "token-exchange: empty access_token in response");
        json_decref(root);
        return NGX_ERROR;
    }

    copy = ngx_pnalloc(pool, vlen + 1);
    if (copy == NULL) {
        json_decref(root);
        return NGX_ERROR;
    }
    ngx_memcpy(copy, val, vlen);
    copy[vlen] = '\0';

    out_token->data = copy;
    out_token->len = vlen;

    json_decref(root);
    return NGX_OK;
#else
    (void) pool; (void) doc; (void) len; (void) out_token;
    ngx_log_error(NGX_LOG_ERR, log, 0,
        "token-exchange: built without jansson (BRIX_HAVE_JANSSON=0)");
    return NGX_ERROR;
#endif
}


/*
 * WHAT: run the token-exchange HTTP POST and return the raw JSON reply.
 * HOW:  in-process libcurl, HTTPS-only, form POST, optional HTTP Basic client
 *       auth, bounded response sink. Fails on transport error or HTTP >= 400.
 */
static ngx_int_t
brix_tx_http_post(ngx_pool_t *pool, const char *endpoint, const ngx_str_t *body,
    const brix_token_exchange_conf_t *cf, brix_tx_sink_t *sink, ngx_log_t *log)
{
    CURL              *curl;
    CURLcode           res;
    struct curl_slist *hdrs = NULL;
    long               code = 0;
    ngx_int_t          rc = NGX_ERROR;

    curl = curl_easy_init();
    if (curl == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "token-exchange: curl_easy_init() failed");
        return NGX_ERROR;
    }

    hdrs = curl_slist_append(hdrs,
        "Content-Type: application/x-www-form-urlencoded");
    if (hdrs == NULL) {
        curl_easy_cleanup(curl);
        return NGX_ERROR;
    }

#ifdef CURLOPT_PROTOCOLS_STR
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, (long) CURLPROTO_HTTPS);
#endif
    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body->data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) body->len);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, brix_tx_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, sink);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, BRIX_TX_CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, BRIX_TX_TIMEOUT);

    if (cf->client_id.len > 0 && cf->client_id.data != NULL) {
        char *cid = brix_tx_cstr(pool, &cf->client_id);
        char *csec = brix_tx_cstr(pool, &cf->client_secret);
        if (cid == NULL || csec == NULL) {
            curl_slist_free_all(hdrs);
            curl_easy_cleanup(curl);
            return NGX_ERROR;
        }
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long) CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, cid);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, csec);
    }

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        rc = NGX_OK;
    } else {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "token-exchange: request to endpoint failed: %s (http %ld)",
            curl_easy_strerror(res), code);
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return rc;
}


ngx_int_t
brix_token_exchange(ngx_pool_t *pool, const ngx_str_t *subject_token,
    const ngx_str_t *audience, const ngx_str_t *scope,
    const brix_token_exchange_conf_t *cf, ngx_str_t *out_token, ngx_log_t *log)
{
    CURL          *curl;
    char          *endpoint;
    ngx_str_t      body;
    brix_tx_sink_t sink;
    ngx_int_t      rc;

    if (pool == NULL || cf == NULL || out_token == NULL
        || subject_token == NULL || subject_token->len == 0
        || cf->endpoint.len == 0 || cf->endpoint.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "token-exchange: missing endpoint or subject token");
        return NGX_ERROR;
    }

    endpoint = brix_tx_cstr(pool, &cf->endpoint);
    if (endpoint == NULL) {
        return NGX_ERROR;
    }

    /* A short-lived easy handle drives curl_easy_escape() for body building. */
    curl = curl_easy_init();
    if (curl == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "token-exchange: curl_easy_init() failed (encode)");
        return NGX_ERROR;
    }

    rc = brix_tx_build_body(curl, pool, subject_token, audience, scope, &body);
    curl_easy_cleanup(curl);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "token-exchange: failed to build request body");
        return NGX_ERROR;
    }

    sink.buf = ngx_pnalloc(pool, BRIX_TX_MAX_RESPONSE);
    if (sink.buf == NULL) {
        return NGX_ERROR;
    }
    sink.len = 0;
    sink.cap = BRIX_TX_MAX_RESPONSE;

    if (brix_tx_http_post(pool, endpoint, &body, cf, &sink, log) != NGX_OK) {
        return NGX_ERROR;
    }

    return brix_tx_parse_response(pool, sink.buf, sink.len, out_token, log);
}
