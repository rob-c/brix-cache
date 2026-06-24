/*
 * macaroon_endpoint.c — POST /.oauth2/token and GET /.well-known/oauth-authorization-server.
 *
 * WHAT: REST endpoints that implement WLCG macaroon token issuance for third-party
 *       delegation.  An authenticated client POSTs a scope and expiry request and
 *       receives a signed macaroon that can be delegated to a TPC agent.
 *
 * WHY: WLCG HTTP-TPC pull operations require the TPC destination to authenticate to
 *      the source server.  The client obtains a scoped macaroon from the source via
 *      POST /.oauth2/token and passes it in the Credential: header of the COPY request.
 *      The destination then uses that macaroon to pull the file.
 *
 * HOW: Discovery handler returns a static JSON document pointing at the token endpoint.
 *      Issuance handler:
 *        1. Verifies macaroon_secret is configured and client is authenticated.
 *        2. Reads and URL-decodes the request body (application/x-www-form-urlencoded).
 *        3. Parses grant_type / scope / expire_in fields.
 *        4. Maps WLCG storage.* scope items to activity + path caveats.
 *        5. Calls xrootd_macaroon_issue() to build the signed token.
 *        6. Returns JSON {token, expires_in, token_type} per XrdMacaroons convention.
 */

#include "webdav.h"
#include "../token/macaroon.h"
#include "../token/macaroon_issue.h"
#include "../compat/http_body.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ----- URL-form decoding ----- */

static int
hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode %XX and '+' in-place; returns new length. */
static size_t
urlencode_decode_inplace(char *str)
{
    char *r = str;
    char *w = str;
    int   hi, lo;

    while (*r) {
        if (*r == '%' && r[1] && r[2]
            && (hi = hex_nibble(r[1])) >= 0
            && (lo = hex_nibble(r[2])) >= 0)
        {
            *w++ = (char)((hi << 4) | lo);
            r   += 3;
        } else if (*r == '+') {
            *w++ = ' ';
            r++;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
    return (size_t)(w - str);
}

/*
 * form_find — locate a field in a null-terminated URL-encoded form body.
 * Copies URL-decoded value into dst (up to dstsz-1 bytes).
 * Returns NGX_OK if found, NGX_DECLINED if absent.
 */
static ngx_int_t
form_find(const char *form, const char *key, char *dst, size_t dstsz)
{
    size_t      klen = strlen(key);
    const char *p    = form;

    while (*p) {
        if (ngx_strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *val = p + klen + 1;
            const char *end = strchr(val, '&');
            size_t      vlen;

            if (end == NULL) {
                end = val + strlen(val);
            }
            vlen = (size_t)(end - val);
            if (vlen >= dstsz) {
                vlen = dstsz - 1;
            }
            ngx_memcpy(dst, val, vlen);
            dst[vlen] = '\0';
            urlencode_decode_inplace(dst);
            return NGX_OK;
        }
        p = strchr(p, '&');
        if (p == NULL) break;
        p++;
    }
    return NGX_DECLINED;
}

/* ----- Scope → activity mapping ----- */

/*
 * scope_to_activities — parse a space-separated WLCG scope string into
 * a comma-joined activity string and the first path found.
 *
 * E.g. "storage.read:/atlas storage.stage:/atlas"
 *   → activities="DOWNLOAD,STAGE"  path="/atlas"
 */
static ngx_int_t
scope_to_activities(const char *scope, char *act_buf, size_t act_sz,
                    char *path_buf, size_t path_sz)
{
    char   tmp[1024];
    char  *token;
    char  *saveptr = NULL;
    size_t act_len = 0;
    int    found   = 0;

    if (!scope || !scope[0]) return NGX_DECLINED;

    strncpy(tmp, scope, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    act_buf[0]  = '\0';
    path_buf[0] = '\0';

    for (token = strtok_r(tmp, " ", &saveptr);
         token != NULL;
         token = strtok_r(NULL, " ", &saveptr))
    {
        char       *colon = strchr(token, ':');
        const char *activity;
        const char *path;
        size_t      alen;

        if (colon == NULL) continue;
        *colon = '\0';
        path   = colon + 1;

        if (strcmp(token, "storage.read") == 0) {
            activity = "DOWNLOAD";
        } else if (strcmp(token, "storage.write") == 0
                   || strcmp(token, "storage.create") == 0) {
            activity = "UPLOAD";
        } else if (strcmp(token, "storage.modify") == 0) {
            activity = "MANAGE";
        } else if (strcmp(token, "storage.stage") == 0) {
            activity = "STAGE";
        } else if (strcmp(token, "storage.delete") == 0) {
            activity = "DELETE";
        } else if (strcmp(token, "storage.list") == 0) {
            activity = "LIST";
        } else {
            continue;
        }

        alen = strlen(activity);
        if (act_len + (act_len > 0 ? 1 : 0) + alen + 1 > act_sz) break;
        if (act_len > 0) {
            act_buf[act_len++] = ',';
        }
        ngx_memcpy(act_buf + act_len, activity, alen);
        act_len += alen;
        act_buf[act_len] = '\0';

        if (!path_buf[0] && path[0]) {
            size_t plen = strlen(path);
            if (plen >= path_sz) plen = path_sz - 1;
            ngx_memcpy(path_buf, path, plen);
            path_buf[plen] = '\0';
        }

        found = 1;
    }

    if (!found) return NGX_DECLINED;
    if (!path_buf[0]) {
        path_buf[0] = '/';
        path_buf[1] = '\0';
    }
    return NGX_OK;
}

/* ----- Helper: send a JSON body ----- */

static ngx_int_t
send_json(ngx_http_request_t *r, ngx_int_t status,
          const char *json, size_t json_len)
{
    ngx_buf_t        *b;
    ngx_chain_t       out;
    u_char           *buf;
    ngx_table_elt_t  *cc;
    ngx_int_t         rc;

    buf = ngx_pnalloc(r->pool, json_len);
    if (buf == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_memcpy(buf, json, json_len);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    b->pos      = buf;
    b->last     = buf + json_len;
    b->memory   = 1;
    b->last_buf = 1;

    out.buf  = b;
    out.next = NULL;

    r->headers_out.status            = status;
    r->headers_out.content_length_n  = (off_t) json_len;
    r->headers_out.content_type.data = (u_char *) "application/json";
    r->headers_out.content_type.len  = sizeof("application/json") - 1;
    r->headers_out.content_type_len  = r->headers_out.content_type.len;

    cc = ngx_list_push(&r->headers_out.headers);
    if (cc != NULL) {
        cc->hash = 1;
        ngx_str_set(&cc->key, "Cache-Control");
        ngx_str_set(&cc->value, "no-store");
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) return rc;
    return ngx_http_output_filter(r, &out);
}

/* ----- Discovery handler ----- */

ngx_int_t
webdav_handle_macaroon_discovery(ngx_http_request_t *r)
{
    u_char      json[512];
    u_char     *p;
    size_t      jlen;
    const char *scheme;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    scheme = (r->connection->ssl != NULL) ? "https" : "http";

    if (r->headers_in.host != NULL) {
        p = ngx_snprintf(json, sizeof(json) - 1,
            "{\"token_endpoint\":\"%s://%V/.oauth2/token\","
            "\"grant_types_supported\":[\"client_credentials\"],"
            "\"token_endpoint_auth_methods_supported\":[\"none\"]}",
            scheme, &r->headers_in.host->value);
    } else {
        p = ngx_snprintf(json, sizeof(json) - 1,
            "{\"token_endpoint\":\"%s://localhost/.oauth2/token\","
            "\"grant_types_supported\":[\"client_credentials\"],"
            "\"token_endpoint_auth_methods_supported\":[\"none\"]}",
            scheme);
    }
    *p   = '\0';
    jlen = (size_t)(p - json);

    return send_json(r, NGX_HTTP_OK, (const char *) json, jlen);
}

/* ----- Issuance body handler (called when request body is ready) ----- */

void
webdav_handle_macaroon_token(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t  *conf;
    ngx_http_xrootd_webdav_req_ctx_t   *ctx;
    u_char                             *body     = NULL;
    size_t                              body_len = 0;
    char                                grant_type[64];
    char                                scope_str[512];
    char                                expire_str[32];
    char                                activities[128];
    char                                path[256];
    u_char                              root_key[64];
    ssize_t                             key_len;
    char                                identifier[96];
    char                                location[256];
    char                                token_out[XROOTD_MACAROON_ISSUE_OUT_MAX];
    char                                json[XROOTD_MACAROON_ISSUE_OUT_MAX + 128];
    long                                expire_in;
    time_t                              expiry;
    ngx_int_t                           rc;
    int                                 n;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    ctx  = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

#define J_NOT_CONFIGURED   "{\"error\":\"not_configured\"}"
#define J_UNAUTHORIZED     "{\"error\":\"unauthorized\"}"
#define J_INVALID_REQUEST  "{\"error\":\"invalid_request\"}"
#define J_UNSUPPORTED_GT   "{\"error\":\"unsupported_grant_type\"}"
#define J_INVALID_SCOPE    "{\"error\":\"invalid_scope\"}"
#define J_SERVER_ERROR     "{\"error\":\"server_error\"}"

    /* Require configured macaroon secret */
    if (conf->token_macaroon_secret.len == 0) {
        rc = send_json(r, NGX_HTTP_NOT_FOUND,
                       J_NOT_CONFIGURED, sizeof(J_NOT_CONFIGURED) - 1);
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /* Require authentication — anonymous requests cannot obtain tokens */
    if (ctx == NULL || !ctx->verified) {
        rc = send_json(r, NGX_HTTP_UNAUTHORIZED,
                       J_UNAUTHORIZED, sizeof(J_UNAUTHORIZED) - 1);
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /* Read body into a contiguous buffer (form POST bodies are small) */
    if (xrootd_http_body_read_all(r, 65536, &body, &body_len) != NGX_OK
        || body == NULL || body_len == 0)
    {
        rc = send_json(r, NGX_HTTP_BAD_REQUEST,
                       J_INVALID_REQUEST, sizeof(J_INVALID_REQUEST) - 1);
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /* Parse grant_type — must be "client_credentials" per RFC 6749 */
    if (form_find((const char *) body, "grant_type",
                  grant_type, sizeof(grant_type)) != NGX_OK
        || strcmp(grant_type, "client_credentials") != 0)
    {
        rc = send_json(r, NGX_HTTP_BAD_REQUEST,
                       J_UNSUPPORTED_GT, sizeof(J_UNSUPPORTED_GT) - 1);
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /* Parse scope — required */
    if (form_find((const char *) body, "scope",
                  scope_str, sizeof(scope_str)) != NGX_OK
        || scope_str[0] == '\0')
    {
        rc = send_json(r, NGX_HTTP_BAD_REQUEST,
                       J_INVALID_SCOPE, sizeof(J_INVALID_SCOPE) - 1);
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /* expire_in is optional; default 3600 seconds, cap at 30 days */
    expire_in = 3600;
    if (form_find((const char *) body, "expire_in",
                  expire_str, sizeof(expire_str)) == NGX_OK
        && expire_str[0] != '\0')
    {
        long v = atol(expire_str);
        if (v > 0 && v <= 86400L * 30) expire_in = v;
    }

    /* Map WLCG scope to macaroon activities + path */
    if (scope_to_activities(scope_str, activities, sizeof(activities),
                            path, sizeof(path)) != NGX_OK)
    {
        rc = send_json(r, NGX_HTTP_BAD_REQUEST,
                       J_INVALID_SCOPE, sizeof(J_INVALID_SCOPE) - 1);
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /* Parse hex secret into binary key material */
    key_len = xrootd_macaroon_secret_parse(
        (const char *) conf->token_macaroon_secret.data,
        conf->token_macaroon_secret.len,
        root_key, sizeof(root_key));
    if (key_len <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "macaroon_endpoint: failed to parse macaroon secret");
        rc = send_json(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                       J_SERVER_ERROR, sizeof(J_SERVER_ERROR) - 1);
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /* Generate a unique identifier: "v=1;t=<unix>;n=<16-hex-random>" */
    {
        u_char rand_bytes[8];
        time_t now = (time_t) ngx_time();

        if (RAND_bytes(rand_bytes, (int) sizeof(rand_bytes)) != 1) {
            /* Fallback: mix time and request pointer for pseudo-random */
            ngx_uint_t seed = (ngx_uint_t) now ^ (ngx_uint_t)(uintptr_t) r;
            size_t i;
            for (i = 0; i < sizeof(rand_bytes); i++) {
                seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
                rand_bytes[i] = (u_char)(seed >> 56);
            }
        }
        snprintf(identifier, sizeof(identifier) - 1,
                 "v=1;t=%ld;n=%02x%02x%02x%02x%02x%02x%02x%02x",
                 (long) now,
                 (unsigned) rand_bytes[0], (unsigned) rand_bytes[1],
                 (unsigned) rand_bytes[2], (unsigned) rand_bytes[3],
                 (unsigned) rand_bytes[4], (unsigned) rand_bytes[5],
                 (unsigned) rand_bytes[6], (unsigned) rand_bytes[7]);
        identifier[sizeof(identifier) - 1] = '\0';
    }

    /*
     * Build the macaroon "location".  When an issuer is configured
     * (xrootd_webdav_token_issuer), stamp THAT as the location: validation pins a
     * macaroon's location to the configured issuer (issuer-pinning, fail-closed —
     * src/token/validate.c), so a Host-derived location would make our own issued
     * macaroon fail re-validation on this very server.  Fall back to the Host
     * header only when no issuer is pinned.
     */
    if (conf->token_issuer.len > 0
        && conf->token_issuer.len < sizeof(location))
    {
        ngx_memcpy(location, conf->token_issuer.data, conf->token_issuer.len);
        location[conf->token_issuer.len] = '\0';
    } else {
        const char *scheme = (r->connection->ssl != NULL) ? "https" : "http";
        u_char     *p;

        if (r->headers_in.host != NULL) {
            p = ngx_snprintf((u_char *) location, sizeof(location) - 1,
                             "%s://%V", scheme,
                             &r->headers_in.host->value);
        } else {
            p = ngx_snprintf((u_char *) location, sizeof(location) - 1,
                             "%s://localhost", scheme);
        }
        *p = '\0';
    }

    expiry = (time_t) ngx_time() + (time_t) expire_in;

    /* Issue the signed token */
    if (xrootd_macaroon_issue(r->connection->log,
                              root_key, (size_t) key_len,
                              location, identifier,
                              activities, path, expiry,
                              token_out, sizeof(token_out)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "macaroon_endpoint: token issuance failed");
        rc = send_json(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                       J_SERVER_ERROR, sizeof(J_SERVER_ERROR) - 1);
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    /* Build JSON response matching XrdMacaroons convention:
     * {"token":"<b64url>","expires_in":<N>,"token_type":"bearer"} */
    n = snprintf(json, sizeof(json) - 1,
                 "{\"token\":\"%s\",\"expires_in\":%ld,\"token_type\":\"bearer\"}",
                 token_out, expire_in);
    if (n < 0) n = 0;

    rc = send_json(r, NGX_HTTP_OK, json, (size_t) n);
    webdav_metrics_finalize_request(r, rc);
}
