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
 *        5. Calls brix_macaroon_issue() to build the signed token.
 *        6. Returns JSON {token, expires_in, token_type} per XrdMacaroons convention.
 */

#include "webdav.h"
#include "auth/token/macaroon.h"
#include "auth/token/macaroon_issue.h"
#include "core/compat/log_diag.h"
#include "core/http/http_body.h"
#include "core/compat/json_min.h"

#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* URL-form decoding */
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

/* Scope → activity mapping */

/*
 * mac_scope_activity_map — WLCG storage.* scope keyword → macaroon activity.
 *
 * WHAT: descriptor table driving scope_to_activities.
 * WHY: table-driven lookup keeps the scope parser free of a strcmp ladder.
 * HOW: exact-match linear scan; unknown scopes map to NULL and are skipped.
 */
static const struct {
    const char *scope;
    const char *activity;
} mac_scope_activity_map[] = {
    { "storage.read",   "DOWNLOAD" },
    { "storage.write",  "UPLOAD"   },
    { "storage.create", "UPLOAD"   },
    { "storage.modify", "MANAGE"   },
    { "storage.stage",  "STAGE"    },
    { "storage.delete", "DELETE"   },
    { "storage.list",   "LIST"     },
};

/*
 * mac_scope_activity — map one scope keyword to its activity name via the
 * descriptor table.  Returns NULL for unrecognised scopes (caller skips).
 */
static const char *
mac_scope_activity(const char *scope_item)
{
    size_t i;
    size_t n = sizeof(mac_scope_activity_map) / sizeof(mac_scope_activity_map[0]);

    for (i = 0; i < n; i++) {
        if (strcmp(scope_item, mac_scope_activity_map[i].scope) == 0) {
            return mac_scope_activity_map[i].activity;
        }
    }
    return NULL;
}

/*
 * mac_act_append — append one activity to the comma-joined list in act_buf.
 * Returns NGX_ERROR when the activity would not fit (caller stops scanning,
 * matching the original overflow behaviour); NGX_OK on success.
 */
static ngx_int_t
mac_act_append(char *act_buf, size_t act_sz, size_t *act_len,
               const char *activity)
{
    size_t alen = strlen(activity);
    size_t cur  = *act_len;

    if (cur + (cur > 0 ? 1 : 0) + alen + 1 > act_sz) {
        return NGX_ERROR;
    }
    if (cur > 0) {
        act_buf[cur++] = ',';
    }
    ngx_memcpy(act_buf + cur, activity, alen);
    cur += alen;
    act_buf[cur] = '\0';
    *act_len = cur;
    return NGX_OK;
}

/*
 * mac_path_capture — record the first non-empty scope path into path_buf
 * (bounded copy); later paths are ignored (first one wins).
 */
static void
mac_path_capture(char *path_buf, size_t path_sz, const char *path)
{
    size_t plen;

    if (path_buf[0] || !path[0]) {
        return;
    }
    plen = strlen(path);
    if (plen >= path_sz) plen = path_sz - 1;
    ngx_memcpy(path_buf, path, plen);
    path_buf[plen] = '\0';
}

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

        if (colon == NULL) continue;
        *colon = '\0';

        activity = mac_scope_activity(token);
        if (activity == NULL) continue;

        if (mac_act_append(act_buf, act_sz, &act_len, activity) != NGX_OK) {
            break;
        }
        mac_path_capture(path_buf, path_sz, colon + 1);
        found = 1;
    }

    if (!found) return NGX_DECLINED;
    if (!path_buf[0]) {
        path_buf[0] = '/';
        path_buf[1] = '\0';
    }
    return NGX_OK;
}

/* Helper: send a JSON body */
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

/* Canned JSON bodies shared by both issuance endpoints */
#define J_NOT_CONFIGURED   "{\"error\":\"not_configured\"}"
#define J_UNAUTHORIZED     "{\"error\":\"unauthorized\"}"
#define J_INVALID_REQUEST  "{\"error\":\"invalid_request\"}"
#define J_UNSUPPORTED_GT   "{\"error\":\"unsupported_grant_type\"}"
#define J_INVALID_SCOPE    "{\"error\":\"invalid_scope\"}"
#define J_SERVER_ERROR     "{\"error\":\"server_error\"}"

/*
 * mac_respond — emit a JSON body and finalize request metrics.
 * WHY: every response path in both issuance handlers ends the same way;
 * folding the pair into one call keeps the handlers early-return flat.
 */
static void
mac_respond(ngx_http_request_t *r, ngx_int_t status,
            const char *json, size_t json_len)
{
    ngx_int_t rc = send_json(r, status, json, json_len);

    webdav_metrics_finalize_request(r, rc);
}

/*
 * mac_gate_and_read_body — shared front gate for both issuance endpoints:
 * (1) a macaroon secret must be configured (else 404 not_configured),
 * (2) the caller must be authenticated (else 401 unauthorized),
 * (3) the request body must read into a contiguous buffer (else 400).
 * Sends the rejection itself; returns NGX_OK only when the handler may
 * proceed.  SECURITY: the check order is load-bearing — do not reorder.
 */
static ngx_int_t
mac_gate_and_read_body(ngx_http_request_t *r,
                       ngx_http_brix_webdav_loc_conf_t *conf,
                       size_t max_body, u_char **body, size_t *body_len)
{
    ngx_http_brix_webdav_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    /* Require configured macaroon secret */
    if (conf->token_macaroon_secret.len == 0) {
        mac_respond(r, NGX_HTTP_NOT_FOUND,
                    J_NOT_CONFIGURED, sizeof(J_NOT_CONFIGURED) - 1);
        return NGX_ERROR;
    }

    /* Require authentication — anonymous requests cannot obtain tokens */
    if (ctx == NULL || !ctx->verified) {
        mac_respond(r, NGX_HTTP_UNAUTHORIZED,
                    J_UNAUTHORIZED, sizeof(J_UNAUTHORIZED) - 1);
        return NGX_ERROR;
    }

    /* Read body into a contiguous buffer (token POST bodies are small) */
    if (brix_http_body_read_all(r, max_body, body, body_len) != NGX_OK
        || *body == NULL || *body_len == 0)
    {
        mac_respond(r, NGX_HTTP_BAD_REQUEST,
                    J_INVALID_REQUEST, sizeof(J_INVALID_REQUEST) - 1);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * mac_authorize — authority bound: a bearer-token caller cannot obtain a
 * macaroon that exceeds their own scope.  GSI-cert callers (token_auth == 0)
 * carry full identity-level authority and are not bounded here.
 *
 * Conservative rule: if ANY write activity (UPLOAD/MANAGE/DELETE) is
 * requested, require write scope on the target path; otherwise require
 * read scope.  This prevents a zero- or read-only-scope token from
 * delegating write rights it does not hold.  Sends the 403 itself;
 * returns NGX_OK only when issuance is authorized.
 */
static ngx_int_t
mac_authorize(ngx_http_request_t *r, const char *activities, const char *path)
{
    ngx_http_brix_webdav_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    int wants_write;
    int scope_ok;

    if (!ctx->token_auth) {
        return NGX_OK;
    }

    wants_write = (strstr(activities, "UPLOAD")  != NULL
                   || strstr(activities, "MANAGE") != NULL
                   || strstr(activities, "DELETE") != NULL);

    if (ctx->identity != NULL) {
        scope_ok = (brix_identity_check_token_scope(ctx->identity,
                                                     path, wants_write)
                    == NGX_OK);
    } else {
        scope_ok = wants_write
            ? brix_token_check_write(ctx->token_scopes,
                                      ctx->token_scope_count, path)
            : brix_token_check_read(ctx->token_scopes,
                                     ctx->token_scope_count, path);
    }

    if (scope_ok) {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "macaroon_endpoint: token scope insufficient for"
                  " activities \"%s\" on \"%s\" — issue denied",
                  activities, path);
    mac_respond(r, NGX_HTTP_FORBIDDEN,
                J_UNAUTHORIZED, sizeof(J_UNAUTHORIZED) - 1);
    return NGX_ERROR;
}

/*
 * mac_make_identifier — build the unique macaroon identifier
 * "v=1;t=<unix>;n=<16-hex-random>".  Falls back to a time/pointer-seeded
 * LCG when RAND_bytes fails (identifier uniqueness, not secrecy, is the
 * goal — the signature carries the security).
 */
static void
mac_make_identifier(ngx_http_request_t *r, char *identifier, size_t idsz)
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
    snprintf(identifier, idsz - 1,
             "v=1;t=%ld;n=%02x%02x%02x%02x%02x%02x%02x%02x",
             (long) now,
             (unsigned) rand_bytes[0], (unsigned) rand_bytes[1],
             (unsigned) rand_bytes[2], (unsigned) rand_bytes[3],
             (unsigned) rand_bytes[4], (unsigned) rand_bytes[5],
             (unsigned) rand_bytes[6], (unsigned) rand_bytes[7]);
    identifier[idsz - 1] = '\0';
}

/*
 * mac_build_location — build the macaroon "location".  When an issuer is
 * configured (brix_webdav_token_issuer), stamp THAT as the location:
 * validation pins a macaroon's location to the configured issuer
 * (issuer-pinning, fail-closed — src/token/validate.c), so a Host-derived
 * location would make our own issued macaroon fail re-validation on this
 * very server.  The dCache endpoint additionally honours the configured
 * macaroon_location (allow_conf_location != 0).  Fall back to the request
 * scheme + Host header only when neither is pinned.
 */
static void
mac_build_location(ngx_http_request_t *r,
                   ngx_http_brix_webdav_loc_conf_t *conf,
                   ngx_uint_t allow_conf_location,
                   char *location, size_t locsz)
{
    const char *scheme;
    u_char     *p;

    if (conf->token_issuer.len > 0 && conf->token_issuer.len < locsz) {
        ngx_memcpy(location, conf->token_issuer.data, conf->token_issuer.len);
        location[conf->token_issuer.len] = '\0';
        return;
    }
    if (allow_conf_location
        && conf->macaroon_location.len > 0
        && conf->macaroon_location.len < locsz)
    {
        ngx_memcpy(location, conf->macaroon_location.data,
                   conf->macaroon_location.len);
        location[conf->macaroon_location.len] = '\0';
        return;
    }

    scheme = (r->connection->ssl != NULL) ? "https" : "http";
    if (r->headers_in.host != NULL) {
        p = ngx_snprintf((u_char *) location, locsz - 1,
                         "%s://%V", scheme, &r->headers_in.host->value);
    } else {
        p = ngx_snprintf((u_char *) location, locsz - 1,
                         "%s://localhost", scheme);
    }
    *p = '\0';
}

/*
 * mac_token_parse_form — decode the OAuth2 token-request form body:
 * grant_type must be "client_credentials" (RFC 6749), scope is required,
 * expire_in is optional (default 3600 seconds, capped at 30 days).
 * Sends the rejection itself; returns NGX_OK only when the fields parse.
 */
static ngx_int_t
mac_token_parse_form(ngx_http_request_t *r, const char *body,
                     char *scope_str, size_t scope_sz, long *expire_in)
{
    char grant_type[64];
    char expire_str[32];

    /* Parse grant_type — must be "client_credentials" per RFC 6749 */
    if (form_find(body, "grant_type", grant_type, sizeof(grant_type)) != NGX_OK
        || strcmp(grant_type, "client_credentials") != 0)
    {
        mac_respond(r, NGX_HTTP_BAD_REQUEST,
                    J_UNSUPPORTED_GT, sizeof(J_UNSUPPORTED_GT) - 1);
        return NGX_ERROR;
    }

    /* Parse scope — required */
    if (form_find(body, "scope", scope_str, scope_sz) != NGX_OK
        || scope_str[0] == '\0')
    {
        mac_respond(r, NGX_HTTP_BAD_REQUEST,
                    J_INVALID_SCOPE, sizeof(J_INVALID_SCOPE) - 1);
        return NGX_ERROR;
    }

    /* expire_in is optional; default 3600 seconds, cap at 30 days */
    *expire_in = 3600;
    if (form_find(body, "expire_in", expire_str, sizeof(expire_str)) == NGX_OK
        && expire_str[0] != '\0')
    {
        long v = atol(expire_str);
        if (v > 0 && v <= 86400L * 30) *expire_in = v;
    }
    return NGX_OK;
}

/* Discovery handler */
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

/* Issuance body handler (called when request body is ready) */
void
webdav_handle_macaroon_token(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t  *conf;
    u_char                             *body     = NULL;
    size_t                              body_len = 0;
    char                                scope_str[512];
    char                                activities[128];
    char                                path[256];
    u_char                              root_key[64];
    ssize_t                             key_len;
    char                                identifier[96];
    char                                location[256];
    char                                token_out[BRIX_MACAROON_ISSUE_OUT_MAX];
    char                                json[BRIX_MACAROON_ISSUE_OUT_MAX + 128];
    long                                expire_in;
    time_t                              expiry;
    int                                 n;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    /* Secret configured + authenticated + body read (order load-bearing) */
    if (mac_gate_and_read_body(r, conf, 65536, &body, &body_len) != NGX_OK) {
        return;
    }

    /* grant_type / scope / expire_in (form POST bodies are small) */
    if (mac_token_parse_form(r, (const char *) body,
                             scope_str, sizeof(scope_str),
                             &expire_in) != NGX_OK)
    {
        return;
    }

    /* Map WLCG scope to macaroon activities + path */
    if (scope_to_activities(scope_str, activities, sizeof(activities),
                            path, sizeof(path)) != NGX_OK)
    {
        mac_respond(r, NGX_HTTP_BAD_REQUEST,
                    J_INVALID_SCOPE, sizeof(J_INVALID_SCOPE) - 1);
        return;
    }

    /* Bearer-token callers cannot exceed their own scope */
    if (mac_authorize(r, activities, path) != NGX_OK) {
        return;
    }

    /* Parse hex secret into binary key material */
    key_len = brix_macaroon_secret_parse(
        (const char *) conf->token_macaroon_secret.data,
        conf->token_macaroon_secret.len,
        root_key, sizeof(root_key));
    if (key_len <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "macaroon_endpoint: failed to parse macaroon secret");
        mac_respond(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                    J_SERVER_ERROR, sizeof(J_SERVER_ERROR) - 1);
        return;
    }

    /* Unique identifier + issuer-pinned location (see mac_build_location) */
    mac_make_identifier(r, identifier, sizeof(identifier));
    mac_build_location(r, conf, 0, location, sizeof(location));

    expiry = (time_t) ngx_time() + (time_t) expire_in;

    /* Issue the signed token */
    if (brix_macaroon_issue(r->connection->log,
                              root_key, (size_t) key_len,
                              location, identifier,
                              activities, path, expiry,
                              token_out, sizeof(token_out)) != NGX_OK)
    {
        BRIX_DIAG_ERR(r->connection->log, 0,
            "macaroon_endpoint: could not issue the requested macaroon",
            "the macaroon signing key is missing or invalid, so tokens "
            "cannot be minted",
            "ensure the macaroon secret/signing key is configured and "
            "readable; clients are getting 500 until it is fixed");
        mac_respond(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                    J_SERVER_ERROR, sizeof(J_SERVER_ERROR) - 1);
        return;
    }

    /* Build JSON response matching XrdMacaroons convention:
     * {"token":"<b64url>","expires_in":<N>,"token_type":"bearer"} */
    n = snprintf(json, sizeof(json) - 1,
                 "{\"token\":\"%s\",\"expires_in\":%ld,\"token_type\":\"bearer\"}",
                 token_out, expire_in);
    if (n < 0) n = 0;

    mac_respond(r, NGX_HTTP_OK, json, (size_t) n);
}


/*
 * mac_iso_component — parse one "<digits><unit>" duration component of a
 * restricted ISO-8601 duration at s[*ip] and accumulate its seconds into
 * *total.  Units D/H/M/S only; both the digit run and the running total are
 * overflow-checked.  Advances *ip past the unit letter.  Returns NGX_OK /
 * NGX_ERROR.  Pure helper for mac_iso8601_secs — code motion only.
 */
static ngx_int_t
mac_iso_component(const char *s, size_t len, size_t *ip, uint64_t *total)
{
    size_t   i = *ip;
    uint64_t v = 0;
    size_t   digits = 0;

    while (i < len && s[i] >= '0' && s[i] <= '9') {
        if (v > (UINT64_MAX - 9) / 10) { return NGX_ERROR; }
        v = v * 10 + (uint64_t) (s[i] - '0');
        i++; digits++;
    }
    if (digits == 0 || i >= len) { return NGX_ERROR; }
    switch (s[i]) {
    case 'D': *total += v * 86400; break;
    case 'H': *total += v * 3600;  break;
    case 'M': *total += v * 60;    break;
    case 'S': *total += v;         break;
    default:  return NGX_ERROR;
    }
    if (*total > (uint64_t) 0x7fffffffffffffffLL) { return NGX_ERROR; }
    *ip = i + 1;
    return NGX_OK;
}

/*
 * mac_iso8601_secs — parse a restricted ISO-8601 duration ("PT1H","PT30M","P1D",
 * "PT3600S") to seconds, clamped to [1,max]. Returns NGX_OK / NGX_ERROR. Units
 * D/H/M/S only (W/Y/Mo unsupported — WLCG macaroons use these). EITHER.
 */
static ngx_int_t
mac_iso8601_secs(const char *s, size_t len, time_t max, time_t *out)
{
    size_t   i = 0;
    uint64_t total = 0;
    int      saw_unit = 0;

    if (s == NULL || out == NULL || len == 0) {
        return NGX_ERROR;
    }
    if (s[i] == 'P') { i++; }
    if (i < len && s[i] == 'T') { i++; }
    while (i < len) {
        if (mac_iso_component(s, len, &i, &total) != NGX_OK) {
            return NGX_ERROR;
        }
        saw_unit = 1;
    }
    if (!saw_unit) { return NGX_ERROR; }
    if (total == 0) { total = 1; }
    if ((time_t) total > max) { total = (uint64_t) max; }
    *out = (time_t) total;
    return NGX_OK;
}

/*
 * mac_caveats_t — output sink for mac_caveats_scan: the two bounded caller
 * buffers (comma-joined activity list + caveat path) bundled so the scan
 * helpers stay under the parameter cap.
 */
typedef struct {
    char   *act;
    size_t  actsz;
    char   *path;
    size_t  pathsz;
} mac_caveats_t;

/*
 * mac_caveat_apply — classify one "..." caveat array element:
 * "activity:<csv>" is accumulated (comma-joined) into out->act,
 * "path:<abs>" overwrites out->path (last one wins).  Unknown caveat
 * kinds are ignored.  Bounded copies only — code motion from the scan.
 */
static void
mac_caveat_apply(const u_char *p, size_t elen, mac_caveats_t *out)
{
    if (elen > 9
        && ngx_strncasecmp((u_char *) p, (u_char *) "activity:", 9) == 0)
    {
        size_t cur = ngx_strlen(out->act);
        size_t cp, room;
        if (cur > 0 && cur + 1 < out->actsz) { out->act[cur++] = ','; }
        cp   = elen - 9;
        room = (cur < out->actsz) ? out->actsz - cur - 1 : 0;
        if (cp > room) { cp = room; }
        ngx_memcpy(out->act + cur, p + 9, cp);
        out->act[cur + cp] = '\0';
    } else if (elen > 5
               && ngx_strncasecmp((u_char *) p, (u_char *) "path:", 5) == 0)
    {
        size_t cp = elen - 5;
        if (cp > out->pathsz - 1) { cp = out->pathsz - 1; }
        ngx_memcpy(out->path, p + 5, cp);
        out->path[cp] = '\0';
    }
}

/*
 * mac_caveats_scan — extract activity/path caveats from a dCache request body's
 * "caveats":["activity:DOWNLOAD,LIST","path:/foo"] array. json_min has no array
 * support, so this is a bounded string scan: for each "..." element it recognises
 * "activity:<csv>" (accumulated, comma-joined into out->act) and "path:<abs>"
 * (last one wins into out->path). Tolerant of whitespace; unknown caveat kinds
 * ignored. EITHER.
 */
static void
mac_caveats_scan(const char *body, size_t len, mac_caveats_t *out)
{
    const u_char *p   = (const u_char *) body;
    const u_char *end = p + len;
    const u_char *arr;

    out->act[0]  = '\0';
    out->path[0] = '\0';
    arr = ngx_strlcasestrn((u_char *) p, (u_char *) end,
                           (u_char *) "\"caveats\"", sizeof("\"caveats\"") - 2);
    if (arr == NULL) {
        return;
    }
    p = ngx_strlchr((u_char *) arr, (u_char *) end, '[');
    if (p == NULL) {
        return;
    }
    p++;
    while (p < end && *p != ']') {
        const u_char *q;
        if (*p != '"') { p++; continue; }
        q = ++p;
        while (q < end && *q != '"') { q++; }
        if (q >= end) { break; }
        mac_caveat_apply(p, (size_t) (q - p), out);
        p = q + 1;
    }
}

/*
 * mac_request_respond — build and send the dCache issuance response:
 * {macaroon, uri{target,targetWithMacaroon,base,baseWithMacaroon}}.
 * Response-assembly order is frozen (behavioral freeze) — code motion only.
 */
static void
mac_request_respond(ngx_http_request_t *r, const char *token_out)
{
    char        json[BRIX_MACAROON_ISSUE_OUT_MAX + 768];
    const char *scheme;
    ngx_str_t   host;
    int         n;

    scheme = (r->connection->ssl != NULL) ? "https" : "http";
    if (r->headers_in.host != NULL) {
        host = r->headers_in.host->value;
    } else {
        ngx_str_set(&host, "localhost");
    }
    n = (int) (ngx_snprintf((u_char *) json, sizeof(json) - 1,
        "{\"macaroon\":\"%s\",\"uri\":{"
        "\"target\":\"%s://%V%V\","
        "\"targetWithMacaroon\":\"%s://%V%V?authz=%s\","
        "\"base\":\"%s://%V/\","
        "\"baseWithMacaroon\":\"%s://%V/?authz=%s\"}}",
        token_out,
        scheme, &host, &r->uri,
        scheme, &host, &r->uri, token_out,
        scheme, &host,
        scheme, &host, token_out) - (u_char *) json);
    if (n < 0) { n = 0; }
    mac_respond(r, NGX_HTTP_OK, json, (size_t) n);
}

void
webdav_handle_macaroon_request(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    u_char        *body = NULL;
    size_t         body_len = 0;
    u_char         root_key[64];
    ssize_t        key_len;
    char           activities[128];
    char           cav_path[1024];
    char           location[256];
    char           identifier[96];
    char           token_out[BRIX_MACAROON_ISSUE_OUT_MAX];
    time_t         validity = 0, exp;
    mac_caveats_t  cavs;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    /* Secret configured + authenticated + body read (order load-bearing) */
    if (mac_gate_and_read_body(r, conf, 16384, &body, &body_len) != NGX_OK) {
        return;
    }

    /* caveats[] → activities + path (default base = request path). */
    cavs.act    = activities;
    cavs.actsz  = sizeof(activities);
    cavs.path   = cav_path;
    cavs.pathsz = sizeof(cav_path);
    mac_caveats_scan((const char *) body, body_len, &cavs);
    if (cav_path[0] == '\0') {
        size_t cp = ngx_min(r->uri.len, sizeof(cav_path) - 1);
        ngx_memcpy(cav_path, r->uri.data, cp);
        cav_path[cp] = '\0';
    }

    /* Bearer-token callers cannot exceed their own scope.  When activities
     * is empty the issued macaroon carries no activity restriction, so we
     * still require at least read scope on the base path to prevent
     * zero-scope tokens from issuing unconstrained macaroons. */
    if (mac_authorize(r, activities, cav_path) != NGX_OK) {
        return;
    }

    /* validity (ISO-8601) → seconds, clamped to the configured max. */
    {
        char vbuf[32];
        if (brix_json_get_str((const char *) body, body_len, "validity",
                                vbuf, sizeof(vbuf)) > 0)
        {
            (void) mac_iso8601_secs(vbuf, ngx_strlen(vbuf),
                                    (time_t) conf->macaroon_max_validity,
                                    &validity);
        }
    }
    if (validity <= 0) { validity = (time_t) conf->macaroon_max_validity; }
    exp = (time_t) ngx_time() + validity;

    /* Unique identifier "v=1;t=<unix>;n=<16-hex-random>" (same scheme as the
     * OAuth2 path — brix_macaroon_issue requires a non-NULL identifier). */
    mac_make_identifier(r, identifier, sizeof(identifier));

    key_len = brix_macaroon_secret_parse(
        (const char *) conf->token_macaroon_secret.data,
        conf->token_macaroon_secret.len, root_key, sizeof(root_key));
    if (key_len <= 0) {
        mac_respond(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                    J_SERVER_ERROR, sizeof(J_SERVER_ERROR) - 1);
        return;
    }

    /* location: pin to the configured issuer (else macaroon_location, else
     * Host) — same rule as the OAuth2 path so our own macaroon re-validates
     * here. */
    mac_build_location(r, conf, 1, location, sizeof(location));

    if (brix_macaroon_issue(r->connection->log, root_key, (size_t) key_len,
                              location, identifier,
                              activities[0] ? activities : NULL,
                              cav_path, exp, token_out, sizeof(token_out)) != NGX_OK)
    {
        mac_respond(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                    J_SERVER_ERROR, sizeof(J_SERVER_ERROR) - 1);
        return;
    }

    /* dCache response: {macaroon, uri{target,targetWithMacaroon,base,baseWithMacaroon}} */
    mac_request_respond(r, token_out);
}
