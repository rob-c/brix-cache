/*
 * macaroon_endpoint_oauth2.c — POST /.oauth2/token (OAuth2 client_credentials).
 *
 * Split out of macaroon_endpoint.c (mechanical file-size split, zero behavior
 * change): the OAuth2 token-issuance handler plus its form-decode and WLCG
 * scope→activity parsing helpers.  Shared front-gate/response helpers live in
 * macaroon_endpoint.c and are reached via macaroon_endpoint_internal.h.
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

#include "macaroon_endpoint_internal.h"

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
