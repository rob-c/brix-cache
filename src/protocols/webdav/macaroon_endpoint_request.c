/*
 * macaroon_endpoint_request.c — dCache-style POST macaroon-request handler.
 *
 * Split out of macaroon_endpoint.c (mechanical file-size split, zero behavior
 * change): the dCache macaroon-request handler plus its ISO-8601 duration
 * parsing and caveats[] scanning helpers.  Shared front-gate/response helpers
 * live in macaroon_endpoint.c and are reached via macaroon_endpoint_internal.h.
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
