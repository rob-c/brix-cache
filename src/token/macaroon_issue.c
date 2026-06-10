/*
 * macaroon_issue.c — WLCG macaroon token issuance.
 *
 * WHAT: Mints new single-root macaroon tokens by constructing the binary
 *       packet sequence (location, identifier, first-party caveats, signature),
 *       computing the HMAC-SHA256 chain, and base64url-encoding the result.
 *
 * WHY: The existing macaroon.c only validates tokens. The macaroon issuance
 *      endpoint (POST /.oauth2/token) needs to mint new tokens for WLCG
 *      third-party delegation — a client authenticates, requests a scoped token,
 *      and the server issues a macaroon that can be delegated to a TPC agent.
 *
 * HOW: Packet wire format: [4-hex plen][label][ ][value][\n]
 *      where plen includes the 4 hex chars. The signature packet omits the
 *      trailing newline (matches XrdMacaroons convention and the test helper).
 *      HMAC chain: sig = HMAC(root_key, identifier_value), then for each
 *      first-party caveat: sig = HMAC(sig, caveat_value). The location packet
 *      is informational only and does not enter the HMAC chain.
 */

#include "macaroon_issue.h"
#include "b64url.h"

#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ISSUE_BIN_MAX  4096

/*
 * write_packet — append one macaroon packet to the output buffer.
 *
 * Format: [4-hex plen][label][ ][value][\n]  (newline added when add_newline=1)
 * plen counts all bytes including the 4-hex prefix itself.
 *
 * Updates *buf and *rem. Returns bytes written, or -1 on overflow.
 */
static int
write_packet(u_char **buf, size_t *rem,
             const char *label, size_t label_len,
             const u_char *value, size_t val_len,
             int add_newline)
{
    size_t plen = 4 + label_len + 1 + val_len + (size_t)(add_newline ? 1 : 0);
    char   hexlen[5];

    if (plen > *rem || plen > 0xFFFF) {
        return -1;
    }

    snprintf(hexlen, sizeof(hexlen), "%04x", (unsigned int) plen);
    ngx_memcpy(*buf, hexlen, 4);
    *buf += 4;
    ngx_memcpy(*buf, label, label_len);
    *buf += label_len;
    **buf = ' ';
    (*buf)++;
    ngx_memcpy(*buf, value, val_len);
    *buf += val_len;
    if (add_newline) {
        **buf = '\n';
        (*buf)++;
    }
    *rem -= plen;
    return (int) plen;
}

ngx_int_t
xrootd_macaroon_issue(ngx_log_t *log,
    const u_char *root_key, size_t root_key_len,
    const char *location,
    const char *identifier,
    const char *activities,
    const char *path,
    time_t expiry,
    char *out_b64, size_t out_b64sz)
{
    u_char        bin[ISSUE_BIN_MAX];
    u_char       *p;
    size_t        rem;
    u_char        sig[32];
    unsigned int  sig_len = 32;

    if (!identifier || !identifier[0] || !root_key || root_key_len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "macaroon_issue: missing identifier or root key");
        return NGX_ERROR;
    }
    if (out_b64sz < XROOTD_MACAROON_ISSUE_OUT_MAX) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "macaroon_issue: output buffer too small");
        return NGX_ERROR;
    }

    p   = bin;
    rem = sizeof(bin);

    /* location packet — informational only, does not update HMAC chain */
    if (location && location[0]) {
        if (write_packet(&p, &rem, "location", 8,
                         (const u_char *) location, strlen(location), 1) < 0)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0, "macaroon_issue: buffer overflow");
            return NGX_ERROR;
        }
    }

    /* identifier packet — initialises the HMAC chain */
    {
        size_t idlen = strlen(identifier);
        if (write_packet(&p, &rem, "identifier", 10,
                         (const u_char *) identifier, idlen, 1) < 0)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0, "macaroon_issue: buffer overflow");
            return NGX_ERROR;
        }
        /* sig = HMAC(root_key, identifier_value) */
        HMAC(EVP_sha256(), root_key, (int) root_key_len,
             (const u_char *) identifier, (int) idlen, sig, &sig_len);
    }

    /* activity: caveat — WLCG activity list (e.g. "DOWNLOAD,LIST") */
    if (activities && activities[0]) {
        char   act_cav[128];
        size_t act_len;
        u_char next_sig[32];

        act_len = (size_t) snprintf(act_cav, sizeof(act_cav),
                                    "activity:%s", activities);
        if (act_len >= sizeof(act_cav)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "macaroon_issue: activity caveat too long");
            return NGX_ERROR;
        }
        if (write_packet(&p, &rem, "cid", 3,
                         (const u_char *) act_cav, act_len, 1) < 0)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0, "macaroon_issue: buffer overflow");
            return NGX_ERROR;
        }
        /* sig = HMAC(sig, caveat_value) */
        HMAC(EVP_sha256(), sig, 32, (const u_char *) act_cav, (int) act_len,
             next_sig, &sig_len);
        ngx_memcpy(sig, next_sig, 32);
    }

    /* path: caveat — path prefix constraint */
    if (path && path[0]) {
        char   path_cav[1024];
        size_t path_cav_len;
        u_char next_sig[32];

        path_cav_len = (size_t) snprintf(path_cav, sizeof(path_cav),
                                          "path:%s", path);
        if (path_cav_len >= sizeof(path_cav)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "macaroon_issue: path caveat too long");
            return NGX_ERROR;
        }
        if (write_packet(&p, &rem, "cid", 3,
                         (const u_char *) path_cav, path_cav_len, 1) < 0)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0, "macaroon_issue: buffer overflow");
            return NGX_ERROR;
        }
        HMAC(EVP_sha256(), sig, 32,
             (const u_char *) path_cav, (int) path_cav_len,
             next_sig, &sig_len);
        ngx_memcpy(sig, next_sig, 32);
    }

    /* before: caveat — expiry in ISO8601 UTC */
    if (expiry > 0) {
        char      exp_cav[64];
        size_t    exp_cav_len;
        u_char    next_sig[32];
        struct tm tm_val;

        gmtime_r(&expiry, &tm_val);
        exp_cav_len = (size_t) snprintf(exp_cav, sizeof(exp_cav),
            "before:%04d-%02d-%02dT%02d:%02d:%02dZ",
            tm_val.tm_year + 1900, tm_val.tm_mon + 1, tm_val.tm_mday,
            tm_val.tm_hour, tm_val.tm_min, tm_val.tm_sec);
        if (exp_cav_len >= sizeof(exp_cav)) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "macaroon_issue: expiry caveat overflow");
            return NGX_ERROR;
        }
        if (write_packet(&p, &rem, "cid", 3,
                         (const u_char *) exp_cav, exp_cav_len, 1) < 0)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0, "macaroon_issue: buffer overflow");
            return NGX_ERROR;
        }
        HMAC(EVP_sha256(), sig, 32,
             (const u_char *) exp_cav, (int) exp_cav_len,
             next_sig, &sig_len);
        ngx_memcpy(sig, next_sig, 32);
    }

    /* signature packet: [4-hex plen]["signature "][32 raw bytes]
     * No trailing newline — matches XrdMacaroons wire convention. */
    {
        /* plen = 4 (hex header) + 10 ("signature ") + 32 (sig bytes) = 46 */
        size_t plen = 46;
        char   hexlen[5];

        if (plen > rem) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "macaroon_issue: buffer overflow");
            return NGX_ERROR;
        }
        snprintf(hexlen, sizeof(hexlen), "%04x", (unsigned int) plen);
        ngx_memcpy(p, hexlen, 4);
        p += 4;
        ngx_memcpy(p, "signature ", 10);
        p += 10;
        ngx_memcpy(p, sig, 32);
        p += 32;
    }

    b64url_encode((const char *) bin, (size_t)(p - bin), out_b64, out_b64sz);
    return NGX_OK;
}
