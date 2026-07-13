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
 * issue_buf_t — output buffer cursor for macaroon packet assembly.
 *
 * WHAT: Bundles the write cursor and remaining capacity so packet writers
 *       take one context parameter instead of a (buf, rem) pointer pair.
 * WHY: Keeps helper signatures at or below the 5-parameter limit and makes
 *      the shared mutable state explicit (single owner, threaded by value).
 * HOW: `p` advances as bytes are appended; `rem` decreases by the same amount.
 *      `start` is retained so the caller can compute the final packet length.
 */
typedef struct {
    u_char *start;
    u_char *p;
    size_t  rem;
} issue_buf_t;

/*
 * write_packet — append one newline-terminated macaroon packet to the buffer.
 *
 * WHAT: Emits [4-hex plen][label][ ][value][\n] into `buf`, where plen counts
 *       all bytes including the 4-hex prefix and the trailing newline.
 * WHY: Every newline-terminated macaroon element (location, identifier,
 *      caveats) shares this exact wire encoding, so a single writer preserves
 *      byte-for-byte layout. The signature packet is newline-less and has its
 *      own writer (emit_signature).
 * HOW: Compute plen, reject on overflow, then copy the fields in order and
 *      advance the cursor. Returns bytes written, or -1 on overflow.
 */
static int
write_packet(issue_buf_t *buf,
             const char *label, size_t label_len,
             const u_char *value, size_t val_len)
{
    size_t plen = 4 + label_len + 1 + val_len + 1;
    char   hexlen[5];

    if (plen > buf->rem || plen > 0xFFFF) {
        return -1;
    }

    snprintf(hexlen, sizeof(hexlen), "%04x", (unsigned int) plen);
    ngx_memcpy(buf->p, hexlen, 4);
    buf->p += 4;
    ngx_memcpy(buf->p, label, label_len);
    buf->p += label_len;
    *buf->p = ' ';
    buf->p++;
    ngx_memcpy(buf->p, value, val_len);
    buf->p += val_len;
    *buf->p = '\n';
    buf->p++;
    buf->rem -= plen;
    return (int) plen;
}

/*
 * chain_hmac — advance the macaroon HMAC-SHA256 chain by one caveat.
 *
 * WHAT: Computes sig = HMAC(sig, msg) and stores the 32-byte result back
 *       into `sig` in place.
 * WHY: Each first-party caveat re-keys the chain with the previous signature;
 *      centralising it keeps the crypto call order identical across caveats.
 * HOW: HMAC into a scratch buffer (the key aliases the output otherwise) and
 *      copy the 32 bytes back over `sig`.
 */
static void
chain_hmac(u_char sig[32], const u_char *msg, size_t msg_len)
{
    u_char       next_sig[32];
    unsigned int next_len = 32;

    HMAC(EVP_sha256(), sig, 32, msg, (int) msg_len, next_sig, &next_len);
    ngx_memcpy(sig, next_sig, 32);
}

/*
 * emit_cid_caveat — write one "cid" caveat packet and extend the HMAC chain.
 *
 * WHAT: Appends the caveat value as a cid packet and folds it into `sig`.
 * WHY: The activity, path, and before caveats differ only in how their value
 *      string is formatted; this helper unifies the write-then-chain step.
 * HOW: write_packet (with newline) then chain_hmac over the same value bytes,
 *      preserving the original per-caveat order. Returns NGX_OK or NGX_ERROR.
 */
static ngx_int_t
emit_cid_caveat(issue_buf_t *buf, u_char sig[32],
                const char *cav, size_t cav_len, ngx_log_t *log)
{
    if (write_packet(buf, "cid", 3, (const u_char *) cav, cav_len) < 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "macaroon_issue: buffer overflow");
        return NGX_ERROR;
    }
    chain_hmac(sig, (const u_char *) cav, cav_len);
    return NGX_OK;
}

/*
 * emit_location — append the informational location packet (no HMAC chaining).
 *
 * WHAT: Writes the location: packet when a non-empty location is supplied.
 * WHY: The location is advisory metadata and must NOT enter the HMAC chain,
 *      so it is handled separately from the caveat helpers.
 * HOW: Skip when absent; otherwise write_packet with a trailing newline.
 *      Returns NGX_OK (including the skipped case) or NGX_ERROR on overflow.
 */
static ngx_int_t
emit_location(issue_buf_t *buf, const char *location, ngx_log_t *log)
{
    if (!location || !location[0]) {
        return NGX_OK;
    }
    if (write_packet(buf, "location", 8,
                     (const u_char *) location, strlen(location)) < 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "macaroon_issue: buffer overflow");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * emit_identifier — append the identifier packet and seed the HMAC chain.
 *
 * WHAT: Writes the identifier: packet and initialises sig = HMAC(root_key, id).
 * WHY: The identifier both appears on the wire and roots the signature chain;
 *      it is the one element keyed by the root key rather than by a prior sig.
 * HOW: write_packet (with newline), then a single HMAC keyed by root_key.
 *      Returns NGX_OK or NGX_ERROR on overflow.
 */
static ngx_int_t
emit_identifier(issue_buf_t *buf, u_char sig[32],
                const u_char *root_key, size_t root_key_len,
                const char *identifier, ngx_log_t *log)
{
    size_t       idlen = strlen(identifier);
    unsigned int sig_len = 32;

    if (write_packet(buf, "identifier", 10,
                     (const u_char *) identifier, idlen) < 0)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "macaroon_issue: buffer overflow");
        return NGX_ERROR;
    }
    /* sig = HMAC(root_key, identifier_value) */
    HMAC(EVP_sha256(), root_key, (int) root_key_len,
         (const u_char *) identifier, (int) idlen, sig, &sig_len);
    return NGX_OK;
}

/*
 * emit_activity_caveat — append the WLCG "activity:" caveat if requested.
 *
 * WHAT: Formats "activity:<activities>" and emits it as a cid caveat.
 * WHY: Encodes the granted WLCG activity list (e.g. "DOWNLOAD,LIST").
 * HOW: snprintf into a fixed buffer, guard against truncation, then delegate
 *      to emit_cid_caveat. Skips silently when no activities are supplied.
 */
static ngx_int_t
emit_activity_caveat(issue_buf_t *buf, u_char sig[32],
                     const char *activities, ngx_log_t *log)
{
    char   act_cav[128];
    size_t act_len;

    if (!activities || !activities[0]) {
        return NGX_OK;
    }
    act_len = (size_t) snprintf(act_cav, sizeof(act_cav),
                                "activity:%s", activities);
    if (act_len >= sizeof(act_cav)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "macaroon_issue: activity caveat too long");
        return NGX_ERROR;
    }
    return emit_cid_caveat(buf, sig, act_cav, act_len, log);
}

/*
 * emit_path_caveat — append the "path:" prefix-constraint caveat if requested.
 *
 * WHAT: Formats "path:<path>" and emits it as a cid caveat.
 * WHY: Restricts the token to a namespace subtree (e.g. "/atlas").
 * HOW: snprintf into a fixed buffer, guard truncation, delegate to
 *      emit_cid_caveat. Skips silently when no path is supplied.
 */
static ngx_int_t
emit_path_caveat(issue_buf_t *buf, u_char sig[32],
                 const char *path, ngx_log_t *log)
{
    char   path_cav[1024];
    size_t path_cav_len;

    if (!path || !path[0]) {
        return NGX_OK;
    }
    path_cav_len = (size_t) snprintf(path_cav, sizeof(path_cav),
                                     "path:%s", path);
    if (path_cav_len >= sizeof(path_cav)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "macaroon_issue: path caveat too long");
        return NGX_ERROR;
    }
    return emit_cid_caveat(buf, sig, path_cav, path_cav_len, log);
}

/*
 * emit_expiry_caveat — append the "before:" ISO8601-UTC expiry caveat.
 *
 * WHAT: Formats "before:YYYY-MM-DDThh:mm:ssZ" and emits it as a cid caveat.
 * WHY: Bounds token validity in time; omitted when expiry <= 0.
 * HOW: gmtime_r + snprintf, guard truncation, delegate to emit_cid_caveat.
 */
static ngx_int_t
emit_expiry_caveat(issue_buf_t *buf, u_char sig[32],
                   time_t expiry, ngx_log_t *log)
{
    char      exp_cav[64];
    size_t    exp_cav_len;
    struct tm tm_val;

    if (expiry <= 0) {
        return NGX_OK;
    }
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
    return emit_cid_caveat(buf, sig, exp_cav, exp_cav_len, log);
}

/*
 * emit_signature — append the terminal signature packet.
 *
 * WHAT: Writes [4-hex plen]["signature "][32 raw sig bytes] with NO trailing
 *       newline, matching the XrdMacaroons wire convention.
 * WHY: The signature packet is the only element carrying raw HMAC bytes and
 *       must be emitted last, verbatim, once the chain is complete.
 * HOW: plen is fixed at 46 (4 + 10 + 32); guard remaining space, then copy the
 *      hex header, label, and signature. Returns NGX_OK or NGX_ERROR.
 */
static ngx_int_t
emit_signature(issue_buf_t *buf, const u_char sig[32], ngx_log_t *log)
{
    /* plen = 4 (hex header) + 10 ("signature ") + 32 (sig bytes) = 46 */
    size_t plen = 46;
    char   hexlen[5];

    if (plen > buf->rem) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "macaroon_issue: buffer overflow");
        return NGX_ERROR;
    }
    snprintf(hexlen, sizeof(hexlen), "%04x", (unsigned int) plen);
    ngx_memcpy(buf->p, hexlen, 4);
    buf->p += 4;
    ngx_memcpy(buf->p, "signature ", 10);
    buf->p += 10;
    ngx_memcpy(buf->p, sig, 32);
    buf->p += 32;
    return NGX_OK;
}

ngx_int_t
brix_macaroon_issue(ngx_log_t *log,
    const u_char *root_key, size_t root_key_len,
    const char *location,
    const char *identifier,
    const char *activities,
    const char *path,
    time_t expiry,
    char *out_b64, size_t out_b64sz)
{
    u_char      bin[ISSUE_BIN_MAX];
    u_char      sig[32] = {0};
    issue_buf_t buf;

    if (!identifier || !identifier[0] || !root_key || root_key_len == 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "macaroon_issue: missing identifier or root key");
        return NGX_ERROR;
    }
    if (out_b64sz < BRIX_MACAROON_ISSUE_OUT_MAX) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "macaroon_issue: output buffer too small");
        return NGX_ERROR;
    }

    buf.start = bin;
    buf.p     = bin;
    buf.rem   = sizeof(bin);

    /* Assemble packets in wire order; each helper preserves the exact
     * write-then-HMAC sequence of the original implementation. */
    if (emit_location(&buf, location, log) != NGX_OK
        || emit_identifier(&buf, sig, root_key, root_key_len,
                           identifier, log) != NGX_OK
        || emit_activity_caveat(&buf, sig, activities, log) != NGX_OK
        || emit_path_caveat(&buf, sig, path, log) != NGX_OK
        || emit_expiry_caveat(&buf, sig, expiry, log) != NGX_OK
        || emit_signature(&buf, sig, log) != NGX_OK)
    {
        return NGX_ERROR;
    }

    b64url_encode((const char *) bin, (size_t)(buf.p - buf.start),
                  out_b64, out_b64sz);
    return NGX_OK;
}
