#include "sss_internal.h"
#include "../path/path.h"
#include "../response/response.h"

#include <openssl/rand.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* SSS Auth Identity — Challenge Generation, TLV Parsing                 */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the SSS authentication identity layer. Includes copy_packed_string() for safe bounded string extraction from wire-format TLV fields, xrootd_sss_parse_identity() for parsing decrypted identity blocks (username, groups, host/IP), xrootd_sss_auth_failed() for sending auth failure responses, and xrootd_sss_send_authmore() for generating encrypted login-ID challenges with Blowfish-CFB + CRC32 integrity.
 *
 * WHY: SSS authentication requires a challenge-response protocol where the server encrypts an identity block (containing random nonce + generation timestamp) using Blowfish-CFB, appends CRC32 for integrity verification, and sends it to the client. The client decrypts, verifies CRC, extracts its username/groups, then re-encrypts with its shared secret key. This file handles both sides of that exchange.
 *
 * HOW: Four functions → copy_packed_string() (bounded string extraction from TLV value bytes) for safe parsing; xrootd_sss_parse_identity() (TLV stream parser) reading type/length/value triples and extracting name/grps/host fields into identity struct; xrootd_sss_auth_failed() (failure response builder); xrootd_sss_send_authmore() (challenge generation: RAND_bytes → gen_time encode → TLV LGID body → CRC32 append → Blowfish-CFB encrypt → wire response). */
static void
/* ---- Function: xrootd_sss_copy_packed_string() ----
 * WHAT: Safe bounded string copy from TLV value bytes into fixed-size C-string buffer. Handles packed (NUL-terminated) strings by stripping trailing NUL before length check, then clamps to dst_len - 1 and appends local NUL terminator. Used by xrootd_sss_parse_identity() to extract username, groups, and host/IP fields from decrypted identity TLV blocks without risking buffer overflow.
 */
xrootd_sss_copy_packed_string(char *dst, size_t dst_len,
    const u_char *src, size_t len)
{
    if (len > 0 && src[len - 1] == '\0') {
        len--;
    }

    if (len >= dst_len) {
        len = dst_len - 1;
    }

    ngx_memcpy(dst, src, len);
    dst[len] = '\0';
}

/*
 * xrootd_sss_parse_identity — parse the decrypted SSS identity TLV block.
 *
 * After decryption and CRC32 verification, the cleartext body (past the
 * XROOTD_SSS_DATA_HDR_LEN fixed header) contains a compact TLV stream:
 *   [1-byte field_type][2-byte big-endian field_len][field_len bytes of value]
 *
 * Known field types:
 *   XROOTD_SSS_TYPE_NAME (0x01) — username
 *   XROOTD_SSS_TYPE_GRPS (0x04) — comma-separated groups
 *   XROOTD_SSS_TYPE_RAND (0x07) — random nonce (not counted for id_count)
 *   XROOTD_SSS_TYPE_LGID (0x10) — local group ID
 *   XROOTD_SSS_TYPE_HOST (0x20) — source hostname or [IP] literal
 *
 * This parser is security-sensitive: every length check must be explicit and
 * complete before advancing cursor.  A wrong check can turn a malformed
 * credential into an out-of-bounds read.
 *
 * Returns: NGX_OK if at least one non-random field was found, NGX_ERROR if
 *   the block is empty or truncated.
 */
ngx_int_t
xrootd_sss_parse_identity(const u_char *data, size_t len,
    xrootd_sss_identity_t *id)
{
    const u_char *cursor;
    const u_char *end;

    ngx_memzero(id, sizeof(*id));
    cursor = data;
    end = data + len;

    /*
     * The decrypted SSS identity block is a compact TLV stream:
     *   [1-byte type][2-byte big-endian length][value bytes]
     *
     * Keep cursor movement explicit; this parser is security-sensitive and a
     * mistaken length check can turn malformed credentials into memory reads.
     */
    while (cursor < end) {
        const u_char *field_value;
        uint8_t       field_type;
        size_t        field_len;

        field_type = *cursor++;
        if ((size_t) (end - cursor) < 2) {
            return NGX_ERROR;
        }

        field_len = ((size_t) cursor[0] << 8) | (size_t) cursor[1];
        cursor += 2;
        if ((size_t) (end - cursor) < field_len) {
            return NGX_ERROR;
        }

        field_value = cursor;

        if (field_type != XROOTD_SSS_TYPE_RAND) {
            id->id_count++;
        }

        switch (field_type) {
        case XROOTD_SSS_TYPE_NAME:
            xrootd_sss_copy_packed_string(id->name, sizeof(id->name),
                                          field_value, field_len);
            break;

        case XROOTD_SSS_TYPE_GRPS:
            xrootd_sss_copy_packed_string(id->grps, sizeof(id->grps),
                                          field_value, field_len);
            break;

        case XROOTD_SSS_TYPE_HOST:
            if (field_len > 0 && field_value[0] == '[') {
                xrootd_sss_copy_packed_string(id->ip, sizeof(id->ip),
                                              field_value, field_len);
            } else {
                xrootd_sss_copy_packed_string(id->host, sizeof(id->host),
                                              field_value, field_len);
            }
            break;

        default:
            break;
        }

        cursor += field_len;
    }

    return id->id_count > 0 ? NGX_OK : NGX_ERROR;
}

ngx_int_t
xrootd_sss_auth_failed(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    xrootd_log_access(ctx, c, "AUTH", "-", "sss",
                      0, kXR_NotAuthorized, "SSS auth failed", 0);
    XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
    return xrootd_send_error(ctx, c, kXR_NotAuthorized, "SSS auth failed");
}

ngx_int_t
xrootd_sss_send_authmore(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const xrootd_sss_key_t *key, const u_char *hdr, size_t hdr_len)
{
    u_char   clear[XROOTD_SSS_DATA_HDR_LEN + 1 + 2 + sizeof("nobody")];
    u_char   plain[sizeof(clear) + 4];
    u_char   cipher[sizeof(clear) + 4];
    u_char  *buf;
    u_char  *clear_cursor;
    size_t   clear_len, cipher_len, total, out_len;
    uint32_t crc, gen_time;

    ngx_memzero(clear, sizeof(clear));
    RAND_bytes(clear, 32);
    gen_time = (uint32_t) (ngx_time() - XROOTD_SSS_BASE_TIME);
    xrootd_sss_write_be32(clear + 32, gen_time);
    clear[39] = XROOTD_SSS_OPT_USEDATA;

    /*
     * Auth-more asks the client to use an explicit local identity.  The
     * identity body is the same TLV format parsed above; sizeof("nobody")
     * intentionally includes the terminating NUL expected by older clients.
     */
    clear_cursor = clear + XROOTD_SSS_DATA_HDR_LEN;
    *clear_cursor++ = XROOTD_SSS_TYPE_LGID;
    *clear_cursor++ = 0;
    *clear_cursor++ = (u_char) sizeof("nobody");
    ngx_memcpy(clear_cursor, "nobody", sizeof("nobody"));
    clear_cursor += sizeof("nobody");
    clear_len = (size_t) (clear_cursor - clear);

    ngx_memcpy(plain, clear, clear_len);
    crc = htonl(xrootd_sss_crc32(plain, clear_len));
    ngx_memcpy(plain + clear_len, &crc, sizeof(crc));

    if (xrootd_sss_bf32_crypt(1, key->key, key->key_len,
                              plain, clear_len + sizeof(crc),
                              cipher, sizeof(cipher), &out_len)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    cipher_len = out_len;

    total = XRD_RESPONSE_HDR_LEN + hdr_len + cipher_len;
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_authmore,
                          (uint32_t) (hdr_len + cipher_len),
                          (ServerResponseHdr *) buf);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, hdr, hdr_len);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + hdr_len, cipher, cipher_len);

    return xrootd_queue_response(ctx, c, buf, total);
}

