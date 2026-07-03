#include "sss_internal.h"
#include "fs/path/path.h"
#include "protocols/root/response/response.h"

#include <openssl/rand.h>
#include <string.h>
#include "core/compat/alloc_guard.h"

/*
 * WHAT: This file implements the SSS authentication identity layer. Includes copy_packed_string() for safe bounded string extraction from wire-format TLV fields, brix_sss_parse_identity() for parsing decrypted identity blocks (username, groups, host/IP), brix_sss_auth_failed() for sending auth failure responses, and brix_sss_send_authmore() for generating encrypted login-ID challenges with Blowfish-CFB + CRC32 integrity.
 *
 * WHY: SSS authentication requires a challenge-response protocol where the server encrypts an identity block (containing random nonce + generation timestamp) using Blowfish-CFB, appends CRC32 for integrity verification, and sends it to the client. The client decrypts, verifies CRC, extracts its username/groups, then re-encrypts with its shared secret key. This file handles both sides of that exchange.
 *
 * HOW: Four functions → copy_packed_string() (bounded string extraction from TLV value bytes) for safe parsing; brix_sss_parse_identity() (TLV stream parser) reading type/length/value triples and extracting name/grps/host fields into identity struct; brix_sss_auth_failed() (failure response builder); brix_sss_send_authmore() (challenge generation: RAND_bytes → gen_time encode → TLV LGID body → CRC32 append → Blowfish-CFB encrypt → wire response). */
static void
/*
 * WHAT: Safe bounded string copy from TLV value bytes into fixed-size C-string buffer. Handles packed (NUL-terminated) strings by stripping trailing NUL before length check, then clamps to dst_len - 1 and appends local NUL terminator. Used by brix_sss_parse_identity() to extract username, groups, and host/IP fields from decrypted identity TLV blocks without risking buffer overflow.
 */
brix_sss_copy_packed_string(char *dst, size_t dst_len,
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
 * brix_sss_parse_identity — parse the decrypted SSS identity TLV block.
 *
 * After decryption and CRC32 verification, the cleartext body (past the
 * BRIX_SSS_DATA_HDR_LEN fixed header) contains a compact TLV stream:
 *   [1-byte field_type][2-byte big-endian field_len][field_len bytes of value]
 *
 * Known field types:
 *   BRIX_SSS_TYPE_NAME (0x01) — username
 *   BRIX_SSS_TYPE_GRPS (0x04) — comma-separated groups
 *   BRIX_SSS_TYPE_RAND (0x07) — random nonce (not counted for id_count)
 *   BRIX_SSS_TYPE_LGID (0x10) — local group ID
 *   BRIX_SSS_TYPE_HOST (0x20) — source hostname or [IP] literal
 *
 * This parser is security-sensitive: every length check must be explicit and
 * complete before advancing cursor.  A wrong check can turn a malformed
 * credential into an out-of-bounds read.
 *
 * Returns: NGX_OK if at least one non-random field was found, NGX_ERROR if
 *   the block is empty or truncated.
 */
ngx_int_t
brix_sss_parse_identity(const u_char *data, size_t len,
    brix_sss_identity_t *id)
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

        if (field_type != BRIX_SSS_TYPE_RAND) {
            id->id_count++;
        }

        switch (field_type) {
        case BRIX_SSS_TYPE_NAME:
            brix_sss_copy_packed_string(id->name, sizeof(id->name),
                                          field_value, field_len);
            break;

        case BRIX_SSS_TYPE_GRPS:
            brix_sss_copy_packed_string(id->grps, sizeof(id->grps),
                                          field_value, field_len);
            break;

        case BRIX_SSS_TYPE_HOST:
            if (field_len > 0 && field_value[0] == '[') {
                brix_sss_copy_packed_string(id->ip, sizeof(id->ip),
                                              field_value, field_len);
            } else {
                brix_sss_copy_packed_string(id->host, sizeof(id->host),
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
brix_sss_auth_failed(brix_ctx_t *ctx, ngx_connection_t *c)
{
    BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "sss",
                      kXR_NotAuthorized, "SSS auth failed");
}

ngx_int_t
brix_sss_send_authmore(brix_ctx_t *ctx, ngx_connection_t *c,
    const brix_sss_key_t *key, const u_char *hdr, size_t hdr_len)
{
    u_char   clear[BRIX_SSS_DATA_HDR_LEN + 1 + 2 + sizeof("nobody")];
    u_char   plain[sizeof(clear) + 4];
    u_char   cipher[sizeof(clear) + 4];
    u_char  *buf;
    u_char  *clear_cursor;
    size_t   clear_len, cipher_len, total, out_len;
    uint32_t crc, gen_time;

    ngx_memzero(clear, sizeof(clear));
    RAND_bytes(clear, 32);
    gen_time = (uint32_t) (ngx_time() - BRIX_SSS_BASE_TIME);
    brix_sss_write_be32(clear + 32, gen_time);
    clear[39] = BRIX_SSS_OPT_USEDATA;

    /*
     * Auth-more asks the client to use an explicit local identity.  The
     * identity body is the same TLV format parsed above; sizeof("nobody")
     * intentionally includes the terminating NUL expected by older clients.
     */
    clear_cursor = clear + BRIX_SSS_DATA_HDR_LEN;
    *clear_cursor++ = BRIX_SSS_TYPE_LGID;
    *clear_cursor++ = 0;
    *clear_cursor++ = (u_char) sizeof("nobody");
    ngx_memcpy(clear_cursor, "nobody", sizeof("nobody"));
    clear_cursor += sizeof("nobody");
    clear_len = (size_t) (clear_cursor - clear);

    ngx_memcpy(plain, clear, clear_len);
    crc = htonl(brix_sss_crc32(plain, clear_len));
    ngx_memcpy(plain + clear_len, &crc, sizeof(crc));

    if (brix_sss_bf32_crypt(1, key->key, key->key_len,
                              plain, clear_len + sizeof(crc),
                              cipher, sizeof(cipher), &out_len)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    cipher_len = out_len;

    total = XRD_RESPONSE_HDR_LEN + hdr_len + cipher_len;
    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->cur_streamid, kXR_authmore,
                          (uint32_t) (hdr_len + cipher_len),
                          (ServerResponseHdr *) buf);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, hdr, hdr_len);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + hdr_len, cipher, cipher_len);

    return brix_queue_response(ctx, c, buf, total);
}

