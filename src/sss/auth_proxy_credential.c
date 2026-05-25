#include "sss_internal.h"

#include <openssl/rand.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* SSS Proxy Credential — Server-side credential for upstream authmore  */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Builds an SSS kXR_auth payload that a proxy server sends to an upstream XRootD server when the upstream requests SSS authentication via kXR_authmore. Constructs header (magic 'sss\0', version, enc type BF32, 8-byte BE key-id) + Blowfish-CFB encrypted cleartext block containing RAND_bytes nonce + gen_time encode + TLV NAME field for username.
 *
 * WHY: In proxy mode the nginx-xrootd server acts as an SSS client to its upstream — it must encrypt a credential with its own shared secret key, append CRC32 integrity check, and send it in kXR_auth format. The upstream decrypts and verifies to authenticate the proxy.
 *
 * HOW: xrootd_sss_build_proxy_credential() → validate inputs (key + buf + username) → build cleartext: RAND_bytes(32) + gen_time BE encode + XROOTD_SSS_OPT_USEDATA flag → TLV NAME block with bounded username → CRC32 append to plain buffer → Blowfish-CFB encrypt via xrootd_sss_bf32_crypt() → write outer header (magic, version, enc type, key-id as 8-byte BE) → return total length. */
/*
 * xrootd_sss_build_proxy_credential — build an SSS kXR_auth payload.
 *
 * Constructs the credential that a proxy sends to an upstream XRootD server
 * when the upstream requests SSS authentication via kXR_authmore.
 *
 * Output layout:
 *   [XROOTD_SSS_HDR_LEN bytes: magic + version + enc + key-id]
 *   [cipher_len bytes: BF32-encrypted cleartext + CRC32]
 *
 * buf must be at least XROOTD_SSS_HDR_LEN + XROOTD_SSS_DATA_HDR_LEN + 64 + 4
 * bytes (at least 256 bytes is always sufficient).
 *
 * Returns NGX_OK on success, NGX_ERROR if the key is missing or crypto fails.
 */
ngx_int_t
xrootd_sss_build_proxy_credential(const xrootd_sss_key_t *key,
    const char *username, u_char *buf, size_t buf_max, size_t *out_len)
{
    u_char   clear[XROOTD_SSS_DATA_HDR_LEN + 3 + 64 + 1]; /* hdr + TLV + username + NUL */
    u_char   plain[sizeof(clear) + 4];
    u_char  *cipher;
    u_char  *clear_cursor;
    size_t   clear_len, cipher_len, total, crypt_out;
    uint32_t crc, gen_time;
    uint64_t key_id_be;

    if (key == NULL || buf == NULL || buf_max < XROOTD_SSS_HDR_LEN + 64) {
        return NGX_ERROR;
    }

    if (username == NULL || *username == '\0') {
        username = "xrd";
    }

    /* Build cleartext: 40-byte fixed header + TLV NAME block */
    ngx_memzero(clear, sizeof(clear));
    RAND_bytes(clear, 32);
    gen_time = (uint32_t) (ngx_time() - XROOTD_SSS_BASE_TIME);
    xrootd_sss_write_be32(clear + 32, gen_time);
    clear[39] = XROOTD_SSS_OPT_USEDATA;   /* include identity TLV */

    clear_cursor = clear + XROOTD_SSS_DATA_HDR_LEN;

    /* TLV: NAME = username (NUL-terminated, NUL included in len) */
    {
        size_t ulen = ngx_strlen(username) + 1; /* +1 for NUL */
        if (ulen > 64) {
            ulen = 64;
        }
        *clear_cursor++ = XROOTD_SSS_TYPE_NAME;
        *clear_cursor++ = 0;
        *clear_cursor++ = (u_char) ulen;
        ngx_memcpy(clear_cursor, username, ulen - 1);
        clear_cursor[ulen - 1] = '\0';
        clear_cursor += ulen;
    }

    clear_len = (size_t) (clear_cursor - clear);

    /* plain = cleartext + CRC32 */
    ngx_memcpy(plain, clear, clear_len);
    crc = htonl(xrootd_sss_crc32(plain, clear_len));
    ngx_memcpy(plain + clear_len, &crc, sizeof(crc));

    /* Encrypt */
    cipher      = buf + XROOTD_SSS_HDR_LEN;
    cipher_len  = clear_len + 4;  /* BF-CFB64 has no padding */
    total       = XROOTD_SSS_HDR_LEN + cipher_len;
    if (total > buf_max) {
        return NGX_ERROR;
    }

    if (xrootd_sss_bf32_crypt(1, key->key, key->key_len,
                               plain, clear_len + 4,
                               cipher, buf_max - XROOTD_SSS_HDR_LEN,
                               &crypt_out)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Build the outer header in buf[0..15] */
    buf[0] = 's'; buf[1] = 's'; buf[2] = 's'; buf[3] = '\0';
    buf[4] = 1;       /* version */
    buf[5] = 0;       /* spare */
    buf[6] = 0;       /* kn_size: no named key */
    buf[7] = XROOTD_SSS_ENC_BF32;
    key_id_be = (uint64_t) key->id;
    /* Write as 8-byte BE */
    buf[ 8] = (u_char) (key_id_be >> 56);
    buf[ 9] = (u_char) (key_id_be >> 48);
    buf[10] = (u_char) (key_id_be >> 40);
    buf[11] = (u_char) (key_id_be >> 32);
    buf[12] = (u_char) (key_id_be >> 24);
    buf[13] = (u_char) (key_id_be >> 16);
    buf[14] = (u_char) (key_id_be >>  8);
    buf[15] = (u_char)  key_id_be;

    *out_len = XROOTD_SSS_HDR_LEN + crypt_out;
    return NGX_OK;
}

