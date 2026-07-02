#include "sss_internal.h"
#include "auth/gsi/gsi_internal.h"
#include "session/registry.h"
#include "core/compat/crc32_ieee.h"   /* shared CRC-32/IEEE (libxrdproto) */
#include "core/compat/sss_bf.h"       /* shared Blowfish-CFB64 (libxrdproto) */

#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include <string.h>

/*
 * WHAT: This file provides shared cryptographic helpers for Simple Shared Secret (SSS) authentication.
 *       Includes big-endian 32/64-bit read/write primitives for wire protocol framing, software CRC32c implementation
 *       for integrity verification (SSS uses CRC32 not HMAC), Blowfish-CFB encryption/decryption for challenge-response,
 *       and OpenSSL 3.x legacy provider loading for SHA-256 digest availability. All helpers are static or internal —
 *       used exclusively by sss/auth.c and sss/key_parse.c during SSS authentication flow.
 *
 * WHY: SSS authentication requires wire-format parsing (big-endian integers), integrity verification via CRC32 appended
 *      to plaintext before encryption, symmetric challenge encryption using Blowfish-CFB with zero IV, and OpenSSL 3.x
 *      compatibility for SHA-256 digest fetching from legacy provider. These helpers centralize crypto operations preventing
 *      duplication across SSS module files and ensuring consistent wire-format handling.
 *
 * HOW: Four helper categories → big-endian read/write (xrootd_sss_read_be32/be64, xrootd_sss_write_be32) for wire protocol parsing;
 *      CRC32 software implementation (xrootd_sss_crc32) using standard polynomial 0xedb88320u for integrity verification;
 *      Blowfish-CFB encryption/decryption (xrootd_sss_bf32_crypt) with EVP_CIPHER_CTX and zero IV for challenge-response;
 *      OpenSSL legacy provider loading (xrootd_sss_load_legacy_provider) ensuring SHA-256 digest availability on OpenSSL 3.x. */

uint32_t
xrootd_sss_read_be32(const u_char *p)
{
    return ((uint32_t) p[0] << 24)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)
         |  (uint32_t) p[3];
}

uint64_t
xrootd_sss_read_be64(const u_char *p)
{
    return ((uint64_t) xrootd_sss_read_be32(p) << 32)
         |  (uint64_t) xrootd_sss_read_be32(p + 4);
}
/*
 * WHAT: Reads an 8-byte big-endian uint64_t from wire protocol payload by composing two be32 reads. Used for parsing larger integer fields in SSS credential payloads.
 */

void
xrootd_sss_write_be32(u_char *p, uint32_t v)
{
    p[0] = (u_char) (v >> 24);
    p[1] = (u_char) (v >> 16);
    p[2] = (u_char) (v >> 8);
    p[3] = (u_char) v;
}
/*
 * WHAT: Writes a uint32_t as 4 bytes in big-endian order into wire protocol buffer. Used by SSS auth challenge generation to encode timestamps and key IDs into server-to-client credential payloads.
 */

/* Forwards to the shared CRC-32/IEEE kernel (libxrdproto) — one source of truth
 * with the native client's SSS mint path. */
uint32_t
xrootd_sss_crc32(const u_char *p, size_t len)
{
    return xrootd_crc32_ieee(p, len);
}
/*
 * WHAT: Computes CRC32 checksum using standard polynomial 0xedb88320u (reflected form). Used by SSS authentication for integrity verification — CRC32 is appended to plaintext before Blowfish encryption, then verified after decryption via direct uint32_t comparison.
 */

/* Forwards to the shared Blowfish-CFB64 kernel (libxrdproto), which owns the
 * OpenSSL-3 legacy-provider load — one source of truth with the client's SSS mint. */
ngx_int_t
xrootd_sss_bf32_crypt(int encrypt, const u_char *key, size_t key_len,
    const u_char *src, size_t src_len, u_char *dst, size_t dst_len,
    size_t *out_len)
{
    return xrootd_sss_bf_crypt(encrypt, key, key_len, src, src_len,
                               dst, dst_len, out_len) == 0 ? NGX_OK : NGX_ERROR;
}
/*
 * WHAT: Blowfish-CFB symmetric encryption/decryption for SSS challenge-response authentication. Uses EVP_CIPHER_CTX with zero IV and no padding. Encrypt mode: EVP_EncryptInit → set_padding(0) → set_key_length(key_len) → init with key+iv → update → final. Decrypt mode mirrors encrypt flow using EVP_Decrypt*. Returns NGX_OK on success with out_len populated, NGX_ERROR on cipher operation failure or invalid parameters (key_len==0 or >INT_MAX). Key length is variable — SSS keys may be shorter than standard 56-byte Blowfish key.
 */

const xrootd_sss_key_t *
xrootd_sss_find_key_arr(ngx_array_t *keys_arr, int64_t id)
{
    xrootd_sss_key_t *keys;
    ngx_uint_t        i;

    if (keys_arr == NULL) {
        return NULL;
    }

    keys = keys_arr->elts;
    for (i = 0; i < keys_arr->nelts; i++) {
        if (keys[i].id == id && (!keys[i].exp || keys[i].exp > ngx_time())) {
            return &keys[i];
        }
    }

    return NULL;
}

const xrootd_sss_key_t *
xrootd_sss_find_key(ngx_stream_xrootd_srv_conf_t *conf, int64_t id)
{
    return xrootd_sss_find_key_arr(conf->sss_keys, id);
}
/*
 * WHAT: Searches configured SSS key table for a matching key ID that is not expired. Returns pointer to first matching active key or NULL if no match found. Used by sss/auth.c during kXR_auth handler to select the correct shared secret for decrypting client challenge.
 */

ngx_int_t
xrootd_sss_verify_blob(ngx_array_t *keys, time_t lifetime,
    const u_char *blob, size_t blob_len,
    xrootd_sss_identity_t *id_out, const xrootd_sss_key_t **key_out,
    char *err, size_t errsz)
{
    const xrootd_sss_key_t *key;
    const u_char           *cipher;
    /* Bounds the decrypt scratch; SSS credentials over any transport (XRootD
     * kXR_auth or CMS kYR_xauth frame) are far smaller than this. */
    u_char                  clear[8192];
    size_t                  hdr_len, cipher_len, out_len, clear_len;
    uint8_t                 kn_size, options;
    int64_t                 key_id;
    uint32_t                got_crc, want_crc, gen_time, now;

    if (key_out) {
        *key_out = NULL;
    }

    if (blob == NULL
        || blob_len < XROOTD_SSS_HDR_LEN + XROOTD_SSS_DATA_HDR_LEN + 4)
    {
        snprintf(err, errsz, "sss credential too short");
        return NGX_ERROR;
    }

    if (blob[0] != 's' || blob[1] != 's' || blob[2] != 's' || blob[3] != '\0'
        || blob[7] != XROOTD_SSS_ENC_BF32)
    {
        snprintf(err, errsz, "sss credential bad magic/enc");
        return NGX_ERROR;
    }

    kn_size = blob[6];
    if (kn_size != 0 && (kn_size > XROOTD_SSS_NAME_MAX || (kn_size & 0x07))) {
        snprintf(err, errsz, "sss credential bad key-name size");
        return NGX_ERROR;
    }

    hdr_len = XROOTD_SSS_HDR_LEN + kn_size;
    if (hdr_len >= blob_len || (kn_size && blob[hdr_len - 1] != '\0')) {
        snprintf(err, errsz, "sss credential malformed header");
        return NGX_ERROR;
    }

    key_id = (int64_t) xrootd_sss_read_be64(blob + 8);
    key = xrootd_sss_find_key_arr(keys, key_id);
    if (key == NULL) {
        snprintf(err, errsz, "sss key id %lld not in keytab", (long long) key_id);
        return NGX_ERROR;
    }

    cipher = blob + hdr_len;
    cipher_len = blob_len - hdr_len;
    if (cipher_len <= 4 || cipher_len > sizeof(clear)) {
        snprintf(err, errsz, "sss ciphertext length out of range");
        return NGX_ERROR;
    }

    if (xrootd_sss_bf32_crypt(0, key->key, key->key_len,
                              cipher, cipher_len, clear, sizeof(clear),
                              &out_len) != NGX_OK
        || out_len <= 4)
    {
        snprintf(err, errsz, "sss decrypt failed");
        return NGX_ERROR;
    }

    clear_len = out_len - 4;
    got_crc  = xrootd_sss_read_be32(clear + clear_len);
    want_crc = xrootd_sss_crc32(clear, clear_len);
    if (got_crc != want_crc || clear_len < XROOTD_SSS_DATA_HDR_LEN) {
        OPENSSL_cleanse(clear, sizeof(clear));
        snprintf(err, errsz, "sss CRC mismatch (wrong key or tampered)");
        return NGX_ERROR;
    }

    gen_time = xrootd_sss_read_be32(clear + 32);
    now = (uint32_t) (ngx_time() - XROOTD_SSS_BASE_TIME);
    if (gen_time + (uint32_t) lifetime <= now) {
        OPENSSL_cleanse(clear, sizeof(clear));
        snprintf(err, errsz, "sss credential expired (replay window)");
        return NGX_ERROR;
    }

    options = clear[39];
    if (options == XROOTD_SSS_OPT_SNDLID) {
        OPENSSL_cleanse(clear, sizeof(clear));
        snprintf(err, errsz, "sss SNDLID credential unsupported");
        return NGX_DECLINED;
    }

    if (id_out != NULL
        && xrootd_sss_parse_identity(clear + XROOTD_SSS_DATA_HDR_LEN,
                                     clear_len - XROOTD_SSS_DATA_HDR_LEN,
                                     id_out) != NGX_OK)
    {
        OPENSSL_cleanse(clear, sizeof(clear));
        snprintf(err, errsz, "sss identity parse failed");
        return NGX_ERROR;
    }

    OPENSSL_cleanse(clear, sizeof(clear));
    if (key_out) {
        *key_out = key;
    }
    return NGX_OK;
}
/*
 * WHAT: Searches configured SSS key table for a matching key ID that is not expired. Returns pointer to first matching active key or NULL if no match found. Used by sss/auth.c during kXR_auth handler to select the correct shared secret for decrypting client challenge.
 */

