/*
 * sss_bf.c — Blowfish-CFB64 crypt for the SSS credential (see sss_bf.h).
 *
 * Shared by the module's SSS auth and the native client's SSS mint. ngx-free;
 * OpenSSL only. Owns the OpenSSL-3 legacy-provider load (Blowfish moved there),
 * idempotent and process-wide.
 */
#include "sss_bf.h"
#include "crc32_ieee.h"          /* xrootd_crc32_ieee — shared IEEE CRC-32 */
#include "protocols/root/protocol/sss.h"     /* XROOTD_SSS_* wire constants (single source) */

#include <limits.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

/* Load the OpenSSL-3 "legacy" provider once (Blowfish lives there). Warm SHA2-256
 * from the default provider first so loading legacy does not become the only
 * active provider for an app that later wants a default-provider digest. No-op
 * before OpenSSL 3.x. */
static void
sss_load_legacy_provider(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    static int done;

    if (!done) {
        EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
        if (md != NULL) {
            EVP_MD_free(md);
        }
        (void) OSSL_PROVIDER_load(NULL, "legacy");
        done = 1;
    }
#endif
}

int
xrootd_sss_bf_crypt(int encrypt, const uint8_t *key, size_t key_len,
                    const uint8_t *src, size_t src_len,
                    uint8_t *dst, size_t dst_max, size_t *out_len)
{
    EVP_CIPHER_CTX *evp;
    uint8_t         iv[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    int             len1 = 0, len2 = 0, ok;

    if (key == NULL || src == NULL || dst == NULL || out_len == NULL) {
        return -1;
    }
    if (key_len == 0 || key_len > INT_MAX || src_len > INT_MAX
        || dst_max < src_len || dst_max > INT_MAX) {
        return -1;
    }
    sss_load_legacy_provider();

    evp = EVP_CIPHER_CTX_new();
    if (evp == NULL) {
        return -1;
    }
    /* CFB64 is a stream mode (no padding); the key length is variable — an SSS
     * key is typically 32 bytes, under Blowfish's 56-byte maximum. */
    if (encrypt) {
        ok = EVP_EncryptInit_ex(evp, EVP_bf_cfb64(), NULL, NULL, NULL) == 1
          && EVP_CIPHER_CTX_set_padding(evp, 0) == 1
          && EVP_CIPHER_CTX_set_key_length(evp, (int) key_len) == 1
          && EVP_EncryptInit_ex(evp, NULL, NULL, key, iv) == 1
          && EVP_EncryptUpdate(evp, dst, &len1, src, (int) src_len) == 1
          && EVP_EncryptFinal_ex(evp, dst + len1, &len2) == 1;
    } else {
        ok = EVP_DecryptInit_ex(evp, EVP_bf_cfb64(), NULL, NULL, NULL) == 1
          && EVP_CIPHER_CTX_set_padding(evp, 0) == 1
          && EVP_CIPHER_CTX_set_key_length(evp, (int) key_len) == 1
          && EVP_DecryptInit_ex(evp, NULL, NULL, key, iv) == 1
          && EVP_DecryptUpdate(evp, dst, &len1, src, (int) src_len) == 1
          && EVP_DecryptFinal_ex(evp, dst + len1, &len2) == 1;
    }
    EVP_CIPHER_CTX_free(evp);
    if (!ok) {
        return -1;
    }
    *out_len = (size_t) (len1 + len2);
    return 0;
}

int
xrootd_sss_build_credential(const uint8_t *key, size_t key_len, uint64_t key_id,
    const char *username, const uint8_t nonce32[32], uint32_t gen_time,
    uint8_t *out, size_t out_max, size_t *out_len)
{
    uint8_t   clear[XROOTD_SSS_DATA_HDR_LEN + 3 + 64 + 1]; /* hdr + TLV + name + NUL */
    uint8_t   plain[sizeof(clear) + 4];                   /* + CRC32 */
    uint8_t  *cursor;
    size_t    ulen, clear_len, crypt_out;
    uint32_t  crc;

    if (key == NULL || key_len == 0 || nonce32 == NULL || out == NULL
        || out_len == NULL || out_max < XROOTD_SSS_HDR_LEN + 64) {
        return -1;
    }
    if (username == NULL || *username == '\0') {
        username = "xrd";
    }

    /* 40-byte data header: 32 nonce + gen_time(BE) + USEDATA opt byte. */
    memset(clear, 0, sizeof(clear));
    memcpy(clear, nonce32, 32);
    clear[32] = (uint8_t) (gen_time >> 24);
    clear[33] = (uint8_t) (gen_time >> 16);
    clear[34] = (uint8_t) (gen_time >> 8);
    clear[35] = (uint8_t)  gen_time;
    clear[39] = XROOTD_SSS_OPT_USEDATA;

    /* NAME TLV: [type][0][len][username NUL-terminated]; len includes the NUL. */
    ulen = strlen(username) + 1;
    if (ulen > 64) {
        ulen = 64;
    }
    cursor = clear + XROOTD_SSS_DATA_HDR_LEN;
    *cursor++ = XROOTD_SSS_TYPE_NAME;
    *cursor++ = 0;
    *cursor++ = (uint8_t) ulen;
    memcpy(cursor, username, ulen - 1);
    cursor[ulen - 1] = '\0';
    cursor += ulen;
    clear_len = (size_t) (cursor - clear);

    /* plain = cleartext + IEEE-CRC32 (big-endian). */
    memcpy(plain, clear, clear_len);
    crc = xrootd_crc32_ieee(plain, clear_len);
    plain[clear_len + 0] = (uint8_t) (crc >> 24);
    plain[clear_len + 1] = (uint8_t) (crc >> 16);
    plain[clear_len + 2] = (uint8_t) (crc >> 8);
    plain[clear_len + 3] = (uint8_t)  crc;

    if ((size_t) XROOTD_SSS_HDR_LEN + clear_len + 4 > out_max) {
        return -1;
    }

    /* BF32-encrypt the body into out[16..] (CFB64: cipher_len == plain_len). */
    if (xrootd_sss_bf_crypt(1, key, key_len, plain, clear_len + 4,
                            out + XROOTD_SSS_HDR_LEN,
                            out_max - XROOTD_SSS_HDR_LEN, &crypt_out) != 0) {
        return -1;
    }

    /* 16-byte outer header: magic + version + spare + kn + enc + key_id(8B BE). */
    out[0] = 's'; out[1] = 's'; out[2] = 's'; out[3] = '\0';
    out[4] = 1;                      /* version */
    out[5] = 0;                      /* spare */
    out[6] = 0;                      /* kn_size: no named key */
    out[7] = XROOTD_SSS_ENC_BF32;
    out[ 8] = (uint8_t) (key_id >> 56);
    out[ 9] = (uint8_t) (key_id >> 48);
    out[10] = (uint8_t) (key_id >> 40);
    out[11] = (uint8_t) (key_id >> 32);
    out[12] = (uint8_t) (key_id >> 24);
    out[13] = (uint8_t) (key_id >> 16);
    out[14] = (uint8_t) (key_id >>  8);
    out[15] = (uint8_t)  key_id;

    *out_len = (size_t) XROOTD_SSS_HDR_LEN + crypt_out;
    return 0;
}
