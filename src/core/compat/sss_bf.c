/*
 * sss_bf.c — Blowfish-CFB64 crypt for the SSS credential (see sss_bf.h).
 *
 * Shared by the module's SSS auth and the native client's SSS mint. ngx-free;
 * OpenSSL only. Owns the OpenSSL-3 legacy-provider load (Blowfish moved there),
 * idempotent and process-wide.
 */
#include "sss_bf.h"
#include "crc32_ieee.h"          /* brix_crc32_ieee — shared IEEE CRC-32 */
#include "protocols/root/protocol/sss.h"     /* BRIX_SSS_* wire constants (single source) */

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

/* ---- Validate the crypt argument set ----
 *
 * WHAT: Returns 1 when every pointer is non-NULL and the lengths are in range
 * (key 1..INT_MAX, src <= INT_MAX, dst_max both >= src_len and <= INT_MAX);
 * returns 0 otherwise. Pure predicate — no side effects.
 *
 * WHY: The bounds are what let brix_sss_bf_crypt cast the size_t lengths to the
 * int arguments OpenSSL's EVP API takes without truncation, and guarantee the
 * output buffer can hold the CFB64 result (cipher_len == plain_len). Hoisting
 * the two guard clauses out of the orchestrator keeps its control flow flat.
 *
 * HOW:
 *   1. Reject any NULL among key/src/dst/out_len.
 *   2. Reject a zero or over-INT_MAX key, an over-INT_MAX source, or an output
 *      cap that is smaller than the source or itself over INT_MAX.
 *   3. Otherwise accept.
 */
static int
sss_bf_args_valid(const uint8_t *key, size_t key_len,
                    const uint8_t *src, size_t src_len,
                    const uint8_t *dst, size_t dst_max, const size_t *out_len)
{
    if (key == NULL || src == NULL || dst == NULL || out_len == NULL) {
        return 0;
    }
    if (key_len == 0 || key_len > INT_MAX || src_len > INT_MAX
        || dst_max < src_len || dst_max > INT_MAX) {
        return 0;
    }
    return 1;
}

/* ---- Run one Blowfish-CFB64 encrypt pass ----
 *
 * WHAT: Configures the caller-supplied EVP context for Blowfish-CFB64 with the
 * given variable-length key and IV, encrypts src_len bytes of src into dst, and
 * stores the two produced lengths through len1/len2. Returns 1 on full success,
 * 0 if any EVP step fails (short-circuiting on the first failure).
 *
 * WHY: CFB64 is a stream mode (no padding); the key length is variable — an SSS
 * key is typically 32 bytes, under Blowfish's 56-byte maximum. Encapsulating the
 * init/update/final chain keeps the orchestrator small and mirrors the decrypt
 * pass exactly so the two stay in lock-step.
 *
 * HOW:
 *   1. Select EVP_bf_cfb64() and disable padding.
 *   2. Set the key length, then install key + IV.
 *   3. EncryptUpdate the whole input (setting *len1), then EncryptFinal_ex at
 *      dst + *len1 (setting *len2). The && chain guarantees *len1 is written
 *      before it is read for the Final offset.
 */
static int
sss_bf_encrypt_run(EVP_CIPHER_CTX *evp, const uint8_t *key, size_t key_len,
                    const uint8_t *iv, const uint8_t *src, size_t src_len,
                    uint8_t *dst, int *len1, int *len2)
{
    return EVP_EncryptInit_ex(evp, EVP_bf_cfb64(), NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_set_padding(evp, 0) == 1
        && EVP_CIPHER_CTX_set_key_length(evp, (int) key_len) == 1
        && EVP_EncryptInit_ex(evp, NULL, NULL, key, iv) == 1
        && EVP_EncryptUpdate(evp, dst, len1, src, (int) src_len) == 1
        && EVP_EncryptFinal_ex(evp, dst + *len1, len2) == 1;
}

/* ---- Run one Blowfish-CFB64 decrypt pass ----
 *
 * WHAT: The exact inverse of sss_bf_encrypt_run — configures the EVP context for
 * Blowfish-CFB64 with the variable-length key and IV, decrypts src_len bytes of
 * src into dst, and stores the two produced lengths through len1/len2. Returns 1
 * on full success, 0 on the first failing EVP step.
 *
 * WHY: Kept byte-for-byte parallel to the encrypt pass (same mode, same padding
 * disable, same key-length handling) so encrypt and decrypt cannot drift; only
 * the EVP_Decrypt* entry points differ.
 *
 * HOW:
 *   1. Select EVP_bf_cfb64() and disable padding.
 *   2. Set the key length, then install key + IV.
 *   3. DecryptUpdate the whole input (setting *len1), then DecryptFinal_ex at
 *      dst + *len1 (setting *len2). The && chain guarantees *len1 is written
 *      before it is read for the Final offset.
 */
static int
sss_bf_decrypt_run(EVP_CIPHER_CTX *evp, const uint8_t *key, size_t key_len,
                    const uint8_t *iv, const uint8_t *src, size_t src_len,
                    uint8_t *dst, int *len1, int *len2)
{
    return EVP_DecryptInit_ex(evp, EVP_bf_cfb64(), NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_set_padding(evp, 0) == 1
        && EVP_CIPHER_CTX_set_key_length(evp, (int) key_len) == 1
        && EVP_DecryptInit_ex(evp, NULL, NULL, key, iv) == 1
        && EVP_DecryptUpdate(evp, dst, len1, src, (int) src_len) == 1
        && EVP_DecryptFinal_ex(evp, dst + *len1, len2) == 1;
}

/* ---- Blowfish-CFB64 crypt orchestrator ----
 *
 * WHAT: Encrypts (encrypt != 0) or decrypts the src_len bytes of src into dst
 * (capacity dst_max) under the variable-length key, writing the produced byte
 * count to *out_len. Returns 0 on success, -1 on bad arguments or any EVP
 * failure. Uses an all-zero 8-byte IV, matching the SSS wire format.
 *
 * WHY: Single entry point shared by the module's SSS auth and the native
 * client's SSS mint. The heavy lifting lives in single-purpose helpers so this
 * stays a flat validate → set-up → run → tear-down sequence.
 *
 * HOW:
 *   1. Validate arguments; bail on -1 if invalid.
 *   2. Ensure the OpenSSL-3 legacy provider (Blowfish) is loaded.
 *   3. Allocate an EVP context; bail on allocation failure.
 *   4. Dispatch to the encrypt or decrypt pass, capturing len1/len2.
 *   5. Free the context; on failure return -1, else publish len1+len2.
 */
int
brix_sss_bf_crypt(int encrypt, const uint8_t *key, size_t key_len,
                    const uint8_t *src, size_t src_len,
                    uint8_t *dst, size_t dst_max, size_t *out_len)
{
    EVP_CIPHER_CTX *evp;
    uint8_t         iv[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    int             len1 = 0, len2 = 0, ok;

    if (!sss_bf_args_valid(key, key_len, src, src_len, dst, dst_max, out_len)) {
        return -1;
    }
    sss_load_legacy_provider();

    evp = EVP_CIPHER_CTX_new();
    if (evp == NULL) {
        return -1;
    }
    if (encrypt) {
        ok = sss_bf_encrypt_run(evp, key, key_len, iv, src, src_len,
                                dst, &len1, &len2);
    } else {
        ok = sss_bf_decrypt_run(evp, key, key_len, iv, src, src_len,
                                dst, &len1, &len2);
    }
    EVP_CIPHER_CTX_free(evp);
    if (!ok) {
        return -1;
    }
    *out_len = (size_t) len1 + (size_t) len2;
    return 0;
}

int
brix_sss_build_credential(const uint8_t *key, size_t key_len, uint64_t key_id,
    const char *username, const uint8_t nonce32[32], uint32_t gen_time,
    uint8_t *out, size_t out_max, size_t *out_len)
{
    uint8_t   clear[BRIX_SSS_DATA_HDR_LEN + 3 + 64 + 1]; /* hdr + TLV + name + NUL */
    uint8_t   plain[sizeof(clear) + 4];                   /* + CRC32 */
    uint8_t  *cursor;
    size_t    ulen, clear_len, crypt_out;
    uint32_t  crc;

    if (key == NULL || key_len == 0 || nonce32 == NULL || out == NULL
        || out_len == NULL || out_max < BRIX_SSS_HDR_LEN + 64) {
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
    clear[39] = BRIX_SSS_OPT_USEDATA;

    /* NAME TLV: [type][0][len][username NUL-terminated]; len includes the NUL. */
    ulen = strlen(username) + 1;
    if (ulen > 64) {
        ulen = 64;
    }
    cursor = clear + BRIX_SSS_DATA_HDR_LEN;
    *cursor++ = BRIX_SSS_TYPE_NAME;
    *cursor++ = 0;
    *cursor++ = (uint8_t) ulen;
    memcpy(cursor, username, ulen - 1);
    cursor[ulen - 1] = '\0';
    cursor += ulen;
    clear_len = (size_t) (cursor - clear);

    /* plain = cleartext + IEEE-CRC32 (big-endian). */
    memcpy(plain, clear, clear_len);
    crc = brix_crc32_ieee(plain, clear_len);
    plain[clear_len + 0] = (uint8_t) (crc >> 24);
    plain[clear_len + 1] = (uint8_t) (crc >> 16);
    plain[clear_len + 2] = (uint8_t) (crc >> 8);
    plain[clear_len + 3] = (uint8_t)  crc;

    if ((size_t) BRIX_SSS_HDR_LEN + clear_len + 4 > out_max) {
        return -1;
    }

    /* BF32-encrypt the body into out[16..] (CFB64: cipher_len == plain_len). */
    if (brix_sss_bf_crypt(1, key, key_len, plain, clear_len + 4,
                            out + BRIX_SSS_HDR_LEN,
                            out_max - BRIX_SSS_HDR_LEN, &crypt_out) != 0) {
        return -1;
    }

    /* 16-byte outer header: magic + version + spare + kn + enc + key_id(8B BE). */
    out[0] = 's'; out[1] = 's'; out[2] = 's'; out[3] = '\0';
    out[4] = 1;                      /* version */
    out[5] = 0;                      /* spare */
    out[6] = 0;                      /* kn_size: no named key */
    out[7] = BRIX_SSS_ENC_BF32;
    out[ 8] = (uint8_t) (key_id >> 56);
    out[ 9] = (uint8_t) (key_id >> 48);
    out[10] = (uint8_t) (key_id >> 40);
    out[11] = (uint8_t) (key_id >> 32);
    out[12] = (uint8_t) (key_id >> 24);
    out[13] = (uint8_t) (key_id >> 16);
    out[14] = (uint8_t) (key_id >>  8);
    out[15] = (uint8_t)  key_id;

    *out_len = (size_t) BRIX_SSS_HDR_LEN + crypt_out;
    return 0;
}
