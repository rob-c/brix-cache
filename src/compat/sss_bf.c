/*
 * sss_bf.c — Blowfish-CFB64 crypt for the SSS credential (see sss_bf.h).
 *
 * Shared by the module's SSS auth and the native client's SSS mint. ngx-free;
 * OpenSSL only. Owns the OpenSSL-3 legacy-provider load (Blowfish moved there),
 * idempotent and process-wide.
 */
#include "sss_bf.h"

#include <limits.h>
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
