#include "gsi_internal.h"
#include <string.h>

/* Crypto helper declarations — defined in parse_crypto_helpers.c */
extern BIGNUM *xrootd_gsi_parse_client_dh_public_key(ngx_connection_t *c, ngx_log_t *log,
    const u_char *public_key_blob, size_t public_key_blob_len);
extern void xrootd_gsi_select_cipher_name(const u_char *payload, size_t payload_len,
    char *cipher_name, size_t cipher_name_size);
extern EVP_PKEY *xrootd_gsi_build_peer_dh_key(ngx_log_t *log, EVP_PKEY *server_dh_key,
    BIGNUM *client_public_bn);

/*
 * xrootd_gsi_parse_x509 — top-level kXGC_cert handler.
 *
 * Preconditions:
 *   - ctx->gsi_dh_key is set (populated by the preceding kXGC_certreq exchange).
 *   - ctx->payload / ctx->cur_dlen hold the raw kXGC_cert payload.
 *
 * Postconditions on success:
 *   - ctx->signing_key[0..31] contains the SHA-256 of the DH shared secret.
 *   - ctx->signing_active = 1 (enables kXR_sigver HMAC verification).
 *   - Returns a non-empty STACK_OF(X509) with the client's proxy chain.
 *     Caller must call sk_X509_pop_free(chain, X509_free).
 *
 * Returns: STACK_OF(X509) * on success, NULL on any error.
 */
STACK_OF(X509) *
xrootd_gsi_parse_x509(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    const u_char      *payload = ctx->payload;
    size_t             plen = ctx->cur_dlen;
    ngx_log_t         *log = c->log;
    const u_char      *cpub_data = NULL, *main_data = NULL;
    size_t             cpub_len = 0, main_len = 0;
    BIGNUM            *bnpub = NULL;
    EVP_PKEY          *peer = NULL;
    EVP_PKEY_CTX      *pkctx;
    unsigned char     *secret = NULL;
    size_t             secret_len = 0;
    const EVP_CIPHER  *evp_cipher;
    EVP_CIPHER_CTX    *dctx = NULL;
    unsigned char     *plain = NULL;
    int                olen = 0, flen = 0;
    const u_char      *x509_data = NULL;
    size_t             x509_len = 0;
    STACK_OF(X509)    *chain = NULL;
    BIO               *bio;
    X509              *cert;
    char               cipher_name[64];
    char               cipher_log[128];

    if (ctx->gsi_dh_key == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: no server DH key (kXGC_certreq skipped?)");
        return NULL;
    }

    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_puk,
                        &cpub_data, &cpub_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_puk not found in outer buffer");
        return NULL;
    }

    bnpub = xrootd_gsi_parse_client_dh_public_key(c, log, cpub_data,
                                                  cpub_len);
    if (bnpub == NULL) {
        return NULL;
    }

    xrootd_gsi_select_cipher_name(payload, plen, cipher_name,
                                  sizeof(cipher_name));

    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_main,
                        &main_data, &main_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_main not found in outer buffer");
        BN_free(bnpub);
        return NULL;
    }

    peer = xrootd_gsi_build_peer_dh_key(log, ctx->gsi_dh_key, bnpub);
    BN_free(bnpub);
    bnpub = NULL;

    if (!peer) {
        return NULL;
    }

    pkctx = EVP_PKEY_CTX_new(ctx->gsi_dh_key, NULL);
    if (pkctx == NULL
        || EVP_PKEY_derive_init(pkctx) != 1
        || EVP_PKEY_CTX_set_dh_pad(pkctx, 0) != 1
        || EVP_PKEY_derive_set_peer(pkctx, peer) != 1)
    {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        return NULL;
    }

    if (EVP_PKEY_derive(pkctx, NULL, &secret_len) != 1) {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        return NULL;
    }
    secret = ngx_palloc(c->pool, secret_len);
    if (!secret) {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        return NULL;
    }

    if (EVP_PKEY_derive(pkctx, secret, &secret_len) != 1) {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        return NULL;
    }
    EVP_PKEY_CTX_free(pkctx);
    EVP_PKEY_free(peer);

    {
        EVP_MD_CTX   *mdctx = EVP_MD_CTX_new();
        unsigned int  dlen = 32;
        u_char        digest[32];

        if (mdctx
            && EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1
            && EVP_DigestUpdate(mdctx, secret, secret_len) == 1
            && EVP_DigestFinal_ex(mdctx, digest, &dlen) == 1)
        {
            ngx_memcpy(ctx->signing_key, digest, 32);
            ctx->signing_active = 1;
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                           "xrootd: GSI signing key derived (HMAC-SHA256)");
        }
        if (mdctx) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
                   "xrootd: GSI DH shared secret %uz bytes, cipher='%s'",
                   secret_len,
                   (xrootd_sanitize_log_string(cipher_name, cipher_log,
                                               sizeof(cipher_log)),
                    cipher_log));

    evp_cipher = EVP_get_cipherbyname(cipher_name);
    if (!evp_cipher) {
        xrootd_sanitize_log_string(cipher_name, cipher_log, sizeof(cipher_log));
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: unknown cipher '%s'", cipher_log);
        OPENSSL_cleanse(secret, secret_len);
        return NULL;
    }

    {
        size_t ltmp = (secret_len > (size_t) EVP_MAX_KEY_LENGTH)
                      ? (size_t) EVP_MAX_KEY_LENGTH : secret_len;
        int    ldef = EVP_CIPHER_key_length(evp_cipher);
        size_t use_len = (size_t) ldef;
        unsigned char iv[EVP_MAX_IV_LENGTH];

        if ((int) ltmp != ldef) {
            EVP_CIPHER_CTX *tctx = EVP_CIPHER_CTX_new();

            EVP_CipherInit_ex(tctx, evp_cipher, NULL, NULL, NULL, 0);
            EVP_CIPHER_CTX_set_key_length(tctx, (int) ltmp);
            if (EVP_CIPHER_CTX_key_length(tctx) == (int) ltmp) {
                use_len = ltmp;
            }
            EVP_CIPHER_CTX_free(tctx);
        }

        ngx_memset(iv, 0, sizeof(iv));

        dctx = EVP_CIPHER_CTX_new();
        if (dctx == NULL) {
            OPENSSL_cleanse(secret, secret_len);
            return NULL;
        }

        EVP_DecryptInit_ex(dctx, evp_cipher, NULL, NULL, NULL);
        if (use_len != (size_t) ldef) {
            EVP_CIPHER_CTX_set_key_length(dctx, (int) use_len);
        }
        EVP_DecryptInit_ex(dctx, NULL, NULL, secret, iv);
        OPENSSL_cleanse(secret, secret_len);
    }

    {
        size_t plain_size = main_len + (size_t) EVP_CIPHER_CTX_block_size(dctx) + 1;

        plain = ngx_palloc(c->pool, plain_size);
        if (!plain) {
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }

        if (EVP_DecryptUpdate(dctx, plain, &olen,
                              main_data, (int) main_len) != 1) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: GSI kXGC_cert: EVP_DecryptUpdate failed");
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }
        if (EVP_DecryptFinal_ex(dctx, plain + olen, &flen) != 1) {
            char errstr[128];

            ERR_error_string_n(ERR_get_error(), errstr, sizeof(errstr));
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: GSI kXGC_cert: EVP_DecryptFinal failed: %s",
                          errstr);
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }
        EVP_CIPHER_CTX_free(dctx);
    }

/*---- PEM certificate extraction section — parse decrypted proxy chain ----
 *
 * WHAT: Extracts the kXRS_x509 bucket from the decrypted plaintext, creates a BIO memory buffer, then reads x509 certificates using PEM_read_bio_X509().
 *       This is the final phase of GSI authentication round 2 — converts encrypted wire payload into parsed certificate objects. */

/*---- Decrypted buffer structure ----
 *
 * WHY: The decrypted kXRS_main plaintext contains another bucket structure with kXRS_x509 inside — this is nested wire format where
 *      the outer envelope (kXRS_main) wraps the inner certificate payload (kXRS_x509). */

/*---- Decrypted buffer flow ----
 *
 * HOW: 1) EVP_DecryptUpdate(dctx, plain, &olen, main_data, main_len) decrypts first block; 
 *      2) EVP_DecryptFinal_ex(dctx, plain+olen, &flen) decrypts final padding block;
 *      3) Total plaintext = olen + flen bytes containing kXRS_x509 bucket. */

/*---- Certificate extraction mechanism ----
 *
 * WHAT: Creates BIO memory buffer from decrypted x509 data using BIO_new_mem_buf(), initializes empty cert chain via sk_X509_new_null().
 *      Then iteratively reads each PEM-encoded certificate via PEM_read_bio_X509() until EOF, pushing each into the stack. */

/*---- Certificate extraction error handling ----
 *
 * WHY: If kXRS_x509 bucket not found in decrypted buffer → return NULL (corrupted payload);
 *      If sk_X509_num(chain) == 0 after parsing → log warning and free chain (empty certificate data). */

/*---- Certificate ownership model after extraction ----
 *
 * WHY: The returned STACK_OF(X509) contains multiple X509 pointers — each must be freed via sk_X509_pop_free(chain, X509_free).
 *      The BIO buffer is freed immediately (BIO_free(bio)) after parsing completes. */

/*---- Certificate extraction logging invariant ----
 *
 * WHY: ngx_log_debug1() logs the number of certificates parsed for monitoring/debugging purposes — useful for tracking proxy chain depth. */

{
        int plain_len = olen + flen;

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                       "xrootd: GSI decrypted kXRS_main: %d bytes", plain_len);

        if (gsi_find_bucket(plain, (size_t) plain_len, (uint32_t) kXRS_x509,
                            &x509_data, &x509_len) != 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: GSI kXGC_cert: kXRS_x509 not found "
                          "in decrypted inner buffer");
            return NULL;
        }
    }

    bio = BIO_new_mem_buf(x509_data, (int) x509_len);
    chain = sk_X509_new_null();
    if (!bio || !chain) {
        BIO_free(bio);
        sk_X509_free(chain);
        return NULL;
    }

    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, cert);
    }
    BIO_free(bio);

    if (sk_X509_num(chain) == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_x509 contained no certs");
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   "xrootd: GSI parsed %d cert(s) from kXRS_x509 after decrypt",
                   sk_X509_num(chain));
    return chain;
}
