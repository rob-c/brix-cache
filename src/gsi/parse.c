#include "gsi_internal.h"

#include <string.h>

/*
 * Decrypt and extract the x509 chain from a kXGC_cert request.
 *
 * GSI (Grid Security Infrastructure) uses a two-message Diffie-Hellman
 * key-exchange handshake layered on top of the XRootD auth protocol:
 *
 *   kXGC_certreq: server → client.  Server sends its DH public key and
 *     certificate.  ctx->gsi_dh_key holds the server's DH private key.
 *
 *   kXGC_cert: client → server (parsed here).  Client sends:
 *     - kXRS_puk bucket: client's DH public key in "---BPUB---...---EPUB--"
 *       hex-encoded format.
 *     - kXRS_main bucket: the client's X.509 proxy chain, AES-CBC encrypted
 *       with the shared DH secret.
 *
 * This function:
 *   1. Extracts and decodes the client's DH public value (BIGNUM).
 *   2. Derives the DH shared secret.
 *   3. SHA-256 hashes the secret to produce ctx->signing_key (32 bytes)
 *      used later for kXR_sigver HMAC-SHA256 request signing.
 *   4. Decrypts kXRS_main using the shared secret as AES key.
 *   5. Extracts the PEM-encoded certificate chain from kXRS_x509 within
 *      the decrypted inner buffer.
 *
 * Ownership: the returned STACK_OF(X509) is heap-allocated.  The caller
 *   must call sk_X509_pop_free(chain, X509_free) when done.  All OpenSSL
 *   intermediate objects are freed before return via goto done / direct calls.
 */

/*
 * xrootd_gsi_parse_client_dh_public_key — extract the client's Diffie-Hellman
 * public key value as a BIGNUM from the "---BPUB---...---EPUB--" blob.
 *
 * BN_hex2bn() requires a NUL-terminated string, so we copy the hex span
 * rather than temporarily scribbling into the wire buffer.
 *
 * Pool allocation: hex_copy uses c->pool (connection lifetime).
 * Ownership: the returned BIGNUM is caller-owned; call BN_free() when done.
 * Returns: BIGNUM * on success, NULL on any error.
 */
static BIGNUM *
xrootd_gsi_parse_client_dh_public_key(ngx_connection_t *c, ngx_log_t *log,
    const u_char *public_key_blob, size_t public_key_blob_len)
{
    static const char begin_marker[] = "---BPUB---";
    static const char end_marker[] = "---EPUB--";

    const u_char *hex_start;
    const u_char *hex_end;
    u_char       *hex_copy;
    size_t        hex_len;
    BIGNUM       *public_key_bn;

    hex_start = memmem((void *) public_key_blob, public_key_blob_len,
                       begin_marker, sizeof(begin_marker) - 1);
    hex_end = memmem((void *) public_key_blob, public_key_blob_len,
                     end_marker, sizeof(end_marker) - 1);

    if (hex_start == NULL || hex_end == NULL
        || hex_end <= hex_start + sizeof(begin_marker) - 1)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: malformed client DH blob");
        return NULL;
    }

    hex_start += sizeof(begin_marker) - 1;
    hex_len = (size_t) (hex_end - hex_start);

    /*
     * BN_hex2bn() needs a NUL-terminated string.  Copy the hex payload instead
     * of scribbling a temporary NUL byte into the request buffer; the original
     * frame is binary wire data and should stay immutable while being parsed.
     */
    hex_copy = ngx_pnalloc(c->pool, hex_len + 1);
    if (hex_copy == NULL) {
        return NULL;
    }

    ngx_memcpy(hex_copy, hex_start, hex_len);
    hex_copy[hex_len] = '\0';

    public_key_bn = NULL;
    if (BN_hex2bn(&public_key_bn, (char *) hex_copy) == 0
        || public_key_bn == NULL)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: BN_hex2bn failed");
        return NULL;
    }

    return public_key_bn;
}


static void
xrootd_gsi_select_cipher_name(const u_char *payload, size_t payload_len,
    char *cipher_name, size_t cipher_name_size)
{
    const u_char *cipher_bucket;
    size_t        cipher_bucket_len;
    size_t        name_len;

    ngx_cpystrn((u_char *) cipher_name, (u_char *) "aes-256-cbc",
                cipher_name_size);

    if (gsi_find_bucket(payload, payload_len, (uint32_t) kXRS_cipher_alg,
                        &cipher_bucket, &cipher_bucket_len)
        != 0 || cipher_bucket_len == 0)
    {
        return;
    }

    /*
     * The cipher bucket may include colon-separated OpenSSL metadata.  The
     * first field is the cipher name used by EVP_get_cipherbyname().
     */
    for (name_len = 0;
         name_len < cipher_bucket_len && name_len < cipher_name_size - 1;
         name_len++)
    {
        if (cipher_bucket[name_len] == ':') {
            break;
        }
        cipher_name[name_len] = cipher_bucket[name_len];
    }

    cipher_name[name_len] = '\0';
}


static EVP_PKEY *
xrootd_gsi_build_peer_dh_key(ngx_log_t *log, EVP_PKEY *server_dh_key,
    BIGNUM *client_public_bn)
{
    EVP_PKEY_CTX   *pkey_ctx;
    EVP_PKEY       *peer_key;
    OSSL_PARAM_BLD *param_builder;
    OSSL_PARAM     *server_params;
    OSSL_PARAM     *client_params;
    OSSL_PARAM     *merged_params;

    pkey_ctx = NULL;
    peer_key = NULL;
    param_builder = NULL;
    server_params = NULL;
    client_params = NULL;
    merged_params = NULL;

    /*
     * OpenSSL 3 represents DH keys through parameter arrays.  The server key
     * owns the group parameters; the client contributes only its public value.
     * Merge those two views before asking EVP to materialize a peer public key.
     */
    if (EVP_PKEY_todata(server_dh_key, EVP_PKEY_KEY_PARAMETERS,
                        &server_params)
        != 1 || server_params == NULL)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot export server DH parameters");
        goto done;
    }

    param_builder = OSSL_PARAM_BLD_new();
    if (param_builder == NULL
        || OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_PUB_KEY,
                                  client_public_bn)
           != 1)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot build client DH parameters");
        goto done;
    }

    client_params = OSSL_PARAM_BLD_to_param(param_builder);
    if (client_params == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot finalize client DH parameters");
        goto done;
    }

    merged_params = OSSL_PARAM_merge(server_params, client_params);
    if (merged_params == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot merge DH parameters");
        goto done;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (pkey_ctx == NULL
        || EVP_PKEY_fromdata_init(pkey_ctx) != 1
        || EVP_PKEY_fromdata(pkey_ctx, &peer_key, EVP_PKEY_PUBLIC_KEY,
                             merged_params)
           != 1)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot build client DH peer key");
        goto done;
    }

done:
    EVP_PKEY_CTX_free(pkey_ctx);
    OSSL_PARAM_BLD_free(param_builder);
    OSSL_PARAM_free(server_params);
    OSSL_PARAM_free(client_params);
    OSSL_PARAM_free(merged_params);

    return peer_key;
}


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
