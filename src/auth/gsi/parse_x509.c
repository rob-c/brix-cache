#include "gsi_internal.h"
#include "gsi_core.h"
#include <string.h>
#include <stdlib.h>

/* Crypto helper declarations — defined in parse_crypto_helpers.c */
extern BIGNUM *brix_gsi_parse_client_dh_public_key(ngx_connection_t *c, ngx_log_t *log,
    const u_char *public_key_blob, size_t public_key_blob_len);
extern void brix_gsi_select_cipher_name(const u_char *payload, size_t payload_len,
    char *cipher_name, size_t cipher_name_size);
extern EVP_PKEY *brix_gsi_build_peer_dh_key(ngx_log_t *log, EVP_PKEY *server_dh_key,
    BIGNUM *client_public_bn);

/*
 * gsi_persist_session_cipher — stash the negotiated GSI session cipher on the
 * connection so a later kXGS_pxyreq/kXGC_sigpxy delegation round (phase-57 §F6)
 * can encrypt/decrypt its main with the same key. Purely additive: the key is
 * already derived for the kXGC_cert decrypt; this copies it (≤32 bytes) + the
 * cipher name + the IV flag. Inert unless brix_tpc_delegate consumes it. The
 * key is cleansed once delegation completes (auth.c) or at disconnect.
 */
static void
gsi_persist_session_cipher(brix_ctx_t *ctx, const char *name,
                           const u_char *key, int keylen, int use_iv)
{
    int n = (keylen > 32) ? 32 : (keylen < 0 ? 0 : keylen);
    size_t nl = ngx_strlen(name);

    ngx_memcpy(ctx->gsi_sess_key, key, (size_t) n);
    ctx->gsi_sess_keylen = n;
    ctx->gsi_sess_use_iv = use_iv;
    if (nl > sizeof(ctx->gsi_sess_cipher) - 1) {
        nl = sizeof(ctx->gsi_sess_cipher) - 1;
    }
    ngx_memcpy(ctx->gsi_sess_cipher, name, nl);
    ctx->gsi_sess_cipher[nl] = '\0';
}

/*
 * gsi_capture_client_rtag — stash the client's kXGC_cert random tag from the
 * decrypted main, so a §F6 kXGS_pxyreq can RSA-sign it (kXRS_signed_rtag) and the
 * client's CheckRtag accepts the delegation round. Inert unless delegation runs.
 */
static void
gsi_capture_client_rtag(brix_ctx_t *ctx, const u_char *plain, size_t plain_len)
{
    const uint8_t *rt = NULL;
    size_t         rtl = 0;

    if (brix_gsi_find_bucket(plain, plain_len, (uint32_t) kXRS_rtag, &rt, &rtl)
        == 0 && rtl > 0 && rtl <= sizeof(ctx->gsi_deleg_client_rtag)) {
        ngx_memcpy(ctx->gsi_deleg_client_rtag, rt, rtl);
        ctx->gsi_deleg_client_rtag_len = (int) rtl;
    }
}

/*
 * gsi_chain_from_plaintext — extract the client proxy chain from a decrypted
 * kXRS_main plaintext (shared by the unsigned and signed-DH round-2 paths).
 * The plaintext is itself an XrdSutBuffer carrying a kXRS_x509 bucket whose
 * data is the PEM-concatenated proxy chain.  Returns a non-empty
 * STACK_OF(X509) (caller sk_X509_pop_free) or NULL.
 */
static STACK_OF(X509) *
gsi_chain_from_plaintext(const u_char *plain, int plain_len, ngx_log_t *log)
{
    const u_char   *x509_data = NULL;
    size_t          x509_len = 0;
    BIO            *bio;
    X509           *cert;
    STACK_OF(X509) *chain;

    if (gsi_find_bucket(plain, (size_t) plain_len, (uint32_t) kXRS_x509,
                        &x509_data, &x509_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI kXGC_cert: kXRS_x509 not found "
                      "in decrypted inner buffer");
        return NULL;
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
                      "brix: GSI kXGC_cert: kXRS_x509 contained no certs");
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   "brix: GSI parsed %d cert(s) from kXRS_x509 after decrypt",
                   sk_X509_num(chain));
    return chain;
}

/*
 * gsi_recover_peer_signed — recover the client's DH public (peer key) from the
 * signed-DH round 2.  The client sends kXRS_cipher = its Public() blob signed
 * with the proxy private key (RSA EncryptPrivate) plus kXRS_puk = the proxy
 * public key (PEM).  We verify/recover the blob with DecryptPublic against that
 * public key, then parse it as a DH peer.  Returns the peer EVP_PKEY (caller
 * frees) or NULL.  This authenticates that the sender holds the proxy key.
 */
static EVP_PKEY *
gsi_recover_peer_signed(const u_char *payload, size_t plen, ngx_log_t *log)
{
    const u_char *cipher = NULL, *puk = NULL;
    size_t        cipherlen = 0, puklen = 0;
    BIO          *pbio;
    EVP_PKEY     *proxy_pub, *peer;
    u_char       *blob;
    size_t        bloblen;

    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_cipher,
                        &cipher, &cipherlen) != 0
        || gsi_find_bucket(payload, plen, (uint32_t) kXRS_puk,
                           &puk, &puklen) != 0)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI signed-DH: kXRS_cipher/kXRS_puk missing");
        return NULL;
    }

    pbio = BIO_new_mem_buf(puk, (int) puklen);
    proxy_pub = pbio ? PEM_read_bio_PUBKEY(pbio, NULL, NULL, NULL) : NULL;
    BIO_free(pbio);
    if (proxy_pub == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI signed-DH: cannot read proxy public key");
        return NULL;
    }

    bloblen = cipherlen + 2 * (size_t) EVP_PKEY_size(proxy_pub) + 64;
    blob = malloc(bloblen);
    bloblen = blob ? brix_gsi_rsa_decrypt_public(proxy_pub, cipher, cipherlen,
                                                   blob, bloblen) : 0;
    EVP_PKEY_free(proxy_pub);
    if (bloblen == 0) {
        free(blob);
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI signed-DH: signature verification failed");
        return NULL;
    }
    peer = brix_gsi_cipher_parse_peer(blob, bloblen);
    free(blob);
    return peer;
}

/*
 * brix_gsi_parse_x509_signed — round-2 handler for the signed-DH variant
 * (mirrors the client's signed path in client/lib/sec/sec_gsi.c).  Recovers the
 * peer DH public from the RSA-signed kXRS_cipher, agrees the padded (HasPad=1)
 * DH secret, decrypts the IV-prepended kXRS_main, and returns the proxy chain.
 * Sets ctx->signing_key = SHA-256(secret) / signing_active for symmetry with
 * the unsigned path.  Returns STACK_OF(X509) * or NULL.
 */
static STACK_OF(X509) *
brix_gsi_parse_x509_signed(brix_ctx_t *ctx, ngx_connection_t *c)
{
    const u_char   *payload = ctx->payload;
    size_t          plen = ctx->cur_dlen;
    ngx_log_t      *log = c->log;
    const u_char   *main_data = NULL;
    size_t          main_len = 0;
    EVP_PKEY       *peer;
    EVP_PKEY_CTX   *pkctx;
    unsigned char  *secret = NULL;
    size_t          secret_len = 0;
    uint8_t         aeskey[BRIX_GSI_MAX_KEY];
    char            cipher_name[64];
    brix_gsi_cipher_t cipher;
    uint8_t        *plain;
    size_t          plain_len = 0;
    STACK_OF(X509) *chain;

    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_main,
                        &main_data, &main_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI signed-DH: kXRS_main missing");
        return NULL;
    }

    peer = gsi_recover_peer_signed(payload, plen, log);
    if (peer == NULL) {
        return NULL;
    }

    /*
     * Padded (HasPad=1) DH secret: the signed-DH AES-128 key is the first 16
     * bytes of the prime-sized secret, so derive with set_dh_pad(1) (unlike the
     * unsigned path's pad=0).  signing_key = SHA-256(secret) mirrors the
     * unsigned path; sigver is off by default whenever signed-DH is selected.
     */
    pkctx = EVP_PKEY_CTX_new(ctx->gsi_dh_key, NULL);
    if (pkctx == NULL
        || EVP_PKEY_derive_init(pkctx) != 1
        || EVP_PKEY_CTX_set_dh_pad(pkctx, 1) != 1
        || EVP_PKEY_derive_set_peer(pkctx, peer) != 1
        || EVP_PKEY_derive(pkctx, NULL, &secret_len) != 1
        || (secret = ngx_palloc(c->pool, secret_len)) == NULL
        || EVP_PKEY_derive(pkctx, secret, &secret_len) != 1)
    {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI signed-DH: DH derive failed");
        return NULL;
    }
    EVP_PKEY_CTX_free(pkctx);
    EVP_PKEY_free(peer);

    /* Phase 52 (WS-A): honour the cipher the client selected (kXRS_cipher_alg);
     * fall back to aes-128-cbc, the default every conformant client offers. */
    brix_gsi_select_cipher_name(payload, plen, cipher_name, sizeof(cipher_name));
    if (!brix_gsi_cipher_lookup(cipher_name, &cipher)) {
        (void) brix_gsi_cipher_lookup("aes-128-cbc", &cipher);
    }

    if (secret_len < (size_t) cipher.key_len) {
        OPENSSL_cleanse(secret, secret_len);
        return NULL;
    }
    ngx_memcpy(aeskey, secret, (size_t) cipher.key_len);

    /* Persist the session cipher for a possible §F6 delegation round — signed-DH
     * path always uses an IV-prepended main (use_iv=1). */
    gsi_persist_session_cipher(ctx, cipher_name, aeskey, cipher.key_len, 1);

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
        }
        if (mdctx) {
            EVP_MD_CTX_free(mdctx);
        }
    }
    OPENSSL_cleanse(secret, secret_len);

    /* The negotiated session cipher (above).  This is the SIGNED-DH path, which
     * a peer only enters when its version >= XrdSecgsiVersDHsigned (10400) — and
     * that is exactly the condition under which stock XrdSecgsi sets useIV=true
     * (XrdSecProtocolgsi.cc: `useIV = (RemVers >= XrdSecgsiVersDHsigned)`).  So
     * the encrypted main always carries a leading IV of the cipher's own length
     * (sessionKey->MaxIVLength()); we strip it unconditionally here.  The IV is
     * NOT signalled by a name suffix — the cipher name on the wire is bare, and
     * select_cipher_name() resolves it.  Default aes-128-cbc; the client's cipher
     * choice is honoured. */
    plain = brix_gsi_cipher_decrypt(&cipher, aeskey, main_data, main_len,
                                      1, &plain_len);
    OPENSSL_cleanse(aeskey, sizeof(aeskey));
    if (plain == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI signed-DH: main decrypt failed");
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   "brix: GSI signed-DH decrypted kXRS_main: %uz bytes",
                   plain_len);
    gsi_capture_client_rtag(ctx, plain, plain_len);   /* §F6 delegation rtag */
    chain = gsi_chain_from_plaintext(plain, (int) plain_len, log);
    free(plain);
    return chain;
}

/*
 * brix_gsi_parse_x509 — top-level kXGC_cert handler.
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
brix_gsi_parse_x509(brix_ctx_t *ctx, ngx_connection_t *c)
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
    char               cipher_name[64];
    char               cipher_log[128];

    if (ctx->gsi_dh_key == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI kXGC_cert: no server DH key (kXGC_certreq skipped?)");
        return NULL;
    }

    /* Signed-DH (>=10400) was selected in round 1 — take the signed path that
     * verifies the RSA-signed kXRS_cipher and decrypts the IV-prepended main. */
    if (ctx->gsi_signed_dh) {
        return brix_gsi_parse_x509_signed(ctx, c);
    }

    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_puk,
                        &cpub_data, &cpub_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI kXGC_cert: kXRS_puk not found in outer buffer");
        return NULL;
    }

    bnpub = brix_gsi_parse_client_dh_public_key(c, log, cpub_data,
                                                  cpub_len);
    if (bnpub == NULL) {
        return NULL;
    }

    brix_gsi_select_cipher_name(payload, plen, cipher_name,
                                  sizeof(cipher_name));

    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_main,
                        &main_data, &main_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI kXGC_cert: kXRS_main not found in outer buffer");
        BN_free(bnpub);
        return NULL;
    }

    peer = brix_gsi_build_peer_dh_key(log, ctx->gsi_dh_key, bnpub);
    BN_free(bnpub);
    bnpub = NULL;

    if (!peer) {
        return NULL;
    }

    /*
     * Derive the DH shared secret from OUR private key (ctx->gsi_dh_key, set in
     * round 1) and the client's public value (peer). set_dh_pad(pkctx, 0) is
     * deliberate: XRootD/gsi expects the *unpadded* big-endian secret (leading
     * zero bytes stripped). Pad-mode 1 would left-pad to the prime size and the
     * subsequent SHA-256 — and thus signing_key — would not match the client's.
     */
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

    /*
     * Two-call EVP_PKEY_derive idiom: the first call (out buffer == NULL) only
     * reports the required length into secret_len so we can size the allocation;
     * the second call (below) actually writes the secret. With pad=0 the length
     * can vary run-to-run, so it MUST be probed rather than assumed == prime size.
     */
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
                           "brix: GSI signing key derived (HMAC-SHA256)");
        }
        if (mdctx) {
            EVP_MD_CTX_free(mdctx);
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
                   "brix: GSI DH shared secret %uz bytes, cipher='%s'",
                   secret_len,
                   (brix_sanitize_log_string(cipher_name, cipher_log,
                                               sizeof(cipher_log)),
                    cipher_log));

    evp_cipher = EVP_get_cipherbyname(cipher_name);
    if (!evp_cipher) {
        brix_sanitize_log_string(cipher_name, cipher_log, sizeof(cipher_log));
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI kXGC_cert: unknown cipher '%s'", cipher_log);
        OPENSSL_cleanse(secret, secret_len);
        return NULL;
    }

    {
        /*
         * Reconcile the DH secret length with the cipher's key length. The peer
         * sender used the raw secret as the key, so we must key the decryptor
         * identically. ltmp = secret clamped to EVP_MAX_KEY_LENGTH (the iv[] /
         * key buffers cannot exceed that); ldef = the cipher's *default* key
         * length (e.g. 32 for aes-256-cbc). use_len defaults to ldef.
         */
        size_t ltmp = (secret_len > (size_t) EVP_MAX_KEY_LENGTH)
                      ? (size_t) EVP_MAX_KEY_LENGTH : secret_len;
        int    ldef = EVP_CIPHER_key_length(evp_cipher);
        size_t use_len = (size_t) ldef;
        unsigned char iv[EVP_MAX_IV_LENGTH];

        /*
         * When the secret length differs from the cipher default, probe whether
         * this cipher actually accepts a custom key length using a throwaway
         * context: set_key_length() can silently no-op for fixed-length ciphers,
         * so we only adopt ltmp if the readback confirms it stuck. This avoids
         * keying the real ctx with a length the cipher would reject/ignore.
         */
        if ((int) ltmp != ldef) {
            EVP_CIPHER_CTX *tctx = EVP_CIPHER_CTX_new();

            EVP_CipherInit_ex(tctx, evp_cipher, NULL, NULL, NULL, 0);
            EVP_CIPHER_CTX_set_key_length(tctx, (int) ltmp);
            if (EVP_CIPHER_CTX_key_length(tctx) == (int) ltmp) {
                use_len = ltmp;
            }
            EVP_CIPHER_CTX_free(tctx);
        }

        /* GSI wire protocol fixes the IV to all-zeros — there is no IV bucket. */
        ngx_memset(iv, 0, sizeof(iv));

        dctx = EVP_CIPHER_CTX_new();
        if (dctx == NULL) {
            OPENSSL_cleanse(secret, secret_len);
            return NULL;
        }

        /*
         * Two-stage Init is required: the first call binds the cipher so that
         * set_key_length() is legal; only after the (optional) length override
         * does the second call (key+iv args) install the actual key material.
         * Passing key+iv in the first call would lock the key length first.
         */
        EVP_DecryptInit_ex(dctx, evp_cipher, NULL, NULL, NULL);
        if (use_len != (size_t) ldef) {
            EVP_CIPHER_CTX_set_key_length(dctx, (int) use_len);
        }
        EVP_DecryptInit_ex(dctx, NULL, NULL, secret, iv);
        /* Persist the session cipher for a possible §F6 delegation round before
         * scrubbing — unsigned path: zero IV (use_iv=0). */
        gsi_persist_session_cipher(ctx, cipher_name, secret, (int) use_len, 0);
        /* Key is now copied into dctx; scrub the plaintext secret immediately. */
        OPENSSL_cleanse(secret, secret_len);
    }

    {
        /*
         * Sizing the plaintext buffer: CBC decryption can emit up to one extra
         * cipher block beyond the ciphertext length (DecryptUpdate may flush a
         * buffered block), so reserve main_len + block_size; the trailing +1 is
         * defensive slack so a NUL-terminator could be appended if ever needed.
         */
        size_t plain_size = main_len + (size_t) EVP_CIPHER_CTX_block_size(dctx) + 1;

        plain = ngx_palloc(c->pool, plain_size);
        if (!plain) {
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }

        if (EVP_DecryptUpdate(dctx, plain, &olen,
                              main_data, (int) main_len) != 1) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix: GSI kXGC_cert: EVP_DecryptUpdate failed");
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }
        if (EVP_DecryptFinal_ex(dctx, plain + olen, &flen) != 1) {
            char errstr[128];

            ERR_error_string_n(ERR_get_error(), errstr, sizeof(errstr));
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix: GSI kXGC_cert: EVP_DecryptFinal failed: %s",
                          errstr);
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }
        EVP_CIPHER_CTX_free(dctx);
    }

    /* Same tail as the signed path: stash the delegation rtag (§F6), then reuse
     * gsi_chain_from_plaintext() to parse the kXRS_x509 bucket into a chain. */
    gsi_capture_client_rtag(ctx, plain, (size_t) (olen + flen));
    return gsi_chain_from_plaintext(plain, olen + flen, log);
}
