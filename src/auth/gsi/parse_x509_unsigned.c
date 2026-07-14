#include "gsi_internal.h"
#include "gsi_core.h"
#include <string.h>
#include <stdlib.h>
#include "parse_x509_internal.h"

/* Crypto helper declarations — defined in parse_crypto_helpers.c */
extern BIGNUM *brix_gsi_parse_client_dh_public_key(ngx_connection_t *c, ngx_log_t *log,
    const u_char *public_key_blob, size_t public_key_blob_len);
extern void brix_gsi_select_cipher_name(const u_char *payload, size_t payload_len,
    char *cipher_name, size_t cipher_name_size);
extern EVP_PKEY *brix_gsi_build_peer_dh_key(ngx_log_t *log, EVP_PKEY *server_dh_key,
    BIGNUM *client_public_bn);

/*
 * gsi_unsigned_derive_secret — WHAT: agree the UNPADDED (HasPad=0) DH shared
 * secret for the unsigned kXGC_cert path. WHY: isolates the two-call
 * EVP_PKEY_derive ladder (a large slice of the handler's CCN) behind one
 * early-return boundary. HOW: set_dh_pad(pkctx, 0) is deliberate — XRootD/gsi
 * expects the *unpadded* big-endian secret (leading zero bytes stripped); pad=1
 * would left-pad to the prime size and the subsequent SHA-256 (and thus
 * signing_key) would not match the client's. Allocates `secret` from c->pool;
 * frees `peer` on every path. Returns the secret with *secret_len set, or NULL.
 */
static unsigned char *
gsi_unsigned_derive_secret(ngx_connection_t *c, EVP_PKEY *dh_key, EVP_PKEY *peer,
                           size_t *secret_len)
{
    EVP_PKEY_CTX  *pkctx = EVP_PKEY_CTX_new(dh_key, NULL);
    unsigned char *secret;

    *secret_len = 0;
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
     * the second call actually writes the secret. With pad=0 the length can vary
     * run-to-run, so it MUST be probed rather than assumed == prime size.
     */
    if (EVP_PKEY_derive(pkctx, NULL, secret_len) != 1) {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        return NULL;
    }
    secret = ngx_palloc(c->pool, *secret_len);
    if (!secret) {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        return NULL;
    }
    if (EVP_PKEY_derive(pkctx, secret, secret_len) != 1) {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        return NULL;
    }
    EVP_PKEY_CTX_free(pkctx);
    EVP_PKEY_free(peer);
    return secret;
}

/*
 * gsi_unsigned_key_length — WHAT: reconcile the DH secret length with the
 * cipher's key length, returning the key length to install in the decryptor.
 * WHY: factors the fixed-vs-variable key-length probe out of the handler. HOW:
 * ldef is the cipher default; when the (clamped) secret length differs, a
 * throwaway context probes whether the cipher actually accepts a custom key
 * length (set_key_length() silently no-ops for fixed-length ciphers), and the
 * override is adopted only if the readback confirms it stuck. Pure: no side
 * effects on the real decrypt context. Returns the key length in bytes.
 */
static size_t
gsi_unsigned_key_length(const EVP_CIPHER *evp_cipher, size_t secret_len)
{
    /*
     * The peer sender used the raw secret as the key, so we must key the
     * decryptor identically. ltmp = secret clamped to EVP_MAX_KEY_LENGTH (the
     * iv[] / key buffers cannot exceed that); ldef = the cipher's *default* key
     * length (e.g. 32 for aes-256-cbc). use_len defaults to ldef.
     */
    size_t ltmp = (secret_len > (size_t) EVP_MAX_KEY_LENGTH)
                  ? (size_t) EVP_MAX_KEY_LENGTH : secret_len;
    int    ldef = EVP_CIPHER_key_length(evp_cipher);
    size_t use_len = (size_t) ldef;

    /*
     * When the secret length differs from the cipher default, probe whether this
     * cipher actually accepts a custom key length using a throwaway context:
     * set_key_length() can silently no-op for fixed-length ciphers, so we only
     * adopt ltmp if the readback confirms it stuck. This avoids keying the real
     * ctx with a length the cipher would reject/ignore.
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
    return use_len;
}

/*
 * gsi_unsigned_decrypt_init — WHAT: build a CBC decrypt context keyed with the
 * reconciled DH secret and a zero IV. WHY: isolates the two-stage EVP init
 * (required so set_key_length() is legal before the key is installed) and the
 * session-cipher persistence + secret scrub. HOW: gsi_unsigned_key_length()
 * picks the key length; the GSI wire fixes the IV to all-zeros (no IV bucket);
 * the negotiated cipher is persisted (use_iv=0) for a possible §F6 delegation
 * round, then `secret` is cleansed. Returns the decrypt ctx, or NULL (secret
 * always cleansed before return). `secret` is copied into the ctx on success.
 */
static EVP_CIPHER_CTX *
gsi_unsigned_decrypt_init(brix_ctx_t *ctx, const EVP_CIPHER *evp_cipher,
                          unsigned char *secret, size_t secret_len,
                          const char *cipher_name)
{
    size_t          ldef = (size_t) EVP_CIPHER_key_length(evp_cipher);
    size_t          use_len = gsi_unsigned_key_length(evp_cipher, secret_len);
    unsigned char   iv[EVP_MAX_IV_LENGTH];
    EVP_CIPHER_CTX *dctx;

    /* GSI wire protocol fixes the IV to all-zeros — there is no IV bucket. */
    ngx_memset(iv, 0, sizeof(iv));

    dctx = EVP_CIPHER_CTX_new();
    if (dctx == NULL) {
        OPENSSL_cleanse(secret, secret_len);
        return NULL;
    }

    /*
     * Two-stage Init is required: the first call binds the cipher so that
     * set_key_length() is legal; only after the (optional) length override does
     * the second call (key+iv args) install the actual key material. Passing
     * key+iv in the first call would lock the key length first.
     */
    EVP_DecryptInit_ex(dctx, evp_cipher, NULL, NULL, NULL);
    if (use_len != ldef) {
        EVP_CIPHER_CTX_set_key_length(dctx, (int) use_len);
    }
    EVP_DecryptInit_ex(dctx, NULL, NULL, secret, iv);
    /* Persist the session cipher for a possible §F6 delegation round before
     * scrubbing — unsigned path: zero IV (use_iv=0). */
    gsi_persist_session_cipher(ctx, cipher_name, secret, (int) use_len, 0);
    /* Key is now copied into dctx; scrub the plaintext secret immediately. */
    OPENSSL_cleanse(secret, secret_len);
    return dctx;
}

/*
 * gsi_unsigned_decrypt_main — WHAT: CBC-decrypt the kXRS_main ciphertext into a
 * fresh pool buffer, returning the plaintext and its length. WHY: isolates the
 * DecryptUpdate/DecryptFinal pair and their error logging. HOW: sizes the buffer
 * to main_len + one block + 1 defensive byte (DecryptUpdate can flush a buffered
 * block; the +1 is slack for a possible NUL). Consumes `dctx` (freed on every
 * path). Returns the plaintext with *plain_len set, or NULL (logged).
 */
static unsigned char *
gsi_unsigned_decrypt_main(ngx_connection_t *c, EVP_CIPHER_CTX *dctx,
                          const u_char *main_data, size_t main_len,
                          size_t *plain_len)
{
    /*
     * Sizing the plaintext buffer: CBC decryption can emit up to one extra
     * cipher block beyond the ciphertext length (DecryptUpdate may flush a
     * buffered block), so reserve main_len + block_size; the trailing +1 is
     * defensive slack so a NUL-terminator could be appended if ever needed.
     */
    size_t         plain_size = main_len
                                + (size_t) EVP_CIPHER_CTX_block_size(dctx) + 1;
    unsigned char *plain;
    int            olen = 0, flen = 0;

    *plain_len = 0;
    plain = ngx_palloc(c->pool, plain_size);
    if (!plain) {
        EVP_CIPHER_CTX_free(dctx);
        return NULL;
    }

    if (EVP_DecryptUpdate(dctx, plain, &olen,
                          main_data, (int) main_len) != 1) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: GSI kXGC_cert: EVP_DecryptUpdate failed");
        EVP_CIPHER_CTX_free(dctx);
        return NULL;
    }
    if (EVP_DecryptFinal_ex(dctx, plain + olen, &flen) != 1) {
        char errstr[128];

        ERR_error_string_n(ERR_get_error(), errstr, sizeof(errstr));
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: GSI kXGC_cert: EVP_DecryptFinal failed: %s",
                      errstr);
        EVP_CIPHER_CTX_free(dctx);
        return NULL;
    }
    EVP_CIPHER_CTX_free(dctx);

    *plain_len = (size_t) olen + (size_t) flen;  /* widen BEFORE adding */
    return plain;
}

/*
 * gsi_unsigned_build_peer — WHAT: parse the client's kXRS_puk DH public and build
 * the peer EVP_PKEY for the unsigned kXGC_cert path, also locating the kXRS_main
 * ciphertext. WHY: pulls the outer-buffer bucket lookups + peer-key construction
 * out of the orchestrator prologue. HOW: kXRS_puk → client DH public BIGNUM →
 * peer key; kXRS_main → main ciphertext span. Every failure is logged and frees
 * the intermediate BIGNUM. Returns the peer key with *main_data / *main_len set,
 * or NULL.
 */
static EVP_PKEY *
gsi_unsigned_build_peer(brix_ctx_t *ctx, ngx_connection_t *c,
                        const u_char **main_data, size_t *main_len)
{
    const u_char *payload = ctx->recv.payload;
    size_t        plen = ctx->recv.cur_dlen;
    ngx_log_t    *log = c->log;
    const u_char *cpub_data = NULL;
    size_t        cpub_len = 0;
    BIGNUM       *bnpub;
    EVP_PKEY     *peer;

    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_puk,
                        &cpub_data, &cpub_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI kXGC_cert: kXRS_puk not found in outer buffer");
        return NULL;
    }

    bnpub = brix_gsi_parse_client_dh_public_key(c, log, cpub_data, cpub_len);
    if (bnpub == NULL) {
        return NULL;
    }

    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_main,
                        main_data, main_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI kXGC_cert: kXRS_main not found in outer buffer");
        BN_free(bnpub);
        return NULL;
    }

    peer = brix_gsi_build_peer_dh_key(log, ctx->gsi.dh_key, bnpub);
    BN_free(bnpub);
    return peer;
}

/*
 * brix_gsi_parse_x509 — top-level kXGC_cert handler.
 *
 * Preconditions:
 *   - ctx->gsi.dh_key is set (populated by the preceding kXGC_certreq exchange).
 *   - ctx->recv.payload / ctx->recv.cur_dlen hold the raw kXGC_cert payload.
 *
 * Postconditions on success:
 *   - ctx->sigver.signing_key[0..31] contains the SHA-256 of the DH shared secret.
 *   - ctx->sigver.signing_active = 1 (enables kXR_sigver HMAC verification).
 *   - Returns a non-empty STACK_OF(X509) with the client's proxy chain.
 *     Caller must call sk_X509_pop_free(chain, X509_free).
 *
 * Returns: STACK_OF(X509) * on success, NULL on any error.
 */
STACK_OF(X509) *
brix_gsi_parse_x509(brix_ctx_t *ctx, ngx_connection_t *c)
{
    const u_char      *payload = ctx->recv.payload;
    size_t             plen = ctx->recv.cur_dlen;
    ngx_log_t         *log = c->log;
    const u_char      *main_data = NULL;
    size_t             main_len = 0;
    EVP_PKEY          *peer = NULL;
    unsigned char     *secret = NULL;
    size_t             secret_len = 0;
    const EVP_CIPHER  *evp_cipher;
    EVP_CIPHER_CTX    *dctx = NULL;
    unsigned char     *plain = NULL;
    size_t             plain_len = 0;
    char               cipher_name[64];
    char               cipher_log[128];

    if (ctx->gsi.dh_key == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI kXGC_cert: no server DH key (kXGC_certreq skipped?)");
        return NULL;
    }

    /* Signed-DH (>=10400) was selected in round 1 — take the signed path that
     * verifies the RSA-signed kXRS_cipher and decrypts the IV-prepended main. */
    if (ctx->gsi.signed_dh) {
        return brix_gsi_parse_x509_signed(ctx, c);
    }

    brix_gsi_select_cipher_name(payload, plen, cipher_name,
                                  sizeof(cipher_name));

    peer = gsi_unsigned_build_peer(ctx, c, &main_data, &main_len);
    if (peer == NULL) {
        return NULL;
    }

    /*
     * Derive the UNPADDED DH shared secret from OUR private key (ctx->gsi.dh_key,
     * set in round 1) and the client's public value (peer).  The helper uses
     * set_dh_pad(0) (XRootD/gsi expects the unpadded big-endian secret) and frees
     * `peer` on every path.
     */
    secret = gsi_unsigned_derive_secret(c, ctx->gsi.dh_key, peer, &secret_len);
    if (secret == NULL) {
        return NULL;
    }

    if (gsi_store_signing_key(ctx, secret, secret_len)) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, log, 0,
                       "brix: GSI signing key derived (HMAC-SHA256)");
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

    dctx = gsi_unsigned_decrypt_init(ctx, evp_cipher, secret, secret_len,
                                     cipher_name);
    if (dctx == NULL) {
        return NULL;
    }

    plain = gsi_unsigned_decrypt_main(c, dctx, main_data, main_len, &plain_len);
    if (plain == NULL) {
        return NULL;
    }

    /* Same tail as the signed path: stash the delegation rtag (§F6), then reuse
     * gsi_chain_from_plaintext() to parse the kXRS_x509 bucket into a chain. */
    gsi_capture_client_rtag(ctx, plain, plain_len);
    gsi_capture_fullproxy(ctx, plain, plain_len);
    return gsi_chain_from_plaintext(plain, (int) plain_len, log);
}
