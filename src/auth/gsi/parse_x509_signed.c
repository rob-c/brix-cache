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
 * gsi_signed_derive_secret — WHAT: agree the padded (HasPad=1) signed-DH shared
 * secret from our private key and the recovered peer public. WHY: isolates the
 * multi-step EVP_PKEY_derive ladder (which dominated the signed handler's CCN)
 * behind one early-return boundary. HOW: two-call derive idiom with
 * set_dh_pad(1) — the signed-DH AES key is the first key_len bytes of the
 * prime-sized secret (unlike the unsigned path's pad=0). Allocates `secret` from
 * c->pool. Frees `peer` on every path (success and failure) so the caller does
 * not. Returns the pool-allocated secret with *secret_len set, or NULL (logged).
 */
static unsigned char *
gsi_signed_derive_secret(ngx_connection_t *c, EVP_PKEY *dh_key, EVP_PKEY *peer,
                         size_t *secret_len)
{
    EVP_PKEY_CTX  *pkctx = EVP_PKEY_CTX_new(dh_key, NULL);
    unsigned char *secret = NULL;

    *secret_len = 0;
    if (pkctx == NULL
        || EVP_PKEY_derive_init(pkctx) != 1
        || EVP_PKEY_CTX_set_dh_pad(pkctx, 1) != 1
        || EVP_PKEY_derive_set_peer(pkctx, peer) != 1
        || EVP_PKEY_derive(pkctx, NULL, secret_len) != 1
        || (secret = ngx_palloc(c->pool, *secret_len)) == NULL
        || EVP_PKEY_derive(pkctx, secret, secret_len) != 1)
    {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: GSI signed-DH: DH derive failed");
        return NULL;
    }
    EVP_PKEY_CTX_free(pkctx);
    EVP_PKEY_free(peer);
    return secret;
}

/*
 * gsi_session_cipher_t — the negotiated signed-DH session cipher, grouped so the
 * select helper stays within the 5-param budget: the bare cipher name (for the
 * §F6 delegation persist), the resolved cipher descriptor, and the copied AES
 * key material.
 */
typedef struct {
    char              name[64];
    brix_gsi_cipher_t cipher;
    uint8_t           aeskey[BRIX_GSI_MAX_KEY];
} gsi_session_cipher_t;

/*
 * gsi_signed_select_key — WHAT: resolve the client-selected cipher, verify the
 * secret is long enough for its key, and copy the AES key into sc. WHY: factors
 * the Phase-52 cipher-selection + length-check out of the handler. HOW:
 * kXRS_cipher_alg lookup with an aes-128-cbc fallback (the default every
 * conformant client offers); rejects (returns 0, after cleansing `secret`) when
 * secret_len < cipher key_len. On success fills sc->cipher and copies key_len
 * bytes into sc->aeskey. Returns 1 on success, 0 on reject.
 */
static int
gsi_signed_select_key(const u_char *payload, size_t plen,
                      unsigned char *secret, size_t secret_len,
                      gsi_session_cipher_t *sc)
{
    /* Phase 52 (WS-A): honour the cipher the client selected (kXRS_cipher_alg);
     * fall back to aes-128-cbc, the default every conformant client offers. */
    brix_gsi_select_cipher_name(payload, plen, sc->name, sizeof(sc->name));
    if (!brix_gsi_cipher_lookup(sc->name, &sc->cipher)) {
        (void) brix_gsi_cipher_lookup("aes-128-cbc", &sc->cipher);
    }

    if (secret_len < (size_t) sc->cipher.key_len) {
        OPENSSL_cleanse(secret, secret_len);
        return 0;
    }
    ngx_memcpy(sc->aeskey, secret, (size_t) sc->cipher.key_len);
    return 1;
}

/*
 * brix_gsi_parse_x509_signed — round-2 handler for the signed-DH variant
 * (mirrors the client's signed path in client/lib/sec/sec_gsi.c).  Recovers the
 * peer DH public from the RSA-signed kXRS_cipher, agrees the padded (HasPad=1)
 * DH secret, decrypts the IV-prepended kXRS_main, and returns the proxy chain.
 * Sets ctx->sigver.signing_key = SHA-256(secret) / signing_active for symmetry with
 * the unsigned path.  Returns STACK_OF(X509) * or NULL.
 */
STACK_OF(X509) *
brix_gsi_parse_x509_signed(brix_ctx_t *ctx, ngx_connection_t *c)
{
    const u_char   *payload = ctx->recv.payload;
    size_t          plen = ctx->recv.cur_dlen;
    ngx_log_t      *log = c->log;
    const u_char   *main_data = NULL;
    size_t          main_len = 0;
    EVP_PKEY       *peer;
    unsigned char  *secret = NULL;
    size_t          secret_len = 0;
    gsi_session_cipher_t sc = {0};
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
     * Padded (HasPad=1) DH secret (helper); signing_key = SHA-256(secret)
     * mirrors the unsigned path; sigver is off by default whenever signed-DH is
     * selected.  gsi_signed_derive_secret frees `peer` on every path.
     */
    secret = gsi_signed_derive_secret(c, ctx->gsi.dh_key, peer, &secret_len);
    if (secret == NULL) {
        return NULL;
    }

    if (!gsi_signed_select_key(payload, plen, secret, secret_len, &sc)) {
        return NULL;
    }

    /* Persist the session cipher for a possible §F6 delegation round — signed-DH
     * path always uses an IV-prepended main (use_iv=1). */
    gsi_persist_session_cipher(ctx, sc.name, sc.aeskey, sc.cipher.key_len, 1);

    (void) gsi_store_signing_key(ctx, secret, secret_len);
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
    plain = brix_gsi_cipher_decrypt(&sc.cipher, sc.aeskey, main_data, main_len,
                                      1, &plain_len);
    OPENSSL_cleanse(sc.aeskey, sizeof(sc.aeskey));
    if (plain == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: GSI signed-DH: main decrypt failed");
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   "brix: GSI signed-DH decrypted kXRS_main: %uz bytes",
                   plain_len);
    gsi_capture_client_rtag(ctx, plain, plain_len);   /* §F6 delegation rtag */
    gsi_capture_fullproxy(ctx, plain, plain_len);     /* §5.1 full-proxy PT */
    chain = gsi_chain_from_plaintext(plain, (int) plain_len, log);
    free(plain);
    return chain;
}
