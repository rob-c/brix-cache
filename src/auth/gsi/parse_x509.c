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
 * gsi_persist_session_cipher — stash the negotiated GSI session cipher on the
 * connection so a later kXGS_pxyreq/kXGC_sigpxy delegation round (phase-57 §F6)
 * can encrypt/decrypt its main with the same key. Purely additive: the key is
 * already derived for the kXGC_cert decrypt; this copies it (≤32 bytes) + the
 * cipher name + the IV flag. Inert unless brix_tpc_delegate consumes it. The
 * key is cleansed once delegation completes (auth.c) or at disconnect.
 */
void
gsi_persist_session_cipher(brix_ctx_t *ctx, const char *name,
                           const u_char *key, int keylen, int use_iv)
{
    int n = (keylen > 32) ? 32 : (keylen < 0 ? 0 : keylen);
    size_t nl = ngx_strlen(name);

    ngx_memcpy(ctx->gsi.sess_key, key, (size_t) n);
    ctx->gsi.sess_keylen = n;
    ctx->gsi.sess_use_iv = use_iv;
    if (nl > sizeof(ctx->gsi.sess_cipher) - 1) {
        nl = sizeof(ctx->gsi.sess_cipher) - 1;
    }
    ngx_memcpy(ctx->gsi.sess_cipher, name, nl);
    ctx->gsi.sess_cipher[nl] = '\0';
}

/*
 * gsi_capture_client_rtag — stash the client's kXGC_cert random tag from the
 * decrypted main, so a §F6 kXGS_pxyreq can RSA-sign it (kXRS_signed_rtag) and the
 * client's CheckRtag accepts the delegation round. Inert unless delegation runs.
 */
void
gsi_capture_client_rtag(brix_ctx_t *ctx, const u_char *plain, size_t plain_len)
{
    const uint8_t *rt = NULL;
    size_t         rtl = 0;

    if (brix_gsi_find_bucket(plain, plain_len, (uint32_t) kXRS_rtag, &rt, &rtl)
        == 0 && rtl > 0 && rtl <= sizeof(ctx->gsi.deleg_client_rtag)) {
        ngx_memcpy(ctx->gsi.deleg_client_rtag, rt, rtl);
        ctx->gsi.deleg_client_rtag_len = (int) rtl;
    }
}

/*
 * gsi_chain_from_plaintext — extract the client proxy chain from a decrypted
 * kXRS_main plaintext (shared by the unsigned and signed-DH round-2 paths).
 * The plaintext is itself an XrdSutBuffer carrying a kXRS_x509 bucket whose
 * data is the PEM-concatenated proxy chain.  Returns a non-empty
 * STACK_OF(X509) (caller sk_X509_pop_free) or NULL.
 */
/*
 * gsi_capture_fullproxy — stash an OPTIONAL client-pushed full proxy PEM
 * (kXRS_x509_fullproxy) from the decrypted kXGC_cert inner buffer (phase-70
 * §5.1). Purely additive: absent in every stock client, present only when the
 * user opted in. Heap-copies the raw bytes onto ctx->gsi.client_fullproxy_pem;
 * auth.c later validates (DN == authenticated DN) and promotes them. The bytes
 * carry a PRIVATE KEY, so they are never logged. No-op when the bucket is
 * missing, empty, or a prior one was already captured.
 */
void
gsi_capture_fullproxy(brix_ctx_t *ctx, const u_char *plain, size_t plain_len)
{
    const u_char *pem = NULL;
    size_t        pemlen = 0;
    u_char       *copy;

    if (ctx->gsi.client_fullproxy_pem != NULL) {
        return;
    }
    if (gsi_find_bucket(plain, plain_len, (uint32_t) kXRS_x509_fullproxy,
                        &pem, &pemlen) != 0 || pemlen == 0) {
        return;
    }
    copy = malloc(pemlen);
    if (copy == NULL) {
        return;
    }
    ngx_memcpy(copy, pem, pemlen);
    ctx->gsi.client_fullproxy_pem = copy;
    ctx->gsi.client_fullproxy_len = pemlen;
}

STACK_OF(X509) *
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
 * gsi_store_signing_key — WHAT: derive signing_key = SHA-256(secret) and, on
 * success, install it into ctx->sigver and set signing_active. WHY: both the
 * unsigned and signed-DH kXGC_cert paths derive the kXR_sigver HMAC key the
 * SAME way (SHA-256 over the raw DH shared secret) — this is the single point of
 * truth so the two paths stay byte-identical. HOW: pure digest over `secret`;
 * only mutates ctx when all three EVP digest steps succeed (fail-quiet, matching
 * prior behaviour where a digest failure simply left signing inactive). Returns
 * 1 if signing was activated, 0 otherwise (caller may log on the 1 branch).
 */
int
gsi_store_signing_key(brix_ctx_t *ctx, const unsigned char *secret,
                      size_t secret_len)
{
    EVP_MD_CTX   *mdctx = EVP_MD_CTX_new();
    unsigned int  dlen = 32;
    u_char        digest[32];
    int           ok = 0;

    if (mdctx
        && EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1
        && EVP_DigestUpdate(mdctx, secret, secret_len) == 1
        && EVP_DigestFinal_ex(mdctx, digest, &dlen) == 1)
    {
        ngx_memcpy(ctx->sigver.signing_key, digest, 32);
        ctx->sigver.signing_active = 1;
        ok = 1;
    }
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    return ok;
}
