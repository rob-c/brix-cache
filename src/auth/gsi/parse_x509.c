#include "gsi_internal.h"
#include "gsi_core.h"
#include <string.h>
#include <stdlib.h>
#include "parse_x509_internal.h"
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */

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
 * gsi_arm_request_signing — WHAT: arm kXR_sigver verification by copying the
 * just-persisted session cipher (ctx->gsi.sess_*) into the sigver-owned fields
 * and setting signing_active. WHY: the signature scheme is stock XrdSecProtect
 * secver 0 — the covered-bytes SHA-256 encrypted with the SESSION cipher — and
 * the verifier must outlive a §F6 delegation round, which cleanses
 * ctx->gsi.sess_key; sigver therefore keeps its own copy. HOW: validates that a
 * cipher was persisted and resolves in the allowlist with a key long enough;
 * only then copies name + key + IV flag and activates. Call immediately after
 * gsi_persist_session_cipher (both round-2 paths). Returns 1 if armed, 0 not.
 */
int
gsi_arm_request_signing(brix_ctx_t *ctx)
{
    brix_gsi_cipher_t cipher;

    if (ctx->gsi.sess_keylen <= 0
        || !brix_gsi_cipher_lookup(ctx->gsi.sess_cipher, &cipher)
        || ctx->gsi.sess_keylen < cipher.key_len)
    {
        return 0;
    }
    ngx_memcpy(ctx->sigver.sig_cipher, ctx->gsi.sess_cipher,
               sizeof(ctx->sigver.sig_cipher));
    ngx_memcpy(ctx->sigver.sig_key, ctx->gsi.sess_key,
               (size_t) ctx->gsi.sess_keylen);
    ctx->sigver.sig_keylen = ctx->gsi.sess_keylen;
    ctx->sigver.sig_use_iv = ctx->gsi.sess_use_iv;
    ctx->sigver.signing_active = 1;
    return 1;
}
