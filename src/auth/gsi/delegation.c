/* File: delegation.c — GSI X.509 proxy delegation, inbound capture (§F6)
 * WHAT: The destination's GSI-server side of proxy delegation. After a verified
 *   kXGC_cert, brix_gsi_begin_delegation() sends a kXGS_pxyreq (a proxy-cert
 *   request, encrypted under the session cipher); brix_gsi_handle_sigpxy()
 *   consumes the client's kXGC_sigpxy (the signed proxy) and assembles the
 *   delegated credential onto the connection.
 *
 * WHY: So a TPC pull can authenticate to the source AS THE USER (the delegated
 *   proxy) rather than as the gateway. Gated on brix_tpc_delegate (default off).
 *
 * HOW: build_pxyreq(leaf) → nested XrdSutBuffer {kXGS_pxyreq + kXRS_x509_req} →
 *   encrypt with the persisted session cipher → outer {kXRS_main + kXRS_cipher_alg}
 *   → kXR_authmore. On kXGC_sigpxy: find kXRS_main → decrypt → find kXRS_x509 →
 *   assemble_proxy(signed, saved reqkey, saved chain). No goto: bundled NULL-safe
 *   cleanup; ownership-transferred fields NULLed before cleanup. */

#include "gsi_internal.h"
#include "gsi_core.h"
#include "delegation.h"
#include "proxy_req.h"
#include "protocols/root/protocol/gsi.h"
#include "protocols/root/response/response.h"
#include "protocols/root/connection/write_helpers.h"
#include "core/compat/alloc_guard.h"

#include <string.h>
#include <stdlib.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

/* Serialise an X509 (or the whole chain when chain!=NULL) to a malloc'd PEM. */
static u_char *
gsi_pem_export(X509 *one, STACK_OF(X509) *chain, size_t *len)
{
    BIO    *b = BIO_new(BIO_s_mem());
    char   *d;
    long    n;
    u_char *out = NULL;
    int     ok = 0;

    if (b != NULL) {
        if (chain != NULL) {
            int i;
            ok = 1;
            for (i = 0; i < sk_X509_num(chain); i++) {
                if (PEM_write_bio_X509(b, sk_X509_value(chain, i)) != 1) {
                    ok = 0;
                }
            }
        } else {
            ok = (PEM_write_bio_X509(b, one) == 1);
        }
    }
    if (ok) {
        n = BIO_get_mem_data(b, &d);
        out = malloc((size_t) n + 1);
        if (out != NULL) {
            memcpy(out, d, (size_t) n);
            out[n] = '\0';
            *len = (size_t) n;
        }
    }
    BIO_free(b);
    return out;
}

/*
 * Re-encode a DER X509_REQ as PEM.  The stock XrdSecgsi client parses the
 * kXRS_x509_req bucket with PEM_read_bio_X509_REQ (XrdCryptosslX509Req), so the
 * proxy request MUST travel as PEM on the wire; brix_gsi_build_pxyreq emits
 * DER (consumed as DER by brix_gsi_sign_pxyreq and its unit tests), so the
 * conversion happens here at the wire edge rather than in the crypto core.
 * A DER request sent verbatim makes the client reject it with
 * "could not resolve proxy request" and decline to delegate.
 */
static u_char *
gsi_req_der_to_pem(const u_char *der, size_t der_len, size_t *pem_len)
{
    const unsigned char *p = der;
    X509_REQ            *req = d2i_X509_REQ(NULL, &p, (long) der_len);
    BIO                 *b;
    char                *d;
    long                 n;
    u_char              *out = NULL;

    if (req == NULL) {
        return NULL;
    }
    b = BIO_new(BIO_s_mem());
    if (b != NULL && PEM_write_bio_X509_REQ(b, req) == 1) {
        n = BIO_get_mem_data(b, &d);
        out = malloc((size_t) n + 1);
        if (out != NULL) {
            memcpy(out, d, (size_t) n);
            out[n] = '\0';
            *pem_len = (size_t) n;
        }
    }
    BIO_free(b);
    X509_REQ_free(req);
    return out;
}

/* Resolve the persisted session cipher; -1 if none was captured. */
static int
gsi_session_cipher(brix_ctx_t *ctx, brix_gsi_cipher_t *cipher)
{
    if (ctx->gsi_sess_keylen <= 0) {
        return -1;
    }
    if (!brix_gsi_cipher_lookup(ctx->gsi_sess_cipher, cipher)
        && !brix_gsi_cipher_lookup("aes-128-cbc", cipher)) {
        return -1;
    }
    return 0;
}

void
brix_gsi_delegation_cleanup(brix_ctx_t *ctx)
{
    if (ctx->gsi_deleg_reqkey != NULL) {
        EVP_PKEY_free(ctx->gsi_deleg_reqkey);
        ctx->gsi_deleg_reqkey = NULL;
    }
    if (ctx->gsi_deleg_chain_pem != NULL) {
        free(ctx->gsi_deleg_chain_pem);
        ctx->gsi_deleg_chain_pem = NULL;
        ctx->gsi_deleg_chain_len = 0;
    }
    if (ctx->gsi_deleg_proxy_pem != NULL) {
        free(ctx->gsi_deleg_proxy_pem);
        ctx->gsi_deleg_proxy_pem = NULL;
        ctx->gsi_deleg_proxy_len = 0;
    }
    OPENSSL_cleanse(ctx->gsi_sess_key, sizeof(ctx->gsi_sess_key));
    ctx->gsi_sess_keylen = 0;
    ctx->gsi_deleg_await = 0;
}

/* Owned scratch for one begin_delegation; freed once (no goto). */
typedef struct {
    u_char      *leaf_pem;
    u_char      *chain_pem;
    size_t       chain_len;
    u_char      *req_der;
    size_t       req_len;
    u_char      *req_pem;
    size_t       req_pem_len;
    EVP_PKEY    *reqkey;
    uint8_t     *enc;
    size_t       enc_len;
    brix_gbuf  inner;
    brix_gbuf  outer;
} bdg_ctx;

static ngx_int_t
bdg_fail(bdg_ctx *b)
{
    free(b->leaf_pem);
    free(b->chain_pem);
    free(b->req_der);
    free(b->req_pem);
    if (b->reqkey) EVP_PKEY_free(b->reqkey);
    free(b->enc);
    brix_gbuf_free(&b->inner);
    brix_gbuf_free(&b->outer);
    return NGX_ERROR;
}

ngx_int_t
brix_gsi_begin_delegation(brix_ctx_t *ctx, ngx_connection_t *c,
                            ngx_stream_brix_srv_conf_t *conf,
                            X509 *leaf, STACK_OF(X509) *chain)
{
    bdg_ctx              b;
    brix_gsi_cipher_t  cipher;
    char                 err[160];
    size_t               leaf_len = 0;
    size_t               calg_len, body_len, total;
    u_char              *buf, *p;
    uint8_t              signed_rtag[1024];
    size_t               signed_rtag_len = 0;
    uint8_t              new_rtag[20];

    memset(&b, 0, sizeof(b));
    brix_gbuf_init(&b.inner);
    brix_gbuf_init(&b.outer);

    if (gsi_session_cipher(ctx, &cipher) != 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI delegation: no session cipher captured");
        return bdg_fail(&b);
    }

    b.leaf_pem  = gsi_pem_export(leaf, NULL, &leaf_len);
    b.chain_pem = gsi_pem_export(NULL, chain, &b.chain_len);
    if (b.leaf_pem == NULL || b.chain_pem == NULL) {
        return bdg_fail(&b);
    }

    /* Build the proxy request for the client's leaf (verified RFC-3820 crypto). */
    err[0] = '\0';
    if (brix_gsi_build_pxyreq(b.leaf_pem, leaf_len, &b.reqkey,
                                &b.req_der, &b.req_len, err, sizeof(err)) != 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI delegation: build pxyreq failed: %s", err);
        return bdg_fail(&b);
    }

    /* The stock client parses kXRS_x509_req as PEM — re-encode the DER request. */
    b.req_pem = gsi_req_der_to_pem(b.req_der, b.req_len, &b.req_pem_len);
    if (b.req_pem == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI delegation: cannot PEM-encode proxy request");
        return bdg_fail(&b);
    }

    /*
     * Rtag proof-chain: RSA-sign (EncryptPrivate, our cert key) the client's
     * kXGC_cert random tag → kXRS_signed_rtag; the client's CheckRtag verifies it
     * with our public key and rejects the round otherwise ("random tag missing").
     * Add a fresh kXRS_rtag challenge for the client to sign in kXGC_sigpxy.
     */
    if (ctx->gsi_deleg_client_rtag_len > 0 && conf->gsi_key != NULL) {
        signed_rtag_len = brix_gsi_rsa_encrypt_private(
            conf->gsi_key, ctx->gsi_deleg_client_rtag,
            (size_t) ctx->gsi_deleg_client_rtag_len,
            signed_rtag, sizeof(signed_rtag));
    }
    if (signed_rtag_len == 0 || !brix_gsi_rand(new_rtag, sizeof(new_rtag))) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI delegation: cannot sign rtag (proof-of-possession)");
        return bdg_fail(&b);
    }

    /* Nested main = {kXGS_pxyreq + signed_rtag + rtag + kXRS_x509_req + none}. */
    brix_gbuf_start(&b.inner, (uint32_t) kXGS_pxyreq);
    brix_gbuf_bucket(&b.inner, (uint32_t) kXRS_signed_rtag,
                       signed_rtag, signed_rtag_len);
    brix_gbuf_bucket(&b.inner, (uint32_t) kXRS_rtag, new_rtag, sizeof(new_rtag));
    brix_gbuf_bucket(&b.inner, (uint32_t) kXRS_x509_req, b.req_pem, b.req_pem_len);
    brix_gbuf_end(&b.inner);
    if (b.inner.err) {
        return bdg_fail(&b);
    }
    b.enc = brix_gsi_cipher_encrypt(&cipher, ctx->gsi_sess_key, b.inner.p,
                                      b.inner.len, ctx->gsi_sess_use_iv,
                                      &b.enc_len);
    if (b.enc == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI delegation: encrypt pxyreq main failed");
        return bdg_fail(&b);
    }

    /* Outer kXGS_pxyreq = {kXRS_main(enc) + kXRS_cipher_alg + none}. */
    calg_len = ngx_strlen(ctx->gsi_sess_cipher);
    brix_gbuf_start(&b.outer, (uint32_t) kXGS_pxyreq);
    brix_gbuf_bucket(&b.outer, (uint32_t) kXRS_main, b.enc, b.enc_len);
    brix_gbuf_bucket(&b.outer, (uint32_t) kXRS_cipher_alg,
                       ctx->gsi_sess_cipher, calg_len);
    brix_gbuf_end(&b.outer);
    if (b.outer.err) {
        return bdg_fail(&b);
    }

    /* Frame as kXR_authmore + the gsi payload, into a pool buffer for queueing. */
    body_len = b.outer.len;
    total = XRD_RESPONSE_HDR_LEN + body_len;
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return bdg_fail(&b);
    }
    brix_build_resp_hdr(ctx->cur_streamid, kXR_authmore,
                          (uint32_t) body_len, (ServerResponseHdr *) buf);
    p = buf + XRD_RESPONSE_HDR_LEN;
    ngx_memcpy(p, b.outer.p, body_len);

    /* Hand the request key + client chain to the connection for kXGC_sigpxy. */
    ctx->gsi_deleg_reqkey    = b.reqkey;  b.reqkey = NULL;
    ctx->gsi_deleg_chain_pem = b.chain_pem; b.chain_pem = NULL;
    ctx->gsi_deleg_chain_len = b.chain_len;
    ctx->gsi_deleg_await     = 1;

    (void) bdg_fail(&b);   /* free the rest (req_der, enc, gbufs, leaf_pem) */

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: GSI delegation: sent kXGS_pxyreq (awaiting signed proxy)");
    return brix_queue_response(ctx, c, buf, total);
}

ngx_int_t
brix_gsi_handle_sigpxy(brix_ctx_t *ctx, ngx_connection_t *c)
{
    const u_char        *payload = ctx->payload;
    size_t               plen = ctx->cur_dlen;
    brix_gsi_cipher_t  cipher;
    const uint8_t       *enc = NULL, *signed_pem = NULL;
    size_t               enc_len = 0, signed_len = 0;
    uint8_t             *plain = NULL;
    size_t               plain_len = 0;
    char                 err[160];
    ngx_int_t            rc = NGX_ERROR;

    if (!ctx->gsi_deleg_await || ctx->gsi_deleg_reqkey == NULL
        || ctx->gsi_deleg_chain_pem == NULL
        || gsi_session_cipher(ctx, &cipher) != 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI kXGC_sigpxy: not awaiting delegation");
        return NGX_ERROR;
    }

    if (brix_gsi_find_bucket(payload, plen, (uint32_t) kXRS_main,
                               &enc, &enc_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI kXGC_sigpxy: kXRS_main missing");
        return NGX_ERROR;
    }
    plain = brix_gsi_cipher_decrypt(&cipher, ctx->gsi_sess_key, enc, enc_len,
                                      ctx->gsi_sess_use_iv, &plain_len);
    if (plain == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI kXGC_sigpxy: main decrypt failed");
        return NGX_ERROR;
    }

    if (brix_gsi_find_bucket(plain, plain_len, (uint32_t) kXRS_x509,
                               &signed_pem, &signed_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI kXGC_sigpxy: signed proxy (kXRS_x509) missing "
                      "(client declined to delegate?)");
        free(plain);
        return NGX_ERROR;
    }

    /* Verify the signed proxy's key matches our request key (assemble's contract);
     * its cert+chain output is discarded — we build a fuller credential below. */
    err[0] = '\0';
    {
        u_char *verify_out = NULL;
        size_t  verify_len = 0;

        if (brix_gsi_assemble_proxy(signed_pem, signed_len, ctx->gsi_deleg_reqkey,
                                      ctx->gsi_deleg_chain_pem,
                                      ctx->gsi_deleg_chain_len, &verify_out,
                                      &verify_len, err, sizeof(err)) != 0) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: GSI kXGC_sigpxy: assemble proxy failed: %s", err);
            free(plain);
            return NGX_ERROR;
        }
        free(verify_out);
    }

    /*
     * Build the full pull credential = proxy cert + its private key (our request
     * key) + issuer chain, PEM, so the TPC pull can authenticate to the source AS
     * THE USER (loaded in src/tpc/gsi/gsi_outbound_certreq.c).
     */
    {
        BIO    *kb = BIO_new(BIO_s_mem());
        char   *kd = NULL;
        long    kl = 0;
        u_char *cred;
        size_t  total;

        if (kb == NULL
            || PEM_write_bio_PrivateKey(kb, ctx->gsi_deleg_reqkey, NULL, NULL, 0,
                                        NULL, NULL) != 1) {
            BIO_free(kb);
            free(plain);
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: GSI kXGC_sigpxy: cannot export proxy key");
            return NGX_ERROR;
        }
        kl = BIO_get_mem_data(kb, &kd);
        total = signed_len + ctx->gsi_deleg_chain_len + (size_t) kl;
        cred = malloc(total + 1);
        if (cred == NULL) {
            BIO_free(kb);
            free(plain);
            return NGX_ERROR;
        }
        /* Order: proxy cert + issuer chain + key — so a cert-reader stops cleanly
         * at the trailing key block while a key-reader skips the cert blocks. */
        ngx_memcpy(cred, signed_pem, signed_len);
        ngx_memcpy(cred + signed_len, ctx->gsi_deleg_chain_pem,
                   ctx->gsi_deleg_chain_len);
        ngx_memcpy(cred + signed_len + ctx->gsi_deleg_chain_len, kd, (size_t) kl);
        cred[total] = '\0';
        BIO_free(kb);
        free(ctx->gsi_deleg_proxy_pem);
        ctx->gsi_deleg_proxy_pem = cred;
        ctx->gsi_deleg_proxy_len = total;
    }
    free(plain);

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: GSI delegation: captured delegated proxy (%uz bytes) "
                  "dn=\"%s\"", ctx->gsi_deleg_proxy_len, ctx->dn);

    /* The request key is consumed; the captured proxy credential remains for the
     * TPC pull. Clear the await flag + cleanse the session key. */
    EVP_PKEY_free(ctx->gsi_deleg_reqkey);
    ctx->gsi_deleg_reqkey = NULL;
    ctx->gsi_deleg_await = 0;
    OPENSSL_cleanse(ctx->gsi_sess_key, sizeof(ctx->gsi_sess_key));
    ctx->gsi_sess_keylen = 0;
    rc = NGX_OK;
    return rc;
}
