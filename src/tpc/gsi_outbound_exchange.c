#include "tpc_internal.h"
#include "../session/session.h"
#include "../protocol/gsi.h"
#include "../gsi/gsi_core.h"   /* shared XrdSecgsi DH/cipher kernel (EOS-proven) */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

/* ---- File: gsi_outbound_exchange.c — GSI round-2 driver for native TPC pull ----
 *
 * WHAT: tpc_outbound_gsi_exchange completes the outbound GSI handshake on a TPC
 *   pull socket after gsi_outbound_certreq.c has sent kXGC_certreq and received
 *   the server's kXGS_cert (`body`). It (optionally) verifies the server leaf cert
 *   against conf->gsi_store, serialises our proxy cert chain to PEM, and hands the
 *   server reply + proxy credential to the SHARED XrdSecgsi round-2 builder
 *   (xrootd_gsi_build_cert_response, src/gsi/gsi_core.c) — the exact
 *   implementation the native client uses. It then sends the resulting kXGC_cert
 *   (kXR_auth seq=4) and checks the server's final status == kXR_ok.
 *
 * WHY: The DH-variant detection, AES session-key agreement, proof-of-possession
 *   (signing the server rtag with our proxy key), encrypted cert-chain main and
 *   outer kXGC_cert assembly are identical to the client's. Routing both through
 *   one kernel removes a ~280-line parallel reimplementation (this file used to
 *   carry it) and gives the destination the signed-DH path for free: whatever DH
 *   variant the server offers, the shared builder handles it.
 *
 * HOW: optional X509_verify_cert(conf->gsi_store, server-leaf) → BIO_s_mem +
 *   PEM_write_bio_X509(chain) → xrootd_gsi_build_cert_response(body, dlen,
 *   chain_pem, pkey, &payload, &plen) → free(body) → tpc_send_kxr_auth(seq=4,
 *   payload) → tpc_recv_response → status==kXR_ok ? 0 : -1. Resource ownership:
 *   this function owns `body` (frees on every exit; the caller NULLs its copy) and
 *   the proxy-chain BIO + response payload it allocates; it does NOT free
 *   x/chain/pkey/certreq/cbio/kbio — gsi_outbound_certreq.c owns those.
 * ------------------------------------------------------------------ */

/*
 * tpc_gsi_exchange_cleanup — release the round-2 resources (each guard NULL-safe)
 * and return rc.  The shared kernel owns its own ephemeral DH keypair, so the only
 * resources this driver holds are the server reply `body`, the proxy-chain PEM BIO
 * and the malloc'd response payload.  Replaces the former round_fail/done ladder.
 */
static int
tpc_gsi_exchange_cleanup(int rc, u_char *body, BIO *chain_bio, u_char *payload)
{
    if (body) free(body);
    if (chain_bio) BIO_free(chain_bio);
    if (payload) free(payload);
    return rc;
}

/* WHAT: GSI round-2 driver for outbound TPC — verify server cert (optional), build
 * the kXGC_cert via the shared gsi_core kernel, send it + check kXR_ok. Returns 0
 * or -1 with t->xrd_error set. Caller: gsi_outbound_certreq.c. */
int
tpc_outbound_gsi_exchange(xrootd_tpc_pull_t *t, int fd,
    u_char *body, uint32_t dlen,
    X509 *x, STACK_OF(X509) *chain, EVP_PKEY *pkey,
    u_char *certreq, BIO *cbio, BIO *kbio)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    int        rc = -1;
    uint16_t   status;
    BIO       *chain_bio = NULL;
    BUF_MEM   *bptr = NULL;
    u_char    *payload = NULL;
    uint32_t   plen = 0;
    char       err[160];
    int        ci;

    /*
     * Optional: verify the server leaf cert using our CA store before we derive a
     * shared secret with it. X509_V_FLAG_ALLOW_PROXY_CERTS is set because GSI
     * delegated proxies are legitimate here. Skipped entirely when no store is
     * configured or the server omitted its kXRS_x509 bucket — only a
     * present-but-invalid cert aborts the handshake.
     */
    if (conf->gsi_store != NULL) {
        const u_char *srv_pem;
        size_t        srv_pem_len;

        if (gsi_find_bucket(body, dlen, (uint32_t) kXRS_x509,
                            &srv_pem, &srv_pem_len)
            == 0 && srv_pem_len > 0)
        {
            BIO              *mbio;
            X509             *srv;
            X509_STORE_CTX   *sctx;

            mbio = BIO_new_mem_buf(srv_pem, (int) srv_pem_len);
            srv = PEM_read_bio_X509(mbio, NULL, NULL, NULL);
            BIO_free(mbio);

            if (srv != NULL) {
                sctx = X509_STORE_CTX_new();
                if (sctx
                    && X509_STORE_CTX_init(sctx, conf->gsi_store, srv, NULL)
                       == 1)
                {
                    X509_STORE_CTX_set_flags(sctx, X509_V_FLAG_ALLOW_PROXY_CERTS);
                    if (X509_verify_cert(sctx) != 1) {
                        snprintf(t->err_msg, sizeof(t->err_msg),
                                 "TPC GSI server certificate verification failed");
                        t->xrd_error = kXR_NotAuthorized;
                        X509_STORE_CTX_free(sctx);
                        X509_free(srv);
                        return tpc_gsi_exchange_cleanup(rc, body, chain_bio,
                                                        payload);
                    }
                }
                if (sctx) {
                    X509_STORE_CTX_free(sctx);
                }
                X509_free(srv);
            }
        }
    }

    /* Serialise our proxy cert chain to one contiguous PEM blob (leaf first) for
     * the shared builder's kXRS_x509 bucket. */
    chain_bio = BIO_new(BIO_s_mem());
    if (chain_bio == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC GSI out of memory");
        t->xrd_error = kXR_NoMemory;
        return tpc_gsi_exchange_cleanup(rc, body, chain_bio, payload);
    }
    for (ci = 0; ci < sk_X509_num(chain); ci++) {
        PEM_write_bio_X509(chain_bio, sk_X509_value(chain, ci));
    }
    BIO_get_mem_ptr(chain_bio, &bptr);

    /*
     * Build the round-2 kXGC_cert via the SHARED XrdSecgsi kernel — the exact
     * implementation the native client uses (proven wire-compatible vs real EOS +
     * stock XrdSecgsi). It detects the DH variant, agrees the AES session key,
     * signs the server rtag with our proxy key (proof-of-possession), and
     * assembles the encrypted proxy chain + our DH public. chain PEM + pkey are
     * borrowed (we still own/free them via the certreq.c finalizer).
     */
    err[0] = '\0';
    if (xrootd_gsi_build_cert_response(body, dlen,
                                       (const uint8_t *) bptr->data,
                                       bptr->length, pkey,
                                       &payload, &plen, err, sizeof(err)) != 0)
    {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI round-2 build failed: %s", err[0] ? err : "unknown");
        t->xrd_error = kXR_NotAuthorized;
        return tpc_gsi_exchange_cleanup(rc, body, chain_bio, payload);
    }

    /* The round-1 server body is consumed; free it (and the chain BIO) before we
     * block on the round-2 round trip. NULL them so cleanup won't double-free. */
    free(body);
    body = NULL;
    BIO_free(chain_bio);
    chain_bio = NULL;

    /* round 2: send our kXGC_cert (seq=4 — protocol=1, login=2, certreq=3). */
    if (tpc_send_kxr_auth(t, fd, 4, payload, plen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC GSI round-2 send failed");
        t->xrd_error = kXR_ServerError;
        return tpc_gsi_exchange_cleanup(rc, body, chain_bio, payload);
    }
    free(payload);
    payload = NULL;

    /* Await the server's verdict. kXR_ok == authenticated. */
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI final auth recv failed");
        t->xrd_error = kXR_ServerError;
        return tpc_gsi_exchange_cleanup(rc, body, chain_bio, payload);
    }
    if (status != kXR_ok) {
        const char *emsg = (body != NULL && dlen > 4)
                           ? (const char *) (body + 4) : "";
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI authentication failed (status=%u): %.*s",
                 (unsigned) status,
                 (int) (dlen > 4 ? dlen - 4 : 0), emsg);
        t->xrd_error = kXR_AuthFailed;
        return tpc_gsi_exchange_cleanup(rc, body, chain_bio, payload);
    }

    rc = 0;
    return tpc_gsi_exchange_cleanup(rc, body, chain_bio, payload);
}
