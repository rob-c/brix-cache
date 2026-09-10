/* File: auth_gsi.c — outbound GSI (X.509 proxy) authentication for the transparent upstream
 * WHAT: the two client-side rounds of an XrdSecgsi handshake the upstream connector
 *   performs when the upstream's kXR_login advert lists `gsi` and
 *   brix_upstream_x509_proxy is configured (phase 115 W2.4).
 *     round 1  brix_upstream_send_gsi_certreq — parse the advert parms, mint the
 *              signed-DH kXGC_certreq via the shared gsi_core wrapper, send it as
 *              kXR_auth "gsi" and mark up->gsi_round = 1.
 *     round 2  brix_upstream_gsi_respond — the reply (kXR_authmore + kXGS_cert) is in
 *              up->resp_body: verify the server's kXRS_x509 leaf against
 *              conf->gsi_store, load the proxy PEM + key, build the kXGC_cert answer
 *              with brix_gsi_build_cert_response, send it, mark up->gsi_round = 2.
 *   The final kXR_ok/kXR_error is judged by bootstrap.c (brix_upstream_bs_auth).
 *
 * WHY: before this file the connector only knew ztn, and only when the upstream
 *   answered kXR_login with kXR_authmore (a stub convention).  A real brix or stock
 *   XRootD server answers kXR_ok + session id + "&P=gsi,...&P=ztn,..." and then
 *   refuses the unauthenticated relayed request — so a GSI-only redirector could
 *   not sit behind a transparent proxy at all.  Sharing the kernel (gsi_core), the
 *   credential loaders (auth/gsi/cred_load) and the peer-leaf verifier
 *   (auth/crypto/gsi_verify) with the cache origin and the TPC destination keeps
 *   the three server-side GSI clients byte-identical on the wire.
 *
 * HOW: every step is a small early-return function; heap results (certreq, PEM,
 *   key, payload) are freed on every exit; failures log the specific reason at ERR
 *   on the upstream connection log and return NGX_ERROR so the caller aborts with
 *   a client-visible kXR_ServerError.  Verification policy: no gsi_store (no
 *   brix_trusted_ca) → warn once per handshake and proceed (the operator opted out,
 *   as on the cache origin); missing bucket or verdict != 1 → refuse.
 */

#include "upstream_internal.h"
#include "auth/gsi/gsi_core.h"
#include "auth/gsi/cred_load.h"
#include "auth/crypto/gsi_verify.h"
#include "auth/crypto/scoped.h"
#include "protocols/root/protocol/gsi.h"

#include <stdlib.h>

ngx_int_t
brix_upstream_send_gsi_certreq(brix_upstream_t *up, const char *gsi_parms)
{
    uint8_t    rtag[BRIX_GSI_RTAG_LEN];
    uint8_t   *certreq;
    size_t     certreq_len = 0;
    ngx_int_t  rc;

    certreq = brix_gsi_build_certreq_from_parms(gsi_parms, rtag, &certreq_len);
    if (certreq == NULL) {
        ngx_log_error(NGX_LOG_ERR, up->conn->log, 0,
                      "brix: upstream gsi: certreq build failed");
        return NGX_ERROR;
    }
    up->gsi_round = 1;
    rc = brix_upstream_send_auth_frame(up, "gsi", certreq, certreq_len);
    free(certreq);
    return rc;
}

/* upstream_gsi_verify_server — MITM checkpoint before agreeing a session secret.
 * Returns NGX_OK when the leaf verifies (or no trust store is configured),
 * NGX_ERROR (reason logged) when the server offered no certificate or it fails. */
static ngx_int_t
upstream_gsi_verify_server(brix_upstream_t *up,
    ngx_stream_brix_srv_conf_t *conf)
{
    const uint8_t  *pem = NULL;
    size_t          pem_len = 0;

    if (conf->gsi_store == NULL) {
        ngx_log_error(NGX_LOG_WARN, up->conn->log, 0,
                      "brix: upstream gsi: no brix_trusted_ca configured; "
                      "upstream server certificate not verified");
        return NGX_OK;
    }
    if (brix_gsi_find_bucket(up->resp_body, up->resp_dlen, (uint32_t) kXRS_x509,
                               &pem, &pem_len) != 0
        || pem_len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, up->conn->log, 0,
                      "brix: upstream gsi: server presented no certificate "
                      "to verify");
        return NGX_ERROR;
    }
    /* Unparseable (-1) and rejected (0) both fail closed: the upstream is a
     * credentialed peer, so "could not evaluate" is not "verified". */
    if (brix_gsi_verify_peer_leaf(conf->gsi_store, pem, pem_len) != 1) {
        ngx_log_error(NGX_LOG_ERR, up->conn->log, 0,
                      "brix: upstream gsi: server certificate verification "
                      "failed");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* upstream_gsi_load_cred — proxy chain from brix_upstream_x509_proxy, key from
 * brix_upstream_x509_key when set, else from the proxy PEM itself.  On success
 * the caller owns *pem (free) and *key (brix_evp_pkey_free); on failure both are
 * NULL and the reason is logged. */
static ngx_int_t
upstream_gsi_load_cred(brix_upstream_t *up, ngx_stream_brix_srv_conf_t *conf,
    uint8_t **pem, size_t *pem_len, EVP_PKEY **key)
{
    const char  *proxy_path = (const char *) conf->upstream_x509_proxy.data;
    const char  *key_path   = (conf->upstream_x509_key.len > 0)
                                ? (const char *) conf->upstream_x509_key.data
                                : proxy_path;

    *pem = brix_gsi_cred_load_pem(proxy_path, pem_len);
    *key = brix_gsi_cred_load_key(key_path);
    if (*pem != NULL && *key != NULL) {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_ERR, up->conn->log, 0,
                  "brix: upstream gsi: cannot load credential "
                  "brix_upstream_x509_proxy \"%V\"%s",
                  &conf->upstream_x509_proxy,
                  (*pem != NULL) ? " (private key)" : "");
    free(*pem);
    brix_evp_pkey_free(*key);
    *pem = NULL;
    *key = NULL;
    return NGX_ERROR;
}

ngx_int_t
brix_upstream_gsi_respond(brix_upstream_t *up, ngx_stream_brix_srv_conf_t *conf)
{
    uint8_t   *pem = NULL;
    size_t     pem_len = 0;
    EVP_PKEY  *key = NULL;
    uint8_t   *payload = NULL;
    uint32_t   plen = 0;
    char       err[128];
    ngx_int_t  rc;

    if (upstream_gsi_verify_server(up, conf) != NGX_OK
        || upstream_gsi_load_cred(up, conf, &pem, &pem_len, &key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    err[0] = '\0';
    if (brix_gsi_build_cert_response(up->resp_body, up->resp_dlen, pem, pem_len,
                                       key, &payload, &plen, err, sizeof(err))
        != 0)
    {
        ngx_log_error(NGX_LOG_ERR, up->conn->log, 0,
                      "brix: upstream gsi: cert response build failed: %s", err);
        rc = NGX_ERROR;
    } else {
        up->gsi_round = 2;
        rc = brix_upstream_send_auth_frame(up, "gsi", payload, plen);
    }

    free(payload);
    free(pem);
    brix_evp_pkey_free(key);
    return rc;
}
