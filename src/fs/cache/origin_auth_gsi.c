/*
 * cache/origin_auth_gsi.c — origin-side GSI (X.509 proxy) auth for cache fills.
 *
 * Split out of origin_auth.c: the two-round XrdSecgsi handshake a cache node
 * performs against its upstream origin (certreq → server cert → verify → cert
 * response → final).  Credential loading lives in auth/gsi/cred_load.c and the
 * peer-leaf verifier in auth/crypto/gsi_verify.c, both shared with the TPC
 * destination and the transparent upstream (phase 115 W2.4).  Keeping the GSI
 * handshake in its own file leaves origin_auth.c focused on the single-round ztn
 * and sss exchanges, and lets the security-sensitive X.509 verification path be
 * reviewed on its own.
 *
 * The public entry point brix_cache_origin_auth_gsi() is declared in
 * cache_internal.h and called from brix_cache_origin_bootstrap().  The shared
 * cache_origin_send_kxr_auth() framer lives in origin_auth.c (also declared in
 * cache_internal.h).
 */

#include "cache_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared handshake/login packers */
#include "protocols/root/protocol/frame_hdr.h"        /* xrd_error_body_decode */
#include "auth/gsi/gsi_core.h"              /* shared XrdSecgsi handshake kernel */
#include "auth/gsi/cred_load.h"             /* shared proxy PEM / key loaders */
#include "auth/crypto/gsi_verify.h"         /* brix_gsi_verify_peer_leaf */
#include "protocols/root/protocol/gsi.h"              /* kXRS_x509 bucket id */
#include "auth/sss/sss_keytab_kernel.h"     /* §14 SSS keytab line grammar */
#include <stdio.h>                        /* fdopen/fgets for the keytab reader */
/* macOS doesn't have endian.h - use libkern/OSByteOrder.h */
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "auth/crypto/scoped.h"   /* W3 NULL-safe destroyers (P90-27.1) */

/* originauth_gsi_certreq — round 1 of the origin GSI handshake: build a
 * kXGC_certreq from the origin's advertised gsi parms and send it as a kXR_auth.
 *
 * WHAT: parse `gsi_parms` for crypto/version/CA, mint a signed-DH certreq bucket,
 *       and write it to the origin connector stream.
 * WHY : isolates the pure request construction (parse + build) with its single
 *       side effect (the socket send) at the tail — the orchestrator stays flat.
 * HOW : brix_gsi_build_certreq_from_parms (shared with TPC and the transparent
 *       upstream: crypto "ssl" default, version 10600, 8-byte rtag, opts 0x80).
 * Returns 0 on a sent certreq, -1 (t error set) on RNG/build/write failure. */
static int
originauth_gsi_certreq(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const char *gsi_parms)
{
    uint8_t   client_rtag[BRIX_GSI_RTAG_LEN];
    uint8_t  *certreq;
    size_t    certreq_len = 0;
    int       rc;

    certreq = brix_gsi_build_certreq_from_parms(gsi_parms, client_rtag,
                                                  &certreq_len);
    if (certreq == NULL) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin gsi certreq build failed");
        return -1;
    }
    rc = cache_origin_send_kxr_auth(oc, "gsi", certreq, (uint32_t) certreq_len);
    free(certreq);
    if (rc != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin gsi certreq write failed");
        return -1;
    }
    return 0;
}

/* originauth_gsi_read_cert — read the round-1 reply and require a kXGS_cert.
 *
 * WHAT: read the origin's response to the certreq and validate it is a
 *       kXR_authmore carrying a >= 16-byte kXGS_cert body.
 * WHY : separates the wire read + status classification from the orchestrator;
 *       the caller owns *body and frees it exactly once.
 * HOW : kXR_error → surface the origin error; anything but kXR_authmore with a
 *       usable body -> AuthFailed. On success body/dlen are set for round 2.
 * Returns 0 with *body owned by the caller, -1 (t error set, *body freed). */
static int
originauth_gsi_read_cert(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    u_char **body, uint32_t *dlen)
{
    uint16_t  status;

    *body = NULL;
    if (brix_cache_read_response(t, oc, &status, body, dlen, 1 << 16) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        brix_cache_set_origin_error(t, *body, *dlen, "cache origin gsi rejected");
        free(*body);
        *body = NULL;
        return -1;
    }
    if (status != kXR_authmore || *body == NULL || *dlen < 16) {
        free(*body);
        *body = NULL;
        brix_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin gsi expected kXGS_cert");
        return -1;
    }
    return 0;
}

/* originauth_gsi_verify_srv_cert — MITM protection before agreeing a secret.
 *
 * WHAT: when the credential names a CA (conf->gsi_store), require the origin's
 *       server cert in the kXGS_cert body AND verify it against that store.
 * WHY : the shared secret must not be agreed with an unverified peer; this is the
 *       security checkpoint. No store = operator opted out (unauthenticated origin).
 * HOW : find the kXRS_x509 bucket, then brix_gsi_verify_peer_leaf (shared with
 *       the TPC destination and the transparent upstream). Verdict unchanged.
 * Returns 0 when verification passes (or is skipped), -1 (t error set) on failure.
 * Never frees `body` — the caller owns it. */
static int
originauth_gsi_verify_srv_cert(brix_cache_fill_t *t, const u_char *body,
    uint32_t dlen)
{
    const uint8_t  *srv_pem = NULL;
    size_t          srv_pem_len = 0;

    if (t->conf->gsi_store == NULL) {
        return 0;
    }
    if (brix_gsi_find_bucket(body, dlen, (uint32_t) kXRS_x509,
                               &srv_pem, &srv_pem_len) != 0
        || srv_pem_len == 0)
    {
        brix_cache_set_error(t, kXR_NotAuthorized, 0,
            "cache origin gsi: server presented no certificate to verify");
        return -1;
    }
    /* Unparseable (-1) and failed (0) both fail closed here: the cache origin
     * is a credentialed peer, so "could not evaluate" is not "verified". */
    if (brix_gsi_verify_peer_leaf(t->conf->gsi_store, srv_pem, srv_pem_len)
        != 1)
    {
        brix_cache_set_error(t, kXR_NotAuthorized, 0,
            "cache origin gsi: server certificate verification failed");
        return -1;
    }
    return 0;
}

/* originauth_gsi_cred_t — the round-2 proxy credential loaded from disk: the PEM
 * cert chain (pem/pem_len) and its private key. Grouped so the load/warn/send
 * steps thread one value and free it as a coherent pair. */
typedef struct {
    uint8_t   *pem;
    size_t     pem_len;
    EVP_PKEY  *key;
} originauth_gsi_cred_t;

/* originauth_gsi_load_credential — load the proxy PEM chain + private key.
 *
 * WHAT: load the cert chain from proxy_path and the key from either a separate
 *       configured key file (cache_origin_x509_key) or the same proxy PEM.
 * WHY : a plain host cert/key pair then works without hand-concatenation into a
 *       proxy; both are loaded together so the caller frees them as a pair.
 * HOW : brix_gsi_cred_load_pem + brix_gsi_cred_load_key; on any failure
 *       both are freed here and the struct is zeroed.
 * Returns 0 with cred fields owned by the caller, -1 (t error set). */
static int
originauth_gsi_load_credential(brix_cache_fill_t *t, const char *proxy_path,
    originauth_gsi_cred_t *cred)
{
    ngx_memzero(cred, sizeof(*cred));

    cred->pem = brix_gsi_cred_load_pem(proxy_path, &cred->pem_len);
    cred->key = brix_gsi_cred_load_key(
        (t->conf != NULL && t->conf->cache_origin_x509_key.len > 0)
            ? (const char *) t->conf->cache_origin_x509_key.data
            : proxy_path);
    if (cred->pem == NULL || cred->key == NULL) {
        free(cred->pem);
        brix_evp_pkey_free(cred->key);
        ngx_memzero(cred, sizeof(*cred));
        brix_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin gsi cannot load proxy credential");
        return -1;
    }
    return 0;
}

/* originauth_gsi_warn_bare_cert — warn if the credential is not a proxy chain.
 *
 * WHAT: count the PEM certificates in the loaded credential and, if fewer than 2,
 *       log a WARN explaining a stock XRootD origin will reject it.
 * WHY : a bare host cert (1 cert) fails at the origin with an opaque "received: 1,
 *       expected: >= 2" — this proactive message names the fix. Pure diagnostic;
 *       does NOT change the handshake outcome.
 * HOW : scan for "-----BEGIN CERTIFICATE-----" markers; warn when count < 2. */
static void
originauth_gsi_warn_bare_cert(const uint8_t *proxy_pem, size_t proxy_pem_len,
    const char *proxy_path)
{
    size_t            ncerts = 0, off = 0;
    static const char BEGIN[] = "-----BEGIN CERTIFICATE-----";
    const size_t      blen = sizeof(BEGIN) - 1;

    while (off < proxy_pem_len) {
        void *p = memmem(proxy_pem + off, proxy_pem_len - off, BEGIN, blen);
        if (p == NULL) { break; }
        ncerts++;
        off = (size_t) ((u_char *) p - proxy_pem) + blen;
    }
    if (ncerts < 2) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
            "brix: origin GSI credential \"%s\" has %uz certificate(s); a "
            "stock XRootD origin requires a delegated PROXY chain (>= 2: "
            "proxy + end-entity cert). A bare host cert/key will be rejected "
            "with \"received: 1, expected: >= 2\". Generate a proxy, e.g. "
            "voms-proxy-init -rfc -cert <hostcert> -key <hostkey> -out "
            "<proxy.pem>, and point x509_proxy at it.",
            proxy_path, ncerts);
    }
}

/* originauth_gsi_send_response — round 2: build kXGC_cert and send it.
 *
 * WHAT: build the cert-response (proof-of-possession over the kXGS_cert body with
 *       the proxy chain + key) and write it as a kXR_auth to the origin.
 * WHY : keeps the crypto build + its single socket-send side effect in one step;
 *       consumes `body` (frees it) so the orchestrator's ownership stays linear.
 * HOW : brix_gsi_build_cert_response fills resp/resp_len (byte-frozen); on failure
 *       the kernel's `err` text is surfaced. `body` and the `cred` fields are all
 *       freed here regardless of outcome.
 * Returns 0 on a sent response, -1 (t error set). */
static int
originauth_gsi_send_response(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    u_char *body, uint32_t dlen, originauth_gsi_cred_t *cred)
{
    uint8_t  *resp = NULL;
    uint32_t  resp_len = 0;
    char      err[160];
    int       rc;

    err[0] = '\0';
    rc = brix_gsi_build_cert_response(body, dlen, cred->pem, cred->pem_len,
                                        cred->key, &resp, &resp_len,
                                        err, sizeof(err));
    free(body);
    free(cred->pem);
    brix_evp_pkey_free(cred->key);
    if (rc != 0) {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
                               err[0] ? err : "cache origin gsi round-2 failed");
        return -1;
    }

    rc = cache_origin_send_kxr_auth(oc, "gsi", resp, resp_len);
    free(resp);
    if (rc != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin gsi round-2 write failed");
        return -1;
    }
    return 0;
}

/* originauth_gsi_read_final — read the round-2 reply and require kXR_ok.
 *
 * WHAT: read the origin's final response and confirm the handshake succeeded.
 * WHY : the terminal checkpoint of the two-round handshake; owns and frees its
 *       own response body.
 * HOW : kXR_error → surface the origin error; anything but kXR_ok → AuthFailed.
 * Returns 0 on a kXR_ok auth, -1 (t error set). */
static int
originauth_gsi_read_final(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    uint16_t  status;
    uint32_t  dlen;
    u_char   *body = NULL;

    if (brix_cache_read_response(t, oc, &status, &body, &dlen, BRIX_XLARGE_BUF_SIZE) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "cache origin gsi authentication failed");
        free(body);
        return -1;
    }
    free(body);
    if (status != kXR_ok) {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin gsi authentication incomplete");
        return -1;
    }
    return 0;
}

/* brix_cache_origin_auth_gsi — present an X.509 proxy to the origin via the
 * in-process XrdSecgsi two-round handshake after a login advertised "&P=gsi". The
 * DH/cipher/proof-of-possession math is the SHARED gsi_core kernel (the exact
 * implementation client/lib/sec/sec_gsi.c and src/tpc/gsi/gsi_outbound_exchange.c use):
 *   round 1  client → kXGC_certreq (build_certreq); server → kXGS_cert (kXR_authmore)
 *   round 2  client → kXGC_cert (build_cert_response w/ the proxy chain + key); → kXR_ok
 * `gsi_parms` is the server's gsi v:/c:/ca: list; `proxy_path` the proxy PEM file.
 * Returns 0 on a kXR_ok auth, -1 otherwise (t error set). C-3.
 *
 * Orchestrator only: each round/concern is a `static originauth_gsi_*` helper and
 * this reads as a flat sequence of `if (step(...) != 0) return -1;`. */
int
brix_cache_origin_auth_gsi(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *gsi_parms, const char *proxy_path)
{
    u_char                 *body = NULL;
    uint32_t                dlen = 0;
    originauth_gsi_cred_t   cred = { 0 };

    /* ---- round 1: kXGC_certreq -> kXGS_cert ---- */
    if (originauth_gsi_certreq(t, oc, gsi_parms) != 0) {
        return -1;
    }
    if (originauth_gsi_read_cert(t, oc, &body, &dlen) != 0) {
        return -1;
    }
    if (originauth_gsi_verify_srv_cert(t, body, dlen) != 0) {
        free(body);
        return -1;
    }

    /* ---- round 2: kXGC_cert with the proxy chain ----
     * The cert chain always comes from proxy_path.  The key normally lives in the
     * same file (a combined proxy PEM), but when the credential supplied a separate
     * cert + key (cache_origin_x509_key set), load the key from there — a plain host
     * cert/key pair then works without being hand-concatenated into a proxy. */
    if (originauth_gsi_load_credential(t, proxy_path, &cred) != 0) {
        free(body);
        return -1;
    }
    originauth_gsi_warn_bare_cert(cred.pem, cred.pem_len, proxy_path);

    /* Consumes body and the cred fields regardless of outcome. */
    if (originauth_gsi_send_response(t, oc, body, dlen, &cred) != 0) {
        return -1;
    }

    return originauth_gsi_read_final(t, oc);
}
