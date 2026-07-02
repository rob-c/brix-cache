/* File: gsi_outbound_certreq.c — GSI certificate request for native TPC pull
 * WHAT: Initiates the outbound GSI authentication handshake on a TPC pull socket. Reads xrootd_certificate and xrootd_certificate_key from config, loads X509 chain + private key via OpenSSL BIO/PEM readers, sends kXGC_certreq wire message (gsi\x00 + opcode + kXRS_none), receives kXR_authmore response containing client cert + CA chain. Validates server expects auth continuation before returning NGX_OK or error code.
 *
 * WHY: Native TPC pull connects directly to an xrootd server on a separate socket; GSI authentication requires the outbound side to present its certificate chain and private key, then receive the server's client certificate + CA chain for mutual verification. This function performs only the first round of that handshake — sending certreq and verifying kXR_authmore response — with subsequent rounds handled by gsi_outbound_common.c functions (tpc_send_kxr_auth continuation).
 *
 * HOW: Validate config has certificate + key paths → ngx_memcpy into local PATH_MAX buffers with NUL termination → BIO_new_file("r") on both cert and key PEM files → sk_X509_new_null() + loop PEM_read_bio_X509(cbio) pushing to chain (x = NULL after each push) → reject if chain empty → PEM_read_bio_PrivateKey(kbio) → malloc(crlen=4+4+8) for wire message → memcpy "gsi\x00" + tpc_put_u32(kXGC_certreq) + tpc_put_u32(kXRS_none) + tpc_put_u32(0) → tpc_send_kxr_auth(t, fd, 3, certreq, crlen) → recv response via tpc_recv_response checking status == kXR_authmore with body ≥16 bytes → every exit returns through tpc_outbound_gsi_finish: BIO_free(cbio/kbio), sk_X509_free(chain), EVP_PKEY_free(pkey), free(certreq/body). Returns NGX_OK on success or error code. Caller: tpc/bootstrap.c (tpc_pull_start).
 * */

#include "tpc/engine/tpc_internal.h"
#include "auth/gsi/gsi_core.h"          /* build_certreq / parse_parms / rand */
#include "protocols/root/session/session.h"       /* XROOTD_SESSION_ID_LEN */

/* Helper functions declared in gsi_outbound_common.c — extern to link them.
 * tpc_put_u32 writes a big-endian uint32 (wire byte order); tpc_send_kxr_auth
 * wraps the payload in a kXR_auth ClientRequestHdr and send_all()s it.
 * tpc_recv_response reads one server reply, returning the status code plus a
 * malloc'd body the caller must free(). */
extern void tpc_put_u32(u_char *p, uint32_t v);
extern int tpc_send_kxr_auth(xrootd_tpc_pull_t *t, int fd, u_char seq, const u_char *cred, uint32_t len);
int tpc_recv_response(xrootd_tpc_pull_t *t, int fd, uint16_t *status,
                      u_char **body, uint32_t *dlen);

/*
 * tpc_outbound_gsi_finish — release the certreq round's OpenSSL/wire resources
 * and return rc unchanged.
 *
 * Called at every exit of tpc_outbound_gsi (success and each early failure).
 * Every handle is NULL-initialised at the top of that function and each guard is
 * NULL-safe, so invoking this at any point frees exactly what had been built so
 * far — which lets the caller exit with a plain `return` instead of a shared
 * goto/label. sk_X509_free frees the stack and every cert it owns.
 */
static int
tpc_outbound_gsi_finish(int rc, BIO *cbio, BIO *kbio, STACK_OF(X509) *chain,
    EVP_PKEY *pkey, u_char *certreq, u_char *body)
{
    if (cbio) BIO_free(cbio);
    if (kbio) BIO_free(kbio);
    if (chain) sk_X509_free(chain);
    if (pkey) EVP_PKEY_free(pkey);
    if (certreq) free(certreq);
    if (body) free(body);
    return rc;
}

/* WHAT: Initiates GSI auth handshake on TPC pull socket — read cert/key PEM, send kXGC_certreq wire message, verify kXR_authmore response. */
int
tpc_outbound_gsi(xrootd_tpc_pull_t *t, int fd,
    const u_char *login_body, uint32_t login_dlen)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    u_char           cert_path[PATH_MAX];   /* NUL-terminated copies of the */
    u_char           key_path[PATH_MAX];    /* ngx_str_t config paths        */
    BIO             *cbio = NULL, *kbio = NULL;  /* pbio unused in this fragment */
    X509            *x = NULL;              /* scratch cert from each PEM read */
    STACK_OF(X509)  *chain = NULL;          /* owns every cert pushed onto it  */
    EVP_PKEY        *pkey = NULL;
    u_char          *certreq = NULL;        /* malloc'd wire message (freed at done) */
    u_char          *body = NULL;           /* malloc'd server reply (freed at done) */
    uint16_t         status;
    uint32_t         dlen;
    int              rc = -1;               /* default = failure; set 0 only on success */

    /*
     * §F6: when proxy delegation captured the user's proxy, authenticate to the
     * source AS THE USER with that in-memory credential (proxy cert + issuer chain
     * + key, PEM) instead of the gateway's xrootd_certificate. Two BIOs over the
     * same blob: one yields the cert chain (stops at the trailing key block), the
     * other the private key (skips the cert blocks). The blob is owned by the pull
     * task (freed in thread.c).
     */
    if (t->deleg_cred_pem != NULL && t->deleg_cred_len > 0) {
        cert_path[0] = '\0';   /* unused on this path; silence later references */
        key_path[0] = '\0';
        cbio = BIO_new_mem_buf(t->deleg_cred_pem, (int) t->deleg_cred_len);
        kbio = BIO_new_mem_buf(t->deleg_cred_pem, (int) t->deleg_cred_len);
    } else {
        /* WHY: paths come from config as length-counted ngx_str_t; reject empty
         * paths and any that would not fit (with room for the NUL) in the local
         * PATH_MAX buffers before we ngx_memcpy + NUL-terminate them below.
         * The >= comparison reserves the final byte for the NUL terminator. */
        if (conf->certificate.len == 0 || conf->certificate_key.len == 0
            || conf->certificate.len >= sizeof(cert_path)
            || conf->certificate_key.len >= sizeof(key_path))
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI outbound needs xrootd_certificate and "
                     "xrootd_certificate_key");
            t->xrd_error = kXR_ArgInvalid;
            return -1;
        }

        ngx_memcpy(cert_path, conf->certificate.data, conf->certificate.len);
        cert_path[conf->certificate.len] = '\0';
        ngx_memcpy(key_path, conf->certificate_key.data, conf->certificate_key.len);
        key_path[conf->certificate_key.len] = '\0';

        /* Open read-only PEM streams over the cert and key files. */
        cbio = BIO_new_file((char *) cert_path, "r");
        kbio = BIO_new_file((char *) key_path, "r");
    }
    if (cbio == NULL || kbio == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI cannot read certificate or key PEM");
        t->xrd_error = kXR_IOError;
        return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey, certreq, body);
    }

    chain = sk_X509_new_null();
    if (chain == NULL) {
        return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey, certreq, body);
    }

    /* Read every certificate in the PEM file into the chain (leaf first,
     * then intermediates). sk_X509_push transfers ownership of x to the
     * stack, so we clear x to NULL afterward — otherwise an early loop exit
     * or error path could double-free a cert that the stack already owns. */
    while ((x = PEM_read_bio_X509(cbio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, x);
        x = NULL;
    }

    /* A cert file that parsed to zero certs cannot authenticate us. */
    if (sk_X509_num(chain) == 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI certificate file has no X.509 certs");
        t->xrd_error = kXR_ArgInvalid;
        return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey, certreq, body);
    }

    pkey = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
    if (pkey == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI cannot read private key PEM");
        t->xrd_error = kXR_ArgInvalid;
        return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey, certreq, body);
    }

    /* WHY: security gate — before we put our identity on the wire, validate
     * the proxy PEM (e.g. not-yet-valid / expired / malformed) so a bad local
     * credential fails fast here with kXR_AuthFailed rather than mid-handshake.
     * cred wraps the in-memory cert_path buffer; nothing is sent yet.
     * Skipped on the §F6 delegated-credential path: that proxy is freshly minted
     * by the client this handshake and already key-verified (assemble_proxy). */
    if (t->deleg_cred_pem == NULL) {
        xrootd_tpc_credential_t cred;

        ngx_memzero(&cred, sizeof(cred));
        cred.type = XROOTD_TPC_CREDENTIAL_PROXY;
        cred.proxy_pem.data = cert_path;
        cred.proxy_pem.len = conf->certificate.len;

        if (xrootd_tpc_credential_validate(
                &cred, t->c != NULL ? t->c->log : NULL) != NGX_OK)
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI credential validation failed");
            t->xrd_error = kXR_AuthFailed;
            return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey, certreq, body);
        }
    }

    /* round 1: kXGC_certreq     * Build the GSI credential payload that opens the handshake. Layout (16B):
     *   [0..3]   "gsi\0"                  4-byte protocol tag (NUL-padded)
     *   [4..7]   kXGC_certreq (=1000)     opcode: client requests server cert
     *   [8..11]  kXRS_none    (=0)        bucket type 0 = end-of-message marker
     *   [12..15] 0                        that terminator bucket's length (0)
     * All multi-byte fields are big-endian via tpc_put_u32. crlen = 4+4+8 so
     * the second tpc_put_u32 below writes into bytes [12..15] of the buffer. */
    {
        size_t   crlen = 0;
        uint32_t version = 0;
        char     crypto[64];
        char     ca[256];

        /* Build a REAL certreq (the stock XrdSecgsi round-1: crypto module +
         * version + issuer-hash + client-opts + random rtag) via the shared
         * gsi_core kernel — the exact bytes the native client sends.  A bare
         * "gsi\0"+kXGC_certreq stub is rejected by the source with kXR_error.
         *
         * Parse the source's advertised gsi parms (v:/c:/ca:) from the login
         * reply body ("<session id><&P=gsi,...>") so it picks the right crypto
         * module + CA chain, exactly like client/lib/sec/sec_gsi.c. */
        crypto[0] = '\0';
        ca[0]     = '\0';
        if (login_dlen > XROOTD_SESSION_ID_LEN) {
            xrootd_gsi_parse_parms(
                (const char *) login_body + XROOTD_SESSION_ID_LEN,
                &version, crypto, sizeof(crypto), ca, sizeof(ca));
        }
        if (crypto[0] == '\0') {
            ngx_memcpy(crypto, "ssl", 4);
        }
        /* Advertise a pre-DHsigned version (< XrdSecgsiVersDHsigned=10400) so the
         * source uses the simpler UNSIGNED DH path — it sends its DH public as a
         * plain kXRS_puk blob, which gsi_outbound_exchange.c implements (it does
         * NOT handle the signed-DH kXRS_cipher path the native client supports).
         * Proof-of-possession is still enforced (we sign the server rtag below). */
        version = 10300;

        if (!xrootd_gsi_rand(t->gsi_rtag, sizeof(t->gsi_rtag))) {
            snprintf(t->err_msg, sizeof(t->err_msg), "TPC GSI RNG failed");
            t->xrd_error = kXR_ServerError;
            return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey,
                                           certreq, body);
        }

        /* clnt_opts 0x80 matches a stock client (delegated-proxy off). The buffer
         * is malloc'd and freed by tpc_outbound_gsi_finish. */
        certreq = xrootd_gsi_build_certreq(crypto, version,
                                           ca[0] ? ca : NULL, 0x80u,
                                           t->gsi_rtag, sizeof(t->gsi_rtag),
                                           &crlen);
        if (certreq == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI cannot build certreq");
            t->xrd_error = kXR_NoMemory;
            return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey,
                                           certreq, body);
        }

        /* seq=3: third request on this stream (protocol=1, login=2). */
        if (tpc_send_kxr_auth(t, fd, 3, certreq, (uint32_t) crlen) != 0) {
            return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey,
                                           certreq, body);
        }
    }

    /* Read the server's reply to certreq. body is malloc'd by the helper and
     * freed at done:; pre-clearing it keeps that cleanup safe on recv failure. */
    body = NULL;
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI kXGS_cert recv failed");
        t->xrd_error = kXR_ServerError;
        return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey, certreq, body);
    }

    /* Security check: the server must answer with kXR_authmore (=4002),
     * signalling "continue authenticating" — any other status (kXR_ok early,
     * kXR_error, etc.) means we cannot proceed and is treated as auth failure.
     * dlen < 16 would be too short to hold the cert + CA bucket the next round
     * (gsi_outbound_exchange.c) parses, so reject undersized bodies here. */
    if (status != kXR_authmore || body == NULL || dlen < 16) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI expected kXR_authmore after certreq (status=%u)",
                 (unsigned) status);
        t->xrd_error = kXR_AuthFailed;
        return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey, certreq, body);
    }

    /* Round 1 complete: server is mid-handshake.  Drive round 2 (the DH key
     * exchange + encrypted client cert) HERE — this call was previously missing,
     * so tpc_outbound_gsi returned "success" after only certreq and the source
     * saw the destination as unauthenticated ("user not authenticated").
     *
     * tpc_outbound_gsi_exchange consumes `body` (frees it on every exit — see the
     * matching change in gsi_outbound_exchange.c), and does NOT free
     * chain/pkey/certreq/cbio/kbio (we do, below).  Clear `body` afterwards so
     * tpc_outbound_gsi_finish cannot double-free it. */
    rc = tpc_outbound_gsi_exchange(t, fd, body, dlen, x, chain, pkey,
                                   certreq, cbio, kbio);
    body = NULL;

    /* Success exit: tpc_outbound_gsi_finish releases every resource (each guard
     * is NULL-safe) and returns rc — the same cleanup every error path uses. */
    return tpc_outbound_gsi_finish(rc, cbio, kbio, chain, pkey, certreq, body);
}
