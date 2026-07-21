/* File: gsi_outbound_certreq.c — GSI certificate request for native TPC pull
 * WHAT: Initiates the outbound GSI authentication handshake on a TPC pull socket. Reads brix_certificate and brix_certificate_key from config, loads X509 chain + private key via OpenSSL BIO/PEM readers, sends kXGC_certreq wire message (gsi\x00 + opcode + kXRS_none), receives kXR_authmore response containing client cert + CA chain. Validates server expects auth continuation before returning NGX_OK or error code.
 *
 * WHY: Native TPC pull connects directly to an xrootd server on a separate socket; GSI authentication requires the outbound side to present its certificate chain and private key, then receive the server's client certificate + CA chain for mutual verification. This function performs only the first round of that handshake — sending certreq and verifying kXR_authmore response — with subsequent rounds handled by gsi_outbound_common.c functions (tpc_send_kxr_auth continuation).
 *
 * HOW: tpc_outbound_gsi is a flat orchestrator over four single-purpose helpers, each
 * owning one handshake step and reporting through a shared tpc_certreq_res_t resource
 * bundle: (1) tpc_certreq_open_creds opens the cert + key BIOs (delegated in-memory blob
 * OR config PEM files); (2) tpc_certreq_load_chain_key reads the X509 chain + private key
 * and validates the local credential (skipped for the freshly-minted delegated proxy);
 * (3) tpc_certreq_build_send parses the source's gsi parms, builds the stock XrdSecgsi
 * round-1 certreq and sends it as seq=3; (4) tpc_certreq_recv_authmore reads the reply and
 * enforces status == kXR_authmore with a ≥16-byte body. On success the orchestrator drives
 * round 2 (tpc_outbound_gsi_exchange, which consumes `body`). Every exit returns through
 * tpc_outbound_gsi_finish(rc, res): BIO_free(cbio/kbio), sk_X509_free(chain),
 * EVP_PKEY_free(pkey), free(certreq/body) — every handle is zero-init and each guard is
 * NULL-safe, so it frees exactly what had been built. Returns NGX_OK on success or an error
 * code. Caller: tpc/bootstrap.c (tpc_pull_start).
 * */

#include "tpc/engine/tpc_internal.h"
#include "auth/gsi/gsi_core.h"          /* build_certreq / parse_parms / rand */
#include "protocols/root/session/session.h"       /* BRIX_SESSION_ID_LEN */
#include "core/compat/cstr.h"

/* Helper functions declared in gsi_outbound_common.c — extern to link them.
 * tpc_put_u32 writes a big-endian uint32 (wire byte order); tpc_send_kxr_auth
 * wraps the payload in a kXR_auth ClientRequestHdr and send_all()s it.
 * tpc_recv_response reads one server reply, returning the status code plus a
 * malloc'd body the caller must free(). */
extern void tpc_put_u32(u_char *p, uint32_t v);
extern int tpc_send_kxr_auth(brix_tpc_pull_t *t, int fd, u_char seq, const u_char *cred, uint32_t len);
int tpc_recv_response(brix_tpc_pull_t *t, int fd, uint16_t *status,
                      u_char **body, uint32_t *dlen);

/*
 * tpc_certreq_res_t — the OpenSSL + wire resources the certreq round acquires.
 *
 * WHAT: bundles every handle tpc_outbound_gsi builds during round 1 so the shared
 * cleanup takes ONE pointer instead of seven positional args.
 * WHY: the finish helper was a 7-param cleanup ladder; collapsing the handles into a
 * struct drops it under the param cap while keeping the exact NULL-safe free order.
 * HOW: zero-initialised at the top of the orchestrator (every field NULL); each step
 * helper fills the fields it owns; tpc_outbound_gsi_finish frees them all once.
 */
typedef struct {
    BIO             *cbio;      /* cert PEM stream (file or in-memory delegated blob) */
    BIO             *kbio;      /* key  PEM stream (file or in-memory delegated blob) */
    STACK_OF(X509)  *chain;     /* owns every cert pushed onto it                     */
    EVP_PKEY        *pkey;      /* private key parsed from kbio                        */
    u_char          *certreq;   /* malloc'd round-1 wire message                       */
    u_char          *body;      /* malloc'd server reply body                          */
} tpc_certreq_res_t;

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
tpc_outbound_gsi_finish(int rc, tpc_certreq_res_t *res)
{
    if (res->cbio) BIO_free(res->cbio);
    if (res->kbio) BIO_free(res->kbio);
    if (res->chain) sk_X509_free(res->chain);
    if (res->pkey) EVP_PKEY_free(res->pkey);
    if (res->certreq) free(res->certreq);
    if (res->body) free(res->body);
    return rc;
}

/*
 * tpc_certreq_open_creds — open the cert + key PEM BIOs for the certreq round.
 *
 * WHAT: fills res->cbio/res->kbio with read-only PEM streams over either the
 * §F6 delegated in-memory credential blob or the config brix_certificate /
 * brix_certificate_key files, plus NUL-terminated copies of those file paths.
 * WHY: the outbound side must present an identity; delegation authenticates AS
 * THE USER with the captured proxy, otherwise as the gateway's configured cert.
 * HOW: if a delegated blob is present, two BIO_new_mem_buf views over the same
 * blob (one yields the cert chain, the other the key) and blank the unused path
 * buffers; else validate + copy the two ngx_str_t config paths into the caller's
 * PATH_MAX buffers via brix_str_cbuf and BIO_new_file("r") each. Returns 0 on
 * success, or -1 with t->err_msg / t->xrd_error set on a bad/empty config path.
 * A NULL BIO (unreadable file) is left for the caller to detect and clean up.
 */
static int
tpc_certreq_open_creds(brix_tpc_pull_t *t, ngx_stream_brix_srv_conf_t *conf,
    tpc_certreq_res_t *res, u_char *cert_path, u_char *key_path)
{
    /*
     * §F6: when proxy delegation captured the user's proxy, authenticate to the
     * source AS THE USER with that in-memory credential (proxy cert + issuer chain
     * + key, PEM) instead of the gateway's brix_certificate. Two BIOs over the
     * same blob: one yields the cert chain (stops at the trailing key block), the
     * other the private key (skips the cert blocks). The blob is owned by the pull
     * task (freed in thread.c).
     */
    if (t->deleg_cred_pem != NULL && t->deleg_cred_len > 0) {
        cert_path[0] = '\0';   /* unused on this path; silence later references */
        key_path[0] = '\0';
        res->cbio = BIO_new_mem_buf(t->deleg_cred_pem, (int) t->deleg_cred_len);
        res->kbio = BIO_new_mem_buf(t->deleg_cred_pem, (int) t->deleg_cred_len);
        return 0;
    }

    /* WHY: paths come from config as length-counted ngx_str_t; reject empty
     * paths and any that would not fit (with room for the NUL) in the local
     * PATH_MAX buffers — brix_str_cbuf() copies + NUL-terminates and
     * returns NULL when the result would not fit. */
    if (conf->certificate.len == 0 || conf->certificate_key.len == 0
        || brix_str_cbuf((char *) cert_path, PATH_MAX,
                         &conf->certificate) == NULL
        || brix_str_cbuf((char *) key_path, PATH_MAX,
                         &conf->certificate_key) == NULL)
    {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI outbound needs brix_certificate and "
                 "brix_certificate_key");
        t->xrd_error = kXR_ArgInvalid;
        return -1;
    }

    /* Open read-only PEM streams over the cert and key files. */
    res->cbio = BIO_new_file((char *) cert_path, "r");
    res->kbio = BIO_new_file((char *) key_path, "r");
    return 0;
}

/*
 * tpc_certreq_load_chain_key — read the X509 chain + private key and validate.
 *
 * WHAT: parses every cert in res->cbio into res->chain (leaf first), reads the
 * private key from res->kbio into res->pkey, and — on the non-delegated path —
 * runs the local proxy PEM through brix_tpc_credential_validate.
 * WHY: an empty chain or unreadable key cannot authenticate us; the pre-flight
 * credential check fails a bad local proxy fast (kXR_AuthFailed) rather than
 * mid-handshake. The freshly-minted delegated proxy is already key-verified
 * (assemble_proxy), so it skips the extra validation.
 * HOW: sk_X509_push transfers ownership of each cert to the stack, so x is
 * cleared after each push to avoid a double-free on error. Returns 0 on success,
 * or -1 with t->err_msg / t->xrd_error set. cert_path/conf feed the credential
 * validate; the caller owns cleanup via tpc_outbound_gsi_finish.
 */
static int
tpc_certreq_load_chain_key(brix_tpc_pull_t *t, ngx_stream_brix_srv_conf_t *conf,
    tpc_certreq_res_t *res, u_char *cert_path)
{
    X509 *x = NULL;              /* scratch cert from each PEM read */

    res->chain = sk_X509_new_null();
    if (res->chain == NULL) {
        return -1;
    }

    /* Read every certificate in the PEM file into the chain (leaf first,
     * then intermediates). sk_X509_push transfers ownership of x to the
     * stack, so we clear x to NULL afterward — otherwise an early loop exit
     * or error path could double-free a cert that the stack already owns. */
    while ((x = PEM_read_bio_X509(res->cbio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(res->chain, x);
        x = NULL;
    }

    /* A cert file that parsed to zero certs cannot authenticate us. */
    if (sk_X509_num(res->chain) == 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI certificate file has no X.509 certs");
        t->xrd_error = kXR_ArgInvalid;
        return -1;
    }

    res->pkey = PEM_read_bio_PrivateKey(res->kbio, NULL, NULL, NULL);
    if (res->pkey == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI cannot read private key PEM");
        t->xrd_error = kXR_ArgInvalid;
        return -1;
    }

    /* WHY: security gate — before we put our identity on the wire, validate
     * the proxy PEM (e.g. not-yet-valid / expired / malformed) so a bad local
     * credential fails fast here with kXR_AuthFailed rather than mid-handshake.
     * cred wraps the in-memory cert_path buffer; nothing is sent yet.
     * Skipped on the §F6 delegated-credential path: that proxy is freshly minted
     * by the client this handshake and already key-verified (assemble_proxy). */
    if (t->deleg_cred_pem == NULL) {
        brix_tpc_credential_t cred;

        ngx_memzero(&cred, sizeof(cred));
        cred.type = BRIX_TPC_CREDENTIAL_PROXY;
        cred.proxy_pem.data = cert_path;
        cred.proxy_pem.len = conf->certificate.len;

        if (brix_tpc_credential_validate(
                &cred, t->c != NULL ? t->c->log : NULL) != NGX_OK)
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI credential validation failed");
            t->xrd_error = kXR_AuthFailed;
            return -1;
        }
    }

    return 0;
}

/*
 * tpc_certreq_build_send — build the stock XrdSecgsi round-1 certreq and send it.
 *
 * WHAT: parses the source's advertised gsi parms from the login reply, builds a
 * REAL certreq (crypto module + version + issuer-hash + client-opts + random
 * rtag) into res->certreq, and sends it as the third request on the stream.
 * WHY: a bare "gsi\0"+kXGC_certreq stub is rejected by the source with kXR_error;
 * the exact bytes the native client sends (via the shared gsi_core kernel) are
 * required. Advertising a pre-DHsigned version keeps the source on the simpler
 * UNSIGNED DH path that gsi_outbound_exchange.c implements.
 * HOW: brix_gsi_parse_parms picks the crypto module + CA chain (defaulting to
 * "ssl"); brix_gsi_rand fills the session rtag; brix_gsi_build_certreq allocates
 * the wire message (freed by tpc_outbound_gsi_finish via res->certreq);
 * tpc_send_kxr_auth frames + sends it as seq=3. Returns 0 on success, or -1 with
 * t->err_msg / t->xrd_error set on RNG / alloc / send failure.
 */
static int
tpc_certreq_build_send(brix_tpc_pull_t *t, int fd,
    const u_char *login_body, uint32_t login_dlen, tpc_certreq_res_t *res)
{
    /* round 1: kXGC_certreq     * Build the GSI credential payload that opens the handshake. Layout (16B):
     *   [0..3]   "gsi\0"                  4-byte protocol tag (NUL-padded)
     *   [4..7]   kXGC_certreq (=1000)     opcode: client requests server cert
     *   [8..11]  kXRS_none    (=0)        bucket type 0 = end-of-message marker
     *   [12..15] 0                        that terminator bucket's length (0)
     * All multi-byte fields are big-endian via tpc_put_u32. crlen = 4+4+8 so
     * the second tpc_put_u32 below writes into bytes [12..15] of the buffer. */
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
    if (login_dlen > BRIX_SESSION_ID_LEN) {
        brix_gsi_parse_parms(
            (const char *) login_body + BRIX_SESSION_ID_LEN,
            &version, crypto, sizeof(crypto), ca, sizeof(ca));
    }
    if (crypto[0] == '\0') {
        ngx_memcpy(crypto, "ssl", 4);
    }
    /* Advertise the signed-DH generation (>= XrdSecgsiVersDHsigned=10400):
     * the shared cert-response kernel (gsi_core_cresp.c) auto-detects whether
     * the source answers with a signed kXRS_cipher or a plain kXRS_puk, so
     * both variants work — same 10600 the origin-fill leg (origin_auth.c) and
     * the native client (sec_gsi.c) already advertise. Signed DH lets the
     * source bind its DH public under its RSA key instead of sending it bare. */
    version = 10600;

    if (!brix_gsi_rand(t->gsi_rtag, sizeof(t->gsi_rtag))) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC GSI RNG failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    /* clnt_opts 0x80 matches a stock client (delegated-proxy off). The buffer
     * is malloc'd and freed by tpc_outbound_gsi_finish. */
    res->certreq = brix_gsi_build_certreq(crypto, version,
                                       ca[0] ? ca : NULL, 0x80u,
                                       t->gsi_rtag, sizeof(t->gsi_rtag),
                                       &crlen);
    if (res->certreq == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI cannot build certreq");
        t->xrd_error = kXR_NoMemory;
        return -1;
    }

    /* seq=3: third request on this stream (protocol=1, login=2). */
    if (tpc_send_kxr_auth(t, fd, 3, res->certreq, (uint32_t) crlen) != 0) {
        return -1;
    }

    return 0;
}

/*
 * tpc_certreq_recv_authmore — read the certreq reply and enforce kXR_authmore.
 *
 * WHAT: receives one server reply into res->body and validates the server is
 * continuing the handshake, returning the body length through *dlen_out.
 * WHY: the server must answer certreq with kXR_authmore (=4002) — any other
 * status (early kXR_ok, kXR_error, …) means we cannot proceed; a body < 16 bytes
 * is too short to hold the cert + CA bucket the next round parses.
 * HOW: tpc_recv_response malloc's res->body (freed by tpc_outbound_gsi_finish);
 * reject a recv failure (kXR_ServerError) and a non-authmore / undersized reply
 * (kXR_AuthFailed). Returns 0 on success, or -1 with t->err_msg / t->xrd_error set.
 */
static int
tpc_certreq_recv_authmore(brix_tpc_pull_t *t, int fd,
    tpc_certreq_res_t *res, uint32_t *dlen_out)
{
    uint16_t status;
    uint32_t dlen;

    /* Read the server's reply to certreq. body is malloc'd by the helper and
     * freed at finish; pre-clearing it keeps that cleanup safe on recv failure. */
    res->body = NULL;
    if (tpc_recv_response(t, fd, &status, &res->body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI kXGS_cert recv failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    /* Security check: the server must answer with kXR_authmore (=4002),
     * signalling "continue authenticating" — any other status (kXR_ok early,
     * kXR_error, etc.) means we cannot proceed and is treated as auth failure.
     * dlen < 16 would be too short to hold the cert + CA bucket the next round
     * (gsi_outbound_exchange.c) parses, so reject undersized bodies here. */
    if (status != kXR_authmore || res->body == NULL || dlen < 16) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI expected kXR_authmore after certreq (status=%u)",
                 (unsigned) status);
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    *dlen_out = dlen;
    return 0;
}

/* WHAT: Initiates GSI auth handshake on TPC pull socket — read cert/key PEM, send kXGC_certreq wire message, verify kXR_authmore response. */
int
tpc_outbound_gsi(brix_tpc_pull_t *t, int fd,
    const u_char *login_body, uint32_t login_dlen)
{
    ngx_stream_brix_srv_conf_t *conf = t->conf;
    u_char             cert_path[PATH_MAX];   /* NUL-terminated copies of the */
    u_char             key_path[PATH_MAX];    /* ngx_str_t config paths        */
    tpc_certreq_res_t  res = { 0 };           /* all handles zero-init, NULL-safe cleanup */
    uint32_t           dlen = 0;
    int                rc = -1;               /* default = failure; set 0 only on success */

    if (tpc_certreq_open_creds(t, conf, &res, cert_path, key_path) != 0) {
        return tpc_outbound_gsi_finish(rc, &res);
    }
    if (res.cbio == NULL || res.kbio == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI cannot read certificate or key PEM");
        t->xrd_error = kXR_IOError;
        return tpc_outbound_gsi_finish(rc, &res);
    }

    if (tpc_certreq_load_chain_key(t, conf, &res, cert_path) != 0) {
        return tpc_outbound_gsi_finish(rc, &res);
    }

    if (tpc_certreq_build_send(t, fd, login_body, login_dlen, &res) != 0) {
        return tpc_outbound_gsi_finish(rc, &res);
    }

    if (tpc_certreq_recv_authmore(t, fd, &res, &dlen) != 0) {
        return tpc_outbound_gsi_finish(rc, &res);
    }

    /* Round 1 complete: server is mid-handshake.  Drive round 2 (the DH key
     * exchange + encrypted client cert) HERE — this call was previously missing,
     * so tpc_outbound_gsi returned "success" after only certreq and the source
     * saw the destination as unauthenticated ("user not authenticated").
     *
     * tpc_outbound_gsi_exchange consumes `res.body` (frees it on every exit — see
     * the matching change in gsi_outbound_exchange.c), and does NOT free
     * chain/pkey/certreq/cbio/kbio (we do, below).  Clear res.body afterwards so
     * tpc_outbound_gsi_finish cannot double-free it. The leaf-cert arg is NULL:
     * the chain owns every cert (the round-1 read left the scratch x at NULL). */
    rc = tpc_outbound_gsi_exchange(t, fd, res.body, dlen, NULL, res.chain,
                                   res.pkey, res.certreq, res.cbio, res.kbio);
    res.body = NULL;

    /* Success exit: tpc_outbound_gsi_finish releases every resource (each guard
     * is NULL-safe) and returns rc — the same cleanup every error path uses. */
    return tpc_outbound_gsi_finish(rc, &res);
}
