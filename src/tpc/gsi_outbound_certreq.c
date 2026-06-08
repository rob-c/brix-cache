/* ---- File: gsi_outbound_certreq.c — GSI certificate request for native TPC pull ----
 *
 * WHAT: Initiates the outbound GSI authentication handshake on a TPC pull socket. Reads xrootd_certificate and xrootd_certificate_key from config, loads X509 chain + private key via OpenSSL BIO/PEM readers, sends kXGC_certreq wire message (gsi\x00 + opcode + kXR_none), receives kXR_authmore response containing client cert + CA chain. Validates server expects auth continuation before returning NGX_OK or error code.
 *
 * WHY: Native TPC pull connects directly to an xrootd server on a separate socket; GSI authentication requires the outbound side to present its certificate chain and private key, then receive the server's client certificate + CA chain for mutual verification. This function performs only the first round of that handshake — sending certreq and verifying kXR_authmore response — with subsequent rounds handled by gsi_outbound_common.c functions (tpc_send_kxr_auth continuation).
 *
 * HOW: Validate config has certificate + key paths → ngx_memcpy into local PATH_MAX buffers with NUL termination → BIO_new_file("r") on both cert and key PEM files → sk_X509_new_null() + loop PEM_read_bio_X509(cbio) pushing to chain (x = NULL after each push) → reject if chain empty → PEM_read_bio_PrivateKey(kbio) → malloc(crlen=4+4+8) for wire message → memcpy "gsi\x00" + tpc_put_u32(kXGC_certreq) + tpc_put_u32(kXR_none) + tpc_put_u32(0) → tpc_send_kxr_auth(t, fd, 3, certreq, crlen) → recv response via tpc_recv_response checking status == kXR_authmore with body ≥16 bytes → goto done cleanup: BIO_free(cbio/kbio), sk_X509_free(chain), EVP_PKEY_free(pkey), free(certreq/body). Returns NGX_OK on success or error code. Caller: tpc/bootstrap.c (tpc_pull_start).
 * ------------------------------------------------------------------ */

#include "tpc_internal.h"

/* Helper functions declared in gsi_outbound_common.c — extern to link them. */
extern void tpc_put_u32(u_char *p, uint32_t v);
extern int tpc_send_kxr_auth(xrootd_tpc_pull_t *t, int fd, u_char seq, const u_char *cred, uint32_t len);
int tpc_recv_response(int fd, uint16_t *status, u_char **body, uint32_t *dlen);

/* WHAT: Initiates GSI auth handshake on TPC pull socket — read cert/key PEM, send kXGC_certreq wire message, verify kXR_authmore response. */
int
tpc_outbound_gsi(xrootd_tpc_pull_t *t, int fd)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    u_char           cert_path[PATH_MAX];
    u_char           key_path[PATH_MAX];
    BIO             *cbio = NULL, *kbio = NULL;  /* pbio unused in this fragment */
    X509            *x = NULL;
    STACK_OF(X509)  *chain = NULL;
    EVP_PKEY        *pkey = NULL;
    u_char          *certreq = NULL;
    u_char          *body = NULL;
    uint16_t         status;
    uint32_t         dlen;
    int              rc = -1;

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

    cbio = BIO_new_file((char *) cert_path, "r");
    kbio = BIO_new_file((char *) key_path, "r");
    if (cbio == NULL || kbio == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI cannot read certificate or key PEM");
        t->xrd_error = kXR_IOError;
        goto done;
    }

    chain = sk_X509_new_null();
    if (chain == NULL) {
        goto done;
    }

    while ((x = PEM_read_bio_X509(cbio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, x);
        x = NULL;
    }

    if (sk_X509_num(chain) == 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI certificate file has no X.509 certs");
        t->xrd_error = kXR_ArgInvalid;
        goto done;
    }

    pkey = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
    if (pkey == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI cannot read private key PEM");
        t->xrd_error = kXR_ArgInvalid;
        goto done;
    }

    {
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
            goto done;
        }
    }

    /* ---- round 1: kXGC_certreq ---- */
    {
        size_t crlen = 4 + 4 + 8;
        u_char *cr;

        certreq = malloc(crlen);
        if (certreq == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg), "TPC GSI certreq OOM");
            t->xrd_error = kXR_NoMemory;
            goto done;
        }

        cr = certreq;
        ngx_memcpy(cr, "gsi\x00", 4);
        cr += 4;
        tpc_put_u32(cr, (uint32_t) kXGC_certreq);
        cr += 4;
        tpc_put_u32(cr, (uint32_t) kXRS_none);
        cr += 4;
        tpc_put_u32(cr, 0);

        if (tpc_send_kxr_auth(t, fd, 3, certreq, (uint32_t) crlen) != 0) {
            goto done;
        }
    }

    body = NULL;
    if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI kXGS_cert recv failed");
        t->xrd_error = kXR_ServerError;
        goto done;
    }

    if (status != kXR_authmore || body == NULL || dlen < 16) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI expected kXR_authmore after certreq (status=%u)",
                 (unsigned) status);
        t->xrd_error = kXR_AuthFailed;
        goto done;
    }

    rc = 0;

done:
    /* Cleanup — this label was in the original gsi_outbound.c before splitting. */
    if (cbio) BIO_free(cbio);
    if (kbio) BIO_free(kbio);
    if (chain) sk_X509_free(chain);
    if (pkey) EVP_PKEY_free(pkey);
    if (certreq) free(certreq);
    if (body) free(body);
    return rc;
}
