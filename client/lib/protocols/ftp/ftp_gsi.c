/*
 * ftp_gsi.c — RFC 2228 GSI (GSSAPI) initiator for the GridFTP client.
 *
 * WHAT: drives the client half of the GSI exchange a GridFTP server runs inside
 *       ADAT tokens — a TLS 1.2 handshake over memory BIOs, then the mandatory
 *       X.509 delegation round ('D' → proxy request → signed proxy) — and, once
 *       established, wraps commands and unwraps protected replies.
 * WHY:  the tree already has the *acceptor* (src/auth/gssapi/gsi_mech.c), but it
 *       is bound to nginx pools and logs and cannot be linked into the client. The
 *       initiator is the mirror image of that state machine, expressed in plain
 *       OpenSSL, so the wire behaviour of the two halves stays symmetric.
 * HOW:  no sockets here — the caller feeds each decoded ADAT token in and sends
 *       whatever bytes the SSL object produced. TLS is pinned to 1.2 to match the
 *       acceptor's pin, proxy certificates are enabled in the verifier (a GSI peer
 *       chain contains them by construction), and the delegation request is signed
 *       by ftp_gsi_cred.c. No goto: every stage is an early-return step.
 */
#include "ftp_gsi_int.h"

#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <stdlib.h>
#include <string.h>

/* Move everything the SSL object has produced into a malloc'd token. */
static int
gss_drain(struct brix_ftp_gss *g, uint8_t **out, size_t *out_len,
          brix_status *st)
{
    char *data = NULL;
    long  n;

    *out = NULL;
    *out_len = 0;
    n = BIO_get_mem_data(g->wbio, &data);
    if (n <= 0) {
        return 0;
    }
    *out = malloc((size_t) n);
    if (*out == NULL) {
        brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
        return -1;
    }
    memcpy(*out, data, (size_t) n);
    *out_len = (size_t) n;
    (void) BIO_reset(g->wbio);
    return 0;
}


/* Read all currently-decrypted application data (the delegation payloads). */
static int
gss_read_app(struct brix_ftp_gss *g, uint8_t **out, size_t *out_len,
             brix_status *st)
{
    size_t   cap = 16384, off = 0;
    uint8_t *buf = malloc(cap);

    *out = NULL;
    *out_len = 0;
    if (buf == NULL) {
        brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
        return -1;
    }
    for (;;) {
        int n = SSL_read(g->ssl, buf + off, (int) (cap - off));

        if (n <= 0) {
            break;
        }
        off += (size_t) n;
        if (off == cap) {
            uint8_t *bigger;

            if (cap >= (size_t) 1 << 20) {
                break;
            }
            cap *= 2;
            bigger = realloc(buf, cap);
            if (bigger == NULL) {
                free(buf);
                brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
                return -1;
            }
            buf = bigger;
        }
    }
    ERR_clear_error();
    *out = buf;
    *out_len = off;
    return 0;
}


static int
gss_ctx_setup(struct brix_ftp_gss *g, const char *ca_dir, int insecure,
              brix_status *st)
{
    X509_VERIFY_PARAM *param;

    g->ctx = SSL_CTX_new(TLS_client_method());
    if (g->ctx == NULL) {
        return brix_ftp_gss_ssl_err(st, "SSL_CTX_new");
    }
    /* The acceptor pins TLS 1.2 (GSI's token framing predates 1.3's post-
     * handshake messages); an initiator offering 1.3 would never converge. */
    if (SSL_CTX_set_max_proto_version(g->ctx, TLS1_2_VERSION) != 1
        || SSL_CTX_set_min_proto_version(g->ctx, TLS1_VERSION) != 1) {
        return brix_ftp_gss_ssl_err(st, "pin TLS version");
    }
    if (insecure) {
        SSL_CTX_set_verify(g->ctx, SSL_VERIFY_NONE, NULL);
        return 0;
    }
    SSL_CTX_set_verify(g->ctx, SSL_VERIFY_PEER, NULL);
    if (ca_dir == NULL || ca_dir[0] == '\0') {
        ca_dir = getenv("X509_CERT_DIR");
    }
    if (ca_dir == NULL || ca_dir[0] == '\0') {
        ca_dir = "/etc/grid-security/certificates";
    }
    if (SSL_CTX_load_verify_locations(g->ctx, NULL, ca_dir) != 1) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "gsiftp: cannot load CA directory %s", ca_dir);
        return -1;
    }
    param = SSL_CTX_get0_param(g->ctx);
    if (param != NULL) {
        /* A GSI peer authenticates with an RFC-3820 proxy chain. */
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_ALLOW_PROXY_CERTS);
    }
    return 0;
}


struct brix_ftp_gss *
brix_ftp_gss_create(const char *proxy, const char *ca_dir, int insecure,
                    brix_status *st)
{
    struct brix_ftp_gss *g;
    char                 path[XRDC_PATH_MAX];

    g = calloc(1, sizeof(*g));
    if (g == NULL) {
        brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
        return NULL;
    }
    if (proxy == NULL || proxy[0] == '\0') {
        brix_ftp_gss_proxy_path(path, sizeof(path));
        proxy = path;
    }
    if (gss_ctx_setup(g, ca_dir, insecure, st) != 0
        || brix_ftp_gss_load_cred(g, proxy, st) != 0) {
        brix_ftp_gss_free(g);
        return NULL;
    }

    g->ssl = SSL_new(g->ctx);
    g->rbio = BIO_new(BIO_s_mem());
    g->wbio = BIO_new(BIO_s_mem());
    if (g->ssl == NULL || g->rbio == NULL || g->wbio == NULL) {
        (void) brix_ftp_gss_ssl_err(st, "SSL_new");
        brix_ftp_gss_free(g);
        return NULL;
    }
    SSL_set_bio(g->ssl, g->rbio, g->wbio);     /* SSL owns both BIOs from here */
    SSL_set_connect_state(g->ssl);
    g->state = FTP_GSS_TLS;
    return g;
}


/* Handshake stage: run SSL_connect and, when it completes, open the mandatory
 * delegation round by sending the 'D' marker as application data. */
static int
gss_step_tls(struct brix_ftp_gss *g, uint8_t **out, size_t *out_len,
             brix_status *st)
{
    int r = SSL_connect(g->ssl);
    int e;

    if (r == 1) {
        if (SSL_write(g->ssl, "D", 1) != 1) {
            g->state = FTP_GSS_FAIL;
            return brix_ftp_gss_ssl_err(st, "send delegation marker");
        }
        g->state = FTP_GSS_DELEG_CSR;
        return (gss_drain(g, out, out_len, st) == 0) ? 1 : -1;
    }
    e = SSL_get_error(g->ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
        return (gss_drain(g, out, out_len, st) == 0) ? 1 : -1;
    }
    g->state = FTP_GSS_FAIL;
    return brix_ftp_gss_ssl_err(st, "TLS handshake failed");
}


/* Delegation stage: the token just fed in is the server's proxy-certificate
 * request; sign it and return the issued certificate. */
static int
gss_step_csr(struct brix_ftp_gss *g, uint8_t **out, size_t *out_len,
             brix_status *st)
{
    uint8_t *csr = NULL, *signed_der = NULL;
    size_t   csr_len = 0, signed_len = 0;
    int      rc;

    if (gss_read_app(g, &csr, &csr_len, st) != 0) {
        g->state = FTP_GSS_FAIL;
        return -1;
    }
    if (csr_len == 0) {
        free(csr);
        g->state = FTP_GSS_FAIL;
        brix_status_set(st, XRDC_EAUTH, 0,
                        "gsiftp: server sent no delegation request");
        return -1;
    }
    rc = brix_ftp_gss_sign_csr(g, csr, csr_len, &signed_der, &signed_len, st);
    free(csr);
    if (rc != 0) {
        g->state = FTP_GSS_FAIL;
        return -1;
    }
    rc = SSL_write(g->ssl, signed_der, (int) signed_len);
    free(signed_der);
    if (rc <= 0) {
        g->state = FTP_GSS_FAIL;
        return brix_ftp_gss_ssl_err(st, "send signed proxy");
    }
    g->state = FTP_GSS_DELEG_ACK;
    return (gss_drain(g, out, out_len, st) == 0) ? 1 : -1;
}


int
brix_ftp_gss_step(struct brix_ftp_gss *g, const uint8_t *in, size_t in_len,
                  uint8_t **out, size_t *out_len, brix_status *st)
{
    *out = NULL;
    *out_len = 0;

    if (g->state == FTP_GSS_FAIL) {
        brix_status_set(st, XRDC_EAUTH, 0, "gsiftp: security context failed");
        return -1;
    }
    if (g->state == FTP_GSS_DONE) {
        return 0;
    }
    if (in_len > 0 && BIO_write(g->rbio, in, (int) in_len) <= 0) {
        g->state = FTP_GSS_FAIL;
        return brix_ftp_gss_ssl_err(st, "buffer peer token");
    }
    if (g->state == FTP_GSS_TLS) {
        return gss_step_tls(g, out, out_len, st);
    }
    if (g->state == FTP_GSS_DELEG_CSR) {
        return gss_step_csr(g, out, out_len, st);
    }
    /* FTP_GSS_DELEG_ACK: the server accepted the delegated proxy. */
    g->state = FTP_GSS_DONE;
    return 0;
}


int
brix_ftp_gss_wrap(struct brix_ftp_gss *g, const void *in, size_t in_len,
                  uint8_t **out, size_t *out_len, brix_status *st)
{
    if (SSL_write(g->ssl, in, (int) in_len) <= 0) {
        return brix_ftp_gss_ssl_err(st, "protect command");
    }
    return gss_drain(g, out, out_len, st);
}


int
brix_ftp_gss_unwrap(struct brix_ftp_gss *g, const void *in, size_t in_len,
                    uint8_t **out, size_t *out_len, brix_status *st)
{
    if (in_len > 0 && BIO_write(g->rbio, in, (int) in_len) <= 0) {
        return brix_ftp_gss_ssl_err(st, "buffer protected reply");
    }
    if (gss_read_app(g, out, out_len, st) != 0) {
        return -1;
    }
    if (*out_len == 0) {
        free(*out);
        *out = NULL;
        brix_status_set(st, XRDC_EPROTO, 0,
                        "gsiftp: empty protected reply");
        return -1;
    }
    return 0;
}


void
brix_ftp_gss_free(struct brix_ftp_gss *g)
{
    if (g == NULL) {
        return;
    }
    if (g->ssl != NULL) {
        SSL_free(g->ssl);            /* frees rbio/wbio via SSL_set_bio */
    } else {
        BIO_free(g->rbio);
        BIO_free(g->wbio);
    }
    if (g->key != NULL) {
        EVP_PKEY_free(g->key);
    }
    if (g->ctx != NULL) {
        SSL_CTX_free(g->ctx);
    }
    free(g->pem);
    free(g);
}
