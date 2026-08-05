/*
 * ftp_gsi_cred.c — X.509 credential handling for the GridFTP GSI initiator.
 *
 * WHAT: base64 codecs for the ADAT/ENC arguments, loading the user's X.509 proxy
 *       (leaf, chain, key) into the initiator's SSL_CTX, and issuing the
 *       delegated proxy the GridFTP server asks for mid-handshake.
 * WHY:  GSI's mandatory delegation round makes the client a certificate *issuer*,
 *       not just a TLS peer; keeping that crypto beside the credential loader —
 *       and away from the handshake driver — means the state machine reads as
 *       protocol and this file reads as PKI.
 * HOW:  the proxy file is opened through the shared hardened reader
 *       (brix_credfile_bio: no symlink, owner-only, 0600) exactly as the root://
 *       GSI driver does, and the request is signed by libxrdproto's
 *       brix_gsi_sign_pxyreq — the same primitive the server side uses, so the
 *       two halves cannot drift.
 */
#include "ftp_gsi_int.h"

#include "auth/gsi/proxy_req.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
brix_ftp_gss_ssl_err(brix_status *st, const char *what)
{
    unsigned long e = ERR_get_error();
    char          buf[160];

    if (e != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
    } else {
        snprintf(buf, sizeof(buf), "no detail");
    }
    ERR_clear_error();
    brix_status_set(st, XRDC_EAUTH, 0, "gsiftp: %s: %s", what, buf);
    return -1;
}


void
brix_ftp_gss_proxy_path(char *out, size_t outsz)
{
    const char *env = getenv("X509_USER_PROXY");

    if (env != NULL && env[0] != '\0') {
        snprintf(out, outsz, "%s", env);
        return;
    }
    snprintf(out, outsz, "/tmp/x509up_u%u", (unsigned) geteuid());
}


char *
brix_ftp_b64_encode(const uint8_t *data, size_t len)
{
    char  *out;
    size_t cap;
    int    n;

    if (data == NULL || len == 0 || len > (size_t) INT_MAX / 2) {
        return NULL;
    }
    cap = ((len + 2) / 3) * 4 + 1;
    out = malloc(cap);
    if (out == NULL) {
        return NULL;
    }
    n = EVP_EncodeBlock((unsigned char *) out, data, (int) len);
    if (n < 0) {
        free(out);
        return NULL;
    }
    out[n] = '\0';
    return out;
}


uint8_t *
brix_ftp_b64_decode(const char *b64, size_t *out_len)
{
    uint8_t *out;
    size_t   len, pad = 0;
    int      n;

    if (b64 == NULL || out_len == NULL) {
        return NULL;
    }
    len = strlen(b64);
    if (len == 0 || (len % 4) != 0) {
        return NULL;
    }
    if (b64[len - 1] == '=') { pad++; }
    if (len >= 2 && b64[len - 2] == '=') { pad++; }

    out = malloc(len / 4 * 3 + 1);
    if (out == NULL) {
        return NULL;
    }
    n = EVP_DecodeBlock(out, (const unsigned char *) b64, (int) len);
    if (n < 0 || (size_t) n < pad) {
        free(out);
        return NULL;
    }
    /* EVP_DecodeBlock reports the padded length; the '=' bytes decoded to zero
     * bytes the payload does not contain. */
    *out_len = (size_t) n - pad;
    return out;
}


/* Open the proxy through the shared hardened credential reader. */
static BIO *
proxy_open(const char *path)
{
    return brix_credfile_bio(path, 1);
}


/* Install leaf + issuer chain from the proxy file, and keep the certs-only PEM
 * (the delegation signer identity) on the session. */
static int
load_certs(struct brix_ftp_gss *g, const char *proxy, brix_status *st)
{
    BIO     *in, *mem;
    X509    *cert;
    BUF_MEM *bm;
    int      n = 0;

    in = proxy_open(proxy);
    if (in == NULL) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "gsiftp: cannot read X.509 proxy %s", proxy);
        return -1;
    }
    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        BIO_free(in);
        return brix_ftp_gss_ssl_err(st, "BIO_new");
    }
    while ((cert = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL) {
        int ok = PEM_write_bio_X509(mem, cert);

        if (ok) {
            /* leaf first, the rest are issuers (SSL_CTX takes a reference). */
            ok = (n == 0) ? SSL_CTX_use_certificate(g->ctx, cert)
                          : SSL_CTX_add1_chain_cert(g->ctx, cert);
        }
        X509_free(cert);
        if (!ok) {
            BIO_free(in);
            BIO_free(mem);
            return brix_ftp_gss_ssl_err(st, "install proxy certificate");
        }
        n++;
    }
    ERR_clear_error();      /* the loop's terminating NULL is a benign PEM EOF */
    BIO_free(in);

    if (n == 0) {
        BIO_free(mem);
        brix_status_set(st, XRDC_EAUTH, 0,
                        "gsiftp: no certificate in X.509 proxy %s", proxy);
        return -1;
    }
    BIO_get_mem_ptr(mem, &bm);
    g->pem = malloc(bm->length);
    if (g->pem == NULL) {
        BIO_free(mem);
        brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
        return -1;
    }
    memcpy(g->pem, bm->data, bm->length);
    g->pem_len = bm->length;
    BIO_free(mem);
    return 0;
}


int
brix_ftp_gss_load_cred(struct brix_ftp_gss *g, const char *proxy,
                       brix_status *st)
{
    BIO *in;

    if (load_certs(g, proxy, st) != 0) {
        return -1;
    }
    in = proxy_open(proxy);
    if (in != NULL) {
        g->key = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
        BIO_free(in);
    }
    ERR_clear_error();
    if (g->key == NULL) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "gsiftp: no private key in X.509 proxy %s", proxy);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey(g->ctx, g->key) != 1) {
        return brix_ftp_gss_ssl_err(st, "install proxy key");
    }
    return 0;
}


int
brix_ftp_gss_sign_csr(struct brix_ftp_gss *g, const uint8_t *csr_der,
                      size_t csr_len, uint8_t **out_der, size_t *out_len,
                      brix_status *st)
{
    brix_gsi_blob_t signer = { g->pem, g->pem_len };
    brix_gsi_blob_t req    = { csr_der, csr_len };
    brix_gsi_buf_t  proxy  = { NULL, 0 };
    char            errbuf[160];
    brix_gsi_err_t  err    = { errbuf, sizeof(errbuf) };
    X509           *issued;
    unsigned char  *der = NULL;
    int             dlen;

    errbuf[0] = '\0';
    if (brix_gsi_sign_pxyreq(&signer, g->key, &req, &proxy, &err) != 0) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "gsiftp: delegation signing failed: %s", errbuf);
        return -1;
    }

    /* The server wants the issued certificate as DER (it d2i_X509()s the first
     * certificate of the token), so re-encode the PEM the signer returned. */
    {
        BIO *mem = BIO_new_mem_buf(proxy.data, (int) proxy.len);

        issued = (mem != NULL) ? PEM_read_bio_X509(mem, NULL, NULL, NULL) : NULL;
        BIO_free(mem);
    }
    free(proxy.data);
    if (issued == NULL) {
        return brix_ftp_gss_ssl_err(st, "re-read issued proxy");
    }
    dlen = i2d_X509(issued, &der);
    X509_free(issued);
    if (dlen <= 0 || der == NULL) {
        return brix_ftp_gss_ssl_err(st, "encode issued proxy");
    }
    *out_der = malloc((size_t) dlen);
    if (*out_der == NULL) {
        OPENSSL_free(der);
        brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
        return -1;
    }
    memcpy(*out_der, der, (size_t) dlen);
    *out_len = (size_t) dlen;
    OPENSSL_free(der);
    return 0;
}
