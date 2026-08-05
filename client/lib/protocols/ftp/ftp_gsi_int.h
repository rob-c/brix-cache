/*
 * ftp_gsi_int.h — internals shared by the GSI initiator's two translation units.
 *
 * WHAT: the initiator's session object plus the credential/delegation helpers the
 *       state machine calls out to.
 * WHY:  the handshake driver (ftp_gsi.c) and the X.509 work it needs — loading the
 *       proxy credential, signing the server's delegation request (ftp_gsi_cred.c)
 *       — are separate concerns with separate failure modes; splitting them keeps
 *       each file small while they still share one struct definition.
 * HOW:  include only from client/lib/protocols/ftp/ftp_gsi*.c.
 */
#ifndef BRIX_FTP_GSI_INT_H
#define BRIX_FTP_GSI_INT_H

#include "ftp_client.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

enum {
    FTP_GSS_TLS = 0,     /* driving SSL_connect                                */
    FTP_GSS_DELEG_CSR,   /* 'D' sent, awaiting the server's proxy request      */
    FTP_GSS_DELEG_ACK,   /* signed proxy sent, awaiting the server's 235       */
    FTP_GSS_DONE,
    FTP_GSS_FAIL
};

struct brix_ftp_gss {
    SSL_CTX  *ctx;
    SSL      *ssl;
    BIO      *rbio;        /* server → SSL                                     */
    BIO      *wbio;        /* SSL → server (drained into ADAT/ENC tokens)      */
    EVP_PKEY *key;         /* proxy private key — signs the delegation request */
    uint8_t  *pem;         /* proxy chain PEM (certs only), the signer identity */
    size_t    pem_len;
    int       state;
};

/* Resolve $X509_USER_PROXY (else /tmp/x509up_u<uid>) into out. */
void brix_ftp_gss_proxy_path(char *out, size_t outsz);

/* Load the proxy credential: leaf + chain + key into `ctx`, and keep the PEM and
 * key on `g` for the delegation round. 0 / -1 (st set). */
int brix_ftp_gss_load_cred(struct brix_ftp_gss *g, const char *proxy,
                           brix_status *st);

/* Sign the server's DER proxy-certificate request with the session proxy and
 * return the issued certificate as DER (malloc'd; caller frees). 0 / -1. */
int brix_ftp_gss_sign_csr(struct brix_ftp_gss *g, const uint8_t *csr_der,
                          size_t csr_len, uint8_t **out_der, size_t *out_len,
                          brix_status *st);

/* Format the current OpenSSL error queue into st (always returns -1). */
int brix_ftp_gss_ssl_err(brix_status *st, const char *what);

#endif /* BRIX_FTP_GSI_INT_H */
