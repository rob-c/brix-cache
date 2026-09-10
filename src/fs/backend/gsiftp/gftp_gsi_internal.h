#ifndef BRIX_GFTP_GSI_INTERNAL_H
#define BRIX_GFTP_GSI_INTERNAL_H

/*
 * gftp_gsi_internal.h — the GSI context shared by the control channel and a
 * PROT P data channel.
 *
 * WHAT: the layout of gftp_gsi_t plus the two construction primitives
 * (gftp_ssl_error, gftp_gsi_setup) that build a client TLS context carrying the
 * X.509 proxy chain and the CA-directory trust anchors.
 *
 * WHY:  a GridFTP protected data channel (DCAU A + PROT P) is a straight TLS
 *       session on the data socket presenting the SAME proxy the control channel
 *       authenticated with — see src/protocols/gridftp/ftp_dc_sec.h for the
 *       inbound mirror of this fact.  The credential loading is therefore the
 *       same code for both, and duplicating it would let the two drift on
 *       exactly the thing that must not drift: which certificate BriX presents
 *       and which roots it trusts.  This header exists only so the data-channel
 *       file (gftp_dc_tls.c) can reuse it; nothing outside this directory
 *       includes it.
 *
 * HOW:  gftp_gsi.c owns the definitions; gftp_dc_tls.c calls gftp_gsi_setup()
 *       on a freshly calloc'd context and then attaches a socket BIO instead of
 *       the control channel's memory BIO pair.
 */

#include "gftp_gsi.h"

#include <openssl/ssl.h>

struct gftp_gsi_s {
    SSL_CTX  *ctx;
    SSL      *ssl;
    BIO      *rbio;
    BIO      *wbio;
    EVP_PKEY *key;
    uint8_t  *pem;
    size_t    pem_len;
    int       state;
};

/* Record the top OpenSSL error on `session` and return -1, so a caller can
 * `return gftp_ssl_error(...)` from any failure arm. */
int gftp_ssl_error(gftp_session_t *session, const char *action);

/* Build gsi->ctx: a TLS client context with proxy certs allowed, the CA
 * directory (or X509_CERT_DIR, or the grid default) as trust anchors, and the
 * proxy chain + key installed.  Returns 0 / -1. */
int gftp_gsi_setup(gftp_gsi_t *gsi, const char *path, const char *ca_dir,
    gftp_session_t *session);

#endif /* BRIX_GFTP_GSI_INTERNAL_H */
