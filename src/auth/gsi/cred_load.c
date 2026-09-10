/* File: cred_load.c — outbound X.509 credential file loaders (PEM chain + key)
 * WHAT: brix_gsi_cred_load_pem() reads every CERTIFICATE block of an operator-configured PEM file and returns them re-serialised as one malloc'd PEM blob; brix_gsi_cred_load_key() reads the first PRIVATE KEY block as an EVP_PKEY. Both open O_RDONLY|O_NOFOLLOW|O_CLOEXEC and never follow a symlink.
 * WHY: three server-side GSI clients (cache-fill origin, TPC destination, transparent upstream) each need the same two reads; before this file the cache origin carried private copies and the upstream would have needed a third. One implementation keeps the symlink hardening and the "certs only" contract identical everywhere.
 * HOW: fd → BIO_new_fd(BIO_CLOSE) → PEM_read_bio_X509 loop re-written into a memory BIO (so a key interleaved in a proxy file is dropped) → malloc copy of the BUF_MEM; the key path is a single PEM_read_bio_PrivateKey. ERR_clear_error() after the cert loop drops the benign PEM_R_NO_START_LINE the loop end always leaves.
 */

#include "cred_load.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* Open `path` read-only without following symlinks and wrap it in a BIO that
 * owns the descriptor.  NULL on either failure (the fd is closed). */
static BIO *
cred_open_bio(const char *path)
{
    int   fd;
    BIO  *in;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);  /* vfs-seam-allow: DOMAIN_CREDENTIAL — operator-configured X.509 credential file (not export storage) */
    if (fd < 0) {
        return NULL;
    }
    in = BIO_new_fd(fd, BIO_CLOSE);
    if (in == NULL) {
        close(fd);
    }
    return in;
}

uint8_t *
brix_gsi_cred_load_pem(const char *path, size_t *outlen)
{
    BIO      *in, *out;
    X509     *cert;
    BUF_MEM  *bm;
    uint8_t  *buf = NULL;
    int       n = 0;

    in = cred_open_bio(path);
    if (in == NULL) {
        return NULL;
    }
    out = BIO_new(BIO_s_mem());
    if (out == NULL) {
        BIO_free(in);
        return NULL;
    }
    while ((cert = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL) {
        PEM_write_bio_X509(out, cert);
        X509_free(cert);
        n++;
    }
    ERR_clear_error();                          /* benign PEM EOF on the loop end */
    BIO_free(in);

    if (n > 0) {
        BIO_get_mem_ptr(out, &bm);
        buf = malloc(bm->length);
        if (buf != NULL) {
            memcpy(buf, bm->data, bm->length);
            *outlen = bm->length;
        }
    }
    BIO_free(out);
    return buf;
}

EVP_PKEY *
brix_gsi_cred_load_key(const char *path)
{
    BIO       *in;
    EVP_PKEY  *k;

    in = cred_open_bio(path);
    if (in == NULL) {
        return NULL;
    }
    k = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);
    return k;
}
