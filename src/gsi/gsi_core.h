/*
 * gsi_core.h — ngx-free GSI/sigver crypto + wire kernels (shared by the nginx
 * module and the native client; see gsi_core.c). Pure OpenSSL + libc.
 */
#ifndef XROOTD_GSI_CORE_H
#define XROOTD_GSI_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

/* ---- XrdSutBuffer (name\0 + step[4] + {type[4] len[4] data}* + kXRS_none) ---- */

/* Find the first bucket of `type`; 0 with out/outlen set, -1 if absent. */
int xrootd_gsi_find_bucket(const uint8_t *buf, size_t len, uint32_t type,
                           const uint8_t **out, size_t *outlen);

/* Growable builder; allocation failure is sticky (->err, checked once). */
typedef struct {
    uint8_t *p;
    size_t   len;
    size_t   cap;
    int      err;
} xrootd_gbuf;

void xrootd_gbuf_init(xrootd_gbuf *g);
void xrootd_gbuf_free(xrootd_gbuf *g);
void xrootd_gbuf_raw(xrootd_gbuf *g, const void *data, size_t n);
void xrootd_gbuf_u32(xrootd_gbuf *g, uint32_t v);                 /* big-endian */
void xrootd_gbuf_start(xrootd_gbuf *g, uint32_t step);           /* "gsi\0" + step */
void xrootd_gbuf_bucket(xrootd_gbuf *g, uint32_t type, const void *d, size_t n);
void xrootd_gbuf_end(xrootd_gbuf *g);                           /* kXRS_none */

/* ---- Diffie-Hellman (ffdhe2048) ---- */

EVP_PKEY *xrootd_gsi_dh_keygen(void);                            /* caller frees */
/* "---BPUB---<hex>---EPUB--" blob → BIGNUM (caller BN_free), NULL on failure. */
BIGNUM   *xrootd_gsi_dh_pub_decode(const uint8_t *blob, size_t len);
/* pub → malloc'd "---BPUB---<UPPERCASE hex>---EPUB--" string, NULL on failure. */
char     *xrootd_gsi_dh_pub_encode(EVP_PKEY *dh);
/* peer key from `mine`'s params (ffdhe2048) + peer_pub; caller frees. */
EVP_PKEY *xrootd_gsi_dh_build_peer(EVP_PKEY *mine, BIGNUM *peer_pub);
/* shared secret (unpadded, dh_pad=0); malloc'd, *slen set; NULL on failure. */
uint8_t  *xrootd_gsi_dh_derive(EVP_PKEY *mine, EVP_PKEY *peer, size_t *slen);

/* ---- kXR_sigver opcode policy ---- */
int xrootd_gsi_sigver_required(uint16_t opcode, int level);

#endif /* XROOTD_GSI_CORE_H */
