/*
 * sss_keytab.h — SSS (Simple Shared Secret) keytab I/O + credential crypto.
 *
 * WHAT: Read/write the text SSS keytab, plus the two crypto primitives an SSS
 *       credential needs: the IEEE CRC32 integrity word and Blowfish-CFB64
 *       encryption. Shared by sec_sss.c (the auth module) and xrdsssadmin.c.
 * WHY:  The native client must speak SSS to an XRootD server byte-for-byte. The
 *       server's own implementation (src/auth/sss/) is nginx-coupled, so the small,
 *       standard kernels are reimplemented here from the wire spec (NOT copied
 *       from XrdSecsss) — clean-room. The CRC is IEEE (poly 0xedb88320), NOT the
 *       Castagnoli crc32c in libxrdproto.
 * HOW:  Keytab line: "0 N:<id> k:<hexkey> u:<user> g:<group> n:<name> [e:<exp>]"
 *       (mode 0600, O_NOFOLLOW). bf32_encrypt uses EVP_bf_cfb64, padding off, a
 *       variable key length, an all-zero 8-byte IV, and loads the OpenSSL-3
 *       "legacy" provider once.
 *
 * Cross-checked against src/auth/sss/{config.c,auth_crypto_helpers.c,
 * auth_proxy_credential.c}; see docs/refactor/phase-37-clean-room-log.md.
 */
#ifndef XRDC_SSS_KEYTAB_H
#define XRDC_SSS_KEYTAB_H

#include "brix.h"
#include "protocols/root/protocol/sss.h"   /* shared SSS wire constants (single source of truth) */

/* Wire constants — aliased to the shared BRIX_SSS_* so the two sides cannot
 * drift, while keeping the client's XRDC_SSS_* spelling at the call sites. */
#define XRDC_SSS_HDR_LEN      BRIX_SSS_HDR_LEN
#define XRDC_SSS_DATA_HDR_LEN BRIX_SSS_DATA_HDR_LEN
#define XRDC_SSS_BASE_TIME    BRIX_SSS_BASE_TIME
#define XRDC_SSS_ENC_BF32     BRIX_SSS_ENC_BF32
#define XRDC_SSS_OPT_USEDATA  BRIX_SSS_OPT_USEDATA
#define XRDC_SSS_TYPE_NAME    BRIX_SSS_TYPE_NAME

#define XRDC_SSS_KEY_MAX      128
#define XRDC_SSS_KEYS_MAX     64    /* keytab entries we keep in memory */

typedef struct {
    int64_t id;                       /* N: wire key id (>= 0) */
    uint8_t key[XRDC_SSS_KEY_MAX];    /* k: raw key bytes */
    size_t  key_len;
    char    user[128];                /* u: */
    char    group[64];                /* g: */
    char    name[192];                /* n: */
    int64_t exp;                      /* e: epoch expiry, 0 = never */
} brix_sss_key;

/* ---- crypto kernels (local; IEEE CRC32 + Blowfish-CFB64) ---- */

/* IEEE CRC32 (reflected, poly 0xedb88320, init/xorout 0xffffffff). */
uint32_t brix_sss_crc32(const uint8_t *p, size_t len);

/* Blowfish-CFB64 encrypt (padding off, variable key length, zero IV; loads the
 * OpenSSL-3 legacy provider). Writes <= dst_max bytes, sets *out_len. 0 / -1. */
int brix_sss_bf32_encrypt(const uint8_t *key, size_t key_len,
                          const uint8_t *src, size_t src_len,
                          uint8_t *dst, size_t dst_max, size_t *out_len,
                          brix_status *st);

/* ---- keytab I/O ---- */

/* Resolve the default keytab path: $XrdSecSSSKT, then $XrdSecsssKT, else
 * ~/.xrd/sss.keytab. Writes into out[outsz]. */
void brix_sss_keytab_default(char *out, size_t outsz);

/* Read up to max keys from the text keytab at path (mode must be 0600,
 * O_NOFOLLOW). Sets *n. Skips expired/blank/comment lines. 0 / -1 (st set). */
int brix_sss_keytab_read(const char *path, brix_sss_key *keys, int max, int *n,
                         brix_status *st);

/* Write n keys to path atomically, mode 0600. 0 / -1 (st set). */
int brix_sss_keytab_write(const char *path, const brix_sss_key *keys, int n,
                          brix_status *st);

#endif /* XRDC_SSS_KEYTAB_H */
