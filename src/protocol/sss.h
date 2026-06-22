/*
 * sss.h — SSS (Simple Shared Secret) wire constants (single source of truth).
 *
 * WHAT: the on-the-wire constants of the XRootD SSS credential format.
 * WHY:  the module's SSS auth (src/sss) and the native client's SSS mint
 *       (client/lib/sss_keytab.c, sec_sss.c) must agree byte-for-byte; previously
 *       each kept its own copy with a "must match the other" comment. This header
 *       is the one place they come from (gsi.h precedent in the same directory).
 * HOW:  header-only macros — no ngx, no includes, no code.
 *
 * Clean-room: wire facts cross-checked against XrdSecsss, not copied from it.
 */
#ifndef XROOTD_PROTOCOL_SSS_H
#define XROOTD_PROTOCOL_SSS_H

/* Outer SSS packet header: "sss\0" magic + version + options + pad + 8-byte keyid. */
#define XROOTD_SSS_HDR_LEN       16
/* Fixed prefix of the decrypted cleartext: 32-byte nonce + 4 gen_time + 4 reserved. */
#define XROOTD_SSS_DATA_HDR_LEN  40
/* SSS timestamp epoch (2008-09-23T13:51:20Z) — keeps the uint32 gen_time valid past 2038. */
#define XROOTD_SSS_BASE_TIME     1222183880

#define XROOTD_SSS_ENC_BF32      '0'   /* Blowfish-CFB64 encoding marker */
#define XROOTD_SSS_OPT_USEDATA   0x00  /* self-contained credential (identity inline) */
#define XROOTD_SSS_OPT_SNDLID    0x01  /* interactive: server supplies the login id */

/* Identity TLV tags inside the cleartext body. */
#define XROOTD_SSS_TYPE_NAME     0x01
#define XROOTD_SSS_TYPE_GRPS     0x04
#define XROOTD_SSS_TYPE_RAND     0x07
#define XROOTD_SSS_TYPE_LGID     0x10
#define XROOTD_SSS_TYPE_HOST     0x20

#endif /* XROOTD_PROTOCOL_SSS_H */
