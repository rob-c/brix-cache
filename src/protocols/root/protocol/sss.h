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
#ifndef BRIX_PROTOCOL_SSS_H
#define BRIX_PROTOCOL_SSS_H

/* Outer SSS packet header: "sss\0" magic + version + options + pad + 8-byte keyid. */
#define BRIX_SSS_HDR_LEN       16
/* Fixed prefix of the decrypted cleartext: 32-byte nonce + 4 gen_time + 4 reserved. */
#define BRIX_SSS_DATA_HDR_LEN  40
/* SSS timestamp epoch (2008-09-23T13:51:20Z) — keeps the uint32 gen_time valid past 2038. */
#define BRIX_SSS_BASE_TIME     1222183880

#define BRIX_SSS_ENC_BF32      '0'   /* Blowfish-CFB64 encoding marker */
#define BRIX_SSS_OPT_USEDATA   0x00  /* self-contained credential (identity inline) */
#define BRIX_SSS_OPT_SNDLID    0x01  /* interactive: server supplies the login id */

/* Identity TLV tags inside the cleartext body.  The v2 entity tags VORG,
 * ROLE, ENDO and CRED fill the gaps the v1 parser left between NAME and
 * RAND; they are the XrdSecEntity field order (name, vorg, role, grps,
 * endorsements, creds) anchored by the two v1-known tags GRPS 0x04 and
 * RAND 0x07 — inferred clean-room, then cross-checked on the wire by
 * tests/test_release20_sss_entity.py (release-2.0-readiness F9). */
#define BRIX_SSS_TYPE_NAME     0x01
#define BRIX_SSS_TYPE_VORG     0x02
#define BRIX_SSS_TYPE_ROLE     0x03
#define BRIX_SSS_TYPE_GRPS     0x04
#define BRIX_SSS_TYPE_ENDO     0x05
#define BRIX_SSS_TYPE_CRED     0x06
#define BRIX_SSS_TYPE_RAND     0x07
#define BRIX_SSS_TYPE_LGID     0x10
#define BRIX_SSS_TYPE_HOST     0x20

/* Receiver-side caps for every entity field (buffer sizes in the server's
 * brix_sss_identity_t and the client registry; each packed string must fit
 * WITH its NUL, the CRED blob is raw).  Producers fail closed at the cap,
 * they never truncate.  BLOB_MAX bounds the whole credential:
 * 16 + 40 + 6*3 + 256*3 + 512 + 1024 + 4096 + 4 = 6478 < 8192. */
#define BRIX_SSS_ENT_NAME_MAX      256
#define BRIX_SSS_ENT_VORG_MAX      256
#define BRIX_SSS_ENT_ROLE_MAX      256
#define BRIX_SSS_ENT_GRPS_MAX      512
#define BRIX_SSS_ENT_ENDO_MAX     1024
#define BRIX_SSS_ENT_CREDS_MAX    4096
#define BRIX_SSS_ENTITY_BLOB_MAX  8192

#endif /* BRIX_PROTOCOL_SSS_H */
