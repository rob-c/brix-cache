/* File: sss_entity.h — SSS v2 entity credential builder + LGID challenge decoder
 * WHAT: The ngx-free kernel that mints a full XrdSecsss v2 *entity* credential
 *       (NAME + VORG + ROLE + GRPS + ENDO + a proxied CRED blob) and decodes the
 *       server's kXR_authmore challenge (the LGID it wants the client to answer
 *       with).  Shared by the module's proxy arm (src/net/proxy/, forwarding the
 *       front-side identity upstream) and the native client (client/lib/auth/sec/
 *       sec_sss.c, --sss-vorg/--sss-role/--sss-endorse/--sss-creds-file and the
 *       per-connection ID registry).
 * WHY: brix_sss_build_credential() (sss_bf.c) is the frozen v1 NAME-only wire —
 *      byte-identical to what every 1.x client sent — and stays untouched.  The
 *      2.0 breadth (release-2.0-readiness F9) needs the remaining entity TLVs,
 *      the SNDLID first round and the challenge decode in ONE place so the server
 *      parser (src/auth/sss/auth_identity_challenge.c), the proxy and the client
 *      cannot drift on field order, caps or the packed-string NUL rule.
 * HOW: A NULL entity mints the SNDLID form (40-byte data header, option byte
 *      BRIX_SSS_OPT_SNDLID, no TLVs) — the server answers kXR_authmore carrying
 *      an LGID; brix_sss_challenge_lgid() decrypts that reply and returns the
 *      LGID so the caller can look its registry up and mint the USEDATA entity.
 *      Strings are packed NUL-terminated with a 2-byte big-endian length (NUL
 *      included); the CRED TLV carries raw bytes.  Every string is capped at the
 *      receiver-side buffer (BRIX_SSS_ENT_*_MAX in protocols/root/protocol/sss.h)
 *      and the builder fails closed (-1) rather than truncating, so a proxied
 *      DN or credential can never be silently shortened into a different identity.
 */
#ifndef BRIX_COMPAT_SSS_ENTITY_H
#define BRIX_COMPAT_SSS_ENTITY_H

#include <stddef.h>
#include <stdint.h>

#include "protocols/root/protocol/sss.h"   /* wire constants + the BRIX_SSS_ENT_* caps */

/* One entity to encode.  NULL / "" strings and a NULL / zero-length creds are
 * omitted from the wire; a NULL / "" name is sent as "xrd" (the v1 default). */
typedef struct {
    const char    *name;       /* NAME  0x01 — user name / DN */
    const char    *vorg;       /* VORG  0x02 — virtual organisation */
    const char    *role;       /* ROLE  0x03 — VO role */
    const char    *grps;       /* GRPS  0x04 — comma-separated group list */
    const char    *endo;       /* ENDO  0x05 — endorsements */
    const uint8_t *creds;      /* CRED  0x06 — proxied credential, raw bytes */
    size_t         creds_len;
} brix_sss_entity_t;

/*
 * Mint an SSS credential for `ent` (USEDATA) or, when ent == NULL, the SNDLID
 * first-round header.  key/key_len/key_id select the keytab entry; nonce32 is
 * the caller's 32 random bytes; gen_time is seconds since BRIX_SSS_BASE_TIME.
 * Writes the complete outer-header + BF32 body to out (capacity out_max, use
 * BRIX_SSS_ENTITY_BLOB_MAX) and its length to *out_len.  Returns 0, or -1 on a
 * NULL argument, a string at or over its cap, a creds blob over its cap, a
 * too-small out buffer or a cipher failure.
 */
int brix_sss_build_entity_credential(const uint8_t *key, size_t key_len,
    uint64_t key_id, const brix_sss_entity_t *ent, const uint8_t nonce32[32],
    uint32_t gen_time, uint8_t *out, size_t out_max, size_t *out_len);

/*
 * Decode a kXR_authmore challenge body (outer header echoed by the server +
 * BF32 body) and copy the LGID it carries into lgid (NUL-terminated, capacity
 * lgid_max).  Returns 0, or -1 on a malformed header, a body that does not
 * decrypt under `key`, a CRC mismatch, or a body without an LGID TLV.
 */
int brix_sss_challenge_lgid(const uint8_t *key, size_t key_len,
    const uint8_t *body, size_t body_len, char *lgid, size_t lgid_max);

#endif /* BRIX_COMPAT_SSS_ENTITY_H */
