/*
 * sss_keytab_kernel.h — shared SSS keytab text grammar.
 *
 * WHAT: The pure-C keytab grammar shared by the server's keytab loader
 *       (src/sss/config.c) and the native client's keytab reader
 *       (client/lib/sss_keytab.c): the one-line field parser and the keytab-file
 *       permission check. The SSS crypto kernels (CRC-32/IEEE, Blowfish-CFB64)
 *       and the hex codec are already shared via libxrdproto; this completes the
 *       set by removing the last byte-for-byte copy — the line grammar itself.
 * WHY:  Both consumers must agree exactly on how a keytab line is tokenised and
 *       on what counts as a safe keytab file; two hand-maintained copies of a
 *       security-sensitive parser are a divergence risk. Keeping one audited copy
 *       means a key minted/written by the client is parsed by the server (and
 *       vice-versa) under identical rules.
 * HOW:  Plain C — no nginx, no OpenSSL, no I/O. The caller owns the file I/O and
 *       reads each line; the kernel parses one line into a neutral entry and the
 *       caller copies the fields into its own key struct (computing any
 *       server-only authz options at the edge). The parser fails closed on a
 *       malformed required field (bad version tag, non-hex key, non-numeric id /
 *       expiry, over-long field) so a tampered keytab is rejected, never
 *       silently truncated.
 */
#ifndef BRIX_SSS_KEYTAB_KERNEL_H
#define BRIX_SSS_KEYTAB_KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>   /* mode_t */

/*
 * Field caps for the neutral entry. These match both consumers' key structs
 * (brix_sss_key_t in src/types/config.h and xrdc_sss_key in
 * client/lib/sss_keytab.h); each consumer copies out with its own bounded copy,
 * so a future size change there only ever truncates safely.
 */
#define SSS_K_KEY_MAX    128
#define SSS_K_USER_MAX   128
#define SSS_K_GROUP_MAX   64
#define SSS_K_NAME_MAX   192

/* One parsed keytab entry (the raw fields; no server-side authz options). */
typedef struct {
    int64_t  id;                       /* N: wire key id (>= 0)               */
    int64_t  exp;                      /* e: epoch expiry, 0 = never          */
    size_t   key_len;                  /* decoded length of key[]             */
    uint8_t  key[SSS_K_KEY_MAX];       /* k: raw key bytes                    */
    char     user[SSS_K_USER_MAX];     /* u: (default "nobody")               */
    char     group[SSS_K_GROUP_MAX];   /* g: (default "nogroup")              */
    char     name[SSS_K_NAME_MAX];     /* n: (default "nowhere")              */
} sss_keytab_entry_t;

/*
 * Parse one keytab line (mutated in place by strtok_r) into *out. `now` is the
 * current epoch used for the expiry check. Returns:
 *   1  — a usable key was parsed into *out;
 *   0  — the line is blank / a comment / an expired key (skip it);
 *  -1  — a required field is malformed (caller should fail closed).
 * Grammar:  <0|1> [u:user] [g:group] [n:name] [N:id] [k:hexkey] [e:expiry]
 * Required: a "0"/"1" version tag, N: (>= 0) and k: (non-empty). Unknown fields
 * are ignored; an inline '#' field starts a comment.
 */
int sss_keytab_parse_line(char *line, sss_keytab_entry_t *out, int64_t now);

/*
 * Validate keytab file permissions (shared secret — must not be exposed).
 * Owner read/write is always allowed; all group/other bits are otherwise
 * rejected. When `allow_dotgrp` is non-zero, a path ending in ".grp" may
 * additionally be group-readable (the server's distributed-keytab variant).
 * Returns 0 if the mode is safe, -1 otherwise.
 */
int sss_keytab_mode_ok(const char *path, mode_t mode, int allow_dotgrp);

#endif /* BRIX_SSS_KEYTAB_KERNEL_H */
