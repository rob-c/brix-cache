/*
 * sss_id.h — per-connection SSS identity registry (the XrdSecsssID role).
 *
 * WHAT: A small, thread-safe map from a login id ("lid") to a full SSS entity
 *       (name, vorg, role, groups, endorsements, proxied credential), plus the
 *       bounded setters that fill one such entity and the reader that loads a
 *       proxied credential from a file.
 * WHY:  A multiplexing front end — a FUSE mount under `allow_other`, a gateway,
 *       a batch mover — carries one connection but many callers.  Without a
 *       registry every caller's request is minted under the process's own login
 *       name, so the server sees one identity for all of them and per-user
 *       authorization on the far side is a fiction.  xrootd solves this with
 *       XrdSecsssID; this is the same contract, clean-room.
 * HOW:  A mutex-guarded dynamic array of fixed-size slots, keyed by an exact
 *       lid string.  Lookup is exact and copies out: there is deliberately NO
 *       fallback to "the first slot" or "the process identity", because the
 *       failure mode of a wrong fallback here is one user's request presented
 *       under another user's name.  Registration is bounded
 *       (XRDC_SSS_ID_SLOTS_MAX) and every string setter fails closed on a value
 *       that would not fit, exactly like the server's parser.
 *
 * The entity itself is minted by the shared kernel (core/compat/sss_entity.c),
 * so client and server produce identical bytes from one implementation.
 */
#ifndef XRDC_SSS_ID_H
#define XRDC_SSS_ID_H

#include <stddef.h>
#include <stdint.h>

#include "core/compat/sss_entity.h"   /* brix_sss_entity_t + BRIX_SSS_ENT_*_MAX */

/* Login-id key length (including the NUL) and the hard cap on registrations. */
#define XRDC_SSS_LID_MAX       64
#define XRDC_SSS_ID_SLOTS_MAX  256

/* One registered identity.  Field widths are the wire caps from sss.h, so an
 * ident that fits here is an ident the server will accept. */
typedef struct {
    char    name[BRIX_SSS_ENT_NAME_MAX];
    char    vorg[BRIX_SSS_ENT_VORG_MAX];
    char    role[BRIX_SSS_ENT_ROLE_MAX];
    char    grps[BRIX_SSS_ENT_GRPS_MAX];
    char    endo[BRIX_SSS_ENT_ENDO_MAX];
    uint8_t creds[BRIX_SSS_ENT_CREDS_MAX];
    size_t  creds_len;
} brix_sss_ident;

/* Opaque registry handle. */
struct brix_sss_id_registry;
typedef struct brix_sss_id_registry brix_sss_id_registry;

/* ---- one identity ---- */

/* Zero *id, then copy the non-NULL/non-empty strings in.  Returns -1 (and
 * leaves *id zeroed) when any value is too long for its field. */
int brix_sss_ident_set(brix_sss_ident *id, const char *name, const char *vorg,
                       const char *role, const char *grps, const char *endo);

/* Attach a proxied credential blob.  -1 when len exceeds the wire cap. */
int brix_sss_ident_set_creds(brix_sss_ident *id, const uint8_t *creds,
                             size_t len);

/* Point *ent at the strings inside *id (borrowed, not copied).  Empty fields
 * become NULL so the builder omits their TLVs. */
void brix_sss_ident_to_entity(const brix_sss_ident *id, brix_sss_entity_t *ent);

/* Read a proxied credential from a file into out[out_max].  Returns -1 when the
 * file is missing, unreadable, empty, or larger than out_max. */
int brix_sss_creds_read_file(const char *path, uint8_t *out, size_t out_max,
                             size_t *out_len);

/* ---- the registry ---- */

/* Create an empty registry; NULL on OOM. */
brix_sss_id_registry *brix_sss_id_create(void);

/* Wipe every slot and free the registry.  NULL-safe. */
void brix_sss_id_destroy(brix_sss_id_registry *reg);

/* Register (or replace) the identity for `lid`.  An empty/NULL lid names the
 * default slot.  Returns -1 on OOM, an over-long lid, or a full registry. */
int brix_sss_id_register(brix_sss_id_registry *reg, const char *lid,
                         const brix_sss_ident *id);

/* Drop the identity for `lid`.  Returns -1 when nothing was registered. */
int brix_sss_id_unregister(brix_sss_id_registry *reg, const char *lid);

/* Copy the identity registered for `lid` into *out.  EXACT match only: a miss
 * returns -1 and *out is zeroed.  Never falls back to another slot. */
int brix_sss_id_find(brix_sss_id_registry *reg, const char *lid,
                     brix_sss_ident *out);

/* Number of registered identities. */
size_t brix_sss_id_count(brix_sss_id_registry *reg);

#endif /* XRDC_SSS_ID_H */
