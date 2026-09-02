/*
 * sd_pblock_cred.c — identity-enforcing *_cred vtable slots for the pblock
 * storage driver.
 *
 * WHAT: Implements every credential-scoped slot of brix_sd_pblock_driver
 *       (open/staged_open/stat/unlink/mkdir/rename/setattr/xattr CRUD/
 *       server_copy/opendir). Each slot resolves the request identity to
 *       catalog-internal synthetic ids (sd_pblock_ident.c), enforces the POSIX
 *       mode-bit rule for the operation against catalog ownership, then
 *       performs the op through the plain implementation (or its owner-aware
 *       `_as` variant when the op creates rows).
 *
 * WHY:  The settled "enforce in pblock" decision: pblock is its own multi-user
 *       authority — the VFS passes identity down (BRIX_SD_CRED_IDENTITY) and
 *       the backend answers may/may-not from its own registry. group = VO, so
 *       per-VO sharing is plain unix group permissions.
 *
 * HOW:  The rule per op (documented on each slot): read ops need R on the
 *       object; write/xattr-mutating ops need W on the object; entry
 *       create/remove/rename need W on the immediate parent (plus the sticky
 *       gate on removal); chmod/chown are owner-only, chown-to-other-uid is
 *       service-only, chgrp only to a VO the requester belongs to. A `service`
 *       identity (no principal) bypasses every check — single-user/tests keep
 *       today's semantics. Enforcement is check-then-act against the catalog:
 *       the small TOCTOU window between the check and the act is accepted (a
 *       concurrent chmod may lag one op), matching the kernel-free design.
 *       ngx-free; gated by BRIX_HAVE_SQLITE like the rest of the backend.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fs/backend/sd.h"

#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"
#include "pblock_store.h"
#include "sd_pblock_internal.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* resolve_or_fail — the common slot prologue: cred → ids, NGX_ERROR/errno on a
 * registry failure. Wrapped so every slot reads as gate + act. */
static ngx_int_t
resolve_or_fail(brix_sd_instance_t *inst, const brix_sd_cred_t *cred,
    pblock_ids_t *ids)
{
    return pblock_ident_resolve(inst->state, cred, ids);
}

/* dst_write_gate — POSIX authority to place an entry at `path`: parent X
 * (traverse) plus W on the entry itself when it exists (an overwrite), else
 * W+X on the immediate parent (a create). Shared by staged_open_cred and
 * server_copy_cred. */
static ngx_int_t
dst_write_gate(pblock_state_t *st, const char *path, const pblock_ids_t *ids)
{
    pblock_meta meta;
    int         rc;

    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 0) {
        if (pblock_ident_check_parent(st, path, ids, X_OK, NULL) != NGX_OK) {
            return NGX_ERROR;
        }
        return pblock_ident_access(&meta, ids, W_OK);
    }
    return pblock_ident_check_parent(st, path, ids, W_OK | X_OK, NULL);
}

/* remove_gate — POSIX authority to remove/replace the entry `path`: W+X on
 * the immediate parent plus the sticky-bit owner rule. ENOENT when absent.
 * Shared by unlink_cred and both halves of rename_cred. */
static ngx_int_t
remove_gate(pblock_state_t *st, const char *path, const pblock_ids_t *ids)
{
    pblock_meta parent, entry;
    int         rc;

    rc = pblock_catalog_lookup(st->cat, path, &entry);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 1) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    if (pblock_ident_check_parent(st, path, ids, W_OK | X_OK,
                                  &parent) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return pblock_ident_sticky_gate(&parent, &entry, ids);
}

/* ---- data-plane opens ------------------------------------------------------ */

/* open_cred — parent X (traverse) first; then existing object: R for a read
 * open, W for a write open (O_TRUNC is a write). Absent + O_CREATE: W on the
 * parent; the new row is owned by the requester (uid, primary-VO gid). */
brix_sd_obj_t *
sd_pblock_open_cred(brix_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    pblock_state_t *st = inst->state;
    pblock_ids_t    ids;
    pblock_meta     meta;
    int             rc;

    if (resolve_or_fail(inst, cred, &ids) != NGX_OK) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    if (ids.service) {
        return sd_pblock_open_as(inst, path, sd_flags, mode, 0, 0, err_out);
    }

    if (pblock_ident_check_parent(st, path, &ids, X_OK, NULL) != NGX_OK) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc < 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    if (rc == 0) {
        int want = (sd_flags & BRIX_SD_O_WRITE) ? W_OK : R_OK;

        if (pblock_ident_access(&meta, &ids, want) != NGX_OK) {
            if (err_out != NULL) { *err_out = errno; }
            return NULL;
        }
    } else if (sd_flags & BRIX_SD_O_CREATE) {
        if (pblock_ident_check_parent(st, path, &ids, W_OK, NULL) != NGX_OK) {
            if (err_out != NULL) { *err_out = errno; }
            return NULL;
        }
    }
    /* absent without O_CREATE falls through: open_as reports ENOENT. */
    return sd_pblock_open_as(inst, path, sd_flags, mode, ids.uid, ids.gid,
                             err_out);
}

/* staged_open_cred — authority to place the committed row: W on an existing
 * final path (overwrite) or W on the parent (create); owner = requester. */
brix_sd_staged_t *
sd_pblock_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, off_t declared_size, const brix_sd_cred_t *cred, int *err_out)
{
    pblock_ids_t ids;

    if (resolve_or_fail(inst, cred, &ids) != NGX_OK) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    if (!ids.service
        && dst_write_gate(inst->state, final_path, &ids) != NGX_OK)
    {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    return sd_pblock_staged_open_as(inst, final_path, mode, declared_size,
                                    ids.uid, ids.gid, err_out);
}

/* ---- namespace ------------------------------------------------------------- */

/* stat_cred — unchecked (documented simplification: no ancestor X-bit walk;
 * metadata visibility is the export's concern). Exists so the VFS ns-cred gate
 * (stat_cred != NULL) routes ALL namespace ops through the cred slots. */
ngx_int_t
sd_pblock_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    (void) cred;
    return sd_pblock_stat(inst, path, out);
}

/* unlink_cred — W on the parent + sticky owner rule. */
ngx_int_t
sd_pblock_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    pblock_ids_t ids;

    if (resolve_or_fail(inst, cred, &ids) != NGX_OK) {
        return NGX_ERROR;
    }
    if (!ids.service && remove_gate(inst->state, path, &ids) != NGX_OK) {
        return NGX_ERROR;
    }
    return sd_pblock_unlink(inst, path, is_dir);
}

/* Per-key gate for the C4 batch: the same remove_gate the single unlink runs,
 * bound to the identity resolved once for the whole window. */
typedef struct {
    pblock_state_t     *st;
    const pblock_ids_t *ids;
} pblock_batch_gate_ctx_t;

static ngx_int_t
pblock_unlink_batch_gate(void *gctx, const char *path)
{
    const pblock_batch_gate_ctx_t *c = gctx;

    return remove_gate(c->st, path, c->ids);
}

/* unlink_many_cred - identity resolved ONCE, then the shared transactional
 * core (sd_pblock_batch.c) runs remove_gate + unlink per key. A service
 * identity skips the gates exactly as the single slot does. */
ngx_int_t
sd_pblock_unlink_many_cred(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b,
    const brix_sd_cred_t *cred)
{
    pblock_ids_t            ids;
    pblock_batch_gate_ctx_t c;

    if (resolve_or_fail(inst, cred, &ids) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ids.service) {
        return sd_pblock_unlink_many(inst, b);
    }
    c.st  = inst->state;
    c.ids = &ids;
    return sd_pblock_unlink_many_core(inst, b, pblock_unlink_batch_gate, &c);
}

/* mkdir_cred — W+X on the parent; the new directory is owned by the requester. */
ngx_int_t
sd_pblock_mkdir_cred(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    pblock_ids_t ids;
    char         canon[PATH_MAX];

    if (resolve_or_fail(inst, cred, &ids) != NGX_OK) {
        return NGX_ERROR;
    }
    /* Canonicalise BEFORE the parent-permission check: a `-cd` MKD "/interop/"
     * would otherwise resolve its parent to the non-existent "/interop" and
     * fail W+X with a spurious ENOENT (see pblock_path_canon). */
    if (pblock_path_canon(path, canon, sizeof(canon)) != 0) {
        return NGX_ERROR;
    }
    path = canon;
    if (!ids.service
        && pblock_ident_check_parent(inst->state, path, &ids, W_OK | X_OK,
                                     NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return sd_pblock_mkdir_as(inst, path, mode, ids.uid, ids.gid);
}

/* rename_cred — removal authority on src (parent W + sticky); placement
 * authority on dst (overwrite: removal authority; create: parent W). */
ngx_int_t
sd_pblock_rename_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred)
{
    pblock_state_t *st = inst->state;
    pblock_ids_t    ids;
    int             rc;

    if (resolve_or_fail(inst, cred, &ids) != NGX_OK) {
        return NGX_ERROR;
    }
    if (!ids.service) {
        if (remove_gate(st, src, &ids) != NGX_OK) {
            return NGX_ERROR;
        }
        rc = pblock_catalog_lookup(st->cat, dst, NULL);
        if (rc < 0) {
            return NGX_ERROR;
        }
        if (rc == 0) {
            if (remove_gate(st, dst, &ids) != NGX_OK) {
                return NGX_ERROR;
            }
        } else if (pblock_ident_check_parent(st, dst, &ids, W_OK | X_OK,
                                             NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    return sd_pblock_rename(inst, src, dst, noreplace);
}

/* exchange_cred — both names exist and both contents are replaced, so the
 * authority needed is removal authority on EACH (parent W+X plus the sticky
 * rule); no placement gate — both slots stay occupied throughout (C6). */
ngx_int_t
sd_pblock_exchange_cred(brix_sd_instance_t *inst, const char *a, const char *b,
    const brix_sd_cred_t *cred)
{
    pblock_state_t *st = inst->state;
    pblock_ids_t    ids;

    if (resolve_or_fail(inst, cred, &ids) != NGX_OK) {
        return NGX_ERROR;
    }
    if (!ids.service) {
        if (remove_gate(st, a, &ids) != NGX_OK
            || remove_gate(st, b, &ids) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    return sd_pblock_exchange(inst, a, b);
}

/* setattr_cred — chmod/chown are owner-only; changing the uid at all is
 * service-only (no giving files away); the owner may chgrp only to a VO they
 * belong to (or their private group); times need ownership or W. */
/*
 * WHAT: Determine whether a requested gid belongs to the resolved identity.
 * WHY:  chgrp is restricted to the caller's private or asserted VO groups.
 * HOW:  Check the private gid, then scan the bounded resolved group vector.
 */
static int
pblock_ident_has_gid(const pblock_ids_t *ids, gid_t gid)
{
    int i;

    if (gid == ids->uid)
        return 1;
    for (i = 0; i < ids->ngids; i++) {
        if (gid == ids->gids[i])
            return 1;
    }
    return 0;
}

/*
 * WHAT: Authorize a non-service setattr request against current metadata.
 * WHY:  Ownership, chown, chgrp, and timestamp rules form one policy gate.
 * HOW:  Apply owner-only mutations and permit times to writable non-owners.
 */
static ngx_int_t
pblock_setattr_authorize(const pblock_meta *meta, const pblock_ids_t *ids,
    const brix_sd_setattr_t *attr)
{
    if ((attr->set_mode || attr->set_owner) && meta->uid != ids->uid) {
        errno = EPERM;
        return NGX_ERROR;
    }
    if (attr->set_owner
        && ((attr->uid != (uid_t) -1 && attr->uid != meta->uid)
            || (attr->gid != (gid_t) -1
                && !pblock_ident_has_gid(ids, attr->gid))))
    {
        errno = EPERM;
        return NGX_ERROR;
    }
    if (attr->set_times && meta->uid != ids->uid
        && pblock_ident_access(meta, ids, W_OK) != NGX_OK)
    {
        errno = EPERM;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
sd_pblock_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    pblock_state_t *st = inst->state;
    pblock_ids_t    ids;
    pblock_meta     meta;

    if (resolve_or_fail(inst, cred, &ids) != NGX_OK) {
        return NGX_ERROR;
    }
    if (!ids.service) {
        if (pblock_ident_check(st, path, &ids, 0, &meta) != NGX_OK) {
            return NGX_ERROR;                   /* ENOENT */
        }
        if (pblock_setattr_authorize(&meta, &ids, attr) != NGX_OK)
            return NGX_ERROR;
    }
    return sd_pblock_setattr(inst, path, attr);
}

/* ---- xattr ------------------------------------------------------------------ */

/* cred_access_gate — resolve the identity and enforce `mode` on the object
 * (service identities bypass, as everywhere in this file). The gate for every
 * slot whose rule is simply "R/W on the object" and that never needs the ids
 * afterwards: xattr CRUD and opendir. */
static ngx_int_t
cred_access_gate(brix_sd_instance_t *inst, const brix_sd_cred_t *cred,
    const char *path, int mode)
{
    pblock_ids_t ids;

    if (resolve_or_fail(inst, cred, &ids) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ids.service) {
        return NGX_OK;
    }
    return pblock_ident_check(inst->state, path, &ids, mode, NULL);
}

/* PBLOCK_CRED_GATED — the whole body of an object-mode-gated slot: run
 * cred_access_gate (using the slot's `inst`/`cred`/`path` parameters), return
 * `errval` when it refuses, else RETURN the delegated call. */
#define PBLOCK_CRED_GATED(mode, errval, call) \
    do { \
        if (cred_access_gate(inst, cred, path, mode) != NGX_OK) { \
            return errval; \
        } \
        return call; \
    } while (0)

/* getxattr_cred / listxattr_cred — R on the object. */
ssize_t
sd_pblock_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    PBLOCK_CRED_GATED(R_OK, -1, sd_pblock_getxattr(inst, path, name, buf, cap));
}

ssize_t
sd_pblock_listxattr_cred(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    PBLOCK_CRED_GATED(R_OK, -1, sd_pblock_listxattr(inst, path, buf, cap));
}

/* setxattr_cred / removexattr_cred — W on the object. */
ngx_int_t
sd_pblock_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    PBLOCK_CRED_GATED(W_OK, NGX_ERROR,
                      sd_pblock_setxattr(inst, path, name, val, len, flags));
}

ngx_int_t
sd_pblock_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    PBLOCK_CRED_GATED(W_OK, NGX_ERROR, sd_pblock_removexattr(inst, path, name));
}

/* ---- copy + directory listing ------------------------------------------------ */

/* server_copy_cred — R on src; placement authority on dst; the copy is owned
 * by the copier (POSIX cp semantics), not the source's owner. */
ngx_int_t
sd_pblock_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    pblock_ids_t ids;

    if (resolve_or_fail(inst, cred, &ids) != NGX_OK) {
        return NGX_ERROR;
    }
    if (!ids.service
        && (pblock_ident_check(inst->state, src, &ids, R_OK, NULL) != NGX_OK
            || dst_write_gate(inst->state, dst, &ids) != NGX_OK))
    {
        return NGX_ERROR;
    }
    return sd_pblock_server_copy_as(inst, src, dst, bytes_out, ids.uid,
                                    ids.gid);
}

/* recall_cred (phase-107 C2) — R on the object: a recall exists to make the
 * object READABLE, so the identity that may read it is the identity that may
 * stage it (and pays the simulated tape latency). pblock is its own multi-user
 * authority, so unlike the wire drivers the twin does not re-sign anything —
 * it gates and delegates, like every R/W-ruled slot above. The recall is
 * bounded-synchronous (pblock_nearline.h), so nothing outlives the call and
 * the borrowed cred is never retained. */
ngx_int_t
sd_pblock_recall_cred(brix_sd_instance_t *inst, const char *key,
    const brix_sd_cred_t *cred, char reqid_out[40])
{
    const char *path = key;              /* catalog keys ARE the object paths */

    PBLOCK_CRED_GATED(R_OK, NGX_ERROR,
                      sd_pblock_recall(inst, key, reqid_out));
}

/* evict_cred (phase-107 C2) — W on the object: eviction destroys the online
 * copy, the same class of mutation as truncate/removexattr, so it takes the
 * same W_OK rule (R would let any reader flush another user's staged data
 * back to simulated tape and re-impose the recall latency on the owner).
 * Gate-and-delegate like every slot above; the demote is synchronous, so the
 * borrowed cred is never retained. */
ngx_int_t
sd_pblock_evict_cred(brix_sd_instance_t *inst, const char *path,
    uint64_t *bytes_out, const brix_sd_cred_t *cred)
{
    PBLOCK_CRED_GATED(W_OK, NGX_ERROR,
                      sd_pblock_evict(inst, path, bytes_out));
}

/* opendir_cred — R on the directory (listing = reading the directory). */
brix_sd_dir_t *
sd_pblock_opendir_cred(brix_sd_instance_t *inst, const char *path,
    int *err_out, const brix_sd_cred_t *cred)
{
    if (cred_access_gate(inst, cred, path, R_OK) != NGX_OK) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }
    return sd_pblock_opendir(inst, path, err_out);
}

#endif /* BRIX_HAVE_SQLITE */
