/*
 * sd_pblock_ident.c — identity resolution + POSIX access checks for the pblock
 * storage driver's catalog-internal ownership model.
 *
 * WHAT: Resolves a request credential (brix_sd_cred_t: authenticated principal
 *       + comma-separated VO list) into pblock_ids_t — the catalog-internal
 *       synthetic uid and VO gids from the catalog's `ids` registry — and
 *       provides the POSIX mode-bit checks the *_cred vtable slots
 *       (sd_pblock_cred.c) enforce: object access by class (owner/group/other),
 *       parent-directory checks for create/remove, and the sticky-bit delete
 *       gate.
 *
 * WHY:  pblock is self-contained multi-user storage: no unix accounts, no
 *       impersonation — the catalog is the identity authority (the settled
 *       "catalog-internal registry" owner model). Group membership IS VO
 *       membership, so a VO-shared directory is just a group-writable
 *       directory owned by the VO's gid. Splitting resolution/checks from the
 *       slots keeps both files under the one-concept size cap.
 *
 * HOW:  Resolution maps principal→uid and each VO name→gid through
 *       pblock_catalog_id_map (auto-assigning, immutable, process-safe); a
 *       VO-less principal gets a user-private group (gid = uid — the id space
 *       is a single sequence, so uids and gids never collide). No cache: the
 *       maps are indexed point SELECTs on a WAL/FULLMUTEX connection, safe from
 *       worker threads where a shared mutable cache would not be. A NULL/empty
 *       principal resolves to `service` (all checks pass), preserving
 *       single-user semantics for identity-less deployments. ngx-free; gated by
 *       BRIX_HAVE_SQLITE like the rest of the backend.
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
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>          /* R_OK / W_OK / X_OK — the `want` bit values */

/* ---- identity resolution --------------------------------------------------
 *
 * WHAT: Fill *out with the credential's synthetic ids: principal→uid, each
 *       VO name in the comma-separated cred->vos→one gid (first VO = primary
 *       gid). NULL cred / NULL or empty principal → out->service = 1 (bypass).
 *       NGX_OK, or NGX_ERROR with errno (registry failure).
 *
 * WHY: Every *_cred slot needs the same cred→ids translation; ids must be
 *      stable across workers and restarts, which the catalog registry
 *      guarantees and an in-process table could not.
 *
 * HOW: 1. Service bypass on missing identity. 2. id_map the principal (USER
 *      kind). 3. Walk the VO CSV, id_mapping each non-empty token (GROUP
 *      kind) up to PBLOCK_MAX_GIDS (excess VOs are ignored — membership
 *      checks just won't see them; 16 covers real WLCG credentials). 4. A
 *      VO-less principal gets gid = uid (user-private group).
 */
ngx_int_t
pblock_ident_resolve(pblock_state_t *st, const brix_sd_cred_t *cred,
    pblock_ids_t *out)
{
    const char *p;
    int64_t     id;

    memset(out, 0, sizeof(*out));
    if (cred == NULL || cred->principal == NULL || cred->principal[0] == '\0') {
        out->service = 1;
        return NGX_OK;
    }

    if (pblock_catalog_id_map(st->cat, PBLOCK_ID_USER, cred->principal,
                              &id) != 0)
    {
        return NGX_ERROR;
    }
    out->uid = (uint32_t) id;

    for (p = cred->vos; p != NULL && *p != '\0'
                        && out->ngids < PBLOCK_MAX_GIDS; /* void */) {
        const char *end = strchr(p, ',');
        size_t      len = end != NULL ? (size_t) (end - p) : strlen(p);
        char        name[256];

        while (len > 0 && p[0] == ' ') { p++; len--; }
        while (len > 0 && p[len - 1] == ' ') { len--; }
        if (len > 0 && len < sizeof(name)) {
            memcpy(name, p, len);
            name[len] = '\0';
            if (pblock_catalog_id_map(st->cat, PBLOCK_ID_GROUP, name,
                                      &id) != 0)
            {
                return NGX_ERROR;
            }
            out->gids[out->ngids++] = (uint32_t) id;
        }
        p = end != NULL ? end + 1 : "";
    }

    /* Primary gid: the first VO, else a user-private group. The id space is
     * one sequence across kinds, so uid-as-gid collides with no VO's gid. */
    out->gid = out->ngids > 0 ? out->gids[0] : out->uid;
    return NGX_OK;
}

/* ---- POSIX mode-bit access check ------------------------------------------
 *
 * WHAT: Grant/deny `want` (OR of R_OK/W_OK/X_OK) on a catalog row per POSIX
 *       class selection: owner bits when ids->uid owns the row, group bits
 *       when the row's gid is any of the requester's VO gids (or the private
 *       group), other bits otherwise. NGX_OK, or NGX_ERROR with errno EACCES.
 *
 * WHY: This one function IS the enforcement model — everything else just
 *      decides which row and which `want` bits to hand it.
 *
 * HOW: Class selection is exclusive (an owner is judged by owner bits alone,
 *      like the kernel). `service` identities pass unconditionally.
 */
ngx_int_t
pblock_ident_access(const pblock_meta *meta, const pblock_ids_t *ids,
    int want)
{
    unsigned shift = 0;
    int      i;

    if (ids->service) {
        return NGX_OK;
    }

    if (meta->uid == ids->uid) {
        shift = 6;
    } else if (meta->gid == ids->gid) {
        shift = 3;
    } else {
        for (i = 0; i < ids->ngids; i++) {
            if (meta->gid == ids->gids[i]) {
                shift = 3;
                break;
            }
        }
    }

    if ((int) ((meta->mode >> shift) & 7 & (unsigned) want) != want) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- object gate: traverse + lookup + access in one call -------------------
 *
 * WHAT: Demand X (search) on `path`'s immediate parent, then look `path` up
 *       and demand `want` on it; fills *meta_out (optional). NGX_OK, or
 *       NGX_ERROR with errno (EACCES traverse/access denied, ENOENT absent).
 *
 * WHY: Nearly every slot starts with exactly this sequence; folding it keeps
 *      the slots one-screen and the error mapping in one place. The traverse
 *      check is what makes a 0770 group directory actually private: without
 *      it a world-readable file INSIDE the directory would still be reachable
 *      by non-members (mode bits are only checked on the entry itself).
 *
 * HOW: pblock_ident_check_parent(X_OK) — immediate parent only, matching the
 *      documented no-ancestor-walk simplification — then catalog lookup
 *      (rc 1 → ENOENT), then pblock_ident_access. Traverse denial reports
 *      EACCES before the entry's existence is consulted, like the kernel.
 */
ngx_int_t
pblock_ident_check(pblock_state_t *st, const char *path,
    const pblock_ids_t *ids, int want, pblock_meta *meta_out)
{
    pblock_meta meta;
    int         rc;

    if (!ids->service
        && pblock_ident_check_parent(st, path, ids, X_OK, NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = pblock_catalog_lookup(st->cat, path, &meta);
    if (rc < 0) {
        return NGX_ERROR;
    }
    if (rc == 1) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    if (meta_out != NULL) {
        *meta_out = meta;
    }
    return pblock_ident_access(&meta, ids, want);
}

/* ---- parent-directory gate -------------------------------------------------
 *
 * WHAT: Demand `want` (normally W_OK) on `path`'s immediate parent directory;
 *       fills *parent_out (optional, for the sticky gate). NGX_OK, or
 *       NGX_ERROR with errno (ENOENT/ENOTDIR from the lookup, EACCES denied).
 *
 * WHY: Create/remove/rename authority lives on the containing directory, not
 *      the entry (POSIX). Only the IMMEDIATE parent is consulted — no
 *      ancestor X-bit walk — a documented simplification: exports present a
 *      flat authority model where ancestor traversal is the VFS/export's
 *      concern, not per-op.
 *
 * HOW: A top-level entry's parent is the root, which usually has no catalog
 *      row: synthesize a service-owned, world-writable, STICKY directory
 *      (mode 01777, like /tmp) so multi-user exports work out of the box —
 *      anyone may create top-level entries, only owners may remove them.
 *      Operators wanting stricter top-level control mkdir real VO
 *      directories with real modes. Deeper paths use the real parent row
 *      (pblock_catalog_parent_lookup).
 */
ngx_int_t
pblock_ident_check_parent(pblock_state_t *st, const char *path,
    const pblock_ids_t *ids, int want, pblock_meta *parent_out)
{
    pblock_meta parent;
    int         rc;

    if (path == NULL || path[0] != '/' || strchr(path + 1, '/') == NULL) {
        /* parent is the root */
        rc = pblock_catalog_lookup(st->cat, "/", &parent);
        if (rc < 0) {
            return NGX_ERROR;
        }
        if (rc == 1) {
            memset(&parent, 0, sizeof(parent));
            parent.is_dir = 1;
            parent.mode   = S_IFDIR | S_ISVTX | 0777;
        }
    } else if (pblock_catalog_parent_lookup(st->cat, path, &parent) != 0) {
        return NGX_ERROR;
    }

    if (parent_out != NULL) {
        *parent_out = parent;
    }
    return pblock_ident_access(&parent, ids, want);
}

/* ---- sticky-bit delete gate -------------------------------------------------
 *
 * WHAT: In a sticky (S_ISVTX) directory, only the entry's owner or the
 *       directory's owner may remove/rename the entry even with write
 *       permission on the directory. NGX_OK, or NGX_ERROR with errno EPERM.
 *
 * WHY: The synthetic root is sticky-world-writable (/tmp semantics): without
 *      this gate any authenticated user could delete any other user's
 *      top-level files. Real sticky directories created by operators get the
 *      same protection.
 *
 * HOW: Exactly the kernel's rule, minus the no-CAP_FOWNER cases pblock does
 *      not model. Service identities pass.
 */
ngx_int_t
pblock_ident_sticky_gate(const pblock_meta *parent, const pblock_meta *entry,
    const pblock_ids_t *ids)
{
    if (ids->service || (parent->mode & S_ISVTX) == 0
        || entry->uid == ids->uid || parent->uid == ids->uid)
    {
        return NGX_OK;
    }
    errno = EPERM;
    return NGX_ERROR;
}

#endif /* BRIX_HAVE_SQLITE */
