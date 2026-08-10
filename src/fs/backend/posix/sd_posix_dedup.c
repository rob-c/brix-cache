/*
 * sd_posix_dedup.c — the POSIX realisation of the commit-time dedup slots
 * (phase-88 W1: the G13 hardlink farm moved below the SD seam).
 *
 * WHAT: Implements sd_posix_dedup_publish / sd_posix_dedup_gc: bind a
 *       content-verified store object and its canonical content-derived alias
 *       (`canon`, e.g. "/.gcas/<2hex>/<hex><sfx>") onto ONE inode via link(2),
 *       and reap the canonical name once it is the last remaining link.
 *
 * WHY:  These mechanics lived above the seam in src/fs/cache/gcas.c as raw
 *       syscalls on the store's local root. Expressing them as driver slots
 *       (a) moves the raw filesystem work where invariant 12 wants it and
 *       (b) makes the caller (gcas.c) storage-neutral, so a refcounting
 *       backend (pblock) can serve brix_cache_global_cas with its own slot.
 *
 * HOW:  publish: first appearance registers the canonical via link(2); later
 *       byte-identical publishes ADOPT the canonical via link-to-temp +
 *       rename(2) (atomic — open readers keep their inode). The filesystem's
 *       st_nlink IS the combined refcount, so there is no bookkeeping to
 *       corrupt; every path is best-effort and any failure leaves plain,
 *       correct per-name copies. gc: unlink the canonical at st_nlink <= 1.
 *       Both run on cache-fill worker threads: no pool access, inst->log only.
 */

#include "fs/backend/sd.h"

#ifndef XRDPROTO_NO_NGX   /* module-only: the ngx-free client never dedups a store */

#include "sd_posix_internal.h"
#include "fs/path/path.h"        /* brix_mkdir_recursive */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- posix_dedup_abs — absolute store path for a store-relative name ----
 *
 * WHAT: Joins the instance's root_canon with `rel` (always leading '/') into
 *       out[cap]. Returns 0, or -1 on overflow / missing root.
 *
 * WHY:  The dedup names travel store-relative (the caller is storage-neutral);
 *       only the POSIX driver knows the physical directory they land in.
 *
 * HOW:  1. Trim trailing '/' runs off root_canon.  2. snprintf-join and
 *       bounds-check.
 */
static int
posix_dedup_abs(const sd_posix_state_t *st, const char *rel, char *out,
    size_t cap)
{
    size_t rlen;
    int    n;

    if (st == NULL || st->root_canon == NULL) {
        return -1;
    }
    rlen = strlen(st->root_canon);
    while (rlen > 0 && st->root_canon[rlen - 1] == '/') {
        rlen--;
    }
    n = snprintf(out, cap, "%.*s%s", (int) rlen, st->root_canon, rel);
    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* ---- posix_dedup_ensure_parent — mkdir -p the parent of an absolute path ----
 *
 * WHAT: Creates the directory chain above `path` (0700). Returns 0 when the
 *       parent exists or was created, -1 on error (errno set).
 *
 * WHY:  The first canonical under a fresh "/.gcas/<2hex>/" prefix needs its
 *       directory; 0700 matches the svc-owned, never-client-listable cache
 *       tree convention.
 *
 * HOW:  1. Copy + bounds-check.  2. Truncate at the last '/'.  3. Delegate to
 *       brix_mkdir_recursive.
 */
static int
posix_dedup_ensure_parent(const char *path)
{
    char  parent[PATH_MAX];
    char *slash;
    int   n;

    n = snprintf(parent, sizeof(parent), "%s", path);
    if (n < 0 || (size_t) n >= sizeof(parent)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        return 0;
    }
    *slash = '\0';
    return brix_mkdir_recursive(parent, 0700);
}

/* ---- posix_dedup_adopt — swap a published name onto an EXISTING canonical ----
 *
 * WHAT: Links the canonical's inode to a ".gclnk" temp next to `obj` and
 *       renames it over `obj` (atomic; open readers keep their old inode).
 *       Returns 0 when publish is finished (bound, skipped, or terminally
 *       failed), -1 when the canonical vanished underneath us (caller retries).
 *
 * WHY:  Adopting — rather than re-linking the fresh copy — is what collapses a
 *       later byte-identical fill onto the shared inode without ever exposing
 *       a missing name.
 *
 * HOW:  1. Same-inode short-circuit.  2. Size-mismatch guard (hash collision /
 *       damaged canonical: never collapse mismatched bytes).  3. link canonical
 *       -> temp (failure = canonical evicted; retry).  4. rename temp -> obj.
 */
static int
posix_dedup_adopt(brix_sd_instance_t *inst, const char *path,
    const char *canon, const char *obj, const struct stat *cst,
    const struct stat *ost)
{
    char tmp[PATH_MAX];
    int  n;

    if (cst->st_ino == ost->st_ino) {
        return 0;                           /* already bound */
    }

    if (cst->st_size != ost->st_size) {
        ngx_log_error(NGX_LOG_WARN, inst->log, 0,
            "gcas: canonical size mismatch for \"%s\" (%O vs %O) — "
            "dedup skipped", path,
            (off_t) cst->st_size, (off_t) ost->st_size);
        return 0;
    }

    n = snprintf(tmp, sizeof(tmp), "%s.gclnk", obj);
    if (n < 0 || (size_t) n >= sizeof(tmp)) {
        return 0;
    }
    unlink(tmp);
    if (link(canon, tmp) != 0) {
        return -1;                          /* canonical evicted underneath us */
    }
    if (rename(tmp, obj) != 0) {
        unlink(tmp);
        return 0;
    }

    ngx_log_error(NGX_LOG_INFO, inst->log, 0,
        "gcas: dedup \"%s\" onto canonical inode", path);
    return 0;
}

/* ---- sd_posix_dedup_publish — driver->dedup_publish for posix stores ----
 *
 * WHAT: Binds the (content-verified) object at `path` and the canonical alias
 *       `canon` to one inode. NGX_OK on every completed/benign path (the
 *       per-name copy always stays correct); NGX_ERROR/errno only on invalid
 *       arguments.
 *
 * WHY:  First appearance of a content hash registers the canonical; later
 *       byte-identical publishes adopt it, so N names for one content cost one
 *       inode. st_nlink carries the refcount — nothing to corrupt.
 *
 * HOW:  1. Resolve both absolute paths.  2. stat the object (gone = nothing to
 *       bind).  3. Two attempts: canonical present -> adopt (retry once when it
 *       is evicted mid-flight); absent -> mkdir -p + link it as the canonical
 *       (EEXIST = lost the register race — loop and adopt the winner).
 */
ngx_int_t
sd_posix_dedup_publish(brix_sd_instance_t *inst, const char *path,
    const char *canon)
{
    sd_posix_state_t *st = inst->state;
    int               attempt;
    char              cabs[PATH_MAX], oabs[PATH_MAX];
    struct stat       ost, cst;

    if (path == NULL || canon == NULL
        || posix_dedup_abs(st, canon, cabs, sizeof(cabs)) != 0
        || posix_dedup_abs(st, path, oabs, sizeof(oabs)) != 0)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (stat(oabs, &ost) != 0) {
        return NGX_OK;          /* committed object already gone — nothing to bind */
    }

    for (attempt = 0; attempt < 2; attempt++) {

        if (stat(cabs, &cst) == 0) {
            if (posix_dedup_adopt(inst, path, cabs, oabs, &cst, &ost) == 0) {
                return NGX_OK;
            }
            continue;           /* canonical evicted underneath us — retry */
        }

        if (posix_dedup_ensure_parent(cabs) != 0) {
            return NGX_OK;      /* best-effort: keep the plain per-name copy */
        }
        if (link(oabs, cabs) == 0) {
            ngx_log_error(NGX_LOG_INFO, inst->log, 0,
                "gcas: registered canonical for \"%s\"", path);
            return NGX_OK;
        }
        /* EEXIST: lost the race — loop once and adopt the winner. */
    }
    return NGX_OK;
}

/* ---- sd_posix_dedup_gc — driver->dedup_gc for posix stores ----
 *
 * WHAT: Unlinks the canonical alias `canon` once it is the last remaining name
 *       of its inode (st_nlink <= 1). NGX_OK always (best-effort; a canonical
 *       still shared, already gone, or unresolvable is a no-op).
 *
 * WHY:  After the last data name referencing a content was evicted, the
 *       canonical would otherwise pin the inode forever.
 *
 * HOW:  1. Resolve the absolute canonical path.  2. stat; more links = still
 *       referenced, keep.  3. unlink + INFO-log the reap.
 */
ngx_int_t
sd_posix_dedup_gc(brix_sd_instance_t *inst, const char *canon)
{
    sd_posix_state_t *st = inst->state;
    char              cabs[PATH_MAX];
    struct stat       cst;

    if (canon == NULL
        || posix_dedup_abs(st, canon, cabs, sizeof(cabs)) != 0)
    {
        return NGX_OK;
    }

    if (stat(cabs, &cst) != 0 || cst.st_nlink > 1) {
        return NGX_OK;          /* other names still hold the inode */
    }

    if (unlink(cabs) == 0) {
        ngx_log_error(NGX_LOG_INFO, inst->log, 0,
            "gcas: reaped canonical \"%s\" (last link)", canon);
    }
    return NGX_OK;
}

#endif /* !XRDPROTO_NO_NGX */
