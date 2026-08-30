/*
 * sd_cache_forward.c — namespace / xattr / dir / staged-write forwarders.
 *
 * WHAT: The read-cache decorator's delegating vtable slots — every write /
 *       namespace / xattr / directory / staged-write op forwards straight to the
 *       wrapped source (a write also invalidates the cached copy). The one
 *       non-trivial slot is sd_cache_stat, which answers from a COMPLETE cinfo
 *       to keep a warm-object stat off the source.
 *
 * WHY:  Split from sd_cache.c (phase-79) to keep every cache file under the
 *       ~500-line, one-concept-per-file cap. These forwarders are the "cache is
 *       transport-transparent above the seam" half of the driver — reviewable
 *       apart from the interposed read-open decision tree and the fill / slice
 *       machinery. The read cache only interposes READ-open; everything here is
 *       pass-through-plus-evict.
 *
 * HOW:  Each slot reaches the source instance through SD_CACHE_SRC / the state's
 *       ->source (sd_cache_internal.h) and dispatches through the source
 *       driver's matching slot, returning NGX_ERROR / ENOTSUP when the source
 *       lacks it. Every slot that mutates the object the store holds a copy of —
 *       unlink, rename (both keys), truncate_path, server_copy (the DESTINATION),
 *       setattr, setxattr, removexattr, staged-open — additionally
 *       brix_cstore_evict the affected key(s) on success, and only on success.
 *       All slots are non-static — the driver vtable in
 *       sd_cache.c wires them by name through sd_cache_internal.h. ZERO
 *       behaviour change from the pre-split file.
 */
#include "sd_cache.h"
#include "sd_cache_internal.h"    /* sd_cache_inst_state + SD_CACHE_ST/SRC */
#include "sd_cache_policy.h"      /* admission + repo-metrics (split out) */
#include "protocols/cvmfs/classify.h"   /* phase-68 manifest-TTL stamping */
#include "observability/metrics/metrics.h"        /* phase-68 T16 counters */
#include "observability/metrics/metrics_macros.h"
#include "fs/cache/cstore.h"
#include "fs/backend/http/sd_http.h"    /* per-upstream fill attribution     */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


/* ---- namespace / xattr / dir forwarders (delegate to the source) ----------
 *
 * Every op below exists in a PLAIN and a CRED-scoped form, and both are one
 * `_common` body taking a (possibly NULL) credential.
 *
 * WHY the cred form has to exist at all: brix_sd_<op>_maybe_cred decides
 * cred-slot vs plain-slot vs deny-refusal by looking at THE INSTANCE IT IS
 * CALLED ON. A decorator publishing `.mkdir` and no `.mkdir_cred` therefore
 * reads, one tier up, exactly like a driver with no per-user support — whatever
 * the source can actually do. The VFS namespace sites work around that today by
 * unwrapping to the LEAF (brix_vfs_ns_leaf) and dispatching there, which costs
 * them the decorator itself: the cache's stat-from-cinfo shortcut, and — the
 * part that bites — its automatic eviction, which each bypassing site then has
 * to re-add by hand as a brix_sd_cache_evict call. Restoring the twins removes
 * the reason for the bypass, and makes a decorator that is dispatched on
 * DIRECTLY (any caller that is not the ns gate) carry the credential correctly.
 *
 * HOW: each cred slot re-dispatches through brix_sd_<op>_maybe_cred against the
 * SOURCE, so the source's own cred/plain/deny decision is the one that governs
 * — the decorator adds no policy, it only stops erasing the credential. The
 * plain slots pass cred=NULL and land on the identical path they always took.
 * ENOTSUP (not the forwarder's ENOSYS) is preserved for the xattr ops, whose
 * callers read it as "this filesystem has no extended attributes". */

static ngx_int_t
sd_cache_stat_common(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s  = SD_CACHE_SRC(inst);
    brix_cache_cinfo_t  ci;

    /* A COMPLETE cached object answers stat from its cinfo — the same
     * authoritative-hit doctrine as open() (section 6.4), and it keeps a stat of
     * a warm object off the source (a remote source would otherwise take a
     * blocking wire round-trip on the caller's thread — the event loop for the
     * kXR_open pre-flight probe). A miss/partial falls through to the source.
     * A credential does not change that: sd_cache_open_common serves a complete
     * hit from the store under a cred too, so diverging here would make stat
     * stricter than the open it is a pre-flight for. */
    if (brix_cstore_cinfo_load(&st->cstore, path, &ci) == NGX_OK
        && (ci.flags & BRIX_CINFO_F_COMPLETE))
    {
        ngx_memzero(out, sizeof(*out));
        out->size   = (off_t) ci.size;
        out->mtime  = (time_t) ci.mtime;
        out->ctime  = (time_t) ci.mtime;
        out->mode   = (mode_t) S_IFREG
                    | (mode_t) ((ci.mode != 0) ? (ci.mode & 0777) : 0644);
        out->is_reg = 1;
        return NGX_OK;
    }

    return brix_sd_stat_maybe_cred(s, path, out, cred);
}

ngx_int_t
sd_cache_stat(brix_sd_instance_t *inst, const char *path, brix_sd_stat_t *out)
{
    return sd_cache_stat_common(inst, path, out, NULL);
}

ngx_int_t
sd_cache_stat_cred(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out, const brix_sd_cred_t *cred)
{
    return sd_cache_stat_common(inst, path, out, cred);
}

static ngx_int_t
sd_cache_unlink_common(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    ngx_int_t             rc;

    rc = brix_sd_unlink_maybe_cred(st->source, path, is_dir, cred);
    if (rc == NGX_OK) {
        (void) brix_cstore_evict(&st->cstore, path);
    }
    return rc;
}

ngx_int_t
sd_cache_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    return sd_cache_unlink_common(inst, path, is_dir, NULL);
}

ngx_int_t
sd_cache_unlink_cred(brix_sd_instance_t *inst, const char *path, int is_dir,
    const brix_sd_cred_t *cred)
{
    return sd_cache_unlink_common(inst, path, is_dir, cred);
}

ngx_int_t
sd_cache_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    return brix_sd_mkdir_maybe_cred(SD_CACHE_SRC(inst), path, mode, NULL);
}

ngx_int_t
sd_cache_mkdir_cred(brix_sd_instance_t *inst, const char *path, mode_t mode,
    const brix_sd_cred_t *cred)
{
    return brix_sd_mkdir_maybe_cred(SD_CACHE_SRC(inst), path, mode, cred);
}

static ngx_int_t
sd_cache_rename_common(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace, const brix_sd_cred_t *cred)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    ngx_int_t             rc;

    rc = brix_sd_rename_maybe_cred(st->source, src, dst, noreplace, cred);
    if (rc == NGX_OK) {
        (void) brix_cstore_evict(&st->cstore, src);
        (void) brix_cstore_evict(&st->cstore, dst);
    }
    return rc;
}

ngx_int_t
sd_cache_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    return sd_cache_rename_common(inst, src, dst, noreplace, NULL);
}

ngx_int_t
sd_cache_rename_cred(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace, const brix_sd_cred_t *cred)
{
    return sd_cache_rename_common(inst, src, dst, noreplace, cred);
}

/* A path-native truncate the SOURCE performs: the store's copy is now the wrong
 * length, so it has to go the same way unlink's and rename's do. The forwarder is
 * ENOTSUP — not the shared relay's ENOSYS — when the source has neither slot,
 * because brix_vfs_truncate_path reads "this backend cannot" as "take the
 * open+ftruncate fallback", and it must reach that decision without the decorator
 * inventing a resize the origin never saw. */
static ngx_int_t
sd_cache_truncate_path_common(brix_sd_instance_t *inst, const char *path,
    off_t len, const brix_sd_cred_t *cred)
{
    sd_cache_inst_state *st = SD_CACHE_ST(inst);
    ngx_int_t            rc;

    if (st->source->driver->truncate_path == NULL
        && st->source->driver->truncate_path_cred == NULL)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    rc = brix_sd_truncate_path_maybe_cred(st->source, path, len, cred);
    if (rc == NGX_OK) {
        (void) brix_cstore_evict(&st->cstore, path);
    }
    return rc;
}

ngx_int_t
sd_cache_truncate_path(brix_sd_instance_t *inst, const char *path, off_t len)
{
    return sd_cache_truncate_path_common(inst, path, len, NULL);
}

ngx_int_t
sd_cache_truncate_path_cred(brix_sd_instance_t *inst, const char *path,
    off_t len, const brix_sd_cred_t *cred)
{
    return sd_cache_truncate_path_common(inst, path, len, cred);
}

/* The DESTINATION is what changed — a cached copy of it predates the copy and
 * would keep being served. The source object is untouched, so it stays. */
static ngx_int_t
sd_cache_server_copy_common(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    sd_cache_inst_state *st = SD_CACHE_ST(inst);
    ngx_int_t            rc;

    rc = brix_sd_server_copy_maybe_cred(st->source, src, dst, bytes_out, cred);
    if (rc == NGX_OK) {
        (void) brix_cstore_evict(&st->cstore, dst);
    }
    return rc;
}

ngx_int_t
sd_cache_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    return sd_cache_server_copy_common(inst, src, dst, bytes_out, NULL);
}

ngx_int_t
sd_cache_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    return sd_cache_server_copy_common(inst, src, dst, bytes_out, cred);
}

/* The cinfo beside the cached copy carries the object's mode/owner/times, so a
 * setattr that only reached the source leaves the served stat describing the old
 * permissions — a stale mode is an access-control answer, not a cosmetic one. */
static ngx_int_t
sd_cache_setattr_common(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    sd_cache_inst_state *st = SD_CACHE_ST(inst);
    ngx_int_t            rc;

    rc = brix_sd_setattr_maybe_cred(st->source, path, attr, cred);
    if (rc == NGX_OK) {
        (void) brix_cstore_evict(&st->cstore, path);
    }
    return rc;
}

ngx_int_t
sd_cache_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    return sd_cache_setattr_common(inst, path, attr, NULL);
}

ngx_int_t
sd_cache_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    return sd_cache_setattr_common(inst, path, attr, cred);
}

/* Capacity belongs to the wrapped source (the cstore is a private spool), so
 * statvfs/Qspace/QFSinfo/SRR report the source's numbers, not the spool's. */
ngx_int_t
sd_cache_space(brix_sd_instance_t *inst, brix_sd_space_t *out)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->space == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return s->driver->space(s, out);
}

/* dir->inst is the SOURCE instance either way, so readdir/closedir below keep
 * dispatching through it and need no cred-scoped form of their own. */
brix_sd_dir_t *
sd_cache_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    return brix_sd_opendir_maybe_cred(SD_CACHE_SRC(inst), path, err_out, NULL);
}

brix_sd_dir_t *
sd_cache_opendir_cred(brix_sd_instance_t *inst, const char *path, int *err_out,
    const brix_sd_cred_t *cred)
{
    return brix_sd_opendir_maybe_cred(SD_CACHE_SRC(inst), path, err_out, cred);
}

ngx_int_t
sd_cache_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    /* The dir handle carries its owning (source) instance; dispatch through it. */
    return d->inst->driver->readdir ? d->inst->driver->readdir(d, out)
                                    : NGX_ERROR;
}

ngx_int_t
sd_cache_closedir(brix_sd_dir_t *d)
{
    return d->inst->driver->closedir ? d->inst->driver->closedir(d) : NGX_ERROR;
}

/* Both xattr slot pairs of the source are absent → the source has no extended
 * attributes at all, which callers read off ENOTSUP; without this the shared
 * forwarder would report the less specific ENOSYS for an op it merely lacks. */
static ngx_int_t
sd_cache_src_no_xattr(const brix_sd_instance_t *s, int write_side)
{
    if (write_side) {
        return s->driver->setxattr == NULL && s->driver->setxattr_cred == NULL
            && s->driver->removexattr == NULL
            && s->driver->removexattr_cred == NULL;
    }
    return s->driver->getxattr == NULL && s->driver->getxattr_cred == NULL
        && s->driver->listxattr == NULL && s->driver->listxattr_cred == NULL;
}

ssize_t
sd_cache_getxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    void *buf, size_t cap)
{
    return sd_cache_getxattr_cred(inst, path, name, buf, cap, NULL);
}

ssize_t
sd_cache_getxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap, const brix_sd_cred_t *cred)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (sd_cache_src_no_xattr(s, 0)) {
        errno = ENOTSUP;
        return -1;
    }
    return brix_sd_getxattr_maybe_cred(s, path, name, buf, cap, cred);
}

ssize_t
sd_cache_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap)
{
    return sd_cache_listxattr_cred(inst, path, buf, cap, NULL);
}

ssize_t
sd_cache_listxattr_cred(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap, const brix_sd_cred_t *cred)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (sd_cache_src_no_xattr(s, 0)) {
        errno = ENOTSUP;
        return -1;
    }
    return brix_sd_listxattr_maybe_cred(s, path, buf, cap, cred);
}

ngx_int_t
sd_cache_setxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    const void *val, size_t len, int flags)
{
    return sd_cache_setxattr_cred(inst, path, name, val, len, flags, NULL);
}

ngx_int_t
sd_cache_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);
    ngx_int_t           rc;

    if (sd_cache_src_no_xattr(s, 1)) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    rc = brix_sd_setxattr_maybe_cred(s, path, name, val, len, flags, cred);
    if (rc == NGX_OK) {
        /* The store copy carries the object's attributes too — including the
         * digest a fill seeds as user.XrdCks.<alg> — so a mutation on the origin
         * leaves them stale exactly the way a data mutation would. */
        (void) brix_cstore_evict(&SD_CACHE_ST(inst)->cstore, path);
    }
    return rc;
}

ngx_int_t
sd_cache_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    return sd_cache_removexattr_cred(inst, path, name, NULL);
}

ngx_int_t
sd_cache_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);
    ngx_int_t           rc;

    if (sd_cache_src_no_xattr(s, 1)) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    rc = brix_sd_removexattr_maybe_cred(s, path, name, cred);
    if (rc == NGX_OK) {
        (void) brix_cstore_evict(&SD_CACHE_ST(inst)->cstore, path);
    }
    return rc;
}

/* ---- staged write forwarders (the write path runs through the source) ----- */

brix_sd_staged_t *
sd_cache_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s = st->source;

    if (s->driver->staged_open == NULL) {
        if (err_out != NULL) {
            *err_out = ENOSYS;
        }
        return NULL;
    }
    /* A staged publish replaces the object; drop any cached copy now. */
    (void) brix_cstore_evict(&st->cstore, final_path);
    return s->driver->staged_open(s, final_path, mode, err_out);
}

/* Credential-scoped staged_open: forwards the per-user cred into the source's
 * staged_open_cred slot when the source driver implements it.
 *
 * WHAT: Evicts any cached copy (a staged write is a replacement) and delegates
 *       to the source via brix_sd_staged_open_maybe_cred so the backend driver
 *       can authenticate as the requesting user for the staged upload.
 *
 * WHY:  Without this slot the cache decorator drops the credential on the floor
 *       when a caller uses brix_sd_staged_open_maybe_cred against it.
 *
 * HOW:  Evict → brix_sd_staged_open_maybe_cred (cred forwarded to source). */
brix_sd_staged_t *
sd_cache_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err_out)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s = st->source;

    if (s->driver->staged_open == NULL && s->driver->staged_open_cred == NULL) {
        if (err_out != NULL) {
            *err_out = ENOSYS;
        }
        return NULL;
    }
    (void) brix_cstore_evict(&st->cstore, final_path);
    return brix_sd_staged_open_maybe_cred(s, final_path, mode, cred, err_out);
}

ssize_t
sd_cache_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    return st->inst->driver->staged_write
         ? st->inst->driver->staged_write(st, buf, len, off) : -1;
}

ngx_int_t
sd_cache_staged_commit(brix_sd_staged_t *st, int noreplace)
{
    return st->inst->driver->staged_commit
         ? st->inst->driver->staged_commit(st, noreplace) : NGX_ERROR;
}

void
sd_cache_staged_abort(brix_sd_staged_t *st)
{
    if (st->inst->driver->staged_abort != NULL) {
        st->inst->driver->staged_abort(st);
    }
}
