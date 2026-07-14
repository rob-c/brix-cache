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
 *       lacks it. unlink/rename/staged-open additionally brix_cstore_evict the
 *       affected key(s). All slots are non-static — the driver vtable in
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


/* ---- namespace / xattr / dir forwarders (delegate to the source) ---------- */

ngx_int_t
sd_cache_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s  = SD_CACHE_SRC(inst);
    brix_cache_cinfo_t  ci;

    /* A COMPLETE cached object answers stat from its cinfo — the same
     * authoritative-hit doctrine as open() (section 6.4), and it keeps a stat of
     * a warm object off the source (a remote source would otherwise take a
     * blocking wire round-trip on the caller's thread — the event loop for the
     * kXR_open pre-flight probe). A miss/partial falls through to the source. */
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

    return s->driver->stat ? s->driver->stat(s, path, out) : NGX_ERROR;
}

ngx_int_t
sd_cache_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s = st->source;
    ngx_int_t             rc;

    rc = s->driver->unlink ? s->driver->unlink(s, path, is_dir) : NGX_ERROR;
    if (rc == NGX_OK) {
        (void) brix_cstore_evict(&st->cstore, path);
    }
    return rc;
}

ngx_int_t
sd_cache_mkdir(brix_sd_instance_t *inst, const char *path, mode_t mode)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);
    return s->driver->mkdir ? s->driver->mkdir(s, path, mode) : NGX_ERROR;
}

ngx_int_t
sd_cache_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    sd_cache_inst_state  *st = SD_CACHE_ST(inst);
    brix_sd_instance_t *s = st->source;
    ngx_int_t             rc;

    rc = s->driver->rename ? s->driver->rename(s, src, dst, noreplace)
                           : NGX_ERROR;
    if (rc == NGX_OK) {
        (void) brix_cstore_evict(&st->cstore, src);
        (void) brix_cstore_evict(&st->cstore, dst);
    }
    return rc;
}

ngx_int_t
sd_cache_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);
    return s->driver->server_copy ? s->driver->server_copy(s, src, dst, bytes_out)
                                  : NGX_ERROR;
}

ngx_int_t
sd_cache_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);
    return s->driver->setattr ? s->driver->setattr(s, path, attr) : NGX_OK;
}

brix_sd_dir_t *
sd_cache_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->opendir == NULL) {
        if (err_out != NULL) {
            *err_out = ENOSYS;
        }
        return NULL;
    }
    return s->driver->opendir(s, path, err_out);    /* dir->inst = the source */
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

ssize_t
sd_cache_getxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    void *buf, size_t cap)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->getxattr == NULL) {
        errno = ENOTSUP;
        return -1;
    }
    return s->driver->getxattr(s, path, name, buf, cap);
}

ssize_t
sd_cache_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->listxattr == NULL) {
        errno = ENOTSUP;
        return -1;
    }
    return s->driver->listxattr(s, path, buf, cap);
}

ngx_int_t
sd_cache_setxattr(brix_sd_instance_t *inst, const char *path, const char *name,
    const void *val, size_t len, int flags)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->setxattr == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return s->driver->setxattr(s, path, name, val, len, flags);
}

ngx_int_t
sd_cache_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    brix_sd_instance_t *s = SD_CACHE_SRC(inst);

    if (s->driver->removexattr == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    return s->driver->removexattr(s, path, name);
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
