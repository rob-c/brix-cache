/*
 * sd_posix_staged.c — the POSIX Storage Driver's staged-write family.
 *
 * WHAT: The temp + atomic-rename staged upload (staged_open/_write/_commit/
 *       _abort/_path), split VERBATIM out of sd_posix_ns.c when the phase-107
 *       C6 typed publish precondition grew the commit past that file's size
 *       cap. The driver descriptor stays in sd_posix.c.
 *
 * WHY:  Same reason as the sd_posix.c → sd_posix_ns.c cut: keep every unit
 *       under the file-size cap with zero behaviour change. The commit is the
 *       one body with new behaviour (C6): ABSENT publishes atomically via
 *       RENAME_NOREPLACE; MATCH_* is an honest advisory stat-compare that
 *       reports atomic = 0 (a posix rename cannot fold a compare into itself).
 *
 * HOW:  Delegates to the shared brix_staged_* compat primitives exactly as
 *       before; the precondition evaluation reuses the one shared evaluator
 *       (brix_sd_precond_eval_stat, sd_batch_types.h) so the etag grammar
 *       never forks from the VFS compat arm.
 */

#include "fs/backend/sd.h"

#ifndef XRDPROTO_NO_NGX
#include "fs/vfs/vfs_internal.h"          /* pwrite_full */
#include "core/compat/staged_file.h"
#include "fs/path/beneath.h"              /* NOREPLACE degradation latch */
#include "fs/path/path.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd_posix_internal.h"

#ifndef XRDPROTO_NO_NGX

/* staged write (temp + atomic rename) */

/* Driver-private staged state: the compat primitive + final path. */
typedef struct {
    brix_staged_file_t staged;
    char                 final_path[PATH_MAX];
} sd_posix_staged_t;

/* Create the target's parent-directory chain inside the store root before the
 * O_EXCL temp is opened.  A staged upload into a fresh subdirectory (e.g. a
 * write-stage tier keyed on "/sub/file" whose store is a dedicated dir that
 * has never seen "/sub") would otherwise ENOENT: brix_staged_open opens the
 * temp adjacent to abspath and does NOT create parents.  This mirrors the
 * O_MKDIRPATH mkpath a direct write runs, so the store side of a subdirectory
 * commit succeeds (the source-side origin creates its own chain via mkpath). */
static void
sd_posix_staged_mkparents(brix_sd_instance_t *inst, sd_posix_state_t *st,
    const char *abspath)
{
    char    parent[PATH_MAX];
    char   *slash;
    size_t  alen = ngx_strlen(abspath);

    if (alen >= sizeof(parent)) {
        return;
    }
    ngx_memcpy(parent, abspath, alen + 1);
    slash = strrchr(parent, '/');
    if (slash != NULL && slash > parent) {
        *slash = '\0';
        (void) brix_mkdir_recursive_confined_canon(inst->log,
            st->root_canon, parent, 0755, NULL);
    }
}

/* Phase-107 C5 admission: a declared final size preallocates the temp up
 * front, so a store that cannot hold the object refuses the OPEN
 * (ENOSPC/EDQUOT), not the commit hours of streaming later.  Anything else
 * (EOPNOTSUPP on an odd filesystem) is advisory per the seam contract - the
 * open proceeds.  Returns 0 to admit, or the errno that must fail the open. */
static int
sd_posix_staged_admit(brix_sd_instance_t *inst, sd_posix_staged_t *ps,
    off_t declared_size)
{
    brix_sd_obj_t  shell;

    if (declared_size <= 0) {
        return 0;
    }
    ngx_memzero(&shell, sizeof(shell));
    shell.driver = inst->driver;
    shell.inst   = inst;
    shell.fd     = ps->staged.fd;
    if (sd_posix_reserve(&shell, declared_size) != NGX_OK
        && (errno == ENOSPC || errno == EDQUOT))
    {
        return errno;
    }
    return 0;
}

brix_sd_staged_t *
sd_posix_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, off_t declared_size, int *err_out)
{
    sd_posix_state_t   *st = inst->state;
    brix_sd_staged_t *handle;
    sd_posix_staged_t  *ps;
    char                abspath[PATH_MAX];

    /* Allocate the staged handle on the heap (ngx_calloc), NOT from inst->pool.
     * staged_open runs in a cache-fill thread-pool thread (brix_cache_fill_*),
     * but inst->pool is the shared, thread-UNSAFE backend pool the main thread
     * also allocates from (sd_posix_open/opendir). Concurrent fills racing on
     * inst->pool corrupt its `last` pointer -> a bad allocation whose memzero
     * SIGSEGVs. The handle + ps are freed explicitly in staged_commit /
     * staged_abort (the terminal ops — the driver vtable has no close). */
    handle = ngx_calloc(sizeof(*handle), inst->log);
    ps = ngx_calloc(sizeof(*ps), inst->log);
    if (handle == NULL || ps == NULL) {
        if (handle != NULL) { ngx_free(handle); }
        if (ps != NULL) { ngx_free(ps); }
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    /* The vtable contract is a root-RELATIVE key (leading slash), matching
     * sd_posix_open and the non-POSIX drivers' staged_open. brix_staged_open
     * (and _commit/_abort) work in ABSOLUTE paths under root_canon, so build the
     * absolute final path here and store it for commit/abort. */
    if ((size_t) snprintf(abspath, sizeof(abspath), "%s%s",
                          st->root_canon, final_path) >= sizeof(abspath))
    {
        ngx_free(handle);
        ngx_free(ps);
        if (err_out != NULL) { *err_out = ENAMETOOLONG; }
        return NULL;
    }

    sd_posix_staged_mkparents(inst, st, abspath);

    {
        brix_staged_open_req_t  oreq = {
            .root_canon = st->root_canon,
            .final_path = abspath,
            .open_flags = O_WRONLY | O_CREAT | O_EXCL,
            .mode       = mode,
            .attempts   = 8,
        };
        if (brix_staged_open(inst->log, &oreq, &ps->staged) != NGX_OK) {
            ngx_free(handle);
            ngx_free(ps);
            if (err_out != NULL) { *err_out = errno; }
            return NULL;
        }
    }

    {
        int err = sd_posix_staged_admit(inst, ps, declared_size);

        if (err != 0) {
            brix_staged_abort(inst->log, st->root_canon, &ps->staged, 1);
            ngx_free(handle);
            ngx_free(ps);
            if (err_out != NULL) { *err_out = err; }
            errno = err;
            return NULL;
        }
    }

    ngx_cpystrn((u_char *) ps->final_path, (u_char *) abspath,
                sizeof(ps->final_path));
    handle->inst = inst;
    handle->state = ps;
    return handle;
}

ssize_t
sd_posix_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    sd_posix_staged_t *ps = st->state;

    if (brix_vfs_pwrite_full(ps->staged.fd, buf, len, off) != NGX_OK) {
        return -1;
    }
    return (ssize_t) len;
}

ngx_int_t
sd_posix_staged_commit(brix_sd_staged_t *st, brix_sd_precond_t *pre)
{
    sd_posix_staged_t *ps = st->state;
    sd_posix_state_t  *inst_st = st->inst->state;
    ngx_int_t          rc;

    /* MATCH_* (phase-107 C6): advisory stat-compare against the final path
     * before a plain rename.  A posix rename cannot fold the compare into
     * itself, so this is check-then-publish; pre->atomic stays 0 and the
     * protocol layer must not claim RFC 7232 semantics for it (§3.5 — honest
     * advisory over an emulation that lies).  Evaluated BEFORE the rename so
     * a refused precondition leaves the target untouched (the temp is then
     * released by the caller's staged_abort). */
    if (pre != NULL && pre->kind != BRIX_SD_PRECOND_NONE
        && pre->kind != BRIX_SD_PRECOND_ABSENT)
    {
        struct stat sb;

        if (lstat(ps->final_path, &sb) != 0) {
            errno = ECANCELED;         /* MATCH_* against a missing target
                                        * is a failed match, not ENOENT */
            return NGX_ERROR;
        }
        if (brix_sd_precond_eval_stat(pre, sb.st_size, sb.st_mtime) != 0) {
            return NGX_ERROR;          /* errno = ECANCELED / ENOTSUP */
        }
    }

    rc = brix_sd_precond_absent(pre)
        ? brix_staged_commit_excl(st->inst->log, inst_st->root_canon,
                                    &ps->staged, ps->final_path)
        : brix_staged_commit(st->inst->log, inst_st->root_canon,
                               &ps->staged, ps->final_path);
    /* Ownership contract (brix_vfs_staged_commit / sd_remote_staged_commit):
     * free the heap-allocated handle ONLY on success. On failure the handle
     * stays valid and the caller (stage_engine / brix_vfs) invokes
     * staged_abort to release it — freeing here would double-free. */
    if (rc != NGX_OK) {
        if (brix_sd_precond_absent(pre) && errno == EEXIST) {
            /* RENAME_NOREPLACE said no — a storage-decided (atomic) refusal,
             * unless this host ever degraded (beneath.c latch); the C6
             * advisory metric keys on this verdict after a failed commit. */
            pre->atomic = !brix_renameat_noreplace_degraded();
        }
        return rc;
    }
    if (brix_sd_precond_absent(pre)) {
        /* RENAME_NOREPLACE decided at the filesystem — unless this host has
         * ever degraded to the check-then-act fallback (beneath.c latch). */
        pre->atomic = !brix_renameat_noreplace_degraded();
    }
    ngx_free(ps);
    ngx_free(st);
    return NGX_OK;
}

void
sd_posix_staged_abort(brix_sd_staged_t *st)
{
    sd_posix_staged_t *ps = st->state;
    sd_posix_state_t  *inst_st = st->inst->state;

    brix_staged_abort(st->inst->log, inst_st->root_canon, &ps->staged, 1);
    /* Terminal op — release the heap-allocated handle (see staged_open). */
    ngx_free(ps);
    ngx_free(st);
}

/* Physical staged-temp path — lets the cache tier digest-verify a fill (and
 * quarantine a mismatch) before commit (phase-68). */
const char *
sd_posix_staged_path(const brix_sd_staged_t *st)
{
    const sd_posix_staged_t *ps = st->state;

    return (ps != NULL && ps->staged.tmp_path[0] != '\0') ? ps->staged.tmp_path
                                                          : NULL;
}

#endif /* !XRDPROTO_NO_NGX */
