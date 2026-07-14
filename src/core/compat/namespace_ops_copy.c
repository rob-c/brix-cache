/*
 * namespace_ops_copy.c — shared namespace service: single-file local copy path.
 *
 * WHAT: Implements the local file-copy orchestration (brix_ns_local_copy) and
 *       its pre-open validation, destination-open, and finalize helpers, plus the
 *       xattr-mirroring helpers (brix_ns_copy_fattrs / brix_xattr_copy_by_prefix).
 * WHY: Split out of namespace_ops.c (phase-79 file-size cap): the copy path is a
 *      self-contained concern — stat/overwrite policy, staged-vs-direct dst open,
 *      copy_file_range + commit + xattr mirror — that is larger than the
 *      delete/mkdir/rename core it sits beside. Keeping it here holds both files
 *      under the 500-line limit while leaving the confinement primitives it reuses
 *      (ns_rel/ns_set_err) single-sourced in the core.
 * HOW: These helpers operate on already-resolved paths; every filesystem touch is
 *      confined by the openat2 RESOLVE_BENEATH primitives (ns_rel opens the rootfd
 *      and strips the within-root tail; brix_open_beneath/brix_stat_beneath act
 *      through it). Protocol handlers are responsible for wire parsing, auth, and
 *      lock checks.
 */

#include "namespace_ops.h"
#include "namespace_ops_internal.h"   /* cross-file: ns_rel / ns_set_err (namespace_ops.c) */
#include "fs/path/path.h"
#include "fs/path/beneath.h"
#include "protocols/root/fattr/ngx_brix_fattr.h"
#include "fs_walk.h"
#include "copy_range.h"
#include "staged_file.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Confinement model for this file (Phase 8 — openat2 RESOLVE_BENEATH).
 *
 * Every path that reaches these helpers is a client-derived path under the
 * export root.  Confinement is established exactly as in namespace_ops.c:
 * ns_rel() opens a kernel-confinement rootfd on root_canon and returns the
 * within-root tail; every stat/open on a path routes through the beneath API so
 * escape is blocked atomically by the kernel.
 *
 * Where beneath is deliberately NOT used (see the inline notes below):
 *   - brix_copy_range(): operates on already-open file descriptors, not paths.
 *     Confinement happened when those fds were obtained via brix_open_beneath;
 *     a path-anchored RESOLVE_BENEATH check is meaningless on an fd.
 *   - brix_ns_copy_fattrs()/listxattr/getxattr/setxattr: the xattr syscalls are
 *     name+path based and have no openat2/RESOLVE_BENEATH-equivalent that takes a
 *     dirfd.  They run on src/dst paths that the immediately-preceding beneath
 *     open already proved resident under the root, so no new escape surface is
 *     introduced; switching them to an fd-based fsetxattr/fgetxattr is a possible
 *     future hardening but is not a confinement gap today.
 */

void
brix_xattr_copy_by_prefix(ngx_log_t *log,
    const char *src, const char *dst,
    const char *prefix, size_t prefix_len,
    size_t value_max)
{
    ssize_t  list_len, vlen;
    char    *list;
    char    *p;
    u_char  *value;

    list_len = listxattr(src, NULL, 0);
    if (list_len <= 0) {
        return;
    }

    list = ngx_alloc((size_t) list_len, log);
    if (list == NULL) {
        return;
    }

    list_len = listxattr(src, list, (size_t) list_len);
    if (list_len <= 0) {
        ngx_free(list);
        return;
    }

    value = ngx_alloc(value_max, log);
    if (value == NULL) {
        ngx_free(list);
        return;
    }

    for (p = list; p < list + list_len; p += strlen(p) + 1) {
        if (strncmp(p, prefix, prefix_len) != 0) {
            continue;
        }
        vlen = getxattr(src, p, value, value_max);
        if (vlen >= 0) {
            (void) setxattr(dst, p, value, (size_t) vlen, 0);
        }
    }

    ngx_free(value);
    ngx_free(list);
}

void
brix_ns_copy_fattrs(ngx_log_t *log, const char *src, const char *dst)
{
    brix_xattr_copy_by_prefix(log, src, dst,
        BRIX_FATTR_XKEY_PFX, BRIX_FATTR_XKEY_PFX_LEN,
        BRIX_FATTR_MAX_VBUF);
}

/*
 * ns_copy_validate — stat the copy endpoints and enforce pre-open policy.
 *
 * WHAT: Confines a stat on src and dst beneath rootfd, rejects a directory
 *       source (BRIX_NS_CONFLICT), and applies the overwrite / overwrite_dirs
 *       gates for an existing destination.  Fills *ssb with the source stat and
 *       sets res->existed/was_dir.  Returns 1 when the caller must return res
 *       immediately, 0 when the copy should proceed.
 * WHY: Extracts the entire pre-open decision tree from the orchestrator so it
 *      stays flat and under the complexity cap; the confined stats and their
 *      ordering are unchanged.
 * HOW: 1. stat_beneath src; error → record errno.  2. Reject a directory source.
 *      3. If dst exists, mark existed; refuse when overwrite is off; for a
 *      directory dst mark was_dir and refuse when overwrite_dirs is off.
 */
static ngx_flag_t
ns_copy_validate(int rootfd, const char *src_rel, const char *dst_rel,
    const brix_ns_copy_opts_t *opts, struct stat *ssb, brix_ns_result_t *res)
{
    struct stat  dsb;

    if (brix_stat_beneath(rootfd, src_rel, ssb) != 0) {
        ns_set_err(res, errno);
        return 1;
    }

    if (S_ISDIR(ssb->st_mode)) {
        res->status = BRIX_NS_CONFLICT; /* COPY on collection not yet shared */
        return 1;
    }

    if (brix_stat_beneath(rootfd, dst_rel, &dsb) == 0) {
        res->existed = 1;
        if (!opts->overwrite) {
            res->status = BRIX_NS_EXISTS;
            return 1;
        }
        if (S_ISDIR(dsb.st_mode)) {
            res->was_dir = 1;
            if (!opts->overwrite_dirs) {
                res->status = BRIX_NS_EXISTS;
                return 1;
            }
        }
    }

    return 0;
}

/*
 * ns_copy_open_dst — open the copy destination, staged or direct.
 *
 * WHAT: Opens dst either through the staging helper (staged_commit) or via a
 *       direct confined create.  On success writes *dst_fd_out, sets
 *       *use_staging_out for the staged path, and (staged) fills *staged.
 *       Returns 1 with res mapped from errno on failure, 0 on success.
 * WHY: The two destination-open strategies plus their error mapping are their
 *      own concern; isolating them keeps the orchestrator's cleanup linear.
 * HOW: 1. staged_commit → brix_staged_open (temp under root), publish its fd and
 *      mark staging.  2. Otherwise → brix_open_beneath with O_WRONLY|O_CREAT|
 *      O_TRUNC at the source mode.  3. Map any errno onto res.
 */
static ngx_flag_t
ns_copy_open_dst(ngx_log_t *log, int rootfd, const char *root_canon,
    const char *dst, const char *dst_rel, mode_t mode,
    const brix_ns_copy_opts_t *opts, brix_staged_file_t *staged,
    int *dst_fd_out, ngx_flag_t *use_staging_out, brix_ns_result_t *res)
{
    if (opts->staged_commit) {
        /* staged_file confines its own temp open/rename internally. */
        brix_staged_open_req_t staged_req = {
            .root_canon = root_canon,
            .final_path = dst,
            .mode       = mode,
            .open_flags = O_WRONLY | O_CREAT | O_TRUNC,
            .attempts   = 16,
        };
        if (brix_staged_open(log, &staged_req, staged) != NGX_OK) {
            ns_set_err(res, errno);
            return 1;
        }
        *dst_fd_out      = staged->fd;
        *use_staging_out = 1;
        return 0;
    }

    *dst_fd_out = brix_open_beneath(rootfd, dst_rel,
                                    O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (*dst_fd_out < 0) {
        ns_set_err(res, errno);
        return 1;
    }

    return 0;
}

/*
 * ns_copy_finalize — copy the bytes, commit the destination, copy xattrs.
 *
 * WHAT: Copies ssb->st_size bytes from src_fd to dst_fd, then commits the
 *       staged file (or closes a direct dst), and optionally mirrors fattr
 *       xattrs.  Fills res with BRIX_NS_OK/created on success or the mapped
 *       errno on failure.  Owns and closes src_fd/dst_fd; leaves rootfd to the
 *       caller.
 * WHY: Concentrates the data-plane copy and its resource cleanup so the
 *      orchestrator does not carry the multi-path close/abort logic; all
 *      confinement was established by the fds' beneath/staged opens.
 * HOW: 1. brix_copy_range on the fds; on failure close src_fd and abort-or-close
 *      dst.  2. Close src_fd.  3. Commit the staged file (error → return) or
 *      close the direct dst_fd.  4. Copy fattr xattrs when requested.
 */
static void
ns_copy_finalize(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, int src_fd, int dst_fd, const struct stat *ssb,
    const brix_ns_copy_opts_t *opts, ngx_flag_t use_staging,
    brix_staged_file_t *staged, brix_ns_result_t *res)
{
    /*
     * NOT a beneath site: brix_copy_range operates on the two file
     * descriptors obtained above (src_fd, dst_fd).  Both fds were opened
     * through brix_open_beneath / staged_file, so confinement is already
     * established; copy_file_range(2)/pread/pwrite act on fds, not paths, and
     * have no RESOLVE_BENEATH concept.  Re-confining here is neither possible
     * nor meaningful.
     */
    if (brix_copy_range(log, src_fd, 0, dst_fd, 0, ssb->st_size, src,
                          use_staging ? staged->tmp_path : dst) != NGX_OK)
    {
        ns_set_err(res, errno);
        close(src_fd);
        if (use_staging) {
            brix_staged_abort(log, root_canon, staged, 1);
        } else {
            close(dst_fd);
        }
        return;
    }

    close(src_fd);

    if (use_staging) {
        if (brix_staged_commit(log, root_canon, staged, dst) != NGX_OK) {
            ns_set_err(res, errno);
            return;
        }
    } else {
        close(dst_fd);
    }

    /*
     * NOT a beneath site: xattr copy is name+path based (listxattr/getxattr/
     * setxattr on src/dst).  There is no openat2/RESOLVE_BENEATH-equivalent for
     * extended attributes that takes a dirfd, and src/dst were just proven
     * resident under the root by the beneath opens above, so this introduces no
     * new escape surface.  (A future hardening could switch to fd-based
     * fgetxattr/fsetxattr; tracked, not a confinement gap.)
     */
    if (opts->preserve_xattrs) {
        brix_ns_copy_fattrs(log, src, dst);
    }

    res->status  = BRIX_NS_OK;
    res->created = 1;
}

brix_ns_result_t
brix_ns_local_copy(ngx_log_t *log, const char *root_canon, const char *src,
    const char *dst, const brix_ns_copy_opts_t *opts)
{
    brix_ns_result_t    res;
    struct stat         ssb;
    int                 src_fd = -1, dst_fd = -1;
    int                 rootfd;
    const char         *src_rel, *dst_rel;
    brix_staged_file_t  staged;
    ngx_flag_t          use_staging = 0;

    ngx_memzero(&res, sizeof(res));

    src_rel = ns_rel(root_canon, src, &rootfd);
    if (src_rel == NULL) {
        ns_set_err(&res, errno);
        return res;
    }
    dst_rel = brix_beneath_strip_root(root_canon, dst);
    if (dst_rel == NULL) {
        close(rootfd);
        ns_set_err(&res, EXDEV);
        return res;
    }

    if (ns_copy_validate(rootfd, src_rel, dst_rel, opts, &ssb, &res)) {
        close(rootfd);
        return res;
    }

    src_fd = brix_open_beneath(rootfd, src_rel, O_RDONLY, 0);
    if (src_fd < 0) {
        ns_set_err(&res, errno);
        close(rootfd);
        return res;
    }

    if (ns_copy_open_dst(log, rootfd, root_canon, dst, dst_rel, ssb.st_mode,
                         opts, &staged, &dst_fd, &use_staging, &res))
    {
        close(src_fd);
        close(rootfd);
        return res;
    }

    ns_copy_finalize(log, root_canon, src, dst, src_fd, dst_fd, &ssb, opts,
                     use_staging, &staged, &res);

    close(rootfd);
    return res;
}
