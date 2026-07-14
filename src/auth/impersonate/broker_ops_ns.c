/*
 * broker_ops_ns.c — parent-relative namespace-mutation broker ops.
 *
 * WHAT: The impersonation-broker file operations that act on a final path
 * component under its confined PARENT directory: mkdir, unlink/rmdir, chmod,
 * chown, rename/rename-noreplace/link, setattr (utimens + chown), symlink and
 * readlink.  Every handler returns 0 or -errno and is dispatched by the opcode
 * table (imp_op_table) that lives in broker_ops.c.
 *
 * WHY: Split out of broker_ops.c (phase-79) to keep both files under the
 * 500-line cap.  These ops share one shape — open the parent via
 * imp_open_parent (RESOLVE_BENEATH), operate on the final component as the
 * mapped user — so they and their private imp_with_parent / imp_step_*
 * machinery form a single cohesive concern.  The fd-based ops (open/stat/
 * truncate/xattr), the confined primitives, and the dispatch entry stay in
 * broker_ops.c; only the eight table-referenced handlers are non-static here.
 *
 * HOW: imp_with_parent wraps the open-parent / run-step / close boilerplate for
 * the single-path ops (mkdir/unlink/chmod/chown), each expressed as a one-line
 * imp_step_* syscall; the multi-path ops (rename/link) and the payload ops
 * (setattr/symlink/readlink) open their parent(s) directly.  Behaviour is
 * identical to the pre-split broker_ops.c.
 */
#include "broker_internal.h"
#include "broker_ops_internal.h"


/*
 * imp_parent_fn_t — per-op syscall step run under a confined parent: `pfd` is
 * the RESOLVE_BENEATH-opened parent directory and `base` the final path
 * component (pointing into the caller's scratch buffer).  Returns 0 or -errno.
 */
typedef int (*imp_parent_fn_t)(int pfd, const char *base,
                               const imp_op_ctx_t *c);


/* ---- imp_with_parent — run one syscall step under the confined parent ----
 *
 * WHAT: Opens the parent directory of c->rel beneath c->rootfd via
 * imp_open_parent, runs `step` on (pfd, base, c) and returns its result
 * (0 or -errno) after closing the parent fd; a failed parent open returns
 * its -errno without calling `step`.
 *
 * WHY: Every single-path parent-relative op (mkdir/unlink/rmdir/chmod/chown)
 * repeated the identical open-parent / early-return / close boilerplate; one
 * shared wrapper keeps the confinement and fd-lifetime rules in exactly one
 * place so a per-op handler is only its syscall.
 *
 * HOW: 1. imp_open_parent into a local scratch buffer; 2. early-return the
 * negative errno on open failure; 3. run `step`; 4. close(pfd); 5. return
 * the step's rc.
 */
static int
imp_with_parent(const imp_op_ctx_t *c, imp_parent_fn_t step)
{
    char        scratch[IMP_PATH_MAX];
    const char *base;
    int         pfd, rc;

    pfd = imp_open_parent(c->rootfd, c->rel, scratch, &base);
    if (pfd < 0) {
        return pfd;
    }
    rc = step(pfd, base, c);
    close(pfd);
    return rc;
}


/* imp_step_mkdir — mkdirat(base, req->mode) under the confined parent. */
static int
imp_step_mkdir(int pfd, const char *base, const imp_op_ctx_t *c)
{
    return mkdirat(pfd, base, c->req->mode) == 0 ? 0 : -errno;
}


/*
 * imp_op_mkdir — IMP_OP_MKDIR: mkdirat(base) under the confined parent.
 * HOW: imp_open_parent confines the dirname, mkdirat creates the final
 * component with req->mode.
 */
int
imp_op_mkdir(const imp_op_ctx_t *c)
{
    return imp_with_parent(c, imp_step_mkdir);
}


/* imp_step_unlink — unlinkat(base); AT_REMOVEDIR for the IMP_OP_RMDIR variant. */
static int
imp_step_unlink(int pfd, const char *base, const imp_op_ctx_t *c)
{
    return unlinkat(pfd, base,
                    c->req->op == IMP_OP_RMDIR ? AT_REMOVEDIR : 0) == 0
               ? 0 : -errno;
}


/*
 * imp_op_unlink — IMP_OP_UNLINK / IMP_OP_RMDIR: unlinkat(base) under the
 * confined parent, AT_REMOVEDIR for the directory variant.
 */
int
imp_op_unlink(const imp_op_ctx_t *c)
{
    return imp_with_parent(c, imp_step_unlink);
}


/* imp_step_chmod — fchmodat(base, req->mode) under the confined parent. */
static int
imp_step_chmod(int pfd, const char *base, const imp_op_ctx_t *c)
{
    return fchmodat(pfd, base, c->req->mode, 0) == 0 ? 0 : -errno;
}


/*
 * imp_op_chmod — IMP_OP_CHMOD: fchmodat(base, req->mode) under the confined
 * parent, as the mapped user (DAC decides).
 */
int
imp_op_chmod(const imp_op_ctx_t *c)
{
    return imp_with_parent(c, imp_step_chmod);
}


/* imp_step_chown — gid-only fchownat(base); req->mode carries the gid. */
static int
imp_step_chown(int pfd, const char *base, const imp_op_ctx_t *c)
{
    return fchownat(pfd, base, (uid_t) -1, (gid_t) c->req->mode,
                    AT_SYMLINK_NOFOLLOW) == 0 ? 0 : -errno;
}


/*
 * imp_op_chown — IMP_OP_CHOWN: gid-only fchownat (uid is fixed by ownership);
 * the mapped user must own the file.  req->mode carries the gid on the wire.
 */
int
imp_op_chown(const imp_op_ctx_t *c)
{
    return imp_with_parent(c, imp_step_chown);
}


/*
 * imp_op_rename_link — IMP_OP_RENAME / IMP_OP_RENAME_NOREPLACE / IMP_OP_LINK:
 * two-path ops.  HOW: confine BOTH parents via imp_open_parent, then linkat or
 * imp_do_rename (which handles the RENAME_NOREPLACE renameat2 fallback).
 */
int
imp_op_rename_link(const imp_op_ctx_t *c)
{
    const char *rel2 = imp_rel(c->req->path2);
    char        scratch[IMP_PATH_MAX], scratch2[IMP_PATH_MAX];
    const char *base, *base2;
    int         pfd, pfd2, rc;

    pfd = imp_open_parent(c->rootfd, c->rel, scratch, &base);
    if (pfd < 0) {
        return pfd;
    }
    pfd2 = imp_open_parent(c->rootfd, rel2, scratch2, &base2);
    if (pfd2 < 0) {
        close(pfd);
        return pfd2;
    }
    if (c->req->op == IMP_OP_LINK) {
        rc = linkat(pfd, base, pfd2, base2, 0) == 0 ? 0 : -errno;
    } else {
        rc = imp_do_rename(pfd, base, pfd2, base2,
                           c->req->op == IMP_OP_RENAME_NOREPLACE) == 0
             ? 0 : -errno;
    }
    close(pfd);
    close(pfd2);
    return rc;
}


/*
 * imp_op_setattr — IMP_OP_SETATTR: utimensat (+ optional fchownat) on the
 * final component, NOFOLLOW.  As the mapped user: chgrp/utimens on a file
 * they own succeeds; a chown to a different owner correctly fails (the broker
 * holds no CAP_CHOWN).
 */
int
imp_op_setattr(const imp_op_ctx_t *c)
{
    char        scratch[IMP_PATH_MAX];
    const char *base;
    int         pfd, rc;

    pfd = imp_open_parent(c->rootfd, c->rel, scratch, &base);
    if (pfd < 0) {
        return pfd;
    }
    rc = 0;
    if (c->req->attr_flags & IMP_ATTR_TIMES) {
        struct timespec ts[2];
        ts[0].tv_sec  = (time_t) c->req->atime_sec;
        ts[0].tv_nsec = (long)   c->req->atime_nsec;
        ts[1].tv_sec  = (time_t) c->req->mtime_sec;
        ts[1].tv_nsec = (long)   c->req->mtime_nsec;
        if (utimensat(pfd, base, ts, AT_SYMLINK_NOFOLLOW) != 0) {
            rc = -errno;
        }
    }
    if (rc == 0 && (c->req->attr_flags & IMP_ATTR_OWNER)) {
        uid_t u = (c->req->set_uid == (uint32_t) -1) ? (uid_t) -1
                                                     : (uid_t) c->req->set_uid;
        gid_t g = (c->req->set_gid == (uint32_t) -1) ? (gid_t) -1
                                                     : (gid_t) c->req->set_gid;
        if (fchownat(pfd, base, u, g, AT_SYMLINK_NOFOLLOW) != 0) {
            rc = -errno;
        }
    }
    close(pfd);
    return rc;
}


/*
 * imp_op_symlink — IMP_OP_SYMLINK: path = link location (root-relative);
 * path2 = verbatim target string.  Only the link site is confined; a target
 * pointing outside the root just cannot be followed later (the confined open
 * re-applies RESOLVE_BENEATH).
 */
int
imp_op_symlink(const imp_op_ctx_t *c)
{
    char        scratch[IMP_PATH_MAX];
    const char *base;
    int         pfd, rc;

    pfd = imp_open_parent(c->rootfd, c->rel, scratch, &base);
    if (pfd < 0) {
        return pfd;
    }
    rc = symlinkat(c->req->path2, pfd, base) == 0 ? 0 : -errno;
    close(pfd);
    return rc;
}


/*
 * imp_op_readlink — IMP_OP_READLINK: readlinkat(base) under the confined
 * parent; the link target goes back as the trailing reply payload.
 */
int
imp_op_readlink(const imp_op_ctx_t *c)
{
    char        scratch[IMP_PATH_MAX];
    const char *base;
    int         pfd;
    ssize_t     n;

    pfd = imp_open_parent(c->rootfd, c->rel, scratch, &base);
    if (pfd < 0) {
        return pfd;
    }
    n = readlinkat(pfd, base, c->data_out, c->data_max);
    close(pfd);
    if (n < 0) {
        return -errno;
    }
    c->rep->data_len   = (uint32_t) n;   /* link target -> trailing payload */
    c->rep->rep_flags |= IMP_REP_HAS_DATA;
    return 0;
}
