/*
 * client_ops.c — the impersonated filesystem op wrappers (phase 40).
 *
 * WHAT: The public brix_imp_* op wrappers (open/stat/mkdir/unlink/rmdir/rename/
 *   link/truncate/chmod/chown/setattr/symlink/readlink and the xattr family)
 *   that the confined beneath helpers call when `map` mode is active.  Each
 *   wrapper builds a request frame and performs one synchronous request/reply
 *   round-trip with the broker via imp_exchange(); OPEN receives the resulting
 *   fd back over SCM_RIGHTS.
 *
 * WHY: Split out of client.c (which was over the file-size cap) so the
 *   connection/state singleton, transport primitives, and the imp_build_req +
 *   imp_exchange core stay in client.c while the op-wrapper surface lives here.
 *   The two cross-file primitives are declared in client_internal.h.
 *
 * HOW: imp_call_status runs the 0/-1 ops; imp_unpack_stat fills a caller
 *   struct stat; imp_get_or_list is the shared get/listxattr body.  Broker
 *   status codes map to errno via imp_status_errno.  No goto; pure helpers,
 *   side effects at the edges.
 */

#include "impersonate.h"
#include "impersonate_proto.h"
#include "client_internal.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>


/* Translate a positive IMP_STATUS_* into the conventional errno for callers. */
static int
imp_status_errno(int status)
{
    switch (status) {
    case IMP_STATUS_DENY:        return EACCES;
    case IMP_STATUS_BADREQ:      return EINVAL;
    case IMP_STATUS_INTERNAL:    return EIO;
    case IMP_STATUS_PRIV_REFUSED: return EPERM;  /* reserved-id refused at broker */
    default:                     return EIO;
    }
}

/*
 * Run an op that returns 0/-1 (no fd).  Maps the broker reply to errno: 0 ->
 * success; status < 0 -> -status (the impersonated syscall's errno); status > 0
 * -> the IMP_STATUS_* errno.  Returns 0 or -1.
 */
static int
imp_call_status(uint32_t op, const char *path, const char *path2,
                uint32_t mode, int64_t length)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    imp_build_req(&req, op, path, path2, 0, mode, length);
    if (imp_exchange(&req, &rep, &fd, NULL, 0, NULL, 0) != 0) {
        return -1;                       /* errno=EIO set by imp_exchange */
    }
    if (fd >= 0) {
        close(fd);                       /* a non-OPEN op should never send an fd */
    }
    if (rep.status == 0) {
        return 0;
    }
    errno = (rep.status < 0) ? -rep.status : imp_status_errno(rep.status);
    return -1;
}


int
brix_imp_open(const char *reqpath, int flags, mode_t mode)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    imp_build_req(&req, IMP_OP_OPEN, reqpath, NULL,
                  (uint32_t) flags, (uint32_t) mode, 0);
    if (imp_exchange(&req, &rep, &fd, NULL, 0, NULL, 0) != 0) {
        return -1;
    }
    if (rep.status == 0 && (rep.rep_flags & IMP_REP_HAS_FD) && fd >= 0) {
        return fd;                       /* caller owns the fd */
    }
    if (fd >= 0) {
        close(fd);                       /* unexpected fd on a failed open */
    }
    errno = (rep.status < 0) ? -rep.status
                             : imp_status_errno(rep.status ? rep.status
                                                           : IMP_STATUS_INTERNAL);
    return -1;
}

/* Fill a caller struct stat from the portable imp_stat_t. */
static void
imp_unpack_stat(struct stat *st, const imp_stat_t *s)
{
    ngx_memzero(st, sizeof(*st));
    st->st_ino     = (ino_t)     s->ino;
    st->st_dev     = (dev_t)     s->dev;
    st->st_size    = (off_t)     s->size;
    st->st_blocks  = (blkcnt_t)  s->blocks;
    st->st_mtime   = (time_t)    s->mtime;
    st->st_ctime   = (time_t)    s->ctime;
    st->st_atime   = (time_t)    s->atime;
    st->st_mode    = (mode_t)    s->mode;
    st->st_uid     = (uid_t)     s->uid;
    st->st_gid     = (gid_t)     s->gid;
    st->st_nlink   = (nlink_t)   s->nlink;
    st->st_blksize = (blksize_t) s->blksize;
}

int
brix_imp_stat(const char *reqpath, struct stat *st, int nofollow)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    imp_build_req(&req, nofollow ? IMP_OP_LSTAT : IMP_OP_STAT,
                  reqpath, NULL, 0, 0, 0);
    if (imp_exchange(&req, &rep, &fd, NULL, 0, NULL, 0) != 0) {
        return -1;
    }
    if (fd >= 0) {
        close(fd);
    }
    if (rep.status == 0 && (rep.rep_flags & IMP_REP_HAS_STAT)) {
        imp_unpack_stat(st, &rep.st);
        return 0;
    }
    errno = (rep.status < 0) ? -rep.status
                             : imp_status_errno(rep.status ? rep.status
                                                           : IMP_STATUS_INTERNAL);
    return -1;
}

int
brix_imp_mkdir(const char *reqpath, mode_t mode)
{
    return imp_call_status(IMP_OP_MKDIR, reqpath, NULL, (uint32_t) mode, 0);
}

int
brix_imp_unlink(const char *reqpath, int is_dir)
{
    return imp_call_status(is_dir ? IMP_OP_RMDIR : IMP_OP_UNLINK,
                           reqpath, NULL, 0, 0);
}

int
brix_imp_rmdir(const char *reqpath)
{
    return imp_call_status(IMP_OP_RMDIR, reqpath, NULL, 0, 0);
}

int
brix_imp_rename(const char *src, const char *dst)
{
    return imp_call_status(IMP_OP_RENAME, src, dst, 0, 0);
}

int
brix_imp_rename_noreplace(const char *src, const char *dst)
{
    return imp_call_status(IMP_OP_RENAME_NOREPLACE, src, dst, 0, 0);
}

int
brix_imp_link(const char *src, const char *dst)
{
    return imp_call_status(IMP_OP_LINK, src, dst, 0, 0);
}

int
brix_imp_truncate(const char *reqpath, off_t length)
{
    return imp_call_status(IMP_OP_TRUNCATE, reqpath, NULL, 0, (int64_t) length);
}

int
brix_imp_chmod(const char *reqpath, mode_t mode)
{
    return imp_call_status(IMP_OP_CHMOD, reqpath, NULL, (uint32_t) mode, 0);
}

int
brix_imp_chown_gid(const char *reqpath, gid_t gid)
{
    /* CHOWN carries the gid in the mode field (uid is fixed by ownership). */
    return imp_call_status(IMP_OP_CHOWN, reqpath, NULL, (uint32_t) gid, 0);
}

int
brix_imp_setattr(const char *reqpath, int set_times,
                   const struct timespec times[2],
                   int set_owner, uid_t uid, gid_t gid)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    imp_build_req(&req, IMP_OP_SETATTR, reqpath, NULL, 0, 0, 0);
    req.attr_flags = (uint32_t) ((set_times ? IMP_ATTR_TIMES : 0)
                                 | (set_owner ? IMP_ATTR_OWNER : 0));
    if (set_times && times != NULL) {
        req.atime_sec  = (int64_t) times[0].tv_sec;
        req.atime_nsec = (int64_t) times[0].tv_nsec;
        req.mtime_sec  = (int64_t) times[1].tv_sec;
        req.mtime_nsec = (int64_t) times[1].tv_nsec;
    }
    req.set_uid = (uid == (uid_t) -1) ? (uint32_t) -1 : (uint32_t) uid;
    req.set_gid = (gid == (gid_t) -1) ? (uint32_t) -1 : (uint32_t) gid;

    if (imp_exchange(&req, &rep, &fd, NULL, 0, NULL, 0) != 0) {
        return -1;
    }
    if (fd >= 0) { close(fd); }
    if (rep.status == 0) {
        return 0;
    }
    errno = (rep.status < 0) ? -rep.status : imp_status_errno(rep.status);
    return -1;
}

int
brix_imp_symlink(const char *target, const char *linkpath)
{
    /* path = link location (root-relative), path2 = verbatim target string. */
    return imp_call_status(IMP_OP_SYMLINK, linkpath, target, 0, 0);
}

ssize_t
brix_imp_readlink(const char *reqpath, char *buf, size_t bufsz)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;
    char      linkbuf[IMP_PATH_MAX];
    size_t    n;

    imp_build_req(&req, IMP_OP_READLINK, reqpath, NULL, 0, 0, 0);
    if (imp_exchange(&req, &rep, &fd, linkbuf, sizeof(linkbuf), NULL, 0) != 0) {
        return -1;
    }
    if (fd >= 0) { close(fd); }
    if (rep.status == 0 && (rep.rep_flags & IMP_REP_HAS_DATA)) {
        n = rep.data_len;
        if (n > bufsz) { n = bufsz; }    /* truncate to caller's buffer (readlink) */
        ngx_memcpy(buf, linkbuf, n);
        return (ssize_t) n;              /* readlinkat returns the byte count */
    }
    errno = (rep.status < 0) ? -rep.status
                             : imp_status_errno(rep.status ? rep.status
                                                           : IMP_STATUS_INTERNAL);
    return -1;
}

/*
 * imp_get_or_list — shared body for getxattr/listxattr (both return a
 * variable-length payload via the reply-side trailing data).  The broker fills
 * its own IMP_XATTR_MAX buffer; we receive it into a process-private buffer and
 * then honour the POSIX f*xattr contract against the caller's buffer: bufsz==0
 * is a size probe (return the length, copy nothing); bufsz < length is ERANGE;
 * otherwise copy and return the length.  `xbuf` is static — the worker event
 * loop is single-threaded and the broker round-trip is fully synchronous, so the
 * call never overlaps itself; this keeps a 64 KiB buffer off the request stack.
 */
static ssize_t
imp_get_or_list(uint32_t op, const char *reqpath, const char *name,
                void *buf, size_t bufsz)
{
    static char xbuf[IMP_XATTR_MAX];
    imp_req_t   req;
    imp_rep_t   rep;
    int         fd = -1;
    size_t      n;

    imp_build_req(&req, op, reqpath, name, 0, 0, 0);
    if (imp_exchange(&req, &rep, &fd, xbuf, sizeof(xbuf), NULL, 0) != 0) {
        return -1;
    }
    if (fd >= 0) { close(fd); }
    if (rep.status != 0) {
        errno = (rep.status < 0) ? -rep.status : imp_status_errno(rep.status);
        return -1;
    }
    n = (rep.rep_flags & IMP_REP_HAS_DATA) ? rep.data_len : 0;
    if (bufsz == 0) {
        return (ssize_t) n;              /* size probe */
    }
    if (n > bufsz) {
        errno = ERANGE;
        return -1;
    }
    ngx_memcpy(buf, xbuf, n);
    return (ssize_t) n;
}

ssize_t
brix_imp_getxattr(const char *reqpath, const char *name,
                    void *buf, size_t bufsz)
{
    return imp_get_or_list(IMP_OP_GETXATTR, reqpath, name, buf, bufsz);
}

ssize_t
brix_imp_listxattr(const char *reqpath, void *buf, size_t bufsz)
{
    return imp_get_or_list(IMP_OP_LISTXATTR, reqpath, NULL, buf, bufsz);
}

int
brix_imp_setxattr(const char *reqpath, const char *name,
                    const void *value, size_t len, int flags)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    if (len > IMP_XATTR_MAX) {
        errno = E2BIG;                   /* broker bounds the inbound payload */
        return -1;
    }
    /* xattr flags (XATTR_CREATE/XATTR_REPLACE/0) ride in the mode field. */
    imp_build_req(&req, IMP_OP_SETXATTR, reqpath, name, 0, (uint32_t) flags, 0);
    req.req_data_len = (uint32_t) len;
    if (imp_exchange(&req, &rep, &fd, NULL, 0, value, len) != 0) {
        return -1;
    }
    if (fd >= 0) { close(fd); }
    if (rep.status == 0) {
        return 0;
    }
    errno = (rep.status < 0) ? -rep.status : imp_status_errno(rep.status);
    return -1;
}

int
brix_imp_removexattr(const char *reqpath, const char *name)
{
    imp_req_t req;
    imp_rep_t rep;
    int       fd = -1;

    imp_build_req(&req, IMP_OP_REMOVEXATTR, reqpath, name, 0, 0, 0);
    if (imp_exchange(&req, &rep, &fd, NULL, 0, NULL, 0) != 0) {
        return -1;
    }
    if (fd >= 0) { close(fd); }
    if (rep.status == 0) {
        return 0;
    }
    errno = (rep.status < 0) ? -rep.status : imp_status_errno(rep.status);
    return -1;
}
