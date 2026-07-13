/*
 * broker_ops.c - extracted concern
 * Phase-38 split of broker.c; behavior-identical.
 */
#include "broker_internal.h"


/* openat2(rootfd, rel, RESOLVE_BENEATH).  Returns fd or -errno. */
int
imp_openat2(int rootfd, const char *rel, uint32_t flags, uint32_t mode)
{
    struct open_how how;
    long            fd;

    ngx_memzero(&how, sizeof(how));
    how.flags   = flags | O_CLOEXEC;
    /*
     * openat2() is stricter than open()/openat(): it rejects (EINVAL) any
     * how.mode bit outside 07777.  Callers legitimately pass a full struct
     * stat st_mode (e.g. staged_file copying a source's permissions during a
     * WebDAV/S3 COPY), which carries the S_IFMT type bits.  Mask to the
     * permission bits, exactly as the worker-local do_openat2() in
     * src/path/beneath.c does, so a struct-stat mode is accepted instead of
     * failing the whole impersonated COPY with EINVAL.
     */
    how.mode    = (flags & O_CREAT) ? (mode & 07777) : 0;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;

    fd = syscall(SYS_openat2, rootfd, rel, &how, sizeof(how));
    return (fd < 0) ? -errno : (int) fd;
}


/*
 * Open the PARENT directory of `rel` beneath rootfd (O_PATH|O_DIRECTORY) and
 * point *base at the final path component.  Returns the parent fd or -errno;
 * rejects a trailing "." / ".." / empty base.  `scratch` (>= IMP_PATH_MAX) holds
 * the mutated copy that *base points into.
 */
int
imp_open_parent(int rootfd, const char *rel, char *scratch, const char **base)
{
    char *slash;
    int   pfd;

    if (ngx_strlen(rel) >= IMP_PATH_MAX) {
        return -ENAMETOOLONG;
    }
    ngx_memcpy(scratch, rel, ngx_strlen(rel) + 1);

    slash = strrchr(scratch, '/');
    if (slash == NULL) {
        *base = scratch;                 /* parent is rootfd itself */
        pfd = imp_openat2(rootfd, ".", O_PATH | O_DIRECTORY, 0);
    } else {
        *slash = '\0';
        *base = slash + 1;
        pfd = imp_openat2(rootfd, imp_rel(scratch), O_PATH | O_DIRECTORY, 0);
    }

    if ((*base)[0] == '\0'
        || ngx_strcmp(*base, ".") == 0 || ngx_strcmp(*base, "..") == 0)
    {
        if (pfd >= 0) { close(pfd); }
        return -EINVAL;
    }
    return pfd;                          /* fd or -errno from imp_openat2 */
}


/* Fill a portable imp_stat_t from a struct stat. */
void
imp_fill_stat(imp_stat_t *o, const struct stat *s)
{
    o->ino     = (uint64_t) s->st_ino;
    o->dev     = (uint64_t) s->st_dev;
    o->size    = (uint64_t) s->st_size;
    o->blocks  = (uint64_t) s->st_blocks;
    o->mtime   = (int64_t)  s->st_mtime;
    o->ctime   = (int64_t)  s->st_ctime;
    o->atime   = (int64_t)  s->st_atime;
    o->mode    = (uint32_t) s->st_mode;
    o->uid     = (uint32_t) s->st_uid;
    o->gid     = (uint32_t) s->st_gid;
    o->nlink   = (uint32_t) s->st_nlink;
    o->blksize = (uint32_t) s->st_blksize;
}



/*
 * imp_xattr_open — open the xattr target file beneath rootfd as the (already
 * impersonated) mapped user for an f*xattr op.  O_RDONLY|O_NONBLOCK is enough:
 * f{get,set,remove,list}xattr check inode permission against the caller's
 * (impersonated) creds at the call, independent of the fd's open mode, while the
 * RESOLVE_BENEATH open both confines the path and enforces the mapped user's DAC
 * to even reach the file.  O_NONBLOCK avoids blocking on a FIFO.  Returns fd or
 * -errno.  (Rare write-only files — mode 0200 — cannot be opened O_RDONLY; such
 * a SETXATTR fails EACCES, an acceptable corner the path-based fallback avoided.)
 */
int
imp_xattr_open(int rootfd, const char *rel)
{
    return imp_openat2(rootfd, rel, O_RDONLY | O_NONBLOCK, 0);
}


/*
 * imp_xattr_name_ok — the broker only services the `user.` xattr namespace (all
 * the module's xattr users live there: locks, dead properties, checksum cache).
 * Refusing every other namespace is defence-in-depth: it denies any attempt to
 * drive the broker into setting security.* / system.* / trusted.* attributes,
 * independent of what the (unprivileged) mapped user's own creds would allow.
 */
int
imp_xattr_name_ok(const char *name)
{
    return ngx_strncmp(name, "user.", 5) == 0;
}


/*
 * imp_xattr_filter_user — restrict a flistxattr(2) result (NUL-separated attribute
 * names, total `len` bytes including terminators) to the `user.` namespace,
 * repacking the kept names densely in place and returning the new length.  Without
 * this the broker would hand the worker the NAMES of every attribute on the file,
 * including system.* / security.* / trusted.* set by root — an information leak
 * (the worker cannot read their VALUES, but it learns they exist).  Matches the
 * same user.-only policy the per-name ops enforce via imp_xattr_name_ok().
 */
size_t
imp_xattr_filter_user(char *list, size_t len)
{
    size_t in = 0, out = 0;

    while (in < len) {
        size_t entry = 0;
        while (in + entry < len && list[in + entry] != '\0') {
            entry++;
        }
        if (in + entry >= len) {
            break;                       /* no NUL terminator: malformed tail */
        }
        entry++;                         /* include the NUL */
        if (imp_xattr_name_ok(list + in)) {
            if (out != in) {
                ngx_memmove(list + out, list + in, entry);
            }
            out += entry;
        }
        in += entry;
    }
    return out;
}



/*
 * renameat, optionally with RENAME_NOREPLACE (atomic create-if-absent).  When
 * `noreplace` is set and the kernel/filesystem lacks RENAME_NOREPLACE
 * (ENOSYS/EINVAL) it falls back to a plain renameat so behaviour degrades to the
 * legacy last-writer-wins rather than spuriously failing; on a modern kernel
 * (>=3.15) the exclusive path is taken and a pre-existing dst yields EEXIST.
 * Returns 0 on success, -1 with errno set.
 */
int
imp_do_rename(int sfd, const char *sbase, int dfd, const char *dbase,
              int noreplace)
{
    if (!noreplace) {
        /* phase72-fp: sfd/sbase ARE the old (source) pair — order is correct */
        return renameat(sfd, sbase, dfd, dbase);  /* NOLINT(readability-suspicious-call-argument) */
    }
    if (syscall(SYS_renameat2, sfd, sbase, dfd, dbase,
                (unsigned int) RENAME_NOREPLACE) == 0) {
        return 0;
    }
    if (errno == ENOSYS || errno == EINVAL) {
        /* phase72-fp: sfd/sbase ARE the old (source) pair — order is correct */
        return renameat(sfd, sbase, dfd, dbase);  /* NOLINT(readability-suspicious-call-argument) */
    }
    return -1;
}


/*
 * imp_op_open — IMP_OP_OPEN: openat2(RESOLVE_BENEATH) and hand the fd back.
 * WHY the O_NONBLOCK dance: a FIFO opened O_RDONLY blocks until a writer
 * arrives, and a device node can block in its open method — either would wedge
 * this single broker process, denying service to *every* worker/tenant (a
 * cross-tenant DoS) since one bad path in the export hangs the whole
 * impersonation channel.  With O_NONBLOCK the open returns immediately for
 * every file type, then we inspect what we actually got and only hand back
 * regular files and directories — the only types the gateway data plane ever
 * serves.  HOW: open O_NONBLOCK -> fstat -> type gate -> clear O_NONBLOCK.
 */
static int
imp_op_open(const imp_op_ctx_t *c)
{
    struct stat st;
    int         fd, fl, rc;

    fd = imp_openat2(c->rootfd, c->rel, c->req->open_flags | O_NONBLOCK,
                     c->req->mode);
    if (fd < 0) {
        return fd;
    }
    if (fstat(fd, &st) != 0) {
        rc = -errno;
        close(fd);
        return rc;
    }
    /*
     * Reject FIFOs, sockets, and character/block devices: the gateway only
     * reads/writes regular files and enumerates directories.  Handing the
     * worker a device or pipe fd would both leak a non-file capability and
     * (for the data plane's blocking pread/pwrite/sendfile) reintroduce the
     * very stall we just avoided.  Fail closed with EOPNOTSUPP.
     */
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
        close(fd);
        return -EOPNOTSUPP;
    }
    /*
     * Restore blocking semantics for the returned fd: O_NONBLOCK was only
     * needed to survive the open(2); the worker's data plane expects a
     * blocking regular-file/dir fd (it has no EAGAIN retry path).  On a
     * regular file/dir O_NONBLOCK is otherwise a no-op, so clearing it is
     * always safe.
     */
    fl = fcntl(fd, F_GETFL);
    if (fl != -1) {
        (void) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }
    *c->out_fd = fd;
    c->rep->rep_flags |= IMP_REP_HAS_FD;
    return 0;
}


/*
 * imp_op_stat — IMP_OP_STAT / IMP_OP_LSTAT: confined stat into rep->st.
 * WHY via O_PATH + AT_EMPTY_PATH: the RESOLVE_BENEATH open both confines the
 * path and (for LSTAT, O_NOFOLLOW) pins the symlink itself.  HOW: openat2 ->
 * fstatat("", AT_EMPTY_PATH) -> imp_fill_stat.
 */
static int
imp_op_stat(const imp_op_ctx_t *c)
{
    struct stat st;
    int         fd, rc;

    fd = imp_openat2(c->rootfd, c->rel,
                     O_PATH | (c->req->op == IMP_OP_LSTAT ? O_NOFOLLOW : 0), 0);
    if (fd < 0) {
        return fd;
    }
    rc = fstatat(fd, "", &st, AT_EMPTY_PATH) == 0 ? 0 : -errno;
    close(fd);
    if (rc != 0) {
        return rc;
    }
    imp_fill_stat(&c->rep->st, &st);
    c->rep->rep_flags |= IMP_REP_HAS_STAT;
    return 0;
}


/*
 * imp_op_truncate — IMP_OP_TRUNCATE: confined open O_WRONLY + ftruncate to
 * req->length.  WHY fd-based: ftruncate on a RESOLVE_BENEATH fd keeps the
 * confinement and the mapped user's DAC check on one open.
 */
static int
imp_op_truncate(const imp_op_ctx_t *c)
{
    int fd, rc;

    fd = imp_openat2(c->rootfd, c->rel, O_WRONLY, 0);
    if (fd < 0) {
        return fd;
    }
    rc = ftruncate(fd, (off_t) c->req->length) == 0 ? 0 : -errno;
    close(fd);
    return rc;
}


/*
 * imp_op_mkdir — IMP_OP_MKDIR: mkdirat(base) under the confined parent.
 * HOW: imp_open_parent confines the dirname, mkdirat creates the final
 * component with req->mode.
 */
static int
imp_op_mkdir(const imp_op_ctx_t *c)
{
    char        scratch[IMP_PATH_MAX];
    const char *base;
    int         pfd, rc;

    pfd = imp_open_parent(c->rootfd, c->rel, scratch, &base);
    if (pfd < 0) {
        return pfd;
    }
    rc = mkdirat(pfd, base, c->req->mode) == 0 ? 0 : -errno;
    close(pfd);
    return rc;
}


/*
 * imp_op_unlink — IMP_OP_UNLINK / IMP_OP_RMDIR: unlinkat(base) under the
 * confined parent, AT_REMOVEDIR for the directory variant.
 */
static int
imp_op_unlink(const imp_op_ctx_t *c)
{
    char        scratch[IMP_PATH_MAX];
    const char *base;
    int         pfd, rc;

    pfd = imp_open_parent(c->rootfd, c->rel, scratch, &base);
    if (pfd < 0) {
        return pfd;
    }
    rc = unlinkat(pfd, base,
                  c->req->op == IMP_OP_RMDIR ? AT_REMOVEDIR : 0) == 0
             ? 0 : -errno;
    close(pfd);
    return rc;
}


/*
 * imp_op_chmod — IMP_OP_CHMOD: fchmodat(base, req->mode) under the confined
 * parent, as the mapped user (DAC decides).
 */
static int
imp_op_chmod(const imp_op_ctx_t *c)
{
    char        scratch[IMP_PATH_MAX];
    const char *base;
    int         pfd, rc;

    pfd = imp_open_parent(c->rootfd, c->rel, scratch, &base);
    if (pfd < 0) {
        return pfd;
    }
    rc = fchmodat(pfd, base, c->req->mode, 0) == 0 ? 0 : -errno;
    close(pfd);
    return rc;
}


/*
 * imp_op_chown — IMP_OP_CHOWN: gid-only fchownat (uid is fixed by ownership);
 * the mapped user must own the file.  req->mode carries the gid on the wire.
 */
static int
imp_op_chown(const imp_op_ctx_t *c)
{
    char        scratch[IMP_PATH_MAX];
    const char *base;
    int         pfd, rc;

    pfd = imp_open_parent(c->rootfd, c->rel, scratch, &base);
    if (pfd < 0) {
        return pfd;
    }
    rc = fchownat(pfd, base, (uid_t) -1, (gid_t) c->req->mode,
                  AT_SYMLINK_NOFOLLOW) == 0 ? 0 : -errno;
    close(pfd);
    return rc;
}


/*
 * imp_op_rename_link — IMP_OP_RENAME / IMP_OP_RENAME_NOREPLACE / IMP_OP_LINK:
 * two-path ops.  HOW: confine BOTH parents via imp_open_parent, then linkat or
 * imp_do_rename (which handles the RENAME_NOREPLACE renameat2 fallback).
 */
static int
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
static int
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
static int
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
static int
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


/*
 * imp_op_xattr_read — IMP_OP_GETXATTR / IMP_OP_LISTXATTR: read xattr value or
 * name list into the trailing reply payload.  WHY the two gates: GETXATTR is
 * user.-namespace-only per name (imp_xattr_name_ok), and LISTXATTR withholds
 * non-user.* attribute NAMES from the worker (imp_xattr_filter_user) — the
 * per-name GET/SET/REMOVE ops are already user.-only.
 */
static int
imp_op_xattr_read(const imp_op_ctx_t *c)
{
    int     fd;
    ssize_t n;

    if (c->req->op == IMP_OP_GETXATTR && !imp_xattr_name_ok(c->req->path2)) {
        return -EPERM;
    }
    fd = imp_xattr_open(c->rootfd, c->rel);
    if (fd < 0) {
        return fd;
    }
    if (c->req->op == IMP_OP_GETXATTR) {
        n = fgetxattr(fd, c->req->path2, c->data_out, c->data_max);
    } else {
        n = flistxattr(fd, c->data_out, c->data_max);
    }
    close(fd);
    if (n < 0) {
        return -errno;                   /* ENODATA / ERANGE / EACCES ... */
    }
    if (c->req->op == IMP_OP_LISTXATTR) {
        n = (ssize_t) imp_xattr_filter_user(c->data_out, (size_t) n);
    }
    c->rep->data_len   = (uint32_t) n;   /* value / name list -> reply payload */
    c->rep->rep_flags |= IMP_REP_HAS_DATA;
    return 0;
}


/*
 * imp_op_setxattr — IMP_OP_SETXATTR: fsetxattr(path2=name) with the inbound
 * request payload as the value; user.-namespace-only (defence-in-depth against
 * driving the broker into setting security./system./trusted. attributes).
 */
static int
imp_op_setxattr(const imp_op_ctx_t *c)
{
    int fd, rc;

    if (!imp_xattr_name_ok(c->req->path2)) {
        return -EPERM;
    }
    fd = imp_xattr_open(c->rootfd, c->rel);
    if (fd < 0) {
        return fd;
    }
    rc = fsetxattr(fd, c->req->path2, c->data_in, c->data_in_len,
                   (int) c->req->mode) == 0 ? 0 : -errno;
    close(fd);
    return rc;
}


/*
 * imp_op_removexattr — IMP_OP_REMOVEXATTR: fremovexattr(path2=name);
 * user.-namespace-only, same policy as SETXATTR.
 */
static int
imp_op_removexattr(const imp_op_ctx_t *c)
{
    int fd, rc;

    if (!imp_xattr_name_ok(c->req->path2)) {
        return -EPERM;
    }
    fd = imp_xattr_open(c->rootfd, c->rel);
    if (fd < 0) {
        return fd;
    }
    rc = fremovexattr(fd, c->req->path2) == 0 ? 0 : -errno;
    close(fd);
    return rc;
}


/*
 * imp_op_table — opcode -> handler descriptor table (coding-standards §8.6:
 * data-driven dispatch over a branch ladder).  WHY exhaustive-by-listing: an
 * op absent from this table (including IMP_OP_PING, which never reaches
 * imp_do_op) fails closed with -ENOSYS, exactly as the former switch default.
 */
typedef int (*imp_op_fn_t)(const imp_op_ctx_t *c);

static const struct {
    uint32_t    op;
    imp_op_fn_t fn;
} imp_op_table[] = {
    { IMP_OP_OPEN,             imp_op_open        },
    { IMP_OP_STAT,             imp_op_stat        },
    { IMP_OP_LSTAT,            imp_op_stat        },
    { IMP_OP_TRUNCATE,         imp_op_truncate    },
    { IMP_OP_MKDIR,            imp_op_mkdir       },
    { IMP_OP_UNLINK,           imp_op_unlink      },
    { IMP_OP_RMDIR,            imp_op_unlink      },
    { IMP_OP_CHMOD,            imp_op_chmod       },
    { IMP_OP_CHOWN,            imp_op_chown       },
    { IMP_OP_RENAME,           imp_op_rename_link },
    { IMP_OP_RENAME_NOREPLACE, imp_op_rename_link },
    { IMP_OP_LINK,             imp_op_rename_link },
    { IMP_OP_SETATTR,          imp_op_setattr     },
    { IMP_OP_SYMLINK,          imp_op_symlink     },
    { IMP_OP_READLINK,         imp_op_readlink    },
    { IMP_OP_GETXATTR,         imp_op_xattr_read  },
    { IMP_OP_LISTXATTR,        imp_op_xattr_read  },
    { IMP_OP_SETXATTR,         imp_op_setxattr    },
    { IMP_OP_REMOVEXATTR,      imp_op_removexattr },
};


/*
 * Perform the requested op while impersonated.  The caller fills every ctx
 * field except `rel` (derived here from c->req->path).  Returns 0 and may set
 * *c->out_fd (>=0, ownership transferred to the caller) and/or c->rep->st; or
 * returns -errno.  `c->data_out` (size `c->data_max`) receives a trailing
 * reply payload for READLINK / GETXATTR / LISTXATTR; rep->data_len +
 * IMP_REP_HAS_DATA are set in that case.  `c->data_in` (size `c->data_in_len`)
 * is the inbound payload for SETXATTR (the value).
 * HOW: last-line reserved-identity guard, then table dispatch to the
 * imp_op_<name>() helper for the opcode; unknown op -> -ENOSYS (fail closed).
 */
int
imp_do_op(imp_op_ctx_t *c)
{
    ngx_uint_t i;

    /*
     * Last-line guard, at the file-op execution point itself: the effective
     * fs-credentials MUST be non-reserved here (imp_become guarantees it).  Read
     * them back one more time and refuse the op rather than ever run a file
     * operation as uid/gid 0 or < the hard floor.  Cheap (two syscalls), and it
     * closes the window completely — no file op runs under a reserved identity.
     */
    if ((uid_t) setfsuid((uid_t) -1) < (uid_t) BRIX_IMP_HARD_MIN_ID
        || (gid_t) setfsgid((gid_t) -1) < (gid_t) BRIX_IMP_HARD_MIN_ID)
    {
        return -EPERM;
    }

    c->rel = imp_rel(c->req->path);

    for (i = 0; i < sizeof(imp_op_table) / sizeof(imp_op_table[0]); i++) {
        if (imp_op_table[i].op == c->req->op) {
            return imp_op_table[i].fn(c);
        }
    }
    return -ENOSYS;
}
