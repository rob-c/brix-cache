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
        return renameat(sfd, sbase, dfd, dbase);
    }
    if (syscall(SYS_renameat2, sfd, sbase, dfd, dbase,
                (unsigned int) RENAME_NOREPLACE) == 0) {
        return 0;
    }
    if (errno == ENOSYS || errno == EINVAL) {
        return renameat(sfd, sbase, dfd, dbase);
    }
    return -1;
}


/*
 * Perform the requested op while impersonated.  Returns 0 and may set *out_fd
 * (>=0, ownership transferred to the caller) and/or rep->st; or returns -errno.
 * `data_out` (size `data_max`) receives a trailing reply payload for READLINK /
 * GETXATTR / LISTXATTR; rep->data_len + IMP_REP_HAS_DATA are set in that case.
 * `data_in` (size `data_in_len`) is the inbound payload for SETXATTR (the value).
 */
int
imp_do_op(int rootfd, const imp_req_t *req, imp_rep_t *rep, int *out_fd,
          char *data_out, size_t data_max,
          const char *data_in, size_t data_in_len)
{
    const char *rel  = imp_rel(req->path);
    const char *rel2;
    char        scratch[IMP_PATH_MAX], scratch2[IMP_PATH_MAX];
    const char *base, *base2;
    int         pfd, pfd2, fd, rc;
    struct stat st;

    /*
     * Last-line guard, at the file-op execution point itself: the effective
     * fs-credentials MUST be non-reserved here (imp_become guarantees it).  Read
     * them back one more time and refuse the op rather than ever run a file
     * operation as uid/gid 0 or < the hard floor.  Cheap (two syscalls), and it
     * closes the window completely — no file op runs under a reserved identity.
     */
    if ((uid_t) setfsuid((uid_t) -1) < (uid_t) XROOTD_IMP_HARD_MIN_ID
        || (gid_t) setfsgid((gid_t) -1) < (gid_t) XROOTD_IMP_HARD_MIN_ID)
    {
        return -EPERM;
    }

    switch (req->op) {

    case IMP_OP_OPEN: {
        int fl;

        /*
         * Force O_NONBLOCK for the open(2) itself.  WHY: a FIFO opened O_RDONLY
         * blocks until a writer arrives, and a device node can block in its
         * open method — either would wedge this single broker process, denying
         * service to *every* worker/tenant (a cross-tenant DoS) since one bad
         * path in the export hangs the whole impersonation channel.  With
         * O_NONBLOCK the open returns immediately for every file type, then we
         * inspect what we actually got and only hand back regular files and
         * directories — the only types the gateway data plane ever serves.
         */
        fd = imp_openat2(rootfd, rel, req->open_flags | O_NONBLOCK, req->mode);
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
        *out_fd = fd;
        rep->rep_flags |= IMP_REP_HAS_FD;
        return 0;
    }

    case IMP_OP_STAT:
    case IMP_OP_LSTAT:
        fd = imp_openat2(rootfd, rel,
                         O_PATH | (req->op == IMP_OP_LSTAT ? O_NOFOLLOW : 0), 0);
        if (fd < 0) {
            return fd;
        }
        rc = fstatat(fd, "", &st, AT_EMPTY_PATH) == 0 ? 0 : -errno;
        close(fd);
        if (rc != 0) {
            return rc;
        }
        imp_fill_stat(&rep->st, &st);
        rep->rep_flags |= IMP_REP_HAS_STAT;
        return 0;

    case IMP_OP_TRUNCATE:
        fd = imp_openat2(rootfd, rel, O_WRONLY, 0);
        if (fd < 0) {
            return fd;
        }
        rc = ftruncate(fd, (off_t) req->length) == 0 ? 0 : -errno;
        close(fd);
        return rc;

    case IMP_OP_MKDIR:
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = mkdirat(pfd, base, req->mode) == 0 ? 0 : -errno;
        close(pfd);
        return rc;

    case IMP_OP_UNLINK:
    case IMP_OP_RMDIR:
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = unlinkat(pfd, base, req->op == IMP_OP_RMDIR ? AT_REMOVEDIR : 0) == 0
                 ? 0 : -errno;
        close(pfd);
        return rc;

    case IMP_OP_CHMOD:
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = fchmodat(pfd, base, req->mode, 0) == 0 ? 0 : -errno;
        close(pfd);
        return rc;

    case IMP_OP_CHOWN:
        /* gid only (uid is fixed by ownership); the mapped user must own it. */
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = fchownat(pfd, base, (uid_t) -1, (gid_t) req->mode,
                      AT_SYMLINK_NOFOLLOW) == 0 ? 0 : -errno;
        close(pfd);
        return rc;

    case IMP_OP_RENAME:
    case IMP_OP_RENAME_NOREPLACE:
    case IMP_OP_LINK:
        rel2 = imp_rel(req->path2);
        pfd  = imp_open_parent(rootfd, rel,  scratch,  &base);
        if (pfd < 0) {
            return pfd;
        }
        pfd2 = imp_open_parent(rootfd, rel2, scratch2, &base2);
        if (pfd2 < 0) {
            close(pfd);
            return pfd2;
        }
        if (req->op == IMP_OP_LINK) {
            rc = linkat(pfd, base, pfd2, base2, 0) == 0 ? 0 : -errno;
        } else {
            rc = imp_do_rename(pfd, base, pfd2, base2,
                               req->op == IMP_OP_RENAME_NOREPLACE) == 0
                 ? 0 : -errno;
        }
        close(pfd);
        close(pfd2);
        return rc;

    case IMP_OP_SETATTR:
        /* utimensat (+ optional fchownat) on the final component, NOFOLLOW.  As
         * the mapped user: chgrp/utimens on a file they own succeeds; a chown to
         * a different owner correctly fails (the broker holds no CAP_CHOWN). */
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = 0;
        if (req->attr_flags & IMP_ATTR_TIMES) {
            struct timespec ts[2];
            ts[0].tv_sec  = (time_t) req->atime_sec;
            ts[0].tv_nsec = (long)   req->atime_nsec;
            ts[1].tv_sec  = (time_t) req->mtime_sec;
            ts[1].tv_nsec = (long)   req->mtime_nsec;
            if (utimensat(pfd, base, ts, AT_SYMLINK_NOFOLLOW) != 0) {
                rc = -errno;
            }
        }
        if (rc == 0 && (req->attr_flags & IMP_ATTR_OWNER)) {
            uid_t u = (req->set_uid == (uint32_t) -1) ? (uid_t) -1
                                                      : (uid_t) req->set_uid;
            gid_t g = (req->set_gid == (uint32_t) -1) ? (gid_t) -1
                                                      : (gid_t) req->set_gid;
            if (fchownat(pfd, base, u, g, AT_SYMLINK_NOFOLLOW) != 0) {
                rc = -errno;
            }
        }
        close(pfd);
        return rc;

    case IMP_OP_SYMLINK:
        /* path = link location (root-relative); path2 = verbatim target string.
         * Only the link site is confined; a target pointing outside the root just
         * cannot be followed later (the confined open re-applies RESOLVE_BENEATH). */
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        rc = symlinkat(req->path2, pfd, base) == 0 ? 0 : -errno;
        close(pfd);
        return rc;

    case IMP_OP_READLINK: {
        ssize_t n;
        pfd = imp_open_parent(rootfd, rel, scratch, &base);
        if (pfd < 0) {
            return pfd;
        }
        n = readlinkat(pfd, base, data_out, data_max);
        close(pfd);
        if (n < 0) {
            return -errno;
        }
        rep->data_len   = (uint32_t) n;     /* link target -> trailing payload */
        rep->rep_flags |= IMP_REP_HAS_DATA;
        return 0;
    }

    case IMP_OP_GETXATTR:
    case IMP_OP_LISTXATTR: {
        ssize_t n;
        if (req->op == IMP_OP_GETXATTR && !imp_xattr_name_ok(req->path2)) {
            return -EPERM;
        }
        fd = imp_xattr_open(rootfd, rel);
        if (fd < 0) {
            return fd;
        }
        if (req->op == IMP_OP_GETXATTR) {
            n = fgetxattr(fd, req->path2, data_out, data_max);
        } else {
            n = flistxattr(fd, data_out, data_max);
        }
        close(fd);
        if (n < 0) {
            return -errno;                  /* ENODATA / ERANGE / EACCES ... */
        }
        if (req->op == IMP_OP_LISTXATTR) {
            /* Withhold non-user.* attribute NAMES from the worker (the per-name
             * GET/SET/REMOVE ops are already user.-only). */
            n = (ssize_t) imp_xattr_filter_user(data_out, (size_t) n);
        }
        rep->data_len   = (uint32_t) n;     /* value / name list -> reply payload */
        rep->rep_flags |= IMP_REP_HAS_DATA;
        return 0;
    }

    case IMP_OP_SETXATTR:
        if (!imp_xattr_name_ok(req->path2)) {
            return -EPERM;
        }
        fd = imp_xattr_open(rootfd, rel);
        if (fd < 0) {
            return fd;
        }
        rc = fsetxattr(fd, req->path2, data_in, data_in_len,
                       (int) req->mode) == 0 ? 0 : -errno;
        close(fd);
        return rc;

    case IMP_OP_REMOVEXATTR:
        if (!imp_xattr_name_ok(req->path2)) {
            return -EPERM;
        }
        fd = imp_xattr_open(rootfd, rel);
        if (fd < 0) {
            return fd;
        }
        rc = fremovexattr(fd, req->path2) == 0 ? 0 : -errno;
        close(fd);
        return rc;

    default:
        return -ENOSYS;
    }
}
