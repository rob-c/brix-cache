/*
 * xrootdfs_meta.c - extracted concern
 * Phase-38 split of xrootdfs.c; behavior-identical.
 */
#include "xrootdfs_internal.h"


/* metadata operations (sync pool + retry)                             */

/* Report a file we currently hold open for write whose committed final path the
 * server cannot yet stat (writes are staged to a temp object and renamed into
 * place only on close).  Without this, the getattr the kernel issues right after
 * CREATE — to finish the open — fails ENOENT and the create()/open() call fails.
 * Returns 1 (handled, stbuf filled) when fi is a writable handle, else 0. */
static int
getattr_from_open_writer(struct fuse_file_info *fi, struct stat *stbuf)
{
    afh *h;

    if (fi == NULL || fi->fh == 0) {
        return 0;
    }
    h = (afh *) (uintptr_t) fi->fh;
    if (h == NULL || !h->writable) {
        return 0;
    }
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode  = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size  = (off_t) h->wsize;
    return 1;
}

int
xfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    xrdc_statinfo si;
    xrdc_status   st;
    if (strcmp(path, "/") == 0) {
        memset(stbuf, 0, sizeof(*stbuf));
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }
    xrdc_status_clear(&st);
    if (g_web) {
        char pbuf[XRDC_PATH_MAX];
        if (xrdc_web_stat(&g_weburl, srv_path(path, pbuf, sizeof(pbuf)), g_bearer,
                          g_web_verify, g_web_ca, &si, &st) != 0) {
            return xfs_err(&st);
        }
        xfs_fill_stat(&si, stbuf);
        return 0;
    }
    char pbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_stat a = { srv_path(path, pbuf, sizeof(pbuf)), &si };
    int rc = xfs_meta(xrdc_fuse_op_lstat, &a, &st);   /* lstat: symlinks present as S_IFLNK */
    if (rc != 0) {
        /* A newly created file we still hold open is staged server-side until
         * close, so its final path is not yet visible to stat (ENOENT). Report
         * it from the open write handle instead of failing the open. */
        if (rc == -ENOENT && getattr_from_open_writer(fi, stbuf)) {
            return 0;
        }
        return rc;
    }
    xfs_fill_stat(&si, stbuf);
    return 0;
}


int
xfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
            struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
    xrdc_dirent *ents = NULL;
    size_t       n = 0, i;
    xrdc_status  st;
    (void) offset; (void) fi; (void) flags;
    xrdc_status_clear(&st);
    if (g_web) {
        char pbuf[XRDC_PATH_MAX];
        if (xrdc_web_readdir(&g_weburl, srv_path(path, pbuf, sizeof(pbuf)), g_bearer,
                             g_web_verify, g_web_ca, &ents, &n, &st) != 0) {
            return xfs_err(&st);
        }
    } else {
        char pbuf[XRDC_PATH_MAX];
        struct xrdc_fuse_ctx_dir a = { srv_path(path, pbuf, sizeof(pbuf)), &ents, &n };
        int rc = xfs_meta(xrdc_fuse_op_dirlist, &a, &st);
        if (rc != 0) {
            return rc;
        }
    }
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    for (i = 0; i < n; i++) {
        struct stat sb;
        struct stat *psb = NULL;
        enum fuse_fill_dir_flags ff = 0;
        if (ents[i].have_stat) {
            xfs_fill_stat(&ents[i].st, &sb);
            psb = &sb;
            ff = FUSE_FILL_DIR_PLUS;
        }
        filler(buf, ents[i].name, psb, 0, ff);
    }
    free(ents);
    return 0;
}


int
xfs_mkdir(const char *path, mode_t mode)
{
    if (g_web) return -EROFS;
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_mkdir a = { srv_path(path, pbuf, sizeof(pbuf)), (int) (mode & 0777) };
    return xfs_meta(xrdc_fuse_op_mkdir, &a, &st);
}


int
xfs_unlink(const char *path)
{
    if (g_web) return -EROFS;
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    return xfs_meta(xrdc_fuse_op_rm, (void *) srv_path(path, pbuf, sizeof(pbuf)), &st);
}


int
xfs_rmdir(const char *path)
{
    if (g_web) return -EROFS;
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    return xfs_meta(xrdc_fuse_op_rmdir, (void *) srv_path(path, pbuf, sizeof(pbuf)), &st);
}


int
xfs_rename(const char *from, const char *to, unsigned int flags)
{
    if (g_web) return -EROFS;
    if (flags != 0) {
        return -EINVAL;
    }
    xrdc_status st; xrdc_status_clear(&st);
    char fbuf[XRDC_PATH_MAX], tbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_mv a = { srv_path(from, fbuf, sizeof(fbuf)),
                        srv_path(to, tbuf, sizeof(tbuf)) };
    return xfs_meta(xrdc_fuse_op_mv, &a, &st);
}


int
xfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    if (g_web) return -EROFS;
    (void) fi;
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_chmod a = { srv_path(path, pbuf, sizeof(pbuf)), (int) (mode & 0777) };
    return xfs_meta(xrdc_fuse_op_chmod, &a, &st);
}


int
xfs_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    if (g_web) return -EROFS;
    (void) fi;
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_trunc a = { srv_path(path, pbuf, sizeof(pbuf)), (int64_t) size };
    return xfs_meta(xrdc_fuse_op_trunc, &a, &st);
}


/* utimens/chown use the vendor kXR_setattr extension when the server advertises
 * it; otherwise they succeed as no-ops so `cp -p` still works against a stock
 * server (XRootD has no base-protocol set-time/owner op). */
int
xfs_utimens(const char *path, const struct timespec tv[2],
            struct fuse_file_info *fi)
{
    if (g_web) return -EROFS;
    (void) fi;
    if (!g_ext_setattr) {
        return 0;   /* honest no-op fallback */
    }
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_setattr a = { srv_path(path, pbuf, sizeof(pbuf)),
                             1, { tv[0], tv[1] }, 0, 0, 0 };
    return xfs_meta(xrdc_fuse_op_setattr, &a, &st);
}


int
xfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
    if (g_web) return -EROFS;
    (void) fi;
    if (!g_ext_setattr) {
        return 0;
    }
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_setattr a;
    memset(&a, 0, sizeof(a));
    a.path = srv_path(path, pbuf, sizeof(pbuf));
    a.set_owner = 1;
    a.uid = (uint32_t) uid;
    a.gid = (uint32_t) gid;
    return xfs_meta(xrdc_fuse_op_setattr, &a, &st);
}


/* symlink / hard link / readlink — vendor extensions; ENOTSUP when unadvertised. */
int
xfs_symlink(const char *target, const char *linkpath)
{
    if (g_web) return -EROFS;
    if (!g_ext_symlink) {
        return -ENOTSUP;
    }
    xrdc_status st; xrdc_status_clear(&st);
    /* `target` is the symlink's literal content (stored verbatim); only `linkpath`
     * is a namespace path to create, so only it is rebased. */
    char lbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_link2 a = { target, srv_path(linkpath, lbuf, sizeof(lbuf)) };
    return xfs_meta(xrdc_fuse_op_symlink, &a, &st);
}


int
xfs_readlink(const char *path, char *buf, size_t size)
{
    if (g_web) return -EINVAL;
    if (!g_ext_readlink || size == 0) {
        return -ENOTSUP;
    }
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    const char *sp = srv_path(path, pbuf, sizeof(pbuf));
    /* readlink is read-only + idempotent → retry-safe across a transient drop. */
    int tries = g_max_retries + 1;
    while (tries-- > 0) {
        xrdc_conn *c = xrdc_pool_checkout(g_pool, &st);
        if (c == NULL) {
            if (tries > 0 && xrdc_status_retryable(&st)) { continue; }
            return xfs_err(&st);
        }
        ssize_t n = xrdc_readlink(c, sp, buf, size, &st);
        xrdc_pool_checkin(g_pool, c, n >= 0 ? 1 : xfs_conn_healthy(&st));
        if (n >= 0) {
            return 0;   /* FUSE: buf is NUL-terminated, return 0 on success */
        }
        if (tries == 0 || !xrdc_status_retryable(&st)) {
            return xfs_err(&st);
        }
    }
    return xfs_err(&st);
}


int
xfs_statfs(const char *path, struct statvfs *stbuf)
{
    char               text[1024];
    xrdc_status        st;
    unsigned long long total = 0, freeb = 0;

    memset(stbuf, 0, sizeof(*stbuf));
    if (g_web) {                               /* no Qspace over WebDAV */
        stbuf->f_bsize = stbuf->f_frsize = 1024 * 1024;
        stbuf->f_namemax = 255;
        return 0;
    }
    xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct ctx_qspace a = { srv_path((path && path[0]) ? path : "/", pbuf,
                                     sizeof(pbuf)), text, sizeof(text) };
    int rc = xfs_meta(op_qspace, &a, &st);
    if (rc != 0) {
        return rc;
    }
    xrdc_parse_qspace(text, &total, &freeb);

    stbuf->f_bsize   = 1024 * 1024;
    stbuf->f_frsize  = stbuf->f_bsize;
    stbuf->f_blocks  = (fsblkcnt_t) (total / stbuf->f_bsize);
    stbuf->f_bfree   = (fsblkcnt_t) (freeb / stbuf->f_bsize);
    stbuf->f_bavail  = stbuf->f_bfree;
    stbuf->f_namemax = 255;
    return 0;
}


int
xfs_access(const char *path, int mask)
{
    if (g_web) return (mask & W_OK) ? -EROFS : 0;
    xrdc_statinfo si;
    xrdc_status   st;
    (void) mask;
    if (strcmp(path, "/") == 0) {
        return 0;
    }
    xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_stat a = { srv_path(path, pbuf, sizeof(pbuf)), &si };
    return xfs_meta(xrdc_fuse_op_stat, &a, &st);
}
