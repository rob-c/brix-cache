/*
 * xrootdfs_io.c - extracted concern
 * Phase-38 split of xrootdfs.c; behavior-identical.
 */
#include "xrootdfs_internal.h"


/* file handles (async mfile + read-ahead / write-back)                */


/* One pread against whichever backend this handle uses. */
ssize_t
afh_pread(afh *h, int64_t off, void *buf, size_t len, xrdc_status *st)
{
    if (h->wf != NULL) {
        return xrdc_webfile_pread(h->wf, off, buf, len, st);
    }
    return xrdc_mfile_pread(h->mf, off, buf, len, st);
}


/* Backend I/O for the shared iobuf engine: read dispatches web vs root via
 * afh_pread; write goes to the root:// mfile (web handles are read-only). */
ssize_t
afh_io_pread(void *be, int64_t off, void *buf, size_t n, xrdc_status *st)
{
    return afh_pread((afh *) be, off, buf, n, st);
}

int
afh_io_pwrite(void *be, int64_t off, const void *buf, size_t n, xrdc_status *st)
{
    return xrdc_mfile_pwrite(((afh *) be)->mf, off, buf, n, st);
}


/* Flush buffered writes. Caller MUST hold h->lock. 0 / -1 (st). */
int
afh_flush_wbuf(afh *h, xrdc_status *st)
{
    return xrdc_iobuf_flush(&h->io, st);
}


void
afh_free(afh *h)
{
    pthread_mutex_destroy(&h->lock);
    xrdc_iobuf_dispose(&h->io);
    free(h);
}


/* Open helper shared by open()/create(): writable + force tri-state. */
int
afh_open(const char *path, int writable, int force, struct fuse_file_info *fi)
{
    xrdc_status st;
    afh        *h = calloc(1, sizeof(*h));
    if (h == NULL) {
        return -ENOMEM;
    }
    pthread_mutex_init(&h->lock, NULL);
    h->writable = writable;
    xrdc_iobuf_init(&h->io, h, afh_io_pread, afh_io_pwrite, writable,
                    g_readahead, g_writeback);
    xrdc_status_clear(&st);

    /* HTTP(S)/WebDAV mounts are READ-ONLY (Range GET); reject write opens. */
    if (g_web) {
        if (writable) {
            afh_free(h);
            return -EROFS;
        }
        char pbuf[XRDC_PATH_MAX];
        h->wf = xrdc_webfile_open(&g_weburl, srv_path(path, pbuf, sizeof(pbuf)),
                                  g_bearer, g_web_verify, g_web_ca, g_max_stall,
                                  NULL, &st);
        if (h->wf == NULL) {
            afh_free(h);
            return xfs_err(&st);
        }
        fi->fh = (uint64_t) (uintptr_t) h;
        return 0;
    }

    /* phase-42 W4/W5: request inline compression when configured — on read opens
     * the server compresses responses (W4), on write opens it decompresses our
     * payloads (W5).  A server that doesn't support it returns plaintext (the
     * mfile learns read_codec/write_codec == 0). */
    char opq[48];
    const char *opaque = NULL;
    if (g_compress[0] != '\0') {
        snprintf(opq, sizeof(opq), "xrootd.compress=%s", g_compress);
        opaque = opq;
    }
    char pbuf[XRDC_PATH_MAX];
    h->mf = xrdc_mfile_open(xrdc_mgr_pick(g_mgr), srv_path(path, pbuf, sizeof(pbuf)),
                            writable, force, 0, opaque,
                            g_max_stall, g_max_retries, &st);
    if (h->mf == NULL) {
        afh_free(h);
        return xfs_err(&st);
    }
    fi->fh = (uint64_t) (uintptr_t) h;
    return 0;
}


int
xfs_open(const char *path, struct fuse_file_info *fi)
{
    int acc = fi->flags & O_ACCMODE;
    if (acc == O_RDONLY) {
        return afh_open(path, 0, 0, fi);
    }
    /* O_TRUNC -> overwrite (force 1), else update in place (force 2). */
    return afh_open(path, 1, xrootd_open_force_for_open(fi->flags), fi);
}


int
xfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void) mode;
    /* O_EXCL → create-new (force=0, fail if exists); else truncate-create. */
    return afh_open(path, 1, xrootd_open_force_for_create(fi->flags), fi);
}


int
xfs_read(const char *path, char *buf, size_t size, off_t offset,
         struct fuse_file_info *fi)
{
    afh        *h = (afh *) (uintptr_t) fi->fh;
    xrdc_status st;
    ssize_t     r;

    (void) path;
    if (h == NULL) {
        return -EBADF;
    }
    xrdc_status_clear(&st);
    pthread_mutex_lock(&h->lock);
    r = xrdc_iobuf_read(&h->io, offset, buf, size, &st);
    pthread_mutex_unlock(&h->lock);
    return r < 0 ? xfs_err(&st) : (int) r;
}


int
xfs_write(const char *path, const char *buf, size_t size, off_t offset,
          struct fuse_file_info *fi)
{
    if (g_web) return -EROFS;
    afh        *h = (afh *) (uintptr_t) fi->fh;
    xrdc_status st;
    int         rc;

    (void) path;
    if (h == NULL || !h->writable) {
        return -EBADF;
    }
    xrdc_status_clear(&st);
    pthread_mutex_lock(&h->lock);
    rc = xrdc_iobuf_write(&h->io, offset, buf, size, &st);
    if (rc == 0 && (int64_t) offset + (int64_t) size > h->wsize) {
        h->wsize = (int64_t) offset + (int64_t) size;   /* track logical EOF */
    }
    pthread_mutex_unlock(&h->lock);
    return rc != 0 ? xfs_err(&st) : (int) size;
}


int
xfs_flush(const char *path, struct fuse_file_info *fi)
{
    if (g_web) return 0;
    afh        *h = (afh *) (uintptr_t) fi->fh;
    xrdc_status st;
    int         rc;
    (void) path;
    if (h == NULL) {
        return 0;
    }
    xrdc_status_clear(&st);
    pthread_mutex_lock(&h->lock);
    rc = afh_flush_wbuf(h, &st);
    pthread_mutex_unlock(&h->lock);
    return rc != 0 ? xfs_err(&st) : 0;
}


int
xfs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    if (g_web) return 0;
    afh        *h = (afh *) (uintptr_t) fi->fh;
    xrdc_status st;
    int         rc;
    (void) path; (void) datasync;
    if (h == NULL) {
        return 0;
    }
    xrdc_status_clear(&st);
    pthread_mutex_lock(&h->lock);
    rc = afh_flush_wbuf(h, &st);
    if (rc == 0) {
        rc = xrdc_mfile_sync(h->mf, &st);
    }
    pthread_mutex_unlock(&h->lock);
    return rc != 0 ? xfs_err(&st) : 0;
}


int
xfs_release(const char *path, struct fuse_file_info *fi)
{
    afh        *h = (afh *) (uintptr_t) fi->fh;
    xrdc_status st;
    (void) path;
    if (h == NULL) {
        return 0;
    }
    xrdc_status_clear(&st);
    pthread_mutex_lock(&h->lock);
    if (h->wf != NULL) {
        xrdc_webfile_close(h->wf, &st);
        h->wf = NULL;
    } else {
        (void) afh_flush_wbuf(h, &st);
        (void) xrdc_mfile_close(h->mf, &st);
    }
    pthread_mutex_unlock(&h->lock);
    afh_free(h);
    fi->fh = 0;
    return 0;
}
