/*
 * copy_gsiftp.c — gsiftp:// / ftp:// single-file transfers for brix_copy().
 *
 * WHAT: route one copy whose source or destination is a GridFTP URL: remote →
 *       local (RETR) and local → remote (STOR), with the local side going through
 *       the client VFS so a download commits atomically like every other scheme.
 * WHY:  GridFTP is still the transfer protocol of record at a large part of the
 *       WLCG estate, and until now xrdcp could not speak it at all — a gsiftp://
 *       argument fell through to the root:// URL parser and died as a usage error.
 * HOW:  brix_copy() intercepts the scheme before its root:// parse and calls
 *       copy_gsiftp(); the direction is decided here, the session engine
 *       (protocols/ftp) does the protocol work, and the payload moves through
 *       sink/source adapters over brix_vfs. Remote→remote and recursive copies are
 *       refused explicitly rather than half-supported.
 */
#include "copy_internal.h"

#include "protocols/ftp/ftp_client.h"

/* Sequential adapter over one VFS handle: the FTP data channel is a stream, so
 * the engine hands over bytes in order and the offset is kept here. */
typedef struct {
    brix_vfs_file *vf;
    int64_t        off;
} gftp_local_io;

static int
gftp_sink_local(void *ctx, const uint8_t *buf, size_t n, brix_status *st)
{
    gftp_local_io *lc = (gftp_local_io *) ctx;

    if (brix_vfs_pwrite(lc->vf, lc->off, buf, n, st) != 0) {
        return -1;
    }
    lc->off += (int64_t) n;
    return 0;
}


static ssize_t
gftp_src_local(void *ctx, uint8_t *buf, size_t cap, brix_status *st)
{
    gftp_local_io *lc = (gftp_local_io *) ctx;
    ssize_t        n = brix_vfs_pread(lc->vf, lc->off, buf, cap, st);

    if (n > 0) {
        lc->off += n;
    }
    return n;
}


static void
gftp_vfs_opts(const brix_copy_opts *o, int64_t expected, brix_vfs_open_opts *v)
{
    v->io_uring        = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;
    v->io_uring_direct = (o != NULL) ? o->io_uring_direct : 0;
    v->expected_size   = expected;
    v->cred            = NULL;
}


/* Open a session for `u`, allocated on the heap: the session carries tens of
 * kilobytes of control buffers and must not sit on a caller's stack. */
static brix_ftp_sess *
gftp_session(const brix_ftpurl *u, const brix_opts *co, brix_status *st)
{
    brix_ftp_sess *s = calloc(1, sizeof(*s));

    if (s == NULL) {
        brix_status_set(st, XRDC_EIO, 0, "gsiftp: out of memory");
        return NULL;
    }
    if (brix_ftp_session_open(s, u, co, st) != 0) {
        free(s);
        return NULL;
    }
    return s;
}


static void
gftp_session_free(brix_ftp_sess *s)
{
    brix_ftp_close(s);
    free(s);
}


/* "…/dir/" or an existing local directory takes the source's basename. */
static void
gftp_join_basename(const char *srcpath, const char *dst, char *out, size_t sz)
{
    const char *base = strrchr(srcpath, '/');
    struct stat sb;
    size_t      dlen = strlen(dst);

    base = (base != NULL) ? base + 1 : srcpath;
    if (dlen > 0 && dst[dlen - 1] == '/') {
        snprintf(out, sz, "%s%s", dst, base);
        return;
    }
    if (stat(dst, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        snprintf(out, sz, "%s/%s", dst, base);
        return;
    }
    snprintf(out, sz, "%s", dst);
}


static int
gftp_download(const brix_ftpurl *su, const char *dst, const brix_copy_opts *o,
              const brix_opts *co, brix_status *st)
{
    brix_ftp_sess     *s;
    brix_vfs_file     *vf = NULL;
    brix_vfs_open_opts vopts;
    gftp_local_io      lc;
    char               target[XRDC_PATH_MAX];
    int64_t            size = -1, mtime = -1;
    int                rc;

    s = gftp_session(su, co, st);
    if (s == NULL) {
        return -1;
    }
    if (brix_ftp_stat(s, su->path, &size, &mtime, st) != 0) {
        gftp_session_free(s);
        return -1;
    }
    gftp_join_basename(su->path, dst, target, sizeof(target));
    if (o != NULL && o->dry_run) {
        if (!o->silent) {
            fprintf(stderr, "xrdcp: (dry run) would copy %s -> %s\n", su->path,
                    target);
        }
        gftp_session_free(s);
        return 0;
    }

    gftp_vfs_opts(o, size, &vopts);
    if (brix_vfs_open(target, XRDC_VFS_WRITE | XRDC_VFS_FORCE, &vopts, &vf, st)
        != 0) {
        gftp_session_free(s);
        return -1;
    }
    lc.vf = vf;
    lc.off = 0;
    rc = brix_ftp_retr(s, su->path, gftp_sink_local, &lc, o, size, st);
    if (rc == 0 && size >= 0 && lc.off != size) {
        brix_status_set(st, XRDC_EIO, 0,
                        "gsiftp: short transfer (%lld of %lld bytes)",
                        (long long) lc.off, (long long) size);
        rc = -1;
    }
    if (rc == 0) {
        rc = brix_vfs_commit(vf, st);
    } else {
        brix_vfs_abort(vf);
    }
    brix_vfs_close(vf);
    gftp_session_free(s);
    return rc;
}


static int
gftp_upload(const char *src, const brix_ftpurl *du, const brix_copy_opts *o,
            const brix_opts *co, brix_status *st)
{
    brix_ftp_sess     *s;
    brix_vfs_file     *vf = NULL;
    brix_vfs_open_opts vopts;
    brix_vfs_stat      vst;
    brix_status        tmp;
    gftp_local_io      lc;
    char               target[XRDC_PATH_MAX];
    int64_t            total = -1;
    size_t             plen;
    int                rc;

    gftp_vfs_opts(o, -1, &vopts);
    if (brix_vfs_open(src, XRDC_VFS_READ, &vopts, &vf, st) != 0) {
        return -1;
    }
    brix_status_clear(&tmp);
    if (brix_vfs_fstat(vf, &vst, &tmp) == 0) {
        total = vst.size;
    }

    plen = strlen(du->path);
    if (plen > 0 && du->path[plen - 1] == '/') {
        const char *base = strrchr(src, '/');

        snprintf(target, sizeof(target), "%s%s", du->path,
                 (base != NULL) ? base + 1 : src);
    } else {
        snprintf(target, sizeof(target), "%s", du->path);
    }

    if (o != NULL && o->dry_run) {
        if (!o->silent) {
            fprintf(stderr, "xrdcp: (dry run) would copy %s -> %s\n", src,
                    target);
        }
        brix_vfs_close(vf);
        return 0;
    }

    s = gftp_session(du, co, st);
    if (s == NULL) {
        brix_vfs_close(vf);
        return -1;
    }
    lc.vf = vf;
    lc.off = 0;
    rc = brix_ftp_stor(s, target, gftp_src_local, &lc, o, total, st);
    gftp_session_free(s);
    brix_vfs_close(vf);
    return rc;
}


/*
 * copy_gsiftp — the scheme's entry point from brix_copy().
 *
 * Exactly one endpoint may be a GridFTP URL: the client has no third-party-copy
 * verb wired for this scheme, so a remote→remote request is a usage error rather
 * than a silent double-hop through the local disk.
 */
int
copy_gsiftp(const char *src, const char *dst, const brix_copy_opts *o,
            const brix_opts *co, brix_status *st)
{
    brix_ftpurl u;
    int         src_ftp = brix_is_ftp_url(src);
    int         dst_ftp = brix_is_ftp_url(dst);

    if (src_ftp && dst_ftp) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "gsiftp: third-party copy between GridFTP endpoints is "
                        "not supported");
        return -1;
    }
    if ((src_ftp && brix_is_web_url(dst)) || (dst_ftp && brix_is_web_url(src))) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "gsiftp: copy between gsiftp:// and http/dav/s3 "
                        "endpoints is not supported");
        return -1;
    }
    if (o != NULL && o->recursive) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "gsiftp: recursive copy is not supported");
        return -1;
    }
    if (src_ftp) {
        if (brix_ftpurl_parse(src, &u) != 0) {
            brix_status_set(st, XRDC_EUSAGE, 0, "gsiftp: bad URL: %s", src);
            return -1;
        }
        return gftp_download(&u, dst, o, co, st);
    }
    if (brix_ftpurl_parse(dst, &u) != 0) {
        brix_status_set(st, XRDC_EUSAGE, 0, "gsiftp: bad URL: %s", dst);
        return -1;
    }
    return gftp_upload(src, &u, o, co, st);
}
