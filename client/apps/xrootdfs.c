/*
 * xrootdfs.c — XRootD FUSE mount on the async, network-resilient core (default).
 *
 * WHAT: The XRootD FUSE driver. The async, multi-in-flight transport (aio.c) is the
 *       default and only built-in behavior; the simple synchronous driver lives in
 *       xrootdfs_legacy.c (reachable via `xrd mount --legacy`). Open files
 *       ride the asynchronous, multi-in-flight transport (aio.c) via resilient
 *       handles (xrdc_mfile, aio_mgr.c): a connection drop or a server restart is
 *       recovered transparently — the file is reopened (fresh handle, never
 *       re-truncated) and the read/write is re-issued at the same offset, so a
 *       mid-transfer cat/dd/cp survives with no EIO and byte-exact data.
 * WHY:  "Faster, more reliable, tolerant to bad wifi from a laptop abroad."
 *       Pipelining over a shared connection pool hides RTT; per-request adaptive
 *       deadlines + reconnect + a kXR_ping heartbeat handle latency, loss, and
 *       transient disconnects.
 * ALT TRANSPORT: when the endpoint is http/https/dav/davs the SAME namespace is
 *       served READ-ONLY over HTTP/WebDAV (webfile.c: PROPFIND stat/readdir +
 *       ranged GET on a persistent socket) instead of root://, so one driver can
 *       mount either protocol against this module or an official XRootD XrdHttp
 *       endpoint — enabling an apples-to-apples root-vs-https comparison. A URL
 *       path component (root://h/data or https://h/data) roots the mount at that
 *       subtree (srv_path).
 * HOW:  Two subsystems, both reusing the proven libxrdc code:
 *         * metadata/path ops (getattr, readdir, mkdir, chmod, statfs, xattr, …)
 *           run the existing synchronous ops on a thread-safe pool, wrapped in a
 *           small retry-on-transient-error loop (xfs_meta) so a brief drop is
 *           ridden out rather than surfaced;
 *         * file I/O (open/read/write/flush/fsync/release) uses xrdc_mfile on the
 *           async manager (xrdc_mgr) — handle resumption + pipelining — under the
 *           same read-ahead / write-back buffering as the classic driver.
 *       Errors map to -errno via xrdc_kxr_to_errno. SIGPIPE is ignored so a dropped
 *       peer never kills the mount (TLS writes have no per-call MSG_NOSIGNAL).
 *
 * Clean-room: composes the public libxrdc async API + libfuse3 only. No XrdCl.
 */
#define FUSE_USE_VERSION 31

#include "xrdc.h"
#include "aio.h"
#include "posix_map.h"       /* shared statinfo→stat / Qspace / listxattr xlate */
#include "iobuf.h"           /* shared read-ahead / write-back engine */
#include "fuse_ops.h"        /* shared pooled meta-op runner + op thunks */
#include "compat/crypto.h"   /* xrootd_crypto_init (libxrdproto SHA/HMAC kernels) */

#include <fuse3/fuse.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>

/* Metadata subsystem: a sync connection pool + the parsed endpoint/opts. */
static xrdc_pool *g_pool;
static xrdc_url   g_url;
static xrdc_opts  g_opts;
static int        g_max_conns = 8;       /* metadata pool size; --max-conns */

/* HTTP(S)/WebDAV transport: selected when the endpoint is http/https/dav/davs.
 * A read-only mount (getattr/readdir/open/read) over the same namespace, for a
 * root-vs-https protocol/performance comparison. g_web=1 routes every callback to
 * the webfile.c layer instead of the root:// pool/mgr. */
static int          g_web = 0;
static xrdc_weburl  g_weburl;
static const char  *g_bearer = NULL;     /* --token / $BEARER_TOKEN (else anon) */
static int          g_web_verify = 1;    /* TLS server-cert verification (https) */
static const char  *g_web_ca = NULL;     /* CA hash dir (else $X509_CERT_DIR) */
static char         g_base[XRDC_PATH_MAX] = "";  /* URL path prefix (export base) */

/* Map a FUSE path ("/file") to the server path under the export base. With an
 * empty base the FUSE path is used verbatim; with base "/data" → "/data/file"
 * and "/" → "/data". Shared by BOTH transports (root:// and http/WebDAV) so a
 * URL like root://host/data or https://host/data mounts that subtree. */
static const char *
srv_path(const char *p, char *buf, size_t sz)
{
    if (g_base[0] == '\0') {
        return p;
    }
    if (strcmp(p, "/") == 0) {
        return g_base;
    }
    size_t bl = strlen(g_base);
    size_t pl = strlen(p);
    if (bl + pl + 1 > sz) {            /* impossible for real paths — fail safe */
        return g_base;
    }
    memcpy(buf, g_base, bl);
    memcpy(buf + bl, p, pl + 1);       /* includes the NUL */
    return buf;
}

/* File-I/O subsystem: the async manager (loop + connection pool for mfiles). */
static xrdc_mgr  *g_mgr;
static int        g_streams     = 4;     /* async data connections; --streams */
static int        g_max_stall   = 60000; /* reconnect patience ms; --max-stall */
static int        g_keepalive   = 15000; /* heartbeat-after-idle ms; --keepalive */
static int        g_max_retries = 5;     /* transient retries; --max-retries */

/* Kernel-side caching policy (set in xfs_init). */
static double     g_attr_timeout  = 1.0;
static double     g_entry_timeout = 1.0;
static int        g_kernel_cache  = 0;
static int        g_xattr         = 0;
/* phase-42 W4: -o compress=<codec> / --compress <codec> — request inline read
 * compression on every read open (transparently inflated by xrdc_mfile).  Empty
 * = plaintext (default). */
static char       g_compress[32]  = "";

/* Vendor POSIX-extension capabilities, probed once at mount via kXR_Qconfig
 * "xrdfs.ext". When a capability is absent the driver keeps the honest fallback
 * (utimens/chown succeed as no-ops so `cp -p` still works; symlink/link → ENOTSUP). */
static int        g_ext_setattr   = 0;
static int        g_ext_symlink   = 0;
static int        g_ext_readlink  = 0;
static int        g_ext_link      = 0;

/* Per-handle I/O buffering sizes (0 disables). */
static size_t     g_readahead = 1024 * 1024;
static size_t     g_writeback = 1024 * 1024;

#define XFS_CKS_XATTR_PFX "user.XrdCks."

/* ------------------------------------------------------------------ */
/* error mapping + helpers                                              */
/* ------------------------------------------------------------------ */

/* Error mapping + the pooled metadata-op runner now live in lib/fuse_ops.c and
 * are shared with the legacy driver.  These keep the driver-local spellings as
 * thin wrappers: xfs_err/xfs_conn_healthy are used throughout the read/write/
 * open paths, and xfs_meta binds the runner to this driver's pool + retry budget
 * (g_max_retries > 0 → the resilient retry+backoff behaviour). */
static int
xfs_err(const xrdc_status *st)
{
    return xrdc_fuse_errno(st);
}

static int
xfs_conn_healthy(const xrdc_status *st)
{
    return xrdc_fuse_conn_healthy(st);
}

static int
xfs_meta(xrdc_fuse_op_fn fn, void *ctx, xrdc_status *st)
{
    return xrdc_fuse_run(g_pool, g_max_retries, fn, ctx, st);
}

static void
xfs_fill_stat(const xrdc_statinfo *si, struct stat *stbuf)
{
    /* allow_symlink=1: the async getattr uses lstat, so kXR_other → S_IFLNK. */
    xrdc_statinfo_to_stat(si, 1, stbuf);
}

/* ------------------------------------------------------------------ */
/* metadata operations (sync pool + retry)                             */
/* ------------------------------------------------------------------ */

static int
xfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    xrdc_statinfo si;
    xrdc_status   st;
    (void) fi;
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
        return rc;
    }
    xfs_fill_stat(&si, stbuf);
    return 0;
}

static int
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

static int
xfs_mkdir(const char *path, mode_t mode)
{
    if (g_web) return -EROFS;
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_mkdir a = { srv_path(path, pbuf, sizeof(pbuf)), (int) (mode & 0777) };
    return xfs_meta(xrdc_fuse_op_mkdir, &a, &st);
}

static int
xfs_unlink(const char *path)
{
    if (g_web) return -EROFS;
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    return xfs_meta(xrdc_fuse_op_rm, (void *) srv_path(path, pbuf, sizeof(pbuf)), &st);
}

static int
xfs_rmdir(const char *path)
{
    if (g_web) return -EROFS;
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    return xfs_meta(xrdc_fuse_op_rmdir, (void *) srv_path(path, pbuf, sizeof(pbuf)), &st);
}

static int
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

static int
xfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    if (g_web) return -EROFS;
    (void) fi;
    xrdc_status st; xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_chmod a = { srv_path(path, pbuf, sizeof(pbuf)), (int) (mode & 0777) };
    return xfs_meta(xrdc_fuse_op_chmod, &a, &st);
}

static int
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
static int
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

static int
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
static int
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

static int
xfs_link(const char *from, const char *to)
{
    if (g_web) return -EROFS;
    if (!g_ext_link) {
        return -ENOTSUP;
    }
    xrdc_status st; xrdc_status_clear(&st);
    char fbuf[XRDC_PATH_MAX], tbuf[XRDC_PATH_MAX];
    struct xrdc_fuse_ctx_link2 a = { srv_path(from, fbuf, sizeof(fbuf)),
                           srv_path(to, tbuf, sizeof(tbuf)) };
    return xfs_meta(xrdc_fuse_op_link, &a, &st);
}

static int
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

struct ctx_qspace { const char *path; char *out; size_t outsz; };
static int op_qspace(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_qspace *a = v; return xrdc_query(c, kXR_Qspace, a->path, a->out, a->outsz, st); }

static int
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

static int
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

/* ------------------------------------------------------------------ */
/* file handles (async mfile + read-ahead / write-back)                */
/* ------------------------------------------------------------------ */

typedef struct {
    xrdc_mfile     *mf;             /* root:// async handle (NULL on web mounts) */
    xrdc_webfile   *wf;            /* http(s)/WebDAV handle (NULL on root mounts) */
    pthread_mutex_t lock;
    int             writable;
    xrdc_iobuf      io;   /* shared read-ahead / write-back engine (iobuf.c) */
} afh;

/* One pread against whichever backend this handle uses. */
static ssize_t
afh_pread(afh *h, int64_t off, void *buf, size_t len, xrdc_status *st)
{
    if (h->wf != NULL) {
        return xrdc_webfile_pread(h->wf, off, buf, len, st);
    }
    return xrdc_mfile_pread(h->mf, off, buf, len, st);
}

/* Backend I/O for the shared iobuf engine: read dispatches web vs root via
 * afh_pread; write goes to the root:// mfile (web handles are read-only). */
static ssize_t
afh_io_pread(void *be, int64_t off, void *buf, size_t n, xrdc_status *st)
{
    return afh_pread((afh *) be, off, buf, n, st);
}
static int
afh_io_pwrite(void *be, int64_t off, const void *buf, size_t n, xrdc_status *st)
{
    return xrdc_mfile_pwrite(((afh *) be)->mf, off, buf, n, st);
}

/* Flush buffered writes. Caller MUST hold h->lock. 0 / -1 (st). */
static int
afh_flush_wbuf(afh *h, xrdc_status *st)
{
    return xrdc_iobuf_flush(&h->io, st);
}

static void
afh_free(afh *h)
{
    pthread_mutex_destroy(&h->lock);
    xrdc_iobuf_dispose(&h->io);
    free(h);
}

/* Open helper shared by open()/create(): writable + force tri-state. */
static int
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

static int
xfs_open(const char *path, struct fuse_file_info *fi)
{
    int acc = fi->flags & O_ACCMODE;
    if (acc == O_RDONLY) {
        return afh_open(path, 0, 0, fi);
    }
    if (fi->flags & O_TRUNC) {
        return afh_open(path, 1, 1 /*truncate*/, fi);
    }
    return afh_open(path, 1, 2 /*update in place*/, fi);
}

static int
xfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void) mode;
    /* O_EXCL → create-new (force=0, fail if exists); else truncate-create. */
    return afh_open(path, 1, (fi->flags & O_EXCL) ? 0 : 1, fi);
}

static int
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

static int
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
    pthread_mutex_unlock(&h->lock);
    return rc != 0 ? xfs_err(&st) : (int) size;
}

static int
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

static int
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

static int
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

/* ------------------------------------------------------------------ */
/* extended attributes (opt-in --xattr) — sync pool                    */
/* ------------------------------------------------------------------ */

static const char *
xfs_xattr_to_fattr(const char *name)
{
    if (strncmp(name, "user.", 5) == 0 && name[5] != '\0') {
        return name + 5;
    }
    return NULL;
}

struct ctx_cks { const char *path; const char *algo; char *hex; size_t hexsz; };
static int op_cks(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_cks *a = v; return xrdc_query_cksum(c, a->path, a->algo, a->hex, a->hexsz, st); }

struct ctx_faget { const char *path; const char *name; void *val; size_t bufsz; size_t *vlen; };
static int op_faget(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_faget *a = v; return xrdc_fattr_get(c, a->path, a->name, a->val, a->bufsz, a->vlen, st); }

static int
xfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
    if (g_web) return -ENOTSUP;
    xrdc_status st;
    int         rc;
    size_t      vlen = 0;
    const char *fname;

    if (!g_xattr) {
        return -ENOTSUP;
    }
    xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    path = srv_path(path, pbuf, sizeof(pbuf));

    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        const char *algo = name + sizeof(XFS_CKS_XATTR_PFX) - 1;
        char        hex[160];
        if (algo[0] == '\0') {
            return -ENODATA;
        }
        struct ctx_cks a = { path, algo, hex, sizeof(hex) };
        rc = xfs_meta(op_cks, &a, &st);
        if (rc != 0) {
            return rc;
        }
        vlen = strlen(hex);
        if (size == 0) {
            return (int) vlen;
        }
        if (vlen > size) {
            return -ERANGE;
        }
        memcpy(value, hex, vlen);
        return (int) vlen;
    }

    fname = xfs_xattr_to_fattr(name);
    if (fname == NULL) {
        return -ENODATA;
    }
    struct ctx_faget a = { path, fname, value, size, &vlen };
    rc = xfs_meta(op_faget, &a, &st);
    if (rc != 0) {
        return rc;
    }
    if (size == 0) {
        return (int) vlen;
    }
    if (vlen > size) {
        return -ERANGE;
    }
    return (int) vlen;
}

struct ctx_faset { const char *path; const char *name; const void *val; size_t vlen; int create_only; };
static int op_faset(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_faset *a = v;
  return xrdc_fattr_set(c, a->path, a->name, a->val, a->vlen, a->create_only, st); }

static int
xfs_setxattr(const char *path, const char *name, const char *value,
             size_t size, int flags)
{
    if (g_web) return -EROFS;
    xrdc_status st;
    const char *fname;
    if (!g_xattr) {
        return -ENOTSUP;
    }
    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        return -EACCES;
    }
    fname = xfs_xattr_to_fattr(name);
    if (fname == NULL) {
        return -ENOTSUP;
    }
    xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct ctx_faset a = { srv_path(path, pbuf, sizeof(pbuf)), fname, value, size,
                           (flags & XATTR_CREATE) ? 1 : 0 };
    return xfs_meta(op_faset, &a, &st);
}

struct ctx_fadel { const char *path; const char *name; };
static int op_fadel(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_fadel *a = v; return xrdc_fattr_del(c, a->path, a->name, st); }

static int
xfs_removexattr(const char *path, const char *name)
{
    if (g_web) return -EROFS;
    xrdc_status st;
    const char *fname;
    if (!g_xattr) {
        return -ENOTSUP;
    }
    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        return -EACCES;
    }
    fname = xfs_xattr_to_fattr(name);
    if (fname == NULL) {
        return -ENODATA;
    }
    xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct ctx_fadel a = { srv_path(path, pbuf, sizeof(pbuf)), fname };
    return xfs_meta(op_fadel, &a, &st);
}

struct ctx_falist { const char *path; char *raw; size_t rawsz; size_t *rawlen; };
static int op_falist(xrdc_conn *c, void *v, xrdc_status *st)
{ struct ctx_falist *a = v; return xrdc_fattr_list(c, a->path, a->raw, a->rawsz, a->rawlen, st); }

static int
xfs_listxattr(const char *path, char *list, size_t size)
{
    if (g_web) return -ENOTSUP;
    xrdc_status st;
    char        raw[16384];
    size_t      rawlen = 0;

    if (!g_xattr) {
        return -ENOTSUP;
    }
    xrdc_status_clear(&st);
    char pbuf[XRDC_PATH_MAX];
    struct ctx_falist a = { srv_path(path, pbuf, sizeof(pbuf)), raw, sizeof(raw),
                            &rawlen };
    int rc = xfs_meta(op_falist, &a, &st);
    if (rc != 0) {
        return rc;
    }
    if (rawlen > sizeof(raw)) {
        rawlen = sizeof(raw);
    }
    /* Convert each server name "U.<x>" → the FUSE name "user.<x>". */
    return xrdc_fattr_listxattr_xlate(raw, rawlen, list, size);
}

static void *
xfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    (void) conn;
    cfg->attr_timeout     = g_attr_timeout;
    cfg->entry_timeout    = g_entry_timeout;
    cfg->negative_timeout = g_attr_timeout;
    cfg->kernel_cache     = g_kernel_cache;
    cfg->use_ino          = 1;
    return NULL;
}

static const struct fuse_operations xfs_ops = {
    .init     = xfs_init,
    .getattr  = xfs_getattr,
    .readdir  = xfs_readdir,
    .open     = xfs_open,
    .create   = xfs_create,
    .read     = xfs_read,
    .write    = xfs_write,
    .flush    = xfs_flush,
    .release  = xfs_release,
    .fsync    = xfs_fsync,
    .mkdir    = xfs_mkdir,
    .unlink   = xfs_unlink,
    .rmdir    = xfs_rmdir,
    .rename   = xfs_rename,
    .chmod    = xfs_chmod,
    .truncate = xfs_truncate,
    .chown    = xfs_chown,
    .utimens  = xfs_utimens,
    .symlink  = xfs_symlink,
    .readlink = xfs_readlink,
    .link     = xfs_link,
    .statfs   = xfs_statfs,
    .access   = xfs_access,
    .getxattr    = xfs_getxattr,
    .setxattr    = xfs_setxattr,
    .listxattr   = xfs_listxattr,
    .removexattr = xfs_removexattr,
};

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

static void
usage(void)
{
    fprintf(stderr,
        "usage: xrootdfs [opts] <endpoint> <mountpoint> [fuse-opts]\n"
        "  endpoint:   root[s]://host[:port][/base]      (binary XRootD; read-write)\n"
        "              http|https|dav|davs://host[:port][/base]\n"
        "                                (WebDAV/XrdHttp; READ-ONLY, ranged GET)\n"
        "              a /base path component roots the mount at that subtree\n"
        "  web-opts:   --token TOK       bearer token for http(s)  ($BEARER_TOKEN)\n"
        "              --noverifyhost    skip TLS server-cert check (self-signed beds)\n"
        "  conn-opts:  --tls --notlsok --noverifyhost --auth <gsi|ztn|unix>\n"
        "              --max-conns N    metadata connection pool size (default 8)\n"
        "  resilience: --streams N      async data connections (default 4)\n"
        "              --max-stall MS   reconnect patience for a dropped link\n"
        "                               (default 60000; 0 = fail fast, no reconnect)\n"
        "              --keepalive MS   heartbeat after this idle time (default 15000)\n"
        "              --max-retries N  transient-error retries (default 5)\n"
        "              --connect-timeout MS  cap on connect+handshake+login\n"
        "                               (default 15000; tighten on a flaky firewall)\n"
        "              --io-timeout MS  steady-state read/write cap (default 30000)\n"
        "  cache-opts: --attr-timeout S --entry-timeout S --kernel-cache\n"
        "              --compress C     inline read compression (gzip|deflate|zstd|\n"
        "                               br|xz|bzip2); server opt-in, transparently\n"
        "                               inflated; ignored if the server declines\n"
        "              --readahead N    per-handle read-ahead bytes (default 1048576)\n"
        "              --writeback N    per-handle write-back bytes (default 1048576)\n"
        "              --xattr          enable extended attributes (kXR_fattr)\n"
        "  fuse-opts:  -f -d -s -o <opt>  (e.g. -o ro -o allow_other)\n"
        "  notes: open files survive a connection drop / server restart transparently\n"
        "         (reopen + resume at the same offset, byte-exact). utimens/chown are\n"
        "         no-ops (no XRootD wire op); symlinks are unsupported.\n");
}

/* Entry point for the default (async/resilient) driver. Invoked by the unified
 * xrootdfs front-end (apps/xrootdfs_main.c); see xrootdfs_drivers.h. */
int
xrootdfs_aio_main(int argc, char **argv)
{
    xrdc_status st;
    const char *endpoint = NULL;
    char       *fuse_argv[64];
    int         fuse_argc = 0;
    int         i, rc;

    if (argc < 3) {
        usage();
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);   /* a dropped peer must never kill the mount */
    memset(&g_opts, 0, sizeof(g_opts));
    g_opts.verify_host = 1;
    xrootd_crypto_init();

    fuse_argv[fuse_argc++] = argv[0];

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        /* Parse our known options ANYWHERE on the line (before OR after the
         * endpoint), so a resilience flag placed after the URL is honored rather
         * than silently leaking to libfuse. Unknown dash-args fall through to the
         * fuse passthrough (so -f/-d/-s/-o still work); the first bare word is the
         * endpoint, the next the mountpoint. */
        if (a[0] == '-') {
            if (strcmp(a, "--tls") == 0)               { g_opts.want_tls = 1; }
            else if (strcmp(a, "--notlsok") == 0)      { g_opts.notlsok = 1; }
            else if (strcmp(a, "--noverifyhost") == 0) { g_opts.verify_host = 0; }
            else if (strcmp(a, "--auth") == 0 && i + 1 < argc) { g_opts.auth_force = argv[++i]; }
            else if (strcmp(a, "--max-conns") == 0 && i + 1 < argc) {
                g_max_conns = atoi(argv[++i]);
                if (g_max_conns < 1) { g_max_conns = 1; }
            }
            else if (strcmp(a, "--streams") == 0 && i + 1 < argc) {
                g_streams = atoi(argv[++i]);
                if (g_streams < 1) { g_streams = 1; }
            }
            else if (strcmp(a, "--max-stall") == 0 && i + 1 < argc) {
                g_max_stall = atoi(argv[++i]);
                if (g_max_stall < 0) { g_max_stall = 0; }
            }
            else if (strcmp(a, "--keepalive") == 0 && i + 1 < argc) {
                g_keepalive = atoi(argv[++i]);
                if (g_keepalive < 0) { g_keepalive = 0; }
            }
            else if (strcmp(a, "--max-retries") == 0 && i + 1 < argc) {
                g_max_retries = atoi(argv[++i]);
                if (g_max_retries < 0) { g_max_retries = 0; }
            }
            else if (strcmp(a, "--connect-timeout") == 0 && i + 1 < argc) {
                xrdc_tmo_set_connect_ms(atoi(argv[++i]));
            }
            else if (strcmp(a, "--io-timeout") == 0 && i + 1 < argc) {
                xrdc_tmo_set_io_ms(atoi(argv[++i]));
            }
            else if (strcmp(a, "--attr-timeout") == 0 && i + 1 < argc) {
                g_attr_timeout = atof(argv[++i]);
            }
            else if (strcmp(a, "--entry-timeout") == 0 && i + 1 < argc) {
                g_entry_timeout = atof(argv[++i]);
            }
            else if (strcmp(a, "--kernel-cache") == 0) { g_kernel_cache = 1; }
            else if (strcmp(a, "--readahead") == 0 && i + 1 < argc) {
                long v = atol(argv[++i]);
                g_readahead = (v > 0) ? (size_t) v : 0;
            }
            else if (strcmp(a, "--writeback") == 0 && i + 1 < argc) {
                long v = atol(argv[++i]);
                g_writeback = (v > 0) ? (size_t) v : 0;
            }
            else if (strcmp(a, "--xattr") == 0) { g_xattr = 1; }
            else if (strcmp(a, "--compress") == 0 && i + 1 < argc) {
                snprintf(g_compress, sizeof(g_compress), "%s", argv[++i]);
            }
            else if (strcmp(a, "--token") == 0 && i + 1 < argc) { g_bearer = argv[++i]; }
            else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(); return 0; }
            else if (fuse_argc < 61) { fuse_argv[fuse_argc++] = argv[i]; }  /* fuse opt */
        } else if (endpoint == NULL) {
            endpoint = a;
        } else if (fuse_argc < 61) {
            fuse_argv[fuse_argc++] = argv[i];
        }
    }

    if (endpoint == NULL || fuse_argc < 2) {
        usage();
        return 2;
    }
    fuse_argv[fuse_argc] = NULL;

    xrdc_status_clear(&st);

    /* HTTP(S)/WebDAV read-only mount when the endpoint is a web URL. */
    if (xrdc_is_web_url(endpoint)) {
        xrdc_statinfo si;
        size_t        bl;
        if (xrdc_weburl_parse(endpoint, &g_weburl) != 0) {
            fprintf(stderr, "xrootdfs: bad web URL: %s\n", endpoint);
            return 2;
        }
        if (g_weburl.is_s3) {
            fprintf(stderr, "xrootdfs: s3:// is not supported as a FUSE mount "
                            "(use http/https/dav/davs)\n");
            return 2;
        }
        g_web = 1;
        if (g_bearer == NULL) {
            g_bearer = getenv("BEARER_TOKEN");
        }
        g_web_verify = g_opts.verify_host;
        g_web_ca = (g_opts.ca_dir != NULL && g_opts.ca_dir[0] != '\0')
                   ? g_opts.ca_dir : getenv("X509_CERT_DIR");
        /* export base = the URL path, trailing '/' trimmed; "/" → "" (verbatim). */
        snprintf(g_base, sizeof(g_base), "%s", g_weburl.path);
        bl = strlen(g_base);
        while (bl > 0 && g_base[bl - 1] == '/') {
            g_base[--bl] = '\0';
        }
        /* fail the mount up front if the export root is unreachable/denied. */
        if (xrdc_web_stat(&g_weburl, g_base[0] ? g_base : "/", g_bearer,
                          g_web_verify, g_web_ca, &si, &st) != 0) {
            fprintf(stderr, "xrootdfs: %s://%s:%d%s: %s\n",
                    g_weburl.tls ? "https" : "http", g_weburl.host, g_weburl.port,
                    g_weburl.path, st.msg);
            return xrdc_shellcode(&st);
        }
        fprintf(stderr,
                "xrootdfs: mounted %s:%d via %s%s (read-only WebDAV; "
                "verify=%d, auth=%s)\n",
                g_weburl.host, g_weburl.port, g_weburl.tls ? "HTTPS" : "HTTP",
                g_base, g_web_verify, g_bearer ? "bearer" : "anon");
        rc = fuse_main(fuse_argc, fuse_argv, &xfs_ops, NULL);
        return rc;
    }

    if (xrdc_endpoint_parse(endpoint, &g_url, &st) != 0) {
        fprintf(stderr, "xrootdfs: %s\n", st.msg);
        return 2;
    }

    /* Export base = the URL path component (root://host/data → "/data"), so the
     * mount roots at that subtree.  Trailing '/' trimmed; a bare host (path "/" or
     * empty) → verbatim FUSE paths.  Shared with the web transport via srv_path(). */
    {
        size_t bl;
        snprintf(g_base, sizeof(g_base), "%s",
                 (g_url.path[0] == '/') ? g_url.path : "");
        bl = strlen(g_base);
        while (bl > 0 && g_base[bl - 1] == '/') {
            g_base[--bl] = '\0';
        }
    }

    g_pool = xrdc_pool_create(&g_url, &g_opts, g_max_conns, &st);
    if (g_pool == NULL) {
        fprintf(stderr, "xrootdfs: connect %s:%d: %s\n",
                g_url.host, g_url.port, st.msg);
        return xrdc_shellcode(&st);
    }
    g_mgr = xrdc_mgr_create(&g_url, &g_opts, g_streams,
                            g_max_stall, g_keepalive, g_max_retries, &st);
    if (g_mgr == NULL) {
        fprintf(stderr, "xrootdfs: async manager: %s\n", st.msg);
        xrdc_pool_destroy(g_pool);
        return xrdc_shellcode(&st);
    }

    /* Probe the server's vendor POSIX extensions (kXR_Qconfig "xrdfs.ext") once;
     * utimens/chown/symlink/readlink/link adapt to what is advertised. */
    {
        xrdc_conn  *pc = xrdc_pool_checkout(g_pool, &st);
        if (pc != NULL) {
            int ok = (xrdc_ext_probe(pc, &g_ext_setattr, &g_ext_symlink,
                                     &g_ext_readlink, &g_ext_link, &st) == 0);
            xrdc_pool_checkin(g_pool, pc, ok ? 1 : xfs_conn_healthy(&st));
        }
    }

    fprintf(stderr,
            "xrootdfs: mounted %s:%d (meta-pool=%d, data-streams=%d, "
            "max-stall=%dms; network-resilient; ext: setattr=%d symlink=%d "
            "readlink=%d link=%d)\n",
            g_url.host, g_url.port, g_max_conns, g_streams, g_max_stall,
            g_ext_setattr, g_ext_symlink, g_ext_readlink, g_ext_link);

    rc = fuse_main(fuse_argc, fuse_argv, &xfs_ops, NULL);

    xrdc_mgr_destroy(g_mgr);
    xrdc_pool_destroy(g_pool);
    return rc;
}
