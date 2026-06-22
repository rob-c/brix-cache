/*
 * xrootdfs_legacy.c — simple synchronous XRootD root:// FUSE mount.
 *
 * WHAT: `xrootdfs_legacy root://host[:port]/ /mnt [-f] [auth opts]` — exposes a
 *       remote XRootD namespace as a directory tree that ordinary tools (ls, cat,
 *       cp, md5sum, …) can read and write through libfuse3.
 * WHY:  The simple, synchronous fallback driver. The DEFAULT driver is xrootdfs(1)
 *       (the async, network-resilient core); this one is kept as a minimal
 *       safety-net implementation, reachable via `xrd mount --legacy`. It has NO
 *       libXrdCl / XrdFfs dependency.
 * HOW:  Concurrency model — XRootD connections are one-request-in-flight and not
 *       thread-safe, so:
 *         * metadata / path ops (getattr, readdir, mkdir, …) borrow a connection
 *           from a thread-safe POOL (xrdc_pool) for the duration of the call;
 *         * each OPEN FILE pins its own dedicated xrdc_conn for its lifetime
 *           (the server's fhandle is only valid on the connection that opened
 *           it), serialised by a per-handle mutex so concurrent reads/writes on
 *           the same fd are safe while different files run in parallel.
 *       The mount runs multi-threaded (libfuse's thread pool). Each callback is a
 *       thin map onto a libxrdc call, errors translated to -errno via
 *       xrdc_kxr_to_errno. Open handles live in a malloc'd xfs_handle in fi->fh.
 *
 * Scope: full metadata + read + write incl. random/in-place updates (O_RDWR
 *        without truncate), create/truncate/mkdir/unlink/rmdir/rename/chmod,
 *        statfs (df), access, readdir-plus, kernel-side attr/data caching, and
 *        per-handle read-ahead + write-back buffering (coalesce sequential reads /
 *        small writes into larger server round-trips; --readahead/--writeback).
 *        Hard wire gaps (no XRootD opcode): set-mtime (utimens) and chown are
 *        accepted as no-ops so `cp -p` succeeds; symlink/hardlink are unsupported.
 *        Opt-in --xattr adds extended attributes (kXR_fattr) plus a read-only
 *        user.XrdCks.<algo> checksum view.
 *
 * Clean-room: composes the public libxrdc API + libfuse3 only.
 */
#define FUSE_USE_VERSION 31

#include "xrdc.h"
#include "posix_map.h"       /* shared statinfo→stat / Qspace / listxattr xlate */
#include "iobuf.h"           /* shared read-ahead / write-back engine */
#include "fuse_ops.h"        /* shared pooled meta-op runner + op thunks */
#include "compat/crypto.h"   /* xrootd_crypto_init (libxrdproto SHA/HMAC kernels) */

#include <fuse3/fuse.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>   /* XATTR_CREATE/XATTR_REPLACE flags */

/* Pool of connections for short metadata/path ops; the parsed endpoint + opts so
 * each open file can spin up its own dedicated connection. */
static xrdc_pool      *g_pool;
static xrdc_url        g_url;
static xrdc_opts       g_opts;
static int             g_max_conns = 8;   /* metadata pool size; --max-conns */

/* Kernel-side caching policy (set on the FUSE connection in xfs_init). The kernel
 * caches attrs/lookups for these many seconds and (when kernel_cache) file data
 * across opens — coherent for a single mount since every mutation goes through it.
 * Tunable so latency-sensitive vs. coherence-strict workloads can pick. */
static double          g_attr_timeout  = 1.0;   /* --attr-timeout  */
static double          g_entry_timeout = 1.0;   /* --entry-timeout */
static int             g_kernel_cache  = 0;     /* --kernel-cache  */
static int             g_xattr         = 0;     /* --xattr: enable getxattr/etc. */

/* Per-handle I/O buffering sizes (0 disables). Read-ahead coalesces sequential
 * reads into one larger server read; write-back coalesces small contiguous writes
 * into one larger server write (flushed on flush/fsync/release). */
static size_t          g_readahead = 1024 * 1024;   /* --readahead */
static size_t          g_writeback = 1024 * 1024;   /* --writeback */

/* The read-only "user.XrdCks.<algo>" virtual xattr exposes the server's stored
 * checksum (via kXR_Qcksum) without an on-disk attribute. */
#define XFS_CKS_XATTR_PFX "user.XrdCks."

/* Per-open-file state stored in fi->fh: a private connection + handle, serialised
 * by a per-handle mutex (the conn is one-request-in-flight). */
typedef struct {
    xrdc_conn       conn;
    xrdc_rfile      f;    /* resilient: reopens its dedicated conn + resumes on a sever */
    pthread_mutex_t lock;
    int             writable;
    xrdc_iobuf      io;   /* shared read-ahead / write-back engine (iobuf.c) */
} xfs_handle;

/* Backend I/O for the shared iobuf engine: this driver pins one xrdc_conn +
 * (resilient) handle per open file, so reads/writes go straight to it. */
static ssize_t
xfs_io_pread(void *be, int64_t off, void *buf, size_t n, xrdc_status *st)
{
    xfs_handle *h = be;
    return xrdc_rfile_pread(&h->f, off, buf, n, st);
}
static int
xfs_io_pwrite(void *be, int64_t off, const void *buf, size_t n, xrdc_status *st)
{
    xfs_handle *h = be;
    return xrdc_rfile_pwrite(&h->f, off, buf, n, st);
}

/* Flush any buffered writes to the server. Caller MUST hold h->lock. 0 / -1 (st). */
static int
xfs_flush_wbuf(xfs_handle *h, xrdc_status *st)
{
    return xrdc_iobuf_flush(&h->io, st);
}

/* The error mapping, the conn-health test, and the pooled metadata-op runner are
 * shared with the async driver in lib/fuse_ops.c.  xfs_err/xfs_conn_healthy stay
 * as thin local wrappers (used throughout the read/write/open paths); the
 * metadata ops below call xrdc_fuse_run(g_pool, 0, …) — max_retries 0 is exactly
 * this simple driver's single checkout → op → checkin → map behaviour. */
static int
xfs_conn_healthy(const xrdc_status *st)
{
    return xrdc_fuse_conn_healthy(st);
}

static int
xfs_err(const xrdc_status *st)
{
    return xrdc_fuse_errno(st);
}

/* Fill a struct stat from an xrdc_statinfo (dir vs regular + size + mtime). The
 * legacy driver does not present symlinks, so allow_symlink=0. */
static void
xfs_fill_stat(const xrdc_statinfo *si, struct stat *stbuf)
{
    xrdc_statinfo_to_stat(si, 0, stbuf);
}

/* ------------------------------------------------------------------ */
/* fuse_operations                                                     */
/* ------------------------------------------------------------------ */

static int
xfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    xrdc_statinfo si;
    xrdc_status   st;
    int           rc;

    (void) fi;
    if (strcmp(path, "/") == 0) {
        memset(stbuf, 0, sizeof(*stbuf));
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }
    xrdc_status_clear(&st);
    struct xrdc_fuse_ctx_stat a = { path, &si };
    rc = xrdc_fuse_run(g_pool, 0, xrdc_fuse_op_stat, &a, &st);
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
    int          rc;

    (void) offset; (void) fi; (void) flags;
    xrdc_status_clear(&st);
    /* want_stat=1 (in the op thunk) → the server returns per-entry stat in the
     * SAME round-trip, so `ls -l` doesn't trigger a getattr storm (readdir-plus). */
    struct xrdc_fuse_ctx_dir a = { path, &ents, &n };
    rc = xrdc_fuse_run(g_pool, 0, xrdc_fuse_op_dirlist, &a, &st);
    if (rc != 0) {
        return rc;
    }
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    for (i = 0; i < n; i++) {
        struct stat        sb;
        struct stat       *psb = NULL;
        enum fuse_fill_dir_flags ff = 0;

        if (ents[i].have_stat) {
            xfs_fill_stat(&ents[i].st, &sb);
            psb = &sb;
            ff = FUSE_FILL_DIR_PLUS;   /* let the kernel cache the attrs too */
        }
        filler(buf, ents[i].name, psb, 0, ff);
    }
    free(ents);
    return 0;
}

/* Allocate a handle with its own dedicated connection (the server fhandle is only
 * valid on the connection that opened it). Returns the handle or NULL (+ -errno in
 * *err) on connect failure. */
static xfs_handle *
xfs_handle_new(int *err)
{
    xfs_handle *h = calloc(1, sizeof(*h));
    xrdc_status st;

    if (h == NULL) {
        *err = -ENOMEM;
        return NULL;
    }
    pthread_mutex_init(&h->lock, NULL);
    xrdc_status_clear(&st);
    if (xrdc_connect(&h->conn, &g_url, &g_opts, &st) != 0) {
        pthread_mutex_destroy(&h->lock);
        free(h);
        *err = xfs_err(&st);
        return NULL;
    }
    return h;
}

static void
xfs_handle_free(xfs_handle *h)
{
    xrdc_close(&h->conn);
    pthread_mutex_destroy(&h->lock);
    xrdc_iobuf_dispose(&h->io);
    free(h);
}

static int
xfs_open(const char *path, struct fuse_file_info *fi)
{
    xfs_handle *h;
    xrdc_status st;
    int         acc = fi->flags & O_ACCMODE;
    int         rc, err = 0;

    h = xfs_handle_new(&err);
    if (h == NULL) {
        return err;
    }
    xrdc_status_clear(&st);
    if (acc == O_RDONLY) {
        rc = xrdc_rfile_open_read(&h->conn, path, NULL, 0, -1, &h->f, &st);
    } else if (fi->flags & O_TRUNC) {
        /* Explicit truncate-on-open → overwrite from empty (force=1). */
        rc = xrdc_rfile_open_write(&h->conn, path, 1, 0, 0, -1, &h->f, &st);
        h->writable = 1;
    } else {
        /* Writable open of an existing file WITHOUT O_TRUNC → in-place update
         * (force=2), so partial edits (sed -i, random writes) preserve unwritten
         * content. */
        rc = xrdc_rfile_open_write(&h->conn, path, 2, 0, 0, -1, &h->f, &st);
        h->writable = 1;
    }
    if (rc != 0) {
        xfs_handle_free(h);
        return xfs_err(&st);
    }
    xrdc_iobuf_init(&h->io, h, xfs_io_pread, xfs_io_pwrite, h->writable,
                    g_readahead, g_writeback);
    fi->fh = (uint64_t) (uintptr_t) h;
    return 0;
}

static int
xfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    xfs_handle *h;
    xrdc_status st;
    int         rc, err = 0;

    (void) mode;
    h = xfs_handle_new(&err);
    if (h == NULL) {
        return err;
    }
    xrdc_status_clear(&st);
    /* O_EXCL → create-new (force=0, fail if exists); otherwise truncate-create. */
    rc = xrdc_rfile_open_write(&h->conn, path, (fi->flags & O_EXCL) ? 0 : 1, 0,
                               0, -1, &h->f, &st);
    if (rc != 0) {
        xfs_handle_free(h);
        return xfs_err(&st);
    }
    h->writable = 1;
    xrdc_iobuf_init(&h->io, h, xfs_io_pread, xfs_io_pwrite, h->writable,
                    g_readahead, g_writeback);
    fi->fh = (uint64_t) (uintptr_t) h;
    return 0;
}

static int
xfs_read(const char *path, char *buf, size_t size, off_t offset,
         struct fuse_file_info *fi)
{
    xfs_handle *h = (xfs_handle *) (uintptr_t) fi->fh;
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
    xfs_handle *h = (xfs_handle *) (uintptr_t) fi->fh;
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
xfs_release(const char *path, struct fuse_file_info *fi)
{
    xfs_handle *h = (xfs_handle *) (uintptr_t) fi->fh;
    xrdc_status st;

    (void) path;
    if (h == NULL) {
        return 0;
    }
    xrdc_status_clear(&st);
    pthread_mutex_lock(&h->lock);
    (void) xfs_flush_wbuf(h, &st);   /* persist buffered writes before close */
    (void) xrdc_rfile_close(&h->f, &st);
    pthread_mutex_unlock(&h->lock);
    xfs_handle_free(h);   /* closes the dedicated conn + destroys the lock */
    fi->fh = 0;
    return 0;
}

/* flush — called on each close(2); persist buffered writes so a later open sees
 * them and any deferred write error is reported here (POSIX close-error contract). */
static int
xfs_flush(const char *path, struct fuse_file_info *fi)
{
    xfs_handle *h = (xfs_handle *) (uintptr_t) fi->fh;
    xrdc_status st;
    int         rc;

    (void) path;
    if (h == NULL) {
        return 0;
    }
    xrdc_status_clear(&st);
    pthread_mutex_lock(&h->lock);
    rc = xfs_flush_wbuf(h, &st);
    pthread_mutex_unlock(&h->lock);
    return rc != 0 ? xfs_err(&st) : 0;
}

static int
xfs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    xfs_handle *h = (xfs_handle *) (uintptr_t) fi->fh;
    xrdc_status st;
    int         rc;

    (void) path; (void) datasync;
    if (h == NULL) {
        return 0;
    }
    xrdc_status_clear(&st);
    pthread_mutex_lock(&h->lock);
    rc = xfs_flush_wbuf(h, &st);                       /* flush buffered writes */
    if (rc == 0) {
        rc = xrdc_file_sync(&h->conn, &h->f.f, &st);   /* then durably sync */
    }
    pthread_mutex_unlock(&h->lock);
    return rc != 0 ? xfs_err(&st) : 0;
}

static int
xfs_mkdir(const char *path, mode_t mode)
{
    xrdc_status st;
    xrdc_status_clear(&st);
    struct xrdc_fuse_ctx_mkdir a = { path, (int) (mode & 0777) };
    return xrdc_fuse_run(g_pool, 0, xrdc_fuse_op_mkdir, &a, &st);
}

static int
xfs_unlink(const char *path)
{
    xrdc_status st;
    xrdc_status_clear(&st);
    return xrdc_fuse_run(g_pool, 0, xrdc_fuse_op_rm, (void *) path, &st);
}

static int
xfs_rmdir(const char *path)
{
    xrdc_status st;
    xrdc_status_clear(&st);
    return xrdc_fuse_run(g_pool, 0, xrdc_fuse_op_rmdir, (void *) path, &st);
}

static int
xfs_rename(const char *from, const char *to, unsigned int flags)
{
    xrdc_status st;
    if (flags != 0) {
        return -EINVAL;   /* RENAME_EXCHANGE / RENAME_NOREPLACE unsupported */
    }
    xrdc_status_clear(&st);
    struct xrdc_fuse_ctx_mv a = { from, to };
    return xrdc_fuse_run(g_pool, 0, xrdc_fuse_op_mv, &a, &st);
}

static int
xfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    xrdc_status st;
    (void) fi;
    xrdc_status_clear(&st);
    struct xrdc_fuse_ctx_chmod a = { path, (int) (mode & 0777) };
    return xrdc_fuse_run(g_pool, 0, xrdc_fuse_op_chmod, &a, &st);
}

static int
xfs_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    xrdc_status st;
    (void) fi;
    xrdc_status_clear(&st);
    struct xrdc_fuse_ctx_trunc a = { path, (int64_t) size };
    return xrdc_fuse_run(g_pool, 0, xrdc_fuse_op_trunc, &a, &st);
}

/* chown/utimens succeed as no-ops so tools like `cp -p` don't abort the copy. */
static int
xfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
    (void) path; (void) uid; (void) gid; (void) fi;
    return 0;
}

static int
xfs_utimens(const char *path, const struct timespec tv[2],
            struct fuse_file_info *fi)
{
    (void) path; (void) tv; (void) fi;
    return 0;
}

/* statfs — report capacity from kXR_Qspace ("oss.space=…&oss.free=…"); reported in
 * 1 MiB blocks so total/free fit f_blocks/f_bfree comfortably for huge backends. */
static int
xfs_statfs(const char *path, struct statvfs *stbuf)
{
    char               text[1024];
    xrdc_status        st;
    xrdc_conn         *c;
    int                rc;
    unsigned long long total = 0, freeb = 0;

    memset(stbuf, 0, sizeof(*stbuf));
    xrdc_status_clear(&st);
    c = xrdc_pool_checkout(g_pool, &st);
    if (c == NULL) {
        return xfs_err(&st);
    }
    /* kXR_Qspace returns "oss.cgroup=…&oss.space=<bytes>&oss.free=<bytes>&…";
     * kXR_stat|kXR_vfs (xrdc_statvfs) uses a different compact format, so query
     * Qspace directly for the parseable byte totals. */
    rc = xrdc_query(c, kXR_Qspace, (path != NULL && path[0]) ? path : "/",
                    text, sizeof(text), &st);
    xrdc_pool_checkin(g_pool, c, rc == 0 ? 1 : xfs_conn_healthy(&st));
    if (rc != 0) {
        return xfs_err(&st);
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

/* access — existence check by stat; the server enforces the real permission on
 * each operation, so mask bits are advisory here. */
static int
xfs_access(const char *path, int mask)
{
    xrdc_statinfo si;
    xrdc_status   st;
    xrdc_conn    *c;
    int           rc;

    (void) mask;
    if (strcmp(path, "/") == 0) {
        return 0;
    }
    xrdc_status_clear(&st);
    c = xrdc_pool_checkout(g_pool, &st);
    if (c == NULL) {
        return xfs_err(&st);
    }
    rc = xrdc_stat(c, path, &si, &st);
    xrdc_pool_checkin(g_pool, c, rc == 0 ? 1 : xfs_conn_healthy(&st));
    return rc != 0 ? xfs_err(&st) : 0;
}

/* ---- extended attributes (opt-in via --xattr) ---------------------------- */
/* FUSE uses "user.<x>" names; the server stores them under its own "user.U."
 * prefix, so we send the bare "<x>" and the module re-prefixes. Only the user.*
 * namespace is exposed. Returns "<x>" or NULL for a non-user.* name. */
static const char *
xfs_xattr_to_fattr(const char *name)
{
    if (strncmp(name, "user.", 5) == 0 && name[5] != '\0') {
        return name + 5;
    }
    return NULL;
}

static int
xfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
    xrdc_status st;
    xrdc_conn  *c;
    int         rc;
    size_t      vlen = 0;
    const char *fname;

    if (!g_xattr) {
        return -ENOTSUP;
    }
    xrdc_status_clear(&st);

    /* Virtual read-only checksum xattr: user.XrdCks.<algo> → kXR_Qcksum hex. */
    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        const char *algo = name + sizeof(XFS_CKS_XATTR_PFX) - 1;
        char        hex[160];

        if (algo[0] == '\0') {
            return -ENODATA;
        }
        c = xrdc_pool_checkout(g_pool, &st);
        if (c == NULL) {
            return xfs_err(&st);
        }
        rc = xrdc_query_cksum(c, path, algo, hex, sizeof(hex), &st);
        xrdc_pool_checkin(g_pool, c, rc == 0 ? 1 : xfs_conn_healthy(&st));
        if (rc != 0) {
            return xfs_err(&st);
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
    c = xrdc_pool_checkout(g_pool, &st);
    if (c == NULL) {
        return xfs_err(&st);
    }
    rc = xrdc_fattr_get(c, path, fname, value, size, &vlen, &st);
    xrdc_pool_checkin(g_pool, c, rc == 0 ? 1 : xfs_conn_healthy(&st));
    if (rc != 0) {
        return xfs_err(&st);
    }
    if (size == 0) {
        return (int) vlen;
    }
    if (vlen > size) {
        return -ERANGE;
    }
    return (int) vlen;
}

static int
xfs_setxattr(const char *path, const char *name, const char *value,
             size_t size, int flags)
{
    xrdc_status st;
    xrdc_conn  *c;
    int         rc;
    const char *fname;

    if (!g_xattr) {
        return -ENOTSUP;
    }
    if (strncmp(name, XFS_CKS_XATTR_PFX, sizeof(XFS_CKS_XATTR_PFX) - 1) == 0) {
        return -EACCES;   /* checksum xattr is read-only */
    }
    fname = xfs_xattr_to_fattr(name);
    if (fname == NULL) {
        return -ENOTSUP;
    }
    xrdc_status_clear(&st);
    c = xrdc_pool_checkout(g_pool, &st);
    if (c == NULL) {
        return xfs_err(&st);
    }
    rc = xrdc_fattr_set(c, path, fname, value, size,
                        (flags & XATTR_CREATE) ? 1 : 0, &st);
    xrdc_pool_checkin(g_pool, c, rc == 0 ? 1 : xfs_conn_healthy(&st));
    return rc != 0 ? xfs_err(&st) : 0;
}

static int
xfs_removexattr(const char *path, const char *name)
{
    xrdc_status st;
    xrdc_conn  *c;
    int         rc;
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
    c = xrdc_pool_checkout(g_pool, &st);
    if (c == NULL) {
        return xfs_err(&st);
    }
    rc = xrdc_fattr_del(c, path, fname, &st);
    xrdc_pool_checkin(g_pool, c, rc == 0 ? 1 : xfs_conn_healthy(&st));
    return rc != 0 ? xfs_err(&st) : 0;
}

static int
xfs_listxattr(const char *path, char *list, size_t size)
{
    xrdc_status st;
    xrdc_conn  *c;
    int         rc;
    char        raw[16384];     /* server list: "U.<x>\0U.<y>\0..." */
    size_t      rawlen = 0;

    if (!g_xattr) {
        return -ENOTSUP;
    }
    xrdc_status_clear(&st);
    c = xrdc_pool_checkout(g_pool, &st);
    if (c == NULL) {
        return xfs_err(&st);
    }
    rc = xrdc_fattr_list(c, path, raw, sizeof(raw), &rawlen, &st);
    xrdc_pool_checkin(g_pool, c, rc == 0 ? 1 : xfs_conn_healthy(&st));
    if (rc != 0) {
        return xfs_err(&st);
    }
    if (rawlen > sizeof(raw)) {
        rawlen = sizeof(raw);    /* truncated listing — clamp defensively */
    }
    /* Convert each server name "U.<x>" → the FUSE name "user.<x>". */
    return xrdc_fattr_listxattr_xlate(raw, rawlen, list, size);
}

/* init — enable kernel-side caching once the connection is up. attr/entry
 * timeouts let the kernel serve repeated getattr/lookup from cache; use_ino makes
 * it honour our stable st_ino; kernel_cache (opt-in) caches file data across opens
 * (safe for read-mostly mounts). */
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
        "usage: xrootdfs_legacy [conn-opts] root[s]://host[:port][/] <mountpoint> [fuse-opts]\n"
        "  (the simple synchronous driver; the default resilient driver is xrootdfs(1))\n"
        "  conn-opts:  --tls --notlsok --noverifyhost --auth <gsi|ztn|unix>\n"
        "              --max-conns N      metadata connection pool size (default 8)\n"
        "              --connect-timeout MS  connect+handshake+login cap (default 15000)\n"
        "              --io-timeout MS    steady-state read/write cap (default 30000)\n"
        "  cache-opts: --attr-timeout S   attr cache seconds (default 1.0)\n"
        "              --entry-timeout S  lookup cache seconds (default 1.0)\n"
        "              --kernel-cache     cache file data across opens (read-mostly)\n"
        "              --readahead N      per-handle read-ahead buffer bytes (default\n"
        "                                 1048576; 0 disables)\n"
        "              --writeback N      per-handle write-back buffer bytes (default\n"
        "                                 1048576; 0 disables)\n"
        "              --xattr            enable extended attributes (kXR_fattr) +\n"
        "                                 read-only user.XrdCks.<algo> checksum xattr\n"
        "  fuse-opts:  -f (foreground) -d (debug) -s (single-threaded) -o <opt>\n"
        "              e.g. -o ro -o allow_other  (forwarded to libfuse)\n"
        "  notes: utimens/chown are accepted but no-op (XRootD has no set-time/owner\n"
        "         wire op); symlinks are unsupported.\n");
}

/* Entry point for the synchronous fallback driver. Invoked by the unified
 * xrootdfs front-end (apps/xrootdfs_main.c) when --legacy is given. */
int
xrootdfs_legacy_main(int argc, char **argv)
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
    memset(&g_opts, 0, sizeof(g_opts));
    g_opts.verify_host = 1;
    xrootd_crypto_init();

    fuse_argv[fuse_argc++] = argv[0];
    /* This entry point only runs in --legacy mode (the binary is `xrootdfs`), so
     * tag the kernel mount subtype explicitly: mounts then show as
     * fuse.xrootdfs_legacy and `xrd mount` can still tell the two apart. */
    fuse_argv[fuse_argc++] = (char *) "-osubtype=xrootdfs_legacy";

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        /* Parse our known options anywhere (before or after the endpoint); unknown
         * dash-args pass through to libfuse (-f/-d/-s/-o); first bare word is the
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
            else if (strcmp(a, "--connect-timeout") == 0 && i + 1 < argc) {
                xrdc_tmo_set_connect_ms(atoi(argv[++i]));
            }
            else if (strcmp(a, "--io-timeout") == 0 && i + 1 < argc) {
                xrdc_tmo_set_io_ms(atoi(argv[++i]));
            }
            else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(); return 0; }
            else if (fuse_argc < 61) { fuse_argv[fuse_argc++] = argv[i]; }  /* fuse opt */
        } else if (endpoint == NULL) {
            endpoint = a;   /* first non-option = the root:// URL */
        } else if (fuse_argc < 61) {
            fuse_argv[fuse_argc++] = argv[i];   /* mountpoint + fuse flags */
        }
    }

    if (endpoint == NULL || fuse_argc < 2) {
        usage();
        return 2;
    }
    fuse_argv[fuse_argc] = NULL;

    xrdc_status_clear(&st);
    if (xrdc_endpoint_parse(endpoint, &g_url, &st) != 0) {
        fprintf(stderr, "xrootdfs: %s\n", st.msg);
        return 2;
    }
    /* The pool connects one conn eagerly, so a bad endpoint/auth fails here. */
    g_pool = xrdc_pool_create(&g_url, &g_opts, g_max_conns, &st);
    if (g_pool == NULL) {
        fprintf(stderr, "xrootdfs: connect %s:%d: %s\n",
                g_url.host, g_url.port, st.msg);
        return xrdc_shellcode(&st);
    }
    fprintf(stderr, "xrootdfs: mounted %s:%d (pool=%d, multi-threaded)\n",
            g_url.host, g_url.port, g_max_conns);

    rc = fuse_main(fuse_argc, fuse_argv, &xfs_ops, NULL);

    xrdc_pool_destroy(g_pool);
    return rc;
}
