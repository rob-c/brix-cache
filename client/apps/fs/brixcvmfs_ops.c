/*
 * brixcvmfs_ops.c — CVMFS-brix read-only FUSE operations (Phase-38 split).
 *
 * WHAT: the FUSE 3.1 high-level op table — getattr/readdir/open/read/readlink/
 *       statfs/getxattr/listxattr/access translated straight into
 *       cvmfs_client_* calls — plus the EROFS refusals for the whole write
 *       family and the TTL-gated refresh/pin-drift audit the read ops fire.
 * WHY:  split from brixcvmfs.c to keep each TU within the file-size budget;
 *       this is the catalog-semantics surface, cleanly separate from the
 *       transport and the mount front-end.
 * HOW:  every op resolves against the process-global client (g_cl) through the
 *       cat_path/mono_now helpers; read ops run the TTL-gated refresh first.
 *       Read-only: every mutating op is refused with -EROFS, not the kernel's
 *       default ENOSYS/EPERM.
 */
#include "brixcvmfs_internal.h"
#include "brixcvmfs_split.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* TTL-gated refresh + pin-drift audit: when the mount is pinned and a verified
 * upstream manifest has moved past the pin, log ONE audit line per drift
 * transition (re-armed if upstream returns to the pin), keep serving the pin. */
static void brix_refresh(void) {
    static int drift_logged = 0;
    cvmfs_client_refresh(g_cl, mono_now());
    char up[48];
    if (cvmfs_client_pin_drift(g_cl, up, sizeof(up))) {
        if (!drift_logged) {
            char pin[48];
            cvmfs_hash_to_hex(&g_cl->pin_root, 0, pin, sizeof(pin));
            fprintf(stderr, "brixcvmfs: audit signal=pindrift repo=%s pinned=%s "
                    "upstream=%s serving=pinned\n", g_cl->config.name, pin, up);
            drift_logged = 1;
        }
    } else {
        drift_logged = 0;
    }
}

/* ---- FUSE ops (read-only) ---------------------------------------------- */

int brixcvmfs_op_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void) fi;
    brix_refresh();                             /* TTL-gated: no-op until due */
    cvmfs_client_reap_tick(g_cl, mono_now());   /* quota-gated: no-op until due */
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc < 0)  return -EIO;
    if (rc == 0) return -ENOENT;

    memset(st, 0, sizeof(*st));
    st->st_mode  = e.mode;
    st->st_size  = (off_t) e.size;
    st->st_mtime = (time_t) e.mtime;
    st->st_nlink = (e.flags & CVMFS_FLAG_DIR) ? 2 : e.linkcount;
    st->st_uid   = e.uid ? e.uid : getuid();
    st->st_gid   = e.gid ? e.gid : getgid();
    return 0;
}

typedef struct { void *buf; fuse_fill_dir_t filler; } readdir_ctx_t;

static void readdir_emit(const cvmfs_dirent_t *e, void *ud) {
    readdir_ctx_t *r = ud;
    if (e->name[0] != '\0')
        r->filler(r->buf, e->name, NULL, 0, 0);
}

int brixcvmfs_op_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags fl) {
    (void) off; (void) fi; (void) fl;
    brix_refresh();                           /* TTL-gated: no-op until due */
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    readdir_ctx_t r = { buf, filler };
    int n = cvmfs_client_readdir(g_cl, cat_path(path), readdir_emit, &r, mono_now());
    if (n >= 0) pf_enqueue(cat_path(path));   /* first listing = prefetch signal */
    return n < 0 ? -EIO : 0;
}

int brixcvmfs_op_open(const char *path, struct fuse_file_info *fi) {
    if ((fi->flags & O_ACCMODE) != O_RDONLY) return -EROFS;   /* read-only fs */
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc < 0)  return -EIO;
    if (rc == 0) return -ENOENT;
    if (!(e.flags & CVMFS_FLAG_FILE)) return -EISDIR;
    return 0;
}

int brixcvmfs_op_read(const char *path, char *buf, size_t size, off_t off,
                   struct fuse_file_info *fi) {
    (void) fi;
    size_t got = 0;
    int rc = cvmfs_client_read(g_cl, cat_path(path), (uint64_t) off, size,
                               (unsigned char *) buf, &got, mono_now());
    return rc == 0 ? (int) got : -EIO;
}

int brixcvmfs_op_readlink(const char *path, char *buf, size_t size) {
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc <= 0) return rc < 0 ? -EIO : -ENOENT;
    if (!(e.flags & CVMFS_FLAG_LINK)) return -EINVAL;
    snprintf(buf, size, "%s", e.symlink);
    return 0;
}

int brixcvmfs_op_statfs(const char *path, struct statvfs *sv) {
    (void) path;
    memset(sv, 0, sizeof(*sv));
    sv->f_bsize = 4096;
    sv->f_namemax = 255;
    return 0;
}

int brixcvmfs_op_getxattr(const char *path, const char *name, char *value, size_t size) {
    int n = cvmfs_client_getxattr(g_cl, cat_path(path), name, value, size, mono_now());
    if (n < 0)              return -ENODATA;    /* attribute not present */
    if (size == 0)          return n;           /* size probe */
    if ((size_t) n > size)  return -ERANGE;
    return n;
}

int brixcvmfs_op_listxattr(const char *path, char *list, size_t size) {
    int n = cvmfs_client_listxattr(g_cl, cat_path(path), list, size, mono_now());
    if (size == 0)          return n;
    if ((size_t) n > size)  return -ERANGE;
    return n;
}

/* access(2): the fs is read-only, so any W_OK is refused up front; X_OK is
 * honored against the node's mode bits (a 0644 file has no execute bit). R_OK /
 * F_OK on a world-readable RO tree always succeed. Mirrors official cvmfs. */
int brixcvmfs_op_access(const char *path, int mask) {
    cvmfs_dirent_t e;
    int rc = cvmfs_client_resolve(g_cl, cat_path(path), &e, mono_now());
    if (rc < 0)  return -EIO;
    if (rc == 0) return -ENOENT;
    if (mask & W_OK) return -EROFS;                 /* read-only filesystem */
    if ((mask & X_OK) && !(e.mode & (S_IXUSR | S_IXGRP | S_IXOTH))) return -EACCES;
    return 0;
}

/* every mutating op is refused with EROFS — a read-only filesystem returns
 * EROFS for the whole write family, not the kernel's default ENOSYS/EPERM. */
static int ro_erofs(void) { return -EROFS; }
static int op_mkdir(const char *p, mode_t m) { (void)p;(void)m; return ro_erofs(); }
static int op_unlink(const char *p) { (void)p; return ro_erofs(); }
static int op_write(const char *p, const char *b, size_t s, off_t o, struct fuse_file_info *fi)
    { (void)p;(void)b;(void)s;(void)o;(void)fi; return ro_erofs(); }
static int op_rmdir(const char *p) { (void)p; return ro_erofs(); }
static int op_rename(const char *f, const char *t, unsigned int fl)
    { (void)f;(void)t;(void)fl; return ro_erofs(); }
static int op_symlink(const char *tgt, const char *p) { (void)tgt;(void)p; return ro_erofs(); }
static int op_link(const char *f, const char *t) { (void)f;(void)t; return ro_erofs(); }
static int op_chmod(const char *p, mode_t m, struct fuse_file_info *fi)
    { (void)p;(void)m;(void)fi; return ro_erofs(); }
static int op_chown(const char *p, uid_t u, gid_t g, struct fuse_file_info *fi)
    { (void)p;(void)u;(void)g;(void)fi; return ro_erofs(); }
static int op_truncate(const char *p, off_t o, struct fuse_file_info *fi)
    { (void)p;(void)o;(void)fi; return ro_erofs(); }
static int op_utimens(const char *p, const struct timespec tv[2], struct fuse_file_info *fi)
    { (void)p;(void)tv;(void)fi; return ro_erofs(); }
static int op_setxattr(const char *p, const char *n, const char *v, size_t s, int f)
    { (void)p;(void)n;(void)v;(void)s;(void)f; return ro_erofs(); }
static int op_removexattr(const char *p, const char *n) { (void)p;(void)n; return ro_erofs(); }
static int op_mknod(const char *p, mode_t m, dev_t d) { (void)p;(void)m;(void)d; return ro_erofs(); }

const struct fuse_operations brixcvmfs_ops = {
    .getattr  = brixcvmfs_op_getattr,
    .readdir  = brixcvmfs_op_readdir,
    .open     = brixcvmfs_op_open,
    .read     = brixcvmfs_op_read,
    .readlink = brixcvmfs_op_readlink,
    .statfs   = brixcvmfs_op_statfs,
    .getxattr  = brixcvmfs_op_getxattr,
    .listxattr = brixcvmfs_op_listxattr,
    .access   = brixcvmfs_op_access,
    .mkdir    = op_mkdir,
    .unlink   = op_unlink,
    .write    = op_write,
    .rmdir       = op_rmdir,
    .rename      = op_rename,
    .symlink     = op_symlink,
    .link        = op_link,
    .chmod       = op_chmod,
    .chown       = op_chown,
    .truncate    = op_truncate,
    .utimens     = op_utimens,
    .setxattr    = op_setxattr,
    .removexattr = op_removexattr,
    .mknod       = op_mknod,
};
