/*
 * brixcvmfs_rw_internal.h — private Phase-38 split contract for the writable
 * CVMFS-brix overlay driver, shared ONLY between brixcvmfs_rw.c (core: state,
 * path/layer helpers, open/read/write family) and brixcvmfs_rw_ext.c
 * (directory + metadata ops, the ops table, mount lifecycle).
 *
 * WHAT: the process-global overlay state and the handful of core helpers/ops
 *       the ext TU calls after the union driver was split by concern.
 * WHY:  not a public API — the read-only driver still binds through
 *       brixcvmfs_internal.h's accessor seam. This header exists so the two rw
 *       TUs can reach one another's state/entry points without reintroducing a
 *       monolith. Behaviour is unchanged from the pre-split single file.
 * HOW:  each extern/prototype is DEFINED in brixcvmfs_rw.c. Single-threaded
 *       mount (-s), so the globals need no locking. See
 *       docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIXCVMFS_RW_INTERNAL_H
#define BRIXCVMFS_RW_INTERNAL_H

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 31
#endif
#include <fuse3/fuse.h>
#include <sys/stat.h>

#include "cvmfs/client/client.h"   /* cvmfs_dirent_t */
#include "fs/overlay.h"            /* brix_overlay, brix_ov_state */

/* ---- process-global overlay state (DEFINED in brixcvmfs_rw.c) ------------ */
extern brix_overlay g_ov;
extern int          g_writes_fd;

/*
 * WHAT: one resolved overlay location — upper stat + state and the lower
 *       dirent — filled by ov_locate/ov_locate_visible.
 * WHY:  mutation ops in the ext TU (unlink, rename, rmdir) need both layers'
 *       facts together; grouping them keeps the handlers small.
 * HOW:  `st`/`s` come from the overlay classify; `e`/`lower` from the CVMFS
 *       catalog resolve (1 found / 0 absent-or-not-consulted).
 */
typedef struct {
    struct stat    st;      /* upper stat, valid when s == BRIX_OV_UPPER */
    brix_ov_state  s;       /* upper / masked / none */
    cvmfs_dirent_t e;       /* lower dirent, valid when lower == 1 */
    int            lower;   /* 1 found / 0 absent (or masked → not consulted) */
} ov_loc_t;

/* ---- core helpers + ops shared with the ext TU (DEFINED in brixcvmfs_rw.c) */
const char *ov_rel(const char *path);
const char *pt_rel(const char *path);
const char *pt_at(const char *pr);
int    rw_reserved(const char *path);
int    lower_resolve(const char *path, cvmfs_dirent_t *e);
int    lower_is_dir(const cvmfs_dirent_t *e);
int    lower_is_file(const cvmfs_dirent_t *e);
int    rw_classify(const char *path, struct stat *st, brix_ov_state *s);
int    merged_exists(const char *path);
int    ov_locate(const char *path, ov_loc_t *l);
int    ov_locate_visible(const char *path, ov_loc_t *l);
mode_t rw_lower_dir_mode(void *ud, const char *rel_dir);
int    rw_ensure_parents(const char *path);
int    rw_copyup(const char *path, const cvmfs_dirent_t *e);
int    rw_open(const char *path, struct fuse_file_info *fi);
int    rw_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int    rw_mknod(const char *path, mode_t mode, dev_t dev);
int    rw_read(const char *path, char *buf, size_t size, off_t off,
               struct fuse_file_info *fi);
int    rw_write(const char *path, const char *buf, size_t size, off_t off,
                struct fuse_file_info *fi);
int    rw_release(const char *path, struct fuse_file_info *fi);
int    rw_fsync(const char *path, int datasync, struct fuse_file_info *fi);
int    rw_truncate(const char *path, off_t len, struct fuse_file_info *fi);
int    rw_getattr(const char *path, struct stat *st, struct fuse_file_info *fi);
int    rw_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                  off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags fl);

/* The directory + metadata ops (rw_mkdir/_unlink/_rmdir/_rename/_symlink/
 * _readlink/_chmod/_chown/_utimens/_statfs/_getxattr/_listxattr), the ops
 * table brixcvmfs_rw_ops and the mount lifecycle live wholly in
 * brixcvmfs_rw_ext.c and reference this header's core seam; they never cross
 * back, so they stay TU-local (static) there. */

#endif /* BRIXCVMFS_RW_INTERNAL_H */
