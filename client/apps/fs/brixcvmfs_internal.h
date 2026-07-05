/*
 * brixcvmfs_internal.h — seam between the read-only CVMFS-brix FUSE driver
 * (brixcvmfs.c) and the writable-overlay driver (brixcvmfs_rw.c).
 *
 * WHAT: exposes the mounted-client accessors and the read-only FUSE ops so the
 *       cvmfs-rw ops table can delegate every lower-layer case to them, plus
 *       the rw hooks brixcvmfs.c calls when the overlay is enabled.
 * WHY:  the rw driver is union logic ONLY — trust chain, catalogs, fetch and
 *       the read-only op semantics stay in one place; the union layer composes
 *       "overlay first, ro-op fallback" across the TU boundary.
 * HOW:  brixcvmfs.c owns the process-global mount state; brixcvmfs_rw.c owns
 *       the process-global overlay state. Both are single-threaded (-s).
 */
#ifndef BRIXCVMFS_INTERNAL_H
#define BRIXCVMFS_INTERNAL_H

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 31
#endif
#include <fuse3/fuse.h>

#include "cvmfs/client/client.h"

/* ---- owned by brixcvmfs.c ------------------------------------------------ */

cvmfs_client_t *brixcvmfs_client(void);          /* the mounted repo client */
const char     *brixcvmfs_cat_path(const char *p);   /* FUSE "/" → catalog "" */
long            brixcvmfs_mono_now(void);

/* read-only FUSE ops (the cvmfs-rw table's lower-layer fallbacks) */
int brixcvmfs_op_getattr(const char *path, struct stat *st, struct fuse_file_info *fi);
int brixcvmfs_op_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags fl);
int brixcvmfs_op_open(const char *path, struct fuse_file_info *fi);
int brixcvmfs_op_read(const char *path, char *buf, size_t size, off_t off,
                      struct fuse_file_info *fi);
int brixcvmfs_op_readlink(const char *path, char *buf, size_t size);
int brixcvmfs_op_statfs(const char *path, struct statvfs *sv);
int brixcvmfs_op_getxattr(const char *path, const char *name, char *value, size_t size);
int brixcvmfs_op_listxattr(const char *path, char *list, size_t size);

/* ---- owned by brixcvmfs_rw.c (defined only when the rw driver is linked;
 * brixcvmfs.c references them weakly so a ro-only link still works) --------- */

extern int brixcvmfs_rw;                         /* 1 = mount with the rw table
                                                    (defined in brixcvmfs.c) */

/* Prepare <mnt>/.brixwrites (or `writes_override`) BEFORE fuse_main hides the
 * mountpoint, and bind the overlay to it. 0 / -1 (message already printed). */
int brixcvmfs_setup_rw(const char *mnt, const char *writes_override);
void brixcvmfs_teardown_rw(void);

extern const struct fuse_operations brixcvmfs_rw_ops;

/* brixMount driver entry: `cvmfs-rw` (sets brixcvmfs_rw, delegates). */
int brixcvmfs_rw_main(int argc, char **argv);

#endif /* BRIXCVMFS_INTERNAL_H */
