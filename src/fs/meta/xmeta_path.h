#ifndef BRIX_FS_META_XMETA_PATH_H
#define BRIX_FS_META_XMETA_PATH_H

/*
 * fs/meta/xmeta_path.h — raw-path carrier for the unified metadata record.
 *
 * WHAT: Load/save/remove an encoded xmeta record for a LOCAL file by absolute
 *       path: the record rides in the data file's "user.xrd.cinfo" xattr when
 *       it fits, else as the stock-readable "<path>.cinfo" sidecar. Plus the
 *       per-file read-modify-write lock every path-side writer shares.
 *
 * WHY:  One carrier implementation for every path-side consumer — the cache's
 *       cinfo layer (fs/cache/cinfo.c) and the CSI integrity engine
 *       (fs/backend/csi_*) persist into the SAME record on the SAME file
 *       under the SAME lock. The SD-instance carrier (xmeta_carrier.h) is the
 *       store-object twin of this file.
 *
 * HOW:  Pure C, ngx-free (standalone-testable): direct getxattr/setxattr and
 *       file I/O — the paths handed here are svc-owned domains (cache trees)
 *       or export data files reached below the VFS seam, never client-mapped
 *       attribute namespaces.
 */

#include "xmeta.h"

/* The reserved xattr + the sidecar suffix (shared with xmeta_carrier.h). */
#define BRIX_XMETA_PATH_XATTR    "user.xrd.cinfo"
#define BRIX_XMETA_PATH_SIDECAR  ".cinfo"
#define BRIX_XMETA_PATH_XATTR_MAX (64 * 1024)

/* Compose "<path>.cinfo" into dst[cap]. 0 on success, -1 if too long. */
int  brix_xmeta_sidecar_path(char *dst, size_t cap, const char *path);

/* Load + decode the record for `path` (xattr first, then the sidecar).
 * BRIX_XMETA_OK (caller frees *xm) / FOREIGN (nothing valid recorded) /
 * ERR (errno). */
int  brix_xmeta_path_load(const char *path, brix_xmeta_t *xm);

/* Encode + persist the record for `path` (xattr preferred, sidecar fallback;
 * exactly one carrier survives). OK / ERR (errno). */
int  brix_xmeta_path_save(const char *path, const brix_xmeta_t *xm);

/* Drop both carriers (best-effort, absent is fine). Always OK. */
int  brix_xmeta_path_remove(const char *path);

/* Open + LOCK_EX the per-file RMW lock: the data file when it exists, else
 * the sidecar path (created; e.g. the slice cache never materializes the
 * base object). Returns the locked fd, or -1 (errno). flock is advisory,
 * per-open-fd, auto-released on close/crash. */
int  brix_xmeta_path_lock(const char *path);
void brix_xmeta_path_unlock(int lockfd);

#endif /* BRIX_FS_META_XMETA_PATH_H */
