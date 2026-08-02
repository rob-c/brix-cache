/*
 * xrootdfs_legacy_internal.h - private split contract for xrootdfs_legacy.c and
 * xrootdfs_legacy_ext.c.  Not a public API: include only from apps/fs/.
 *
 * The legacy (synchronous) FUSE driver shares this TU-local state with its ext
 * TU under an `lg_` prefix so none of its symbols collide with the identically
 * named globals of the default async driver (both live in the one `xrootdfs`
 * binary; see xrootdfs_drivers.h).  Behaviour is unchanged from the pre-split
 * single file.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_XROOTDFS_LEGACY_INTERNAL_H
#define BRIX_XROOTDFS_LEGACY_INTERNAL_H

#define FUSE_USE_VERSION 31
#include "brix.h"
#include <fuse3/fuse.h>

/* Shared driver state (defined in xrootdfs_legacy.c). */
extern brix_pool *lg_pool;
extern brix_url   lg_url;
extern brix_opts  lg_opts;
extern int        lg_max_conns;
extern double     lg_attr_timeout;
extern double     lg_entry_timeout;
extern int        lg_kernel_cache;
extern int        lg_xattr;
extern size_t     lg_readahead;
extern size_t     lg_writeback;

/* The synchronous driver's FUSE op table (defined in xrootdfs_legacy.c). */
extern const struct fuse_operations lg_xfs_ops;

/* Server-side checksum xattr prefix (bare "<x>" re-prefixed to "user.U." by the server). */
#define XFS_CKS_XATTR_PFX "user.XrdCks."

/* Core helpers shared with the ext TU (defined in xrootdfs_legacy.c). */
int lg_xfs_conn_healthy(const brix_status *st);
int lg_xfs_err(const brix_status *st);

/* xattr ops (defined in xrootdfs_legacy_ext.c; named by lg_xfs_ops). */
int lg_xfs_getxattr(const char *path, const char *name, char *value, size_t size);
int lg_xfs_setxattr(const char *path, const char *name, const char *value,
                    size_t size, int flags);
int lg_xfs_removexattr(const char *path, const char *name);
int lg_xfs_listxattr(const char *path, char *list, size_t size);

#endif /* BRIX_XROOTDFS_LEGACY_INTERNAL_H */
