#ifndef BRIX_SD_CEPH_STRIPER_H
#define BRIX_SD_CEPH_STRIPER_H

/*
 * sd_ceph_striper.h — thin wrappers over the libradosstriper C API
 * (`rados_striper_*`), so the rados driver's data plane is byte-for-byte the stock
 * XrdCeph layout (see docs spec §1). The object name handed in is the PHYSICAL
 * striper name (post-N2N, post-pool-extract) — these wrappers are pool-agnostic;
 * `sd_ceph.c` binds the ioctx (one pool per export, or the RAL `<pool>:` split).
 *
 * Compiled ONLY under BRIX_HAVE_RADOSSTRIPER (the ./configure probe for
 * <radosstriper/libradosstriper.h>); otherwise this file is empty, exactly as
 * `sd_ceph.c` is gated on BRIX_HAVE_CEPH — a build without Ceph is unchanged.
 *
 * Error convention: 0 on success, or a NEGATIVE errno (the librados convention),
 * which `sd_ceph.c` maps to the SD/errno surface. Reads/stat return byte/size via
 * out-params. All ops are worker-thread-safe (synchronous librados).
 */

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#if defined(BRIX_HAVE_RADOSSTRIPER)

#include <rados/librados.h>
#include <radosstriper/libradosstriper.h>

/* Layout to stamp on newly-created striper objects (must match the site's stock
 * XrdCeph defaults so our writes and stock's are interoperable). */
typedef struct {
    unsigned int stripe_unit;    /* e.g. ceph default; 0 = leave library default */
    unsigned int stripe_count;
    unsigned int object_size;    /* stock default 4 MiB */
} sd_ceph_striper_layout_t;

/* Create a striper bound to `ioctx`, applying `layout` (NULL = library defaults).
 * Returns 0 + *out, or a negative errno. Destroy with sd_ceph_striper_destroy. */
int  sd_ceph_striper_create(rados_ioctx_t ioctx,
                            const sd_ceph_striper_layout_t *layout,
                            rados_striper_t *out);
void sd_ceph_striper_destroy(rados_striper_t striper);

/* Data plane on the physical striper object `soid`. */
ssize_t sd_ceph_striper_read (rados_striper_t, const char *soid,
                              void *buf, size_t len, uint64_t off);
ssize_t sd_ceph_striper_write(rados_striper_t, const char *soid,
                              const void *buf, size_t len, uint64_t off);
int     sd_ceph_striper_trunc(rados_striper_t, const char *soid, uint64_t size);
int     sd_ceph_striper_remove(rados_striper_t, const char *soid);
int     sd_ceph_striper_stat (rados_striper_t, const char *soid,
                              uint64_t *size_out, time_t *mtime_out);

/* xattr (lands on the first stripe, exactly as stock). getxattr returns the value
 * length (>=0) or a negative errno; -ERANGE-style short buffers follow librados. */
ssize_t sd_ceph_striper_getxattr(rados_striper_t, const char *soid,
                                 const char *name, void *buf, size_t cap);
int     sd_ceph_striper_setxattr(rados_striper_t, const char *soid,
                                 const char *name, const void *buf, size_t len);
int     sd_ceph_striper_rmxattr (rados_striper_t, const char *soid,
                                 const char *name);
/* List xattr names into `buf` as NUL-separated names (like listxattr). Returns the
 * total bytes used (>=0), or a negative errno. */
ssize_t sd_ceph_striper_listxattr(rados_striper_t, const char *soid,
                                  char *buf, size_t cap);

#endif /* BRIX_HAVE_RADOSSTRIPER */

#endif /* BRIX_SD_CEPH_STRIPER_H */
