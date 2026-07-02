/* client/lib/vfs.h
 *
 * vfs.h — client storage-backend abstraction.
 *
 * WHAT: one open-file handle (pread/pwrite/fstat/truncate/sync/commit/abort/close)
 *       over a backend vtable, so a copy endpoint can be local POSIX, a block
 *       device, or an S3/object store interchangeably.
 * WHY:  copy.c hard-codes POSIX fds for the local endpoint and threads three
 *       different ad-hoc I/O seams (pump_src/sink_fn, iobuf be+pread/pwrite,
 *       xrdc_disk_ring). One handle unifies them and lets non-POSIX backends in.
 * HOW:  the keystone is commit(): POSIX finalises by fsync+rename(temp->final);
 *       block by fsync; S3 by multipart-complete. caps lets the copy engine pick
 *       a path (random-write vs append-only, atomic-temp vs native commit).
 *       ngx-free.
 *
 * BACKEND I/O: this VFS is the client-side *shell* (URL/scheme resolution,
 *       credential store, commit/abort, io_uring fast-path). The raw byte I/O of
 *       the POSIX and block backends is dispatched through the SHARED Storage
 *       Driver `xrootd_sd_posix_driver` (src/fs/backend/sd.h, ngx-free under
 *       -DXRDPROTO_NO_NGX via libxrdproto) — the SAME driver the nginx server's
 *       data plane uses (src/fs/vfs/vfs_io_core.c). So `pread`/`pwrite`/`fstat`/
 *       `ftruncate`/`fsync` have ONE implementation across client and server.
 *       (The old "never reuse sd.h — phase-55 broke it" caveat is obsolete: sd.h
 *       now carries a complete ngx-free fallback, so the worker-safe raw-fd
 *       surface is shared without pulling nginx into the client.)
 */
#ifndef XRDC_VFS_H
#define XRDC_VFS_H

#include "xrdc.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t */

typedef enum {
    XRDC_VFS_READ   = 0x01,   /* open for reading                                  */
    XRDC_VFS_WRITE  = 0x02,   /* open for writing (create+truncate unless RESUME)  */
    XRDC_VFS_RESUME = 0x04,   /* writer: keep existing object, resume at offset     */
    XRDC_VFS_FORCE  = 0x08,   /* writer: overwrite an existing destination          */
} xrdc_vfs_oflags;

typedef enum {
    XRDC_VFS_CAP_RANDOM_WRITE = 0x01, /* pwrite at any offset (posix/block); 0=append/stream (s3) */
    XRDC_VFS_CAP_TRUNCATE     = 0x02,
    XRDC_VFS_CAP_ATOMIC_TEMP  = 0x04, /* commit = temp+rename (posix); 0=native commit (s3/block) */
    XRDC_VFS_CAP_FADVISE      = 0x08,
} xrdc_vfs_caps;

typedef struct {
    int64_t size;
    int64_t mtime;
    int     is_dir;
    int     exists;
} xrdc_vfs_stat;

typedef struct xrdc_cred_store xrdc_cred_store;   /* fwd decl (Part B); NULL for local */

typedef struct {
    int              io_uring;      /* XRDC_IO_URING_{OFF,AUTO,ON} for posix/block      */
    int64_t          expected_size; /* writer hint: <0 unknown; drives s3 single-PUT vs MPU */
    xrdc_cred_store *cred;          /* credential source for s3/web backends (NULL=local) */
} xrdc_vfs_open_opts;

typedef struct xrdc_vfs_file xrdc_vfs_file;

/* Per-handle vtable. A backend's open() allocates a concrete struct whose first
 * member is `xrdc_vfs_file base;` and sets base.ops/base.caps. */
typedef struct xrdc_vfs_ops {
    ssize_t (*pread)(xrdc_vfs_file *f, int64_t off, void *buf, size_t n, xrdc_status *st);
    int     (*pwrite)(xrdc_vfs_file *f, int64_t off, const void *buf, size_t n, xrdc_status *st);
    int     (*fstat)(xrdc_vfs_file *f, xrdc_vfs_stat *out, xrdc_status *st);
    int     (*truncate)(xrdc_vfs_file *f, int64_t size, xrdc_status *st);
    int     (*sync)(xrdc_vfs_file *f, xrdc_status *st);
    int     (*commit)(xrdc_vfs_file *f, xrdc_status *st); /* finalise: rename/MPU-complete/fsync */
    void    (*abort)(xrdc_vfs_file *f);                   /* discard partial: unlink temp / abort MPU */
    void    (*close)(xrdc_vfs_file *f);                   /* free handle (after commit OR abort) */
} xrdc_vfs_ops;

struct xrdc_vfs_file {
    const xrdc_vfs_ops *ops;
    uint32_t            caps;   /* xrdc_vfs_caps for this open handle */
};

typedef struct xrdc_vfs_backend {
    const char *scheme;         /* "file","block","s3","s3s" — matched against the URL */
    uint32_t    caps;           /* default caps advertised pre-open */
    int (*open)(const struct xrdc_vfs_backend *be, const char *url, int flags,
                const xrdc_vfs_open_opts *opts, xrdc_vfs_file **out, xrdc_status *st);
    int (*stat)(const struct xrdc_vfs_backend *be, const char *url,
                xrdc_vfs_stat *out, xrdc_status *st);
} xrdc_vfs_backend;

/* ---- Façade: the only surface copy.c/tools use. Resolves URL->backend. ---- */
int      xrdc_vfs_open(const char *url, int flags, const xrdc_vfs_open_opts *opts,
                       xrdc_vfs_file **out, xrdc_status *st);
int      xrdc_vfs_stat_url(const char *url, const xrdc_vfs_open_opts *opts,
                           xrdc_vfs_stat *out, xrdc_status *st);
ssize_t  xrdc_vfs_pread(xrdc_vfs_file *f, int64_t off, void *buf, size_t n, xrdc_status *st);
int      xrdc_vfs_pwrite(xrdc_vfs_file *f, int64_t off, const void *buf, size_t n, xrdc_status *st);
int      xrdc_vfs_fstat(xrdc_vfs_file *f, xrdc_vfs_stat *out, xrdc_status *st);
int      xrdc_vfs_truncate(xrdc_vfs_file *f, int64_t size, xrdc_status *st);
int      xrdc_vfs_sync(xrdc_vfs_file *f, xrdc_status *st);
int      xrdc_vfs_commit(xrdc_vfs_file *f, xrdc_status *st);
void     xrdc_vfs_abort(xrdc_vfs_file *f);
void     xrdc_vfs_close(xrdc_vfs_file *f);
uint32_t xrdc_vfs_get_caps(const xrdc_vfs_file *f);  /* note: distinct from the enum xrdc_vfs_caps */

#endif /* XRDC_VFS_H */
