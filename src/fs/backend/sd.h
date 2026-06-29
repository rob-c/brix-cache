/*
 * sd.h — Storage Driver (SD) interface: the pluggable layer below the VFS.
 *
 * WHAT: Declares the capability bitmap, the opaque driver/instance/object/dir/
 *       staged handle types, the POD stat/dirent descriptors, the driver vtable
 *       (xrootd_sd_driver_s), the small capability-gated accessor helpers, and
 *       the registry API that turns a backend name into a bound per-export
 *       instance. POSIX is the default driver (sd_posix.c); block/object drivers
 *       (phases 55.D/E) register the same way.
 *
 * WHY:  The VFS (src/fs/) is the protocol-agnostic data plane, but it is still
 *       hard-wired to POSIX syscalls. This header is the seam that lets the VFS
 *       call "move these bytes / mutate this name" against a driver it selected
 *       at config time, while keeping all policy (confinement re-check, metrics,
 *       access log, cache, buffer shaping) above the seam. See
 *       docs/refactor/phase-55-storage-backend-abstraction.md.
 *
 * HOW:  A driver is a static const xrootd_sd_driver_t with a caps bitmap and a
 *       flat table of function pointers. The registry (sd_registry.c) builds an
 *       xrootd_sd_instance_t per export by name; the VFS opens objects on the
 *       instance and runs the worker-safe raw ops (pread/pwrite/...) on the
 *       returned object handle from any dispatch tier. Phase 55.A ships this
 *       header + the POSIX driver + the registry, registered in the build but
 *       not yet wired into any VFS callsite (that is 55.B+).
 */
#ifndef XROOTD_SD_H
#define XROOTD_SD_H

#ifdef XRDPROTO_NO_NGX
/* ngx-free consumers (the native client via shared libxrdproto) include this
 * header ONLY for the worker-safe POSIX raw-fd surface — xrootd_sd_posix_wrap()
 * + the driver's pread/pwrite/... slots — which touch no nginx runtime. Supply
 * the minimal nginx type/macro surface this header *names* so it compiles
 * without ngx_core.h. Each is a typedef or macro (no runtime symbol), so the
 * built libxrdproto stays ngx-free (check-ngx-free.sh inspects the archive for
 * ngx_* symbols). The ngx-coupled namespace/instance/registry slots are simply
 * absent (NULL) in the ngx-free POSIX driver (see sd_posix.c). */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>     /* struct timespec for xrootd_sd_setattr_t */
typedef intptr_t          ngx_int_t;
typedef int               ngx_fd_t;
typedef struct ngx_log_s  ngx_log_t;   /* opaque: only ever a pointer field */
typedef struct ngx_pool_s ngx_pool_t;  /* opaque: only ever a pointer field */
#ifndef NGX_INVALID_FILE
#define NGX_INVALID_FILE  (-1)
#endif
#ifndef NGX_OK
#define NGX_OK            0
#endif
#ifndef NGX_ERROR
#define NGX_ERROR         (-1)
#endif
#ifndef NGX_DONE
#define NGX_DONE          (-4)
#endif
#ifndef ngx_inline
#define ngx_inline        inline
#endif
#ifndef ngx_memzero
#define ngx_memzero(buf, n) memset(buf, 0, (n))
#endif
#else
#include <ngx_config.h>
#include <ngx_core.h>
#endif

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

/* ---- capability bitmap ----------------------------------------------------
 * A driver advertises what it can do; the VFS consults this to shape behaviour
 * (e.g. only emit a sendfile buffer when CAP_SENDFILE). Absences are honest:
 * the VFS degrades or rejects rather than emulating a missing primitive. */
typedef enum {
    XROOTD_SD_CAP_FD            = 1u << 0,  /* exposes a real kernel fd          */
    /* CAP_SENDFILE implies CAP_FD: xrootd_sd_fd(obj) is a real seekable kernel
     * fd valid as the source of sendfile(2) and of an nginx file-backed
     * (b->in_file) buffer for any byte range. A backend without it MUST be
     * served memory-backed; the VFS read path enforces that fallback. */
    XROOTD_SD_CAP_SENDFILE      = 1u << 1,
    XROOTD_SD_CAP_RANDOM_WRITE  = 1u << 2,  /* pwrite at arbitrary offset        */
    XROOTD_SD_CAP_RANGE_READ    = 1u << 3,  /* pread at arbitrary offset         */
    XROOTD_SD_CAP_TRUNCATE      = 1u << 4,  /* ftruncate                         */
    XROOTD_SD_CAP_SERVER_COPY   = 1u << 5,  /* native copy (copy_file_range/COPY)*/
    XROOTD_SD_CAP_XATTR         = 1u << 6,  /* user.* xattrs / object metadata   */
    XROOTD_SD_CAP_HARD_RENAME   = 1u << 7,  /* atomic rename (else copy+delete)  */
    XROOTD_SD_CAP_DIRS          = 1u << 8,  /* real directories (else key-prefix)*/
    XROOTD_SD_CAP_APPEND        = 1u << 9,  /* O_APPEND semantics                */
    XROOTD_SD_CAP_IOURING       = 1u << 10, /* fd is io_uring-submittable        */
    XROOTD_SD_CAP_FSCS          = 1u << 11  /* filesystem page checksums (CSI)   */
} xrootd_sd_cap_t;

/* ---- SD open flags --------------------------------------------------------
 * Backend-neutral open intent. The POSIX driver maps these to O_* internally;
 * non-POSIX drivers interpret them in their own terms. */
#define XROOTD_SD_O_READ     0x01
#define XROOTD_SD_O_WRITE    0x02
#define XROOTD_SD_O_CREATE   0x04
#define XROOTD_SD_O_EXCL     0x08
#define XROOTD_SD_O_TRUNC    0x10
#define XROOTD_SD_O_APPEND   0x20
#define XROOTD_SD_O_DIR      0x40
#define XROOTD_SD_O_NOFOLLOW 0x80   /* refuse a symlink at the final component */

typedef struct xrootd_sd_driver_s   xrootd_sd_driver_t;
typedef struct xrootd_sd_instance_s xrootd_sd_instance_t;
typedef struct xrootd_sd_obj_s      xrootd_sd_obj_t;
typedef struct xrootd_sd_dir_s      xrootd_sd_dir_t;
typedef struct xrootd_sd_staged_s   xrootd_sd_staged_t;

/* Protocol-neutral stat the driver fills; the VFS maps it to xrootd_vfs_stat_t. */
typedef struct {
    off_t       size;
    time_t      mtime;
    time_t      ctime;
    mode_t      mode;
    ino_t       ino;
    unsigned    is_dir:1;
    unsigned    is_reg:1;
} xrootd_sd_stat_t;

/* One directory entry name (NUL-terminated). POSIX = a dirent name; object =
 * the final path component synthesized from a key under the listing prefix. */
typedef struct {
    char        name[256];
} xrootd_sd_dirent_t;

/* Metadata-mutation request for the driver's setattr slot — the storage-neutral
 * union of kXR_chmod (mode) and kXR_setattr (times + owner). Each set_* flag gates
 * its field group; an unset group is left untouched. atime/mtime carry per-field
 * UTIME_OMIT / UTIME_NOW in tv_nsec (utimensat(2) semantics). uid/gid of
 * (uid_t)-1 / (gid_t)-1 leave that id unchanged. A driver applies what its
 * namespace can represent (e.g. a catalog backend may not track owner/atime). */
typedef struct {
    unsigned         set_mode:1;
    unsigned         set_times:1;
    unsigned         set_owner:1;
    mode_t           mode;
    struct timespec  atime;
    struct timespec  mtime;
    uid_t            uid;
    gid_t            gid;
} xrootd_sd_setattr_t;

/* Per-export bound driver instance: the driver, its log, an instance-lifetime
 * pool, and driver-private state (POSIX: rootfd + root_canon). */
struct xrootd_sd_instance_s {
    const xrootd_sd_driver_t *driver;
    ngx_log_t                *log;
    ngx_pool_t               *pool;
    void                     *state;
};

/* Opaque open object. fd is the real descriptor for CAP_FD backends, else
 * NGX_INVALID_FILE. snap is the metadata captured at open. state is driver-
 * private (object key/upload state for non-POSIX backends). */
struct xrootd_sd_obj_s {
    const xrootd_sd_driver_t *driver;
    xrootd_sd_instance_t     *inst;
    ngx_fd_t                  fd;
    xrootd_sd_stat_t          snap;
    void                     *state;
    /* 1 iff driver->open allocated THIS obj struct on the heap (malloc), so a
     * caller that adopts the object by value (the VFS copies *o into its handle)
     * knows to free the now-redundant shell. Drivers that allocate the obj on a
     * pool (e.g. POSIX) leave it 0. The per-open `state` is always released by
     * driver->close, independent of this flag. */
    unsigned                  heap_shell:1;
};

struct xrootd_sd_dir_s {
    xrootd_sd_instance_t     *inst;
    void                     *state;
};

struct xrootd_sd_staged_s {
    xrootd_sd_instance_t     *inst;
    void                     *state;
};

/* ---- the driver vtable ----------------------------------------------------
 * Flat, POD-pointer-only so the raw-I/O ops can run on an AIO worker thread.
 * The raw byte ops (pread/pwrite/ftruncate/fsync/fstat) are WORKER-SAFE: no
 * nginx pool, metrics, log, or cache. inst-keyed ops take an already-confined
 * logical path; each driver enforces its own physical confinement. */
struct xrootd_sd_driver_s {
    const char *name;        /* "posix" | "block" | "s3" */
    uint32_t    caps;        /* xrootd_sd_cap_t bitmap    */

    /* instance lifecycle (event loop, at config/worker init) */
    ngx_int_t  (*init)   (xrootd_sd_instance_t *inst, void *driver_conf);
    void       (*cleanup)(xrootd_sd_instance_t *inst);

    /* object lifecycle */
    xrootd_sd_obj_t *(*open)(xrootd_sd_instance_t *inst, const char *path,
                             int sd_flags, mode_t mode, int *err_out);
    ngx_int_t  (*close)(xrootd_sd_obj_t *obj);

    /* worker-safe raw byte I/O */
    ssize_t    (*pread)    (xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off);
    ssize_t    (*pwrite)   (xrootd_sd_obj_t *obj, const void *buf, size_t len, off_t off);
    ssize_t    (*preadv)   (xrootd_sd_obj_t *obj, const struct iovec *iov,
                            int iovcnt, off_t off);
    ssize_t    (*preadv2)  (xrootd_sd_obj_t *obj, const struct iovec *iov,
                            int iovcnt, off_t off, int flags);
    ssize_t    (*copy_range)(xrootd_sd_obj_t *src, off_t src_off,
                             xrootd_sd_obj_t *dst, off_t dst_off, size_t len);
    /* Decide whether [off, off+len) of this object can be served zero-copy and,
     * if so, return the kernel fd to sendfile from; else NGX_INVALID_FILE
     * ("serve memory-backed"). want_zerocopy is the VFS's storage-neutral
     * transport verdict (1 = cleartext, no per-read CRC; 0 = must copy in
     * userspace). The BACKEND owns this decision — the VFS only passes the
     * request + transport context and consumes the answer. A NULL slot means
     * the backend never sendfiles. */
    ngx_fd_t   (*read_sendfile_fd)(xrootd_sd_obj_t *obj, off_t off, size_t len,
                                   unsigned want_zerocopy);
    ngx_int_t  (*ftruncate)(xrootd_sd_obj_t *obj, off_t len);
    ngx_int_t  (*fsync)    (xrootd_sd_obj_t *obj);
    ngx_int_t  (*fstat)    (xrootd_sd_obj_t *obj, xrootd_sd_stat_t *out);

    /* namespace (logical paths) */
    ngx_int_t  (*stat)       (xrootd_sd_instance_t *inst, const char *path,
                              xrootd_sd_stat_t *out);
    ngx_int_t  (*unlink)     (xrootd_sd_instance_t *inst, const char *path, int is_dir);
    ngx_int_t  (*mkdir)      (xrootd_sd_instance_t *inst, const char *path, mode_t mode);
    ngx_int_t  (*rename)     (xrootd_sd_instance_t *inst, const char *src,
                              const char *dst, int noreplace);
    ngx_int_t  (*server_copy)(xrootd_sd_instance_t *inst, const char *src,
                              const char *dst, off_t *bytes_out);
    /* Mutate a path's metadata (mode / times / owner) per the set_* mask. NULL ⇒
     * the backend has no mutable metadata (block/object data-only namespaces); the
     * VFS treats that as a no-op success so MKCOL/PUT chmod flows still pass. A
     * backend applies only what its namespace can represent and returns ENOENT for
     * an absent path, 0 on success, -1/errno otherwise. */
    ngx_int_t  (*setattr)    (xrootd_sd_instance_t *inst, const char *path,
                              const xrootd_sd_setattr_t *attr);

    /* directory iteration */
    xrootd_sd_dir_t *(*opendir)(xrootd_sd_instance_t *inst, const char *path,
                                int *err_out);
    ngx_int_t  (*readdir) (xrootd_sd_dir_t *d, xrootd_sd_dirent_t *out);
    ngx_int_t  (*closedir)(xrootd_sd_dir_t *d);

    /* xattr / object metadata */
    ssize_t    (*getxattr) (xrootd_sd_instance_t *inst, const char *path,
                            const char *name, void *buf, size_t cap);
    ssize_t    (*listxattr)(xrootd_sd_instance_t *inst, const char *path,
                            void *buf, size_t cap);
    ngx_int_t  (*setxattr) (xrootd_sd_instance_t *inst, const char *path,
                            const char *name, const void *val, size_t len, int flags);
    ngx_int_t  (*removexattr)(xrootd_sd_instance_t *inst, const char *path,
                              const char *name);

    /* staged/atomic write (multipart for object stores) */
    xrootd_sd_staged_t *(*staged_open)(xrootd_sd_instance_t *inst,
                                       const char *final_path, mode_t mode,
                                       int *err_out);
    ssize_t    (*staged_write) (xrootd_sd_staged_t *st, const void *buf,
                                size_t len, off_t off);
    ngx_int_t  (*staged_commit)(xrootd_sd_staged_t *st, int noreplace);
    void       (*staged_abort) (xrootd_sd_staged_t *st);
};

/* ---- capability-gated accessors (never poke the vtable directly) ---------- */

/* The instance's capability bitmap (0 when inst/driver is NULL). */
uint32_t xrootd_sd_caps(const xrootd_sd_instance_t *inst);
/* The object's real fd, or NGX_INVALID_FILE when the backend lacks CAP_FD. */
ngx_fd_t xrootd_sd_fd(const xrootd_sd_obj_t *obj);
/* The backend driver name ("posix" by default; "?" when inst is NULL). */
const char *xrootd_sd_backend_name(const xrootd_sd_instance_t *inst);
/* 1 iff the instance advertises ALL bits in required_caps. */
ngx_int_t xrootd_sd_supports(const xrootd_sd_instance_t *inst,
    uint32_t required_caps);

/* ---- registry ------------------------------------------------------------- */

/* Look up a registered driver by name (e.g. "posix"); NULL if unknown. */
const xrootd_sd_driver_t *xrootd_sd_driver_find(const char *name);
/* Build a per-export instance: alloc on pool, bind the named driver, run its
 * init() with driver_conf. Returns the instance, or NULL with *err_out set
 * (ENOENT = unknown driver). The POSIX driver_conf is the root_canon string. */
xrootd_sd_instance_t *xrootd_sd_instance_create(ngx_pool_t *pool, ngx_log_t *log,
    const char *name, void *driver_conf, int *err_out);
/* Tear down an instance (driver cleanup()); NULL-safe. */
void xrootd_sd_instance_destroy(xrootd_sd_instance_t *inst);

/* The built-in POSIX driver (defined in sd_posix.c). */
extern const xrootd_sd_driver_t xrootd_sd_posix_driver;

/* Unconfined open of `path` with backend-neutral XROOTD_SD_O_* flags — the
 * ngx-free counterpart of the server's confined sd_posix_open (which resolves
 * under a rootfd via RESOLVE_BENEATH). For the userland clients, whose endpoints
 * are arbitrary user paths with no export root. Shares the flag vocabulary +
 * O_* mapping with the driver so the open is single-sourced. Returns an fd, or
 * -1 with errno set. (Defined in sd_posix.c; compiled in every build.) */
int xrootd_sd_posix_open_unconfined(const char *path, int sd_flags, mode_t mode);

/* The built-in block-device driver (defined in sd_block.c): raw fd I/O identical
 * to POSIX + a BLKGETSIZE64-aware fstat. Shared by the client (block:// copy
 * endpoints) and any future block-backed server export. */
extern const xrootd_sd_driver_t xrootd_sd_block_driver;

/* Open a block device unconfined (no create/truncate — opened in place).
 * Returns an fd, or -1 with errno set. (Defined in sd_block.c.) */
int xrootd_sd_block_open_unconfined(const char *path, int sd_flags, mode_t mode);

/* The driver used for an export that selects no explicit backend (today: POSIX).
 * Lets the VFS resolve "the default backend" without naming a concrete driver. */
const xrootd_sd_driver_t *xrootd_sd_default_driver(void);

#if XROOTD_HAVE_SQLITE
/* ---- pblock: full-parity, block-based POSIX drop-in (sd_pblock.c) ----------
 * A complete backend that stores opaque object bytes in real POSIX blob files
 * (real kernel fds → CAP_FD/SENDFILE, full random I/O) and the entire logical
 * namespace + metadata in a SQLite catalog (sd_pblock_catalog.c). It advertises
 * the same capabilities as POSIX and implements every vtable slot; the hot byte
 * path never touches SQLite. Compiled only when the build found libsqlite3. */
extern const xrootd_sd_driver_t xrootd_sd_pblock_driver;

/* driver_conf for xrootd_sd_pblock_driver.init(): the export's storage root (the
 * blob folder `data/` and `catalog.db` are created beneath it), the SQLite busy
 * timeout used for cross-worker write contention, and the default object block
 * size (bytes) for NEW files — 0 selects PBLOCK_DEFAULT_BLOCK_SIZE (64 MiB). The
 * block size is recorded per file at creation, so retuning it only affects files
 * written afterwards. */
typedef struct {
    const char *root;
    int         busy_timeout_ms;
    int64_t     block_size;
} xrootd_sd_pblock_conf_t;
#endif

/* Build a pool-lived POSIX instance that BORROWS an already-open persistent
 * rootfd (+ root_canon) — it neither opens nor closes that fd. For the VFS hot
 * open path, which already holds the export's persistent confinement anchor.
 * Returns NULL (errno set) for rootfd < 0 or on OOM. (Defined in sd_posix.c.) */
xrootd_sd_instance_t *xrootd_sd_posix_borrow_instance(ngx_pool_t *pool,
    ngx_log_t *log, int rootfd, const char *root_canon);

/* ---- xrootd_sd_posix_wrap — bind a bare fd to a stack POSIX SD object ------
 *
 * WHAT: Zero-initializes *obj and points it at the built-in POSIX driver over a
 *       plain fd, for dispatching a single fd op through the driver vtable.
 *
 * WHY:  The VFS's fd-keyed I/O loops (pread_full/pwrite_full/write_counted) own
 *       the EINTR/short-I/O policy but must route the raw syscall through the
 *       Storage Driver seam. The POSIX raw slots touch only obj->fd, so a
 *       zero-initialized stack object with driver+fd set is sufficient and keeps
 *       the hot path allocation-free.
 *
 * HOW:  ngx_memzero, set the driver pointer and fd.
 */
static ngx_inline void
xrootd_sd_posix_wrap(xrootd_sd_obj_t *obj, ngx_fd_t fd)
{
    ngx_memzero(obj, sizeof(*obj));
    obj->driver = &xrootd_sd_posix_driver;
    obj->fd = fd;
}

#endif /* XROOTD_SD_H */
