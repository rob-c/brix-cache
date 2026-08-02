/*
 * sd.h — Storage Driver (SD) interface: the pluggable layer below the VFS.
 *
 * WHAT: Declares the capability bitmap, the opaque driver/instance/object/dir/
 *       staged handle types, the POD stat/dirent descriptors, the driver vtable
 *       (brix_sd_driver_s), the small capability-gated accessor helpers, and
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
 * HOW:  A driver is a static const brix_sd_driver_t with a caps bitmap and a
 *       flat table of function pointers. The registry (sd_registry.c) builds an
 *       brix_sd_instance_t per export by name; the VFS opens objects on the
 *       instance and runs the worker-safe raw ops (pread/pwrite/...) on the
 *       returned object handle from any dispatch tier. The VFS reaches ALL raw
 *       storage I/O through this seam — raw data syscalls live only in
 *       src/fs/backend/ (invariant 12, enforced by tools/ci/check_vfs_seam.py).
 */
#ifndef BRIX_SD_H
#define BRIX_SD_H

#ifdef XRDPROTO_NO_NGX
/* ngx-free consumers (the native client via shared libxrdproto) include this
 * header ONLY for the worker-safe POSIX raw-fd surface — brix_sd_posix_wrap()
 * + the driver's pread/pwrite/... slots — which touch no nginx runtime. Supply
 * the minimal nginx type/macro surface this header *names* so it compiles
 * without ngx_core.h. Each is a typedef or macro (no runtime symbol), so the
 * built libxrdproto stays ngx-free (check-ngx-free.sh inspects the archive for
 * ngx_* symbols). The ngx-coupled namespace/instance/registry slots are simply
 * absent (NULL) in the ngx-free POSIX driver (see sd_posix.c). */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>   /* free() for brix_sd_obj_release */
#include <string.h>
#include <time.h>     /* struct timespec for brix_sd_setattr_t */
typedef intptr_t          ngx_int_t;
typedef uintptr_t         ngx_uint_t;
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
#include <errno.h>       /* errno/ENOSYS in the inline *_maybe_cred fallbacks; the
                          * ngx-free shared/xrdproto build has no nginx errno pull-in */
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

/* ---- capability bitmap ----------------------------------------------------
 * A driver advertises what it can do; the VFS consults this to shape behaviour
 * (e.g. only emit a sendfile buffer when CAP_SENDFILE). Absences are honest:
 * the VFS degrades or rejects rather than emulating a missing primitive. */
typedef enum {
    BRIX_SD_CAP_FD            = 1u << 0,  /* exposes a real kernel fd          */
    /* CAP_SENDFILE implies CAP_FD: brix_sd_fd(obj) is a real seekable kernel
     * fd valid as the source of sendfile(2) and of an nginx file-backed
     * (b->in_file) buffer for any byte range. A backend without it MUST be
     * served memory-backed; the VFS read path enforces that fallback. */
    BRIX_SD_CAP_SENDFILE      = 1u << 1,
    BRIX_SD_CAP_RANDOM_WRITE  = 1u << 2,  /* pwrite at arbitrary offset        */
    BRIX_SD_CAP_RANGE_READ    = 1u << 3,  /* pread at arbitrary offset         */
    BRIX_SD_CAP_TRUNCATE      = 1u << 4,  /* ftruncate                         */
    BRIX_SD_CAP_SERVER_COPY   = 1u << 5,  /* native copy (copy_file_range/COPY)*/
    BRIX_SD_CAP_XATTR         = 1u << 6,  /* user.* xattrs / object metadata   */
    BRIX_SD_CAP_HARD_RENAME   = 1u << 7,  /* atomic rename (else copy+delete)  */
    BRIX_SD_CAP_DIRS          = 1u << 8,  /* real directories (else key-prefix)*/
    BRIX_SD_CAP_APPEND        = 1u << 9,  /* O_APPEND semantics                */
    BRIX_SD_CAP_IOURING       = 1u << 10, /* fd is io_uring-submittable        */
    BRIX_SD_CAP_FSCS          = 1u << 11, /* filesystem page checksums (CSI)   */
    /* The backend is NEARLINE (tape/MSS): an object may be offline, so a read can
     * fault a slow async recall instead of returning bytes. A nearline backend
     * advertises this AND implements the recall slot below; the composing registry
     * then REQUIRES a cache tier (the recall target, phase-64 P4/§9.4) in front of
     * it. Drivers that always serve online leave this 0 (the common case). */
    BRIX_SD_CAP_NEARLINE      = 1u << 12, /* tape/MSS: reads may recall (§9)    */
    BRIX_SD_CAP_CATALOG       = 1u << 13, /* native object-catalog enumeration  */
    /* phase-71 capability-uniformity: split implicit read-only/writable and
     * memory-serve assumptions out of VFS backend-identity branches into caps. */
    BRIX_SD_CAP_DIRS_WRITE    = 1u << 14, /* mutable catalog: mkdir/rmdir/rename */
    BRIX_SD_CAP_XATTR_WRITE   = 1u << 15, /* set/remove xattr (read = CAP_XATTR) */
    BRIX_SD_CAP_MEMFILE       = 1u << 16  /* serve bytes memory-backed w/o CAP_FD */
} brix_sd_cap_t;

/* Per-open credential types — brix_sd_cred_kind_t, enum brix_cred_mode,
 * brix_sd_cred_t (split out; sd.h < 600 LOC). */
#include "sd_cred_types.h"

/* ---- SD open flags --------------------------------------------------------
 * Backend-neutral open intent. The POSIX driver maps these to O_* internally;
 * non-POSIX drivers interpret them in their own terms. */
#define BRIX_SD_O_READ     0x01
#define BRIX_SD_O_WRITE    0x02
#define BRIX_SD_O_CREATE   0x04
#define BRIX_SD_O_EXCL     0x08
#define BRIX_SD_O_TRUNC    0x10
#define BRIX_SD_O_APPEND   0x20
#define BRIX_SD_O_DIR      0x40
#define BRIX_SD_O_NOFOLLOW 0x80   /* refuse a symlink at the final component */

/* ---- read-advise hints ----------------------------------------------------
 * Backend-neutral access-pattern advice for the optional read_advise slot.
 * SEQUENTIAL grows the whole-fd read-ahead window (a streaming GET); WILLNEED
 * forces immediate range read-ahead (the windowed prefetch subsystem); RANDOM
 * shrinks read-ahead. Different tools — do not collapse them. */
#define BRIX_SD_ADV_SEQUENTIAL 0
#define BRIX_SD_ADV_WILLNEED   1
#define BRIX_SD_ADV_RANDOM     2

typedef struct brix_sd_driver_s   brix_sd_driver_t;
typedef struct brix_sd_instance_s brix_sd_instance_t;
typedef struct brix_sd_obj_s      brix_sd_obj_t;
typedef struct brix_sd_dir_s      brix_sd_dir_t;
typedef struct brix_sd_staged_s   brix_sd_staged_t;

/* Residency of a nearline (tape/MSS) object — the online/offline model the VFS
 * residency seam (brix_vfs_residency) exposes to protocol handlers so they can
 * advertise tape state (the HTTP Tape REST API, S3 InvalidObjectState /
 * x-amz-storage-class, root:// stat's nearline flag) WITHOUT forcing a recall. A
 * non-nearline driver has no residency slot; the seam reports ONLINE for it (a
 * plain disk/object export is always resident). */
typedef enum {
    BRIX_SD_RES_ONLINE   = 0,  /* resident in the online buffer, readable now      */
    BRIX_SD_RES_NEARLINE = 1,  /* on the backend, stageable (a recall faults it in) */
    BRIX_SD_RES_OFFLINE  = 2,  /* on the backend, not retrievable right now         */
    BRIX_SD_RES_LOST     = 3   /* the object is gone                                */
} brix_sd_residency_t;

/* Driver space report (optional `space` slot, phase-83 F5): the backend's own
 * view of total/used/free bytes for the export — quota-aware logical space for
 * catalog backends (pblock), rather than the raw statvfs(2) of the filesystem
 * under it. Consumers: kXR_statvfs, SRR reporting. */
typedef struct {
    uint64_t total_bytes;
    uint64_t used_bytes;
    uint64_t free_bytes;
} brix_sd_space_t;

/* One entry the catalog-enumeration verb (driver->enumerate) reports per stored
 * backend object — independent of the namespace. `key` is the backend object key
 * (always present). `path` is the logical path the driver recovered for it, or
 * NULL when it cannot (⇒ an orphan-object candidate). size/mtime are valid only
 * when have_stat (the enumerator was asked for stats and the per-object stat
 * succeeded). All pointers are owned by the enumerator and valid only for the
 * duration of the callback. */
typedef struct {
    const char *key;
    const char *path;
    int         have_stat;
    off_t       size;
    time_t      mtime;
} brix_sd_catalog_ent_t;

/* Per-object callback fired by driver->enumerate. Return 0 to continue the
 * enumeration, non-zero to abort it (that code is returned to the caller). */
typedef int (*brix_sd_catalog_cb)(void *ctx, const brix_sd_catalog_ent_t *ent);

/* Protocol-neutral stat the driver fills; the VFS maps it to brix_vfs_stat_t.
 * uid/gid are the owner ids in the driver's own namespace (POSIX: kernel ids;
 * pblock: catalog-internal synthetic ids); 0 for backends with no owner model. */
typedef struct {
    off_t       size;
    time_t      mtime;
    time_t      ctime;
    mode_t      mode;
    ino_t       ino;
    uid_t       uid;
    gid_t       gid;
    unsigned    is_dir:1;
    unsigned    is_reg:1;
} brix_sd_stat_t;

/* One directory entry name (NUL-terminated). POSIX = a dirent name; object =
 * the final path component synthesized from a key under the listing prefix.
 * d_type is the entry's DT_* kind (dirent.h) when the backend can classify it
 * cheaply, else DT_UNKNOWN (= 0, what a memzero'd entry reads) — consumers
 * fall back to a stat; a backend must never guess. NEVER an authorization or
 * confinement input (a spoofed d_type may only cost a fallback stat). */
typedef struct {
    char           name[256];
    unsigned char  d_type;
} brix_sd_dirent_t;

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
} brix_sd_setattr_t;

/* Per-export bound driver instance: the driver, its log, an instance-lifetime
 * pool, and driver-private state (POSIX: rootfd + root_canon). */
struct brix_sd_instance_s {
    const brix_sd_driver_t *driver;
    ngx_log_t                *log;
    ngx_pool_t               *pool;
    void                     *state;
    /* Effective capability bitmap. Seeded from driver->caps at instance create;
     * a driver's init may narrow/extend it per export (Phase-83 pblock lab caps=
     * mask). brix_sd_caps()/brix_sd_fd() read THIS, not driver->caps, so a masked
     * capability is honoured everywhere the VFS dispatches on caps. */
    uint32_t                  caps;
};

/* Opaque open object. fd is the real descriptor for CAP_FD backends, else
 * NGX_INVALID_FILE. snap is the metadata captured at open. state is driver-
 * private (object key/upload state for non-POSIX backends). */
struct brix_sd_obj_s {
    const brix_sd_driver_t *driver;
    brix_sd_instance_t     *inst;
    ngx_fd_t                  fd;
    brix_sd_stat_t          snap;
    void                     *state;
    /* 1 iff driver->open allocated THIS obj struct on the heap (malloc), so a
     * caller that adopts the object by value (the VFS copies *o into its handle)
     * knows to free the now-redundant shell. Drivers that allocate the obj on a
     * pool (e.g. POSIX) leave it 0. The per-open `state` is always released by
     * driver->close, independent of this flag. */
    unsigned                  heap_shell:1;
};

struct brix_sd_dir_s {
    brix_sd_instance_t     *inst;
    void                     *state;
};

struct brix_sd_staged_s {
    brix_sd_instance_t     *inst;
    void                     *state;
};

/* ---- the driver vtable ----------------------------------------------------
 * Flat, POD-pointer-only so the raw-I/O ops can run on an AIO worker thread.
 * The raw byte ops (pread/pwrite/ftruncate/fsync/fstat) are WORKER-SAFE: no
 * nginx pool, metrics, log, or cache. inst-keyed ops take an already-confined
 * logical path; each driver enforces its own physical confinement. */
struct brix_sd_driver_s {
    const char *name;        /* "posix" | "block" | "s3" */
    uint32_t    caps;        /* brix_sd_cap_t bitmap    */
    uint32_t    cred_accept; /* OR of brix_sd_cred_kind_t consumed; 0 = none */

    /* instance lifecycle (event loop, at config/worker init) */
    ngx_int_t  (*init)   (brix_sd_instance_t *inst, void *driver_conf);
    void       (*cleanup)(brix_sd_instance_t *inst);

    /* object lifecycle */
    brix_sd_obj_t *(*open)(brix_sd_instance_t *inst, const char *path,
                             int sd_flags, mode_t mode, int *err_out);
    ngx_int_t  (*close)(brix_sd_obj_t *obj);

    /* worker-safe raw byte I/O */
    ssize_t    (*pread)    (brix_sd_obj_t *obj, void *buf, size_t len, off_t off);
    ssize_t    (*pwrite)   (brix_sd_obj_t *obj, const void *buf, size_t len, off_t off);
    ssize_t    (*preadv)   (brix_sd_obj_t *obj, const struct iovec *iov,
                            int iovcnt, off_t off);
    ssize_t    (*preadv2)  (brix_sd_obj_t *obj, const struct iovec *iov,
                            int iovcnt, off_t off, int flags);
    ssize_t    (*copy_range)(brix_sd_obj_t *src, off_t src_off,
                             brix_sd_obj_t *dst, off_t dst_off, size_t len);
    /* Decide whether [off, off+len) of this object can be served zero-copy and,
     * if so, return the kernel fd to sendfile from; else NGX_INVALID_FILE
     * ("serve memory-backed"). want_zerocopy is the VFS's storage-neutral
     * transport verdict (1 = cleartext, no per-read CRC; 0 = must copy in
     * userspace). The BACKEND owns this decision — the VFS only passes the
     * request + transport context and consumes the answer. A NULL slot means
     * the backend never sendfiles. */
    ngx_fd_t   (*read_sendfile_fd)(brix_sd_obj_t *obj, off_t off, size_t len,
                                   unsigned want_zerocopy);
    ngx_int_t  (*ftruncate)(brix_sd_obj_t *obj, off_t len);
    ngx_int_t  (*fsync)    (brix_sd_obj_t *obj);
    ngx_int_t  (*fstat)    (brix_sd_obj_t *obj, brix_sd_stat_t *out);
    /* Access-pattern advice for [off, off+len) (len == 0 ⇒ whole object);
     * advice ∈ BRIX_SD_ADV_*. Advisory only: NGX_OK whether or not the kernel
     * honoured it, NGX_ERROR (errno set) only on a hard failure the caller may
     * log and ignore. Must not change position, size, or contents. Worker-safe
     * (no pool/metrics/log). NULL ⇒ the backend has no advice primitive (the
     * VFS treats the call as a no-op). */
    ngx_int_t  (*read_advise)(brix_sd_obj_t *obj, off_t off, size_t len,
                              int advice);

    /* namespace (logical paths) */
    ngx_int_t  (*stat)       (brix_sd_instance_t *inst, const char *path,
                              brix_sd_stat_t *out);
    ngx_int_t  (*unlink)     (brix_sd_instance_t *inst, const char *path, int is_dir);
    ngx_int_t  (*mkdir)      (brix_sd_instance_t *inst, const char *path, mode_t mode);
    ngx_int_t  (*rename)     (brix_sd_instance_t *inst, const char *src,
                              const char *dst, int noreplace);
    ngx_int_t  (*server_copy)(brix_sd_instance_t *inst, const char *src,
                              const char *dst, off_t *bytes_out);
    /* Mutate a path's metadata (mode / times / owner) per the set_* mask. NULL ⇒
     * the backend has no mutable metadata (block/object data-only namespaces); the
     * VFS treats that as a no-op success so MKCOL/PUT chmod flows still pass. A
     * backend applies only what its namespace can represent and returns ENOENT for
     * an absent path, 0 on success, -1/errno otherwise. */
    ngx_int_t  (*setattr)    (brix_sd_instance_t *inst, const char *path,
                              const brix_sd_setattr_t *attr);

    /* directory iteration */
    brix_sd_dir_t *(*opendir)(brix_sd_instance_t *inst, const char *path,
                                int *err_out);
    ngx_int_t  (*readdir) (brix_sd_dir_t *d, brix_sd_dirent_t *out);
    ngx_int_t  (*closedir)(brix_sd_dir_t *d);

    /* xattr / object metadata */
    ssize_t    (*getxattr) (brix_sd_instance_t *inst, const char *path,
                            const char *name, void *buf, size_t cap);
    ssize_t    (*listxattr)(brix_sd_instance_t *inst, const char *path,
                            void *buf, size_t cap);
    ngx_int_t  (*setxattr) (brix_sd_instance_t *inst, const char *path,
                            const char *name, const void *val, size_t len, int flags);
    ngx_int_t  (*removexattr)(brix_sd_instance_t *inst, const char *path,
                              const char *name);

    /* staged/atomic write (multipart for object stores) */
    brix_sd_staged_t *(*staged_open)(brix_sd_instance_t *inst,
                                       const char *final_path, mode_t mode,
                                       int *err_out);
    ssize_t    (*staged_write) (brix_sd_staged_t *st, const void *buf,
                                size_t len, off_t off);
    ngx_int_t  (*staged_commit)(brix_sd_staged_t *st, int noreplace);
    void       (*staged_abort) (brix_sd_staged_t *st);
    /* Physical path of the staged temp file, or NULL when the staged write has
     * no local file (remote/object stores). Lets the cache tier verify a fill
     * against its digest (and quarantine a mismatch) before commit — phase-68.
     * Optional slot: NULL means "no path available". */
    const char *(*staged_path) (const brix_sd_staged_t *st);

    /* nearline (tape/MSS) recall — phase-64 §9.3. Initiate or join an async recall
     * of `key` from offline (tape) into the backend's online buffer, returning a
     * stable request id in reqid_out (≤39 chars + NUL) that the cache tier parks a
     * stalled open on (brix_stage waiter). Returns NGX_AGAIN (queued / in-flight —
     * park the open), NGX_OK (already online — do a normal cache-fill), or NGX_ERROR
     * (errno set). NULL on non-nearline drivers (the VFS/cache never calls it unless
     * BRIX_SD_CAP_NEARLINE is advertised). */
    ngx_int_t  (*recall)(brix_sd_instance_t *inst, const char *key,
                         char reqid_out[40]);

    /* nearline residency (tape/MSS) — classify `key` as online/nearline/offline/lost
     * WITHOUT initiating a recall (a pure read of the MSS residency model). The VFS
     * residency seam (brix_vfs_residency) calls this only on a driver advertising
     * BRIX_SD_CAP_NEARLINE; NULL elsewhere (the seam reports ONLINE). Returns
     * NGX_OK (out set) or NGX_ERROR (errno set, e.g. ENOENT for an unknown key). */
    ngx_int_t  (*residency)(brix_sd_instance_t *inst, const char *key,
                            brix_sd_residency_t *out);

    /* export space report (phase-83 F5) — the driver's own total/used/free view
     * (quota-aware logical space for catalog backends). NULL ⇒ the caller falls
     * back to statvfs(2) on the export root. Returns NGX_OK (out set) or
     * NGX_ERROR (errno set). */
    ngx_int_t  (*space)(brix_sd_instance_t *inst, brix_sd_space_t *out);

    /* object-catalog enumeration (inventory/drift, spec §E1/D2). Enumerate the
     * driver's OWN physical object catalog — NOT a namespace walk — firing cb
     * once per stored object (brix_sd_catalog_ent_t). want_stat asks for
     * size/mtime per object (an extra per-object stat). Returns NGX_OK (full
     * enumeration; cb may have aborted early), or NGX_ERROR (errno set). NULL on
     * drivers with no native catalog (POSIX: the namespace IS the catalog) — the
     * VFS wrapper then reports ENOTSUP. Advertised via BRIX_SD_CAP_CATALOG. */
    ngx_int_t  (*enumerate)(brix_sd_instance_t *inst, int want_stat,
                            brix_sd_catalog_cb cb, void *ctx);

    /* credential-scoped open slots (OPTIONAL — Phase 1 per-user backend auth).
     *
     * WHAT: Like open / staged_open but carries a per-user brix_sd_cred_t so the
     *       driver can authenticate to the remote backend as the requesting user
     *       rather than the static service credential.
     *
     * WHY:  Data-plane opens need user identity; namespace ops (stat/rename/…)
     *       stay on the service credential in Phase 1 — threading cred everywhere
     *       is deferred.
     *
     * HOW:  NULL on any driver that does not implement per-user auth (POSIX, block,
     *       pblock, Ceph — service-level or user-impersonated elsewhere). sd_xroot
     *       implements both: it copies the proxy path into the fill task before
     *       calling brix_cache_origin_bootstrap, where it wins over every static
     *       service credential. Designated-initializer drivers that omit these
     *       slots get NULL; the forwarders below fall back to the plain slot. */
    brix_sd_obj_t    *(*open_cred)(brix_sd_instance_t *inst, const char *path,
                                    int sd_flags, mode_t mode,
                                    const brix_sd_cred_t *cred, int *err_out);
    brix_sd_staged_t *(*staged_open_cred)(brix_sd_instance_t *inst,
                                           const char *final_path, mode_t mode,
                                           const brix_sd_cred_t *cred,
                                           int *err_out);

    /* credential-scoped namespace slots (OPTIONAL — Phase 2 Task 1 per-user
     * backend auth for namespace/metadata operations).
     *
     * WHAT: Like the plain namespace slots (stat/unlink/mkdir/rename/…) but each
     *       accepts a trailing const brix_sd_cred_t * so the driver can open the
     *       remote session as the requesting user rather than the static service
     *       credential for every path-based op, not just data-plane opens.
     *
     * WHY:  Without these, a deny-mode request whose credential gate fires on the
     *       data-plane still has its probe stat (brix_vfs_probe) run under the
     *       service credential, violating the invariant that a denied request must
     *       never reach the origin.  Extending the cred to namespace ops closes
     *       that gap completely.
     *
     * HOW:  NULL on any driver that does not support per-user namespace auth.
     *       sd_xroot registers implementations for every ns op it supports.
     *       Designated-initializer drivers that omit these slots get NULL; the
     *       brix_sd_<op>_maybe_cred forwarders below fall back to the plain slot.
     *       The capability-check (stat_cred != NULL) is the canonical gate for the
     *       VFS brix_vfs_ns_cred() decision. */
    ngx_int_t      (*stat_cred)(brix_sd_instance_t *inst, const char *path,
                                 brix_sd_stat_t *out,
                                 const brix_sd_cred_t *cred);
    ngx_int_t      (*unlink_cred)(brix_sd_instance_t *inst, const char *path,
                                   int is_dir,
                                   const brix_sd_cred_t *cred);
    ngx_int_t      (*mkdir_cred)(brix_sd_instance_t *inst, const char *path,
                                  mode_t mode,
                                  const brix_sd_cred_t *cred);
    ngx_int_t      (*rename_cred)(brix_sd_instance_t *inst, const char *src,
                                   const char *dst, int noreplace,
                                   const brix_sd_cred_t *cred);
    ngx_int_t      (*setattr_cred)(brix_sd_instance_t *inst, const char *path,
                                    const brix_sd_setattr_t *attr,
                                    const brix_sd_cred_t *cred);
    ssize_t        (*getxattr_cred)(brix_sd_instance_t *inst, const char *path,
                                     const char *name, void *buf, size_t cap,
                                     const brix_sd_cred_t *cred);
    ssize_t        (*listxattr_cred)(brix_sd_instance_t *inst, const char *path,
                                      void *buf, size_t cap,
                                      const brix_sd_cred_t *cred);
    ngx_int_t      (*setxattr_cred)(brix_sd_instance_t *inst, const char *path,
                                     const char *name, const void *val,
                                     size_t len, int flags,
                                     const brix_sd_cred_t *cred);
    ngx_int_t      (*removexattr_cred)(brix_sd_instance_t *inst,
                                        const char *path, const char *name,
                                        const brix_sd_cred_t *cred);
    ngx_int_t      (*server_copy_cred)(brix_sd_instance_t *inst,
                                        const char *src, const char *dst,
                                        off_t *bytes_out,
                                        const brix_sd_cred_t *cred);
    brix_sd_dir_t *(*opendir_cred)(brix_sd_instance_t *inst, const char *path,
                                    int *err_out,
                                    const brix_sd_cred_t *cred);
};

/* Release a driver object obtained from driver->open() by a caller that holds it
 * by POINTER (not the VFS, which adopts the object by value and frees the shell
 * itself in vfs_open.c): close it via its own vtable, then free a heap-allocated
 * shell (heap_shell=1, e.g. POSIX's malloc'd obj — allocated off inst->pool so a
 * cache-fill thread never touches the thread-unsafe ngx_cycle->pool). NULL-safe;
 * a pool-allocated shell (heap_shell=0) is just closed. */
static inline void
brix_sd_obj_release(brix_sd_obj_t *o)
{
    if (o == NULL) {
        return;
    }
    if (o->driver != NULL && o->driver->close != NULL) {
        o->driver->close(o);
    }
    if (o->heap_shell) {
        free(o);
    }
}

/* ---- capability-gated accessors (never poke the vtable directly) ---------- */

/* The instance's capability bitmap (0 when inst/driver is NULL). */
uint32_t brix_sd_caps(const brix_sd_instance_t *inst);
/* The object's real fd, or NGX_INVALID_FILE when the backend lacks CAP_FD. */
ngx_fd_t brix_sd_fd(const brix_sd_obj_t *obj);
/* The backend driver name ("posix" by default; "?" when inst is NULL). */
const char *brix_sd_backend_name(const brix_sd_instance_t *inst);
/* 1 iff the instance advertises ALL bits in required_caps. */
ngx_int_t brix_sd_supports(const brix_sd_instance_t *inst,
    uint32_t required_caps);
/* The instance's accepted-credential-kind bitmap (0 when inst/driver is NULL). */
uint32_t brix_sd_cred_accept(const brix_sd_instance_t *inst);

/* credential-scoped open + namespace forwarders (split out; sd.h < 600 LOC) */
#include "sd_cred_forward.h"

/* ---- registry ------------------------------------------------------------- */
#include "sd_registry.h"

#endif /* BRIX_SD_H */
