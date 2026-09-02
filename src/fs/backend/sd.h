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

#include "sd_ngx_compat.h"  /* nginx surface, real or XRDPROTO_NO_NGX shim */
#include "sd_batch_types.h"  /* brix_sd_unlink_batch_t (C4), brix_sd_precond_t (C6) */
#include "sd_value_types.h"  /* residency/space/catalog/stat/dirent/setattr values */

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
    BRIX_SD_CAP_MEMFILE       = 1u << 16, /* serve bytes memory-backed w/o CAP_FD */
    BRIX_SD_CAP_BULK_DELETE   = 1u << 17, /* unlink_many is a real batch (C4)   */
    /* staged_commit evaluates its brix_sd_precond_t ATOMICALLY at the storage
     * (phase-107 C6): the compare and the publish cannot interleave with a
     * concurrent writer. A driver without the bit may still evaluate a
     * precondition — it then reports the result as ADVISORY by leaving
     * pre->atomic clear, and the protocol layer must not claim RFC 7232
     * semantics for it. The bit is the static claim; pre->atomic is the
     * per-call truth (on `http` the property is a runtime fact about the
     * origin, probed once and recorded, not a compile-time fact). */
    BRIX_SD_CAP_PRECOND       = 1u << 18
} brix_sd_cap_t;

/* Per-open credential types — brix_sd_cred_kind_t, enum brix_cred_mode,
 * brix_sd_cred_t (split out; sd.h < 600 LOC). */
#include "sd_domain.h"      /* brix_vfs_domain_t (phase-107 C9) */
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
    /* What this storage IS; EXPORT == 0, so a zeroing factory yields the
     * strict domain and a service-storage composer overrides it (sd_domain.h). */
    brix_vfs_domain_t         domain;
};

/* Opaque open object. fd is the real descriptor for CAP_FD backends, else
 * NGX_INVALID_FILE. snap is the metadata captured at open. state is driver-
 * private (object key/upload state for non-POSIX backends). */
/* Read-open cache verdict stamped on the returned object by the sd_cache
 * decorator (sd_cache_open_common).  NONE = the open never consulted a cache
 * tier (no tier composed, write/create open, or admission-filtered path).
 * The VFS open orchestrator — the first layer that knows the requesting
 * protocol — translates HIT/MISS into brix_metric_cache_result(). */
#define BRIX_SD_CACHE_OUTCOME_NONE  0u
#define BRIX_SD_CACHE_OUTCOME_HIT   1u
#define BRIX_SD_CACHE_OUTCOME_MISS  2u

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
    /* BRIX_SD_CACHE_OUTCOME_* verdict for this read-open (sd_cache only). */
    unsigned                  cache_outcome:2;
    /* Logical bytes the cache decorator evicted invalidating this path on a
     * WRITE/CREATE/TRUNC open (sd_cache only; 0 otherwise — every driver
     * zero-allocates its obj). The protocol adopt site accounts it via
     * brix_metric_cache_evicted. */
    uint64_t                  cache_evicted_bytes;
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
    /* Space reservation for a declared final object size (OPTIONAL - phase-107
     * C5). The VFS calls it at most once per object, immediately after a
     * create/trunc write-open, and only when the client declared the final size
     * up front (root:// `oss.asize`, HTTP Content-Length, GridFTP ALLO). `size`
     * is the FINAL object size, not a delta. NGX_OK = reserved (or nothing to
     * do); NGX_ERROR with errno ENOSPC/EDQUOT = the declaration cannot be
     * satisfied - the caller FAILS the open; NGX_ERROR with any other errno is
     * ADVISORY (the caller logs at info and the open proceeds). Must not change
     * the object's visible size or contents (FALLOC_FL_KEEP_SIZE semantics).
     * NULL = no reservation primitive (identical to an advisory failure).
     * Staged-plane drivers (remote/xroot/frm) receive the declaration as
     * staged_open's declared_size parameter instead - this slot is the
     * random-write object plane's half of the same C5 contract. No _cred twin:
     * reserve runs inside an already-open object whose credential the driver
     * holds. */
    ngx_int_t  (*reserve)(brix_sd_obj_t *obj, off_t size);

    /* namespace (logical paths) */
    ngx_int_t  (*stat)       (brix_sd_instance_t *inst, const char *path,
                              brix_sd_stat_t *out);
    ngx_int_t  (*unlink)     (brix_sd_instance_t *inst, const char *path, int is_dir);
    /* Bulk delete (phase-107 C4); full contract in sd_batch_types.h. */
    ngx_int_t  (*unlink_many)(brix_sd_instance_t *inst,
                              brix_sd_unlink_batch_t *b);
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
    /* Resize the object at `path` to `len` WITHOUT opening a write handle
     * (kXR_truncate with a path payload). NULL ⇒ the VFS falls back to
     * open()+ftruncate()+close(). A stage decorator forwards this straight to its
     * source, so a truncate over a staged remote backend resizes the origin by
     * name — no whole-file RECALL and no staged write-open that would self-collide
     * on commit. ENOENT for an absent path; 0 on success, -1/errno otherwise. */
    ngx_int_t  (*truncate_path)(brix_sd_instance_t *inst, const char *path,
                                off_t len);

    /* Durable-publish barrier (phase-107 C3). Make the DIRECTORY ENTRY of the
     * just-published object at `path` durable — for a POSIX namespace, fsync
     * the parent directory of `path` (opened O_RDONLY|O_DIRECTORY through the
     * confined-fd machinery, never O_PATH and never by re-resolving the name);
     * for pblock, flush the catalogue's directory. `path` is export-relative
     * and already confined by the caller; the slot derives the parent, never
     * re-resolves. NGX_OK = the entry is durable; NGX_ERROR with errno set
     * (EIO fsync failed, ENOENT parent vanished under a concurrent rmdir).
     * NULL ⇒ the publish is atomic-and-durable at the far end (http/xroot/
     * remote/ceph) or there is no local directory entry (block/mirage) — the
     * caller treats the publish as durable-to-the-far-end. A failed barrier
     * FAILS the publish (the name is already visible; the caller reports EIO
     * and logs at crit rather than claim durability it does not have). */
    ngx_int_t  (*sync_publish)(brix_sd_instance_t *inst, const char *path);

    /* Atomic two-name exchange (phase-107 C6): swap `a` and `b` — both
     * export-relative, already confined by the caller — with NO instant at
     * which either name is missing. renameat2(RENAME_EXCHANGE) on posix, one
     * catalogue transaction on pblock. NULL ⇒ the backend has no primitive
     * and the VFS refuses with ENOTSUP — NEVER emulated with two renames,
     * whose window in which neither name resolves is exactly what the caller
     * asked to avoid (§3.5 fallback doctrine). Both names must exist (ENOENT
     * otherwise, matching RENAME_EXCHANGE). On ENOSYS/EINVAL from a kernel or
     * filesystem without the flag the slot reports ENOTSUP — unlike the
     * NOREPLACE fallback in fs/path/beneath.c there is no pre-checked
     * consolation to degrade to. */
    ngx_int_t  (*exchange)     (brix_sd_instance_t *inst, const char *a,
                                const char *b);

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

    /* staged/atomic write (multipart for object stores).
     * declared_size (phase-107 C5): the final object size the client declared
     * up front, or 0 when none was declared. A driver that can act on it does
     * so AT open - remote derives a legal multipart part size from it, xroot
     * forwards it as `oss.asize` on the origin open, posix/frm preallocate the
     * temp/online buffer - and fails the open with errno ENOSPC/EDQUOT when
     * the declaration cannot be satisfied. Drivers with no use for it ignore
     * it. It is a hint about the eventual commit size, never a limit: writes
     * beyond it remain legal (subject to the driver's own quota/extent). */
    brix_sd_staged_t *(*staged_open)(brix_sd_instance_t *inst,
                                       const char *final_path, mode_t mode,
                                       off_t declared_size, int *err_out);
    ssize_t    (*staged_write) (brix_sd_staged_t *st, const void *buf,
                                size_t len, off_t off);
    /* Publish the staged object, honouring the typed precondition (phase-107
     * C6; contract + refusal errnos in sd_batch_types.h). `pre` may be NULL —
     * NULL and a zeroed struct both mean NONE, the old unconditional commit.
     * ABSENT is the old `noreplace` boolean; MATCH_* is compare-and-publish.
     * A kind the driver cannot evaluate at all is ENOTSUP (never a silent
     * pass, never a two-step emulation); a driver that evaluated at the
     * storage sets pre->atomic (the reason the parameter is non-const). */
    ngx_int_t  (*staged_commit)(brix_sd_staged_t *st, brix_sd_precond_t *pre);
    void       (*staged_abort) (brix_sd_staged_t *st);
    /* Physical path of the staged temp file, or NULL when the staged write has
     * no local file (remote/object stores). Lets the cache tier verify a fill
     * against its digest (and quarantine a mismatch) before commit — phase-68.
     * Optional slot: NULL means "no path available". */
    const char *(*staged_path) (const brix_sd_staged_t *st);

    /* commit-time content dedup (OPTIONAL — phase-88 W1, the G13 seam).
     *
     * WHAT: dedup_publish collapses byte-identical stored copies of the object
     *       at `path` after the CALLER proved its content identity (e.g. a
     *       cvmfs-cas verified fill). `canon` is a stable content-derived alias
     *       (store-relative, leading '/') the driver MAY materialise as a real
     *       name (posix: the /.gcas hardlink farm) or ignore entirely
     *       (refcounting/content-addressed backends: their own catalog already
     *       carries content identity). dedup_gc releases the alias after the
     *       last name referencing its content was removed (posix reaps a
     *       last-link canonical; refcounting backends need no GC — slot NULL).
     *
     * WHY:  Cross-repo dedup of verified CAS objects was hardlink-only and thus
     *       posix-store-only; expressing it as a driver verb lets any backend
     *       with a native dedup primitive (pblock refs) serve brix_cache_global_cas.
     *
     * HOW:  Best-effort contract: NGX_OK = published / folded / benignly
     *       skipped (the per-repo copy is always left correct); NGX_ERROR with
     *       errno only on a hard failure the caller may log (ENOTSUP = the
     *       instance is not armed for dedup). Both run on cache-fill worker
     *       threads: no nginx pool access; inst->log only. NULL = the backend
     *       cannot dedup (config refuses brix_cache_global_cas on it). */
    ngx_int_t  (*dedup_publish)(brix_sd_instance_t *inst, const char *path,
                                const char *canon);
    ngx_int_t  (*dedup_gc)(brix_sd_instance_t *inst, const char *canon);

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

    /* credential-scoped recall twin (phase-107 C2) — same contract as `recall`,
     * running as the REQUESTER rather than the service identity. The recall
     * OUTLIVES the request, so implementations must COPY the borrowed
     * credential, never retain the caller's pointer (the sd_remote opendir
     * asymmetry, written into the contract so it is not rediscovered). NULL
     * where the nearline plane has no per-user leg (frm: the MSS adapter runs
     * as the service; the *_maybe_cred forwarder then refuses in DENY mode). */
    ngx_int_t  (*recall_cred)(brix_sd_instance_t *inst, const char *key,
                              const brix_sd_cred_t *cred, char reqid_out[40]);

    /* evict (phase-107 C2) — drop the ONLINE copy of `path` while the logical
     * object survives elsewhere (a cache-store entry, a clean stage-buffer
     * copy, an MSS-backed online buffer, a simulated tape row, an upstream
     * kXR_prepare(kXR_evict)). Idempotent: NGX_OK even when the copy is already
     * absent, with *bytes_out (optional) = bytes actually freed (0 when the
     * driver cannot know). Gated on the SLOT, not a capability bit — a cache
     * decorator's eviction and a leaf's nearline release are different
     * questions and both are legitimate. NULL where the online copy is the
     * ONLY copy (posix/ceph): evicting there is a delete wearing a different
     * verb, and the VFS answers ENOTSUP instead. NGX_ERROR with errno set. */
    ngx_int_t  (*evict)(brix_sd_instance_t *inst, const char *path,
                        uint64_t *bytes_out);
    ngx_int_t  (*evict_cred)(brix_sd_instance_t *inst, const char *path,
                             uint64_t *bytes_out, const brix_sd_cred_t *cred);

    /* export space report (phase-83 F5) — the driver's own total/used/free view
     * (quota-aware logical space for catalog backends). NULL ⇒ the caller falls
     * back to statvfs(2) on the export root. Returns NGX_OK (out set) or
     * NGX_ERROR (errno set). */
    ngx_int_t  (*space)(brix_sd_instance_t *inst, brix_sd_space_t *out);

    /* native digest query (checksum offload) — ask the backend for a stored or
     * origin-advertised digest of the open object in EXACTLY the requested
     * canonical algorithm, WITHOUT reading the object's bytes (a root:// origin's
     * kXR_Qcksum, an object store's stored checksum). Returns NGX_OK with
     * hex_out filled (lowercase hex, NUL-terminated) only when the backend
     * digest is authoritative for `algo`; NGX_DECLINED when it holds no digest
     * in that algorithm; NGX_ERROR on a transport fault. Callers treat
     * DECLINED and ERROR identically — fall back to the byte-reading compute —
     * so a network fault can never fail a checksum request the compute path can
     * still satisfy. Worker-safe (runs on AIO threads, like pread). NULL ⇒ the
     * backend has no native digests. */
    ngx_int_t  (*query_checksum)(brix_sd_obj_t *obj, const char *algo,
                                 char *hex_out, size_t hex_sz);

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
                                           off_t declared_size,
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
    ngx_int_t      (*unlink_many_cred)(brix_sd_instance_t *inst,
                                        brix_sd_unlink_batch_t *b,
                                        const brix_sd_cred_t *cred);
    ngx_int_t      (*mkdir_cred)(brix_sd_instance_t *inst, const char *path,
                                  mode_t mode,
                                  const brix_sd_cred_t *cred);
    ngx_int_t      (*rename_cred)(brix_sd_instance_t *inst, const char *src,
                                   const char *dst, int noreplace,
                                   const brix_sd_cred_t *cred);
    /* exchange has a _cred twin because it is a namespace operation on two
     * paths that may each need the caller's identity; sync_publish does not,
     * because it flushes a directory the driver already holds open. */
    ngx_int_t      (*exchange_cred)(brix_sd_instance_t *inst, const char *a,
                                     const char *b,
                                     const brix_sd_cred_t *cred);
    ngx_int_t      (*setattr_cred)(brix_sd_instance_t *inst, const char *path,
                                    const brix_sd_setattr_t *attr,
                                    const brix_sd_cred_t *cred);
    ngx_int_t      (*truncate_path_cred)(brix_sd_instance_t *inst,
                                    const char *path, off_t len,
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

/* object release + capability-gated accessors (split out; sd.h < 600 LOC) */
#include "sd_accessors.h"

/* credential-scoped open + namespace forwarders (split out; sd.h < 600 LOC) */
#include "sd_cred_forward.h"

/* ---- registry ------------------------------------------------------------- */
#include "sd_registry.h"

#endif /* BRIX_SD_H */
