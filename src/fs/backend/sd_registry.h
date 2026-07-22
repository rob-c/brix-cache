/*
 * sd_registry.h — Storage Driver registry API, built-in driver externs, and the
 *                 stack-object / vectored-read helper wraps.
 *
 * A verbatim relocation of the trailing registry + helper section out of sd.h
 * (pure textual split to keep every SD header < 600 LOC). The inline helpers
 * (brix_sd_posix_wrap / brix_sd_obj_preadv) dereference the full brix_sd_obj_t /
 * brix_sd_driver_t definitions, so this header is a transitive fragment of sd.h,
 * included from there AFTER those structs (and the BRIX_HAVE_SQLITE macro) are
 * in scope — never on its own. Do NOT include this header directly — include
 * "sd.h".
 */
#ifndef BRIX_SD_REGISTRY_H
#define BRIX_SD_REGISTRY_H

#include <errno.h>       /* ENOTSUP in the brix_sd_obj_preadv fallback */
#include <sys/types.h>   /* off_t / mode_t / ssize_t in helper signatures */
#include <sys/uio.h>     /* struct iovec for brix_sd_obj_preadv */

/* ---- registry ------------------------------------------------------------- */

/* Look up a registered driver by name (e.g. "posix"); NULL if unknown. */
const brix_sd_driver_t *brix_sd_driver_find(const char *name);
/* Census: iterate the registered (name-resolvable) filesystems — the table
 * generates from core/types/fs_list.h. For tooling/health surfaces. */
ngx_uint_t brix_sd_driver_count(void);
const brix_sd_driver_t *brix_sd_driver_at(ngx_uint_t i);
/* Build a per-export instance: bind the named driver and run its init() with
 * driver_conf. Returns the instance, or NULL with *err_out set (ENOENT =
 * unknown driver). The POSIX driver_conf is the root_canon string.
 * Instances are process-lifetime singletons allocated from a private pool the
 * registry owns and never destroys — callers must NOT assume any tie to a
 * cycle/request pool (composition may run during configuration parse, when
 * ngx_cycle still names the transient init cycle). */
brix_sd_instance_t *brix_sd_instance_create(ngx_log_t *log,
    const char *name, void *driver_conf, int *err_out);
/* Tear down an instance (driver cleanup()); NULL-safe. */
void brix_sd_instance_destroy(brix_sd_instance_t *inst);

/* The built-in POSIX driver (defined in sd_posix.c). */
extern const brix_sd_driver_t brix_sd_posix_driver;

/* Unconfined open of `path` with backend-neutral BRIX_SD_O_* flags — the
 * ngx-free counterpart of the server's confined sd_posix_open (which resolves
 * under a rootfd via RESOLVE_BENEATH). For the userland clients, whose endpoints
 * are arbitrary user paths with no export root. Shares the flag vocabulary +
 * O_* mapping with the driver so the open is single-sourced. Returns an fd, or
 * -1 with errno set. (Defined in sd_posix.c; compiled in every build.) */
int brix_sd_posix_open_unconfined(const char *path, int sd_flags, mode_t mode);

/* The built-in block-device driver (defined in sd_block.c): raw fd I/O identical
 * to POSIX + a BLKGETSIZE64-aware fstat. Shared by the client (block:// copy
 * endpoints) and any future block-backed server export. */
extern const brix_sd_driver_t brix_sd_block_driver;

/* Open a block device unconfined (no create/truncate — opened in place).
 * Returns an fd, or -1 with errno set. (Defined in sd_block.c.) */
int brix_sd_block_open_unconfined(const char *path, int sd_flags, mode_t mode);

/* The driver used for an export that selects no explicit backend (today: POSIX).
 * Lets the VFS resolve "the default backend" without naming a concrete driver. */
const brix_sd_driver_t *brix_sd_default_driver(void);

#if BRIX_HAVE_SQLITE
/* ---- pblock: full-parity, block-based POSIX drop-in (sd_pblock.c) ----------
 * A complete backend that stores opaque object bytes in real POSIX blob files
 * (real kernel fds → CAP_FD/SENDFILE, full random I/O) and the entire logical
 * namespace + metadata in a SQLite catalog (sd_pblock_catalog.c). It advertises
 * the same capabilities as POSIX and implements every vtable slot; the hot byte
 * path never touches SQLite. Compiled only when the build found libsqlite3. */
extern const brix_sd_driver_t brix_sd_pblock_driver;

/* driver_conf for brix_sd_pblock_driver.init(): the export's storage root (the
 * blob folder `data/` and `catalog.db` are created beneath it), the SQLite busy
 * timeout used for cross-worker write contention, and the default object block
 * size (bytes) for NEW files — 0 selects PBLOCK_DEFAULT_BLOCK_SIZE (64 MiB). The
 * block size is recorded per file at creation, so retuning it only affects files
 * written afterwards.
 *
 * `enforce_unprivileged` + `unpriv_user`: pblock writes blob files and the SQLite
 * catalog as the worker's own uid (it has no impersonation broker and never
 * chowns). Worker-time production builds set `enforce_unprivileged` so a worker
 * that is (mis)configured to run as root is permanently dropped to an
 * unprivileged account — `unpriv_user` if set, else "nobody" — BEFORE any blob/
 * dir/DB is created, so pblock on-disk data can never be root-owned. The normal
 * way to choose the account is the nginx `user <acct>;` directive (the worker
 * then already runs unprivileged and the drop is a no-op); `unpriv_user` is the
 * caller-supplied fallback account for a root worker (NULL ⇒ "nobody"). The flag
 * is left 0 by the standalone unit test (and any master/config-time probe), which
 * therefore never drops. */
typedef struct {
    const char *root;
    int         busy_timeout_ms;
    int64_t     block_size;
    const char *unpriv_user;             /* root-worker fallback; NULL/"" ⇒ "nobody" */
    unsigned    enforce_unprivileged:1;  /* worker build ⇒ drop off root pre-write */
} brix_sd_pblock_conf_t;
#endif

/* Build a pool-lived POSIX instance that BORROWS an already-open persistent
 * rootfd (+ root_canon) — it neither opens nor closes that fd. For the VFS hot
 * open path, which already holds the export's persistent confinement anchor.
 * Returns NULL (errno set) for rootfd < 0 or on OOM. (Defined in sd_posix.c.) */
brix_sd_instance_t *brix_sd_posix_borrow_instance(ngx_pool_t *pool,
    ngx_log_t *log, int rootfd, const char *root_canon);

/* ---- brix_sd_posix_wrap — bind a bare fd to a stack POSIX SD object ------
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
brix_sd_posix_wrap(brix_sd_obj_t *obj, ngx_fd_t fd)
{
    ngx_memzero(obj, sizeof(*obj));
    obj->driver = &brix_sd_posix_driver;
    obj->fd = fd;
}

/* ---- brix_sd_obj_preadv — vectored read with per-driver fallback ---------
 *
 * WHAT: Issues a positioned vectored read on `obj`, using the driver's native
 *       preadv slot when present, else emulating it with one driver->pread per
 *       iovec. Returns total bytes read (short = EOF), or -1 with errno set
 *       (ENOTSUP when the driver has no byte-read slot at all).
 *
 * WHY:  preadv/preadv2 are OPTIONAL vtable slots — remote/object drivers
 *       (sd_remote) implement only pread, and the read fan-out paths (pgread,
 *       kXR_readv batches) previously called obj->driver->preadv unguarded,
 *       which is a NULL call (SIGSEGV) on those backends. One shared fallback
 *       keeps the emulation policy (stop on short read) in a single place.
 *
 * HOW:  Native slot when non-NULL; otherwise fill each iovec with a pread
 *       loop — a short-but-nonzero pread is NOT EOF (drivers may cap a single
 *       request), only a 0-byte pread is, so keep reading until the iovec is
 *       full or the driver reports EOF/error. A -1 mid-loop after bytes were
 *       already delivered reports the bytes (POSIX readv semantics); the
 *       caller's next call surfaces the error.
 */
static ngx_inline ssize_t
brix_sd_obj_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    ssize_t  total = 0;
    int      i;
    int      eof = 0;

    if (obj->driver->preadv != NULL) {
        return obj->driver->preadv(obj, iov, iovcnt, off);
    }

    if (obj->driver->pread == NULL) {
        errno = ENOTSUP;
        return -1;
    }

    for (i = 0; i < iovcnt && !eof; i++) {
        size_t filled = 0;

        while (filled < iov[i].iov_len) {
            ssize_t n = obj->driver->pread(obj,
                                           (char *) iov[i].iov_base + filled,
                                           iov[i].iov_len - filled,
                                           off + total);
            if (n < 0) {
                if (total > 0) {
                    return total;
                }
                return -1;
            }
            if (n == 0) {
                eof = 1;        /* only a 0-byte pread means EOF */
                break;
            }
            filled += (size_t) n;
            total  += n;
        }
    }

    return total;
}

#endif /* BRIX_SD_REGISTRY_H */
