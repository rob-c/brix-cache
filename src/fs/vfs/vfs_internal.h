/*
 * vfs_internal.h — implementation-private definitions shared by the vfs_*.c units.
 *
 * WHAT: Defines the real handle structs hidden behind vfs.h's opaque typedefs
 *       (brix_vfs_file_s, brix_vfs_dir_s), the inline confinement/write
 *       guards (brix_vfs_require_confined, brix_vfs_require_write), the
 *       ctx-path accessor (brix_vfs_ctx_path), the metrics/access-log observer
 *       helpers (brix_vfs_observe_ctx_op / brix_vfs_observe_file_op and the
 *       elapsed-usec/proto helpers they use), and the cross-unit prototypes
 *       (fill_stat, copy_path, adopt_fd, pread_full, pwrite_full).
 *
 * WHY:  Every vfs_*.c file needs the same guard-then-syscall-then-observe
 *       pattern and the same handle layout. Centralising it here keeps the
 *       per-op files thin and guarantees that confinement re-verification and
 *       metric/log emission happen identically for every operation.
 *
 * HOW:  The guards reject any ctx whose resolved path is empty or not confined
 *       (and, for writes, when allow_write is unset), setting errno. The
 *       observer helpers translate an rc/errno into an brix_err_class_t,
 *       compute latency from a start ngx_current_msec, then call
 *       brix_metric_op_done + brix_access_log_emit and restore errno so the
 *       caller can return it untouched. Only this header is included by the
 *       vfs_*.c units; protocol handlers include vfs.h instead.
 */
#ifndef BRIX_VFS_INTERNAL_H
#define BRIX_VFS_INTERNAL_H

#include "vfs.h"

#include "fs/backend/ucred.h"
#include "auth/token/exchange.h"          /* brix_token_exchange_conf_t (§5.4)   */
#include "auth/s3/sts.h"                  /* brix_s3_sts_conf_t (§5.5 hook)       */
#include "core/compat/crc32c.h"
#include "core/compat/namespace_ops.h"
#include "core/compat/staged_file.h"
#include "observability/metrics/access_log.h"
#include "fs/path/path.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Per-request delegation live-cred bag (phase-70 §4). Carries the raw
 * forwardable credential BYTES the front door captured — distinct from the
 * dir-based select bound by brix_vfs_ctx_bind_backend_cred. The front door
 * fills exactly the fields for the strategy it captured:
 *   PASSTHROUGH bearer  — bearer holds the raw JWT text;
 *   PASSTHROUGH x509    — have_proxy_pem=1 + proxy_pem holds the full proxy PEM
 *                         (cert chain + private key) the user voluntarily supplied.
 * `mode` is the resolved brix_cred_mode. All bytes are owned by the request pool
 * and must never be logged. The vfs.h forward declaration names this struct so a
 * pointer can hang on brix_vfs_ctx_t without exposing the layout to handlers. */
struct brix_deleg_live_s {
    int                 have_proxy_pem;  /* 1 = proxy_pem holds a full x509 proxy   */
    ngx_str_t           proxy_pem;       /* full proxy PEM (chain + key); never log  */
    ngx_str_t           bearer;          /* raw JWT text; never log                  */
    enum brix_cred_mode mode;            /* resolved delegation strategy             */
    /* Phase-70 §5.4 EXCHANGE conf (borrowed from conf; NUL-terminated). When
     * `mode` is BRIX_CRED_EXCHANGE and `tx.endpoint` is set, the cred gate trades
     * the live bearer for a backend-audienced token via brix_token_exchange();
     * when tx.endpoint is unset EXCHANGE degrades to verbatim bearer passthrough.
     * `tx_audience` is the first backend_token_aud entry (target audience). These
     * are populated by brix_vfs_deleg_set_exchange() at capture time — when that
     * call is absent tx.endpoint stays empty and the verbatim fallback applies. */
    brix_token_exchange_conf_t tx;
    ngx_str_t                  tx_audience;
};

struct brix_vfs_file_s {
    /* Backend object: carries the open descriptor plus its driver + instance,
     * so close and (future) data-plane ops route through the storage driver
     * rather than assuming a raw POSIX fd. obj.fd is the descriptor for fd-based
     * backends, NGX_INVALID_FILE otherwise. */
    brix_sd_obj_t   obj;
    /* phase-71 step 2: lazily-materialised memfd for a CAP_MEMFILE backend that
     * has no kernel fd of its own (obj.fd == NGX_INVALID_FILE). The whole object
     * is pread into this memfd on the first sendfile_fd request so the serve path
     * is a uniform seekable fd for every backend; closed in brix_vfs_close.
     * NGX_INVALID_FILE until materialised (and for fd-backed backends, always). */
    ngx_fd_t          memfd;
    off_t             size;
    time_t            mtime;
    time_t            ctime;
    ino_t             ino;
    mode_t            mode;
    ngx_pool_t       *pool;
    ngx_log_t        *log;
    brix_vfs_ctx_t *ctx;
    char             *path;
    unsigned          from_cache:1;
    unsigned          is_tls:1;
    unsigned          cleanup_registered:1;
    /* phase-45 W2/R1: when set, the cached size/mtime/ctime/mode/ino above are
     * authoritative, so brix_vfs_file_stat() answers from them without a second
     * fstat.  adopt_fd sets it iff the handle is READ-ONLY: a read-only handle
     * cannot change its own file, so the open-time fstat stays valid for its
     * lifetime (this is the S3/WebDAV GET read-then-stat fast path).  A writable
     * handle leaves it 0, forcing a live fstat — correct even though no current
     * caller writes through a VFS handle (writes use the io_core job interface on
     * the raw fd), so a future write-through-handle path is safe by construction. */
    unsigned          stat_current:1;
};

struct brix_vfs_dir_s {
    DIR        *dir;
    ngx_pool_t *pool;
    ngx_log_t  *log;
    char       *path;
    const char *root_canon;   /* for broker-routed per-child lstat (impersonation) */
    /* Non-POSIX backend: the driver's open directory + the bits readdir needs to
     * stat children through the same driver. sd_dir != NULL selects the driver
     * path; `dir` stays NULL. */
    brix_sd_dir_t          *sd_dir;
    brix_sd_instance_t     *sd;
    const brix_sd_driver_t *drv;
    const char               *sd_logical;   /* export-relative dir path */
};

struct brix_vfs_staged_s {
    brix_staged_file_t  staged;   /* the compat temp-file primitive (POSIX)    */
    /* Non-NULL when the export selects a non-POSIX backend: the staged lifecycle
     * is delegated to that driver's staged_open/write/commit/abort slots and
     * `staged.fd` stays NGX_INVALID_FILE (object backends expose no kernel fd).
     * driver_total accumulates the bytes written, for the commit metric. */
    brix_sd_staged_t   *driver_staged;
    off_t                 driver_total;
    /* Write-back staging is no longer a vfs_staged mode: the registry composes the
     * sd_stage decorator (phase-63 C-2/C-6), so a remote-backend export with staging
     * enabled stages locally + promotes inside the driver's staged_* slots above. */
    /* INVARIANT: never NULL on a handle a caller can hold — the sole
     * constructor (brix_vfs_staged_open) allocates and deep-copies it before
     * anything else and returns NULL on failure, so write/commit/abort may
     * dereference it unguarded. (gcc -fanalyzer flags those derefs as
     * possible-NULL: it models the opaque parameter, not the constructor —
     * known false positive, do not "fix" with a guard that hides misuse.) */
    brix_vfs_ctx_t     *ctx;      /* carries root_canon + final (resolved) path */
    ngx_pool_t           *pool;
    ngx_log_t            *log;
};

/* The export-root-relative ("logical") form of a confined path — what an
 * inst-keyed storage-driver op expects (the SD seam keys its namespace on the
 * logical path). Strips a root_canon prefix; returns `path` unchanged when it is
 * not under root_canon. Defined in vfs_open.c, shared with vfs_staged.c. */
const char *brix_vfs_export_relative(const brix_vfs_ctx_t *ctx,
    const char *path);
/* Path-based form for ctx-less callers (rename_path/mkdir_path). */
const char *brix_vfs_export_relative_root(const char *path,
    const char *root_canon);

/* The NON-default storage driver bound to this ctx (e.g. pblock), or NULL when
 * the export uses the default POSIX path. The VFS namespace + data ops dispatch
 * through it (with brix_vfs_export_relative paths) when non-NULL; otherwise they
 * fall to the existing POSIX confined-canon / ns_* helpers unchanged. */
static ngx_inline const brix_sd_driver_t *
brix_vfs_ctx_driver(const brix_vfs_ctx_t *ctx)
{
    if (ctx != NULL && ctx->sd != NULL
        && ctx->sd->driver != brix_sd_default_driver())
    {
        return ctx->sd->driver;
    }
    return NULL;
}

/* Map a storage-driver stat into the VFS stat callers see (the driver path's
 * counterpart of brix_vfs_fill_stat for a struct stat). */
static ngx_inline void
brix_vfs_sd_stat_fill(const brix_sd_stat_t *in, brix_vfs_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size = in->size;
    out->mtime = in->mtime;
    out->ctime = in->ctime;
    out->mode = (ngx_uint_t) in->mode;
    out->ino = in->ino;
    out->uid = in->uid;
    out->gid = in->gid;
    out->is_directory = in->is_dir ? 1 : 0;
    out->is_regular = in->is_reg ? 1 : 0;
}

/* Build a transient storage-driver object view from a ctx + fd: the bound
 * instance (or NULL for the default backend), that backend's driver, and the
 * fd. Used to ask the backend to perform/decide a per-fd operation without the
 * VFS hard-coding any concrete driver. "No explicit backend" resolves to
 * brix_sd_default_driver() rather than naming POSIX. */
static ngx_inline void
brix_vfs_ctx_sd_obj(const brix_vfs_ctx_t *ctx, ngx_fd_t fd,
    brix_sd_obj_t *obj)
{
    ngx_memzero(obj, sizeof(*obj));
    obj->inst = ctx != NULL ? ctx->sd : NULL;
    obj->driver = (obj->inst != NULL) ? obj->inst->driver
                                      : brix_sd_default_driver();
    obj->fd = fd;
}

/* Same, for an open handle: copy its backend object (driver + instance + fd). */
static ngx_inline void
brix_vfs_handle_sd_obj(const brix_vfs_file_t *fh, brix_sd_obj_t *obj)
{
    if (fh != NULL) {
        *obj = fh->obj;
    } else {
        brix_vfs_ctx_sd_obj(NULL, NGX_INVALID_FILE, obj);
    }
}

/* Map the backend's protocol-neutral stat into the VFS stat the callers see. */
static ngx_inline void
brix_vfs_sd_stat_to_vfs(const brix_sd_stat_t *in, brix_vfs_stat_t *out)
{
    ngx_memzero(out, sizeof(*out));
    out->size = in->size;
    out->mtime = in->mtime;
    out->ctime = in->ctime;
    out->mode = (ngx_uint_t) in->mode;
    out->ino = in->ino;
    out->uid = in->uid;
    out->gid = in->gid;
    out->is_directory = in->is_dir ? 1 : 0;
    out->is_regular = in->is_reg ? 1 : 0;
}

/* Ask the handle's backend for a sendfile-able fd over [off, off+len), passing
 * the VFS's storage-neutral zero-copy verdict; returns the fd, or
 * NGX_INVALID_FILE when the backend declines (or has no read_sendfile_fd slot).
 * This is the single place the VFS consults the backend's sendfile decision. */
static ngx_inline ngx_fd_t
brix_vfs_handle_sendfile_fd(const brix_vfs_file_t *fh, off_t off,
    size_t len, unsigned want_zerocopy)
{
    brix_sd_obj_t obj;

    brix_vfs_handle_sd_obj(fh, &obj);
    if (obj.driver == NULL || obj.driver->read_sendfile_fd == NULL) {
        return NGX_INVALID_FILE;
    }
    return obj.driver->read_sendfile_fd(&obj, off, len, want_zerocopy);
}

/* Borrow the ctx's resolved confined path as a NUL-terminated C string.
 * Returns NULL (not "") when ctx or the resolved path is unset; the pointer
 * is owned by the ctx and must not be freed or outlive it. */
static ngx_inline const char *
brix_vfs_ctx_path(const brix_vfs_ctx_t *ctx)
{
    if (ctx == NULL || ctx->resolved.resolved.data == NULL) {
        return NULL;
    }

    return (const char *) ctx->resolved.resolved.data;
}

/* Read guard: assert the ctx has a non-empty, kernel-confined resolved path.
 * Returns NGX_OK if confined, else NGX_ERROR with errno=EINVAL. Every wire op
 * must pass this before touching the filesystem. */
static ngx_inline ngx_int_t
brix_vfs_require_confined(const brix_vfs_ctx_t *ctx)
{
    const char *path = brix_vfs_ctx_path(ctx);

    if (ctx == NULL || path == NULL || path[0] == '\0'
        || !ctx->resolved.is_confined)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Write guard: confinement check (as above) plus ctx->allow_write.
 * Returns NGX_OK only when both hold; otherwise NGX_ERROR with errno=EINVAL
 * (unconfined) or EACCES (write not permitted). */
static ngx_inline ngx_int_t
brix_vfs_require_write(const brix_vfs_ctx_t *ctx)
{
    if (brix_vfs_require_confined(ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!ctx->allow_write) {
        errno = EACCES;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Translate a namespace status into a faithful POSIX errno. The namespace layer
 * sets res.sys_errno for syscall failures but leaves it 0 for the conditions it
 * derives itself (notably BRIX_NS_NOT_EMPTY from its own emptiness probe), so
 * callers that collapse a failed brix_ns_* result to errno must use this for
 * the sys_errno==0 case rather than a blanket EIO — otherwise a non-empty rmdir
 * surfaces as EIO/500 instead of ENOTEMPTY/409. */
static ngx_inline int
brix_vfs_ns_status_errno(brix_ns_status_t status)
{
    switch (status) {
    case BRIX_NS_OK:        return 0;
    case BRIX_NS_NOT_FOUND: return ENOENT;
    case BRIX_NS_DENIED:    return EACCES;
    case BRIX_NS_EXISTS:    return EEXIST;
    case BRIX_NS_CONFLICT:  return ENOTDIR;
    case BRIX_NS_NOT_EMPTY: return ENOTEMPTY;
    case BRIX_NS_TOO_LONG:  return ENAMETOOLONG;
    case BRIX_NS_NO_SPACE:  return ENOSPC;
    case BRIX_NS_IO_ERROR:  return EIO;
    }

    return EIO;
}

/* Pick the protocol label for this ctx's metrics, defaulting to
 * BRIX_PROTO_ROOT when ctx is NULL or its metrics_proto is out of range. */
static ngx_inline brix_proto_t
brix_vfs_metrics_proto(const brix_vfs_ctx_t *ctx)
{
    if (ctx == NULL || ctx->metrics_proto >= BRIX_PROTO_COUNT) {
        return BRIX_PROTO_ROOT;
    }

    return ctx->metrics_proto;
}

/* phase-56 D-1: a real monotonic timestamp in NANOseconds for op-latency.
 * Replaces the cached ngx_current_msec, which (a) only advances on event-loop
 * ticks — so a synchronous metadata op that never yields reported 0 µs — and
 * (b) is millisecond-resolution, quantizing the whole sub-ms band to 0/1000 µs.
 * CLOCK_MONOTONIC is vDSO-backed (~20 ns/call, lost in the syscalls the op
 * already makes) and gives honest sub-µs deltas. NOT CLOCK_MONOTONIC_COARSE —
 * that is also ~1-4 ms granularity and would only fix (a), not the resolution. */
static ngx_inline uint64_t
brix_vfs_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

/* Latency since start_ns in MICROseconds (start is an brix_vfs_now_ns()
 * snapshot). Clamps to 0 if the monotonic clock appears to have gone backwards. */
static ngx_inline ngx_msec_t
brix_vfs_elapsed_usec(uint64_t start_ns)
{
    uint64_t now_ns = brix_vfs_now_ns();

    if (now_ns < start_ns) {
        return 0;
    }

    return (ngx_msec_t) ((now_ns - start_ns) / 1000ull);
}

/* Post-op observer: derive the error class from rc/sys_errno, compute latency
 * from start_msec, then emit one metric (brix_metric_op_done) and one access
 * log line (brix_access_log_emit) for op. bytes is the transferred count;
 * result may be NULL. Borrows path (does not copy). Restores errno=sys_errno on
 * return so the caller can propagate it unchanged. */
static ngx_inline void
brix_vfs_observe_ctx_op(const brix_vfs_ctx_t *ctx, const char *path,
    brix_metric_op_t op, const brix_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, uint64_t start_ns)
{
    brix_err_class_t err;
    ngx_msec_t         latency_usec;

    err = rc == NGX_OK ? BRIX_ERR_NONE
                       : brix_metric_err_from_errno(sys_errno);
    latency_usec = brix_vfs_elapsed_usec(start_ns);

    brix_metric_op_done(brix_vfs_metrics_proto(ctx), op, bytes,
                          latency_usec, err);

    /* Per-backend storage byte totals (staged-commit writes, VFS-metered
     * reads). ctx->sd == NULL is the default-POSIX instance. */
    if (rc == NGX_OK && bytes > 0) {
        brix_metric_backend_bytes(
            ctx != NULL && ctx->sd != NULL ? brix_sd_backend_name(ctx->sd)
                                           : "posix",
            op, bytes);
    }

    brix_access_log_emit(ctx, path, op, result, bytes, err, latency_usec);

    errno = sys_errno;
}

/* Handle-keyed convenience wrapper for brix_vfs_observe_ctx_op: pulls ctx and
 * path from fh (tolerating fh==NULL). Same errno-restoring semantics. */
static ngx_inline void
brix_vfs_observe_file_op(const brix_vfs_file_t *fh,
    brix_metric_op_t op, const brix_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, uint64_t start_ns)
{
    brix_vfs_observe_ctx_op(fh != NULL ? fh->ctx : NULL,
                              fh != NULL ? fh->path : NULL,
                              op, result, bytes, rc, sys_errno, start_ns);
}

/* Translate a struct stat into the protocol-neutral brix_vfs_stat_t: zeroes
 * *out first, then copies size/mtime/ctime/mode/ino and sets is_directory /
 * is_regular from the mode. Silent no-op if either pointer is NULL. */
void brix_vfs_fill_stat(const struct stat *st, brix_vfs_stat_t *out);

/* Duplicate a NUL-terminated C string into pool (ngx_pnalloc'd, NUL-terminated).
 * Returns the copy, or NULL with errno=EINVAL (bad args) / ENOMEM. The copy
 * lives as long as pool. */
char *brix_vfs_copy_path(ngx_pool_t *pool, const char *path);

/* Wrap an already-open fd in a freshly pcalloc'd handle (from ctx->pool):
 * fstat()s fd to populate cached size/mtime/ino/mode, dups path, and records
 * attrs.from_cache and ctx->is_tls. attrs.writable is non-zero iff the fd was
 * opened for writing; it gates the stat_current fast path (see brix_vfs_file_stat)
 * — a writable handle never trusts its open-time metadata, a read-only one always
 * can (the file cannot change through it). On success *out is set and the handle
 * adopts fd (caller stops owning it). Returns NGX_ERROR (out unchanged/NULL) on
 * bad args (EINVAL), fstat failure (errno from fstat), or OOM (ENOMEM).
 * `attrs` bundles the from_cache/writable tags — see brix_vfs_adopt_attrs_t. */
ngx_int_t brix_vfs_adopt_fd(brix_vfs_ctx_t *ctx, const char *path,
    ngx_fd_t fd, brix_vfs_adopt_attrs_t attrs, brix_vfs_file_t **out);

/* brix_vfs_pread_full / brix_vfs_pwrite_full are now declared in the public
 * vfs.h (raw fd full read/write primitives) so module byte loops outside src/fs
 * can route through the storage seam too. */

/* Per-user backend credential policy gates (vfs_cred.c).
 *
 * WHAT: Examine ctx->storage_cred_dir and the ctx identity, select a per-user
 *       x509 proxy via brix_sd_ucred_select, and report whether the op should
 *       proceed with a user credential (use_cred=1, *cred filled from *store),
 *       the service credential (use_cred=0), or be refused (NGX_ERROR, errno/
 *       *err_out = EACCES).
 *
 * WHY:  brix_vfs_backend_cred gates data-plane opens (open/staged_open), keyed
 *       on driver->open_cred.  brix_vfs_ns_cred gates namespace ops (stat/unlink/
 *       mkdir/rename/copy/setattr/xattr/opendir), keyed on driver->stat_cred.
 *       Both share the same select+deny+fallback decision body in vfs_cred.c.
 *
 * HOW:  The gates are stateless — each probes the credential file at call time.
 *       *store and *cred are stack-allocated by the callers and live for the
 *       duration of the driver call that follows. */
ngx_int_t brix_vfs_backend_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out);

/* Namespace-op credential gate (Phase 2 Task 1).  Same semantics as
 * brix_vfs_backend_cred but capability-checks driver->stat_cred rather than
 * driver->open_cred — the canonical namespace credential-scope indicator.
 * Called from the VFS ns dispatch sites before dispatching through the
 * brix_sd_<op>_maybe_cred forwarders. */
ngx_int_t brix_vfs_ns_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out);

/* Unwrap stage/cache decorator layers from `top` to reach the leaf driver
 * instance — the first non-decorator in the composed chain (e.g. sd_xroot,
 * sd_pblock, sd_posix).  Used by the VFS ns dispatch sites so that
 * brix_sd_<op>_maybe_cred dispatches on the leaf (which HAS *_cred slots)
 * rather than the decorator (which has only plain relays).
 * Returns `top` unchanged if it is already a leaf, or NULL if `top` is NULL. */
brix_sd_instance_t *brix_vfs_ns_leaf(brix_sd_instance_t *top);

/* ---- brix_vfs_cred_gate_active ---------------------------------------------
 *
 * WHAT: True when the per-user backend credential gate (brix_vfs_ns_cred /
 *       brix_vfs_backend_cred) must run for this ctx — i.e. a per-user
 *       credential SOURCE is bound: either the directory-based SELECT policy
 *       (storage_cred_dir) OR a live delegation bag (PASSTHROUGH/EXCHANGE).
 *
 * WHY:  The namespace dispatch sites (vfs_xattr/stat/unlink/mkdir/rename/dir/
 *       copy) originally guarded the gate on `storage_cred_dir != NULL` alone.
 *       That drops the credential in pure PASSTHROUGH mode (a deleg bag bound
 *       with NO storage_credential_dir): the ns op then runs on the static
 *       service credential, which a per-user (e.g. token-only) backend rejects —
 *       asymmetric with the data-plane open, whose gate (vfs_backend_cred_decide)
 *       already consults the deleg bag before the dir. This predicate makes the
 *       ns guard consider BOTH sources so a passthrough bearer/proxy reaches the
 *       backend on namespace ops (e.g. the WebDAV lock-state getxattr) exactly
 *       as it does on data-plane opens.
 *
 * HOW:  storage_cred_dir set, OR brix_vfs_backend_mode(ctx) != BRIX_CRED_SELECT
 *       (a bag is bound). A no-op change for the dir-only and no-cred configs. */
int brix_vfs_cred_gate_active(brix_vfs_ctx_t *ctx);

/* Delegation live-cred materialiser (phase-70 §5.1/§5.4, vfs_deleg.c).
 *
 * WHAT: For a ctx carrying a bound live bag in PASSTHROUGH mode, validate the
 *       captured bytes and materialise them into *cred: a bearer token is copied
 *       straight through (cred->bearer); a full x509 proxy PEM is written to a
 *       0600 temp path (cred->x509_proxy) with a pool cleanup that unlink()s +
 *       zeroes the path. Sets cred->mode. On success *use_cred=1, NGX_OK. On a
 *       missing/invalid live cred: *err_out=EACCES and NGX_ERROR when the ctx is
 *       in fallback-deny, else *use_cred=0 + NGX_OK (fall to service cred).
 *
 * WHY:  The one place the front door's raw forwardable credential becomes the
 *       exact cred form the backend GSI/ZTN presenter already consumes, so no
 *       new origin-leg code is needed.
 *
 * HOW:  Reuses brix_proxy_gsi_write_pem_temp() (net/proxy) for the bytes→path
 *       adaptor and PEM_read_bio_X509 to reject non-PEM. The full RFC-3820
 *       chain-trust + DN-match validation is a documented TODO (§5.1) — the
 *       capture agent supplies validated bytes for now. */
ngx_int_t brix_vfs_deleg_live_cred(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred, int *err_out);

/* Phase-70 §5.5/§5.7 call-ready EXCHANGE hooks — compiled + linkable but not yet
 * driven from the cred gate (the STS service-key conf / delegated GSS cred are
 * not reachable from brix_vfs_ctx_t without a capture-site bind owned by other
 * agents; see the DEFERRED notes in vfs_deleg.c). Declared here (not static) so
 * they link and are ready for that wiring. brix_s3_sts_conf_t comes from
 * auth/s3/sts.h (included above). */
ngx_int_t brix_vfs_deleg_sts_cred(brix_vfs_ctx_t *ctx,
    const brix_s3_sts_conf_t *cf, brix_sd_cred_t *cred,
    int *use_cred, int *err_out);
ngx_int_t brix_vfs_deleg_krb5_token(brix_vfs_ctx_t *ctx, void *deleg_gss_cred,
    const char *origin_service_princ, ngx_str_t *out_token);

#endif /* BRIX_VFS_INTERNAL_H */
