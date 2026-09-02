/*
 * vfs_internal.h — implementation-private definitions shared by the vfs_*.c units.
 *
 * WHAT: Defines the real handle structs hidden behind vfs.h's opaque typedefs
 *       (brix_vfs_file_s, brix_vfs_dir_s), the inline confinement/write
 *       guards (brix_vfs_require_confined; mutation authority lives in
 *       vfs_policy.h), the
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
 * HOW:  The guards reject any ctx whose resolved path is empty or not confined,
 *       setting errno; mutation authority is decided separately by the
 *       vfs_policy.c kernel, which returns EROFS for a read-only endpoint. The
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
#include "observability/metrics/io_monitor.h"   /* per-request I/O monitor fold */
#include "fs/path/path.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "fs/vfs/vfs_policy.h"  /* mutation op + gate (phase-109 checked wrapper) */

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
    /* Borrowed pointer at the conf's per-worker minted-token cache slot
     * (phase-70 §5.4 / P90-70.9): the EXCHANGE leg lazily creates a
     * brix_tx_cache_t there (ngx_cycle->pool) and consults it before POSTing
     * the RFC-8693 grant. NULL ⇒ no caching (every op re-exchanges). */
    void                     **tx_cache_slot;
    /* Phase-70 §5.1 in-gate chain re-verify (P90-70.4). Borrowed X509_STORE*
     * (conf-owned; typed void* so this header stays OpenSSL-free) + max proxy
     * chain depth (0 = OpenSSL default), stamped by
     * brix_vfs_deleg_set_ca_store() at capture time. NULL ⇒ the PASSTHROUGH
     * materialiser skips the re-verify and relies on the capture-side gate. */
    void       *ca_store;
    ngx_uint_t  ca_verify_depth;
    /* Phase-70 §5.6 SSS identity injection (P90-70.3). Borrowed conf bytes
     * (NUL-terminated — conf tokens are). Non-empty ⇒ when the bag carries NO
     * forwardable bytes (no pem, no bearer) the gate materialises an SSS
     * credential asserting the caller's principal, signed with this keytab.
     * Proven credential bytes always win over injection. Stamped by
     * brix_vfs_deleg_set_sss() — which, unlike the other setters, allocates
     * the bag itself when none is bound (injection needs no captured bytes). */
    ngx_str_t   sss_keytab;
    /* Phase-70 §5.5 S3 STS EXCHANGE. Borrowed brix_s3_sts_conf_t* (typed void*
     * so the field costs no extra coupling beyond the sts.h already included).
     * Non-NULL => when the bag carries NO forwardable bytes AND the leaf backend
     * accepts BRIX_SD_CRED_S3, the gate exchanges the node's S3 service cred for
     * temporary creds scoped to the caller via brix_vfs_deleg_sts_cred(). Like
     * SSS injection this needs no captured bytes, so brix_vfs_deleg_set_sts()
     * allocates the bag when none is bound. The conf (5 borrowed conf-owned
     * ngx_str_t + ttl) is built on the request pool at the capture site. */
    const void *sts;
    /* Phase-70 §5.7 krb5 GSSAPI EXCHANGE. Unlike SSS/STS this DOES have captured
     * bytes: the front door captures the user's forwarded TGT and serialises it
     * to a 0600 FILE ccache (brix_krb5_cred_to_ccache) — a live gss_cred_id_t is
     * request-scoped and cannot ride the async brix_cache_fill_t, so the path is
     * the async-safe carry, mirroring the gsi proxy-PEM→0600-path trick.
     * `krb5_ccache` is that path and `krb5_origin_princ` the derived origin
     * service principal (host/<fqdn>@REALM); both are borrowed NUL-terminated
     * strings on the request pool. Non-empty krb5_ccache ⇒ when the leaf accepts
     * BRIX_SD_CRED_GSS_KRB5 the gate carries them onto the cred and the origin
     * leg re-imports via brix_krb5_cred_from_ccache. Stamped by
     * brix_vfs_deleg_set_krb5(). A full x509 proxy still wins above. */
    ngx_str_t   krb5_ccache;
    ngx_str_t   krb5_origin_princ;
};

struct brix_vfs_file_s {
    /* Backend object: carries the open descriptor plus its driver + instance,
     * so close and the data-plane ops (vfs_io_core.c) route through the storage
     * driver rather than assuming a raw POSIX fd. obj.fd is the descriptor for
     * fd-based backends, NGX_INVALID_FILE otherwise. */
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
    /* Phase-105: the endpoint's mutation policy, COPIED at open. A handle can
     * outlive the ctx that opened it (and a caller may hold only the handle),
     * so the handle carries its own copy rather than re-reading ctx — and a
     * pcalloc'd handle that skipped the constructor reads READ_ONLY. */
    brix_vfs_mutation_policy_t mutation_policy;
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
    /* Non-POSIX backend: the driver's open directory + what readdir needs to stat
     * children through the same driver. sd_dir != NULL selects it; `dir` NULL. */
    brix_sd_dir_t          *sd_dir;
    brix_sd_instance_t     *sd;
    const brix_sd_driver_t *drv;
    const char               *sd_logical;   /* export-relative dir path */
    brix_sd_dirent_t de_scratch; /* handle-owned borrow-API readdir scratch */
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
    /* Phase-105: the endpoint's mutation policy, copied at staged_open — the
     * write/commit gates decide from this, never from a re-read of ctx. */
    brix_vfs_mutation_policy_t mutation_policy;
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

/* Quiet getxattr at an explicit confined path (vfs_xattr.c, phase-107 C7):
 * the full pipeline with NO OP_XATTR observation — the lock gate's ancestor
 * probes must not perturb the pinned xattr counter deltas. `path` = ctx's
 * resolved path or a same-export ancestor. Byte count, or -1 with errno. */
ssize_t brix_vfs_getxattr_quiet_at(brix_vfs_ctx_t *ctx, const char *path,
    const char *name, void *buf, size_t bufsz);

/* Recursive driver-namespace delete (vfs_unlink.c): per-key DFS, cred-threaded
 * on the LEAF. brix_vfs_rmtree_dispatch (vfs_unlink_many.c, phase-107 C4)
 * routes to the windowed bulk walk under BRIX_SD_CAP_BULK_DELETE, else here. */
ngx_int_t brix_vfs_driver_rmtree(brix_sd_instance_t *leaf,
    const brix_sd_driver_t *drv, const char *logical,
    const brix_sd_cred_t *cred, ngx_uint_t depth);
ngx_int_t brix_vfs_rmtree_dispatch(brix_sd_instance_t *leaf,
    const brix_sd_driver_t *drv, const char *logical,
    const brix_sd_cred_t *cred);

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

/* Deep-copy `ctx` and the buffers it POINTS at — the resolved confined path,
 * root_canon and the lock-token presentation, all of which can live in a caller
 * stack frame or request header buffer — onto `pool`,
 * returning a self-contained ctx that outlives the caller. Every other ctx member
 * points at config- or connection-scoped memory that already outlives any write
 * session, so a shallow struct copy carries them correctly. Returns NULL
 * (errno = ENOMEM) on allocation failure. Shared by the staged-upload handle and
 * the unified writer — both persist across the open→write→commit request
 * boundary, so a ctx pointing at request stack buffers would be a use-after-free
 * at commit. */
static ngx_inline brix_vfs_ctx_t *
brix_vfs_ctx_pool_clone(const brix_vfs_ctx_t *ctx, ngx_pool_t *pool)
{
    brix_vfs_ctx_t *copy;
    const char     *rpath;

    if (ctx == NULL) {
        errno = EINVAL;
        return NULL;
    }
    rpath = brix_vfs_ctx_path(ctx);

    copy = ngx_palloc(pool, sizeof(*copy));
    if (copy == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    *copy = *ctx;

    if (rpath != NULL) {
        size_t  n = ngx_strlen(rpath);
        u_char *d = ngx_pnalloc(pool, n + 1);
        if (d == NULL) {
            errno = ENOMEM;
            return NULL;
        }
        ngx_memcpy(d, rpath, n + 1);
        copy->resolved.resolved.data = d;
        copy->resolved.resolved.len  = n;
    }
    if (ctx->root_canon != NULL) {
        size_t  n = ngx_strlen(ctx->root_canon);
        u_char *d = ngx_pnalloc(pool, n + 1);
        if (d == NULL) {
            errno = ENOMEM;
            return NULL;
        }
        ngx_memcpy(d, ctx->root_canon, n + 1);
        copy->root_canon = (const char *) d;
    }
    /* phase-107 C7: the lock-token presentation borrows the request's header
     * buffer, which dies while this clone lives on — carried BY VALUE like
     * the mutation policy; dropping it would 423 the lock's own holder. */
    if (ctx->lock_token != NULL) {
        size_t  n = ngx_strlen(ctx->lock_token);
        u_char *d = ngx_pnalloc(pool, n + 1);
        if (d == NULL) {
            errno = ENOMEM;
            return NULL;
        }
        ngx_memcpy(d, ctx->lock_token, n + 1);
        copy->lock_token = (const char *) d;
    }
    return copy;
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

/* NULL-checked confinement+mutation gate (phase-109).  The public
 * brix_vfs_require_confined_mutation (vfs_policy.c) rejects a NULL ctx, but
 * that contract sits across a TU boundary the analyzer cannot see — gcc 13
 * flagged every post-gate ctx dereference in the path mutators (CWE-476).
 * This inline makes the reject locally provable and keeps one copy of it
 * instead of a guard block per call site.  Same behaviour: EINVAL + error. */
static ngx_inline ngx_int_t
brix_vfs_confined_mutation_checked(const brix_vfs_ctx_t *ctx,
    brix_vfs_mutation_op_t op)
{
    if (ctx == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    return brix_vfs_require_confined_mutation(ctx, op);
}

/* Write guard: phase-105 replaced this with the typed mutation-policy kernel.
 * Path mutators call brix_vfs_require_confined_mutation(ctx, op) (confinement
 * then policy, EROFS on a read-only endpoint); handle/staged/writer mutators
 * call brix_vfs_require_mutation_policy() on their own copied policy. There is
 * deliberately no boolean-shaped wrapper left: a gate that cannot name its
 * operation cannot be observed, and the old EACCES result was indistinguishable
 * from an authorization failure. See vfs_policy.h. */

/* Attribute ONE read-only mutation denial to (proto, op). Called by the policy
 * kernel and by the handle/staged/writer gates that decide from a copied policy
 * and therefore reject outside the kernel's context forms — never by a call
 * site that merely relays an already-observed failure. Defined in
 * vfs_policy.c. */
void brix_vfs_mutation_denied_observe(brix_proto_t proto,
    brix_vfs_mutation_op_t op);

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
 * return so the caller can propagate it unchanged.
 *
 * ctx == NULL means there is no request context — an internal maintenance op
 * (e.g. the integrity code persisting checksum sidecars via the NULL-ctx
 * f-xattr variants). Those are not client I/O: observing them would default
 * the proto label to "stream" and misattribute s3/webdav-triggered sidecar
 * touches, so they are deliberately not metered or access-logged. */
static ngx_inline void
brix_vfs_observe_ctx_op_ex(const brix_vfs_ctx_t *ctx, const char *path,
    brix_metric_op_t op, const brix_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, uint64_t start_ns,
    unsigned meter_io)
{
    brix_err_class_t err;
    ngx_msec_t         latency_usec;

    if (ctx == NULL) {
        errno = sys_errno;
        return;
    }

    err = rc == NGX_OK ? BRIX_ERR_NONE
                       : brix_metric_err_from_errno(sys_errno);
    latency_usec = brix_vfs_elapsed_usec(start_ns);

    /* phase-106 W1 / phase-110 W1-W4: fold this op into the request's or
     * session's I/O monitor, which the uniform $brix_* variables read at log
     * time (io_monitor.h). NULL monitor = an unmonitored path (metadata-only
     * builders, internal maintenance) and is the common case; every helper
     * below is a silent no-op on NULL.
     *   - op/path/outcome: candidate primary op under the weight rule, on
     *     success AND failure (a failed stat on a GET of a missing file is the
     *     outcome the operator wants: op=stat status=not_found).
     *   - backend time: successful ops only — a failed op's latency is error
     *     handling, not backend service time.
     *   - received bytes: a successful WRITE's count is what the client sent
     *     (the staged PUT commit observes its total once; a GET's cache fill
     *     writes through its own unmonitored ctx, so it never lands here).
     *   - SERVED bytes are deliberately NOT folded here: the client-facing
     *     serve is zero-copy (sendfile / output filter) and never reaches this
     *     observer, so the plane books result->bytes_sent at its serve site.
     * Single-writer contract: see io_monitor.h. */
    brix_io_monitor_record_op(ctx->io_monitor, op, path, err);
    if (rc == NGX_OK) {
        brix_io_monitor_add_latency(ctx->io_monitor, latency_usec);
        if (op == BRIX_METRIC_OP_WRITE) {
            brix_io_monitor_add_received(ctx->io_monitor, bytes);
        }
    }

    /* meter_io == 0: the owning protocol books the unified io_ops/latency row
     * for this operation itself (data-plane READ/WRITE via *_metrics_response,
     * bytes via the per-protocol wire-ledger fold), so emitting it here too
     * would double-count. Backend byte totals and the access-log line stay
     * VFS-owned either way. */
    if (meter_io) {
        brix_metric_op_done(brix_vfs_metrics_proto(ctx), op, bytes,
                              latency_usec, err);
    }

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

/* Full observer: metric + backend bytes + access log. */
static ngx_inline void
brix_vfs_observe_ctx_op(const brix_vfs_ctx_t *ctx, const char *path,
    brix_metric_op_t op, const brix_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, uint64_t start_ns)
{
    brix_vfs_observe_ctx_op_ex(ctx, path, op, result, bytes, rc, sys_errno,
                                 start_ns, 1);
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

/* Descend ONE cache/stage decorator to the instance it wraps; NULL at a leaf or
 * on a non-decorator instance. Defined in vfs_stat.c (the residency/space seams
 * walk it) and shared with the catalog-enumeration seam in vfs_walk.c: a verb
 * that describes the BACKING STORE rather than a cached copy must be answered by
 * the leaf, never refused because a tier decorator sits on top. */
brix_sd_instance_t *brix_vfs_decorator_source(const brix_sd_instance_t *inst);

/* Book the phase-107 C6 metric pair for ONE refused publish precondition:
 * brix_vfs_precond_failed_total{kind}, plus _advisory_total{driver} when the
 * refusal was NOT decided atomically at the storage (pre->atomic == 0).
 * Filters on the typed refusal errno (EEXIST for ABSENT, ECANCELED for
 * MATCH_*) — callable on any commit/copy failure path; NULL/NONE precondition
 * or unrelated errno is a no-op. `driver_name` = the deciding backend
 * ("posix" for compat arms). Defined in vfs_staged.c; shared w/ vfs_copy.c. */
void brix_vfs_precond_refused_observe(const brix_sd_precond_t *pre, int err,
    const char *driver_name);

/* brix_vfs_pread_full / brix_vfs_pwrite_full are now declared in the public
 * vfs.h (raw fd full read/write primitives) so module byte loops outside src/fs
 * can route through the storage seam too. */

#include "vfs_cred_internal.h"

#endif /* BRIX_VFS_INTERNAL_H */
