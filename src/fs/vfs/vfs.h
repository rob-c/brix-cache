/*
 * vfs.h — public API for the unified VFS (POSIX-filesystem data plane).
 *
 * WHAT: The only header protocol op handlers include to touch the export root.
 *       Declares the open flags (BRIX_VFS_O_READ/WRITE/CREATE/EXCL/TRUNC/
 *       APPEND/MKDIRPATH/NOCACHE), the opaque handle types (brix_vfs_file_t,
 *       brix_vfs_dir_t), the per-operation request descriptor
 *       brix_vfs_ctx_t, the result/stat structs (brix_vfs_stat_t,
 *       brix_vfs_io_result_t), and every brix_vfs_* entry point —
 *       open/close, read/write, stat, opendir/readdir/closedir, and the
 *       namespace mutators unlink/rmdir/rename/mkdir plus truncate/sync.
 *
 * WHY:  All four front ends (XRootD root://, WebDAV davs://, the S3 subset, and
 *       CMS data-server I/O) funnel through this one protocol-agnostic surface
 *       so confinement, metrics, access logging, page-CRC, and cache
 *       integration are implemented once and inherited for free. Handlers must
 *       never call open/pread/rename directly — they fill an brix_vfs_ctx_t
 *       and call here.
 *
 * HOW:  A caller populates brix_vfs_ctx_t with the export root_canon (and the
 *       persistent per-worker rootfd), the already-resolved client path
 *       (brix_path_result_t, produced by ../path/), the caller identity,
 *       allow_write/is_tls/want_pgcrc/cache flags, and the metrics_proto, then
 *       invokes a single entry point. The handle accessors (brix_vfs_file_fd
 *       et al.) are the only way callers reach the underlying fd/size/mtime.
 */
#ifndef BRIX_VFS_H
#define BRIX_VFS_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/path/unified.h"
#include "core/types/identity.h"
#include "observability/metrics/unified.h"
#include "fs/backend/sd.h"

#define BRIX_VFS_O_READ        0x01
#define BRIX_VFS_O_WRITE       0x02
#define BRIX_VFS_O_CREATE      0x04
#define BRIX_VFS_O_EXCL        0x08
#define BRIX_VFS_O_TRUNC       0x10
#define BRIX_VFS_O_APPEND      0x20
#define BRIX_VFS_O_MKDIRPATH   0x40
#define BRIX_VFS_O_NOCACHE     0x80

typedef struct brix_vfs_file_s   brix_vfs_file_t;
typedef struct brix_vfs_dir_s    brix_vfs_dir_t;
#ifndef BRIX_VFS_STAGED_T_DECLARED
#define BRIX_VFS_STAGED_T_DECLARED
typedef struct brix_vfs_staged_s brix_vfs_staged_t;
#endif

/* Per-request live-cred bag (phase-70 §4): raw forwardable credential BYTES the
 * front door captured for this request (distinct from the dir-based select in
 * brix_vfs_ctx_bind_backend_cred). The full definition lives in vfs_internal.h;
 * ctx only holds a borrowed pointer, so a forward declaration suffices here. */
typedef struct brix_deleg_live_s brix_deleg_live_t;

/* Options for brix_vfs_copy() — mirrors brix_ns_copy_opts_t without pulling
 * the namespace_ops header into this public surface. */
typedef struct {
    unsigned recursive:1;
    unsigned overwrite:1;
    unsigned overwrite_dirs:1;
    unsigned preserve_xattrs:1;
    unsigned staged_commit:1;
} brix_vfs_copy_opts_t;

typedef struct {
    off_t        size;
    time_t       mtime;
    time_t       ctime;
    time_t       atime;      /* access time — for oss.at in kXR_Qxattr replies   */
    ngx_uint_t   mode;
    ino_t        ino;
    dev_t        dev;        /* with ino: the kXR stat id (ino<<32 | dev)       */
    uid_t        uid;        /* with gid+mode: stat readable/writable flags     */
    gid_t        gid;
    blkcnt_t     blocks;     /* st_blocks — the VFS-mode stat size (blocks*512)  */
    unsigned     is_directory:1;
    unsigned     is_regular:1;
} brix_vfs_stat_t;

typedef struct {
    off_t        offset;
    size_t       length;
    uint32_t     crc32c;
    unsigned     from_cache:1;
    unsigned     eof:1;
} brix_vfs_io_result_t;

typedef struct {
    ngx_pool_t          *pool;
    ngx_log_t           *log;
    brix_identity_t   *identity;
    brix_proto_t       metrics_proto;
    const char          *root_canon;
    const char          *cache_root_canon;
    int                  rootfd;           /* persistent O_PATH fd, or -1 */
    /* Bound storage-driver instance for this export, or NULL to use the default
     * POSIX backend (full-featured, sendfile-capable). Reserved for per-export
     * backend selection; today the VFS treats NULL as POSIX. */
    brix_sd_instance_t *sd;
    void                *cache_writethrough_cfg;
    /* Phase-1 per-user backend credentials: the export's credential dir
     * (borrowed from conf, NUL-terminated; NULL/"" = feature off) and the
     * fallback policy. Set via brix_vfs_ctx_bind_backend_cred(). */
    const char          *storage_cred_dir;
    /* Phase-2 T9 opt-in credential minting: mint CA cert/key paths and the
     * minted-proxy TTL (borrowed from conf, NUL-terminated; cert==NULL/""
     * = minting off). Set via brix_vfs_ctx_bind_backend_mint(); only wired at
     * the data-plane sites where minting is meaningful (davs/S3 GET/PUT). */
    const char          *storage_cred_mint_ca_cert;
    const char          *storage_cred_mint_ca_key;
    ngx_uint_t           storage_cred_mint_ttl;
    /* Phase-70 §4 delegation live-cred bag: the front door binds captured
     * forwardable credential BYTES (bearer text / full x509 proxy PEM) + the
     * resolved delegation mode here via brix_vfs_ctx_bind_backend_deleg(). NULL
     * = no live bag ⇒ the cred gate stays on the SELECT path (phase-1). */
    brix_deleg_live_t   *deleg_live;
    brix_path_result_t resolved;
    unsigned             allow_write:1;
    unsigned             is_tls:1;
    unsigned             want_pgcrc:1;
    unsigned             cache_enabled:1;
    unsigned             cache_writethrough:1;
    unsigned             storage_cred_deny:1;
} brix_vfs_ctx_t;

/* Populate *vctx for a transient (rootfd = -1) confined open of an
 * already-resolved canonical path, filling the fields the HTTP front ends set
 * identically (pool/log/proto, export+cache roots, cache_enabled, allow_write,
 * is_tls, identity, resolved path). HTTP-agnostic: callers pass pool/log/is_tls
 * from their own request. Callers may tweak individual fields afterwards. */
void brix_vfs_ctx_init(brix_vfs_ctx_t *vctx, ngx_pool_t *pool,
    ngx_log_t *log, brix_proto_t proto, const char *root_canon,
    const char *cache_root_canon, int allow_write, int is_tls,
    brix_identity_t *identity, const char *resolved_path);

/* Bind the export's per-user backend credential policy onto an already-
 * initialised VFS ctx (called immediately after brix_vfs_ctx_init at data-plane
 * open/staged-open sites). cred_dir->len==0 or cred_dir==NULL disables the
 * feature for this ctx (brix_vfs_backend_cred returns NGX_OK, use_cred=0). */
void brix_vfs_ctx_bind_backend_cred(brix_vfs_ctx_t *vctx,
    const ngx_str_t *cred_dir, ngx_uint_t fallback_deny);

/* Bind the export's opt-in credential-minting config (phase-2 T9) onto an
 * already-initialised VFS ctx. Call AFTER brix_vfs_ctx_bind_backend_cred, at
 * data-plane sites only (davs/S3 GET/PUT) — namespace-only ops never need to
 * mint. ca_cert->len==0 disables minting for this ctx (the gate behaves
 * exactly as Phase-1: DECLINED stays DECLINED). */
void brix_vfs_ctx_bind_backend_mint(brix_vfs_ctx_t *vctx,
    const ngx_str_t *ca_cert, const ngx_str_t *ca_key, ngx_uint_t ttl_secs);

/* Bind a per-request delegation live-cred bag (phase-70 §4) onto an already-
 * initialised VFS ctx. `live` carries the raw forwardable credential BYTES the
 * front door captured (bearer text / full x509 proxy PEM) plus the resolved
 * brix_cred_mode; it is borrowed (owned by the caller's request pool) and must
 * outlive the VFS op. A NULL bag leaves the ctx on the SELECT path (phase-1).
 * Defined in vfs_deleg.c. */
void brix_vfs_ctx_bind_backend_deleg(brix_vfs_ctx_t *vctx,
    brix_deleg_live_t *live);

/* Report the delegation mode resolved for this ctx: the bound live bag's mode,
 * or BRIX_CRED_SELECT when no bag is bound. Defined in vfs_deleg.c. */
enum brix_cred_mode brix_vfs_backend_mode(brix_vfs_ctx_t *vctx);

/* Snapshot the ctx's bound delegation bytes so a caller can re-bind the same
 * credential onto a derived/child ctx (phase-70). Writes the resolved mode into
 * *mode and, if `bearer` is non-NULL, the raw JWT (borrowed — same lifetime as
 * the source bag). Sets *mode=BRIX_CRED_SELECT and an empty bearer when no bag is
 * bound. The proxy PEM is not exposed here (it is a 0600-materialised secret that
 * must be re-captured, not copied around). Defined in vfs_deleg.c. */
void brix_vfs_deleg_snapshot(const brix_vfs_ctx_t *vctx,
    enum brix_cred_mode *mode, ngx_str_t *bearer);

/* Allocate a delegation live-cred bag from `pool`, populate it with the captured
 * forwardable credential BYTES, and bind it onto `vctx` (phase-70 §5.1/§5.4).
 *
 * `mode` is the export's resolved brix_cred_mode (conf->common.backend_delegation);
 * when it is BRIX_CRED_SELECT this is a no-op (the ctx stays on the dir-based
 * SELECT path). `bearer` is the raw JWT text (or {0,NULL} when none was captured);
 * `proxy_pem` is a user-supplied full x509 proxy PEM (or {0,NULL}). Both byte
 * ranges must be owned by `pool` and outlive every VFS op on `vctx`; they are
 * borrowed, not copied. Returns NGX_OK on success (or the mode-SELECT no-op),
 * NGX_ERROR on OOM. The bag itself is opaque to protocol handlers — this is the
 * single constructor so the struct layout stays private to the VFS. Defined in
 * vfs_deleg.c. */
ngx_int_t brix_vfs_deleg_bind(ngx_pool_t *pool, brix_vfs_ctx_t *vctx,
    enum brix_cred_mode mode, const ngx_str_t *bearer,
    const ngx_str_t *proxy_pem);

/* Populate the EXCHANGE conf on the ctx's bound live-cred bag (phase-70 §5.4).
 * Call at capture time, AFTER brix_vfs_deleg_bind, when the export's mode is
 * BRIX_CRED_EXCHANGE: `endpoint`/`client_id`/`client_secret` come from
 * conf->common.backend_tx_* and `audience` from the first backend_token_aud
 * entry. All strings are borrowed (conf-owned, NUL-terminated) and must outlive
 * the VFS op. A no-op when no bag is bound or `endpoint` is empty — the cred gate
 * then degrades EXCHANGE to verbatim bearer passthrough. Defined in vfs_deleg.c. */
void brix_vfs_deleg_set_exchange(brix_vfs_ctx_t *vctx,
    const ngx_str_t *endpoint, const ngx_str_t *client_id,
    const ngx_str_t *client_secret, const ngx_str_t *audience);

/* The export-root-relative ("logical") form of an absolute confined `path` — the
 * key an inst-keyed storage driver expects (what brix_vfs_open passes to the
 * driver's open slot). Returns `path` unchanged when it is not under the ctx's
 * export root. A borrowed pointer into `path` (no allocation). */
const char *brix_vfs_export_relative(const brix_vfs_ctx_t *ctx,
    const char *path);

/* Open ctx->resolved under the confinement cascade with the given
 * BRIX_VFS_O_* flags (translated to O_* internally). BRIX_VFS_O_WRITE
 * requires ctx->allow_write (else EACCES); BRIX_VFS_O_MKDIRPATH pre-creates
 * the parent dir tree; read opens may be satisfied from the read-through cache.
 * Returns a handle allocated on ctx->pool, or NULL with the syscall errno
 * written to *err_out (if non-NULL). The fd is closed by brix_vfs_close. */
brix_vfs_file_t *brix_vfs_open(brix_vfs_ctx_t *ctx,
    ngx_uint_t flags, int *err_out);
/* Close the handle's fd (idempotent; NULL/already-closed handle is NGX_OK).
 * The handle struct itself lives on the pool and is not freed here. Logs and
 * returns NGX_ERROR if the close(2) fails. */
ngx_int_t brix_vfs_close(brix_vfs_file_t *fh, ngx_log_t *log);

/* Accessors over the handle's cached metadata (captured at open via fstat) —
 * no syscalls. fd: underlying descriptor or NGX_INVALID_FILE if fh is NULL. */
ngx_fd_t brix_vfs_file_fd(const brix_vfs_file_t *fh);
/* Adopt a storage-driver object (from a driver's open slot) into a NEW VFS read
 * handle, preserving its per-open state; the object's own fstat populates the
 * handle metadata. A heap_shell object is freed once copied. Used by the cache
 * hit-serve path (src/cache/open.c). writable is 0 for a read handle. */
ngx_int_t brix_vfs_adopt_obj(brix_vfs_ctx_t *ctx, const char *path,
    brix_sd_obj_t *o, unsigned writable, brix_vfs_file_t **out);

/* WHAT: The handle-tagging attributes for brix_vfs_adopt_fd — the two per-adopt
 *       flags that describe how the wrapped fd should be recorded, bundled so the
 *       adopt call stays at five parameters (the per-call ctx/path/fd/out vary
 *       every call; these classify the handle).
 * WHY:  `from_cache` and `writable` always travel together as the "how to tag
 *       this handle" group — grouping them keeps the primitive's signature within
 *       the arity budget without hiding the per-call pointers behind a struct.
 * HOW:  `from_cache` tags the handle as served from the read-through cache;
 *       `writable` is non-zero iff the fd was opened for writing (it gates the
 *       stat_current fast path — a writable handle never trusts its open-time
 *       metadata, a read-only one always can). Both are treated as booleans. */
typedef struct {
    unsigned  from_cache;   /* tag the handle as cache-served */
    unsigned  writable;     /* fd opened for writing (gates stat_current) */
} brix_vfs_adopt_attrs_t;

/* Wrap an already-open kernel fd in a NEW VFS read handle (the default POSIX
 * driver), fstat'ing it into the handle metadata. The handle is sendfile-capable
 * (CAP_FD|CAP_SENDFILE). Used to serve a materialized local temp file through the
 * shared sendfile pipeline. `attrs` tags the handle (from_cache / writable — see
 * brix_vfs_adopt_attrs_t). NGX_OK with *out set, or NGX_ERROR (errno set). */
ngx_int_t brix_vfs_adopt_fd(brix_vfs_ctx_t *ctx, const char *path,
    ngx_fd_t fd, brix_vfs_adopt_attrs_t attrs, brix_vfs_file_t **out);

/* Copy the handle's storage-driver object (driver + instance + fd) into *out.
 * Layer 3: lets a caller route whole-object I/O (e.g. checksum-at-rest) through
 * the backend driver rather than the bare block-0 fd. For a default POSIX handle
 * out->driver is the POSIX driver (equivalent to using the fd). */
void brix_vfs_file_sd_obj(const brix_vfs_file_t *fh, brix_sd_obj_t *out);
/* The handle's fd ONLY when the backend can back a zero-copy transfer
 * (CAP_FD|CAP_SENDFILE), else NGX_INVALID_FILE. Callers that build a sendfile /
 * file-backed (b->in_file) response MUST gate on this — a NGX_INVALID_FILE
 * return means "this backend cannot sendfile; serve memory-backed instead".
 * For the default POSIX backend this is always the real fd. */
ngx_fd_t brix_vfs_file_sendfile_fd(const brix_vfs_file_t *fh);
/* 1 iff this handle's backend supports zero-copy sendfile (CAP_FD|CAP_SENDFILE),
 * else 0. The predicate form of brix_vfs_file_sendfile_fd(). */
ngx_uint_t brix_vfs_file_can_sendfile(const brix_vfs_file_t *fh);
/* The census name of the backend serving this handle ("posix" for the default
 * instance or a NULL handle) — for per-backend byte attribution at serve time. */
const char *brix_vfs_file_backend_name(const brix_vfs_file_t *fh);

/* Read up to `len` bytes at offset `off` through the handle's storage driver, for
 * a memory-backed serve of a backend with no single sendfile fd. Bytes read
 * (0 = EOF) or -1/errno. */
ssize_t brix_vfs_file_pread(brix_vfs_file_t *fh, void *buf, size_t len,
    off_t off);
/* Borrowed pointer to the handle's NUL-terminated path (owned by the pool);
 * returns "" (never NULL) when fh or its path is NULL. */
const char *brix_vfs_file_path(const brix_vfs_file_t *fh);
/* Cached file size in bytes (grows as writes extend the handle); 0 if fh NULL. */
off_t brix_vfs_file_size(const brix_vfs_file_t *fh);
/* Cached mtime captured at open; 0 if fh NULL. Not refreshed after writes. */
time_t brix_vfs_file_mtime(const brix_vfs_file_t *fh);
/* 1 if this handle was served from the read-through cache, else 0. */
ngx_uint_t brix_vfs_file_from_cache(const brix_vfs_file_t *fh);
/* Live fstat(2) of the open fd into *stat_out (unlike the cached accessors).
 * NGX_ERROR with errno set on a bad handle or fstat failure. */
ngx_int_t brix_vfs_file_stat(const brix_vfs_file_t *fh,
    brix_vfs_stat_t *stat_out);

/* lstat the resolved ctx path into *stat_out (symlinks reported, not followed).
 * Confined and metered as OP_STAT; NGX_ERROR with errno set on guard failure
 * (NULL stat_out / unconfined ctx -> EINVAL) or lstat error. */
ngx_int_t brix_vfs_stat(brix_vfs_ctx_t *ctx,
    brix_vfs_stat_t *stat_out);

/* stat the resolved ctx path into *stat_out, FOLLOWING a trailing in-export
 * symlink chroot-style (RESOLVE_IN_ROOT, confined to the export). Confined and
 * metered as OP_STAT; NGX_ERROR with errno set on guard failure / stat error. */
ngx_int_t brix_vfs_statf(brix_vfs_ctx_t *ctx,
    brix_vfs_stat_t *stat_out);

/* Classify the resolved ctx path's nearline (tape/MSS) residency — online /
 * nearline / offline / lost — WITHOUT forcing a recall, so protocol handlers can
 * advertise tape state (the HTTP Tape REST API, S3 InvalidObjectState /
 * x-amz-storage-class, root:// stat's nearline flag). Walks any read-cache /
 * write-stage decorators down to the CAP_NEARLINE driver; an export with no
 * nearline tier always reports ONLINE. NGX_OK with *out set, or NGX_ERROR (errno)
 * on a guard failure or driver error. The phase-64 replacement for the FRM
 * residency-xattr probe (frm_residency_probe). When `nearline_export` is non-NULL
 * it is set to 1 iff the residency came from a nearline (tape/MSS) tier (0 for a
 * plain disk/object export) — so callers that need the WLCG locality vocabulary can
 * distinguish ONLINE-on-a-tape-export (ONLINE_AND_NEARLINE) from ONLINE-on-disk. */
ngx_int_t brix_vfs_residency(brix_vfs_ctx_t *ctx,
    brix_sd_residency_t *out, int *nearline_export);

/* Confined existence/type probe for pre-op resolution / ACL gates. Like
 * brix_vfs_stat but emits NO OP_STAT metric/access-log line (the caller's own
 * op accounts for the access). nofollow selects lstat vs stat semantics.
 * NGX_OK (stat_out filled) when present, NGX_DECLINED when absent (errno kept),
 * NGX_ERROR on a confinement-guard failure. */
ngx_int_t brix_vfs_probe(brix_vfs_ctx_t *ctx, int nofollow,
    brix_vfs_stat_t *stat_out);

/* Open the resolved ctx directory under confinement. Returns a handle on
 * ctx->pool, or NULL with the errno in *err_out (if non-NULL). The open is
 * metered as OP_DIRLIST. Release with brix_vfs_closedir. */
brix_vfs_dir_t *brix_vfs_opendir(brix_vfs_ctx_t *ctx, int *err_out);
/* Non-metered confined opendir for bulk recursive walks (S3 ListObjects, WebDAV
 * SEARCH): emits NO OP_DIRLIST metric/access-log (the enclosing protocol op
 * accounts for the whole traversal, which would otherwise log one phantom open
 * per visited subdirectory). Otherwise identical to brix_vfs_opendir. */
brix_vfs_dir_t *brix_vfs_opendir_quiet(brix_vfs_ctx_t *ctx, int *err_out);
/* Yield the next entry, one per call: name as a pool-allocated NUL-terminated
 * ngx_str_t in *name_out, plus an optional lstat of the child into *stat_out
 * (pass NULL to skip). "." and ".." are filtered out. Returns NGX_DONE at
 * end-of-stream, NGX_ERROR (errno set) on failure, NGX_OK otherwise. */
ngx_int_t brix_vfs_readdir(brix_vfs_dir_t *dh, ngx_str_t *name_out,
    brix_vfs_stat_t *stat_out);

/* Entry kind derived from the readdir d_type, for callers that only need to
 * classify dir-vs-file without a per-entry stat (S3 ListObjects, WebDAV SEARCH).
 * BRIX_VFS_DT_UNKNOWN means the filesystem did not populate d_type — the caller
 * should brix_vfs_probe() the child to classify. OTHER covers symlinks/specials
 * (never listed or traversed). */
typedef enum {
    BRIX_VFS_DT_UNKNOWN = 0,
    BRIX_VFS_DT_DIR,
    BRIX_VFS_DT_REG,
    BRIX_VFS_DT_OTHER
} brix_vfs_dirent_kind_t;

/* Like brix_vfs_readdir but yields the entry KIND from d_type (no per-entry
 * stat — preserves the fast classification path). *kind_out (optional) is set as
 * above. "." and ".." are filtered. NGX_DONE at end-of-stream, NGX_ERROR (errno)
 * on failure, NGX_OK otherwise. */
ngx_int_t brix_vfs_readdir_kind(brix_vfs_dir_t *dh, ngx_str_t *name_out,
    brix_vfs_dirent_kind_t *kind_out);

/* Close the directory stream (idempotent; NULL/already-closed is NGX_OK). The
 * handle struct stays on the pool. Logs and returns NGX_ERROR on closedir(3). */
ngx_int_t brix_vfs_closedir(brix_vfs_dir_t *dh, ngx_log_t *log);

/* The open directory's fd, for a dirfd-relative entry access that must stay
 * inside the same opened (impersonation-confined) directory — e.g. a TOCTOU-safe
 * per-entry openat() for a dirlist checksum. NGX_INVALID_FILE for a NULL/closed
 * handle, or a backend with no real fd (caller then has no dirfd-relative path). */
ngx_fd_t brix_vfs_dir_fd(const brix_vfs_dir_t *dh);

/* Remove the resolved ctx path as a regular file (non-recursive). Write-gated
 * (requires allow_write) and requires a non-NULL root_canon; metered as
 * OP_DELETE. NGX_ERROR with errno set (mapped from the namespace status). */
ngx_int_t brix_vfs_unlink(brix_vfs_ctx_t *ctx);
/* Remove the resolved ctx directory: recursively when `recursive`, otherwise
 * only if empty. Write-gated, confined; metered as OP_DELETE. NGX_ERROR with
 * errno set on failure (e.g. ENOTEMPTY for a non-empty dir when not recursive). */
ngx_int_t brix_vfs_rmdir(brix_vfs_ctx_t *ctx, unsigned recursive);
/* Move the resolved ctx (source) path to the already-resolved destination `dst`
 * (borrowed; must be is_confined with a non-empty resolved path). Write-gated;
 * both endpoints confined; metered as OP_RENAME. `overwrite_dirs` removes an
 * existing DIRECTORY destination first (WebDAV MOVE Overwrite:T; rename(2)
 * alone only replaces an empty dir); with it 0 an existing dir dest fails
 * with errno==EEXIST (kXR_mv semantics). NGX_ERROR with errno set. */
ngx_int_t brix_vfs_rename(brix_vfs_ctx_t *ctx,
    const brix_path_result_t *dst, unsigned overwrite_dirs);
/* Thread-safe confined rename of src→dst under root_canon (no pool alloc, no
 * metric — usable off the event loop / pool-less). `overwrite` replaces an
 * existing destination; otherwise an existing dst fails with errno==EEXIST.
 * *was_dir_out (optional) reports whether a conflicting destination was a
 * directory (kXR_mv maps EEXIST + was_dir → kXR_isDirectory vs kXR_ItExists).
 * NGX_OK, or NGX_ERROR with errno set (EEXIST/ENOTEMPTY/EACCES/ENOTDIR/ENOENT
 * from the namespace status). */
ngx_int_t brix_vfs_rename_path(brix_sd_instance_t *sd, ngx_log_t *log,
    const char *root_canon, const char *src, const char *dst,
    unsigned overwrite, int *was_dir_out);
/* Enumerate the bound backend's OWN object catalog (inventory/drift, spec
 * §E1/D2) — the driver-agnostic seam over the SD `enumerate` verb. Fires cb once
 * per stored object (brix_sd_catalog_ent_t); want_stat asks for per-object
 * size/mtime. Returns NGX_OK (full enumeration), the cb's non-zero abort code, or
 * NGX_DECLINED with errno==ENOTSUP when the backend has no native catalog (POSIX:
 * the namespace IS the catalog — callers fall back to a vfs_walk). Thread-safe to
 * the extent the driver's enumerate is (the Ceph verb runs on a thread worker). */
ngx_int_t brix_vfs_enumerate_catalog(brix_sd_instance_t *sd, int want_stat,
    brix_sd_catalog_cb cb, void *ctx);
/* Create the resolved ctx path as a directory with `mode`, creating missing
 * parent components when `parents`. Write-gated, confined; metered as OP_MKDIR.
 * NGX_ERROR with errno set (e.g. EEXIST when the target already exists). */
/* Change the resolved ctx path's permission bits. Write-gated; impersonation-
 * aware (performed by the broker as the mapped user when impersonation is on, so
 * the file's real owner can chmod even though the worker is not the owner). NGX_OK
 * / NGX_ERROR with errno set. */
ngx_int_t brix_vfs_chmod(brix_vfs_ctx_t *ctx, mode_t mode);

/* Apply kXR_setattr (timestamps and/or owner) to the resolved ctx path through
 * the VFS seam. Write-gated; routes to the backend's setattr slot for a non-POSIX
 * export (no-op success when the backend has no mutable metadata) and to the
 * impersonation-aware confined utimensat/fchownat path for the default POSIX
 * export. NGX_OK / NGX_ERROR with errno set. */
ngx_int_t brix_vfs_setattr(brix_vfs_ctx_t *ctx,
    const brix_sd_setattr_t *attr);

ngx_int_t brix_vfs_mkdir(brix_vfs_ctx_t *ctx, mode_t mode,
    unsigned parents);
/* ftruncate the open handle to `length` and update the cached fh->size so later
 * reads see the new length. Unmetered. NGX_ERROR with errno set on a bad handle,
 * negative length, or ftruncate failure. */
ngx_int_t brix_vfs_truncate(brix_vfs_file_t *fh, off_t length);
/* fsync the open handle to stable storage. Unmetered (the enclosing write op
 * records the metric). NGX_ERROR with errno set on a bad handle or fsync error. */
ngx_int_t brix_vfs_sync(brix_vfs_file_t *fh);

/* Confined walk / open-unlink / raw-rw / xattr / copy / staged-write declarations
 * were split out (phase-79 file-size burndown) into vfs_ops.h, included here so
 * every fs/vfs.h consumer still sees them. */
#include "fs/vfs/vfs_ops.h"

#endif /* BRIX_VFS_H */
