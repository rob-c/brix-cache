/*
 * vfs.h — public API for the unified VFS (POSIX-filesystem data plane).
 *
 * WHAT: The only header protocol handlers include to touch the export root:
 *       flags, opaque handles, request/results and every brix_vfs_* operation.
 *
 * WHY:  All four front ends (XRootD root://, WebDAV davs://, the S3 subset, and
 *       CMS data-server I/O) funnel through this one protocol-agnostic surface
 *       so confinement, metrics, access logging, page-CRC, and cache
 *       integration are implemented once and inherited for free. Handlers must
 *       never call open/pread/rename directly — they fill an brix_vfs_ctx_t
 *       and call here.
 *
 * HOW:  A caller supplies an already-resolved path, export, identity and policy
 *       in brix_vfs_ctx_t. Handle accessors alone expose fd/size/mtime.
 */
#ifndef BRIX_VFS_H
#define BRIX_VFS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/path/unified.h"
#include "core/types/identity.h"
#include "observability/metrics/unified.h"
#include "fs/backend/sd.h"
#include "fs/path/site_n2n.h"            /* brix_n2n_cfg_t (phase-108 C13/A.4) */
#include "vfs_policy.h"                  /* brix_vfs_mutation_policy_t (phase-105) */
#include "vfs_authz_types.h"             /* brix_vfs_authz_t (phase-108 C12) */

#define BRIX_VFS_O_READ        0x01
#define BRIX_VFS_O_WRITE       0x02
#define BRIX_VFS_O_CREATE      0x04
#define BRIX_VFS_O_EXCL        0x08
#define BRIX_VFS_O_TRUNC       0x10
#define BRIX_VFS_O_APPEND      0x20
#define BRIX_VFS_O_MKDIRPATH   0x40
#define BRIX_VFS_O_NOCACHE     0x80
/* Writer-session only (brix_vfs_writer_open): force the atomic staged temp+publish
 * path even for a random-write-capable backend, so a failed/aborted write never
 * leaves a partial object at the final path (the WebDAV/S3 PUT invariant). Ignored
 * by brix_vfs_open (only O_TRUNC is forwarded from the writer to the handle open). */
#define BRIX_VFS_O_ATOMIC      0x100
/* Writer-session only (phase-107 C1): the caller declares up front that extents
 * may arrive out of order, so a staged-only backend provisions its spill scratch
 * at open instead of on the first reordered write. Without it the writer still
 * self-promotes into spill mode on the first off != cursor write. Ignored by
 * brix_vfs_open and by a random-write-capable backend (no ordering constraint). */
#define BRIX_VFS_WRITER_O_UNORDERED  0x200

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
    /* Publish precondition on the DESTINATION (phase-107 C6), decided at the
     * copy's own commit rather than by an edge check that races. BORROWED
     * (NULL = none); refusals surface as EEXIST (ABSENT) / ECANCELED
     * (MATCH_*), same contract as staged_commit's parameter. */
    const brix_sd_precond_t *precond;
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

/* Observability accumulator (src/observability/metrics/io_monitor.h). A bare
 * forward decl keeps the VFS layer free of any observability include: it only
 * ever folds into the pointee through brix_io_monitor_add(). */
struct brix_io_monitor_s;
struct brix_vfs_ctx_s {
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
    /* Export N2N rule borrowed from the backend registry. NULL is IDENTITY;
     * pool clones carry the scalar pointer without per-request allocation. */
    const brix_n2n_cfg_t *n2n;
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
    time_t               storage_cred_mint_ttl;
    /* Phase-70 §4 delegation live-cred bag: the front door binds captured
     * forwardable credential BYTES (bearer text / full x509 proxy PEM) + the
     * resolved delegation mode here via brix_vfs_ctx_bind_backend_deleg(). NULL
     * = no live bag ⇒ the cred gate stays on the SELECT path (phase-1). */
    brix_deleg_live_t   *deleg_live;
    /* phase-108 C12: the export's authorization rule set + rollout mode for the
     * VFS authorization backstop (position 1.5, after the mutation-policy
     * kernel, before the lock check). Bound by brix_vfs_ctx_bind_authz(); a
     * zeroed ctx has bound=0 ⇒ the backstop fails closed under ENFORCE. */
    brix_vfs_authz_t     authz;
    brix_path_result_t resolved;
    /* Phase-105: whether this request's ENDPOINT may modify exported storage.
     * Typed, not a bit, and zero is READ_ONLY, so a zeroed or hand-built ctx
     * fails closed; immutable for the life of the operation. Every mutation
     * entry point asks brix_vfs_require_mutation() rather than reading it. */
    brix_vfs_mutation_policy_t mutation_policy;
    /* Per-request I/O monitor, or NULL when this request is not monitored
     * (metadata-only paths, internal maintenance ops). The owning HTTP plane
     * allocates it on the request pool on the EVENT LOOP and points here; the
     * post-op observer folds bytes/latency/crc into it. Borrowed, never freed
     * by the VFS. See io_monitor.h for the threading contract. */
    struct brix_io_monitor_s *io_monitor;
    /* phase-110 W7: the client's address as a borrowed NUL-terminated string
     * (r->connection->addr_text on HTTP, ctx->peer_ip on root://), or NULL ⇒
     * "-". Set at the ctx builders on the EVENT LOOP; read by
     * brix_access_log_emit so the JSON access log records `remote` and is
     * self-sufficient (no join to nginx's log). Borrowed: the pointee lives on
     * the request/connection, never freed by the VFS. */
    const char          *peer;
    /* Phase-107 C5: the final object size the client declared for THIS write
     * (root:// `oss.asize`, HTTP Content-Length on PUT, GridFTP ALLO), or 0
     * when none was declared. Consumed once by the open paths - the object
     * plane calls driver->reserve after a create/trunc write-open, the staged
     * plane forwards it as staged_open's declared_size - so remote picks a
     * legal multipart part size, xroot forwards `oss.asize` to the origin, and
     * posix/frm preallocate. A scalar, so brix_vfs_ctx_pool_clone carries it
     * into detached write sessions for free. Never a limit: a client may write
     * past its declaration (the driver's own quota/extent still applies). */
    off_t                declared_size;
    /* 2.0 F5 (upstream pfc.urlcgi): the per-open cache hints the client carried
     * on THIS open (root:// `pfc.blocksize` / `pfc.prefetch`), all-zero when
     * none. Consumed once by the object-plane open, which hands it to the
     * driver's open_hinted slot. By value, like declared_size, so a pool clone
     * carries it for free. */
    brix_sd_open_hints_t open_hints;
    /* Phase-107 C7: the client's lock-token presentation for THIS operation —
     * the raw `If:` (else `Lock-Token:`) header VALUE, borrowed and
     * NUL-terminated, or NULL when the request presented none. Filled by the
     * WebDAV edge only; every other protocol has no way to present a WebDAV
     * lock token, so its mutations are always "foreign" to a held lock. The
     * lock gate matches by substring search, exactly as the WebDAV edge's
     * webdav_lock_if_header_matches does, so ownership answers agree across
     * planes. Never logged: it is a bearer secret for the lock. */
    const char          *lock_token;
    unsigned             is_tls:1;
    unsigned             want_pgcrc:1;
    unsigned             cache_enabled:1;
    unsigned             cache_writethrough:1;
    unsigned             storage_cred_deny:1;
    /* 2.0: the cache store already refused to hold this request's object (the
     * HTTP fill worker's ENOSPC re-entry, brix_io_monitor_t.fill_refused). The
     * driver open then carries BRIX_SD_O_NOFILL, so the cache decorator serves
     * the source directly instead of starting a second, equally doomed fill.
     * Set only by brix_http_monitor_bind / brix_http_cache_fill_if_needed. */
    unsigned             cache_no_fill:1;
};

/* Populate *vctx for a transient (rootfd = -1) confined open of an
 * already-resolved canonical path, filling the fields the HTTP front ends set
 * identically (pool/log/proto, export+cache roots, cache_enabled, the endpoint
 * mutation policy, is_tls, identity, resolved path). HTTP-agnostic: callers
 * pass pool/log/is_tls from their own request. Callers may tweak individual
 * fields afterwards.
 *
 * `mutation_policy` is the TYPED endpoint policy (phase-105), not a boolean:
 * derive it from merged configuration with brix_vfs_policy_from_write_enable()
 * or name BRIX_VFS_MUTATION_READ_ONLY for an intrinsically read-only surface.
 * Any value outside the enum is normalised to READ_ONLY here, so no caller can
 * open an endpoint by passing a stray non-zero integer. */
void brix_vfs_ctx_init(brix_vfs_ctx_t *vctx, ngx_pool_t *pool,
    ngx_log_t *log, brix_proto_t proto, const char *root_canon,
    const char *cache_root_canon,
    brix_vfs_mutation_policy_t mutation_policy, int is_tls,
    brix_identity_t *identity, const char *resolved_path);

/* Derive a child operation from an already-bound VFS context. The complete
 * request/export scope (identity, authorization rules, backend, N2N, delegated
 * credentials, endpoint policy, monitor, and peer) is copied by value; only
 * the confined resolved path changes. This is the canonical way for recursive
 * walkers and lazy metadata probes to avoid rebuilding a partial context.
 * Returns NGX_OK, or NGX_ERROR/EINVAL for a NULL input or target path. */
ngx_int_t brix_vfs_ctx_derive_path(brix_vfs_ctx_t *vctx,
    const brix_vfs_ctx_t *parent, const char *resolved_path);

/* phase-110 W1: record a cache lookup outcome for this ctx — bumps the unified
 * brix_cache_hits/misses counters (brix_metric_cache_result) AND folds the
 * same HIT/MISS word into ctx->io_monitor, so $brix_cache_status, the JSON
 * "cache_status" key and the Prometheus label agree by construction. Every
 * ctx-bearing site that used to call brix_metric_cache_result directly calls
 * this instead; the metric-only call remains for planes with no VFS ctx
 * (cvmfs). NULL ctx is a no-op. */
void brix_vfs_observe_cache_result(brix_vfs_ctx_t *ctx, unsigned hit);

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
    const ngx_str_t *ca_cert, const ngx_str_t *ca_key, time_t ttl_secs);

/* The export-root-relative ("logical") form of an absolute confined `path` — the
 * key an inst-keyed storage driver expects (what brix_vfs_open passes to the
 * driver's open slot). Returns `path` unchanged when it is not under the ctx's
 * export root. A borrowed pointer into `path` (no allocation). */
const char *brix_vfs_export_relative(const brix_vfs_ctx_t *ctx,
    const char *path);

/* Open ctx->resolved under the confinement cascade with the given
 * BRIX_VFS_O_* flags (translated to O_* internally). BRIX_VFS_O_WRITE
 * requires a writable endpoint (else EROFS); BRIX_VFS_O_MKDIRPATH pre-creates
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

/* The same fd, for the WINDOW the caller is about to send.  A fd-less
 * CAP_MEMFILE backend materialises its whole-object memfd only when the window
 * IS the whole object, so a ranged read of a remote object no longer fetches
 * the object; a strict sub-window returns NGX_INVALID_FILE and the caller takes
 * its memory-backed path.  Pass len < 0 for a caller that will read no bytes
 * at all (HEAD).  See vfs_open_handle.c for why the backend probe itself is
 * deliberately left asking for the whole object. */
ngx_fd_t brix_vfs_file_sendfile_fd_window(const brix_vfs_file_t *fh, off_t off,
    off_t len);
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
/* Write up to `len` bytes at offset `off` through the handle's storage driver —
 * the backend-neutral write twin of brix_vfs_file_pread. Unlike
 * brix_vfs_pwrite_full (which wraps a raw fd in the POSIX driver and so bypasses
 * an object backend's block layout + size bookkeeping), this dispatches to the
 * bound driver's pwrite slot, so a pblock/object backend routes its blocks and
 * tracks the catalog size. Bytes written or -1/errno; the caller loops on a
 * short write. */
ssize_t brix_vfs_file_pwrite(brix_vfs_file_t *fh, const void *buf, size_t len,
    off_t off);
/* Self-computed write-verify seam (src/fs/vfs/vfs_wverify.c): given a write-side
 * CRC accumulator (core/compat/wverify.h) fed with every written extent and a
 * FRESH read-only handle on the just-closed object, re-read the object through
 * its storage driver and confirm the persisted content matches what was written.
 * NGX_OK on match; NGX_ERROR on any mismatch, gap, short/oversize object, or
 * read failure. Backend-agnostic — the only trustworthy end-to-end check for an
 * object backend (pblock/rados) with no single kernel-file identity. */
struct brix_wverify_s;
ngx_int_t brix_vfs_wverify_check(struct brix_wverify_s *w, brix_vfs_file_t *rfh);
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

/* C-2 (phase-56): drop this worker's cached negative-stat entry (both stat
 * arms) for the resolved (root_canon, path). Every same-worker publish point
 * that can materialise a path OUTSIDE brix_vfs_open/mkdir/rename — a protocol
 * layer's direct create-open or staged-commit rename — MUST call this on
 * success so a cached ENOENT never outlives a same-worker create. No-op when
 * the cache is off (default). */
void brix_vfs_neg_stat_forget(const char *root_canon, const char *path);

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

/* Driver-reported export space (phase-83 F5): walk the ctx's backend (through
 * cache/stage decorators) to the first driver implementing the optional `space`
 * slot and return its quota-aware total/used/free view. NGX_OK (out set),
 * NGX_DECLINED (no driver reports space — caller falls back to statvfs(2)), or
 * NGX_ERROR (errno) on a guard/driver failure. */
ngx_int_t brix_vfs_space(brix_vfs_ctx_t *ctx, brix_sd_space_t *out);

/* 1 iff any tier of the resolved ctx chain declares CAP_NEARLINE (phase-107
 * C2): the export fronts tape/archive even if no tier implements recall. */
int brix_vfs_nearline_export(brix_vfs_ctx_t *ctx);

/* Startup advisor probe (phase-107 C2): 1 iff the composed chain declares
 * CAP_NEARLINE on some tier but pairs it with a recall slot on none — the
 * export can only stage through a prepare_command, and with none configured
 * should say so at worker startup. NULL chain (default POSIX) is 0. */
int brix_vfs_chain_nearline_unstageable(brix_sd_instance_t *chain);

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

/* Zero-copy sibling of brix_vfs_readdir: name_out->data BORROWS the handle's
 * current entry name — valid ONLY until the next readdir or closedir on this
 * handle. For single-pass consumers (the kXR_dirlist chunk streamer) that
 * finish with the name inside the same loop iteration; anyone who must hold a
 * name across iterations uses brix_vfs_readdir (pooled copy). */
ngx_int_t brix_vfs_readdir_borrow(brix_vfs_dir_t *dh, ngx_str_t *name_out,
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
/* Enumerate the bound backend's OWN object catalog (inventory/drift, spec
 * §E1/D2) — the driver-agnostic seam over the SD `enumerate` verb. Fires cb once
 * per stored object (brix_sd_catalog_ent_t); want_stat asks for per-object
 * size/mtime. Returns NGX_OK (full enumeration), the cb's non-zero abort code, or
 * NGX_DECLINED with errno==ENOTSUP when the backend has no native catalog (POSIX:
 * the namespace IS the catalog — callers fall back to a vfs_walk). Thread-safe to
 * the extent the driver's enumerate is (the Ceph verb runs on a thread worker). */
ngx_int_t brix_vfs_enumerate_catalog(brix_sd_instance_t *sd, int want_stat,
    brix_sd_catalog_cb cb, void *ctx);
/* Advisory read-ahead hint (BRIX_SD_ADV_*) for [off, off+len) on the open
 * handle; len == 0 hints the whole object. Best-effort: NGX_OK whether or not
 * the backend/kernel honours it, and a silent no-op success on a backend with
 * no read_advise slot. NGX_ERROR with errno set only on a bad handle/args or a
 * hard driver failure. Never changes position, size, or contents. */
ngx_int_t brix_vfs_file_read_advise(brix_vfs_file_t *fh, off_t off, size_t len,
    int advice);

/* Confined walk / open-unlink / raw-rw / xattr / copy / staged-write declarations
 * were split out (phase-79 file-size burndown) into vfs_ops.h, the
 * namespace/object mutation declarations (phase-107 W5) into vfs_mutate.h and
 * the phase-70 delegation live-cred binding (2.0 file-size cap) into
 * vfs_deleg.h; all three are included here so every fs/vfs.h consumer still
 * sees them. */
#include "fs/vfs/vfs_ops.h"
#include "fs/vfs/vfs_mutate.h"
#include "fs/vfs/vfs_deleg.h"

#endif /* BRIX_VFS_H */
