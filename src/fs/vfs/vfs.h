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
#include "auth/s3/sts.h"                 /* brix_s3_sts_conf_t (§5.5 set_sts) */
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

/* Does the storage backend resolved for this ctx consume a forwarded X.509 proxy
 * PEM (BRIX_SD_CRED_PROXY_PEM in its cred_accept mask)? Lets a protocol gate a
 * default-on proxy delegation to only the backends that can actually use it
 * (xroot, s3), leaving posix/pblock (which accept no forwarded proxy) untouched
 * so binding a proxy bag there never turns into a spurious cred-gate deny.
 * Returns 1 when the backend accepts a proxy PEM, 0 otherwise (incl. NULL ctx or
 * the default-POSIX NULL backend). Defined in vfs_deleg.c. */
int brix_vfs_backend_accepts_proxy(brix_vfs_ctx_t *vctx);

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
 * the VFS op. `tx_cache_slot` (optional, may be NULL) is the address of the
 * conf's `backend_tx_cache` pointer — the gate lazily creates the per-worker
 * RFC-8693 minted-token cache there (P90-70.9); NULL disables caching. A no-op
 * when no bag is bound or `endpoint` is empty — the cred gate then degrades
 * EXCHANGE to verbatim bearer passthrough. Defined in vfs_deleg_bind.c. */
void brix_vfs_deleg_set_exchange(brix_vfs_ctx_t *vctx,
    const ngx_str_t *endpoint, const ngx_str_t *client_id,
    const ngx_str_t *client_secret, const ngx_str_t *audience,
    void **tx_cache_slot);

/* Bind the export's trusted CA store onto the ctx's bound live-cred bag so the
 * PASSTHROUGH materialiser re-verifies the proxy chain in-gate (phase-70 §5.1
 * RFC-3820 chain-trust, P90-70.4). Call at capture time, AFTER
 * brix_vfs_deleg_bind: `ca_store` is the protocol conf's X509_STORE* (webdav
 * conf->ca_store / stream conf->gsi_store; typed void* so this header stays
 * OpenSSL-free) and is borrowed — it must outlive the VFS op. `verify_depth` is
 * the max proxy chain depth (0 = OpenSSL default). A no-op when no bag is bound
 * or `ca_store` is NULL — the gate then relies on the capture-side validation
 * alone. Defined in vfs_deleg_bind.c. */
void brix_vfs_deleg_set_ca_store(brix_vfs_ctx_t *vctx, void *ca_store,
    ngx_uint_t verify_depth);

/* Arm SSS identity injection on the ctx (phase-70 §5.6 / P90-70.3): when the
 * request carries NO forwardable credential bytes, the cred gate materialises
 * an SSS credential asserting the caller's authenticated principal, signed
 * with `keytab` (conf->common.backend_sss_keytab; borrowed conf bytes,
 * NUL-terminated). Proven bytes (proxy PEM / bearer) always win over
 * injection. Unlike the other setters this ALLOCATES the bag (from vctx->pool)
 * when none is bound — injection is precisely the no-captured-bytes case where
 * brix_vfs_deleg_bind declined to bind. A no-op when `mode` is
 * BRIX_CRED_SELECT or `keytab` is empty; on bag-allocation OOM it degrades to
 * SELECT exactly like brix_vfs_deleg_bind's no-bytes path. Defined in
 * vfs_deleg_bind.c. */
void brix_vfs_deleg_set_sss(brix_vfs_ctx_t *vctx, enum brix_cred_mode mode,
    const ngx_str_t *keytab);

/* Arm S3 STS credential EXCHANGE on the ctx (phase-70 §5.5): when the request
 * carries NO forwardable credential bytes and the leaf backend accepts an S3
 * credential, the cred gate exchanges the node's S3 SERVICE credential for
 * temporary (ak/sk/session) creds scoped to the caller's identity via STS
 * AssumeRole/GetSessionToken. `cf` is a borrowed brix_s3_sts_conf_t built from
 * conf->common.backend_sts_* (its ngx_str_t fields point at conf-owned bytes;
 * the struct itself must outlive the VFS op — build it on the request pool).
 * Like brix_vfs_deleg_set_sss this ALLOCATES the bag (from vctx->pool) when none
 * is bound — STS, like SSS, is precisely the no-captured-bytes case. A no-op
 * when `mode` is BRIX_CRED_SELECT or `cf` is NULL; on bag-allocation OOM it
 * degrades to SELECT. Defined in vfs_deleg_bind.c. */
void brix_vfs_deleg_set_sts(brix_vfs_ctx_t *vctx, enum brix_cred_mode mode,
    const brix_s3_sts_conf_t *cf);

/* Arm krb5 GSSAPI EXCHANGE on the ctx (phase-70 §5.7): the front door has
 * captured the caller's forwarded TGT and serialised it to a 0600 FILE ccache
 * (brix_krb5_cred_to_ccache); this stamps that async-safe ccache PATH plus the
 * derived origin service principal onto the bag. When the leaf backend accepts
 * BRIX_SD_CRED_GSS_KRB5 the cred gate carries them onto the cred (mode EXCHANGE)
 * and the origin leg re-imports the cred and negotiates AS the caller. `ccache`
 * and `origin_princ` are borrowed NUL-terminated request-pool strings that must
 * outlive the VFS op. Like set_sss/set_sts this ALLOCATES the bag when none is
 * bound; a no-op when `mode` is BRIX_CRED_SELECT or either string is empty; on
 * bag-allocation OOM it degrades to SELECT. Defined in vfs_deleg_bind.c. */
void brix_vfs_deleg_set_krb5(brix_vfs_ctx_t *vctx, enum brix_cred_mode mode,
    const ngx_str_t *ccache, const ngx_str_t *origin_princ);

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
 * were split out (phase-79 file-size burndown) into vfs_ops.h, and the
 * namespace/object mutation declarations (phase-107 W5) into vfs_mutate.h; both
 * are included here so every fs/vfs.h consumer still sees them. */
#include "fs/vfs/vfs_ops.h"
#include "fs/vfs/vfs_mutate.h"

#endif /* BRIX_VFS_H */
