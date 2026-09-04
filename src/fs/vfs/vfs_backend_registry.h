/*
 * vfs_backend_registry.h — per-export storage-backend resolution.
 *
 * WHAT: A tiny per-worker table mapping an export's canonical root to its
 *       selected non-POSIX storage backend (today: pblock). Config parsing
 *       registers the export's backend choice; brix_vfs_ctx_init() resolves a
 *       ctx's root_canon to a bound brix_sd_instance_t through this table, so
 *       EVERY VFS op (any protocol) routes to the driver without each handler
 *       threading the instance by hand.
 *
 * WHY:  The backend instance must be created per worker (a SQLite connection
 *       cannot be shared across fork) and lazily (after fork), but the *choice*
 *       (root, backend name, block size) is known at config time. Splitting those
 *       — register the choice at config time, create the instance on first use
 *       per worker — lets one ctx_init lookup cover all ~50 ctx-build sites.
 *
 * HOW:  brix_vfs_backend_config() records {root_canon, "pblock", block_size}
 *       at config time (deduped on reload). brix_vfs_backend_resolve() looks up
 *       root_canon; on the first hit in a given worker it builds the instance on
 *       the cycle pool and caches it. A root with no registered backend (or a
 *       no-sqlite build) resolves to NULL ⇒ the default POSIX path.
 */
#ifndef BRIX_VFS_BACKEND_REGISTRY_H
#define BRIX_VFS_BACKEND_REGISTRY_H

#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/path/site_n2n.h"        /* brix_n2n_cfg_t for config_n2n / backend_n2n */
#include "core/compat/af_policy.h"   /* BRIX_AF_* family policy for config_str/_xroot */

/* Record (at config time) that the export rooted at `root_canon` uses backend
 * `name` (currently only "pblock") with `block_size` bytes (0 = default). Safe to
 * call repeatedly for the same root (last write wins) so a config reload is
 * idempotent. No-op for an empty root or an unknown backend name. */
void brix_vfs_backend_config(const char *root_canon, const ngx_str_t *name,
    size_t block_size);

/* brix_vfs_xroot_origin_t — the endpoint a remote root:// primary backend binds
 * to, as parsed from the brix_storage_backend URL.
 *
 * WHAT: host/port plus the three declarations the URL SCHEME carries: `tls`
 *       (roots://), `family` (the export's address-family constraint) and
 *       `nearline` (root+tape:// — the origin fronts an MSS).
 * WHY:  the four fields are all int-or-string and trivially transposable
 *       positionally, and `nearline` is the second flag to join them; one named
 *       struct keeps the call site self-describing (the same reason
 *       brix_sd_xroot_origin_cfg_t exists one layer down).
 * HOW:  `host` need only outlive the call — it is copied onto the entry. */
typedef struct {
    const char *host;      /* required: origin hostname (non-empty) */
    int         port;      /* required: origin port (1..65535) */
    int         tls;       /* non-zero: roots:// (TLS) */
    int         family;    /* brix_af_policy_t address-family constraint */
    int         nearline;  /* non-zero: root+tape:// — recall, do not block */
} brix_vfs_xroot_origin_t;

/* Record (at config time) that the export rooted at `root_canon` is backed by
 * the REMOTE root:// origin `o`, served through the sd_xroot driver. Works for
 * any export — stream OR http — since it carries the origin params explicitly
 * rather than a protocol-specific conf. Safe to call repeatedly for the same
 * root (idempotent reload). */
void brix_vfs_backend_config_xroot(const char *root_canon,
    const brix_vfs_xroot_origin_t *o);

/* The optional declarations an http origin URL carries in its query suffix.
 * Both are opt-in and default off, so an origin URL without a query behaves
 * exactly as it did before either existed. */
typedef struct {
    int         put_checksum;  /* "?put_checksum=1" (#12): the commit PUT carries
                                * Content-MD5 so the origin rejects a
                                * wire-corrupted upload. */
    const char *tape_api;      /* "?tape_api=/api/v1": the WLCG Tape REST API
                                * base on this origin. Non-empty arms
                                * BRIX_SD_CAP_NEARLINE, which commits the export
                                * to carrying a cache tier as the recall target
                                * (§9.4, enforced at config time) — so it is a
                                * declaration, never inferred. NULL = none. */
} brix_vfs_http_origin_opts_t;

/* Record (at config time) that the export rooted at `root_canon` is backed by a
 * read-only HTTP(S) source (`host`:`port`, TLS iff `tls`, URL base `base_path`),
 * served through the sd_http driver over the shared libcurl transport. `opts`
 * may be NULL (no query declarations). */
void brix_vfs_backend_config_http(const char *root_canon, const char *host,
    int port, int tls, const char *base_path,
    const brix_vfs_http_origin_opts_t *opts);

/* Record (at config time) that the export rooted at `root_canon` is backed by
 * an S3 source (`host`:`port`, TLS iff `tls`, path-style `bucket`), served
 * through the sd_remote driver over the shared libcurl S3 transport. The driver
 * advertises CAP_RANGE_READ (+CAP_MEMFILE) — no CAP_RANDOM_WRITE — so in-place
 * partial writes are rejected at the cap layer, while sequential uploads go
 * through the whole-object staged path (.staged_* → single PUT or MPU) and
 * deletes through .unlink (phase-71/phase-80). */
/* The optional declarations an s3 origin URL carries in its query suffix. */
typedef struct {
    int put_checksum;   /* "?put_checksum=1" (#12): sign x-amz-checksum-crc32 */
    int nearline;       /* "?nearline=1": the bucket is archive-backed
                         * (GLACIER/DEEP_ARCHIVE), so residency comes from the
                         * storage class and recall from RestoreObject. Arms
                         * BRIX_SD_CAP_NEARLINE — a declaration, like tape_api
                         * above, and subject to the same cache-tier contract. */
    int restore_days;   /* "?restore_days=N": how long a restored copy stays
                         * readable. 0 leaves the driver's default. */
} brix_vfs_s3_origin_opts_t;

void brix_vfs_backend_config_s3(const char *root_canon, const char *host,
    int port, int tls, const char *bucket,
    const brix_vfs_s3_origin_opts_t *opts);

typedef struct {
    const char *host;
    int         port;
    const char *base_path;
    int         require_gsi;
} brix_vfs_gsiftp_origin_t;

/* Register an outbound ftp:// or gsiftp:// storage origin. GSI credentials use
 * the existing backend credential setter; `o` only describes the endpoint. */
void brix_vfs_backend_config_gsiftp(const char *root_canon,
    const brix_vfs_gsiftp_origin_t *o);

/* Register the export's `storage_backend` config value, dispatching on its form:
 * a "root://host:port" / "roots://host:port" URL → a remote root:// primary
 * (config_xroot); any other value → a local driver name (config, pblock). One
 * entry point both the stream and http (webdav/s3) config paths call. `family`
 * is the brix_af_policy_t (BRIX_AF_AUTO/_INET/_INET6) for a remote root://
 * origin connect; non-remote backends ignore it. Returns NGX_OK, or NGX_ERROR
 * (cf-logged) on a malformed remote URL. */
ngx_int_t brix_vfs_backend_config_str(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *backend, size_t block_size, int family);

/* Phase-108 A.4: apply the export's explicit `brix_n2n_scheme` / `brix_n2n_pool`
 * / `brix_n2n_prefix` directives over the default translation the backend parser
 * already derived (ceph ⇒ CEPHFS_PATH+key_prefix; every other backend ⇒
 * IDENTITY). Validates at nginx -t and OVERRIDES nothing when all three are unset
 * (scheme->len==0). Rejects: an unknown scheme; `ral` without a pool; a pool
 * over 127 or a prefix over 255 bytes (a config error, never a runtime
 * truncation); and — the footgun guard — `ral` on the RADOS ("ceph") backend,
 * whose object names are ioctx-bound, not "<pool>:"-prefixed. Returns NGX_OK, or
 * NGX_ERROR (cf-logged). A no-op for an export with no backend registry entry. */
ngx_int_t brix_vfs_backend_config_n2n(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *scheme, const ngx_str_t *pool, const ngx_str_t *prefix);

/* Phase-108 A.4: the export's resolved name translation (borrowed, worker-
 * lifetime), or NULL when the export has no registry entry (⇒ IDENTITY). Bound
 * onto ctx->n2n in brix_vfs_ctx_init. Pure lookup, no allocation. */
const brix_n2n_cfg_t *brix_vfs_backend_n2n(const char *root_canon);

/* Upstream credential material a backend build consumes (plain primitives, so the
 * registry stays independent of the config credential block). NULL / "" ⇒ unset.
 * Each backend build reads only the fields its scheme needs: bearer→ztn (sd_http/
 * sd_xroot); x509_proxy/ca_dir→GSI (sd_xroot); s3_*→SigV4 (sd_remote/sd_s3);
 * sss_keytab→SSS (sd_xroot origin). */
typedef struct brix_vfs_backend_cred_s {
    const char *bearer;
    const char *x509_proxy;
    const char *x509_key;   /* separate GSI key PEM; NULL ⇒ key is in x509_proxy */
    const char *ca_dir;
    const char *s3_access_key;
    const char *s3_secret_key;
    const char *s3_region;
    const char *sss_keytab;
} brix_vfs_backend_cred_t;

/* Attach (at config time) the credential the source backend authenticates to its
 * upstream with (§14 brix_credential). Set after the backend is registered for the
 * same root; all-unset ⇒ anonymous. NULL `cred` ⇒ anonymous (clears any prior). */
void brix_vfs_backend_set_credential(const char *root_canon,
    const brix_vfs_backend_cred_t *cred);

/* Mark (at config time) whether the export rooted at `root_canon` stages uploads
 * locally and PROMOTES them to a remote backend on commit (write-back), vs.
 * streaming straight through (Mode A passthrough). Only meaningful for a remote
 * (xroot) backend. Set after the backend is registered for the same root. */
void brix_vfs_backend_set_staging(const char *root_canon, int on);

/* phase-107 C1 — the writer's SPILL scratch for this export. The setter runs at
 * config time (spill_root already canonical, validated OUTSIDE every export
 * root by the caller); the getter runs on the write path and never allocates:
 * *root_out borrows the entry's storage (NULL means "no scratch"), *max_out is
 * the per-spill byte cap (0 = uncapped). Returns NGX_OK when the export is
 * registered, NGX_ERROR otherwise (outputs are zeroed either way first). */
void brix_vfs_backend_set_spill(const char *root_canon,
    const char *spill_root, off_t spill_max);
ngx_int_t brix_vfs_backend_spill(const char *root_canon,
    const char **root_out, off_t *max_out);

/* phase-107 C3 durable publish. set_durable registers the export's merged
 * brix_durable_publish flag at config time (on==0 opts the export out of the
 * per-publish parent-directory fsync). brix_vfs_backend_durable answers at
 * publish time; an unregistered root — including the NULL/empty root of a
 * transient ctx — is DURABLE (the default is on, and absence fails safe). */
void brix_vfs_backend_set_durable(const char *root_canon, ngx_flag_t on);
ngx_int_t brix_vfs_backend_durable(const char *root_canon);

/* phase-107 C7 lock enforcement. set_lock_enforcement registers the export's
 * merged brix_lock_enforcement mode at config time (registered only when it
 * relaxes the default); brix_vfs_backend_lock_enforcement answers on the
 * mutation path. An unregistered root — including the NULL/empty root of a
 * transient ctx — is STRICT (0): absence fails toward enforcement. Values are
 * brix_vfs_lock_enforcement_t (vfs_policy.h). */
void brix_vfs_backend_set_lock_enforcement(const char *root_canon,
    ngx_uint_t mode);
ngx_uint_t brix_vfs_backend_lock_enforcement(const char *root_canon);

/* Resolve `root_canon` to its bound storage-driver instance, creating it on first
 * use in this worker (on ngx_cycle->pool). Returns NULL when the export has no
 * registered non-POSIX backend (⇒ default POSIX) or on creation failure (logged). */
brix_sd_instance_t *brix_vfs_backend_resolve(const char *root_canon,
    ngx_log_t *log);

/* Return the HTTP endpoint of the http/https backend registered at `root_canon`,
 * or -1 for any other backend kind (or no registration). Pointers alias the
 * registry's stable per-process storage (valid for the process lifetime);
 * callers must not free or modify them. Consumed by protocol-side uncached
 * passthroughs (phase-68 cvmfs geo/manifest) that talk to the same origin the
 * tier fills from. */
int brix_vfs_backend_http_endpoint(const char *root_canon,
    const char **host, int *port, int *tls, const char **base);

/* Runtime twin of the config-time http registration (phase-68 T14 proxy
 * mode): register a synthetic per-upstream export entry keyed `up_root`
 * (http origin host:port; cache tier cloned from `template_root` with the
 * store path suffixed `store_suffix` for per-upstream isolation). Idempotent
 * per worker; event-loop only. NGX_OK, or NGX_ERROR (table full/overflow). */
ngx_int_t brix_vfs_backend_register_http_upstream(const char *up_root,
    const char *template_root, const char *host, int port, int tls,
    const char *store_suffix);

/* T19 origin selection: endpoint inventory + config-time rank recording for
 * the http backend at `root_canon` (see vfs_backend_config.c). */
int  brix_vfs_backend_http_endpoint_at(const char *root_canon, int idx,
    const char **host, int *port);
void brix_vfs_backend_set_http_ranks(const char *root_canon,
    const int *ranks, int n);

/* Resolve the bound backend for an ABSOLUTE path by longest-prefix match against
 * the registered export roots (so a staged-file commit can find the export a
 * final path belongs to without the caller threading root_canon). On a match,
 * builds/returns the instance (as resolve() does) and, if `root_out` is non-NULL,
 * points it at the matched export root_canon (stable for the process lifetime).
 * Returns NULL (⇒ default POSIX) when no registered export root is a prefix of
 * `abs_path`. */
brix_sd_instance_t *brix_vfs_backend_resolve_for_path(const char *abs_path,
    const char **root_out, ngx_log_t *log);

/* C-7 observability: a read-only snapshot of one registered export's composed
 * stack, for the /metrics storage-backend info gauge. Pointers alias the registry's
 * stable per-process storage (valid for the process lifetime). */
typedef struct {
    const char *root_canon;
    const char *backend;     /* "pblock" | "xroot" | "http" (config-time choice) */
    const char *host;        /* xroot/http origin host, or "" */
    int         port;
    int         tls;
    int         staging;     /* write-back stage decorator composed */
    int         has_token;   /* §14 bearer credential configured */
    int         has_proxy;   /* §14 X.509 proxy credential configured */
} brix_vfs_backend_info_t;

/* Number of registered exports (config-time count; stable after config load). */
ngx_uint_t brix_vfs_backend_export_count(void);

/* Fill *out for export index `i` (< export_count). Returns NGX_OK, or NGX_ERROR for
 * an out-of-range index. Read-only — never builds an instance. */
ngx_int_t brix_vfs_backend_export_info(ngx_uint_t i,
    brix_vfs_backend_info_t *out);

#endif /* BRIX_VFS_BACKEND_REGISTRY_H */
