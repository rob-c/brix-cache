/* client.h — CVMFS-brix client assembler (pure C; the mount→resolve→read core).
 *
 * WHAT: composes the whole read stack into one object — verify the trust chain,
 *       load the root catalog, resolve a path to metadata, and read a file's
 *       bytes — behind a small API the FUSE layer (SP-F layer 2) drives.
 * WHY:  keep every hard part (crypto, catalog SQL, content fetch, failover)
 *       testable end-to-end WITHOUT libfuse or a real mount; the FUSE binding is
 *       then a thin translation of these calls into fuse_operations.
 * HOW:  transport is the same injected seam the fetch orchestrator uses; the
 *       client owns a failover engine, a CAS cache, a fetch context, and the
 *       opened root catalog. Named metadata (.cvmfswhitelist/.cvmfspublished) is
 *       fetched raw over failover; CAS objects (cert, catalog, content) go through
 *       the hash-verifying fetch orchestrator. Nested-catalog descent uses the
 *       catalog reader's nested() lookup.
 */
#ifndef BRIX_CVMFS_CLIENT_H
#define BRIX_CVMFS_CLIENT_H

#include <stddef.h>
#include "cvmfs/config/repo.h"
#include "cvmfs/failover/failover.h"
#include "cvmfs/fetch/fetch.h"
#include "cvmfs/catalog/catalog.h"
#include "cvmfs/filter/xorf.h"
#include "cvmfs/index/pathidx.h"
#include "cvmfs/signature/manifest.h"
#include "cache/cas_store.h"

typedef struct {
    cvmfs_repo_config_t config;
    cvmfs_failover_t    fo;
    brix_cas_store_t    cache;
    cvmfs_fetch_ctx_t   fetch;
    cvmfs_transport_fn  transport;
    void               *transport_ud;

    unsigned char       manifest_buf[65536];
    size_t              manifest_len;
    cvmfs_manifest_t    manifest;
    unsigned char       manifest_stage[65536]; /* refresh staging: verified-then-commit */

    char                catalog_tmp[512];      /* tmp_dir for spilled catalogs */
    char                root_catalog_tmp[512]; /* root catalog's spill file */
    cvmfs_catalog_t    *root_catalog;

    unsigned char       master_pub[8192];      /* repo master key (for refresh) */
    size_t              master_pub_len;
    long                mounted_at;            /* monotonic secs */
    long                last_refresh;          /* last manifest re-verify */
    long                last_reap;             /* last quota reap tick */
    long                ttl;                   /* manifest TTL secs */

    /* Reproducibility pin: when set, the mount serves exactly pin_root and
     * refresh never swaps catalogs; a verified upstream advance is recorded as
     * drift for the FUSE layer to surface. */
    cvmfs_hash_t        pin_root;
    int                 pin_set;
    int                 pin_drift;             /* latest verified upstream root != pin */
    char                pin_drift_hex[48];     /* that upstream root's hex */

    /* G1 negative-lookup filter (phase-87): consulted at the top of resolve;
     * only honoured while negf_root still equals the SERVED root catalog, so a
     * refresh that installs a new revision silently deactivates it (a stale
     * filter can never fabricate an ENOENT for a path the new revision has). */
    cvmfs_xorf_t        negf;
    cvmfs_hash_t        negf_root;
    int                 negf_set;

    /* G6 mmap path index (phase-87): resolve/readdir/read fast paths, honoured
     * only while pidx_root equals the SERVED root (the filter's guard rule);
     * a failed index-resolved read drops it (fail-safe over-invalidation). */
    cvmfs_pathidx_t     pidx;
    cvmfs_hash_t        pidx_root;
    int                 pidx_set;

    /* Cache-format knobs (phase-87 G4/G5): set via cvmfs_client_cache_config
     * BEFORE cvmfs_client_mount (the pin_root pattern). Default = flat store. */
    int                 cache_packed;
    int                 cache_tiering;
    long                cache_seg_bytes;   /* <=0 = backend default */

    unsigned char       scratch[8u * 1024u * 1024u];   /* transport landing */
} cvmfs_client_t;

/* Verify trust + load the root catalog. `master_pub_pem` is the repo master key.
 * The caller has already filled client->config (fqrn) and added the failover
 * servers/proxies. Returns 0 on success, negative on failure (bad sig, expired
 * whitelist, fetch exhausted, corrupt catalog). */
/* Mount the repo. Cache backing is either an absolute `cache_dir` (when
 * `cache_dirfd < 0`) or an already-open directory fd `cache_dirfd` (overlay
 * mode — the caller owns the fd). `quota_bytes` (0 = unbounded) is the cache high
 * watermark; the store auto-reaps to 75% on fills that exceed it. */
int cvmfs_client_mount(cvmfs_client_t *cl, const char *repo_name,
                       const unsigned char *master_pub_pem, size_t master_pub_len,
                       const char *cache_dir, const char *tmp_dir,
                       long quota_bytes, int cache_dirfd,
                       cvmfs_transport_fn transport, void *ud, long now);

void cvmfs_client_umount(cvmfs_client_t *cl);

/* Resolve a repo-root-relative path (root = "/") to its dirent, following nested
 * catalog transitions. Returns 1 found, 0 absent, -1 error. */
int cvmfs_client_resolve(cvmfs_client_t *cl, const char *path, cvmfs_dirent_t *out, long now);

/* List directory `path`, following nested-catalog transitions (a mountpoint's
 * children live in its nested catalog). Invokes `cb` per entry. Returns the
 * entry count, or <0 on error. */
int cvmfs_client_readdir(cvmfs_client_t *cl, const char *path,
                         cvmfs_readdir_cb cb, void *ud, long now);

/* Read up to `len` bytes at `offset` from file `path` into `buf`; *outlen gets
 * the bytes read (0 at/after EOF). Handles chunked files transparently. Returns 0
 * on success, negative on error (not a file, fetch failed). */
int cvmfs_client_read(cvmfs_client_t *cl, const char *path, uint64_t offset,
                      size_t len, unsigned char *buf, size_t *outlen, long now);

/* If the manifest TTL has expired, re-fetch + re-verify it and, when the repo has
 * published a new revision (root-catalog hash changed), swap in the new root
 * catalog. A failed refresh keeps the current catalog serving (offline-tolerant).
 * Returns 1 if a new revision was installed, 0 if unchanged/not due, -1 on error. */
int cvmfs_client_refresh(cvmfs_client_t *cl, long now);

/* Opportunistic cache-quota reap. Time-gated (~30s) so it's cheap to call from
 * hot FUSE ops; enforces the quota if the cache is over its high watermark
 * (a safety net for a cache adopted over-quota from a prior run). */
void cvmfs_client_reap_tick(cvmfs_client_t *cl, long now);

/* Magic extended attributes (getfattr -n user.<name>). Writes the value for
 * `name` on `path` into `out`; returns the length, or -1 if the attribute is not
 * defined here. Supported: user.fqrn, user.revision, user.root_hash, user.host,
 * user.proxy, user.hash (files), user.nchunks (files). */
int cvmfs_client_getxattr(cvmfs_client_t *cl, const char *path, const char *name,
                          char *out, size_t outlen, long now);

/* The NUL-separated list of magic attribute names applicable to `path` (files
 * additionally carry user.hash / user.nchunks). Returns the total byte length
 * (which may exceed outlen; then out is left untouched). */
int cvmfs_client_listxattr(cvmfs_client_t *cl, const char *path,
                           char *out, size_t outlen, long now);

/* Pin the mount to an exact root-catalog hash ("<hex>[-algo]"). Call BEFORE
 * cvmfs_client_mount. The trust chain still verifies in full each mount/refresh;
 * the root catalog is then fetched BY THE PIN (the CAS fetch is hash-verified,
 * so a tampered pin target is refused) and refresh never swaps it.
 * Returns 0, or -1 on an unparsable hash. */
int cvmfs_client_pin_root(cvmfs_client_t *cl, const char *hex);

/* Select the packed cache backend (phase-87 G4: log-structured segments under
 * <cache>/pack/) and optionally G5 format tiering (zstd cold packing + hot
 * promotion). Call BEFORE cvmfs_client_mount. `seg_bytes<=0` = default. */
void cvmfs_client_cache_config(cvmfs_client_t *cl, int packed, int tiering,
                               long seg_bytes);

/* Drift probe: returns 1 when the latest VERIFIED upstream manifest advertises
 * a root catalog different from the pin (its hex is written into out), else 0. */
int cvmfs_client_pin_drift(cvmfs_client_t *cl, char *out, size_t outlen);

/* ---- G1 negative-lookup filter (client_negfilter.c) --------------------- */

/* Build the filter from the client's OWN verified paths walk of the served
 * root catalog (every hop hash-verified — no trust in a proxy-supplied image)
 * and activate it. Returns 0 activated, -1 on walk/build failure (filter left
 * inactive — lookups just stay live). */
int cvmfs_client_negfilter_build(cvmfs_client_t *cl, long now);

/* Adopt an already-built/deserialized filter bound to `root`. Refused (-1)
 * unless `root` equals the currently served root catalog — a filter for any
 * other revision must never answer. On success the filter's heap moves into
 * the client (`f` is zeroed); the caller must not reset it afterwards. */
int cvmfs_client_negfilter_adopt(cvmfs_client_t *cl, cvmfs_xorf_t *f,
                                 const cvmfs_hash_t *root);

/* The active filter + its bound root (for sidecar serialization), or NULL. */
const cvmfs_xorf_t *cvmfs_client_negfilter(const cvmfs_client_t *cl,
                                           cvmfs_hash_t *root_out);

void cvmfs_client_negfilter_clear(cvmfs_client_t *cl);

/* ---- G6 mmap path index (client_pathidx.c) ------------------------------ */

/* Build the index from the client's OWN verified paths walk of the served
 * root catalog, write it as sidecar `name` under directory fd `dfd`
 * (tmp+rename), mmap it back and activate it. Returns 0 activated, -1 on any
 * failure (index left inactive — lookups stay on the catalogs). */
int cvmfs_client_pathidx_build(cvmfs_client_t *cl, int dfd, const char *name,
                               long now);

/* Adopt an existing sidecar. Refused (-1) unless it validates AND records the
 * currently served root catalog — an index for any other revision must never
 * answer. */
int cvmfs_client_pathidx_load(cvmfs_client_t *cl, int dfd, const char *name);

void cvmfs_client_pathidx_clear(cvmfs_client_t *cl);
int  cvmfs_client_pathidx_active(const cvmfs_client_t *cl);

#endif /* BRIX_CVMFS_CLIENT_H */
