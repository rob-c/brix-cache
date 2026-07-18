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

/* Drift probe: returns 1 when the latest VERIFIED upstream manifest advertises
 * a root catalog different from the pin (its hex is written into out), else 0. */
int cvmfs_client_pin_drift(cvmfs_client_t *cl, char *out, size_t outlen);

#endif /* BRIX_CVMFS_CLIENT_H */
