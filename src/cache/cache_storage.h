#ifndef XROOTD_CACHE_STORAGE_H
#define XROOTD_CACHE_STORAGE_H

/*
 * cache_storage.h — per-role SD storage instances for the cache.
 *
 * WHAT: The cache performs ALL disk byte-I/O through an xrootd_sd_instance_t per
 *       role — the read cache (cache_root), the sidecar/state tree
 *       (cache_state_root, POSIX), and the write-back staging cache
 *       (cache_wt_stage_root). The POSIX driver is bound to a per-worker O_PATH
 *       rootfd by default; a configured backend (e.g. pblock) is resolved through
 *       the backend registry instead. No raw libc disk calls in the cache data path.
 *
 * WHY:  Makes every cache storage role independently backend-pluggable and routes
 *       the cache through the same SD seam as the export, so a node can run one
 *       backend for its primary and its cache. See the design spec.
 *
 * HOW:  xrootd_cache_storage_init() (per-worker, from process.c) opens the O_PATH
 *       rootfds and builds the instances; xrootd_cache_storage_cleanup() closes
 *       them at exit. The resolvers return the pre-built instance for a role. The
 *       cache key is the server-controlled export-relative path (no raw client path).
 */

#include "cache_internal.h"
#include "../fs/backend/sd.h"

/* Build the per-role SD instances + O_PATH rootfds for this worker. No-op when no
 * cache is configured. Returns NGX_OK, or NGX_ERROR on a hard failure (a missing
 * cache dir is reported by the existing config validation, not here). */
ngx_int_t xrootd_cache_storage_init(ngx_stream_xrootd_srv_conf_t *conf,
    ngx_cycle_t *cycle);

/* Close the per-role rootfds at worker exit. NULL-safe / idempotent. */
void xrootd_cache_storage_cleanup(ngx_stream_xrootd_srv_conf_t *conf);

/* The read-cache storage instance (cache_root). NULL if no cache configured. */
xrootd_sd_instance_t *xrootd_cache_storage(const ngx_stream_xrootd_srv_conf_t *conf);
/* The POSIX instance holding the .cinfo/.meta sidecar tree. NULL if no cache. */
xrootd_sd_instance_t *xrootd_cache_state_storage(const ngx_stream_xrootd_srv_conf_t *conf);
/* The write-back staging instance. NULL when no staging role is configured (the
 * flush then reads the primary — the Phase-1 fallback). */
xrootd_sd_instance_t *xrootd_cache_wt_stage(const ngx_stream_xrootd_srv_conf_t *conf);

/* Look up a cache root's read / state instance by its cache_root_canon — for the
 * VFS cache-open hook (open.c), which has the root string but not the conf. NULL
 * if no cache is configured on that root. */
xrootd_sd_instance_t *xrootd_cache_storage_by_root(const char *cache_root_canon);
xrootd_sd_instance_t *xrootd_cache_state_by_root(const char *cache_root_canon);
/* The POSIX state (sidecar) root for a cache root (== cache root if co-located). */
const char *xrootd_cache_state_root_by_root(const char *cache_root_canon);

/* Map a cache_path (cache_root + key) to its sidecar base path under the state
 * root (state_root + key) — where the .meta/.cinfo POSIX sidecars live. For a
 * co-located cache (state_root == cache_root) this is cache_path unchanged.
 * 0 / -1. */
int xrootd_cache_sidecar_path(const char *cache_root, const char *state_root,
    const char *cache_path, char *dst, size_t dstsz);

/* Driver-aware three-state readiness for a cache_path (cache_root + key): 1 = a
 * complete cached object exists (serve it), 0 = absent (schedule a fill), -1 =
 * error. When a cache STORAGE backend is configured the readiness is a driver
 * stat of the export-relative key (a pblock/object cache has no POSIX file at
 * cache_path); a POSIX cache falls back to xrootd_cache_file_ready(). */
int xrootd_cache_ready(const ngx_stream_xrootd_srv_conf_t *conf,
                       const char *cache_path);

/* The export-relative key under cache_root for an absolute cache_path, or NULL if
 * cache_path is not under cache_root (the suffix keeps its leading '/'). */
const char *xrootd_cache_key_under_root(const ngx_stream_xrootd_srv_conf_t *conf,
                                        const char *cache_path);

/* Export-relative cache key for `resolved` (server-controlled, leading-slash).
 * 0 / -1 (not under the export root, or overflow). */
int xrootd_cache_key(const ngx_stream_xrootd_srv_conf_t *conf,
                     const char *resolved, char *dst, size_t dstsz);
/* Pure form (no conf) used by the standalone unit test. */
int xrootd_cache_key_from(const char *cache_root_canon, const char *root_canon,
                          const char *resolved, char *dst, size_t dstsz);

#endif /* XROOTD_CACHE_STORAGE_H */
