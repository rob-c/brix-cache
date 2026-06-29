/*
 * vfs_backend_registry.h — per-export storage-backend resolution.
 *
 * WHAT: A tiny per-worker table mapping an export's canonical root to its
 *       selected non-POSIX storage backend (today: pblock). Config parsing
 *       registers the export's backend choice; xrootd_vfs_ctx_init() resolves a
 *       ctx's root_canon to a bound xrootd_sd_instance_t through this table, so
 *       EVERY VFS op (any protocol) routes to the driver without each handler
 *       threading the instance by hand.
 *
 * WHY:  The backend instance must be created per worker (a SQLite connection
 *       cannot be shared across fork) and lazily (after fork), but the *choice*
 *       (root, backend name, block size) is known at config time. Splitting those
 *       — register the choice at config time, create the instance on first use
 *       per worker — lets one ctx_init lookup cover all ~50 ctx-build sites.
 *
 * HOW:  xrootd_vfs_backend_config() records {root_canon, "pblock", block_size}
 *       at config time (deduped on reload). xrootd_vfs_backend_resolve() looks up
 *       root_canon; on the first hit in a given worker it builds the instance on
 *       the cycle pool and caches it. A root with no registered backend (or a
 *       no-sqlite build) resolves to NULL ⇒ the default POSIX path.
 */
#ifndef XROOTD_VFS_BACKEND_REGISTRY_H
#define XROOTD_VFS_BACKEND_REGISTRY_H

#include <ngx_core.h>

#include "backend/sd.h"

/* Record (at config time) that the export rooted at `root_canon` uses backend
 * `name` (currently only "pblock") with `block_size` bytes (0 = default). Safe to
 * call repeatedly for the same root (last write wins) so a config reload is
 * idempotent. No-op for an empty root or an unknown backend name. */
void xrootd_vfs_backend_config(const char *root_canon, const ngx_str_t *name,
    size_t block_size);

/* Record (at config time) that the export rooted at `root_canon` is backed by a
 * REMOTE root:// origin, served through the sd_xroot driver. `srv_conf` is the
 * export's ngx_stream_xrootd_srv_conf_t* (the origin connection params —
 * cache_origin_host/port/tls — are read from it on first use per worker). Safe to
 * call repeatedly for the same root (idempotent reload). */
void xrootd_vfs_backend_config_xroot(const char *root_canon, void *srv_conf);

/* Resolve `root_canon` to its bound storage-driver instance, creating it on first
 * use in this worker (on ngx_cycle->pool). Returns NULL when the export has no
 * registered non-POSIX backend (⇒ default POSIX) or on creation failure (logged). */
xrootd_sd_instance_t *xrootd_vfs_backend_resolve(const char *root_canon,
    ngx_log_t *log);

/* Resolve the bound backend for an ABSOLUTE path by longest-prefix match against
 * the registered export roots (so a staged-file commit can find the export a
 * final path belongs to without the caller threading root_canon). On a match,
 * builds/returns the instance (as resolve() does) and, if `root_out` is non-NULL,
 * points it at the matched export root_canon (stable for the process lifetime).
 * Returns NULL (⇒ default POSIX) when no registered export root is a prefix of
 * `abs_path`. */
xrootd_sd_instance_t *xrootd_vfs_backend_resolve_for_path(const char *abs_path,
    const char **root_out, ngx_log_t *log);

#endif /* XROOTD_VFS_BACKEND_REGISTRY_H */
