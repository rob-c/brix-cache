#include "cache_internal.h"
#include "meta.h"
#include "open.h"          /* brix_cache_path_for_resolved */
#include "cstore.h"          /* brix_cstore_local_root (driver-truthful reap root) */
#include "cache_storage.h"  /* brix_cache_storage_cstore (resolve the tier cstore) */


#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/*
 * paths.c — cache file path helpers: deterministic suffix construction, parent
 * directory creation, and ready-file detection for the open-or-fill admission
 * logic. Each does one path op with bounds checking and errno translation.
 */

/* brix_cache_append_suffix — snprintf base + suffix into dst (e.g. "data" →
 * "data.part") with bounds checking, so atomic .part → final renames can't collide;
 * NGX_OK, or -1 on truncation/snprintf failure. */

int
brix_cache_append_suffix(char *dst, size_t dstsz, const char *path,
    const char *suffix)
{
    int n;

    n = snprintf(dst, dstsz, "%s%s", path, suffix);
    return (n >= 0 && (size_t) n < dstsz) ? 0 : -1;
}

int
brix_cache_meta_path(char *dst, size_t dstsz, const char *cache_path)
{
    return brix_cache_append_suffix(dst, dstsz, cache_path, ".meta");
}

/* brix_cache_ensure_parent — extract path's dirname and create it recursively
 * (brix_mkdir_recursive, 0755) so a fill worker writing a newly-discovered origin
 * file doesn't ENOENT; NGX_OK if it exists or was created, -1 on ENAMETOOLONG. */

int
brix_cache_ensure_parent(const char *path)
{
    char  parent[PATH_MAX];
    char *slash;
    int   n;

    n = snprintf(parent, sizeof(parent), "%s", path);
    if (n < 0 || (size_t) n >= sizeof(parent)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        return 0;
    }

    *slash = '\0';
    /* 0700: the cache tree is svc-owned and never client-listable; a mapped
     * low-priv uid must not be able to traverse/enumerate another user's cached
     * paths on a shared filesystem. */
    return brix_mkdir_recursive(parent, 0700);
}

/* brix_cache_file_ready — three-state readiness for the open-or-fill decision:
 * 1 = an existing regular file (cache hit), 0 = ENOENT (cache miss → schedule fill),
 * -1 = stat failure or non-regular type (S_ISREG rejects dirs/symlinks, errno set). */

int
brix_cache_file_ready(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        return (errno == ENOENT) ? 0 : -1;
    }

    if (!S_ISREG(st.st_mode)) {
        errno = S_ISDIR(st.st_mode) ? EISDIR : EINVAL;
        return -1;
    }

    return 1;
}

/* brix_cache_state_root — the directory the unified .cinfo persistence records
 * live under: the explicit brix_cache_state_root if set, else cache_root, else
 * NULL (no state tree ⇒ the persistent dirty record is skipped, in-memory only). */
const char *
brix_cache_state_root(const ngx_stream_brix_srv_conf_t *conf)
{
    if (conf == NULL) {
        return NULL;
    }
    if (conf->cache_state_root.len > 0) {
        return (const char *) conf->cache_state_root.data;
    }
    /* Tier grammar (§14a): the durable cache state + the evictable objects live in
     * the PHYSICAL cache STORE, never the advertised (logical) cache_root. The
     * authoritative location is the store instance's OWN local dir — ask the
     * resolved cstore, not the URL string, so this is driver-truthful for every
     * scheme. A non-local store (s3/rados/remote) returns NULL: the reaper/state
     * layer MUST then decline filesystem reaping (store-native eviction handles it)
     * rather than fall back to cache_root and reap the wrong tree. cache_root is the
     * physical root ONLY in the legacy (no-cache_store) config below. */
    if (conf->common.cache_store.len > 0) {
        return brix_cstore_local_root(brix_cache_storage_cstore(conf));
    }
    if (conf->cache_root.len > 0) {
        return (const char *) conf->cache_root.data;
    }
    return NULL;
}

/* brix_cache_state_path — map a resolved export path to the cache/state-tree
 * path whose ".cinfo" sidecar holds this file's unified persistence record. A
 * pure lexical re-root (export root_canon → the state root); same construction
 * used by mark_dirty / mark_clean / the reaper so they always agree. Returns
 * NGX_OK / NGX_ERROR (no state root, or overflow). */
ngx_int_t
brix_cache_state_path(const ngx_stream_brix_srv_conf_t *conf,
    const char *resolved, char *dst, size_t dstsz)
{
    const char *root = brix_cache_state_root(conf);

    if (root == NULL || conf->common.root_canon[0] == '\0') {
        errno = EINVAL;
        return NGX_ERROR;
    }
    return brix_cache_path_for_resolved(root, conf->common.root_canon,
                                          resolved, dst, dstsz);
}
