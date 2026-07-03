#include "open.h"
#include "cache_internal.h"
#include "cache_storage.h"
#include "meta.h"

#include "fs/vfs/vfs_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/*
 * open.c — read-side cache hit path: serve a file from the local cache tree.
 *
 * WHAT: The VFS cache-open hook (brix_cache_open) plus its helpers: mapping a
 *       resolved export path to its cache-tree path (brix_cache_path_for_resolved),
 *       validating a hit against the origin (brix_cache_validate_meta), and
 *       bumping the access time for LRU (brix_cache_record_access).
 *
 * WHY:  When read-through caching is on, reads should be satisfied from the
 *       local cache whenever a complete, fresh copy exists, avoiding an origin
 *       round-trip. This file decides "is there a usable cache hit?" and, if so,
 *       adopts the open fd into the VFS layer.
 *
 * HOW:  brix_cache_open() declines (NGX_DECLINED) for anything that must not
 *       be served from cache — caching disabled, BRIX_VFS_O_NOCACHE, or any
 *       write/create/trunc/append intent — so callers fall back to the origin.
 *       Otherwise it derives the cache path under cache_root_canon, checks
 *       brix_cache_file_ready(), opens it O_RDONLY|O_NOFOLLOW|O_CLOEXEC, and
 *       confirms freshness via the meta sidecar (size + mtime) before handing
 *       the fd to brix_vfs_adopt_fd(). Confinement here is path-construction
 *       + O_NOFOLLOW rather than RESOLVE_BENEATH (the cache tree is a different
 *       directory from the export rootfd) — see the in-function comment.
 */

/*
 * brix_cache_path_for_resolved — map an export path to its cache-tree path.
 *
 * Strips root_canon from the resolved export path and re-roots the remaining
 * suffix under cache_root_canon, writing the result to out (NUL-terminated).
 * Rejects (NGX_ERROR) NULL/empty args, a resolved path not under root_canon, a
 * malformed suffix (EINVAL), or a result that would overflow out (ENAMETOOLONG).
 * Note: this is a pure lexical remap, not a confinement check.
 */
ngx_int_t
brix_cache_path_for_resolved(const char *cache_root_canon,
    const char *root_canon, const char *resolved, char *out, size_t outsz)
{
    size_t      cache_len;
    size_t      root_len;
    size_t      suffix_len;
    const char *suffix;

    if (cache_root_canon == NULL || root_canon == NULL || resolved == NULL
        || out == NULL || outsz == 0 || cache_root_canon[0] == '\0'
        || root_canon[0] == '\0' || resolved[0] == '\0')
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    root_len = strlen(root_canon);
    if (ngx_strncmp((u_char *) resolved, (u_char *) root_canon, root_len)
        != 0)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (root_len == 1 && root_canon[0] == '/') {
        suffix = (resolved[1] != '\0') ? resolved : "";
    } else {
        suffix = resolved + root_len;
    }
    if (suffix[0] != '\0' && suffix[0] != '/') {
        errno = EINVAL;
        return NGX_ERROR;
    }

    cache_len = strlen(cache_root_canon);
    suffix_len = strlen(suffix);
    if (cache_len == 1 && cache_root_canon[0] == '/' && suffix[0] == '/') {
        suffix++;
        suffix_len--;
    }
    if (cache_len + suffix_len >= outsz) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    ngx_memcpy(out, cache_root_canon, cache_len);
    ngx_memcpy(out + cache_len, suffix, suffix_len + 1);

    return NGX_OK;
}

/*
 * brix_cache_validate_meta — confirm a cache hit still matches the origin.
 *
 * Reads the sidecar meta for cache_path and compares its recorded size and
 * mtime against the live cache file stat (st). Returns NGX_OK if they agree,
 * NGX_DECLINED otherwise (no meta, or stale: errno set to ESTALE on mismatch),
 * so the caller falls back to the origin.
 */
static ngx_int_t
brix_cache_validate_meta(const char *cache_path, const struct stat *st,
    ngx_log_t *log)
{
    brix_cache_meta_t meta;

    if (brix_cache_meta_read(log, cache_path, &meta) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (meta.size != (uint64_t) st->st_size
        || meta.mtime != (uint64_t) st->st_mtime)
    {
        errno = ESTALE;
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/*
 * brix_cache_open — VFS cache-open hook: serve a read from the cache if able.
 *
 * Declines (NGX_DECLINED) when caching is disabled, BRIX_VFS_O_NOCACHE is
 * set, or any write/create/trunc/append flag is present, and on a cache miss,
 * not-ready file, or stale meta. On a validated hit it opens the cache file
 * read-only and adopts the fd via brix_vfs_adopt_fd(), returning *fh_out and
 * NGX_OK. Returns NGX_ERROR on hard I/O errors (errno set).
 */
ngx_int_t
brix_cache_open(brix_vfs_ctx_t *ctx, ngx_uint_t flags,
    brix_vfs_file_t **fh_out)
{
    char        cache_path[PATH_MAX];
    const char *resolved;
    struct stat st;
    ngx_int_t   rc;

    if (fh_out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    *fh_out = NULL;

    if (ctx == NULL || !ctx->cache_enabled
        || ctx->cache_root_canon == NULL || ctx->cache_root_canon[0] == '\0'
        || (flags & BRIX_VFS_O_NOCACHE)
        || (flags & (BRIX_VFS_O_WRITE | BRIX_VFS_O_CREATE
                     | BRIX_VFS_O_TRUNC | BRIX_VFS_O_APPEND)))
    {
        return NGX_DECLINED;
    }

    resolved = brix_vfs_ctx_path(ctx);
    if (brix_cache_path_for_resolved(ctx->cache_root_canon,
                                       ctx->root_canon, resolved,
                                       cache_path, sizeof(cache_path))
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    /*
     * Exclusively-VFS hit-serve: the cache file is opened through the cache
     * STORAGE driver (POSIX driver on the cache rootfd by default, or a configured
     * backend), keyed on the cache namespace. The driver owns confinement; for a
     * driver-backed cache the bytes live in the driver's namespace, not as a POSIX
     * file. The normal read path memory-serves when the backend cannot sendfile.
     */
    {
        brix_sd_instance_t *inst =
            brix_cache_storage_by_root(ctx->cache_root_canon);
        const char           *key;
        brix_sd_stat_t      sd_st;
        brix_sd_obj_t      *o;
        int                   e = 0;

        if (inst == NULL) {
            return NGX_DECLINED;          /* no cache storage on this root */
        }
        /* key = the suffix under cache_root (what the driver keys its namespace on). */
        key = cache_path + ngx_strlen(ctx->cache_root_canon);
        if (key[0] != '/') {
            return NGX_DECLINED;
        }

        if (inst->driver->stat(inst, key, &sd_st) != NGX_OK) {
            return (errno == ENOENT || errno == ENOTDIR) ? NGX_DECLINED
                                                         : NGX_ERROR;
        }
        if (!sd_st.is_reg) {
            return NGX_DECLINED;
        }

        /* Validate against the .meta sidecar (origin freshness) at the POSIX state
         * path (== cache_path for a co-located cache). Synthesize a struct stat
         * from the driver snapshot. */
        ngx_memzero(&st, sizeof(st));
        st.st_size  = sd_st.size;
        st.st_mtime = sd_st.mtime;
        st.st_mode  = S_IFREG;
        {
            const char *state_root =
                brix_cache_state_root_by_root(ctx->cache_root_canon);
            char        sidecar[PATH_MAX];

            if (state_root == NULL
                || brix_cache_sidecar_path(ctx->cache_root_canon, state_root,
                       cache_path, sidecar, sizeof(sidecar)) != 0
                || brix_cache_validate_meta(sidecar, &st, ctx->log) != NGX_OK)
            {
                return NGX_DECLINED;     /* obj not opened yet — nothing to close */
            }
        }

        o = inst->driver->open(inst, key, BRIX_SD_O_READ, 0, &e);
        if (o == NULL) {
            errno = e;
            return (e == ENOENT || e == ENOTDIR) ? NGX_DECLINED : NGX_ERROR;
        }

        rc = brix_vfs_adopt_obj(ctx, key, o, 0 /* read-only */, fh_out);
        if (rc != NGX_OK) {
            int err = errno;
            (void) inst->driver->close(o);
            if (o->heap_shell) {
                free(o);
            }
            errno = err;
        }
        return rc;
    }
}

/*
 * brix_cache_record_access — refresh a cache file's atime for LRU eviction.
 *
 * Touches cache_path's access time (atime only, via utimensat with UTIME_NOW /
 * UTIME_OMIT) so the eviction pass in evict_policy.c sees it as recently used.
 * The bytes argument is currently unused. Returns NGX_OK on success or where
 * UTIME_OMIT is unavailable, NGX_ERROR on bad args or a failed utimensat.
 */
ngx_int_t
brix_cache_record_access(const char *cache_path, size_t bytes,
    ngx_log_t *log)
{
    (void) bytes;

    if (cache_path == NULL || cache_path[0] == '\0') {
        errno = EINVAL;
        return NGX_ERROR;
    }

#if defined(UTIME_OMIT)
    {
        struct timespec ts[2];

        ts[0].tv_sec = 0;
        ts[0].tv_nsec = UTIME_NOW;
        ts[1].tv_sec = 0;
        ts[1].tv_nsec = UTIME_OMIT;

        if (utimensat(AT_FDCWD, cache_path, ts, 0) != 0) {
            if (log != NULL) {
                ngx_log_error(NGX_LOG_DEBUG, log, errno,
                              "brix: cache access timestamp update failed \"%s\"",
                              cache_path);
            }
            return NGX_ERROR;
        }
    }
#else
    (void) log;
#endif

    return NGX_OK;
}
