#include "evict_internal.h"
#include "meta.h"


static ngx_int_t
xrootd_cache_evict_one(xrootd_cache_fill_t *t,
    xrootd_cache_evict_list_t *list, size_t idx, ngx_log_t *log,
    xrootd_cache_fs_usage_t *usage, ngx_uint_t *evicted_files,
    uint64_t *evicted_bytes)
{
    if (unlink(list->elts[idx].path) != 0) {
        if (errno != ENOENT) {
            ngx_log_error(NGX_LOG_WARN, log, errno,
                          "xrootd: cache eviction unlink failed \"%s\"",
                          list->elts[idx].path);
            xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        }

        return NGX_OK;
    }

    {
        char meta_path[PATH_MAX];

        if (xrootd_cache_meta_path(meta_path, sizeof(meta_path),
                                   list->elts[idx].path) == 0)
        {
            (void) unlink(meta_path);
        }
    }

    list->evicted[idx] = 1;
    (*evicted_files)++;
    if (list->elts[idx].size > 0) {
        *evicted_bytes += (uint64_t) list->elts[idx].size;
    }

    if (t->conf->manager_mode && t->c != NULL
        && t->c->local_sockaddr != NULL)
    {
        const char *fs_path   = list->elts[idx].path;
        const char *root      = (const char *) t->conf->cache_root.data;
        size_t      root_len  = t->conf->cache_root.len;

        if (ngx_strncmp(fs_path, root, root_len) == 0
            && fs_path[root_len] == '/')
        {
            u_char   addr_buf[NGX_SOCKADDR_STRLEN];
            size_t   addr_len;
            uint16_t self_port;

            addr_len = ngx_sock_ntop(t->c->local_sockaddr,
                                     t->c->local_socklen,
                                     addr_buf, sizeof(addr_buf) - 1, 0);
            addr_buf[addr_len] = '\0';
            self_port = 0;
            if (t->c->local_sockaddr->sa_family == AF_INET) {
                self_port = ntohs(
                    ((struct sockaddr_in *) t->c->local_sockaddr)->sin_port);
            } else if (t->c->local_sockaddr->sa_family == AF_INET6) {
                self_port = ntohs(
                    ((struct sockaddr_in6 *) t->c->local_sockaddr)->sin6_port);
            }
            xrootd_srv_unregister_path((const char *) addr_buf, self_port,
                                       fs_path + root_len);
        }
    }

    if (xrootd_cache_fs_usage((char *) t->conf->cache_root.data, usage)
        != NGX_OK)
    {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * xrootd_cache_evict_if_needed — evict cached files when the filesystem
 * occupancy exceeds the configured threshold.
 *
 * Called from the cache-fill thread after each completed download.  The
 * function is a no-op if the cache is not enabled or the threshold is 0.
 *
 * Eviction strategy (two-pass LRU):
 *   Pass 1 (optional): evict files larger than cache_max_file_size, oldest
 *     first.  Large cold files free the most space fastest.
 *   Pass 2: evict any remaining files oldest-atime-first until the filesystem
 *     occupancy drops below the threshold.
 *
 * protect_path is the file currently being filled (if any) — it is not
 * a candidate for eviction even if it is the oldest file.
 *
 * The occupancy_ppm threshold is checked twice: once before acquiring the
 * lock and once after, to avoid unnecessary lock contention when multiple
 * workers race to evict.
 *
 * Thread safety: this function runs in a thread-pool thread, not the nginx
 *   event loop.  All filesystem operations are safe to call there.  The
 *   metrics increments use ngx_atomic_fetch_add() which is thread-safe.
 */
void
xrootd_cache_evict_if_needed(xrootd_cache_fill_t *t, const char *protect_path,
    ngx_log_t *log)
{
    xrootd_cache_fs_usage_t      usage;
    xrootd_cache_evict_list_t    list;
    struct stat                  root_st;
    char                         lock_path[PATH_MAX];
    ngx_uint_t                   threshold;
    size_t                       i;
    ngx_uint_t                   evicted_files;
    uint64_t                     evicted_bytes;
    ngx_int_t                    evict_rc;

    if (t == NULL || t->conf == NULL || !t->conf->cache) {
        return;
    }

    threshold = t->conf->cache_eviction_threshold;
    if (threshold == 0 || threshold >= 1000000) {
        return;
    }

    if (xrootd_cache_fs_usage((char *) t->conf->cache_root.data, &usage)
        != NGX_OK)
    {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        return;
    }

    if (usage.occupancy_ppm <= threshold) {
        return;
    }

    ngx_memzero(lock_path, sizeof(lock_path));
    if (xrootd_cache_try_evict_lock(t->conf, lock_path, sizeof(lock_path),
                                    log) != NGX_OK)
    {
        return;
    }

    if (xrootd_cache_fs_usage((char *) t->conf->cache_root.data, &usage)
        != NGX_OK)
    {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        xrootd_cache_evict_unlock(lock_path);
        return;
    }

    if (usage.occupancy_ppm <= threshold) {
        xrootd_cache_evict_unlock(lock_path);
        return;
    }

    if (stat((char *) t->conf->cache_root.data, &root_st) != 0) {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        xrootd_cache_evict_unlock(lock_path);
        return;
    }

    ngx_memzero(&list, sizeof(list));
    list.root_dev = root_st.st_dev;
    list.protect_path = protect_path;

    if (xrootd_cache_collect_dir(&list, (char *) t->conf->cache_root.data,
                                 log) != NGX_OK)
    {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
    }

    if (list.nelts > 1) {
        qsort(list.elts, list.nelts, sizeof(list.elts[0]),
              xrootd_cache_candidate_cmp);
    }

    evicted_files = 0;
    evicted_bytes = 0;
    evict_rc = NGX_OK;

/*
 * Two-pass eviction:
 *   Pass 1 — evict files above cache_max_file_size first (oldest first).
 *             Large files are usually not worth keeping after they've grown
 *             cold; evicting them first frees the most space fastest.
 *   Pass 2 — evict any remaining files oldest first until we drop below
 *             the occupancy threshold.
 *
 * When cache_max_file_size is 0 (no size limit), pass 1 is skipped and
 * pass 2 degrades to the original single-pass LRU behaviour.
 */

    /* Pass 1: large files only (size > cache_max_file_size), oldest first */
    if (t->conf->cache_max_file_size > 0) {
        for (i = 0; i < list.nelts && usage.occupancy_ppm > threshold
             && evict_rc == NGX_OK; i++)
        {
            if (list.elts[i].size <= t->conf->cache_max_file_size) {
                continue;
            }
            evict_rc = xrootd_cache_evict_one(t, &list, i, log, &usage,
                                              &evicted_files, &evicted_bytes);
        }
    }

    /* Pass 2: remaining files (or all files if no size limit), oldest first */
    for (i = 0; i < list.nelts && usage.occupancy_ppm > threshold
         && evict_rc == NGX_OK; i++)
    {
        if (list.evicted[i]) {
            continue;
        }
        evict_rc = xrootd_cache_evict_one(t, &list, i, log, &usage,
                                          &evicted_files, &evicted_bytes);
    }

    if (evicted_files > 0) {
        xrootd_cache_metric_add(t->ctx, cache_evictions_total, evicted_files);
        xrootd_cache_metric_add(t->ctx, cache_evicted_bytes_total,
                                evicted_bytes);
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "xrootd: cache eviction removed %ui files, %uL bytes, "
                      "occupancy=0.%06ui threshold=0.%06ui",
                      evicted_files, (uint64_t) evicted_bytes,
                      usage.occupancy_ppm, threshold);
    }

    xrootd_cache_free_candidates(&list);
    xrootd_cache_evict_unlock(lock_path);
}
