#include "evict_internal.h"
#include "cache_storage.h"
#include "meta.h"

/*
 * evict_policy.c — cache eviction policy driver (two-pass LRU by occupancy).
 *
 * WHAT: Implements the eviction decision loop that keeps cache filesystem
 *       occupancy below cache_eviction_threshold. The public entry point
 *       xrootd_cache_evict_if_needed() and the per-file actor
 *       xrootd_cache_evict_one() live here; candidate collection, sorting, and
 *       free-space measurement are delegated to evict_candidates.c.
 *
 * WHY:  A read-through cache fills indefinitely as clients request new files.
 *       Without bounded occupancy the cache disk fills up and fills start
 *       failing. This file is the policy half of that pressure relief — what to
 *       remove and when — separated from the mechanics of scanning the tree.
 *
 * HOW:  Invoked from the cache-fill thread (thread.c) after each completed
 *       download. It double-checks occupancy (cheaply, then again after taking
 *       xrootd_cache_try_evict_lock to avoid worker races), collects the
 *       candidate set with xrootd_cache_collect_dir(), sorts oldest-first via
 *       xrootd_cache_candidate_cmp(), then evicts in two passes:
 *         Pass 1 — files larger than cache_max_file_size (skipped if 0).
 *         Pass 2 — everything else, oldest first.
 *       Each pass stops as soon as occupancy drops below the threshold. The
 *       protect_path (the file currently being filled) is never evicted.
 *       Runs in a thread-pool thread, not the event loop, so direct filesystem
 *       syscalls are permitted; metric updates use atomic adds.
 */

/*
 * xrootd_cache_evict_one — remove a single cache file and account for it.
 *
 * Unlinks list->elts[idx].path (and its sidecar meta file via
 * xrootd_cache_meta_path), marks the slot evicted, and accumulates the
 * evicted_files/evicted_bytes counters. In manager_mode it also unregisters
 * the freed path from the server registry so the manager stops advertising it.
 * Refreshes *usage with xrootd_cache_fs_usage() so the caller's threshold loop
 * sees the new occupancy. A missing file (ENOENT) is treated as already gone
 * (NGX_OK); other unlink errors bump cache_eviction_errors_total but still
 * return NGX_OK so eviction continues. Returns NGX_ERROR only if the post-unlink
 * usage re-measurement fails.
 */
static ngx_int_t
xrootd_cache_evict_one(ngx_stream_xrootd_srv_conf_t *conf, xrootd_ctx_t *ctx,
    ngx_connection_t *c, xrootd_cache_evict_list_t *list, size_t idx,
    ngx_log_t *log, xrootd_cache_fs_usage_t *usage, ngx_uint_t *evicted_files,
    uint64_t *evicted_bytes)
{
    {
        xrootd_cstore_t *cs  = (xrootd_cstore_t *) list->cstore;
        const char      *key = list->elts[idx].path
                               + ngx_strlen(list->cache_root);

        /* Remove the object + its cinfo record + L1 entry through the cstore
         * adapter — the policy layer never unlinks via the store driver itself
         * (phase-64 P3/G5). cstore_evict is best-effort (returns NGX_OK even on a
         * failed unlink), so eviction continues; the .meta sidecar below is the
         * legacy stats record the cstore does not own and is dropped separately. */
        (void) xrootd_cstore_evict(cs, key);
    }

    /* Remove the .meta/.cinfo sidecars (POSIX) at the state path (== the cache
     * path for a co-located cache). The .cinfo unlink is redundant with
     * cstore_evict for a co-located store but still covers a separate state_root. */
    {
        char sidecar[PATH_MAX];
        char meta_path[PATH_MAX];
        const char *base = list->elts[idx].path;

        if (xrootd_cache_sidecar_path(list->cache_root, list->state_root,
                                      list->elts[idx].path, sidecar,
                                      sizeof(sidecar)) == 0)
        {
            base = sidecar;
        }
        if (xrootd_cache_meta_path(meta_path, sizeof(meta_path), base) == 0) {
            (void) unlink(meta_path);
        }
        if (snprintf(meta_path, sizeof(meta_path), "%s.cinfo", base)
            < (int) sizeof(meta_path))
        {
            (void) unlink(meta_path);
        }
    }

    list->evicted[idx] = 1;
    (*evicted_files)++;
    if (list->elts[idx].size > 0) {
        *evicted_bytes += (uint64_t) list->elts[idx].size;
    }

    if (conf->manager_mode && c != NULL
        && c->local_sockaddr != NULL)
    {
        const char *fs_path   = list->elts[idx].path;
        const char *root      = (const char *) conf->cache_root.data;
        size_t      root_len  = conf->cache_root.len;

        if (ngx_strncmp(fs_path, root, root_len) == 0
            && fs_path[root_len] == '/')
        {
            u_char   addr_buf[NGX_SOCKADDR_STRLEN];
            size_t   addr_len;
            uint16_t self_port;

            addr_len = ngx_sock_ntop(c->local_sockaddr,
                                     c->local_socklen,
                                     addr_buf, sizeof(addr_buf) - 1, 0);
            addr_buf[addr_len] = '\0';
            self_port = 0;
            if (c->local_sockaddr->sa_family == AF_INET) {
                self_port = ntohs(
                    ((struct sockaddr_in *) c->local_sockaddr)->sin_port);
            } else if (c->local_sockaddr->sa_family == AF_INET6) {
                self_port = ntohs(
                    ((struct sockaddr_in6 *) c->local_sockaddr)->sin6_port);
            }
            xrootd_srv_unregister_path((const char *) addr_buf, self_port,
                                       fs_path + root_len);
        }
    }

    if (xrootd_cache_usage_measure((xrootd_cstore_t *) list->cstore,
            (char *) conf->cache_root.data, usage) != NGX_OK)
    {
        xrootd_cache_metric_add(ctx, cache_eviction_errors_total, 1);
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
/*
 * xrootd_cache_purge_to_target — the eviction engine, decoupled from any fill
 * task so both the on-fill safety net and the background watermark reaper can
 * drive it. Collects the candidate set under cache_root, sorts oldest-first, and
 * evicts in two passes (large files first, then plain LRU) until occupancy drops
 * to `target_ppm` or the candidate set is exhausted. `ctx` (per-connection
 * metrics) and `c` (the manager socket for path-unregister) are OPTIONAL — the
 * timer passes NULL for both; the macro/branches are NULL-safe. The caller owns
 * the cross-worker eviction lock and the threshold pre-check. Writes the evicted
 * file/byte counts (when the out-pointers are non-NULL) and returns NGX_OK, or
 * NGX_ERROR if a usage re-measurement failed mid-purge (partial work is kept).
 */
ngx_int_t
xrootd_cache_purge_to_target(ngx_stream_xrootd_srv_conf_t *conf,
    xrootd_ctx_t *ctx, ngx_connection_t *c, const char *protect_path,
    ngx_uint_t target_ppm, ngx_log_t *log, ngx_uint_t *evicted_files_out,
    uint64_t *evicted_bytes_out)
{
    xrootd_cache_fs_usage_t   usage;
    xrootd_cache_evict_list_t list;
    struct stat               root_st;
    size_t                    i;
    ngx_uint_t                evicted_files = 0;
    uint64_t                  evicted_bytes = 0;
    ngx_int_t                 evict_rc = NGX_OK;

    if (evicted_files_out != NULL) { *evicted_files_out = 0; }
    if (evicted_bytes_out != NULL) { *evicted_bytes_out = 0; }

    if (xrootd_cache_usage_measure(xrootd_cache_storage_cstore(conf),
            (char *) conf->cache_root.data, &usage) != NGX_OK)
    {
        xrootd_cache_metric_add(ctx, cache_eviction_errors_total, 1);
        return NGX_ERROR;
    }
    if (usage.occupancy_ppm <= target_ppm) {
        return NGX_OK;                       /* already at/below target */
    }
    if (stat((char *) conf->cache_root.data, &root_st) != 0) {
        xrootd_cache_metric_add(ctx, cache_eviction_errors_total, 1);
        return NGX_ERROR;
    }

    ngx_memzero(&list, sizeof(list));
    list.root_dev = root_st.st_dev;
    list.protect_path = protect_path;
    list.inst = xrootd_cache_storage(conf);          /* store instance (removal)   */
    list.cstore = xrootd_cache_storage_cstore(conf); /* enumerate via the adapter  */
    list.cache_root = (const char *) conf->cache_root.data;
    list.state_root = conf->cache_state_root.len
                      ? (const char *) conf->cache_state_root.data
                      : (const char *) conf->cache_root.data;

    if (list.inst == NULL || list.cstore == NULL
        || xrootd_cache_collect_dir(&list, "/", log) != NGX_OK)
    {
        xrootd_cache_metric_add(ctx, cache_eviction_errors_total, 1);
    }

    if (list.nelts > 1) {
        qsort(list.elts, list.nelts, sizeof(list.elts[0]),
              xrootd_cache_candidate_cmp);
    }

    /*
     * Two-pass eviction:
     *   Pass 1 — files above cache_max_file_size first (oldest first): large
     *            cold files free the most space fastest.
     *   Pass 2 — remaining files oldest-first until occupancy ≤ target_ppm.
     * Pass 1 is skipped when cache_max_file_size is 0 (no size limit), so pass 2
     * degrades to plain single-pass LRU.
     */
    if (conf->cache_max_file_size > 0) {
        for (i = 0; i < list.nelts && usage.occupancy_ppm > target_ppm
             && evict_rc == NGX_OK; i++)
        {
            if (list.elts[i].size <= conf->cache_max_file_size) {
                continue;
            }
            evict_rc = xrootd_cache_evict_one(conf, ctx, c, &list, i, log,
                          &usage, &evicted_files, &evicted_bytes);
        }
    }

    for (i = 0; i < list.nelts && usage.occupancy_ppm > target_ppm
         && evict_rc == NGX_OK; i++)
    {
        if (list.evicted[i]) {
            continue;
        }
        evict_rc = xrootd_cache_evict_one(conf, ctx, c, &list, i, log,
                      &usage, &evicted_files, &evicted_bytes);
    }

    xrootd_cache_free_candidates(&list);

    if (evicted_files_out != NULL) { *evicted_files_out = evicted_files; }
    if (evicted_bytes_out != NULL) { *evicted_bytes_out = evicted_bytes; }
    return evict_rc;
}

/*
 * xrootd_cache_evict_if_needed — on-fill safety net: when cache_root occupancy
 * exceeds cache_eviction_threshold, take the cross-worker lock and purge back to
 * the threshold. Runs in the fill worker after each download; the proactive
 * watermark reaper (reap_watermark.c) handles the quiet-but-full case.
 */
void
xrootd_cache_evict_if_needed(xrootd_cache_fill_t *t, const char *protect_path,
    ngx_log_t *log)
{
    xrootd_cache_fs_usage_t usage;
    char                    lock_path[PATH_MAX];
    ngx_uint_t              threshold;
    ngx_uint_t              evicted_files = 0;
    uint64_t                evicted_bytes = 0;

    if (t == NULL || t->conf == NULL || !t->conf->cache) {
        return;
    }

    threshold = t->conf->cache_eviction_threshold;
    if (threshold == 0 || threshold >= 1000000) {
        return;
    }

    if (xrootd_cache_usage_measure(xrootd_cache_storage_cstore(t->conf),
            (char *) t->conf->cache_root.data, &usage) != NGX_OK)
    {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        return;
    }
    if (usage.occupancy_ppm <= threshold) {
        return;                              /* cheap pre-lock check */
    }

    ngx_memzero(lock_path, sizeof(lock_path));
    if (xrootd_cache_try_evict_lock(t->conf, lock_path, sizeof(lock_path),
                                    log) != NGX_OK)
    {
        return;
    }

    if (xrootd_cache_purge_to_target(t->conf, t->ctx, t->c, protect_path,
            threshold, log, &evicted_files, &evicted_bytes) == NGX_OK
        && evicted_files > 0)
    {
        xrootd_cache_metric_add(t->ctx, cache_evictions_total, evicted_files);
        xrootd_cache_metric_add(t->ctx, cache_evicted_bytes_total,
                                evicted_bytes);
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "xrootd: cache eviction (on-fill) removed %ui files, "
                      "%uL bytes, threshold=0.%06ui",
                      evicted_files, (uint64_t) evicted_bytes, threshold);
    }

    xrootd_cache_evict_unlock(lock_path);
}
