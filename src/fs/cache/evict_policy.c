#include "evict_internal.h"
#include "cache_storage.h"
#include "meta.h"

/*
 * evict_policy.c — cache eviction policy driver (two-pass LRU by occupancy).
 *
 * WHAT: Implements the eviction decision loop that keeps cache filesystem
 *       occupancy below cache_eviction_threshold. The public entry point
 *       brix_cache_evict_if_needed() and the per-file actor
 *       brix_cache_evict_one() live here; candidate collection, sorting, and
 *       free-space measurement are delegated to evict_candidates.c.
 *
 * WHY:  A read-through cache fills indefinitely as clients request new files.
 *       Without bounded occupancy the cache disk fills up and fills start
 *       failing. This file is the policy half of that pressure relief — what to
 *       remove and when — separated from the mechanics of scanning the tree.
 *
 * HOW:  Invoked from the cache-fill thread (thread.c) after each completed
 *       download. It double-checks occupancy (cheaply, then again after taking
 *       brix_cache_try_evict_lock to avoid worker races), collects the
 *       candidate set with brix_cache_collect_dir(), sorts oldest-first via
 *       brix_cache_candidate_cmp(), then evicts in two passes:
 *         Pass 1 — files larger than cache_max_file_size (skipped if 0).
 *         Pass 2 — everything else, oldest first.
 *       Each pass stops as soon as occupancy drops below the threshold. The
 *       protect_path (the file currently being filled) is never evicted.
 *       Runs in a thread-pool thread, not the event loop, so direct filesystem
 *       syscalls are permitted; metric updates use atomic adds.
 */

/*
 * brix_cache_evict_ctx_t — the invariant context for a single purge pass.
 *
 * WHAT: Bundles the state that stays fixed while brix_cache_evict_one() walks
 *       the candidate list — the server conf, optional per-connection metrics
 *       ctx, optional manager socket, log, the candidate list, and the running
 *       occupancy/counters that each eviction updates.
 * WHY:  brix_cache_evict_one() otherwise needs nine positional arguments; a
 *       cohesive struct passed by pointer keeps the actor at ≤5 params and lets
 *       the two-pass driver share one initialised block instead of threading a
 *       long argument list through both loops.
 * HOW:  brix_cache_purge_to_target() zero-inits one on the stack, fills it once
 *       after the candidate set is built, then hands it to brix_cache_evict_one()
 *       per victim. `usage` is the live occupancy re-measured after each unlink;
 *       `evicted_files`/`evicted_bytes` accumulate across the whole purge.
 */
typedef struct {
    ngx_stream_brix_srv_conf_t *conf;
    brix_ctx_t                 *ctx;
    ngx_connection_t           *c;
    ngx_log_t                  *log;
    brix_cache_evict_list_t    *list;
    brix_cache_fs_usage_t      *usage;
    ngx_uint_t                  evicted_files;
    uint64_t                    evicted_bytes;
} brix_cache_evict_ctx_t;

/*
 * brix_cache_evict_remove_object — drop the cached object via the cstore adapter.
 *
 * WHAT: Removes the data object + its cinfo record + L1 entry for candidate
 *       idx through brix_cstore_evict(), keyed by the path suffix beneath
 *       cache_root.
 * WHY:  The policy layer never unlinks via the store driver itself
 *       (phase-64 P3/G5); it must go through the cstore adapter, which is
 *       best-effort (returns NGX_OK even on a failed unlink) so eviction
 *       continues regardless.
 * HOW:  Computes the store key (path minus the cache_root prefix) and calls the
 *       adapter. The .meta/.cinfo sidecars the cstore does not own are dropped
 *       separately by brix_cache_evict_remove_sidecars().
 */
static void
brix_cache_evict_remove_object(brix_cache_evict_list_t *list, size_t idx)
{
    brix_cstore_t *cs  = (brix_cstore_t *) list->cstore;
    const char    *key = list->elts[idx].path + ngx_strlen(list->cache_root);

    (void) brix_cstore_evict(cs, key);
}

/*
 * brix_cache_evict_remove_sidecars — unlink the legacy .meta/.cinfo sidecars.
 *
 * WHAT: Removes the .meta stats record and the .cinfo record (POSIX) sitting at
 *       the state path for candidate idx.
 * WHY:  The .meta sidecar is a legacy stats record the cstore does not own, and
 *       for a separate state_root the .cinfo is not covered by cstore_evict; both
 *       must be dropped here so no orphan sidecars accumulate.
 * HOW:  Resolves the state-path base (the sidecar path when it differs from the
 *       cache path, else the cache path itself), then best-effort unlinks
 *       <base>.meta and <base>.cinfo. Failures are ignored — the sidecars are
 *       advisory and the object is already gone.
 */
static void
brix_cache_evict_remove_sidecars(brix_cache_evict_list_t *list, size_t idx)
{
    char        sidecar[PATH_MAX];
    char        meta_path[PATH_MAX];
    const char *base = list->elts[idx].path;

    if (brix_cache_sidecar_path(list->cache_root, list->state_root,
                                  list->elts[idx].path, sidecar,
                                  sizeof(sidecar)) == 0)
    {
        base = sidecar;
    }
    if (brix_cache_meta_path(meta_path, sizeof(meta_path), base) == 0) {
        (void) unlink(meta_path);
    }
    if (snprintf(meta_path, sizeof(meta_path), "%s.cinfo", base)
        < (int) sizeof(meta_path))
    {
        (void) unlink(meta_path);
    }
}

/*
 * brix_cache_local_self_port — read the listening port off a manager socket.
 *
 * WHAT: Returns the host-order TCP port bound on c->local_sockaddr, or 0 for a
 *       non-IP family.
 * WHY:  brix_srv_unregister_path() advertises freed paths keyed by this node's
 *       own address:port; the port must be extracted from the family-specific
 *       sockaddr and byte-swapped to host order.
 * HOW:  Branches on sa_family and ntohs()es the matching sin_port / sin6_port.
 */
static uint16_t
brix_cache_local_self_port(ngx_connection_t *c)
{
    if (c->local_sockaddr->sa_family == AF_INET) {
        return ntohs(((struct sockaddr_in *) c->local_sockaddr)->sin_port);
    }
    if (c->local_sockaddr->sa_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *) c->local_sockaddr)->sin6_port);
    }
    return 0;
}

/*
 * brix_cache_evict_unregister — stop the manager advertising a freed path.
 *
 * WHAT: In manager_mode, unregisters candidate idx's namespace path from the
 *       server registry so the manager no longer advertises it as cached here.
 * WHY:  A manager node tracks which files each cache holds; once a file is
 *       evicted the manager must forget it or clients will be routed to a miss.
 * HOW:  No-op unless manager_mode and a usable local socket are present. Confirms
 *       the file lives under cache_root, derives this node's address:port, and
 *       calls brix_srv_unregister_path() with the namespace suffix.
 */
static void
brix_cache_evict_unregister(brix_cache_evict_ctx_t *ec, size_t idx)
{
    ngx_stream_brix_srv_conf_t *conf = ec->conf;
    ngx_connection_t           *c    = ec->c;
    const char                 *fs_path;
    const char                 *root;
    size_t                      root_len;
    u_char                      addr_buf[NGX_SOCKADDR_STRLEN];
    size_t                      addr_len;
    uint16_t                    self_port;

    if (!conf->manager_mode || c == NULL || c->local_sockaddr == NULL) {
        return;
    }

    fs_path  = ec->list->elts[idx].path;
    root     = (const char *) conf->cache_root.data;
    root_len = conf->cache_root.len;

    if (ngx_strncmp(fs_path, root, root_len) != 0 || fs_path[root_len] != '/') {
        return;
    }

    addr_len = ngx_sock_ntop(c->local_sockaddr, c->local_socklen,
                             addr_buf, sizeof(addr_buf) - 1, 0);
    addr_buf[addr_len] = '\0';
    self_port = brix_cache_local_self_port(c);

    brix_srv_unregister_path((const char *) addr_buf, self_port,
                               fs_path + root_len);
}

/*
 * brix_cache_evict_one — remove a single cache file and account for it.
 *
 * Unlinks ec->list->elts[idx].path (and its sidecar meta file via
 * brix_cache_meta_path), marks the slot evicted, and accumulates the
 * evicted_files/evicted_bytes counters on ec. In manager_mode it also
 * unregisters the freed path from the server registry so the manager stops
 * advertising it. Refreshes *ec->usage with brix_cache_usage_measure() so the
 * caller's threshold loop sees the new occupancy. A missing file (ENOENT) is
 * treated as already gone (cstore_evict is best-effort); unlink errors on the
 * sidecars are ignored so eviction continues. Returns NGX_ERROR only if the
 * post-unlink usage re-measurement fails.
 */
static ngx_int_t
brix_cache_evict_one(brix_cache_evict_ctx_t *ec, size_t idx)
{
    brix_cache_evict_list_t *list = ec->list;

    brix_cache_evict_remove_object(list, idx);
    brix_cache_evict_remove_sidecars(list, idx);

    list->evicted[idx] = 1;
    ec->evicted_files++;
    if (list->elts[idx].size > 0) {
        ec->evicted_bytes += (uint64_t) list->elts[idx].size;
    }

    brix_cache_evict_unregister(ec, idx);

    if (brix_cache_usage_measure((brix_cstore_t *) list->cstore,
            (char *) ec->conf->cache_root.data, ec->usage) != NGX_OK)
    {
        brix_cache_metric_add(ec->ctx, cache_eviction_errors_total, 1);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * brix_cache_purge_setup — measure occupancy and build the sorted candidate set.
 *
 * WHAT: Measures physical-root occupancy, checks it against target_ppm, and (if
 *       over target) initialises *list, walks the physical cache root for
 *       candidates, and sorts them oldest-first. Reports whether purging is
 *       needed via *proceed.
 * WHY:  Extracting the measure/stat/collect/sort preamble keeps the driver
 *       brix_cache_purge_to_target() under the complexity cap while preserving
 *       the exact same short-circuits and candidate ordering.
 * HOW:  §14a device-scopes the PHYSICAL cache root (a pure tier cache advertises
 *       cache_root "/", whose device differs from the store dir). On any hard
 *       failure it bumps cache_eviction_errors_total and returns NGX_ERROR with
 *       *proceed=0. When occupancy is already ≤ target it returns NGX_OK with
 *       *proceed=0. Otherwise it fills ec->list / ec->usage and qsorts, returning
 *       NGX_OK with *proceed=1. Candidate-collection failure is (as before)
 *       non-fatal — the error counter bumps but the partial list is still purged.
 *       Reads conf/ctx/log/list/usage off the pre-initialised ec.
 */
static ngx_int_t
brix_cache_purge_setup(brix_cache_evict_ctx_t *ec, const char *protect_path,
    ngx_uint_t target_ppm, int *proceed)
{
    ngx_stream_brix_srv_conf_t *conf  = ec->conf;
    brix_ctx_t                 *ctx   = ec->ctx;
    ngx_log_t                  *log   = ec->log;
    brix_cache_fs_usage_t      *usage = ec->usage;
    brix_cache_evict_list_t    *list  = ec->list;
    struct stat                 root_st;
    const char                 *phys_root;

    *proceed = 0;

    /* §14a: measure + device-scope the PHYSICAL cache root (tier-aware). A pure
     * tier cache advertises cache_root "/", whose device differs from the store
     * dir — using it for root_dev would make the same-device candidate filter
     * drop every object. */
    phys_root = brix_cache_state_root(conf);
    if (phys_root == NULL) {
        brix_cache_metric_add(ctx, cache_eviction_errors_total, 1);
        return NGX_ERROR;
    }
    if (brix_cache_usage_measure(brix_cache_storage_cstore(conf),
            phys_root, usage) != NGX_OK)
    {
        brix_cache_metric_add(ctx, cache_eviction_errors_total, 1);
        return NGX_ERROR;
    }
    if (usage->occupancy_ppm <= target_ppm) {
        return NGX_OK;                       /* already at/below target */
    }
    if (stat(phys_root, &root_st) != 0) {
        brix_cache_metric_add(ctx, cache_eviction_errors_total, 1);
        return NGX_ERROR;
    }

    ngx_memzero(list, sizeof(*list));
    list->root_dev = root_st.st_dev;
    list->protect_path = protect_path;
    list->inst = brix_cache_storage(conf);          /* store instance (removal) */
    list->cstore = brix_cache_storage_cstore(conf); /* enumerate via the adapter */
    /* §14a: walk the PHYSICAL cache root (tier-aware — the posix cache_store dir
     * for the tier grammar, else cache_state_root/cache_root), so a pure tier
     * cache (advertised cache_root "/") still evicts from the real store dir. */
    list->cache_root = phys_root;
    list->state_root = phys_root;

    if (list->inst == NULL || list->cstore == NULL
        || brix_cache_collect_dir(list, "/", log) != NGX_OK)
    {
        brix_cache_metric_add(ctx, cache_eviction_errors_total, 1);
    }

    if (list->nelts > 1) {
        qsort(list->elts, list->nelts, sizeof(list->elts[0]),
              brix_cache_candidate_cmp);
    }

    *proceed = 1;
    return NGX_OK;
}

/*
 * brix_cache_purge_large_pass — pass 1: evict oversize files, oldest first.
 *
 * WHAT: Evicts candidates larger than cache_max_file_size (oldest first) until
 *       occupancy drops to target_ppm or an eviction fails.
 * WHY:  Large cold files free the most space fastest; this pass is skipped when
 *       cache_max_file_size is 0 (no size limit) so pass 2 degrades to plain LRU.
 * HOW:  Walks the sorted list, skipping under-limit files, calling
 *       brix_cache_evict_one() on each oversize victim. Returns the first
 *       non-NGX_OK rc (mid-purge usage re-measurement failure) or NGX_OK.
 */
static ngx_int_t
brix_cache_purge_large_pass(brix_cache_evict_ctx_t *ec, ngx_uint_t target_ppm)
{
    brix_cache_evict_list_t *list = ec->list;
    ngx_int_t                rc   = NGX_OK;
    size_t                   i;

    if (ec->conf->cache_max_file_size == 0) {
        return NGX_OK;
    }

    for (i = 0; i < list->nelts && ec->usage->occupancy_ppm > target_ppm
         && rc == NGX_OK; i++)
    {
        if (list->elts[i].size <= ec->conf->cache_max_file_size) {
            continue;
        }
        rc = brix_cache_evict_one(ec, i);
    }
    return rc;
}

/*
 * brix_cache_purge_lru_pass — pass 2: evict remaining files oldest-first.
 *
 * WHAT: Evicts every not-yet-evicted candidate, oldest first, until occupancy
 *       drops to target_ppm or an eviction fails.
 * WHY:  This is the plain LRU relief pass that runs after the large-file pass
 *       (and is the sole pass when no size limit is configured).
 * HOW:  Walks the sorted list, skipping slots already evicted in pass 1, calling
 *       brix_cache_evict_one() on each. Returns the first non-NGX_OK rc or NGX_OK.
 */
static ngx_int_t
brix_cache_purge_lru_pass(brix_cache_evict_ctx_t *ec, ngx_uint_t target_ppm)
{
    brix_cache_evict_list_t *list = ec->list;
    ngx_int_t                rc   = NGX_OK;
    size_t                   i;

    for (i = 0; i < list->nelts && ec->usage->occupancy_ppm > target_ppm
         && rc == NGX_OK; i++)
    {
        if (list->evicted[i]) {
            continue;
        }
        rc = brix_cache_evict_one(ec, i);
    }
    return rc;
}

/*
 * brix_cache_evict_if_needed — evict cached files when the filesystem
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
 * brix_cache_purge_to_target — the eviction engine, decoupled from any fill
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
brix_cache_purge_to_target(ngx_stream_brix_srv_conf_t *conf,
    brix_ctx_t *ctx, ngx_connection_t *c, const char *protect_path,
    ngx_uint_t target_ppm, ngx_log_t *log, ngx_uint_t *evicted_files_out,
    uint64_t *evicted_bytes_out)
{
    brix_cache_fs_usage_t   usage;
    brix_cache_evict_list_t list;
    brix_cache_evict_ctx_t  ec;
    ngx_int_t               setup_rc;
    ngx_int_t               evict_rc = NGX_OK;
    int                     proceed  = 0;

    if (evicted_files_out != NULL) { *evicted_files_out = 0; }
    if (evicted_bytes_out != NULL) { *evicted_bytes_out = 0; }

    ngx_memzero(&ec, sizeof(ec));
    ec.conf  = conf;
    ec.ctx   = ctx;
    ec.c     = c;
    ec.log   = log;
    ec.list  = &list;
    ec.usage = &usage;

    setup_rc = brix_cache_purge_setup(&ec, protect_path, target_ppm, &proceed);
    if (setup_rc != NGX_OK || !proceed) {
        return setup_rc;
    }

    /*
     * Two-pass eviction:
     *   Pass 1 — files above cache_max_file_size first (oldest first): large
     *            cold files free the most space fastest.
     *   Pass 2 — remaining files oldest-first until occupancy ≤ target_ppm.
     * Pass 1 is skipped when cache_max_file_size is 0 (no size limit), so pass 2
     * degrades to plain single-pass LRU.
     */
    evict_rc = brix_cache_purge_large_pass(&ec, target_ppm);
    if (evict_rc == NGX_OK) {
        evict_rc = brix_cache_purge_lru_pass(&ec, target_ppm);
    }

    brix_cache_free_candidates(&list);

    if (evicted_files_out != NULL) { *evicted_files_out = ec.evicted_files; }
    if (evicted_bytes_out != NULL) { *evicted_bytes_out = ec.evicted_bytes; }
    return evict_rc;
}

/*
 * brix_cache_evict_if_needed — on-fill safety net: when cache_root occupancy
 * exceeds cache_eviction_threshold, take the cross-worker lock and purge back to
 * the threshold. Runs in the fill worker after each download; the proactive
 * watermark reaper (reap_watermark.c) handles the quiet-but-full case.
 */
void
brix_cache_evict_if_needed(brix_cache_fill_t *t, const char *protect_path,
    ngx_log_t *log)
{
    brix_cache_fs_usage_t usage;
    char                    lock_path[PATH_MAX];
    ngx_uint_t              threshold;
    ngx_uint_t              evicted_files = 0;
    uint64_t                evicted_bytes = 0;

    if (t == NULL || t->conf == NULL || !t->conf->cache) {
        return;
    }

    threshold = t->conf->cache_eviction_threshold;
    if (threshold == 0 || threshold >= BRIX_CACHE_PPM_FULL_SCALE) {
        return;
    }

    if (brix_cache_usage_measure(brix_cache_storage_cstore(t->conf),
            (char *) t->conf->cache_root.data, &usage) != NGX_OK)
    {
        brix_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        return;
    }
    if (usage.occupancy_ppm <= threshold) {
        return;                              /* cheap pre-lock check */
    }

    ngx_memzero(lock_path, sizeof(lock_path));
    if (brix_cache_try_evict_lock(t->conf, lock_path, sizeof(lock_path),
                                    log) != NGX_OK)
    {
        return;
    }

    if (brix_cache_purge_to_target(t->conf, t->ctx, t->c, protect_path,
            threshold, log, &evicted_files, &evicted_bytes) == NGX_OK
        && evicted_files > 0)
    {
        brix_cache_metric_add(t->ctx, cache_evictions_total, evicted_files);
        brix_cache_metric_add(t->ctx, cache_evicted_bytes_total,
                                evicted_bytes);
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "brix: cache eviction (on-fill) removed %ui files, "
                      "%uL bytes, threshold=0.%06ui",
                      evicted_files, (uint64_t) evicted_bytes, threshold);
    }

    brix_cache_evict_unlock(lock_path);
}
