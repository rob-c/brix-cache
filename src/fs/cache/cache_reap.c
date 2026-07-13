/*
 * cache_reap.c — stale-dirty reaper. See cache_reap.h. Bounds abandoned
 * write-back staging the eviction guard would otherwise protect forever.
 */

#include "cache_reap.h"   /* + cache_internal.h: brix_cache_state_root */
#include "cinfo.h"
#include "cache_storage.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* A sidecar / slice file we drive off the data file rather than treat as one. */
static int
reap_is_sidecar(const char *name)
{
    const char *dot = strrchr(name, '.');

    if (dot != NULL && (strcmp(dot, ".cinfo") == 0 || strcmp(dot, ".meta") == 0
                        || strcmp(dot, ".part") == 0 || strcmp(dot, ".lock") == 0))
    {
        return 1;
    }
    return strstr(name, ".__xrds") != NULL;   /* slice files + slice meta */
}

/* Remove a reaped data file's sidecars (best-effort). */
static void
reap_unlink_sidecars(const char *data_path)
{
    char sc[PATH_MAX];

    if (brix_cache_cinfo_path(sc, sizeof(sc), data_path) == 0) {
        (void) unlink(sc);
    }
    if (snprintf(sc, sizeof(sc), "%s.meta", data_path) < (int) sizeof(sc)) {
        (void) unlink(sc);
    }
}

/* The per-server shared-memory metrics slot for `conf`, or NULL when metrics are
 * unconfigured (so the reaper degrades cleanly with no counter). Mirrors the slot
 * resolution in connection/handler.c. */
static ngx_brix_srv_metrics_t *
reap_metrics_slot(const ngx_stream_brix_srv_conf_t *conf)
{
    ngx_brix_metrics_t *shm;

    if (conf == NULL || conf->metrics_slot < 0
        || conf->metrics_slot >= BRIX_METRICS_MAX_SERVERS
        || ngx_brix_shm_zone == NULL
        || ngx_brix_shm_zone->data == NULL
        || ngx_brix_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    shm = ngx_brix_shm_zone->data;
    return &shm->servers[conf->metrics_slot];
}

/*
 * WHAT:  Immutable, per-walk context threaded through the recursive reaper.
 * WHY:   Collapses reap_dir's fixed argument set (cutoff/device/log/metrics/
 *        store/data-root) into a single pointer so the recursive call and every
 *        extracted helper carry one param instead of seven — keeping each
 *        function within the ≤5-param budget without introducing globals.
 * HOW:   Populated once by brix_cache_reap_dirty from the resolved config and
 *        root stat, then passed by const pointer through the whole walk. `dir`
 *        stays a separate argument because it changes per recursion level.
 */
typedef struct {
    time_t                    cutoff;     /* aged-out boundary (now - max_age) */
    dev_t                     dev;        /* root device — never cross it      */
    ngx_log_t                *log;        /* reap-event log sink               */
    ngx_brix_srv_metrics_t   *slot;       /* SHM metrics slot (may be NULL)    */
    brix_cstore_t            *cstore;     /* data-removal adapter (may be NULL)*/
    const char               *data_root;  /* cstore key prefix (may be NULL)   */
} reap_ctx_t;

/*
 * WHAT:  Decide whether a directory entry names a candidate regular file, and
 *        when so return its full path in `child` (a PATH_MAX buffer).
 * WHY:   Isolates the same-device, dot-skip, sidecar-skip, path-build and type
 *        gating from the classification/removal logic so each stays single-job.
 * HOW:   Skips "."/".."/sidecars, builds `dir/name` (skips on truncation),
 *        lstats it, and rejects anything off the root device. Directories are
 *        signalled to the caller (which recurses); non-regular files are
 *        skipped. Returns 1 when `child` describes a regular candidate,
 *        0 to skip this entry, and sets *is_dir when a same-device subdir.
 */
static int
reap_entry_candidate(const char *dir, const struct dirent *de,
    const reap_ctx_t *rc, char *child, int *is_dir)
{
    struct stat st;

    *is_dir = 0;

    if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
        return 0;
    }
    if (reap_is_sidecar(de->d_name)) {
        return 0;
    }
    if (snprintf(child, PATH_MAX, "%s/%s", dir, de->d_name) >= PATH_MAX) {
        return 0;
    }
    if (lstat(child, &st) != 0 || st.st_dev != rc->dev) {
        return 0;
    }
    if (S_ISDIR(st.st_mode)) {
        *is_dir = 1;
        return 0;
    }
    return S_ISREG(st.st_mode) ? 1 : 0;
}

/*
 * WHAT:  Classify WHY a tracked regular file is reapable (or that it is not).
 * WHY:   Concentrates the aged-dirty vs finished-write-back decision — the
 *        behaviour-critical eviction policy — in one place off the walk loop.
 * HOW:   Reads the cinfo state; keeps untracked files. Dirty data reaps only
 *        once aged past cutoff (incomplete when a flush was started, abandoned
 *        otherwise). Clean-but-flushed staging copies reap once the last flush
 *        ages out (COMPLETED). Clean read-fills are left for occupancy-driven
 *        eviction. Returns 1 with *reason set when reapable, else 0.
 */
static int
reap_classify(const char *child, const reap_ctx_t *rc,
    brix_cache_cinfo_state_t *cs, brix_cache_reap_reason_t *reason)
{
    if (brix_cache_cinfo_state(child, cs) != NGX_OK) {
        return 0;                           /* no record → keep (untracked file) */
    }

    if (cs->is_dirty) {
        /* Un-flushed data: reap only once it has aged past the max-age. */
        if (cs->dirty_since == 0 || (time_t) cs->dirty_since > rc->cutoff) {
            return 0;                       /* dirty but not yet aged → keep */
        }
        *reason = (cs->flush_gen > 0) ? BRIX_CACHE_REAP_INCOMPLETE
                                      : BRIX_CACHE_REAP_ABANDONED;
        return 1;
    }
    if (cs->flush_gen > 0) {
        /* Clean AND written back at least once: a finished write-back staging
         * copy whose bytes are safely on the origin. Reclaim it once the last
         * flush has aged out. A read-through fill (flush_gen==0, clean) has no
         * write-back to reclaim and is left for occupancy-driven eviction. */
        if (cs->last_flush == 0 || (time_t) cs->last_flush > rc->cutoff) {
            return 0;                       /* completed but not yet aged → keep */
        }
        *reason = BRIX_CACHE_REAP_COMPLETED;
        return 1;
    }
    return 0;                               /* clean read-fill → keep (evictable) */
}

/*
 * WHAT:  Remove one classified-reapable file (data + sidecars), bump the
 *        metric, and log the reap event.
 * WHY:   Keeps the destructive edge (unlink/evict + counter + log) in a single
 *        helper so the walk loop reads as pure control flow.
 * HOW:   Removes the DATA through the cstore adapter (phase-64 P3/G5: the policy
 *        layer never unlinks via the store driver itself); cstore_evict also
 *        drops the object's cinfo + L1 entry. The .meta sidecar is the legacy
 *        stats plane the cstore does not own, dropped by reap_unlink_sidecars.
 *        For the default co-located cache the state root IS the data root, so
 *        the key is child minus data_root; a file outside the data root is
 *        state-only (raw unlink). Then bumps slot->cache_dirty_reaped[reason]
 *        (slot may be NULL) and logs completed vs stale-dirty distinctly.
 */
static void
reap_remove(const char *child, const reap_ctx_t *rc,
    const brix_cache_cinfo_state_t *cs, brix_cache_reap_reason_t reason)
{
    if (rc->cstore != NULL && rc->data_root != NULL
        && ngx_strncmp(child, rc->data_root, ngx_strlen(rc->data_root)) == 0)
    {
        (void) brix_cstore_evict(rc->cstore, child + ngx_strlen(rc->data_root));
    } else {
        (void) unlink(child);
    }
    reap_unlink_sidecars(child);

    if (rc->slot != NULL) {
        (void) ngx_atomic_fetch_add(&rc->slot->cache_dirty_reaped[reason], 1);
    }
    if (reason == BRIX_CACHE_REAP_COMPLETED) {
        ngx_log_error(NGX_LOG_NOTICE, rc->log, 0,
            "brix: cache reaped completed write-back file "
            "(flushed, reclaimed): \"%s\"", child);
    } else {
        ngx_log_error(NGX_LOG_WARN, rc->log, 0,
            "brix: cache reaped stale-dirty file (reason=%s, %uL "
            "un-flushed bytes discarded): \"%s\"",
            reason == BRIX_CACHE_REAP_INCOMPLETE ? "incomplete"
                                                   : "abandoned",
            (unsigned long) (cs->dirty_hi - cs->dirty_lo), child);
    }
}

/*
 * WHAT:  Recursively scan `dir` (same device as root), reaping aged write-back
 *        files: aged-dirty data (abandoned/incomplete → discarded) and finished
 *        write-back staging copies (completed → reclaimed).
 * WHY:   The dirty-reaper's tree walk; bounds abandoned staging the eviction
 *        guard would otherwise protect forever.
 * HOW:   Per entry: reap_entry_candidate gates to a same-device regular file
 *        (recursing into same-device subdirs), reap_classify decides if/why it
 *        is reapable, reap_remove does the destructive work. Each reaped file
 *        bumps rc->slot->cache_dirty_reaped[reason] (slot may be NULL). Returns
 *        the count reaped in this subtree.
 */
static ngx_uint_t
reap_dir(const char *dir, const reap_ctx_t *rc)
{
    DIR           *dp;
    struct dirent *de;
    ngx_uint_t     n = 0;
    char           child[PATH_MAX];

    dp = opendir(dir);
    if (dp == NULL) {
        return 0;
    }

    while ((de = readdir(dp)) != NULL) {
        brix_cache_cinfo_state_t   cs;
        brix_cache_reap_reason_t   reason = BRIX_CACHE_REAP_ABANDONED;
        int                        is_dir = 0;

        if (!reap_entry_candidate(dir, de, rc, child, &is_dir)) {
            if (is_dir) {
                n += reap_dir(child, rc);
            }
            continue;
        }
        if (!reap_classify(child, rc, &cs, &reason)) {
            continue;
        }
        reap_remove(child, rc, &cs, reason);
        n++;
    }

    closedir(dp);
    return n;
}

ngx_uint_t
brix_cache_reap_dirty(const ngx_stream_brix_srv_conf_t *conf, ngx_log_t *log)
{
    const char *root;
    struct stat rs;
    reap_ctx_t  rc;

    if (conf == NULL || conf->cache_dirty_max_age == 0) {
        return 0;
    }
    root = brix_cache_state_root(conf);
    if (root == NULL || stat(root, &rs) != 0) {
        return 0;
    }

    /* Data removal routes through the cstore adapter (P3/G5); data_root is
     * cache_root (== the state root for the default co-located cache). The state
     * tree is still walked raw above — it is the POSIX state plane (.cinfo state
     * records), not the store's data objects, so it is not a store-driver touch. */
    ngx_memzero(&rc, sizeof(rc));
    rc.cutoff    = time(NULL) - conf->cache_dirty_max_age;
    rc.dev       = rs.st_dev;
    rc.log       = log;
    rc.slot      = reap_metrics_slot(conf);
    rc.cstore    = brix_cache_storage_cstore(conf);
    rc.data_root = (const char *) conf->cache_root.data;

    return reap_dir(root, &rc);
}
