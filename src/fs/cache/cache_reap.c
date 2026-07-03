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

/* Recursively scan `dir` (same device as root), reaping aged write-back files:
 * aged-dirty data (abandoned/incomplete → discarded) and finished write-back
 * staging copies (completed → reclaimed). Each reaped file bumps the matching
 * slot->cache_dirty_reaped[reason] (slot may be NULL). */
static ngx_uint_t
reap_dir(const char *dir, time_t cutoff, dev_t dev, ngx_log_t *log,
    ngx_brix_srv_metrics_t *slot, brix_cstore_t *cstore,
    const char *data_root)
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
        struct stat                 st;
        brix_cache_cinfo_state_t  cs;
        brix_cache_reap_reason_t  reason;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        if (reap_is_sidecar(de->d_name)) {
            continue;
        }
        if (snprintf(child, sizeof(child), "%s/%s", dir, de->d_name)
            >= (int) sizeof(child))
        {
            continue;
        }
        if (lstat(child, &st) != 0 || st.st_dev != dev) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            n += reap_dir(child, cutoff, dev, log, slot, cstore, data_root);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        if (brix_cache_cinfo_state(child, &cs) != NGX_OK) {
            continue;                       /* no record → keep (untracked file) */
        }

        /* Classify WHY this file is reapable (see brix_cache_reap_reason_t). */
        if (cs.is_dirty) {
            /* Un-flushed data: reap only once it has aged past the max-age. */
            if (cs.dirty_since == 0 || (time_t) cs.dirty_since > cutoff) {
                continue;                   /* dirty but not yet aged → keep */
            }
            reason = (cs.flush_gen > 0) ? BRIX_CACHE_REAP_INCOMPLETE
                                        : BRIX_CACHE_REAP_ABANDONED;
        } else if (cs.flush_gen > 0) {
            /* Clean AND written back at least once: a finished write-back staging
             * copy whose bytes are safely on the origin. Reclaim it once the last
             * flush has aged out. A read-through fill (flush_gen==0, clean) has no
             * write-back to reclaim and is left for occupancy-driven eviction. */
            if (cs.last_flush == 0 || (time_t) cs.last_flush > cutoff) {
                continue;                   /* completed but not yet aged → keep */
            }
            reason = BRIX_CACHE_REAP_COMPLETED;
        } else {
            continue;                       /* clean read-fill → keep (evictable) */
        }

        /* Remove the DATA through the cstore adapter (phase-64 P3/G5: the policy
         * layer never unlinks via the store driver itself); cstore_evict also drops
         * the object's cinfo + L1 entry. The .meta sidecar is the legacy stats plane
         * the cstore does not own, dropped by reap_unlink_sidecars. For the default
         * co-located cache the state root IS the data root, so the key is child
         * minus data_root; a file outside the data root is state-only (raw unlink). */
        if (cstore != NULL && data_root != NULL
            && ngx_strncmp(child, data_root, ngx_strlen(data_root)) == 0)
        {
            (void) brix_cstore_evict(cstore, child + ngx_strlen(data_root));
        } else {
            (void) unlink(child);
        }
        reap_unlink_sidecars(child);
        if (slot != NULL) {
            (void) ngx_atomic_fetch_add(&slot->cache_dirty_reaped[reason], 1);
        }
        if (reason == BRIX_CACHE_REAP_COMPLETED) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "brix: cache reaped completed write-back file "
                "(flushed, reclaimed): \"%s\"", child);
        } else {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "brix: cache reaped stale-dirty file (reason=%s, %uL "
                "un-flushed bytes discarded): \"%s\"",
                reason == BRIX_CACHE_REAP_INCOMPLETE ? "incomplete"
                                                       : "abandoned",
                (unsigned long) (cs.dirty_hi - cs.dirty_lo), child);
        }
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
    time_t      now, cutoff;

    if (conf == NULL || conf->cache_dirty_max_age == 0) {
        return 0;
    }
    root = brix_cache_state_root(conf);
    if (root == NULL || stat(root, &rs) != 0) {
        return 0;
    }
    now = time(NULL);
    cutoff = now - conf->cache_dirty_max_age;
    /* Data removal routes through the cstore adapter (P3/G5); data_root is
     * cache_root (== the state root for the default co-located cache). The state
     * tree is still walked raw above — it is the POSIX state plane (.cinfo state
     * records), not the store's data objects, so it is not a store-driver touch. */
    return reap_dir(root, cutoff, rs.st_dev, log, reap_metrics_slot(conf),
                    brix_cache_storage_cstore(conf),
                    (const char *) conf->cache_root.data);
}
