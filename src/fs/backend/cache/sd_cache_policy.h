#ifndef BRIX_FS_BACKEND_CACHE_SD_CACHE_POLICY_H
#define BRIX_FS_BACKEND_CACHE_SD_CACHE_POLICY_H

/*
 * sd_cache_policy.h — cache admission policy + per-repo fill accounting.
 *
 * The decisions and bookkeeping the read-through cache consults on every fill:
 * whether a path is admissible (prefix allow/deny + size cap), the CVMFS
 * per-repo metrics attribution, and the stale-if-error serve decision.  Split
 * out of sd_cache.c so the policy surface is reviewable independently of the
 * fill spine and the vtable adapters that call it.  Implemented in
 * sd_cache_policy.c.
 */

#include "sd_cache_internal.h"                 /* sd_cache_inst_state */
#include "observability/metrics/metrics.h"     /* ngx_brix_cvmfs_repo_metrics_t */

#include <time.h>                               /* struct timespec */

/* Admission: 1 if `path` (size `size`, -1 if unknown) may be cached. */
int  sd_cache_admit(const brix_cache_policy_t *pol, const char *path, off_t size);

/* CVMFS per-repo metrics slot for `key` (NULL if this export is not a repo). */
ngx_brix_cvmfs_repo_metrics_t *
     sd_cache_repo_metrics(const sd_cache_inst_state *st, const char *key);

/* Attribute origin/upstream fill bytes + outcome to the repo metrics. */
void sd_cache_note_origin_bytes(const sd_cache_inst_state *st, const char *key,
         off_t bytes);
void sd_cache_note_upstream(const sd_cache_inst_state *st, int ok, off_t bytes,
         long dur_ms);

/* Elapsed milliseconds since `t0` (CLOCK_MONOTONIC). */
long sd_cache_ms_since(const struct timespec *t0);

/* 1 if `key` names a CVMFS manifest/root object (TTL-stamped, not a data blob). */
int  sd_cache_is_manifest_key(const char *key);

/* 1 if a cached-but-stale object for `key` may be served (stale-if-error). */
int  sd_cache_stale_serve_ok(sd_cache_inst_state *st, const char *key);

#endif /* BRIX_FS_BACKEND_CACHE_SD_CACHE_POLICY_H */
