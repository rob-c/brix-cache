/*
 * sd_cache_policy.c — cache admission policy + per-repo fill accounting.
 *
 * Admission (prefix allow/deny + size cap), CVMFS per-repo metrics attribution,
 * and the stale-if-error serve decision.  Split out of sd_cache.c; the fill
 * spine and vtable ops call the externally-visible entry points via
 * sd_cache_policy.h.  sd_cache_has_prefix / sd_cache_is_cvmfs stay file-private.
 */

#include "sd_cache_policy.h"
#include "sd_cache.h"                           /* brix_sd_cache_source_instance */
#include "protocols/cvmfs/classify.h"          /* manifest-TTL classification */
#include "observability/metrics/metrics_macros.h"
#include "fs/backend/http/sd_http.h"           /* per-upstream fill attribution */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- admission filter (policy) -------------------------------------------- */

static int
sd_cache_has_prefix(const char *path, ngx_array_t *prefixes)
{
    ngx_str_t  *p;
    ngx_uint_t  i;

    if (prefixes == NULL) {
        return 0;
    }
    p = prefixes->elts;
    for (i = 0; i < prefixes->nelts; i++) {
        if (p[i].len > 0
            && ngx_strncmp(path, p[i].data, p[i].len) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/* Decide whether `path` (of `size` bytes, or -1 when not yet known) may be cached
 * under the policy: deny-prefix wins; a non-empty allow list must match; an
 * include regex must match; an over-size object is not cached. */
int
sd_cache_admit(const brix_cache_policy_t *pol, const char *path, off_t size)
{
    if (sd_cache_has_prefix(path, pol->deny_prefixes)) {
        return 0;
    }
    if (pol->allow_prefixes != NULL && pol->allow_prefixes->nelts > 0
        && !sd_cache_has_prefix(path, pol->allow_prefixes))
    {
        return 0;
    }
    if (pol->include_regex != NULL
        && regexec(pol->include_regex, path, 0, NULL, 0) != 0)
    {
        return 0;
    }
    if (size >= 0 && pol->max_file_size > 0 && size > pol->max_file_size) {
        return 0;
    }
    return 1;
}

/* 1 iff this cache instance carries the cvmfs personality (other exports'
 * fills must not feed the cvmfs metric family). */
static int
sd_cache_is_cvmfs(const sd_cache_inst_state *st)
{
    return st->policy.verify == BRIX_CACHE_VERIFY_CVMFS_CAS
        || st->policy.cvmfs_manifest_ttl > 0;
}

/* Per-fqrn SHM counters for `key`, or NULL (non-cvmfs export / no repo /
 * SHM unmapped). Runs on fill worker threads — the slot table is lock-free. */
ngx_brix_cvmfs_repo_metrics_t *
sd_cache_repo_metrics(const sd_cache_inst_state *st, const char *key)
{
    cvmfs_url_info_t info;

    if (!sd_cache_is_cvmfs(st) || key == NULL
        || cvmfs_classify_url(key, strlen(key), &info) != 0
        || info.repo == NULL)
    {
        return NULL;
    }
    return brix_cvmfs_repo_slot(info.repo, info.repo_len);
}

/* phase-68 T16: WAN-in byte accounting, gated on the cvmfs personality. */
void
sd_cache_note_origin_bytes(const sd_cache_inst_state *st, const char *key,
    off_t bytes)
{
    ngx_brix_cvmfs_repo_metrics_t *rm;

    if (bytes <= 0 || !sd_cache_is_cvmfs(st)) {
        return;
    }
    BRIX_CVMFS_METRIC_ADD(origin_bytes_total, (ngx_atomic_uint_t) bytes);
    rm = sd_cache_repo_metrics(st, key);
    if (rm != NULL) {
        BRIX_ATOMIC_ADD(&rm->origin_bytes_total, (ngx_atomic_uint_t) bytes);
    }
}

/* phase-68 T16: per-upstream (Stratum-1) fill attribution, gated on the cvmfs
 * personality. Resolves the http source instance beneath the cache source and
 * records this fill attempt against the "host:port" it answered from — the
 * RAL-vs-CERN view. `ok`/`bytes`/`dur_ms` describe the attempt; failover comes
 * from the http instance's last-read record. */
void
sd_cache_note_upstream(const sd_cache_inst_state *st, int ok, off_t bytes,
    long dur_ms)
{
    brix_sd_instance_t *h = st->source;
    char                  host[BRIX_CVMFS_UPSTREAM_NAME_MAX];
    int                   guard = 0;

    if (!sd_cache_is_cvmfs(st)) {
        return;
    }
    /* Descend the source chain to the http instance (usually src itself). */
    while (h != NULL && (h->driver == NULL || h->driver->name == NULL
                         || strcmp(h->driver->name, "http") != 0)
           && guard++ < 8)
    {
        h = brix_sd_cache_source_instance(h);
    }
    if (h == NULL || sd_http_last_origin(h, host, sizeof(host)) != 0) {
        return;
    }
    brix_cvmfs_upstream_record(host, ok, bytes, dur_ms,
                                 sd_http_last_was_failover(h));
}

/* Milliseconds elapsed since a CLOCK_MONOTONIC start, clamped non-negative. */
long
sd_cache_ms_since(const struct timespec *t0)
{
    struct timespec now;
    long            ms;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    ms = (now.tv_sec - t0->tv_sec) * 1000L
       + (now.tv_nsec - t0->tv_nsec) / 1000000L;
    return ms < 0 ? 0 : ms;
}

/* phase-68: 1 iff `key` is CVMFS MANIFEST-class (mutable signed metadata). */
int
sd_cache_is_manifest_key(const char *key)
{
    cvmfs_url_info_t info;

    return (key != NULL
            && cvmfs_classify_url(key, strlen(key), &info) == 0
            && info.cls == CVMFS_URL_MANIFEST);
}

/* phase-68 bounded stale-if-error: 1 iff an expired-but-COMPLETE cached copy
 * of `key` exists whose total age is inside the 10x-TTL window — the caller
 * absorbs the refill failure and the stale copy serves. Re-arms the entry's
 * expiry one TTL forward so the next origin retry happens a TTL from now
 * (not on every request); the 10x bound is keyed on filled_at, which re-arms
 * never touch. */
int
sd_cache_stale_serve_ok(sd_cache_inst_state *st, const char *key)
{
    brix_cache_cinfo_t  ci;
    time_t                now = time(NULL);
    time_t                ttl = st->policy.cvmfs_manifest_ttl;

    if (ttl <= 0) {
        return 0;
    }
    if (brix_cstore_cinfo_load(&st->cstore, key, &ci) != NGX_OK
        || (ci.flags & BRIX_CINFO_F_COMPLETE) == 0
        || brix_cache_cinfo_expired(&ci, now) != 1)
    {
        return 0;
    }
    if (ci.filled_at == 0
        || (uint64_t) now >= ci.filled_at + 10 * (uint64_t) ttl)
    {
        return 0;                       /* stale window exhausted: fail hard */
    }
    ngx_log_error(NGX_LOG_WARN, st->log, 0,
        "sd_cache: refill of \"%s\" failed; serving stale copy (%uL s past "
        "expiry)\n"
        "  cause: origin unreachable or fill error\n"
        "  fix:   check Stratum-1 reachability; stale serving stops at 10x "
        "manifest_ttl", key,
        (uint64_t) ((uint64_t) now - ci.expires_at));
    brix_cache_cinfo_set_expires(&ci, now + ttl);   /* next retry in one TTL */
    (void) brix_cstore_cinfo_store(&st->cstore, key, &ci);
    return 1;
}
