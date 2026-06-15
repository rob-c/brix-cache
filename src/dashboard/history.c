#include "dashboard.h"
#include "../metrics/metrics.h"
#include "../compat/shm_slots.h"

#include <ngx_shmtx.h>

/*
 * dashboard/history.c — rolling time-series of activity for the dashboard charts.
 *
 * WHAT: Maintains the SHM-backed history ring (xrootd_dashboard_history_t) of
 *       XROOTD_DASHBOARD_HISTORY_BUCKETS fixed-width
 *       (XROOTD_DASHBOARD_HISTORY_INTERVAL_MS) buckets recording active transfer
 *       counts per protocol, cumulative bytes rx/tx, error and auth-failure
 *       totals.  xrootd_dashboard_history_sample() writes the current bucket;
 *       xrootd_dashboard_history_snapshot() returns the recent window in
 *       chronological order; ngx_xrootd_dashboard_history_shm_init() is the SHM
 *       zone init callback.
 * WHY:  The dashboard plots trends over time, which needs periodic point-in-time
 *       samples persisted across workers and reloads — hence shared memory and a
 *       bounded ring instead of per-worker state.  Sampling derives values from
 *       the existing dashboard transfer table and the metrics SHM zone rather
 *       than maintaining a parallel counter set, so the series cannot drift from
 *       the live numbers.
 * HOW:  Buckets are addressed by absolute time: index =
 *       (bucket_start_ms / INTERVAL_MS) % BUCKETS, with bucket_start_ms stored in
 *       each slot so a reader can tell a current bucket from a stale wrapped one.
 *       sample() snaps now_ms down to the interval boundary, zero-fills any
 *       buckets skipped since last_bucket_start_ms (idle gaps), then tallies
 *       active transfers from ngx_xrootd_dashboard_shm_zone and byte/error/auth
 *       totals from ngx_xrootd_shm_zone (per-server, WebDAV and S3).  A single
 *       static ngx_shmtx_t (re-created on reload) guards both sample and
 *       snapshot.  write_stalls and cache_occupancy_ppm are reserved/unpopulated.
 */

static ngx_shmtx_t xrootd_dashboard_history_mutex;

static xrootd_dashboard_history_t *
dashboard_history_table(void)
{
    if (ngx_xrootd_dashboard_history_shm_zone == NULL
        || ngx_xrootd_dashboard_history_shm_zone->data == NULL
        || ngx_xrootd_dashboard_history_shm_zone->data == (void *) 1)
    {
        return NULL;
    }

    return (xrootd_dashboard_history_t *)
           ngx_xrootd_dashboard_history_shm_zone->data;
}

static ngx_uint_t
dashboard_history_bucket_index(int64_t bucket_start_ms)
{
    return (ngx_uint_t)
        ((bucket_start_ms / XROOTD_DASHBOARD_HISTORY_INTERVAL_MS)
         % XROOTD_DASHBOARD_HISTORY_BUCKETS);
}

ngx_int_t
ngx_xrootd_dashboard_history_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t                  fresh;
    xrootd_dashboard_history_t *hist;

    /*
     * Allocate the history ring FROM the slab pool so the slab-pool header at
     * shm.addr (force-unlocked by nginx on every child exit) is left intact.
     * The helper zeroes a fresh ring and (re-)creates the mutex from the leading
     * ngx_shmtx_sh_t lock on fresh, reload, and re-attach; on reuse the existing
     * time-series is preserved across the config reload.
     */
    hist = xrootd_shm_table_alloc(shm_zone, data,
                                  sizeof(xrootd_dashboard_history_t),
                                  &xrootd_dashboard_history_mutex, &fresh);
    if (hist == NULL) {
        return NGX_ERROR;
    }

    /* No fresh-only field inits: the helper's memzero leaves
     * last_bucket_start_ms = 0 and every bucket empty, which is the entire
     * first-startup state. */
    (void) fresh;

    return NGX_OK;
}

void
xrootd_dashboard_history_sample(int64_t now_ms)
{
    xrootd_dashboard_history_t        *hist;
    xrootd_dashboard_history_bucket_t *bucket;
    ngx_xrootd_metrics_t              *met;
    xrootd_transfer_table_t           *tbl;
    int64_t                            bucket_start;
    int64_t                            clear_start;
    uint64_t                           bytes_rx = 0;
    uint64_t                           bytes_tx = 0;
    uint64_t                           errors = 0;
    uint64_t                           auth_failures = 0;
    ngx_uint_t                         active_root = 0;
    ngx_uint_t                         active_webdav = 0;
    ngx_uint_t                         active_s3 = 0;
    ngx_uint_t                         active_tpc = 0;
    ngx_uint_t                         i, j;

    hist = dashboard_history_table();
    if (hist == NULL) {
        return;
    }

    bucket_start = now_ms
                   - (now_ms % XROOTD_DASHBOARD_HISTORY_INTERVAL_MS);

    ngx_shmtx_lock(&xrootd_dashboard_history_mutex);

    if (hist->last_bucket_start_ms == 0) {
        hist->last_bucket_start_ms = bucket_start;
    }

    if (bucket_start > hist->last_bucket_start_ms) {
        clear_start = hist->last_bucket_start_ms
                      + XROOTD_DASHBOARD_HISTORY_INTERVAL_MS;
        for (; clear_start <= bucket_start;
             clear_start += XROOTD_DASHBOARD_HISTORY_INTERVAL_MS)
        {
            j = dashboard_history_bucket_index(clear_start);
            ngx_memzero(&hist->buckets[j], sizeof(hist->buckets[j]));
            hist->buckets[j].bucket_start_ms = clear_start;
        }
        hist->last_bucket_start_ms = bucket_start;
    }

    j = dashboard_history_bucket_index(bucket_start);
    bucket = &hist->buckets[j];
    if (bucket->bucket_start_ms != bucket_start) {
        ngx_memzero(bucket, sizeof(*bucket));
        bucket->bucket_start_ms = bucket_start;
    }

    if (ngx_xrootd_dashboard_shm_zone != NULL
        && ngx_xrootd_dashboard_shm_zone->data != NULL
        && ngx_xrootd_dashboard_shm_zone->data != (void *) 1)
    {
        tbl = ngx_xrootd_dashboard_shm_zone->data;
        for (i = 0; i < XROOTD_DASHBOARD_MAX_TRANSFERS; i++) {
            xrootd_transfer_slot_t *slot = &tbl->slots[i];

            if (slot->in_use == 0) {
                continue;
            }

            if (slot->direction == XROOTD_XFER_DIR_TPC) {
                active_tpc++;
            }

            switch (slot->proto) {
            case XROOTD_XFER_PROTO_WEBDAV:
                active_webdav++;
                break;
            case XROOTD_XFER_PROTO_S3:
                active_s3++;
                break;
            default:
                active_root++;
                break;
            }
        }
    }

    if (ngx_xrootd_shm_zone != NULL
        && ngx_xrootd_shm_zone->data != NULL
        && ngx_xrootd_shm_zone->data != (void *) 1)
    {
        met = ngx_xrootd_shm_zone->data;
        for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
            ngx_xrootd_srv_metrics_t *srv = &met->servers[i];

            bytes_rx += (uint64_t) srv->bytes_rx_total;
            bytes_tx += (uint64_t) srv->bytes_tx_total;
            auth_failures += (uint64_t) srv->op_err[XROOTD_OP_AUTH];
            for (j = 0; j < XROOTD_NOPS; j++) {
                errors += (uint64_t) srv->op_err[j];
            }
        }

        bytes_rx += (uint64_t) met->webdav.bytes_rx_total;
        bytes_tx += (uint64_t) met->webdav.bytes_tx_total;
        bytes_rx += (uint64_t) met->s3.bytes_rx_total;
        bytes_tx += (uint64_t) met->s3.bytes_tx_total;
        auth_failures +=
            (uint64_t) met->webdav.auth_total[XROOTD_WEBDAV_AUTH_RESULT_REJECTED];
        auth_failures +=
            (uint64_t) met->s3.auth_total[XROOTD_S3_AUTH_SIG_MISMATCH]
            + (uint64_t) met->s3.auth_total[XROOTD_S3_AUTH_MALFORMED]
            + (uint64_t) met->s3.auth_total[XROOTD_S3_AUTH_BAD_KEY];
    }

    bucket->active_root = active_root;
    bucket->active_webdav = active_webdav;
    bucket->active_s3 = active_s3;
    bucket->active_tpc = active_tpc;
    bucket->bytes_rx = (ngx_atomic_t) bytes_rx;
    bucket->bytes_tx = (ngx_atomic_t) bytes_tx;
    bucket->errors = (ngx_atomic_t) errors;
    bucket->auth_failures = (ngx_atomic_t) auth_failures;
    bucket->write_stalls = 0;
    bucket->cache_occupancy_ppm = 0;

    ngx_shmtx_unlock(&xrootd_dashboard_history_mutex);
}

ngx_uint_t
xrootd_dashboard_history_snapshot(xrootd_dashboard_history_bucket_t *out,
    ngx_uint_t max_buckets)
{
    xrootd_dashboard_history_t *hist;
    int64_t                     newest;
    int64_t                     oldest;
    int64_t                     ts;
    ngx_uint_t                  n;

    if (out == NULL || max_buckets == 0) {
        return 0;
    }

    hist = dashboard_history_table();
    if (hist == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&xrootd_dashboard_history_mutex);

    newest = hist->last_bucket_start_ms;
    if (newest == 0) {
        ngx_shmtx_unlock(&xrootd_dashboard_history_mutex);
        return 0;
    }

    if (max_buckets > XROOTD_DASHBOARD_HISTORY_BUCKETS) {
        max_buckets = XROOTD_DASHBOARD_HISTORY_BUCKETS;
    }

    oldest = newest - ((int64_t) max_buckets - 1)
                      * XROOTD_DASHBOARD_HISTORY_INTERVAL_MS;
    n = 0;

    for (ts = oldest; ts <= newest && n < max_buckets;
         ts += XROOTD_DASHBOARD_HISTORY_INTERVAL_MS)
    {
        ngx_uint_t idx = dashboard_history_bucket_index(ts);
        if (hist->buckets[idx].bucket_start_ms == ts) {
            out[n++] = hist->buckets[idx];
        }
    }

    ngx_shmtx_unlock(&xrootd_dashboard_history_mutex);
    return n;
}
