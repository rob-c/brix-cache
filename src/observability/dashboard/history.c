#include "dashboard.h"
#include "observability/metrics/metrics.h"
#include "core/compat/shm_slots.h"

#include <ngx_shmtx.h>

/*
 * dashboard/history.c — rolling time-series of activity for the dashboard charts.
 *
 * WHAT: Maintains the SHM-backed history ring (brix_dashboard_history_t) of
 *       BRIX_DASHBOARD_HISTORY_BUCKETS fixed-width
 *       (BRIX_DASHBOARD_HISTORY_INTERVAL_MS) buckets recording active transfer
 *       counts per protocol, cumulative bytes rx/tx, error and auth-failure
 *       totals.  brix_dashboard_history_sample() writes the current bucket;
 *       brix_dashboard_history_snapshot() returns the recent window in
 *       chronological order; ngx_brix_dashboard_history_shm_init() is the SHM
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
 *       active transfers from ngx_brix_dashboard_shm_zone and byte/error/auth
 *       totals from ngx_brix_shm_zone (per-server, WebDAV and S3).  A single
 *       static ngx_shmtx_t (re-created on reload) guards both sample and
 *       snapshot.  write_stalls and cache_occupancy_ppm are reserved/unpopulated.
 */

static ngx_shmtx_t brix_dashboard_history_mutex;

static brix_dashboard_history_t *
dashboard_history_table(void)
{
    if (ngx_brix_dashboard_history_shm_zone == NULL
        || ngx_brix_dashboard_history_shm_zone->data == NULL
        || ngx_brix_dashboard_history_shm_zone->data == (void *) 1)
    {
        return NULL;
    }

    return (brix_dashboard_history_t *)
           ngx_brix_dashboard_history_shm_zone->data;
}

static ngx_uint_t
dashboard_history_bucket_index(int64_t bucket_start_ms)
{
    return (ngx_uint_t)
        ((bucket_start_ms / BRIX_DASHBOARD_HISTORY_INTERVAL_MS)
         % BRIX_DASHBOARD_HISTORY_BUCKETS);
}

ngx_int_t
ngx_brix_dashboard_history_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t                  fresh;
    brix_dashboard_history_t *hist;

    /*
     * Allocate the history ring FROM the slab pool so the slab-pool header at
     * shm.addr (force-unlocked by nginx on every child exit) is left intact.
     * The helper zeroes a fresh ring and (re-)creates the mutex from the leading
     * ngx_shmtx_sh_t lock on fresh, reload, and re-attach; on reuse the existing
     * time-series is preserved across the config reload.
     */
    hist = brix_shm_table_alloc(shm_zone, data,
                                  sizeof(brix_dashboard_history_t),
                                  &brix_dashboard_history_mutex, &fresh);
    if (hist == NULL) {
        return NGX_ERROR;
    }

    /* No fresh-only field inits: the helper's memzero leaves
     * last_bucket_start_ms = 0 and every bucket empty, which is the entire
     * first-startup state. */
    (void) fresh;

    return NGX_OK;
}

/*
 * dashboard_history_zero_fill_gap — clear buckets skipped since the last sample.
 *
 * WHAT: When bucket_start has advanced past hist->last_bucket_start_ms, walks
 *       every interval boundary strictly between the two, zero-fills that ring
 *       slot and stamps its bucket_start_ms, then advances
 *       last_bucket_start_ms to bucket_start.
 * WHY:  Idle gaps (no sampling for several intervals) must leave the wrapped
 *       ring slots reading as empty-but-current rather than stale data from a
 *       prior lap, so the snapshot reader plots zeros for the quiet window.
 * HOW:  Iterates from last_bucket_start_ms + INTERVAL up to and including
 *       bucket_start, mapping each boundary to its ring index. No-op when
 *       bucket_start has not advanced. Caller holds the history mutex.
 */
static void
dashboard_history_zero_fill_gap(brix_dashboard_history_t *hist,
    int64_t bucket_start)
{
    int64_t     clear_start;
    ngx_uint_t  j;

    if (bucket_start <= hist->last_bucket_start_ms) {
        return;
    }

    clear_start = hist->last_bucket_start_ms
                  + BRIX_DASHBOARD_HISTORY_INTERVAL_MS;
    for (; clear_start <= bucket_start;
         clear_start += BRIX_DASHBOARD_HISTORY_INTERVAL_MS)
    {
        j = dashboard_history_bucket_index(clear_start);
        ngx_memzero(&hist->buckets[j], sizeof(hist->buckets[j]));
        hist->buckets[j].bucket_start_ms = clear_start;
    }
    hist->last_bucket_start_ms = bucket_start;
}

/*
 * dashboard_history_select_bucket — resolve and prepare the current ring slot.
 *
 * WHAT: Returns the ring slot for bucket_start, resetting it (memzero + stamp)
 *       when the slot still carries a stale wrapped bucket_start_ms.
 * WHY:  Re-sampling the same bucket must accumulate into a live slot, but a
 *       slot inherited from an earlier lap of the ring must start clean so its
 *       counters reflect only the current bucket.
 * HOW:  Maps bucket_start to its ring index; if the stored bucket_start_ms
 *       differs, zeroes the slot and stamps it. Caller holds the history mutex.
 */
static brix_dashboard_history_bucket_t *
dashboard_history_select_bucket(brix_dashboard_history_t *hist,
    int64_t bucket_start)
{
    brix_dashboard_history_bucket_t *bucket;

    bucket = &hist->buckets[dashboard_history_bucket_index(bucket_start)];
    if (bucket->bucket_start_ms != bucket_start) {
        ngx_memzero(bucket, sizeof(*bucket));
        bucket->bucket_start_ms = bucket_start;
    }
    return bucket;
}

/*
 * dashboard_history_count_active — tally in-flight transfers per protocol.
 *
 * WHAT: Scans the dashboard transfer table and fills active[] (per protocol
 *       row) plus *active_tpc (count of third-party-copy direction slots).
 * WHY:  The history series records concurrency, which is derived from the live
 *       transfer table rather than a parallel counter so it cannot drift.
 * HOW:  Skips unused slots; TPC-direction slots bump *active_tpc; a slot's
 *       proto in [1, NPROTOS] indexes active[proto-1], and untracked/legacy
 *       slots fall back to the historic root bucket. No-op (leaves outputs at
 *       their caller-zeroed state) when the dashboard zone is absent.
 */
static void
dashboard_history_count_active(ngx_uint_t active[BRIX_XFER_NPROTOS],
    ngx_uint_t *active_tpc)
{
    brix_transfer_table_t *tbl;
    ngx_uint_t             i;

    if (ngx_brix_dashboard_shm_zone == NULL
        || ngx_brix_dashboard_shm_zone->data == NULL
        || ngx_brix_dashboard_shm_zone->data == (void *) 1)
    {
        return;
    }

    tbl = ngx_brix_dashboard_shm_zone->data;
    for (i = 0; i < BRIX_DASHBOARD_MAX_TRANSFERS; i++) {
        brix_transfer_slot_t *slot = &tbl->slots[i];

        if (slot->in_use == 0) {
            continue;
        }

        if (slot->direction == BRIX_XFER_DIR_TPC) {
            (*active_tpc)++;
        }

        /* per-proto counts index by list row (id-1); untracked/legacy
         * slots keep the historic root bucket */
        if (slot->proto >= 1 && slot->proto <= BRIX_XFER_NPROTOS) {
            active[slot->proto - 1]++;
        } else {
            active[BRIX_XFER_PROTO_ROOT - 1]++;
        }
    }
}

/*
 * dashboard_history_sum_totals — accumulate cumulative byte/error/auth totals.
 *
 * WHAT: Sums bytes rx/tx, error counts and auth-failure counts across the
 *       per-server metrics array plus the WebDAV and S3 aggregate metrics.
 * WHY:  The dashboard plots cumulative totals sourced from the live metrics
 *       SHM zone so the series stays consistent with /metrics.
 * HOW:  Per server: adds bytes rx/tx, the AUTH-op error count into auth
 *       failures, and every op_err[] entry into errors. Then folds in WebDAV
 *       and S3 bytes and their protocol-specific auth-rejection buckets. No-op
 *       (leaves outputs at their caller-zeroed state) when the metrics zone is
 *       absent.
 */
static void
dashboard_history_sum_totals(uint64_t *bytes_rx, uint64_t *bytes_tx,
    uint64_t *errors, uint64_t *auth_failures)
{
    ngx_brix_metrics_t *met;
    ngx_uint_t          i, j;

    if (ngx_brix_shm_zone == NULL
        || ngx_brix_shm_zone->data == NULL
        || ngx_brix_shm_zone->data == (void *) 1)
    {
        return;
    }

    met = ngx_brix_shm_zone->data;
    for (i = 0; i < BRIX_METRICS_MAX_SERVERS; i++) {
        ngx_brix_srv_metrics_t *srv = &met->servers[i];

        *bytes_rx += (uint64_t) srv->bytes_rx_total;
        *bytes_tx += (uint64_t) srv->bytes_tx_total;
        *auth_failures += (uint64_t) srv->op_err[BRIX_OP_AUTH];
        for (j = 0; j < BRIX_NOPS; j++) {
            *errors += (uint64_t) srv->op_err[j];
        }
    }

    *bytes_rx += (uint64_t) met->webdav.bytes_rx_total;
    *bytes_tx += (uint64_t) met->webdav.bytes_tx_total;
    *bytes_rx += (uint64_t) met->s3.bytes_rx_total;
    *bytes_tx += (uint64_t) met->s3.bytes_tx_total;
    *auth_failures +=
        (uint64_t) met->webdav.auth_total[BRIX_WEBDAV_AUTH_RESULT_REJECTED];
    *auth_failures +=
        (uint64_t) met->s3.auth_total[BRIX_S3_AUTH_SIG_MISMATCH]
        + (uint64_t) met->s3.auth_total[BRIX_S3_AUTH_MALFORMED]
        + (uint64_t) met->s3.auth_total[BRIX_S3_AUTH_BAD_KEY];
}

void
brix_dashboard_history_sample(int64_t now_ms)
{
    brix_dashboard_history_t        *hist;
    brix_dashboard_history_bucket_t *bucket;
    int64_t                            bucket_start;
    uint64_t                           bytes_rx = 0;
    uint64_t                           bytes_tx = 0;
    uint64_t                           errors = 0;
    uint64_t                           auth_failures = 0;
    ngx_uint_t                         active[BRIX_XFER_NPROTOS] = { 0 };
    ngx_uint_t                         active_tpc = 0;
    ngx_uint_t                         p;

    hist = dashboard_history_table();
    if (hist == NULL) {
        return;
    }

    bucket_start = now_ms
                   - (now_ms % BRIX_DASHBOARD_HISTORY_INTERVAL_MS);

    ngx_shmtx_lock(&brix_dashboard_history_mutex);

    if (hist->last_bucket_start_ms == 0) {
        hist->last_bucket_start_ms = bucket_start;
    }

    dashboard_history_zero_fill_gap(hist, bucket_start);
    bucket = dashboard_history_select_bucket(hist, bucket_start);

    dashboard_history_count_active(active, &active_tpc);
    dashboard_history_sum_totals(&bytes_rx, &bytes_tx, &errors,
                                 &auth_failures);

    for (p = 0; p < BRIX_XFER_NPROTOS; p++) {
        bucket->active[p] = active[p];
    }
    bucket->active_tpc = active_tpc;
    bucket->bytes_rx = (ngx_atomic_t) bytes_rx;
    bucket->bytes_tx = (ngx_atomic_t) bytes_tx;
    bucket->errors = (ngx_atomic_t) errors;
    bucket->auth_failures = (ngx_atomic_t) auth_failures;
    bucket->write_stalls = 0;
    bucket->cache_occupancy_ppm = 0;

    ngx_shmtx_unlock(&brix_dashboard_history_mutex);
}

ngx_uint_t
brix_dashboard_history_snapshot(brix_dashboard_history_bucket_t *out,
    ngx_uint_t max_buckets)
{
    brix_dashboard_history_t *hist;
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

    ngx_shmtx_lock(&brix_dashboard_history_mutex);

    newest = hist->last_bucket_start_ms;
    if (newest == 0) {
        ngx_shmtx_unlock(&brix_dashboard_history_mutex);
        return 0;
    }

    if (max_buckets > BRIX_DASHBOARD_HISTORY_BUCKETS) {
        max_buckets = BRIX_DASHBOARD_HISTORY_BUCKETS;
    }

    oldest = newest - ((int64_t) max_buckets - 1)
                      * BRIX_DASHBOARD_HISTORY_INTERVAL_MS;
    n = 0;

    for (ts = oldest; ts <= newest && n < max_buckets;
         ts += BRIX_DASHBOARD_HISTORY_INTERVAL_MS)
    {
        ngx_uint_t idx = dashboard_history_bucket_index(ts);
        if (hist->buckets[idx].bucket_start_ms == ts) {
            out[n++] = hist->buckets[idx];
        }
    }

    ngx_shmtx_unlock(&brix_dashboard_history_mutex);
    return n;
}
