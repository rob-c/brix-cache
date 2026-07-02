/*
 * ratelimit.c — Phase 25 leaky-bucket core (request rate + bandwidth).
 *
 * The leaky-bucket formulation matches ngx_http_limit_req_module: a bucket
 * fills with each charged unit and drains at the configured rate over elapsed
 * wall-clock.  req_excess is stored × 1000 so a 1-request charge is 1000 units
 * and fractional drain over millisecond intervals stays integer.  Bandwidth
 * uses the same shape but charges raw byte counts (× 1) and drains at bw_rate
 * bytes/s.
 *
 * Fail-open: any internal failure (zone not yet attached, slab exhausted after
 * eviction) returns NGX_OK so rate limiting never denies otherwise-authorised
 * access — availability beats strict enforcement.
 */
#include "ratelimit.h"


ngx_int_t
xrootd_rl_check(xrootd_rl_rule_t *rule, const char *key_str,
    uint32_t *wait_seconds)
{
    xrootd_rl_zone_t *zone = rule->zone;
    xrootd_rl_node_t *rln;
    uint32_t          hash;
    size_t            len;
    ngx_msec_t        now, elapsed;
    ngx_uint_t        excess, drain, burst_units;
    ngx_int_t         rc = NGX_OK;

    if (rule->req_rate == 0 || zone == NULL || zone->sh == NULL) {
        return NGX_OK;
    }

    len  = ngx_strlen(key_str);
    hash = xrootd_rl_hash(key_str, len);
    now  = ngx_current_msec;

    ngx_shmtx_lock(&zone->shpool->mutex);

    rln = xrootd_rl_lookup_locked(zone, hash, key_str, len);
    if (rln == NULL) {
        rln = xrootd_rl_create_locked(zone, hash, key_str, len);
        if (rln == NULL) {
            ngx_shmtx_unlock(&zone->shpool->mutex);
            return NGX_OK;                 /* fail open */
        }
        rln->last = now;
    }

    elapsed = (now > rln->last) ? (now - rln->last) : 0;
    drain   = (ngx_uint_t) ((uint64_t) rule->req_rate * elapsed / 1000);
    excess  = (rln->req_excess > drain) ? (rln->req_excess - drain) : 0;

    /* burst headroom in the same ×1000 unit as req_rate / excess. */
    burst_units = rule->req_burst * 1000;

    if (excess + 1000 > burst_units) {
        /* Throttled — seconds to drain back under the burst ceiling (ceil). */
        ngx_uint_t over = excess + 1000 - burst_units;
        *wait_seconds = (uint32_t) ((over + rule->req_rate - 1) / rule->req_rate);
        if (*wait_seconds == 0) { *wait_seconds = 1; }
        /*
         * Persist the DRAINED excess (without the +1000 charge) and advance the
         * clock together.  Omitting this — writing rln->last = now but leaving
         * rln->req_excess at its pre-drain value — discards the drain that
         * accrued since the last request, so under sustained offered load the
         * bucket never actually drains: every throttle resets the clock against
         * a stale, pegged excess and the effective serve rate collapses far
         * below the configured rate.  Writing the drained value back is what
         * lets the bucket drain at exactly req_rate between accepted requests.
         */
        rln->req_excess = excess;
        rln->throttle_count++;
        rln->last = now;
        rc = NGX_AGAIN;
    } else {
        rln->req_excess = excess + 1000;
        rln->last       = now;
        rln->req_total++;
    }

    ngx_shmtx_unlock(&zone->shpool->mutex);
    return rc;
}


/* W7: per-principal concurrency (in-flight) limit */
ngx_int_t
xrootd_rl_conc_acquire(xrootd_rl_rule_t *rule, const char *key_str)
{
    xrootd_rl_zone_t *zone = rule->zone;
    xrootd_rl_node_t *rln;
    uint32_t          hash;
    size_t            len;
    ngx_int_t         rc = NGX_OK;

    if (rule->req_conc == 0 || zone == NULL || zone->sh == NULL) {
        return NGX_OK;
    }

    len  = ngx_strlen(key_str);
    hash = xrootd_rl_hash(key_str, len);

    ngx_shmtx_lock(&zone->shpool->mutex);

    rln = xrootd_rl_lookup_locked(zone, hash, key_str, len);
    if (rln == NULL) {
        rln = xrootd_rl_create_locked(zone, hash, key_str, len);
        if (rln == NULL) {
            ngx_shmtx_unlock(&zone->shpool->mutex);
            return NGX_OK;                 /* fail open */
        }
        rln->last = ngx_current_msec;
    }

    if (rln->in_flight >= rule->req_conc) {
        rln->throttle_count++;
        rc = NGX_AGAIN;                    /* at cap — reserve nothing */
    } else {
        rln->in_flight++;                  /* slot reserved; caller must release */
        rln->req_total++;
    }

    ngx_shmtx_unlock(&zone->shpool->mutex);
    return rc;
}

void
xrootd_rl_conc_release(xrootd_rl_rule_t *rule, const char *key_str)
{
    xrootd_rl_zone_t *zone = rule->zone;
    xrootd_rl_node_t *rln;
    uint32_t          hash;
    size_t            len;

    if (rule->req_conc == 0 || zone == NULL || zone->sh == NULL) {
        return;
    }

    len  = ngx_strlen(key_str);
    hash = xrootd_rl_hash(key_str, len);

    /*
     * Fresh lookup under the lock — never dereference a cached node pointer,
     * since the LRU reaper may have evicted (freed) the node between acquire
     * and release.  If the node is gone the slot accounting simply resets, which
     * is a benign accuracy drift only possible under memory pressure.
     */
    ngx_shmtx_lock(&zone->shpool->mutex);
    rln = xrootd_rl_lookup_locked(zone, hash, key_str, len);
    if (rln != NULL && rln->in_flight > 0) {
        rln->in_flight--;
    }
    ngx_shmtx_unlock(&zone->shpool->mutex);
}


ngx_int_t
xrootd_rl_bw_check(xrootd_rl_rule_t *rule, const char *key_str,
    uint32_t *wait_seconds)
{
    xrootd_rl_zone_t *zone = rule->zone;
    xrootd_rl_node_t *rln;
    uint32_t          hash;
    size_t            len;
    ngx_msec_t        now, elapsed;
    ngx_uint_t        excess, drain;
    ngx_int_t         rc = NGX_OK;

    if (rule->bw_rate == 0 || zone == NULL || zone->sh == NULL) {
        return NGX_OK;
    }

    len  = ngx_strlen(key_str);
    hash = xrootd_rl_hash(key_str, len);
    now  = ngx_current_msec;

    ngx_shmtx_lock(&zone->shpool->mutex);

    rln = xrootd_rl_lookup_locked(zone, hash, key_str, len);
    if (rln == NULL) {
        ngx_shmtx_unlock(&zone->shpool->mutex);
        return NGX_OK;                     /* nothing charged yet — allow */
    }

    elapsed = (now > rln->last) ? (now - rln->last) : 0;
    drain   = (ngx_uint_t) ((uint64_t) rule->bw_rate * elapsed / 1000);
    excess  = (rln->bw_excess > drain) ? (rln->bw_excess - drain) : 0;
    rln->bw_excess = excess;     /* update the drained value (no charge here) */

    if (excess > rule->bw_burst) {
        ngx_uint_t over = excess - rule->bw_burst;
        *wait_seconds = (uint32_t) ((over + rule->bw_rate - 1) / rule->bw_rate);
        if (*wait_seconds == 0) { *wait_seconds = 1; }
        rln->throttle_count++;
        rc = NGX_AGAIN;
    }

    ngx_shmtx_unlock(&zone->shpool->mutex);
    return rc;
}


void
xrootd_rl_charge_bytes(xrootd_rl_rule_t *rule, const char *key_str,
    size_t nbytes)
{
    xrootd_rl_zone_t *zone = rule->zone;
    xrootd_rl_node_t *rln;
    uint32_t          hash;
    size_t            len;
    ngx_msec_t        now, elapsed;
    ngx_uint_t        excess, drain;

    if (rule->bw_rate == 0 || nbytes == 0 || zone == NULL || zone->sh == NULL) {
        return;
    }

    len  = ngx_strlen(key_str);
    hash = xrootd_rl_hash(key_str, len);
    now  = ngx_current_msec;

    ngx_shmtx_lock(&zone->shpool->mutex);

    rln = xrootd_rl_lookup_locked(zone, hash, key_str, len);
    if (rln == NULL) {
        rln = xrootd_rl_create_locked(zone, hash, key_str, len);
        if (rln == NULL) {
            ngx_shmtx_unlock(&zone->shpool->mutex);
            return;
        }
        rln->last = now;
    }

    elapsed = (now > rln->last) ? (now - rln->last) : 0;
    drain   = (ngx_uint_t) ((uint64_t) rule->bw_rate * elapsed / 1000);
    excess  = (rln->bw_excess > drain) ? (rln->bw_excess - drain) : 0;

    rln->bw_excess   = excess + (ngx_uint_t) nbytes;
    rln->bytes_total += nbytes;
    rln->last         = now;

    ngx_shmtx_unlock(&zone->shpool->mutex);
}


/* dashboard snapshot */
ngx_int_t
xrootd_rl_snapshot(xrootd_rl_zone_t *zone, xrootd_rl_snapshot_entry_t *out,
    ngx_uint_t max, ngx_uint_t *count)
{
    ngx_queue_t      *q;
    xrootd_rl_node_t *rln;
    ngx_uint_t        n = 0;

    *count = 0;
    if (zone == NULL || zone->sh == NULL) {
        return NGX_OK;
    }

    ngx_shmtx_lock(&zone->shpool->mutex);

    /* Walk the LRU queue (most-recent first) and copy out under the lock. */
    for (q = ngx_queue_head(&zone->sh->queue);
         q != ngx_queue_sentinel(&zone->sh->queue) && n < max;
         q = ngx_queue_next(q))
    {
        rln = ngx_queue_data(q, xrootd_rl_node_t, queue);

        ngx_memcpy(out[n].key_str, rln->key_str,
                   ngx_min(rln->len, XROOTD_RL_KEY_LEN - 1));
        out[n].key_str[ngx_min(rln->len, XROOTD_RL_KEY_LEN - 1)] = '\0';
        out[n].req_total      = rln->req_total;
        out[n].bytes_total    = rln->bytes_total;
        out[n].throttle_count = rln->throttle_count;
        out[n].req_excess     = rln->req_excess;
        out[n].bw_excess      = rln->bw_excess;
        n++;
    }

    ngx_shmtx_unlock(&zone->shpool->mutex);

    /* Sort by throttle_count descending (small N — insertion sort). */
    {
        ngx_uint_t i, j;
        for (i = 1; i < n; i++) {
            xrootd_rl_snapshot_entry_t tmp = out[i];
            for (j = i; j > 0 && out[j - 1].throttle_count < tmp.throttle_count;
                 j--)
            {
                out[j] = out[j - 1];
            }
            out[j] = tmp;
        }
    }

    *count = n;
    return NGX_OK;
}
