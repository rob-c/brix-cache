#include "metrics_internal.h"
#include "config/config.h"

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/*
 * WHAT: Track Virtual Organization (VO) activity and unique user identities in shared memory.
 * WHY: Prometheus metrics need VO-level and user-level aggregation without storing full DNs or token subjects
 *      as label strings (INVARIANT #8: low-cardinality labels only). FNV-1a hash provides fast 32-bit identity
 *      deduplication; VO slots track bytes_tx/bytes_rx per organization; user slots track session counts and unique count.
 * HOW: Two tracking functions share the same pattern — iterate fixed-size slot array, find match via comparison (VO=string compare, USER=hash),
 *      increment atomic counters on match or allocate new slot on miss with eviction fallback when array fills. FNV-1a hash uses 0x811c9dc5 seed + XOR-multiply loop.
 */

/* xrootd_fnv1a_hash — 32-bit FNV-1a over arbitrary data, used to dedup identities
 * (DNs, token subjects) by hash rather than storing them verbatim (INVARIANT #8 —
 * no DN/token label explosion in Prometheus). */


static ngx_inline uint32_t
xrootd_fnv1a_hash(const void *data, size_t len)
{
    const u_char *p = (const u_char *) data;
    uint32_t      h = 0x811c9dc5u;

    while (len--) {
        h ^= *p++;
        h *= 0x01000193u;
    }
    return h;
}

/* xrootd_track_vo_activity — bump the per-VO atomic byte + request counters for
 * per-experiment Prometheus throughput; a new VO takes the first empty slot, and
 * when all slots are full overflow_total increments and slot 0 is reused. */

ngx_int_t
xrootd_track_vo_activity(ngx_xrootd_metrics_t *shm, const char *vo_name,
                          size_t bytes_tx, size_t bytes_rx)
{
    ngx_uint_t  i;
    int         match = -1;

    if (shm == NULL || vo_name == NULL || vo_name[0] == '\0') {
        return NGX_ERROR;
    }

    for (i = 0; i < XROOTD_VO_MAX_TRACKED; i++) {
        ngx_xrootd_vo_slot_t *slot = &shm->vo_global.slots[i];

        if (!slot->name[0]) {
            continue;
        }

        if (ngx_strncmp(slot->name, vo_name, XROOTD_VO_NAME_LEN) == 0) {
            match = (int) i;
            break;
        }
    }

    if (match >= 0) {
        ngx_xrootd_vo_slot_t *slot = &shm->vo_global.slots[match];
        XROOTD_ATOMIC_ADD(&slot->bytes_tx_total, bytes_tx);
        XROOTD_ATOMIC_ADD(&slot->bytes_rx_total, bytes_rx);
        XROOTD_ATOMIC_INC(&slot->requests_total);

    } else {
        int target = -1;

        for (i = 0; i < XROOTD_VO_MAX_TRACKED; i++) {
            if (!shm->vo_global.slots[i].name[0]) {
                target = (int) i;
                break;
            }
        }

        if (target < 0) {
            XROOTD_ATOMIC_INC(&shm->vo_global.overflow_total);
            target = 0;
            memset(shm->vo_global.slots[0].name, 0, sizeof(shm->vo_global.slots[0].name));
            shm->vo_global.slot_count--;
        }

        ngx_xrootd_vo_slot_t *slot = &shm->vo_global.slots[target];
        size_t copy_len = ngx_min(strlen(vo_name), XROOTD_VO_NAME_LEN - 1);
        ngx_memcpy(slot->name, vo_name, copy_len);
        slot->name[copy_len] = '\0';

        if (!slot->bytes_tx_total && !slot->bytes_rx_total && !slot->requests_total) {
            shm->vo_global.slot_count++;
        }

        XROOTD_ATOMIC_ADD(&slot->bytes_tx_total, bytes_tx);
        XROOTD_ATOMIC_ADD(&slot->bytes_rx_total, bytes_rx);
        XROOTD_ATOMIC_INC(&slot->requests_total);
    }

    return NGX_OK;
}

/* xrootd_track_unique_user — track unique identities by FNV-1a hash (no DNs as
 * labels, INVARIANT #8): bump the session count and unique_count on a new identity;
 * when all slots are full evictions_total increments and slot 0 is reused. */

ngx_int_t
xrootd_track_unique_user(ngx_xrootd_metrics_t *shm, const char *identity,
                          size_t identity_len)
{
    uint32_t        h;
    ngx_uint_t      i;
    int             match = -1;

    if (shm == NULL || identity == NULL || identity_len == 0) {
        return NGX_ERROR;
    }

    h = xrootd_fnv1a_hash(identity, identity_len);

    for (i = 0; i < XROOTD_USERS_MAX_TRACKED; i++) {
        if (shm->user_tracking.slots[i].id_hash == h) {
            match = (int) i;
            break;
        }
    }

    if (match >= 0) {
        XROOTD_ATOMIC_INC(&shm->user_tracking.slots[match].sessions_total);

    } else {
        int target = -1;

        for (i = 0; i < XROOTD_USERS_MAX_TRACKED; i++) {
            if (!shm->user_tracking.slots[i].id_hash) {
                target = (int) i;
                break;
            }
        }

        if (target < 0) {
            shm->user_tracking.evictions_total++;
            target = 0;
            shm->user_tracking.slots[0].id_hash = 0;
            XROOTD_ATOMIC_DEC(&shm->user_tracking.unique_count);
        }

        struct timeval tv;
        gettimeofday(&tv, NULL);

        shm->user_tracking.slots[target].id_hash   = h;
        shm->user_tracking.slots[target].first_seen = (time_t) tv.tv_sec;
        shm->user_tracking.slots[target].sessions_total = 1;
        XROOTD_ATOMIC_INC(&shm->user_tracking.unique_count);
        XROOTD_ATOMIC_INC(&shm->user_tracking.total_unique);
    }

    return NGX_OK;
}
