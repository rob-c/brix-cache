/*
 * kv.c — data-plane operations for the generic cross-worker key/value store in
 * nginx shared memory (configuration + registry live in kv_config.c).
 *
 * This file owns the request-time table operations — get / set / delete /
 * stats — and the low-level open-addressed probe primitives they build on
 * (FNV-1a hash, bucket accessor, backward-shift deletion, key match, value
 * copy). Every op takes the per-zone spinlock, runs a single O(1) probe
 * sequence with no I/O or allocation inside the critical section, and releases
 * it. The slab-backed table layout it walks (brix_kv_header_t + entry array) is
 * defined in kv_internal.h and shared with kv_config.c; see that header for the
 * layout diagram and the shm.addr / slab-pool-safety contract.
 */
#include "core/ngx_brix_module.h"   /* full ngx core + stream types */
#include "core/fnv.h"
#include "kv.h"
#include "kv_internal.h"


static uint64_t
brix_kv_hash(const void *key, size_t len)
{
    const uint8_t *p = key;
    uint64_t       h = BRIX_FNV1A64_OFFSET_BASIS;
    size_t         i;

    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= BRIX_FNV1A64_PRIME;
    }
    return h;
}

static brix_kv_header_t *
brix_kv_hdr(brix_kv_t *kv)
{
    /*
     * The table (header + entry array) is slab-allocated and published via
     * shm_zone->data by brix_shm_table_alloc() — it does NOT sit at
     * shm.addr (that holds nginx's ngx_slab_pool_t header, which must stay
     * intact so ngx_unlock_mutexes() can force-unlock the slab mutex on child
     * death). Until init runs, zone->data still holds the (void*)1 pending
     * sentinel or the kv handle, so guard against a non-table pointer.
     */
    if (kv == NULL || kv->zone == NULL || kv->zone->data == NULL
        || kv->zone->data == kv || kv->zone->data == (void *) 1)
    {
        return NULL;
    }
    return (brix_kv_header_t *) kv->zone->data;
}

static brix_kv_entry_t *
brix_kv_slot(brix_kv_header_t *h, size_t stride, uint32_t i)
{
    return (brix_kv_entry_t *)
        ((u_char *) h + sizeof(brix_kv_header_t) + (size_t) i * stride);
}

/*
 * Backward-shift deletion (Knuth Algorithm R): empty the slot at `hole`, then
 * pull forward any following entries whose home bucket lets them fill the gap,
 * preserving the linear-probe invariant so no live entry becomes unreachable.
 */
static ngx_uint_t
brix_kv_should_shift(uint32_t home, uint32_t hole, uint32_t cur)
{
    /* Shift iff `home` is NOT in the cyclic interval (hole, cur]. */
    if (hole <= cur) {
        return !(home > hole && home <= cur);
    }
    return !(home > hole || home <= cur);
}

static void
brix_kv_remove_at(brix_kv_header_t *h, size_t stride, uint32_t mask,
    uint32_t hole)
{
    uint32_t cur = hole;

    for ( ;; ) {
        brix_kv_slot(h, stride, hole)->key_len = 0;

        for ( ;; ) {
            brix_kv_entry_t *e;
            uint32_t           home;

            cur = (cur + 1) & mask;
            e = brix_kv_slot(h, stride, cur);
            if (e->key_len == 0) {
                return;                  /* end of probe chain */
            }
            home = (uint32_t) (e->hash & mask);
            if (brix_kv_should_shift(home, hole, cur)) {
                break;                   /* this entry can fill the hole */
            }
        }

        ngx_memcpy(brix_kv_slot(h, stride, hole),
                   brix_kv_slot(h, stride, cur), stride);
        hole = cur;
    }
}


/* ---- Test whether a probed slot holds the requested key ----
 *
 * WHAT: Returns 1 when entry `e` stores the key (hash, length, and bytes all
 *       match), 0 otherwise. Pure predicate; touches no shared counters.
 *
 * WHY: The same three-part key comparison (hash, key_len, memcmp of the inline
 *      key bytes) is the match test for lookup, insert-overwrite, and delete.
 *      Factoring it into one predicate removes the duplicated compound
 *      condition from all three probe loops and keeps the comparison identical.
 *
 * HOW:
 *   1. Compare the stored FNV hash against the caller's hash.
 *   2. Compare the stored key length against the caller's key_len.
 *   3. Compare the inline key bytes (which follow the entry header) via
 *      ngx_memcmp; return 1 only when all three agree.
 */
static ngx_uint_t
brix_kv_entry_matches(brix_kv_entry_t *e, uint64_t hash, const void *key,
    size_t key_len)
{
    return e->hash == hash && e->key_len == key_len
        && ngx_memcmp((u_char *) e + sizeof(*e), key, key_len) == 0;
}

/* ---- Copy a matched entry's value into the caller's buffer ----
 *
 * WHAT: Copies entry `e`'s value bytes into `out`, truncating to the caller's
 *       supplied capacity, and writes the copied length back through *out_len.
 *       No-op when the caller passed no output buffer (out or out_len NULL).
 *
 * WHY: Isolates the read-out side effect from the lookup probe so the probe
 *      loop reads as a flat match/expiry/copy sequence. Callers hold the zone
 *      mutex; the entry bytes are read only under that lock.
 *
 * HOW:
 *   1. Return immediately when out or out_len is NULL (existence-only probe).
 *   2. Clamp the entry's val_len to the caller's *out_len capacity.
 *   3. Copy that many value bytes (they follow the inline key at key_max) and
 *      publish the copied length through *out_len.
 */
static void
brix_kv_copy_value(brix_kv_entry_t *e, brix_kv_t *kv, void *out,
    size_t *out_len)
{
    size_t  vl;

    if (out == NULL || out_len == NULL) {
        return;
    }
    vl = e->val_len;
    if (vl > *out_len) {
        vl = *out_len;
    }
    ngx_memcpy(out, (u_char *) e + sizeof(*e) + kv->key_max, vl);
    *out_len = vl;
}


int
brix_kv_get(brix_kv_t *kv, const void *key, size_t key_len,
    void *out, size_t *out_len)
{
    brix_kv_header_t *h = brix_kv_hdr(kv);
    uint64_t            hash;
    size_t              stride;
    uint32_t            mask, maxprobe, idx, p;
    ngx_msec_t          now;
    int                 result = 0;

    if (h == NULL || key_len == 0 || key_len > kv->key_max) {
        return 0;
    }

    hash     = brix_kv_hash(key, key_len);
    stride   = sizeof(brix_kv_entry_t) + kv->key_max + kv->val_max;
    now      = ngx_current_msec;

    ngx_shmtx_lock(&kv->mutex);

    mask     = h->capacity - 1; /* phase79-fp: h NULL-checked at entry; analyzer drops the guard across ngx_shmtx_lock */
    maxprobe = h->capacity / 2;
    idx      = (uint32_t) (hash & mask);

    for (p = 0; p < maxprobe; p++) {
        brix_kv_entry_t *e = brix_kv_slot(h, stride, idx);

        if (e->key_len == 0) {
            break;                       /* probe chain ends — not found */
        }
        if (brix_kv_entry_matches(e, hash, key, key_len)) {
            if (e->expires != 0 && e->expires <= now) {
                brix_kv_remove_at(h, stride, mask, idx);
                if (h->count > 0) { h->count--; }
                h->evictions++;
                break;                   /* expired — treat as miss */
            }
            brix_kv_copy_value(e, kv, out, out_len);
            result = 1;
            break;
        }
        idx = (idx + 1) & mask;
    }

    if (result) { h->hits++; } else { h->misses++; }

    ngx_shmtx_unlock(&kv->mutex);
    return result;
}

ngx_int_t
brix_kv_set(brix_kv_t *kv, const void *key, size_t key_len,
    const void *val, size_t val_len, ngx_msec_t ttl_ms)
{
    brix_kv_header_t *h = brix_kv_hdr(kv);
    uint64_t            hash;
    size_t              stride;
    uint32_t            mask, maxprobe, idx, p;
    ngx_msec_t          now;
    ngx_int_t           rc = NGX_ERROR;

    if (h == NULL
        || key_len == 0 || key_len > kv->key_max
        || val_len > kv->val_max)
    {
        return NGX_ERROR;
    }

    hash   = brix_kv_hash(key, key_len);
    stride = sizeof(brix_kv_entry_t) + kv->key_max + kv->val_max;
    now    = ngx_current_msec;

    ngx_shmtx_lock(&kv->mutex);

    mask     = h->capacity - 1; /* phase79-fp: h NULL-checked at entry; analyzer drops the guard across ngx_shmtx_lock */
    maxprobe = h->capacity / 2;
    idx      = (uint32_t) (hash & mask);

    for (p = 0; p < maxprobe; p++) {
        brix_kv_entry_t *e = brix_kv_slot(h, stride, idx);

        if (e->key_len == 0) {
            /* New insert — enforce the 0.5 load-factor cap. */
            if (h->count >= h->capacity / 2) {
                break;
            }
            e->hash    = hash;
            e->key_len = (uint32_t) key_len;
            e->val_len = (uint32_t) val_len;
            e->expires = ttl_ms ? (now + ttl_ms) : 0;
            ngx_memcpy((u_char *) e + sizeof(*e), key, key_len);
            if (val_len) {
                ngx_memcpy((u_char *) e + sizeof(*e) + kv->key_max,
                           val, val_len);
            }
            h->count++;
            rc = NGX_OK;
            break;
        }
        if (brix_kv_entry_matches(e, hash, key, key_len)) {
            /* Overwrite existing key. */
            e->val_len = (uint32_t) val_len;
            e->expires = ttl_ms ? (now + ttl_ms) : 0;
            if (val_len) {
                ngx_memcpy((u_char *) e + sizeof(*e) + kv->key_max,
                           val, val_len);
            }
            rc = NGX_OK;
            break;
        }
        idx = (idx + 1) & mask;
    }

    ngx_shmtx_unlock(&kv->mutex);
    return rc;
}

void
brix_kv_delete(brix_kv_t *kv, const void *key, size_t key_len)
{
    brix_kv_header_t *h = brix_kv_hdr(kv);
    uint64_t            hash;
    size_t              stride;
    uint32_t            mask, maxprobe, idx, p;

    if (h == NULL || key_len == 0 || key_len > kv->key_max) {
        return;
    }

    hash   = brix_kv_hash(key, key_len);
    stride = sizeof(brix_kv_entry_t) + kv->key_max + kv->val_max;

    ngx_shmtx_lock(&kv->mutex);

    mask     = h->capacity - 1; /* phase79-fp: h NULL-checked at entry; analyzer drops the guard across ngx_shmtx_lock */
    maxprobe = h->capacity / 2;
    idx      = (uint32_t) (hash & mask);

    for (p = 0; p < maxprobe; p++) {
        brix_kv_entry_t *e = brix_kv_slot(h, stride, idx);

        if (e->key_len == 0) {
            break;
        }
        if (brix_kv_entry_matches(e, hash, key, key_len)) {
            brix_kv_remove_at(h, stride, mask, idx);
            if (h->count > 0) { h->count--; }
            break;
        }
        idx = (idx + 1) & mask;
    }

    ngx_shmtx_unlock(&kv->mutex);
}

void
brix_kv_stats(brix_kv_t *kv, brix_kv_stats_t *out)
{
    brix_kv_header_t *h = brix_kv_hdr(kv);

    ngx_memzero(out, sizeof(*out));
    if (h == NULL) {
        return;
    }

    ngx_shmtx_lock(&kv->mutex);
    out->hits      = h->hits;
    out->misses    = h->misses;
    out->evictions = h->evictions;
    out->count     = h->count;
    out->capacity  = h->capacity;
    ngx_shmtx_unlock(&kv->mutex);
}
