/*
 * auth_gate_l1.c — per-worker L1 auth-verdict cache (see header).
 *
 * Direct-mapped, lockless (single-threaded event loop), bounded memory.  The key
 * is already a SHA-256 from auth_gate.c, so the bucket index is taken straight
 * from its leading bytes — no re-hash.  Expiry uses the nginx monotonic msec
 * clock so it inherits the L2 TTL exactly.
 */

#include "auth_gate_l1.h"

#define BRIX_AUTH_L1_DEFAULT_SLOTS  2048   /* tiny entries (~48B) → ~96KB */

typedef struct {
    u_char                   key[32];    /* SHA-256 auth-gate key; valid iff set */
    unsigned                 set:1;      /* slot occupied */
    ngx_msec_t               expire;     /* ngx_current_msec deadline */
    brix_auth_cache_val_t  val;        /* cached grant/deny verdict */
} brix_auth_l1_slot_t;

struct brix_auth_l1_s {
    ngx_uint_t              nslots;
    brix_auth_l1_slot_t  *slots;
};

brix_auth_l1_t *
brix_auth_l1_create(ngx_pool_t *pool, ngx_uint_t slots)
{
    brix_auth_l1_t  *cache;

    if (slots == 0) {
        slots = BRIX_AUTH_L1_DEFAULT_SLOTS;
    }
    if (slots < 64) {
        slots = 64;
    }

    cache = ngx_pcalloc(pool, sizeof(*cache));
    if (cache == NULL) {
        return NULL;
    }
    cache->slots = ngx_pcalloc(pool, slots * sizeof(brix_auth_l1_slot_t));
    if (cache->slots == NULL) {
        return NULL;
    }
    cache->nslots = slots;
    return cache;
}

static ngx_inline ngx_uint_t
brix_auth_l1_index(brix_auth_l1_t *cache, const u_char key[32])
{
    uint32_t  h = ((uint32_t) key[0] << 24) | ((uint32_t) key[1] << 16)
                | ((uint32_t) key[2] << 8) | (uint32_t) key[3];
    return (ngx_uint_t) (h % cache->nslots);
}

int
brix_auth_l1_lookup(brix_auth_l1_t *cache, const u_char key[32],
    brix_auth_cache_val_t *val)
{
    brix_auth_l1_slot_t  *slot;

    if (cache == NULL || key == NULL) {
        return 0;
    }

    slot = &cache->slots[brix_auth_l1_index(cache, key)];
    if (!slot->set || ngx_memcmp(slot->key, key, 32) != 0) {
        return 0;
    }
    /* Expired? (monotonic msec; the signed delta handles wrap.) */
    if ((ngx_msec_int_t) (ngx_current_msec - slot->expire) >= 0) {
        return 0;
    }

    *val = slot->val;
    return 1;
}

void
brix_auth_l1_store(brix_auth_l1_t *cache, const u_char key[32],
    const brix_auth_cache_val_t *val, ngx_msec_t ttl_ms)
{
    brix_auth_l1_slot_t  *slot;

    if (cache == NULL || key == NULL || val == NULL || ttl_ms == 0) {
        return;
    }

    slot = &cache->slots[brix_auth_l1_index(cache, key)];
    ngx_memcpy(slot->key, key, 32);
    slot->val    = *val;
    slot->expire = ngx_current_msec + ttl_ms;
    slot->set    = 1;
}
