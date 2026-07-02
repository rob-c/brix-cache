/*
 * worker_cache.c — per-worker L1 bearer-token validation cache (see header).
 *
 * Direct-mapped: a token always hashes to one bucket, so a repeatedly-presented
 * token stays resident and keeps hitting; distinct tokens that collide simply
 * evict each other (bounded memory, no LRU bookkeeping, O(1) probe).  Lock-free
 * because it is only ever touched from the single-threaded event loop.
 */

#include "worker_cache.h"
#include "compat/crypto.h"   /* xrootd_sha256 */

#include <time.h>

/*
 * Cap on how long a validated token may be served from cache without being
 * re-validated, regardless of its `exp`.  Mirrors the SHM cache's bound so
 * revocation / key rotation is picked up within this window.  Kept in seconds
 * here (the L1 expiry is an absolute unix time).
 */
#define XROOTD_TOKEN_L1_MAX_TTL_SECS  (5 * 60)

typedef struct {
    u_char                 fp[32];     /* SHA-256(token); all-zero = empty slot */
    int64_t                expire_at;  /* unix secs; entry invalid once now >= */
    xrootd_token_claims_t  claims;     /* the cached, already-validated claims  */
} xrootd_token_l1_slot_t;

struct xrootd_token_l1_s {
    ngx_uint_t               nslots;
    xrootd_token_l1_slot_t  *slots;
};

xrootd_token_l1_t *
xrootd_token_l1_create(ngx_pool_t *pool, ngx_uint_t slots)
{
    xrootd_token_l1_t  *cache;

    if (slots < 64) {
        slots = 64;
    }

    cache = ngx_pcalloc(pool, sizeof(*cache));
    if (cache == NULL) {
        return NULL;
    }

    cache->slots = ngx_pcalloc(pool, slots * sizeof(xrootd_token_l1_slot_t));
    if (cache->slots == NULL) {
        return NULL;
    }
    cache->nslots = slots;
    return cache;
}

/*
 * Fingerprint the token and pick its bucket.  Returns 0 on hash failure (caller
 * treats it as a miss / no-op).  The bucket index is derived from the first four
 * fingerprint bytes — uniformly distributed for SHA-256 output.
 */
static int
xrootd_token_l1_locate(xrootd_token_l1_t *cache, const char *token,
    size_t token_len, u_char fp[32], ngx_uint_t *idx)
{
    uint32_t  h;

    if (xrootd_sha256((const u_char *) token, token_len, fp) != 1) {
        return 0;
    }
    h = ((uint32_t) fp[0] << 24) | ((uint32_t) fp[1] << 16)
      | ((uint32_t) fp[2] << 8) | (uint32_t) fp[3];
    *idx = (ngx_uint_t) (h % cache->nslots);
    return 1;
}

int
xrootd_token_l1_lookup(xrootd_token_l1_t *cache, const char *token,
    size_t token_len, xrootd_token_claims_t *claims)
{
    xrootd_token_l1_slot_t  *slot;
    u_char                   fp[32];
    ngx_uint_t               idx;

    if (cache == NULL || token == NULL || token_len == 0) {
        return 0;
    }
    if (!xrootd_token_l1_locate(cache, token, token_len, fp, &idx)) {
        return 0;
    }

    slot = &cache->slots[idx];
    if (slot->expire_at == 0
        || ngx_memcmp(slot->fp, fp, sizeof(fp)) != 0)
    {
        return 0;                          /* empty slot or different token */
    }
    if (slot->expire_at <= (int64_t) time(NULL)) {
        return 0;                          /* stale — force re-validation */
    }

    *claims = slot->claims;                /* struct copy of validated claims */
    return 1;
}

void
xrootd_token_l1_store(xrootd_token_l1_t *cache, const char *token,
    size_t token_len, const xrootd_token_claims_t *claims)
{
    xrootd_token_l1_slot_t  *slot;
    u_char                   fp[32];
    ngx_uint_t               idx;
    int64_t                  now, expire_at;

    if (cache == NULL || token == NULL || token_len == 0) {
        return;
    }
    if (!xrootd_token_l1_locate(cache, token, token_len, fp, &idx)) {
        return;
    }

    now = (int64_t) time(NULL);
    if (claims->exp <= 0) {
        expire_at = now + XROOTD_TOKEN_L1_MAX_TTL_SECS;
    } else {
        if (claims->exp <= now) {
            return;                        /* already expired — don't cache */
        }
        expire_at = claims->exp;
        if (expire_at > now + XROOTD_TOKEN_L1_MAX_TTL_SECS) {
            expire_at = now + XROOTD_TOKEN_L1_MAX_TTL_SECS;
        }
    }

    slot = &cache->slots[idx];
    ngx_memcpy(slot->fp, fp, sizeof(fp));
    slot->claims    = *claims;
    slot->expire_at = expire_at;
}
