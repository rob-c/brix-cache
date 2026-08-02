/*
 * exchange_cache.c — per-worker token-exchange result cache (see header).
 *
 * WHAT: Direct-mapped (subject-token, audience) → minted-token cache with a
 *       hard TTL clamp, for the phase-70 §5.4 EXCHANGE leg.
 *
 * WHY:  Re-POSTing the RFC-8693 grant to the issuer on every VFS op is pure
 *       latency and issuer load; but a cache over credentials must (a) bind
 *       entries to the exact subject token so no principal can ever receive
 *       another's minted token, and (b) bound how long a revoked/rotated grant
 *       can keep being replayed. SHA-256 keying gives (a); the
 *       min(exp, +5 min) clamp gives (b).
 *
 * HOW:  Mirrors worker_cache.c: one slot per hash bucket, colliding keys evict
 *       each other, no LRU bookkeeping, event-loop-only so lock-free. The
 *       minted token's `exp` is read by splitting the compact JWS and decoding
 *       its payload (no signature work — the issuer minted it over TLS a
 *       moment ago); an unparseable or already-expired mint is simply not
 *       cached. Tokens are secrets: nothing from a slot is ever logged.
 */
#include "exchange_cache.h"
#include "b64url.h"
#include "json.h"
#include "core/compat/crypto.h"   /* brix_sha256 */

/* A minted token larger than this is served uncached rather than truncated. */
#define BRIX_TX_CACHE_TOKEN_MAX  4096

typedef struct {
    u_char   fp[32];        /* SHA-256(subject ‖ 0x0A ‖ aud); all-zero = empty */
    time_t   expire_at;     /* absolute unix secs; invalid once now >= this    */
    size_t   len;           /* minted token length                             */
    u_char   token[BRIX_TX_CACHE_TOKEN_MAX + 1];   /* NUL-terminated           */
} brix_tx_cache_slot_t;

struct brix_tx_cache_s {
    ngx_uint_t             nslots;
    brix_tx_cache_slot_t  *slots;
};

brix_tx_cache_t *
brix_tx_cache_create(ngx_pool_t *pool, ngx_uint_t slots)
{
    brix_tx_cache_t *c;

    if (pool == NULL || slots == 0) {
        return NULL;
    }

    c = ngx_pcalloc(pool, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    c->slots = ngx_pcalloc(pool, slots * sizeof(brix_tx_cache_slot_t));
    if (c->slots == NULL) {
        return NULL;
    }
    c->nslots = slots;
    return c;
}

/* ---- tx_cache_slot_for -----------------------------------------------------
 *
 * WHAT: Hash (subject, aud) to the one slot that key can occupy, writing the
 *       32-byte fingerprint to `fp`.
 *
 * WHY:  The fingerprint covers the FULL subject token bytes — two different
 *       client tokens (even for the same principal) never share a slot hit —
 *       and a 0x0A separator keeps (s="a", aud="b") distinct from (s="ab").
 *       JWT text is base64url + dots, so 0x0A cannot occur inside either part.
 *
 * HOW:  One incremental-free SHA-256 over a small stitched stack buffer would
 *       need subject-sized stack; instead hash the concatenation via two
 *       passes folded with the streaming-free helper: SHA-256(subject) is
 *       computed first, then SHA-256(that digest ‖ 0x0A ‖ aud). Collision
 *       resistance is inherited from SHA-256 composition. */
static brix_tx_cache_slot_t *
tx_cache_slot_for(brix_tx_cache_t *c, const ngx_str_t *subject,
    const ngx_str_t *aud, u_char fp[32])
{
    u_char      inner[32];
    u_char      buf[32 + 1 + 512];
    size_t      alen;
    ngx_uint_t  idx;

    if (brix_sha256(subject->data, subject->len, inner) != 1) {
        return NULL;
    }

    alen = (aud != NULL && aud->data != NULL) ? aud->len : 0;
    if (alen > 512) {
        return NULL;   /* audiences are short URLs; refuse rather than clip */
    }

    ngx_memcpy(buf, inner, 32);
    buf[32] = 0x0A;
    if (alen > 0) {
        ngx_memcpy(buf + 33, aud->data, alen);
    }
    if (brix_sha256(buf, 33 + alen, fp) != 1) {
        return NULL;
    }

    idx = ((ngx_uint_t) fp[0] << 24 | (ngx_uint_t) fp[1] << 16
           | (ngx_uint_t) fp[2] << 8 | (ngx_uint_t) fp[3]) % c->nslots;
    return &c->slots[idx];
}

int
brix_tx_cache_lookup(brix_tx_cache_t *cache, const ngx_str_t *subject,
    const ngx_str_t *aud, time_t now, ngx_str_t *out)
{
    u_char                 fp[32];
    brix_tx_cache_slot_t  *slot;

    if (cache == NULL || subject == NULL || subject->len == 0 || out == NULL) {
        return 0;
    }

    slot = tx_cache_slot_for(cache, subject, aud, fp);
    if (slot == NULL || slot->len == 0
        || ngx_memcmp(slot->fp, fp, sizeof(fp)) != 0) {
        return 0;
    }
    if (now >= slot->expire_at) {
        slot->len = 0;   /* dead entry — free the slot eagerly */
        return 0;
    }

    out->data = slot->token;
    out->len  = slot->len;
    return 1;
}

/* ---- tx_cache_minted_exp ---------------------------------------------------
 *
 * WHAT: Read the `exp` claim out of the freshly-minted compact JWS; 0 when the
 *       token cannot be parsed or carries no positive exp.
 *
 * WHY:  The cache must never outlive the credential itself — `exp` is the
 *       issuer's own bound and the base the 5-minute clamp tightens. */
static time_t
tx_cache_minted_exp(const ngx_str_t *minted)
{
    xrdjwt_seg  seg[3];
    u_char      payload[8192];
    ssize_t     plen;
    int64_t     exp = 0;

    if (xrdjwt_split((const char *) minted->data, minted->len, seg) != 0) {
        return 0;
    }
    plen = b64url_decode(seg[1].p, seg[1].n, payload, sizeof(payload));
    if (plen <= 0) {
        return 0;
    }
    if (json_get_int64((const char *) payload, (size_t) plen, "exp", &exp) != 0
        || exp <= 0) {
        return 0;
    }
    return (time_t) exp;
}

void
brix_tx_cache_store(brix_tx_cache_t *cache, const ngx_str_t *subject,
    const ngx_str_t *aud, const ngx_str_t *minted, time_t now)
{
    u_char                 fp[32];
    time_t                 exp, cap;
    brix_tx_cache_slot_t  *slot;

    if (cache == NULL || subject == NULL || subject->len == 0
        || minted == NULL || minted->len == 0 || minted->data == NULL
        || minted->len > BRIX_TX_CACHE_TOKEN_MAX) {
        return;
    }

    exp = tx_cache_minted_exp(minted);
    if (exp <= now) {
        return;   /* unparseable or already expired — never cache blind */
    }

    cap = now + BRIX_TX_CACHE_MAX_TTL_SECS;
    slot = tx_cache_slot_for(cache, subject, aud, fp);
    if (slot == NULL) {
        return;
    }

    ngx_memcpy(slot->fp, fp, sizeof(fp));
    ngx_memcpy(slot->token, minted->data, minted->len);
    slot->token[minted->len] = '\0';
    slot->len       = minted->len;
    slot->expire_at = (exp < cap) ? exp : cap;
}
