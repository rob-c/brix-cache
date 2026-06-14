/*
 * rate_limit.c — token-bucket rate limiter over the KV store (see header).
 */
#include "ngx_xrootd_module.h"
#include "shm/rate_limit.h"

/*
 * Per-identity bucket state stored verbatim as the KV value.
 *
 * WHAT: the entire mutable token-bucket state for one identity — token count
 *       plus the wall-clock timestamp the count was last brought current.
 * WHY:  the KV value is an opaque fixed-width byte blob (memcpy'd in/out of the
 *       shared slot), so the struct IS the on-shm record; its size must not
 *       exceed the zone's val_max (checked at config time, see directive).
 * HOW:  read with xrootd_kv_get into a stack copy, mutated locally, written
 *       back with xrootd_kv_set.  No pointers — safe to copy across the
 *       process boundary into shared memory.  sizeof() is typically 16 bytes
 *       (4-byte tokens + ngx_msec_t, modulo alignment padding).
 */
typedef struct {
    uint32_t    tokens;       /* tokens currently available */
    ngx_msec_t  last_refill;  /* ngx_current_msec of the last refill */
} xrootd_rl_val_t;

/* KV key is "rl:" + raw identity bytes; the prefix namespaces rate-limit
 * entries so a single zone could be shared with other "rl:"-free consumers. */
#define XROOTD_RL_KEY_PREFIX_LEN  3   /* "rl:" */
#define XROOTD_RL_ID_MAX          256 /* identity bytes hashed; longer ids are truncated */

/*
 * xrootd_rate_limit_check() — one token-bucket admission test for `id`.
 *
 * WHAT: refill the identity's bucket by elapsed time, spend one token, and
 *       return NGX_OK (admit) or NGX_DECLINED (empty bucket — reject).
 * WHY:  bucket state is shared across all workers via the KV zone, so the
 *       limit is global, not per-worker.
 * HOW (locking / consistency): this function takes NO lock itself.  Each of
 *       the xrootd_kv_get and xrootd_kv_set calls grabs and releases the
 *       zone's shared spinlock independently (see kv.c).  The read-modify-write
 *       is therefore NOT atomic: two workers can both read the same token count
 *       and both spend it, so the effective limit may over-admit slightly under
 *       contention.  This is the deliberate "best-effort" contract documented
 *       in rate_limit.h — acceptable for request throttling, and it keeps the
 *       critical section to a single O(1) probe with no callback inside it.
 */
ngx_int_t
xrootd_rate_limit_check(const xrootd_rate_limit_conf_t *rl,
    const char *id, size_t id_len)
{
    u_char           key[XROOTD_RL_KEY_PREFIX_LEN + XROOTD_RL_ID_MAX];
    size_t           key_len;
    xrootd_rl_val_t  v;
    size_t           vlen = sizeof(v);
    ngx_msec_t       now, elapsed, ttl;
    uint32_t         refill;

    /* Fail-open: a missing zone or zeroed rate/burst means the directive was
     * never configured for this scope, so admit unconditionally rather than
     * dividing by zero in the ttl computation below. */
    if (rl == NULL || rl->kv == NULL || rl->rate == 0 || rl->burst == 0) {
        return NGX_OK;                       /* disabled — admit */
    }
    /* Clamp the identity to the fixed key buffer; the stack `key` array is
     * exactly PREFIX_LEN + XROOTD_RL_ID_MAX bytes, so this bounds the memcpy
     * below and prevents a stack overflow on an attacker-influenced id_len. */
    if (id_len > XROOTD_RL_ID_MAX) {
        id_len = XROOTD_RL_ID_MAX;
    }

    /* Build "rl:" + id in place; key_len is the exact span hashed by the KV
     * layer (no NUL terminator — these are length-counted opaque bytes). */
    key[0] = 'r'; key[1] = 'l'; key[2] = ':';
    ngx_memcpy(key + XROOTD_RL_KEY_PREFIX_LEN, id, id_len);
    key_len = XROOTD_RL_KEY_PREFIX_LEN + id_len;

    now = ngx_current_msec;

    /* Pre-seed `v` with a full, freshly-refilled bucket.  xrootd_kv_get only
     * overwrites &v on a hit, so on a miss (new identity, or an entry the KV
     * layer lazily evicted as TTL-expired) these defaults stand — a first-seen
     * caller starts with the full burst allowance.  vlen is passed by-ref and
     * clamped by the KV layer to the stored val_len. */
    v.tokens      = rl->burst;
    v.last_refill = now;
    (void) xrootd_kv_get(rl->kv, key, key_len, &v, &vlen);

    /* Refill proportional to elapsed time.  When no whole token has accrued,
     * leave last_refill untouched so the fractional remainder keeps building
     * across calls rather than being discarded. */
    /* elapsed is unsigned ngx_msec_t arithmetic.  In normal operation now >=
     * last_refill; should the monotonic-ish clock ever go backwards the wrap
     * yields a huge elapsed, but refill is then clamped to burst below, so the
     * worst case is one over-full bucket, never a deficit. */
    elapsed = now - v.last_refill;
    if (elapsed > 0) {
        /* tokens accrued = elapsed_ms * rate_per_sec / 1000.  64-bit product
         * before the divide avoids overflow for large elapsed*rate; the result
         * fits uint32_t because it is immediately capped at burst. */
        refill = (uint32_t) ((uint64_t) elapsed * rl->rate / 1000ULL);
        if (refill > 0) {
            uint64_t t = (uint64_t) v.tokens + refill;
            v.tokens      = (t > rl->burst) ? rl->burst : (uint32_t) t;
            /* Only advance last_refill when at least one whole token accrued.
             * Leaving it untouched when refill == 0 preserves the sub-token
             * fractional remainder: it keeps accumulating in `elapsed` across
             * calls instead of being silently rounded down to zero each time,
             * which would otherwise cap the effective rate below `rate`. */
            v.last_refill = now;
        }
    }

    /* Per-entry TTL = time to refill an empty bucket to full + 1s slack.
     * WHY: once this many ms pass with no traffic the bucket would be full
     * anyway, so letting the KV layer lazily evict the idle entry on its next
     * probe is free — it just re-seeds to a full bucket on the next request.
     * Division by rl->rate is safe: the rate==0 fail-open guard above
     * guarantees rate is non-zero here. */
    ttl = (ngx_msec_t) ((uint64_t) rl->burst * 1000 / rl->rate) + 1000;

    /* Empty bucket: persist the (refilled-but-still-zero) state so last_refill
     * advances, then reject.  We still write so the next caller's elapsed is
     * measured from now, not from the original last_refill. */
    if (v.tokens == 0) {
        (void) xrootd_kv_set(rl->kv, key, key_len, &v, sizeof(v), ttl);
        return NGX_DECLINED;                 /* bucket empty — reject */
    }

    /* Spend one token for this request and write the bucket back.  The set may
     * silently fail (zone full at the 0.5 load-factor cap, see kv.c); we ignore
     * that and admit — failing open is the right call for a throttle whose
     * state store is momentarily saturated. */
    v.tokens--;
    (void) xrootd_kv_set(rl->kv, key, key_len, &v, sizeof(v), ttl);
    return NGX_OK;
}

/*
 * xrootd_rate_limit_directive() — parse and bind one
 *   xrootd_rate_limit zone=<name> rate=<N>r/s burst=<N> [key=dn|ip];
 *
 * WHAT: validate the args, resolve the named KV zone, and populate the
 *       xrootd_rate_limit_conf_t embedded in the caller's conf struct.
 * WHY:  this is the only place rl->kv is set, so a parse failure here leaves
 *       kv == NULL and xrootd_rate_limit_check() fails open (admits).
 * HOW:  cmd->offset is the byte offset of the embedded conf field within the
 *       owning module's conf struct — the usual ngx_command_t pattern for a
 *       sub-struct that has no dedicated NGX_*_CONF_OFFSET slot.
 */
char *
xrootd_rate_limit_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    /* Reach the embedded conf field by raw offset (see doc comment). */
    xrootd_rate_limit_conf_t *rl =
        (xrootd_rate_limit_conf_t *) ((char *) conf + cmd->offset);
    ngx_str_t   *value = cf->args->elts;
    ngx_str_t    zone  = ngx_null_string;
    ngx_uint_t   rate  = 0;
    ngx_uint_t   burst = 0;
    ngx_uint_t   key_ip = 0;
    ngx_uint_t   i;
    ngx_int_t    n;
    xrootd_kv_t *kv;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            zone.data = value[i].data + 5;
            zone.len  = value[i].len - 5;

        } else if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {
            u_char *p = value[i].data + 5;
            size_t  len = value[i].len - 5;
            /* accept "<N>r/s" or bare "<N>" */
            if (len > 3 && ngx_strncmp(p + len - 3, "r/s", 3) == 0) {
                len -= 3;
            }
            n = ngx_atoi(p, len);
            if (n == NGX_ERROR || n <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid xrootd_rate_limit rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            rate = (ngx_uint_t) n;

        } else if (ngx_strncmp(value[i].data, "burst=", 6) == 0) {
            n = ngx_atoi(value[i].data + 6, value[i].len - 6);
            if (n == NGX_ERROR || n <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid xrootd_rate_limit burst \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            burst = (ngx_uint_t) n;

        } else if (ngx_strncmp(value[i].data, "key=", 4) == 0) {
            /* len == 6 pins the value to exactly two bytes ("key=" + 2), so
             * "ip"/"dn" match strictly and e.g. "key=ipv6" is rejected rather
             * than prefix-matching "ip". */
            if (value[i].len == 6
                && ngx_strncmp(value[i].data + 4, "ip", 2) == 0) {
                key_ip = 1;
            } else if (value[i].len == 6
                && ngx_strncmp(value[i].data + 4, "dn", 2) == 0) {
                key_ip = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_rate_limit key must be dn or ip, got \"%V\"",
                    &value[i]);
                return NGX_CONF_ERROR;
            }

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid xrootd_rate_limit parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (zone.len == 0 || rate == 0 || burst == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_rate_limit requires zone=<name> rate=<N>r/s burst=<N>");
        return NGX_CONF_ERROR;
    }

    /* The zone must already exist: xrootd_kv_zone is processed earlier in the
     * same main block and registers into the module-wide registry that
     * xrootd_kv_find searches by name. */
    kv = xrootd_kv_find(&zone);
    if (kv == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_rate_limit: unknown zone \"%V\" "
            "(declare it with xrootd_kv_zone first)", &zone);
        return NGX_CONF_ERROR;
    }
    /* Refuse a zone whose value slots cannot hold a whole bucket record;
     * otherwise xrootd_kv_set would truncate/reject the value at runtime and
     * the limiter would silently malfunction.  This is the compile-time-style
     * guard that lets xrootd_rate_limit_check() memcpy the struct without
     * re-checking sizes on every request. */
    if (kv->val_max < sizeof(xrootd_rl_val_t)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_rate_limit zone \"%V\" too small: need val>=%uz",
            &zone, sizeof(xrootd_rl_val_t));
        return NGX_CONF_ERROR;
    }

    rl->kv     = kv;
    rl->rate   = rate;
    rl->burst  = burst;
    rl->key_ip = key_ip;
    return NGX_CONF_OK;
}
