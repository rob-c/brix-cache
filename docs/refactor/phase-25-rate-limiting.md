# Phase 25 — Advanced Rate Limiting & Traffic Shaping

**Status:** IMPLEMENTED — 2026-06-13 (verified against `src/ratelimit/`). All of
Steps A–I landed and tested (`tests/test_phase25_ratelimit.py`, 15 tests); a W7
per-principal *concurrency* limiter was added beyond the original draft and now
covers **both** the HTTP/WebDAV and `root://` stream planes (stream support added
2026-06-13 — see W7 row and "Resolved" below).  
**Effort:** Large (≈ 2,200 LoC new, ≈ 400 LoC integration across callers)  
**Depends on:** Phase 2 (identity unification), Phase 3 (path resolution)  
**Optional dependency:** Phase 20 (SHM KV store) — see Step A note

> The sections below are the original design plan, preserved for context. The
> reconciliation table immediately following is the authoritative current status.

---

## Implementation status (2026-06-13, vs `src/ratelimit/`)

The implementation matches the plan closely and is functionally complete. The
draft's planned file/symbol names differ from what shipped (consolidated into
fewer files); the table maps plan → actual code.

| Plan step | Status | Where (actual) |
|---|---|---|
| **A** — SHM zone init + LRU eviction | **DONE** | `ratelimit_zone.c`: `xrootd_rl_init_zone`, `xrootd_rl_zone_add/_get/_zones_all`, `xrootd_rl_evict_oldest_locked`, rbtree+LRU per `xrootd_rl_shctx_t` |
| **B** — Leaky-bucket core (req check + bw pre-check + charge) | **DONE** | `ratelimit.c`: `xrootd_rl_check`, `xrootd_rl_bw_check`, `xrootd_rl_charge_bytes`, `xrootd_rl_snapshot` (fail-open on zone exhaustion) |
| **C** — Key extraction (VO / ISSUER / IP / DN / VOLUME) | **DONE** | `ratelimit_keys.c`: `xrootd_rl_key_stream`, `xrootd_rl_key_http`; DN is **FNV-1a32-hashed** into the key (`rl_key_dn_hash`); VOLUME = longest-prefix match → `NGX_DECLINED` when no match |
| **D** — HTTP/WebDAV enforcement (429 + Retry-After; bw charge) | **DONE** | `ratelimit_http.c`: `xrootd_rl_http_access_handler` (`rl_reject` → 429+Retry-After), `xrootd_rl_http_log_handler` (bandwidth charge + concurrency release in LOG phase) |
| **E** — XRootD stream enforcement (`kXR_wait`; bw charge) | **DONE** | `ratelimit_stream.c`: `xrootd_rl_stream_gate` (`xrootd_rl_check` + `xrootd_rl_bw_check` → `xrootd_send_wait`), `xrootd_rl_charge_ctx` (post-send); opcode gating `rl_op_rate_limited`/`rl_op_path_bearing` |
| **F** — Config directives | **DONE (renamed)** | `xrootd_rate_limit_zone` (stream-main + http-main), `xrootd_rate_limit_rule` (stream-srv + http-loc), `xrootd_bandwidth_limit` (stream-srv + http-loc), `xrootd_concurrency_limit` (**stream-srv + http-loc**). Setters in `ratelimit_keys.c`; rules stored in `rl_rules` arrays on srv/loc conf |
| **G** — Metrics | **DONE** | `src/metrics/ratelimit.c` `xrootd_export_ratelimit_metrics` → `rl_throttled_http_total`, `rl_throttled_stream_total`, `rl_eviction_total`, `rl_zone_full_errors` |
| **H** — Dashboard endpoint | **DONE (path differs)** | `GET /xrootd/api/v1/ratelimit` (not `/api/v1/ratelimit/status`) → `dashboard_build_v1_ratelimit` (`src/dashboard/api.c`) via `xrootd_rl_snapshot`, sorted by throttle_count |
| **I** — Integration (dispatch gate + read/write bw charge) | **DONE** | Stream gate in dispatch; `xrootd_rl_charge_ctx` at read/write send sites |
| **W7** — Per-principal concurrency cap | **DONE (HTTP + stream)** | *Beyond the original draft.* `xrootd_rl_conc_acquire/_release`, `req_conc`/`in_flight` on the node, `xrootd_concurrency_limit` directive. **HTTP**: acquired in the access handler, released in the LOG phase (per-request, leak-free). **Stream** (`root://`): acquired once in `xrootd_rl_stream_gate` on the first matching rule (over-cap → `kXR_wait`), slot stashed on `ctx->rl_conc_rule`/`rl_conc_key`, released once for the connection's lifetime via `xrootd_rl_release_ctx` in `xrootd_on_disconnect` (no LOG phase on the stream plane) |

### Deviations from the draft (intentional, no action needed)

- **Files consolidated**: planned `zone.c`/`keys.c`/`http_handler.c`/`stream_check.c`/`hash.c`
  shipped as `ratelimit_zone.c` / `ratelimit_keys.c` (keys **and** directive setters)
  / `ratelimit_http.c` / `ratelimit_stream.c`, with the hash folded into
  `ratelimit_zone.c`. Core = `ratelimit.c`; metrics = `src/metrics/ratelimit.c`.
- **Hash**: **FNV-1a32** (`xrootd_rl_hash`), not the planned xxhash32.
- **Directive names**: `xrootd_rate_limit_rule` (not `xrootd_rate_limit`) to avoid
  colliding with the unrelated Phase-20 `xrootd_rate_limit`; concurrency uses
  `xrootd_concurrency_limit`.
- **Dashboard path**: `/xrootd/api/v1/ratelimit`.
- **Tests**: `tests/test_phase25_ratelimit.py` (15 tests), not `tests/test_ratelimit.py`.

### Resolved

- **Stream-plane concurrency limiting (W7)** — *Closed 2026-06-13.*
  `xrootd_concurrency_limit` is now registered in the stream srv command table
  (`src/stream/module.c`, reusing the conf-agnostic `xrootd_rl_conc_directive`), and
  `xrootd_rl_stream_gate` calls `xrootd_rl_conc_acquire` on the first matching rule.
  Because the stream plane has **no LOG phase**, the slot is reserved per-connection
  (not per-request): it is stashed on `ctx->rl_conc_rule`/`ctx->rl_conc_key`
  (`src/core/types/context.h`) when acquired and released exactly once via the new
  `xrootd_rl_release_ctx` from `xrootd_on_disconnect` (`src/connection/disconnect.c`).
  This caps **concurrent connections per principal**; over-cap returns
  `kXR_wait(1)` so the client retries when a slot frees. Per-principal in-flight
  caps now apply to both `davs://`/HTTP and `root://`. Build clean; the stream
  directive parses (`nginx -t`).

  > Semantics note: HTTP counts each request, stream counts each connection (the
  > natural unit on a plane with no per-request teardown). A single `key=` and
  > `limit=` on a stream rule therefore bounds concurrent root:// connections from
  > that principal.

### Pending / incomplete
- **Bandwidth pre-check is conservative** — `xrootd_rl_bw_check` throttles on the
  *previous* excess and charges nothing up front (bytes are charged post-send via
  `xrootd_rl_charge_bytes`/`xrootd_rl_charge_ctx`); a burst can momentarily exceed
  the cap by up to one response before the bucket catches up. This is by design
  (matches the draft) — noted for operators, not a bug.

---

## Motivation

`ngx_http_limit_req_module` enforces request rates by IP or cookie — too coarse for HEP storage
gateways.  A Tier-1 site needs policies like:

- `/atlas` VO: 500 kXR_read/s global, burst to 800 — no single VO starves the bus
- Token issuer `https://wlcg.cern.ch/`: 200 r/s WebDAV GET — cap WLCG bulk traffic
- `/store/tape`: 50 MiB/s aggregate bandwidth — protect tape-backed paths
- Anonymous IP: 10 r/s, no burst — block bulk unauthenticated scanners

The XRootD wire protocol has a first-class mechanism for backpressure: `kXR_wait(seconds)` tells
the client to retry after a hold-off.  HTTP callers receive a standard 429.  This plan implements
leaky-bucket rate limiting keyed on XRootD-specific metadata (VO group, token issuer, storage
volume prefix, DN, IP) across both the stream and HTTP/WebDAV planes.

---

## Algorithm: Leaky Bucket (matching nginx convention)

Token bucket fills at burst capacity and drains at the configured rate.  We use the same
formulation as `ngx_http_limit_req_module`:

```
elapsed_ms   = now_ms - node->last
excess       = node->req_excess - (req_rate_per_s * elapsed_ms / 1000)
excess       = max(0, excess)
node->last   = now_ms
if excess + 1000 > burst * 1000:
    throttle (return wait or 429)
else:
    node->req_excess = excess + 1000  /* charge one request unit */
```

`req_rate_per_s` and `burst` are stored × 1000 to avoid floating-point in the kernel path.
Bandwidth throttling uses the same formula but charges `bytes_sent × 1000` instead of `1000`.

---

## Data Structures

### `src/ratelimit/ratelimit.h`

```c
#ifndef XROOTD_RATELIMIT_H
#define XROOTD_RATELIMIT_H

#include "../ngx_xrootd_module.h"

/* Key dimensions for rate limit lookup. */
typedef enum {
    XROOTD_RL_KEY_VO      = 0,   /* ctx->primary_vo / wctx->identity->vo_csv  */
    XROOTD_RL_KEY_ISSUER  = 1,   /* ctx->identity->issuer                      */
    XROOTD_RL_KEY_IP      = 2,   /* ctx->peer_ip / r->connection->addr_text    */
    XROOTD_RL_KEY_DN      = 3,   /* ctx->dn / wctx->dn                         */
    XROOTD_RL_KEY_VOLUME  = 4,   /* longest-prefix match on resolved path      */
} xrootd_rl_key_type_t;

/* One entry in the rate-limit SHM rbtree. */
#define XROOTD_RL_KEY_LEN  128

typedef struct {
    ngx_rbtree_node_t  rbn;               /* key = xxhash32 of key_str             */
    ngx_msec_t         last;              /* timestamp of last request (ms)         */
    ngx_uint_t         req_excess;        /* leaky-bucket excess × 1000             */
    ngx_uint_t         bw_excess;         /* bandwidth excess × 1000 (bytes/s)      */
    uint64_t           req_total;         /* cumulative requests since node created  */
    uint64_t           bytes_total;       /* cumulative bytes since node created     */
    uint32_t           throttle_count;    /* times this key was throttled           */
    char               key_str[XROOTD_RL_KEY_LEN];  /* displayable key (dashboard) */
} xrootd_rl_node_t;

/* SHM zone header (one per `xrootd_rate_limit_zone` directive). */
typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_shmtx_t        mutex;
    ngx_shmtx_sh_t     mutex_lock;
    ngx_uint_t         node_count;
    ngx_uint_t         evict_count;      /* nodes pruned by LRU eviction          */
} xrootd_rl_zone_t;

/* One rate-limit rule (from config). */
typedef struct {
    xrootd_rl_key_type_t  key_type;
    ngx_str_t             key_match;    /* "" = wildcard; "/atlas" = VO prefix     */
    ngx_uint_t            req_rate;     /* req/s × 1000 (0 = no req-rate limit)    */
    ngx_uint_t            req_burst;    /* max excess tokens × 1000               */
    ngx_uint_t            bw_rate;      /* bytes/s (0 = no bandwidth limit)        */
    ngx_uint_t            bw_burst;     /* max bandwidth burst in bytes            */
    ngx_flag_t            nodelay;      /* 1 = reject immediately; 0 = kXR_wait/429 */
} xrootd_rl_rule_t;

/* Zone handle (runtime, per config). */
typedef struct {
    ngx_shm_zone_t       *shm_zone;
    ngx_str_t             name;
    size_t                size;
} xrootd_rl_zone_handle_t;

/*
 * Public API used by stream dispatch and HTTP access handlers.
 *
 * xrootd_rl_check — look up or create a node for `key_str` in `zone`, apply
 *                   `rule`.  Returns NGX_OK (allowed), NGX_AGAIN (throttled:
 *                   *wait_seconds set for kXR_wait), or NGX_ERROR (internal).
 *
 * xrootd_rl_charge_bytes — update bandwidth bucket after response is sent.
 *                          Call after xrootd_send_ok or ngx_http_output_filter.
 */
ngx_int_t xrootd_rl_check(xrootd_rl_zone_t *zone, xrootd_rl_rule_t *rule,
    const char *key_str, uint32_t *wait_seconds);
void xrootd_rl_charge_bytes(xrootd_rl_zone_t *zone, xrootd_rl_rule_t *rule,
    const char *key_str, size_t nbytes);

/* Dashboard snapshot (copies nodes under lock; caller allocates nodes array). */
typedef struct {
    char     key_str[XROOTD_RL_KEY_LEN];
    uint64_t req_total;
    uint64_t bytes_total;
    uint32_t throttle_count;
    ngx_uint_t req_excess;
    ngx_uint_t bw_excess;
} xrootd_rl_snapshot_entry_t;

ngx_int_t xrootd_rl_snapshot(xrootd_rl_zone_t *zone,
    xrootd_rl_snapshot_entry_t *out, ngx_uint_t max, ngx_uint_t *count);

#endif /* XROOTD_RATELIMIT_H */
```

### Key string construction

The lookup key is a human-readable string formatted as `<type>:<value>` so the same node is
always found for the same logical principal regardless of which worker evaluates it:

| Key type | Format | Example |
|---|---|---|
| `VO`     | `vo:<primary_vo>` | `vo:/atlas/Role=production` |
| `ISSUER` | `iss:<issuer_url>` | `iss:https://wlcg.cern.ch/` |
| `IP`     | `ip:<addr>` | `ip:192.168.1.42` |
| `DN`     | `dn:<sha256_hex[16]>` | `dn:a3f0...` (hash to fit 128 chars) |
| `VOLUME` | `vol:<path_prefix>` | `vol:/store/tape` |

The rbtree node key (`rbn.key`) is `xxhash32(key_str)` — collision probability across < 10 k
active principals is negligible and a collision only causes two different principals to share a
bucket, a safe degradation.

---

## Step A — SHM Zone Initialization

**File:** `src/ratelimit/zone.c`

Mirrors the pattern from `src/manager/registry.c` and `src/metrics/metrics.c`.

```c
/* Called from ngx_http_xrootd_webdav_module postconfiguration. */
ngx_int_t
xrootd_rl_zone_init(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_rl_zone_t *zone;

    if (data) {
        /* Nginx reload: share existing zone across the reload boundary. */
        shm_zone->data = data;
        return NGX_OK;
    }

    zone = ngx_slab_calloc(shm_zone->shm.addr, sizeof(*zone));
    if (zone == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&zone->rbtree, &zone->sentinel,
                    xrootd_rl_rbtree_insert_value);
    if (ngx_shmtx_create(&zone->mutex, &zone->mutex_lock, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    shm_zone->data = zone;
    return NGX_OK;
}
```

**Note:** Phase 20's KV store uses a generic SHM allocator.  Rate limiting deliberately uses its
own zone because: (a) access pattern is write-heavy with microsecond-granularity updates,
(b) eviction semantics differ from general KV, (c) separate zones allow the operator to size
them independently.

### LRU eviction

The rbtree has no built-in LRU.  When `ngx_slab_alloc` fails (zone full), scan for the node
with the smallest `last` timestamp and evict it before retrying:

```c
static xrootd_rl_node_t *
xrootd_rl_evict_oldest(xrootd_rl_zone_t *zone)
{
    ngx_rbtree_node_t   *node, *sentinel, *oldest_node;
    xrootd_rl_node_t    *oldest;
    ngx_msec_t           min_last;

    sentinel = zone->rbtree.sentinel;
    node     = zone->rbtree.root;
    min_last = NGX_MAX_UINT32_VALUE;
    oldest_node = NULL;

    /* In-order traversal to find oldest last timestamp. */
    xrootd_rl_rbtree_scan(node, sentinel, &oldest_node, &min_last);

    if (oldest_node == NULL) return NULL;

    oldest = (xrootd_rl_node_t *)oldest_node;
    ngx_rbtree_delete(&zone->rbtree, oldest_node);
    ngx_slab_free_locked(zone->shm_zone->shm.addr, oldest_node);
    zone->evict_count++;
    return NULL;  /* caller retries alloc */
}
```

Scanning is O(n) but the zone should hold several thousand nodes at most — the scan takes
< 1 µs in practice.  (Same pattern used by `ngx_http_limit_req_module`.)

---

## Step B — Core Leaky-Bucket Logic

**File:** `src/ratelimit/ratelimit.c`

```c
ngx_int_t
xrootd_rl_check(xrootd_rl_zone_t *zone, xrootd_rl_rule_t *rule,
    const char *key_str, uint32_t *wait_seconds)
{
    uint32_t            hash;
    ngx_rbtree_node_t  *node;
    xrootd_rl_node_t   *rl;
    ngx_msec_t          now, elapsed;
    ngx_uint_t          excess;
    ngx_int_t           rc = NGX_OK;

    hash = xrootd_xxhash32(key_str, ngx_strlen(key_str), 0);
    now  = ngx_current_msec;

    ngx_shmtx_lock(&zone->mutex);

    node = xrootd_rl_rbtree_lookup(&zone->rbtree, hash, key_str);

    if (node == NULL) {
        rl = ngx_slab_calloc_locked(zone->shm_zone->shm.addr, sizeof(*rl));
        if (rl == NULL) {
            xrootd_rl_evict_oldest(zone);
            rl = ngx_slab_calloc_locked(zone->shm_zone->shm.addr, sizeof(*rl));
        }
        if (rl == NULL) {
            ngx_shmtx_unlock(&zone->mutex);
            return NGX_OK;  /* fail open: prefer liveness over strict limiting */
        }
        rl->rbn.key = hash;
        ngx_cpystrn((u_char *)rl->key_str, (u_char *)key_str,
                    XROOTD_RL_KEY_LEN - 1);
        rl->last = now;
        ngx_rbtree_insert(&zone->rbtree, &rl->rbn);
        zone->node_count++;
    } else {
        rl = (xrootd_rl_node_t *)node;
    }

    /* --- request rate check --- */
    if (rule->req_rate > 0) {
        elapsed = (now >= rl->last) ? (now - rl->last) : 0;
        excess  = rl->req_excess;

        /* Drain at configured rate over elapsed interval. */
        if (excess > (ngx_uint_t)(rule->req_rate * elapsed / 1000)) {
            excess -= (ngx_uint_t)(rule->req_rate * elapsed / 1000);
        } else {
            excess = 0;
        }

        if (excess + 1000 > rule->req_burst * 1000) {
            /* Throttled — compute hold-off in seconds (ceil). */
            *wait_seconds = (uint32_t)
                ((excess + 1000 - rule->req_burst * 1000 + rule->req_rate - 1)
                 / rule->req_rate);
            rl->throttle_count++;
            rc = NGX_AGAIN;
        } else {
            rl->req_excess = excess + 1000;
            rl->last       = now;
            rl->req_total++;
        }
    }

    ngx_shmtx_unlock(&zone->mutex);
    return rc;
}

void
xrootd_rl_charge_bytes(xrootd_rl_zone_t *zone, xrootd_rl_rule_t *rule,
    const char *key_str, size_t nbytes)
{
    /*
     * Bandwidth limiting: charge after the response is sent.
     * Pre-check (in xrootd_rl_check) already gated the request; this call
     * updates the running excess for future requests.
     * Called outside of the main lock path — acquire a short spinlock here.
     */
    uint32_t            hash;
    ngx_rbtree_node_t  *node;
    xrootd_rl_node_t   *rl;
    ngx_msec_t          now, elapsed;
    ngx_uint_t          excess;

    if (rule->bw_rate == 0 || nbytes == 0) return;

    hash = xrootd_xxhash32(key_str, ngx_strlen(key_str), 0);
    now  = ngx_current_msec;

    ngx_shmtx_lock(&zone->mutex);

    node = xrootd_rl_rbtree_lookup(&zone->rbtree, hash, key_str);
    if (node == NULL) {
        ngx_shmtx_unlock(&zone->mutex);
        return;
    }

    rl = (xrootd_rl_node_t *)node;
    elapsed = (now >= rl->last) ? (now - rl->last) : 0;
    excess  = rl->bw_excess;

    if (excess > (ngx_uint_t)(rule->bw_rate * elapsed / 1000)) {
        excess -= (ngx_uint_t)(rule->bw_rate * elapsed / 1000);
    } else {
        excess = 0;
    }

    /* Charge current response bytes × 1000 against the bucket. */
    rl->bw_excess   = excess + (ngx_uint_t)(nbytes * 1000);
    rl->bytes_total += nbytes;
    rl->last         = now;

    ngx_shmtx_unlock(&zone->mutex);
}
```

### Bandwidth pre-check gate

`xrootd_rl_check` handles the request-count dimension.  Bandwidth is checked separately,
because the byte count is not known at request-dispatch time for read operations (the file
size may be unknown until `open` resolves).  The design uses a two-phase approach:

1. **Pre-check** (`xrootd_rl_bw_check`): called before read/write dispatch.  Uses the _previous
   excess_ as a conservative estimate.  If the bucket is already overflowing, throttle.
2. **Charge** (`xrootd_rl_charge_bytes`): called after response is sent with actual byte count.

```c
ngx_int_t
xrootd_rl_bw_check(xrootd_rl_zone_t *zone, xrootd_rl_rule_t *rule,
    const char *key_str, uint32_t *wait_seconds)
{
    /* Same logic as req_rate check but against bw_excess and bw_burst. */
    ...
    /* Throttled if bw_excess > bw_burst * 1000 (no +1000 charge yet). */
}
```

---

## Step C — Rate Limit Key Extraction

**File:** `src/ratelimit/keys.c`

Stream and HTTP contexts expose identity through different struct types.  A pair of extraction
functions produce a canonical `key_str` buffer given the rule's `key_type`.

```c
/* Stream plane. */
ngx_int_t
xrootd_rl_key_stream(xrootd_rl_rule_t *rule, xrootd_ctx_t *ctx,
    const char *path,  /* resolved, confined path */
    char *out, size_t out_sz)
{
    switch (rule->key_type) {

    case XROOTD_RL_KEY_VO:
        if (ctx->primary_vo[0] == '\0') {
            ngx_snprintf((u_char *)out, out_sz, "vo:(anon)");
        } else {
            ngx_snprintf((u_char *)out, out_sz, "vo:%s", ctx->primary_vo);
        }
        break;

    case XROOTD_RL_KEY_ISSUER:
        if (ctx->identity == NULL || ctx->identity->issuer.len == 0) {
            ngx_snprintf((u_char *)out, out_sz, "iss:(none)");
        } else {
            ngx_snprintf((u_char *)out, out_sz, "iss:%V",
                         &ctx->identity->issuer);
        }
        break;

    case XROOTD_RL_KEY_IP:
        ngx_snprintf((u_char *)out, out_sz, "ip:%s", ctx->peer_ip);
        break;

    case XROOTD_RL_KEY_DN:
        if (ctx->dn[0] == '\0') {
            ngx_snprintf((u_char *)out, out_sz, "dn:(none)");
        } else {
            /* Hash DN to avoid exceeding key_str length. */
            uint8_t h[8];
            xrootd_xxhash64_bytes((u_char *)ctx->dn,
                                  ngx_strlen(ctx->dn), 0, h);
            ngx_snprintf((u_char *)out, out_sz,
                "dn:%02x%02x%02x%02x%02x%02x%02x%02x",
                h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
        }
        break;

    case XROOTD_RL_KEY_VOLUME:
        /*
         * Match path against rule->key_match prefix.
         * If it matches, key = "vol:<prefix>".
         * If it does not match, this rule does not apply — caller skips.
         */
        if (rule->key_match.len > 0 &&
            ngx_strncmp(path, rule->key_match.data,
                        rule->key_match.len) != 0)
        {
            return NGX_DECLINED;  /* rule does not apply to this path */
        }
        ngx_snprintf((u_char *)out, out_sz, "vol:%V", &rule->key_match);
        break;

    default:
        return NGX_ERROR;
    }

    out[out_sz - 1] = '\0';
    return NGX_OK;
}

/* HTTP/WebDAV plane — same logic, different context struct. */
ngx_int_t
xrootd_rl_key_http(xrootd_rl_rule_t *rule, ngx_http_request_t *r,
    ngx_http_xrootd_webdav_req_ctx_t *wctx,
    const char *path, char *out, size_t out_sz);
```

**Wildcard matching:** If `rule->key_match.len == 0`, the rule applies to _all_ values of the
key type.  The key string still encodes the actual value (e.g., `vo:/cms`) so separate counters
accumulate per-VO.

---

## Step D — HTTP/WebDAV Enforcement

**File:** `src/ratelimit/http_handler.c`  
**Hook:** `NGX_HTTP_ACCESS_PHASE` — runs after auth, before content

```c
static ngx_int_t
xrootd_rl_http_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t  *lcf;
    ngx_http_xrootd_webdav_req_ctx_t   *wctx;
    xrootd_rl_rule_t                   *rules;
    xrootd_rl_zone_t                   *zone;
    ngx_uint_t                          i;
    char                                key_str[XROOTD_RL_KEY_LEN];
    uint32_t                            wait_sec;
    ngx_int_t                           rc;
    const char                         *path;

    lcf  = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    wctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    if (lcf->rl_rules == NULL || wctx == NULL) {
        return NGX_DECLINED;
    }

    zone  = lcf->rl_zone->shm_zone->data;
    rules = lcf->rl_rules->elts;
    path  = (wctx->resolved_path != NULL) ? wctx->resolved_path : "";

    for (i = 0; i < lcf->rl_rules->nelts; i++) {

        rc = xrootd_rl_key_http(&rules[i], r, wctx, path,
                                 key_str, sizeof(key_str));
        if (rc == NGX_DECLINED) continue;  /* volume prefix did not match */

        rc = xrootd_rl_check(zone, &rules[i], key_str, &wait_sec);
        if (rc == NGX_AGAIN) {
            /* Throttled */
            XROOTD_PROXY_METRIC_INC(rl_throttled_http, 1);
            xrootd_rl_metric_inc_by_key(key_str);

            if (rules[i].nodelay) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "rate limit: rejected %s (key=%s)", r->uri.data, key_str);
                return NGX_HTTP_TOO_MANY_REQUESTS;  /* 429 */
            }

            /* Set Retry-After header. */
            r->headers_out.retry_after = ngx_http_create_header(r);
            if (r->headers_out.retry_after) {
                r->headers_out.retry_after->value.data =
                    ngx_palloc(r->pool, NGX_INT_T_LEN);
                r->headers_out.retry_after->value.len =
                    ngx_sprintf(r->headers_out.retry_after->value.data,
                                "%ud", wait_sec)
                    - r->headers_out.retry_after->value.data;
            }

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "rate limit: throttling %s for %us (key=%s)",
                r->uri.data, wait_sec, key_str);
            return NGX_HTTP_TOO_MANY_REQUESTS;
        }
        /* NGX_OK — check next rule */
    }

    return NGX_DECLINED;
}
```

Registration in `src/webdav/postconfig.c` (existing file, append to `postconfig` handler):

```c
h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
if (h == NULL) return NGX_ERROR;
*h = xrootd_rl_http_handler;
```

### Bandwidth charge on HTTP send

Add a body filter that counts bytes written and calls `xrootd_rl_charge_bytes` after the chain
drains:

```c
static ngx_int_t
xrootd_rl_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t  *cl;
    size_t        nbytes = 0;
    ...
    for (cl = in; cl; cl = cl->next) {
        if (!ngx_buf_special(cl->buf)) {
            nbytes += ngx_buf_size(cl->buf);
        }
    }
    /* Call through to the next body filter first. */
    ngx_int_t rc = ngx_http_next_body_filter(r, in);
    if (nbytes > 0 && wctx->rl_key_str[0] != '\0') {
        xrootd_rl_charge_bytes(zone, rule, wctx->rl_key_str, nbytes);
    }
    return rc;
}
```

`wctx->rl_key_str` is set during the access phase handler when a bandwidth rule applies.

---

## Step E — XRootD Stream Enforcement

**File:** `src/ratelimit/stream_check.c`  
**Hook:** Called from `src/handshake/dispatch.c` before routing each opcode

The stream dispatcher already has access to `xrootd_ctx_t *ctx` and the resolved path at the
point each opcode is handled.  Rate limiting inserts a check before the handler runs:

```c
/* In src/handshake/dispatch.c, after resolve_path, before calling handler: */
static ngx_int_t
xrootd_dispatch_maybe_ratelimit(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint16_t opcode, const char *path)
{
    xrootd_stream_conf_t  *scf;
    xrootd_rl_zone_t      *zone;
    xrootd_rl_rule_t      *rules;
    ngx_uint_t             i;
    char                   key_str[XROOTD_RL_KEY_LEN];
    uint32_t               wait_sec;
    ngx_int_t              rc;

    scf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_xrootd_module);
    if (scf->rl_rules == NULL) return NGX_OK;

    zone  = scf->rl_zone->shm_zone->data;
    rules = scf->rl_rules->elts;

    for (i = 0; i < scf->rl_rules->nelts; i++) {
        rc = xrootd_rl_key_stream(&rules[i], ctx, path,
                                   key_str, sizeof(key_str));
        if (rc == NGX_DECLINED) continue;

        rc = xrootd_rl_check(zone, &rules[i], key_str, &wait_sec);
        if (rc == NGX_AGAIN) {
            XROOTD_PROXY_METRIC_INC(rl_throttled_stream, 1);
            xrootd_rl_metric_inc_by_key(key_str);

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "rate limit: kXR_wait %us for op 0x%04xd (key=%s)",
                wait_sec, opcode, key_str);

            /* kXR_wait tells the client to retry after wait_sec seconds. */
            return xrootd_send_wait(ctx, c, wait_sec);
        }
    }
    return NGX_OK;
}
```

If `xrootd_dispatch_maybe_ratelimit` returns non-`NGX_OK`, the caller returns that value
without invoking the opcode handler — the connection remains open for the client to retry.

### Which opcodes are rate-limited

Only data-plane opcodes that consume measurable resources:

| Opcode | Rate check | Bandwidth charge |
|---|---|---|
| `kXR_open` | yes (request rate) | no |
| `kXR_read`, `kXR_readv`, `kXR_pgread` | yes (both) | yes (after send) |
| `kXR_write`, `kXR_writev`, `kXR_pgwrite` | yes (both) | yes (after flush) |
| `kXR_dirlist` | yes (request rate) | no |
| `kXR_locate` | yes (request rate) | no |
| `kXR_stat` | no | no |
| `kXR_ping`, `kXR_close`, `kXR_sync` | no | no |
| `kXR_login`, `kXR_auth` | no (handled by auth_gate) | no |

Skipping stat/ping/close prevents rate limiting from interfering with keepalive and health
checks.

---

## Step F — Configuration Directives

**File:** extend `src/core/config/directives.c`; fields in `src/core/config/config.h`

### `xrootd_rate_limit_zone`

Declares a named SHM zone.  May appear in `http {}` or `stream {}` blocks.

```nginx
xrootd_rate_limit_zone zone=rl_main:10m;
```

Parsed as: name=`rl_main`, size=10 MiB.

### `xrootd_rate_limit`

Associates a leaky-bucket request-rate rule with the current location (HTTP) or server (stream).
Multiple directives stack — all matching rules are checked, first throttle wins.

```nginx
# HTTP location block:
xrootd_rate_limit zone=rl_main key=vo rate=500r/s burst=800 nodelay;
xrootd_rate_limit zone=rl_main key=issuer rate=200r/s burst=300;
xrootd_rate_limit zone=rl_main key=ip rate=10r/s burst=20 nodelay;

# Stream server block:
xrootd_rate_limit zone=rl_main key=vo rate=500r/s burst=800;
xrootd_rate_limit zone=rl_main key=volume:/store/tape rate=50r/s burst=100;
```

Parameters:
- `key=vo|issuer|ip|dn|volume[:<prefix>]` — dimension and optional match value
- `rate=<N>r/s` — steady-state rate in requests per second
- `burst=<N>` — burst headroom above rate
- `nodelay` — reject immediately (429/kXR_wait=0) instead of queuing with a hold-off

### `xrootd_bandwidth_limit`

Bandwidth limit in bytes per second.  Uses same zone and key as request-rate rules.

```nginx
xrootd_bandwidth_limit zone=rl_main key=volume:/store/tape rate=50m/s burst=200m;
xrootd_bandwidth_limit zone=rl_main key=vo rate=100m/s burst=500m;
```

Parameters:
- `rate=<N>[k|m|g]/s` — bytes/s (k=1024, m=1048576, g=1073741824)
- `burst=<N>[k|m|g]` — burst allowance in bytes

### Parsing helpers

`r/s` suffix parsed by a custom setter that calls `ngx_parse_size` for the numeric part and
validates the `/s` unit.  `m/s` parsed similarly with an IEC-binary multiplier function.

```c
static char *
ngx_conf_set_rate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t  *value = cf->args->elts;
    /* ... parse "500r/s" → 500; "50m/s" → 52428800 */
}
```

### Full example nginx.conf snippet

```nginx
http {
    xrootd_rate_limit_zone zone=rl:10m;

    server {
        listen 8443 ssl;

        location / {
            xrootd_webdav on;

            # Per-VO: 500 req/s, burst 800
            xrootd_rate_limit zone=rl key=vo rate=500r/s burst=800;
            # Per-issuer: 200 req/s, burst 300, immediate reject
            xrootd_rate_limit zone=rl key=issuer rate=200r/s burst=300 nodelay;
            # Unauthenticated IP: 10 req/s, no burst, immediate reject
            xrootd_rate_limit zone=rl key=ip rate=10r/s burst=10 nodelay;
            # Tape path: 50 req/s + 50 MiB/s bandwidth cap
            xrootd_rate_limit    zone=rl key=volume:/store/tape rate=50r/s burst=80;
            xrootd_bandwidth_limit zone=rl key=volume:/store/tape rate=50m/s burst=200m;
        }
    }
}

stream {
    xrootd_rate_limit_zone zone=rl_stream:5m;

    server {
        listen 1094;
        xrootd on;

        xrootd_rate_limit zone=rl_stream key=vo rate=500r/s burst=800;
        xrootd_rate_limit zone=rl_stream key=ip rate=50r/s burst=100 nodelay;
        xrootd_bandwidth_limit zone=rl_stream key=vo rate=200m/s burst=1g;
    }
}
```

---

## Step G — Metrics

**New metric slots** in `src/metrics/metrics.h` (extend existing enum):

```c
/* Rate limiting metrics */
ngx_atomic_t  rl_throttled_http_total;   /* HTTP/WebDAV requests returned 429  */
ngx_atomic_t  rl_throttled_stream_total; /* stream requests answered kXR_wait  */
ngx_atomic_t  rl_eviction_total;         /* SHM LRU evictions                  */
ngx_atomic_t  rl_zone_full_errors;       /* alloc failures (zone exhausted)     */
```

**Prometheus export** (`src/metrics/ratelimit.c`):

```
# HELP xrootd_rl_throttled_http_total HTTP requests throttled (429)
# TYPE xrootd_rl_throttled_http_total counter
xrootd_rl_throttled_http_total 4712

# HELP xrootd_rl_throttled_stream_total XRootD stream requests throttled (kXR_wait)
# TYPE xrootd_rl_throttled_stream_total counter
xrootd_rl_throttled_stream_total 1843

# HELP xrootd_rl_eviction_total LRU node evictions from rate limit SHM zone
# TYPE xrootd_rl_eviction_total counter
xrootd_rl_eviction_total 0

# HELP xrootd_rl_zone_full_errors_total Allocation failures in rate limit SHM zone
# TYPE xrootd_rl_zone_full_errors_total counter
xrootd_rl_zone_full_errors_total 0
```

**Per-key counters** are kept in the SHM nodes and exposed only via the dashboard API (not
Prometheus, to avoid high-cardinality label explosion — see INVARIANT 8 in CLAUDE.md).

---

## Step H — Dashboard API Endpoint

**New route** in `src/dashboard/api.c`:

```
GET /api/v1/ratelimit/status
```

Response:

```json
{
  "zone": "rl_main",
  "size_bytes": 10485760,
  "node_count": 342,
  "evict_count": 0,
  "principals": [
    {
      "key":            "vo:/atlas",
      "req_total":      8412942,
      "bytes_total":    108937461248,
      "throttle_count": 17,
      "req_excess":     0,
      "bw_excess":      0
    },
    {
      "key":            "vo:/cms",
      "req_total":      3291004,
      "bytes_total":    44010291200,
      "throttle_count": 0,
      "req_excess":     204,
      "bw_excess":      0
    }
  ]
}
```

Implementation calls `xrootd_rl_snapshot()` (≤ 256 entries by default; sorted by
`throttle_count` descending so the most-throttled principals appear first) then serialises with
jansson.  The snapshot is taken under the SHM spinlock and released before JSON serialisation to
minimise lock hold time.

---

## Step I — Integration Points Summary

| Location | Change |
|---|---|
| `src/webdav/postconfig.c` | Register `xrootd_rl_http_handler` in `NGX_HTTP_ACCESS_PHASE` |
| `src/webdav/postconfig.c` | Register `xrootd_rl_body_filter` in body filter chain |
| `src/handshake/dispatch.c` | Call `xrootd_dispatch_maybe_ratelimit` before each opcode handler |
| `src/read/read.c`, `pgread.c` | Call `xrootd_rl_charge_bytes` after `xrootd_send_ok` |
| `src/write/write.c`, `pgwrite.c` | Call `xrootd_rl_charge_bytes` after write flush |
| `src/core/config/config.h` | Add `rl_zone`, `rl_rules`, `rl_bw_rules` to loc/srv conf structs |
| `src/core/config/directives.c` | Parse `xrootd_rate_limit_zone`, `xrootd_rate_limit`, `xrootd_bandwidth_limit` |
| `src/metrics/metrics.h` | Add 4 new counters |
| `src/metrics/ratelimit.c` | New file: Prometheus export for rate limit counters |
| `src/dashboard/api.c` | New route `GET /api/v1/ratelimit/status` |

---

## New Source Files

| File | LoC | Purpose |
|---|---|---|
| `src/ratelimit/ratelimit.h` | 80 | Public API and data structures |
| `src/ratelimit/zone.c` | 120 | SHM zone init + LRU eviction |
| `src/ratelimit/ratelimit.c` | 200 | Leaky-bucket core: check + charge |
| `src/ratelimit/keys.c` | 150 | Key string extraction (stream + HTTP) |
| `src/ratelimit/http_handler.c` | 160 | NGX_HTTP_ACCESS_PHASE handler |
| `src/ratelimit/stream_check.c` | 100 | Stream dispatch gate |
| `src/ratelimit/hash.c` | 50 | xxhash32 (small, license-compatible) |
| `src/metrics/ratelimit.c` | 80 | Prometheus export |

All 8 files must be added to `NGX_ADDON_SRCS` in `src/core/config/config.h`.  No `./configure` rerun
needed if the module was already configured with `--add-module=$REPO` (new `.c` files in
`NGX_ADDON_SRCS` are picked up by `make` without re-running configure).

---

## Invariants & Edge Cases

1. **Fail open on zone exhaustion**: if SHM alloc fails even after LRU eviction, the request
   proceeds unthrottled and `rl_zone_full_errors` is incremented.  Rate limiting must never
   prevent otherwise-authorised access when the zone fills.

2. **kXR_wait vs disconnect**: `xrootd_send_wait(ctx, c, wait_sec)` sends the response and
   returns `NGX_OK` — the connection stays open.  The client retries after `wait_sec`.  Do not
   close the connection or return `NGX_ERROR`.

3. **Clock skew between workers**: `ngx_current_msec` is updated by nginx's event loop before
   each event cycle; it may lag by up to one timer resolution (1 ms default).  The leaky bucket
   is not sensitive to single-millisecond skew between workers since the minimum effective
   hold-off is 1 second.

4. **Nginx reload**: the SHM zone init callback checks `data != NULL` and reuses the existing
   zone — rate limit state survives nginx graceful reloads.  Hot reload semantics: old workers
   drain their connections using the old config's rule set while new workers use the new one;
   both share the same SHM zone, so the per-principal counters remain accurate.

5. **Anonymous requests**: if no identity is available (no GSI, no JWT, no SSS), key extraction
   falls back to the IP address for VO/issuer/DN key types.  This ensures anonymous bulk clients
   are always subject to at least the `key=ip` rule.

6. **Volume prefix matching**: `XROOTD_RL_KEY_VOLUME` rules only apply when the request path
   starts with `rule->key_match`.  Paths that do not match that prefix are transparently skipped
   (`NGX_DECLINED` from `xrootd_rl_key_stream`).  Multiple volume rules can coexist — each
   prefix accumulates its own bucket.

---

## Testing Requirements

**Per CLAUDE.md: 3 tests per change: success + error + security-neg**

```
tests/test_ratelimit.py::TestHTTPRateLimit::test_vo_rate_limit_429
    # burst 5 requests through, 6th returns 429, Retry-After header present

tests/test_ratelimit.py::TestHTTPRateLimit::test_nodelay_immediate_429
    # nodelay rule: first request over rate returns 429 with no Retry-After delay

tests/test_ratelimit.py::TestHTTPRateLimit::test_bypass_no_auth_gets_ip_rate
    # unauthenticated client hits ip rate limit, not VO rate limit

tests/test_ratelimit.py::TestStreamRateLimit::test_vo_rate_limit_kxr_wait
    # burst 5 kXR_read through, 6th gets kXR_wait response with seconds field set

tests/test_ratelimit.py::TestStreamRateLimit::test_rate_limit_no_effect_on_stat
    # kXR_stat never throttled even when req_rate exhausted

tests/test_ratelimit.py::TestBandwidthLimit::test_bw_bucket_charged_after_read
    # send 10 MiB via kXR_read; check dashboard API shows bytes_total = 10 MiB

tests/test_ratelimit.py::TestDashboard::test_dashboard_shows_throttle_count
    # throttle a principal; GET /api/v1/ratelimit/status; check throttle_count > 0

tests/test_ratelimit.py::TestDashboard::test_dashboard_sort_by_throttle_count
    # multiple principals; most-throttled appears first in response
```

---

## Implementation Order

1. **Step A** — SHM zone + LRU eviction (`zone.c`) — no integration yet, unit-testable in isolation
2. **Step B** — Leaky bucket core (`ratelimit.c`, `hash.c`) — unit tests via direct C test binary
3. **Step C** — Key extraction (`keys.c`) — depends on A+B
4. **Step G** — Metrics (`metrics.h` extension, `metrics/ratelimit.c`) — no blockers
5. **Step D** — HTTP handler (`http_handler.c`) — depends on A+B+C+G
6. **Step E** — Stream gate (`stream_check.c`) — depends on A+B+C+G
7. **Step F** — Directives (`directives.c`, `config.h`) — depends on all above (wires config to zones/rules)
8. **Step H** — Dashboard API — depends on A+G
9. Integration: connect dispatch.c, read.c, write.c call sites — last, after all components verified

Each step should build and pass its own unit/integration tests before proceeding to the next.
