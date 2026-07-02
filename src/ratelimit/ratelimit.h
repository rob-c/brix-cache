/*
 * ratelimit.h — Phase 25 advanced rate limiting & traffic shaping.
 *
 * WHAT: A leaky-bucket request-rate and bandwidth limiter keyed on
 * XRootD-specific identity dimensions (VO group, token issuer, client IP, DN,
 * or storage-volume path prefix) rather than the coarse per-IP/per-DN bucket of
 * the Phase 20 `xrootd_rate_limit` directive.  Throttled XRootD stream clients
 * receive kXR_wait(seconds); throttled HTTP/WebDAV clients receive 429 +
 * Retry-After.
 *
 * WHY: A Tier-1 storage gateway needs policies like "ATLAS VO: 500 req/s, burst
 * 800" or "/store/tape: 50 MiB/s aggregate" that the stock nginx limiter and the
 * Phase 20 per-IP limiter cannot express.  This module adds a second, richer
 * limiter that coexists with — and is independent of — Phase 20.
 *
 * HOW: One or more named shared-memory zones (`xrootd_rate_limit_zone`) hold an
 * rbtree of per-principal leaky-bucket nodes allocated from the zone's nginx
 * slab pool, with an LRU queue for O(1) eviction when the zone fills (same
 * structure as ngx_http_limit_req_module).  Rules (`xrootd_rate_limit_rule`,
 * `xrootd_bandwidth_limit`) attach to a WebDAV location or a stream server and
 * are evaluated by an HTTP access-phase handler and a stream dispatch gate.
 *
 * Naming note: the Phase 20 directive `xrootd_rate_limit` (per-IP/DN token
 * bucket over the KV store) is unrelated and unchanged; Phase 25 uses the
 * distinct `xrootd_rate_limit_zone` / `xrootd_rate_limit_rule` /
 * `xrootd_bandwidth_limit` directives.
 */
#ifndef XROOTD_RATELIMIT_H
#define XROOTD_RATELIMIT_H

#include "../ngx_xrootd_module.h"
#include <ngx_http.h>   /* ngx_http_request_t for the HTTP-plane declarations */

/* Key dimensions for a rate-limit lookup. */
typedef enum {
    XROOTD_RL_KEY_VO      = 0,   /* primary VO / vo_csv                    */
    XROOTD_RL_KEY_ISSUER  = 1,   /* token issuer URL                       */
    XROOTD_RL_KEY_IP      = 2,   /* client address                         */
    XROOTD_RL_KEY_DN      = 3,   /* GSI subject DN (hashed into the key)   */
    XROOTD_RL_KEY_VOLUME  = 4,   /* longest-prefix match on the request path */
} xrootd_rl_key_type_t;

#define XROOTD_RL_KEY_LEN   128  /* max bytes of the human-readable key string */

/* One per-principal leaky-bucket node, slab-allocated inside the SHM zone. */
typedef struct {
    ngx_rbtree_node_t  node;            /* node.key = FNV-1a32(key_str)        */
    ngx_queue_t        queue;           /* LRU linkage (head = most-recent)    */
    ngx_msec_t         last;            /* last update (ms)                    */
    ngx_uint_t         req_excess;      /* request leaky-bucket excess × 1000  */
    ngx_uint_t         bw_excess;       /* bandwidth excess (bytes, × 1)       */
    uint64_t           req_total;       /* cumulative allowed requests         */
    uint64_t           bytes_total;     /* cumulative bytes charged            */
    uint32_t           throttle_count;  /* times throttled                     */
    ngx_uint_t         in_flight;       /* W7: current concurrent requests     */
    uint64_t           io_time_us;      /* phase-59 W3a: IO service-time in the
                                           current interval (XrdThrottle load)  */
    ngx_msec_t         io_window;       /* start of the current interval        */
    ngx_uint_t         open_files;      /* phase-59 W3a: per-user open handles  */
    u_short            len;             /* key_str length                      */
    u_char             key_str[1];      /* flexible: `len` bytes follow        */
} xrootd_rl_node_t;

/* Shared rbtree + LRU queue living at the head of the slab pool. */
typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;
} xrootd_rl_shctx_t;

/* Runtime handle for one named zone (resolved at config time). */
typedef struct {
    xrootd_rl_shctx_t *sh;        /* set in the zone init callback           */
    ngx_slab_pool_t   *shpool;    /* the zone's slab pool                    */
    ngx_shm_zone_t    *shm_zone;
    ngx_str_t          name;
    size_t             size;
} xrootd_rl_zone_t;

/* One configured rule.  A rule carries a request-rate limit, a bandwidth
 * limit, or both (set by xrootd_rate_limit_rule / xrootd_bandwidth_limit). */
typedef struct {
    xrootd_rl_key_type_t  key_type;
    ngx_str_t             key_match;   /* "" = wildcard; else VOLUME prefix    */
    ngx_uint_t            req_rate;    /* req/s × 1000 (0 = no request limit)  */
    ngx_uint_t            req_burst;   /* burst capacity (requests, not ×1000) */
    ngx_uint_t            bw_rate;     /* bytes/s (0 = no bandwidth limit)     */
    ngx_uint_t            bw_burst;    /* burst capacity in bytes              */
    ngx_uint_t            req_conc;    /* W7: max concurrent in-flight (0=off) */
    ngx_flag_t            nodelay;     /* 1 = reject now; 0 = kXR_wait/Retry   */
    xrootd_rl_zone_t     *zone;        /* resolved zone handle                 */
} xrootd_rl_rule_t;

/* Dashboard snapshot row. */
typedef struct {
    char     key_str[XROOTD_RL_KEY_LEN];
    uint64_t req_total;
    uint64_t bytes_total;
    uint32_t throttle_count;
    ngx_uint_t req_excess;
    ngx_uint_t bw_excess;
} xrootd_rl_snapshot_entry_t;


/* ---- zone management (ratelimit_zone.c) ---------------------------------- */

/* Declare/attach a named SHM zone; called from the zone directive setter.
 * Returns the resolved handle in *out (allocated from cf->pool). */
ngx_int_t xrootd_rl_zone_add(ngx_conf_t *cf, ngx_str_t *name, size_t size,
    xrootd_rl_zone_t **out);

/* Resolve a previously-declared zone by name (config time). NULL if unknown. */
xrootd_rl_zone_t *xrootd_rl_zone_get(ngx_str_t *name);

/* Copy up to max declared-zone handles into out[]; returns the count. */
ngx_uint_t xrootd_rl_zones_all(xrootd_rl_zone_t **out, ngx_uint_t max);

/*
 * Zero the in-use gauges (in_flight, open_files) on every node of a shared
 * zone. Called on reload adoption: these gauges self-heal only via a matched
 * decrement, so a worker SIGKILLed (e.g. at reload's worker_shutdown_timeout)
 * mid-request leaks its increment permanently, it survives reload in the SHM
 * zone, and accumulates every restart cycle until the gauge reaches the
 * configured cap and rejects that key forever. Resetting at each reload bounds
 * any crash-leak to a single generation. The time-windowed rate/bandwidth
 * buckets are deliberately preserved (they self-heal and must survive reload).
 */
void xrootd_rl_zone_reset_gauges(xrootd_rl_shctx_t *sh);

/* Internal helpers (ratelimit_zone.c) used by the leaky-bucket core.  All the
 * lookup/create helpers require the caller to hold zone->shpool->mutex. */

/* FNV-1a 32-bit hash over the first len bytes of key (matches kv.c); pure, no
 * locking.  Used both as the rbtree node key and the SHM lookup hash. */
uint32_t xrootd_rl_hash(const char *key, size_t len);

/* Find the bucket node for (hash, key_str[0..len)); NULL if absent.  Caller
 * holds the mutex.  Side effect: on a hit the node is bumped to the LRU head
 * (so a lookup also marks it recently-used), so this is NOT read-only. */
xrootd_rl_node_t *xrootd_rl_lookup_locked(xrootd_rl_zone_t *zone,
    uint32_t hash, const char *key_str, size_t len);

/* Slab-allocate a new zeroed bucket node for (hash, key_str), copying len key
 * bytes in, and link it into the rbtree at the LRU head.  Caller holds the
 * mutex.  May evict up to 8 LRU-tail nodes to make room; returns NULL on
 * persistent slab exhaustion (callers fail open). */
xrootd_rl_node_t *xrootd_rl_create_locked(xrootd_rl_zone_t *zone,
    uint32_t hash, const char *key_str, size_t len);


/* ---- core leaky bucket (ratelimit.c) ------------------------------------- */

/*
 * Request-rate check: look up or create the node for key_str, drain at
 * rule->req_rate, and charge one request.  Returns NGX_OK (allowed),
 * NGX_AGAIN (throttled — *wait_seconds set, ceil), or NGX_OK on internal
 * failure (fail-open).  No-op returning NGX_OK if rule->req_rate == 0.
 */
ngx_int_t xrootd_rl_check(xrootd_rl_rule_t *rule, const char *key_str,
    uint32_t *wait_seconds);

/*
 * Bandwidth pre-check: throttle if the bandwidth bucket is already overflowing
 * (uses the previous excess as a conservative estimate; charges nothing).
 * Returns NGX_OK / NGX_AGAIN.  No-op returning NGX_OK if rule->bw_rate == 0.
 */
ngx_int_t xrootd_rl_bw_check(xrootd_rl_rule_t *rule, const char *key_str,
    uint32_t *wait_seconds);

/* Charge nbytes against the bandwidth bucket after a response is sent. */
void xrootd_rl_charge_bytes(xrootd_rl_rule_t *rule, const char *key_str,
    size_t nbytes);

/*
 * W7 — per-principal concurrency limit.  acquire() reserves one in-flight slot
 * for key_str under rule->req_conc: NGX_OK if a slot was taken (caller MUST
 * pair it with exactly one release()), NGX_AGAIN if the principal is already at
 * its cap (nothing reserved).  release() returns a previously-acquired slot.
 * No-ops returning NGX_OK / void when rule->req_conc == 0.
 */
ngx_int_t xrootd_rl_conc_acquire(xrootd_rl_rule_t *rule, const char *key_str);
void      xrootd_rl_conc_release(xrootd_rl_rule_t *rule, const char *key_str);

/* Snapshot up to max nodes from a zone (sorted by throttle_count desc). */
ngx_int_t xrootd_rl_snapshot(xrootd_rl_zone_t *zone,
    xrootd_rl_snapshot_entry_t *out, ngx_uint_t max, ngx_uint_t *count);


/* ---- key extraction + directive parsing (ratelimit_keys.c) --------------- */

/* Build the "<type>:<value>" key for the stream plane.  Returns NGX_OK,
 * NGX_DECLINED (VOLUME prefix did not match `path` — rule does not apply),
 * or NGX_ERROR. */
ngx_int_t xrootd_rl_key_stream(xrootd_rl_rule_t *rule, xrootd_ctx_t *ctx,
    const char *path, char *out, size_t out_sz);

/* HTTP/WebDAV plane equivalent.  wctx is an
 * ngx_http_xrootd_webdav_req_ctx_t* (opaque here to avoid pulling webdav.h). */
ngx_int_t xrootd_rl_key_http(xrootd_rl_rule_t *rule, ngx_http_request_t *r,
    void *wctx, const char *path, char *out, size_t out_sz);

/* Directive setters (shared by the HTTP and stream command tables).  All are
 * standard ngx_command_t set callbacks returning NGX_CONF_OK / NGX_CONF_ERROR;
 * the rule/bw/conc setters read the target rules array via cmd->offset, so the
 * same function serves both the WebDAV loc-conf and the stream srv-conf. */

/* xrootd_rate_limit_zone zone=NAME:SIZE — parse and declare a named SHM zone
 * (delegates to xrootd_rl_zone_add); no rule is created. */
char *xrootd_rl_zone_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* xrootd_rate_limit_rule ... — push one request-rate rule (rate=<N>r/s,
 * default burst 1) onto the conf's rules array; binds to a zone declared
 * earlier by name (errors if unknown). */
char *xrootd_rl_rule_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* xrootd_bandwidth_limit ... — like the rule setter but rate=/burst= are bytes
 * (default burst = one second of rate); sets bw_rate/bw_burst on the rule. */
char *xrootd_rl_bw_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* xrootd_concurrency_limit zone=NAME key=<type> limit=N (W7) — push a rule with
 * a hard in-flight cap (req_conc), not a leaky bucket; same array/zone binding. */
char *xrootd_rl_conc_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


/* ---- HTTP enforcement (ratelimit_http.c) --------------------------------- */

/*
 * NGX_HTTP_ACCESS_PHASE handler — evaluate every rule on the request's location
 * (register after the auth handler so identity is populated).  Returns
 * NGX_HTTP_TOO_MANY_REQUESTS (429, with Retry-After unless the rule is nodelay)
 * when any req-rate / bandwidth / concurrency dimension is exhausted, else
 * NGX_DECLINED (allowed — also returned for subrequests and when no rules apply).
 * Side effects on the allowed path: stashes the matched bandwidth rule+key and a
 * reserved W7 concurrency slot on the webdav request ctx (allocating the ctx if
 * absent) for the log handler to charge/release; fails open on lookup errors.
 */
ngx_int_t xrootd_rl_http_access_handler(ngx_http_request_t *r);

/*
 * NGX_HTTP_LOG_PHASE handler (main request only) — releases the W7 concurrency
 * slot reserved by the access handler exactly once (runs even on error/abort, so
 * the slot never leaks) and charges the response size against the bandwidth
 * bucket stashed on the webdav ctx (content_length_n, falling back to
 * connection->sent minus header_size).  Always returns NGX_OK.
 */
ngx_int_t xrootd_rl_http_log_handler(ngx_http_request_t *r);


/* ---- stream enforcement (ratelimit_stream.c) ----------------------------- */

/*
 * Stream dispatch gate: evaluate all rules for the current opcode/path.
 * Returns NGX_OK to proceed, or a non-NGX_OK rc (the kXR_wait result) that the
 * dispatcher must return without running the opcode handler.  When a bandwidth
 * rule applies, the zone/rule/key are stashed on ctx for the post-send charge.
 */
ngx_int_t xrootd_rl_stream_gate(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* Charge nbytes against the bandwidth bucket stashed on ctx by the gate. */
void xrootd_rl_charge_ctx(xrootd_ctx_t *ctx, size_t nbytes);

/* Release the per-connection concurrency slot (W7) the stream gate acquired, if
 * any.  Called once from xrootd_on_disconnect — idempotent (no-op if none). */
void xrootd_rl_release_ctx(xrootd_ctx_t *ctx);

/* (Prometheus export xrootd_export_ratelimit_metrics() is declared in
 * src/metrics/metrics_internal.h alongside the other exporters.) */

#endif /* XROOTD_RATELIMIT_H */
