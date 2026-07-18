/*
 * ratelimit.h — Phase 25 advanced rate limiting & traffic shaping.
 *
 * WHAT: A leaky-bucket request-rate and bandwidth limiter keyed on
 * XRootD-specific identity dimensions (VO group, token issuer, client IP, DN,
 * or storage-volume path prefix) rather than the coarse per-IP/per-DN bucket of
 * the Phase 20 `brix_rate_limit` directive.  Throttled XRootD stream clients
 * receive kXR_wait(seconds); throttled HTTP/WebDAV clients receive 429 +
 * Retry-After.
 *
 * WHY: A Tier-1 storage gateway needs policies like "ATLAS VO: 500 req/s, burst
 * 800" or "/store/tape: 50 MiB/s aggregate" that the stock nginx limiter and the
 * Phase 20 per-IP limiter cannot express.  This module adds a second, richer
 * limiter that coexists with — and is independent of — Phase 20.
 *
 * HOW: One or more named shared-memory zones (`brix_rate_limit_zone`) hold an
 * rbtree of per-principal leaky-bucket nodes allocated from the zone's nginx
 * slab pool, with an LRU queue for O(1) eviction when the zone fills (same
 * structure as ngx_http_limit_req_module).  Rules (`brix_rate_limit_rule`,
 * `brix_bandwidth_limit`) attach to a WebDAV location or a stream server and
 * are evaluated by an HTTP access-phase handler and a stream dispatch gate.
 *
 * Naming note: the Phase 20 directive `brix_rate_limit` (per-IP/DN token
 * bucket over the KV store) is unrelated and unchanged; Phase 25 uses the
 * distinct `brix_rate_limit_zone` / `brix_rate_limit_rule` /
 * `brix_bandwidth_limit` directives.
 */
#ifndef BRIX_RATELIMIT_H
#define BRIX_RATELIMIT_H

#include "core/ngx_brix_module.h"
#include <ngx_http.h>   /* ngx_http_request_t for the HTTP-plane declarations */

/* Key dimensions for a rate-limit lookup. */
typedef enum {
    BRIX_RL_KEY_VO      = 0,   /* primary VO / vo_csv                    */
    BRIX_RL_KEY_ISSUER  = 1,   /* token issuer URL                       */
    BRIX_RL_KEY_IP      = 2,   /* client address                         */
    BRIX_RL_KEY_DN      = 3,   /* GSI subject DN (hashed into the key)   */
    BRIX_RL_KEY_VOLUME  = 4,   /* longest-prefix match on the request path */
    BRIX_RL_KEY_SUBJECT = 5,   /* WLCG/JWT token subject (hashed into key) */
} brix_rl_key_type_t;

#define BRIX_RL_KEY_LEN   128  /* max bytes of the human-readable key string */

/* Fixed-point scale for the request leaky-bucket: req_rate, req_excess and the
 * burst ceiling are all stored in milli-requests, so one whole request costs
 * BRIX_RL_REQ_SCALE units.  Lets the drain math stay in integers. */
#define BRIX_RL_REQ_SCALE  1000

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
} brix_rl_node_t;

/* Shared rbtree + LRU queue living at the head of the slab pool. */
typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;
} brix_rl_shctx_t;

/* Runtime handle for one named zone (resolved at config time). */
typedef struct {
    brix_rl_shctx_t *sh;        /* set in the zone init callback           */
    ngx_slab_pool_t   *shpool;    /* the zone's slab pool                    */
    ngx_shm_zone_t    *shm_zone;
    ngx_str_t          name;
    size_t             size;
} brix_rl_zone_t;

/* One configured rule.  A rule carries a request-rate limit, a bandwidth
 * limit, or both (set by brix_rate_limit_rule / brix_bandwidth_limit). */
typedef struct {
    brix_rl_key_type_t  key_type;
    ngx_str_t             key_match;   /* "" = wildcard; else VOLUME prefix    */
    ngx_uint_t            req_rate;    /* req/s × 1000 (0 = no request limit)  */
    ngx_uint_t            req_burst;   /* burst capacity (requests, not ×1000) */
    ngx_uint_t            bw_rate;     /* bytes/s (0 = no bandwidth limit)     */
    ngx_uint_t            bw_burst;    /* burst capacity in bytes              */
    ngx_uint_t            req_conc;    /* W7: max concurrent in-flight (0=off) */
    ngx_flag_t            nodelay;     /* 1 = reject now; 0 = kXR_wait/Retry   */
    brix_rl_zone_t     *zone;        /* resolved zone handle                 */
} brix_rl_rule_t;

/* Dashboard snapshot row. */
typedef struct {
    char     key_str[BRIX_RL_KEY_LEN];
    uint64_t req_total;
    uint64_t bytes_total;
    uint32_t throttle_count;
    ngx_uint_t req_excess;
    ngx_uint_t bw_excess;
} brix_rl_snapshot_entry_t;


/* ---- zone management (ratelimit_zone.c) ---------------------------------- */

/* Declare/attach a named SHM zone; called from the zone directive setter.
 * Returns the resolved handle in *out (allocated from cf->pool). */
ngx_int_t brix_rl_zone_add(ngx_conf_t *cf, ngx_str_t *name, size_t size,
    brix_rl_zone_t **out);

/* Resolve a previously-declared zone by name (config time). NULL if unknown. */
brix_rl_zone_t *brix_rl_zone_get(ngx_str_t *name);

/* Copy up to max declared-zone handles into out[]; returns the count. */
ngx_uint_t brix_rl_zones_all(brix_rl_zone_t **out, ngx_uint_t max);

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
void brix_rl_zone_reset_gauges(brix_rl_shctx_t *sh);

/* Internal helpers (ratelimit_zone.c) used by the leaky-bucket core.  All the
 * lookup/create helpers require the caller to hold zone->shpool->mutex. */

/* FNV-1a 32-bit hash over the first len bytes of key (matches kv.c); pure, no
 * locking.  Used both as the rbtree node key and the SHM lookup hash. */
uint32_t brix_rl_hash(const char *key, size_t len);

/* Find the bucket node for (hash, key_str[0..len)); NULL if absent.  Caller
 * holds the mutex.  Side effect: on a hit the node is bumped to the LRU head
 * (so a lookup also marks it recently-used), so this is NOT read-only. */
brix_rl_node_t *brix_rl_lookup_locked(brix_rl_zone_t *zone,
    uint32_t hash, const char *key_str, size_t len);

/* Slab-allocate a new zeroed bucket node for (hash, key_str), copying len key
 * bytes in, and link it into the rbtree at the LRU head.  Caller holds the
 * mutex.  May evict up to 8 LRU-tail nodes to make room; returns NULL on
 * persistent slab exhaustion (callers fail open). */
brix_rl_node_t *brix_rl_create_locked(brix_rl_zone_t *zone,
    uint32_t hash, const char *key_str, size_t len);


/* ---- core leaky bucket (ratelimit.c) ------------------------------------- */

/*
 * Request-rate check: look up or create the node for key_str, drain at
 * rule->req_rate, and charge one request.  Returns NGX_OK (allowed),
 * NGX_AGAIN (throttled — *wait_seconds set, ceil), or NGX_OK on internal
 * failure (fail-open).  No-op returning NGX_OK if rule->req_rate == 0.
 */
ngx_int_t brix_rl_check(brix_rl_rule_t *rule, const char *key_str,
    uint32_t *wait_seconds);

/*
 * Bandwidth pre-check: throttle if the bandwidth bucket is already overflowing
 * (uses the previous excess as a conservative estimate; charges nothing).
 * Returns NGX_OK / NGX_AGAIN.  No-op returning NGX_OK if rule->bw_rate == 0.
 */
ngx_int_t brix_rl_bw_check(brix_rl_rule_t *rule, const char *key_str,
    uint32_t *wait_seconds);

/* Charge nbytes against the bandwidth bucket after a response is sent. */
void brix_rl_charge_bytes(brix_rl_rule_t *rule, const char *key_str,
    size_t nbytes);

/*
 * W7 — per-principal concurrency limit.  acquire() reserves one in-flight slot
 * for key_str under rule->req_conc: NGX_OK if a slot was taken (caller MUST
 * pair it with exactly one release()), NGX_AGAIN if the principal is already at
 * its cap (nothing reserved).  release() returns a previously-acquired slot.
 * No-ops returning NGX_OK / void when rule->req_conc == 0.
 */
ngx_int_t brix_rl_conc_acquire(brix_rl_rule_t *rule, const char *key_str);
void      brix_rl_conc_release(brix_rl_rule_t *rule, const char *key_str);

/* Snapshot up to max nodes from a zone (sorted by throttle_count desc). */
ngx_int_t brix_rl_snapshot(brix_rl_zone_t *zone,
    brix_rl_snapshot_entry_t *out, ngx_uint_t max, ngx_uint_t *count);


/* ---- key extraction + directive parsing (ratelimit_keys.c) --------------- */

/* Build the "<type>:<value>" key for the stream plane.  Returns NGX_OK,
 * NGX_DECLINED (VOLUME prefix did not match `path` — rule does not apply),
 * or NGX_ERROR. */
ngx_int_t brix_rl_key_stream(brix_rl_rule_t *rule, brix_ctx_t *ctx,
    const char *path, char *out, size_t out_sz);

/*
 * Resolved HTTP/WebDAV-plane identity inputs for one key derivation.
 *
 * WHAT: A bundle of the already-resolved identity handles that brix_rl_key_http()
 * reads to build a rate-limit key: the unified identity (`id`, may be NULL), the
 * raw WebDAV request ctx that carries the cert DN (`wctx`, an opaque
 * ngx_http_brix_webdav_req_ctx_t* kept as void* so this header need not pull in
 * webdav.h, may be NULL on early-phase requests), the connection address (`ip`),
 * and the lazily-resolved request path (`path`, used only by VOLUME rules).
 *
 * WHY: Bundling these into one struct keeps brix_rl_key_http() at four arguments
 * (it previously took six loose ones) and lets the caller resolve the
 * side-effecting handles — the WebDAV ctx's identity and the connection address —
 * once, up front, before populating the literal.  The per-key-type branch logic
 * then reads one explicit, already-resolved struct rather than a loose argument
 * list.  Key-derivation semantics and the anon IP-fallback are unchanged.
 *
 * HOW: The HTTP access handler fills `id`/`wctx` from the WebDAV ctx and `ip`
 * from the connection, passes a pointer here, and brix_rl_key_http() switches on
 * rule->key_type over these fields.
 */
typedef struct {
    brix_identity_t *id;
    void            *wctx;   /* ngx_http_brix_webdav_req_ctx_t* (opaque) */
    ngx_str_t       *ip;
    const char      *path;
} rl_key_req_t;

/* HTTP/WebDAV plane equivalent of brix_rl_key_stream().  Reads the already-
 * resolved identity handles from `req` (see rl_key_req_t) so the caller hoists
 * the side-effecting lookups (wctx->identity, connection addr) before the call. */
ngx_int_t brix_rl_key_http(brix_rl_rule_t *rule, const rl_key_req_t *req,
    char *out, size_t out_sz);

/* Directive setters (shared by the HTTP and stream command tables).  All are
 * standard ngx_command_t set callbacks returning NGX_CONF_OK / NGX_CONF_ERROR;
 * the rule/bw/conc setters read the target rules array via cmd->offset, so the
 * same function serves both the WebDAV loc-conf and the stream srv-conf. */

/* brix_rate_limit_zone zone=NAME:SIZE — parse and declare a named SHM zone
 * (delegates to brix_rl_zone_add); no rule is created. */
char *brix_rl_zone_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* brix_rate_limit_rule ... — push one request-rate rule (rate=<N>r/s,
 * default burst 1) onto the conf's rules array; binds to a zone declared
 * earlier by name (errors if unknown). */
char *brix_rl_rule_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* brix_bandwidth_limit ... — like the rule setter but rate=/burst= are bytes
 * (default burst = one second of rate); sets bw_rate/bw_burst on the rule. */
char *brix_rl_bw_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* brix_concurrency_limit zone=NAME key=<type> limit=N (W7) — push a rule with
 * a hard in-flight cap (req_conc), not a leaky bucket; same array/zone binding. */
char *brix_rl_conc_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


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
ngx_int_t brix_rl_http_access_handler(ngx_http_request_t *r);

/*
 * NGX_HTTP_LOG_PHASE handler (main request only) — releases the W7 concurrency
 * slot reserved by the access handler exactly once (runs even on error/abort, so
 * the slot never leaks) and charges the response size against the bandwidth
 * bucket stashed on the webdav ctx (content_length_n, falling back to
 * connection->sent minus header_size).  Always returns NGX_OK.
 */
ngx_int_t brix_rl_http_log_handler(ngx_http_request_t *r);


/* ---- stream enforcement (ratelimit_stream.c) ----------------------------- */

/*
 * Stream dispatch gate: evaluate all rules for the current opcode/path.
 * Returns NGX_OK to proceed, or a non-NGX_OK rc (the kXR_wait result) that the
 * dispatcher must return without running the opcode handler.  When a bandwidth
 * rule applies, the zone/rule/key are stashed on ctx for the post-send charge.
 */
ngx_int_t brix_rl_stream_gate(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* Charge nbytes against the bandwidth bucket stashed on ctx by the gate. */
void brix_rl_charge_ctx(brix_ctx_t *ctx, size_t nbytes);

/* Release the per-connection concurrency slot (W7) the stream gate acquired, if
 * any.  Called once from brix_on_disconnect — idempotent (no-op if none). */
void brix_rl_release_ctx(brix_ctx_t *ctx);

/* (Prometheus export brix_export_ratelimit_metrics() is declared in
 * src/metrics/metrics_internal.h alongside the other exporters.) */

#endif /* BRIX_RATELIMIT_H */
