/*
 * dns.h — runtime DNS for BriX (phase-116): resolv.conf-driven resolver
 * policy, the async resolve driver, the per-worker answer cache, the
 * thread-to-loop bridge, and the config-time target registry that lets every
 * brix hostname be parse-only at `nginx -t` and resolved (and re-resolved)
 * at runtime.
 *
 * WHAT: One public surface for the layers under src/net/dns/:
 *         policy    — brix_dns_policy_t built by `brix_resolver auto` from the
 *                     resolv.conf the process can see (resolver_build.c),
 *         driver    — brix_dns_resolve(): async, search/ndots-aware, cached;
 *                     nginx's resolver when one is in scope, else a thread-
 *                     pool getaddrinfo (resolve.c / resolve_thread.c),
 *         sync      — brix_dns_resolve_sync(): the ONE blocking entry point
 *                     for thread-pool code; literal -> cache -> bridge to the
 *                     event loop's resolver -> libc (resolve_thread.c),
 *         bridge    — resolve_bridge.c: an eventfd-woken queue that lets a
 *                     thread-pool task use the loop's nginx resolver,
 *         cache     — positive + negative per-worker cache (cache.c),
 *         targets   — brix_dns_target_t: a directive's hostname registered at
 *                     parse time, resolved from init_process with backoff,
 *                     refreshed on TTL expiry / failure, rotated round-robin
 *                     (targets.c),
 *         curl pin  — curl_pin.h: CURLOPT_RESOLVE pinning so libcurl never
 *                     resolves on its own,
 *         reverse   — brix_dns_reverse*(): PTR lookups (XrdAcc host rules,
 *                     protbind templates, `host` auth, the TPC origin id)
 *                     with their own address-keyed cache: cached-only probes
 *                     for the event loop, async fills, a blocking flavour for
 *                     threads (reverse.c / reverse_cache.c),
 *         prefetch  — brix_dns_lookup_cached() / brix_dns_prefetch(): the
 *                     never-blocking forward probe the event loop uses for a
 *                     TPC source preflight (prefetch.c).
 * WHY:  nginx open-source resolves hostnames once at parse time (a dead name
 *       is a fatal `nginx -t` error) and never reads resolv.conf; nginx Plus
 *       re-resolves but still needs a hand-written `resolver`.  brix closes
 *       both gaps: no hostname may stop the server starting (I-DNS-1), and
 *       resolution always follows the visible resolv.conf (I-DNS-2/3).
 * HOW:  Everything async lives on the event loop; the libc resolver is called
 *       in exactly one place (resolve_thread.c) and never on the event loop
 *       except for the deadline-bounded OCSP transaction the GSI handshake
 *       already performs inline (I-DNS-4, guard tools/ci/check_dns_seam.py —
 *       strict, no allow-markers, no backlog).  The registry, the cache and
 *       the bridge are per-process singletons following the origin_probe
 *       precedent (config-time statics that survive the fork).
 */
#ifndef BRIX_NET_DNS_H
#define BRIX_NET_DNS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include "core/compat/af_policy.h"
#include "net/dns/resolv_conf.h"
#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#endif

#define BRIX_DNS_MAX_ADDRS         8
#define BRIX_DNS_ERROR_LEN         96
#define BRIX_DNS_CACHE_MAX_DEFAULT 4096
#define BRIX_DNS_RETRY_INITIAL_MS  1000
#define BRIX_DNS_RETRY_MAX_MS      30000
#define BRIX_DNS_MIN_TTL_DEFAULT   1
#define BRIX_DNS_MAX_TTL_DEFAULT   300
#define BRIX_DNS_NEG_TTL_DEFAULT   5
#define BRIX_DNS_THREAD_TTL        30   /* libc answers carry no TTL */
#define BRIX_DNS_NTOP_LEN          (NGX_SOCKADDR_STRLEN + 1)
#define BRIX_DNS_REVERSE_NAME_LEN  256  /* one FQDN (RFC 1035 §2.3.4 + NUL) */
#define BRIX_DNS_PENDING_HOLD      5    /* seconds an in-flight marker lives */

/* brix_resolver mode */
#define BRIX_DNS_MODE_UNSET  0
#define BRIX_DNS_MODE_OFF    1
#define BRIX_DNS_MODE_AUTO   2

/* target lifecycle (metric label + dashboard "state") */
#define BRIX_DNS_STATE_RESOLVING 0
#define BRIX_DNS_STATE_RESOLVED  1
#define BRIX_DNS_STATE_FAILED    2
#define BRIX_DNS_STATE_COUNT     3

/* outcome class of one completed resolver query (metric label `result`);
 * cache hits are not queries and are never counted here */
#define BRIX_DNS_RESULT_OK       0
#define BRIX_DNS_RESULT_NXDOMAIN 1
#define BRIX_DNS_RESULT_TIMEOUT  2
#define BRIX_DNS_RESULT_ERROR    3
#define BRIX_DNS_RESULT_COUNT    4

typedef struct brix_dns_addr_s {
    struct sockaddr_storage  ss;
    socklen_t                len;
} brix_dns_addr_t;

/* Built once per `brix_resolver auto` directive (config time, cf->pool).
 * Shared read-only by every worker; the cache it points at is per-worker.
 * Named so ngx-free headers (net_target.h, gftp_client.h, sts.h, …) can
 * carry `const struct brix_dns_policy_s *` without including this file. */
typedef struct brix_dns_policy_s  brix_dns_policy_t;

struct brix_dns_policy_s {
    ngx_uint_t          mode;        /* BRIX_DNS_MODE_* */
    ngx_str_t           path;        /* resolv.conf path actually read */
    brix_resolv_conf_t  rc;          /* parsed file + env */
    ngx_resolver_t     *resolver;    /* nginx resolver built from rc; NULL=off */
    ngx_msec_t          valid;       /* valid= override (0 = honour TTL) */
    time_t              min_ttl;
    time_t              max_ttl;
    time_t              negative_ttl;
    ngx_flag_t          ipv4;
    ngx_flag_t          ipv6;
    ngx_flag_t          search;      /* apply search/ndots expansion */
};

/* The preamble field: lives in brix_shared_conf_t.dns on both planes and
 * is adopted parent -> child (brix_shared_adopt_unified). */
typedef struct {
    brix_dns_policy_t  *policy;        /* [brix_resolver] NULL = unset/inherit */
    ngx_msec_t          retry_initial; /* [brix_dns_retry <initial> <max>] */
    ngx_msec_t          retry_max;
    ngx_uint_t          cache_max;     /* [brix_dns_cache_max] */
    ngx_str_t           status_zone;   /* [brix_dns_status_zone] label */
} brix_dns_conf_t;

void brix_dns_conf_init(brix_dns_conf_t *dns);
void brix_dns_conf_adopt(brix_dns_conf_t *dst, const brix_dns_conf_t *src);

/* The nginx resolver a policy makes usable (AUTO mode, at least one
 * nameserver), else NULL.  Pure: safe from any thread. */
ngx_resolver_t *brix_dns_policy_resolver(const brix_dns_policy_t *policy);

/* ---- address helpers (pool-free, thread-safe) ---------------------------- */

/* Parse an IPv4/IPv6 literal (optionally "[v6]") into *out with port 0.
 * NGX_OK on a literal, NGX_DECLINED for anything that needs a lookup. */
ngx_int_t brix_dns_parse_literal(const ngx_str_t *name, brix_dns_addr_t *out);

/* Numeric text of an address without its port ("10.0.0.1", "fe80::1").
 * Returns the length written; 0 (and an empty string) for an unknown family. */
size_t brix_dns_addr_ntop(const brix_dns_addr_t *addr, char *buf, size_t sz);

/* ---- async driver -------------------------------------------------------- */

typedef struct brix_dns_req_s  brix_dns_req_t;
typedef void (*brix_dns_handler_pt)(brix_dns_req_t *req);

struct brix_dns_req_s {
    /* in */
    ngx_str_t                 name;      /* hostname or IP literal */
    in_port_t                 port;      /* host order, stamped into answers */
    brix_af_policy_t          af;
    int                       socktype;  /* SOCK_STREAM / SOCK_DGRAM */
    const brix_dns_policy_t  *policy;    /* NULL = libc semantics */
    ngx_resolver_t           *resolver;  /* scope resolver; dummy/NULL = none */
    ngx_log_t                *log;
    brix_dns_handler_pt       handler;   /* may run before brix_dns_resolve returns */
    void                     *data;
    /* out */
    ngx_int_t                 rc;        /* NGX_OK / NGX_ERROR */
    ngx_int_t                 state;     /* NGX_RESOLVE_* / 0 */
    const char               *error;     /* static text on failure */
    brix_dns_addr_t           addrs[BRIX_DNS_MAX_ADDRS];
    ngx_uint_t                naddrs;
    time_t                    ttl;       /* seconds the answer may be cached */
    unsigned                  cached:1;
    unsigned                  literal:1;
    unsigned                  negative:1;/* failure came from the negative cache */
    /* private (driver state) */
    ngx_event_t               ev;
    ngx_uint_t                cand;
    ngx_uint_t                ncand;
    ngx_uint_t                attempt;
    u_char                    cbuf[BRIX_RESOLV_DOMAIN_LEN * 2];
    ngx_str_t                 cname;
    ngx_resolver_ctx_t       *rctx;      /* in-flight nginx resolver ctx */
    void                     *task;      /* in-flight thread task */
};

/* Start resolving.  NGX_OK: the request was accepted and req->handler WILL be
 * (or already was) invoked exactly once; NGX_ERROR: it could not be started
 * (allocation) and the handler is NOT invoked. */
ngx_int_t brix_dns_resolve(brix_dns_req_t *req);

/* Abandon an in-flight request: the handler will NOT be invoked and the
 * request memory may be released by the caller afterwards.  Event loop only. */
void brix_dns_resolve_cancel(brix_dns_req_t *req);

/* Human-readable state name for logs/dashboard. */
const char *brix_dns_state_name(ngx_uint_t state);

/* ---- lookup accounting (metrics.c; atomic, callable from any thread) ---- */

/* Count one completed query by BRIX_DNS_RESULT_* class. */
void brix_dns_lookup_note(ngx_uint_t result);
void brix_dns_lookups_count(ngx_uint_t counts[BRIX_DNS_RESULT_COUNT]);
const char *brix_dns_result_name(ngx_uint_t result);

/* Blocking flavour for thread-pool code (net_target pin, TPC/cache-origin
 * connects, cvmfs probes, curl pinning): IP literal -> per-worker cache ->
 * the event loop's nginx resolver via the bridge (policy AUTO, off-loop) ->
 * libc getaddrinfo.  Answers carry `port`.  Returns the number of addresses
 * (0 = failure, *err filled).  Called on the event loop itself (the OCSP
 * transaction inside the GSI handshake) it skips the bridge and blocks on
 * libc, which is that caller's pre-existing, deadline-bounded contract. */
ngx_uint_t brix_dns_resolve_sync(const brix_dns_policy_t *policy,
    const char *host, in_port_t port, brix_af_policy_t af, int socktype,
    brix_dns_addr_t *addrs, ngx_uint_t max, char *err, size_t errsz);

/* Copy a diagnostic into the caller's optional error buffer (err may be
 * NULL or empty; "" clears it).  Shared by every sync/probe entry point. */
static ngx_inline void
brix_dns_set_err(char *err, size_t errsz, const char *msg)
{
    if (err != NULL && errsz > 0) {
        (void) ngx_snprintf((u_char *) err, errsz, "%s%Z", msg);
    }
}

/* internal: backends (resolve.c / resolve_thread.c / resolve_bridge.c) */
ngx_int_t brix_dns_resolve_via_thread(brix_dns_req_t *req);
#if (NGX_THREADS)
/* One thread task on its own small pool, bound for the "default" pool.
 * NGX_DECLINED: no pool configured (the caller falls back); NGX_ERROR: out
 * of memory.  _post hands the task over: on failure it clears the owner's
 * slot and frees the pool, so both drivers share one error path. */
ngx_int_t brix_dns_thread_task_new(ngx_log_t *log, size_t ctx_size,
    ngx_thread_pool_t **tp, ngx_pool_t **pool, ngx_thread_task_t **task);
ngx_int_t brix_dns_thread_task_post(ngx_thread_pool_t *tp,
    ngx_thread_task_t *task, ngx_pool_t *pool, void **owner);
#endif
void brix_dns_thread_detach(brix_dns_req_t *req);
void brix_dns_req_finish(brix_dns_req_t *req);
ngx_int_t brix_dns_bridge_init_worker(ngx_cycle_t *cycle);
ngx_int_t brix_dns_bridge_resolve(const brix_dns_policy_t *policy,
    const char *host, in_port_t port, brix_af_policy_t af, int socktype,
    brix_dns_addr_t *addrs, ngx_uint_t max, ngx_uint_t *naddrs,
    char *err, size_t errsz);
void brix_dns_bridge_stats(ngx_uint_t *requests, ngx_uint_t *timeouts);

/* ---- per-worker cache (mutex-guarded: loop + thread-pool callers) -------- */

void brix_dns_cache_set_max(ngx_uint_t max);
void brix_dns_reverse_cache_set_max(ngx_uint_t max);
ngx_int_t brix_dns_cache_lookup(brix_dns_req_t *req);   /* NGX_OK hit / DECLINED */
void brix_dns_cache_store(const brix_dns_req_t *req);
/* Mark (name, af) as being looked up so cached-only probes do not start a
 * second fill; the marker is a miss for brix_dns_cache_lookup and is replaced
 * by the answer.  1 = newly marked (start a fill), 0 = known or in flight. */
unsigned brix_dns_cache_mark_pending(const ngx_str_t *name,
    brix_af_policy_t af, time_t hold);
void brix_dns_cache_stats(ngx_uint_t *entries, ngx_uint_t *hits,
    ngx_uint_t *misses, ngx_uint_t *negative_hits);

/* ---- never-blocking forward probe (event loop) --------------------------- */

/* Literal -> per-worker cache only, nothing started.  NGX_OK: *naddrs answers
 * carrying `port`; NGX_DECLINED: a definitive negative (cached NXDOMAIN,
 * family excluded, empty host); NGX_AGAIN: unknown.  Thread-safe. */
ngx_int_t brix_dns_cache_probe(const brix_dns_policy_t *policy,
    const char *host, in_port_t port, brix_af_policy_t af,
    brix_dns_addr_t *addrs, ngx_uint_t max, ngx_uint_t *naddrs,
    char *err, size_t errsz);

/* brix_dns_cache_probe, plus on NGX_AGAIN a background fill is started
 * (brix_dns_prefetch) so a later probe hits the cache.  Event loop only. */
ngx_int_t brix_dns_lookup_cached(const brix_dns_policy_t *policy,
    const char *host, in_port_t port, brix_af_policy_t af,
    brix_dns_addr_t *addrs, ngx_uint_t max, ngx_uint_t *naddrs,
    char *err, size_t errsz);

/* Fire-and-forget fill of the forward cache for host/af (self-owned request
 * logging to the cycle log, so it may outlive the caller's connection;
 * de-duplicated by the pending marker).  Event loop only. */
void brix_dns_prefetch(const brix_dns_policy_t *policy, const char *host,
    in_port_t port, brix_af_policy_t af);

/* ---- reverse (PTR) lookups ------------------------------------------------ */

typedef struct brix_dns_rev_req_s  brix_dns_rev_req_t;
typedef void (*brix_dns_rev_handler_pt)(brix_dns_rev_req_t *req);

struct brix_dns_rev_req_s {
    /* in */
    struct sockaddr_storage   ss;
    socklen_t                 len;
    const brix_dns_policy_t  *policy;    /* NULL = libc semantics */
    ngx_log_t                *log;
    brix_dns_rev_handler_pt   handler;   /* may run before brix_dns_reverse returns */
    void                     *data;
    /* out */
    ngx_int_t                 rc;        /* NGX_OK name / NGX_DECLINED no PTR /
                                            NGX_ERROR resolver failure */
    const char               *error;     /* static text unless rc == NGX_OK */
    char                      name[BRIX_DNS_REVERSE_NAME_LEN];
    time_t                    ttl;       /* seconds the answer may be cached */
    unsigned                  cached:1;
    /* private (driver state) */
    ngx_resolver_ctx_t       *rctx;
    void                     *task;
};

/* Async PTR through the policy's nginx resolver, else a thread-pool
 * getnameinfo.  Same contract as brix_dns_resolve(): NGX_OK = the handler
 * runs exactly once (possibly inline); NGX_ERROR = not started. */
ngx_int_t brix_dns_reverse(brix_dns_rev_req_t *req);
void brix_dns_reverse_cancel(brix_dns_rev_req_t *req);

/* Cached-only probe for the event loop: NGX_OK (name in buf), NGX_DECLINED
 * (no PTR, negative-cached), NGX_AGAIN (unknown or in flight).  Never blocks. */
ngx_int_t brix_dns_reverse_cached(const struct sockaddr *sa, socklen_t len,
    char *buf, size_t buflen);

/* Start a background PTR fill for `sa` unless one is cached or in flight —
 * the accept/login hooks warm the cache before an authorization decision
 * needs it.  Event loop only. */
void brix_dns_reverse_prefetch(const brix_dns_policy_t *policy,
    const struct sockaddr *sa, socklen_t len);

/* Blocking flavour for thread-pool code (the TPC pull's tpc.org build):
 * cache -> loop resolver via the bridge -> libc getnameinfo(NI_NAMEREQD),
 * the one such call in src/.  NGX_OK name / NGX_DECLINED no PTR / NGX_ERROR. */
ngx_int_t brix_dns_reverse_sync(const brix_dns_policy_t *policy,
    const struct sockaddr *sa, socklen_t len, char *buf, size_t buflen);

/* Config-time: a feature that resolves a name no brix_dns_target_register()
 * saw — a peer's PTR, a pmark firefly destination, a proxy upstream, a WebDAV
 * proxy-pool backend — needs a backend even when the configuration declares no
 * brix_resolver.  Registers the default thread pool so the libc lookup runs off
 * the event loop.  Idempotent.  NGX_CONF_OK / NGX_CONF_ERROR. */
char *brix_dns_backend_prepare(ngx_conf_t *cf);

/* internal: reverse backends + the address-keyed cache (reverse_cache.c) */
ngx_int_t brix_dns_reverse_via_thread(brix_dns_rev_req_t *req);
void brix_dns_reverse_thread_detach(brix_dns_rev_req_t *req);
void brix_dns_rev_req_finish(brix_dns_rev_req_t *req);
ngx_int_t brix_dns_bridge_reverse(const brix_dns_policy_t *policy,
    const struct sockaddr *sa, socklen_t len, char *buf, size_t buflen,
    ngx_int_t *answer);             /* NGX_OK bridged (*answer = OK/DECLINED/
                                       ERROR) / NGX_DECLINED not bridged */
ngx_int_t brix_dns_rcache_lookup(const struct sockaddr *sa, socklen_t len,
    char *buf, size_t buflen);                       /* OK / DECLINED / AGAIN */
unsigned brix_dns_rcache_mark_pending(const struct sockaddr *sa,
    socklen_t len, time_t hold);
void brix_dns_rcache_store(const struct sockaddr *sa, socklen_t len,
    const char *name, time_t ttl);                   /* name NULL = negative */
void brix_dns_rcache_stats(ngx_uint_t *entries, ngx_uint_t *hits,
    ngx_uint_t *misses, ngx_uint_t *negative_hits);

/* ---- policy / resolver construction ------------------------------------- */

char *brix_conf_set_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_conf_set_dns_retry(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_conf_set_dns_cache_max(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_resolver_t *brix_dns_resolver_build(ngx_conf_t *cf,
    brix_dns_policy_t *pol);

/* ---- config-time target registry ---------------------------------------- */

typedef struct brix_dns_target_s  brix_dns_target_t;

struct brix_dns_target_s {
    const char              *directive;   /* static text, e.g. "brix_cms_manager" */
    ngx_str_t                host;        /* NUL-terminated copy */
    in_port_t                port;
    brix_af_policy_t         af;
    int                      socktype;
    const brix_dns_conf_t   *dns;         /* owning scope (read after merge) */
    ngx_cycle_t             *cycle;       /* registration cycle */

    /* published address: consumers keep this pointer; socklen==0 until the
     * first successful resolution (literals are published at parse time). */
    ngx_addr_t               addr;
    struct sockaddr_storage  addr_ss;

    brix_dns_addr_t          addrs[BRIX_DNS_MAX_ADDRS];
    ngx_uint_t               naddrs;
    ngx_uint_t               rr;          /* round-robin cursor */
    ngx_uint_t               state;       /* BRIX_DNS_STATE_* */
    char                     last_error[BRIX_DNS_ERROR_LEN];
    ngx_msec_t               next_retry;  /* absolute ngx_current_msec, 0=none */
    ngx_msec_t               backoff;
    time_t                   expires;     /* TTL-driven refresh deadline */
    ngx_uint_t               failures;
    ngx_uint_t               resolutions;
    unsigned                 literal:1;
    unsigned                 armed:1;     /* worker timer installed */
    unsigned                 inflight:1;

    ngx_event_t              timer;
    brix_dns_req_t           req;
};

/* Register (or reuse) a target for host:port at config time.  Never resolves
 * a hostname; IP literals are published immediately.  NULL on allocation
 * failure only. */
brix_dns_target_t *brix_dns_target_register(ngx_conf_t *cf,
    const char *directive, const ngx_str_t *host, in_port_t port,
    brix_af_policy_t af, int socktype, const brix_dns_conf_t *dns);

/* Arm the per-worker resolution timers for every target of `cycle` (and the
 * thread-to-loop bridge) — called from BOTH plane init_process hooks;
 * idempotent per process. */
ngx_int_t brix_dns_targets_init_worker(ngx_cycle_t *cycle);

/* Copy the next round-robin address into *sa.  NGX_DECLINED while unresolved. */
ngx_int_t brix_dns_target_next(brix_dns_target_t *t,
    struct sockaddr_storage *sa, socklen_t *len);

/* Consumer hint: the published address just failed to connect — refresh soon. */
void brix_dns_target_note_failure(brix_dns_target_t *t);

/* Observability: per-state counts (this worker's view) and row iteration. */
void brix_dns_targets_count(ngx_uint_t counts[BRIX_DNS_STATE_COUNT]);
ngx_uint_t brix_dns_targets_n(void);
const brix_dns_target_t *brix_dns_target_at(ngx_uint_t i);

#endif /* BRIX_NET_DNS_H */
