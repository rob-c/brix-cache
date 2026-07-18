/* cvmfs.h — the cvmfs:// protocol surface.
 *
 * WHAT: loc-conf + request-ctx types, the handler entry, and the gate/geo
 *       prototypes for the dedicated CVMFS protocol plane.
 * WHY:  cvmfs:// is a first-class protocol (peer of webdav/, s3/): its own
 *       module owns configuration and its own content handler owns every
 *       request — WebDAV dispatch is never involved.
 * HOW:  the loc-conf embeds the SAME shared preamble (`common`) the other
 *       HTTP protocols embed, so brix_cvmfs_storage_backend /
 *       brix_cvmfs_cache_store compose the identical phase-63/64 storage
 *       stack underneath a protocol-specific top.
 */
#ifndef BRIX_CVMFS_H
#define BRIX_CVMFS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "classify.h"
#include "core/config/shared_conf.h"
#include "fs/backend/sd.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"
#include "observability/sesslog/sesslog.h"

/* T19: origin-selection policy for the multi-endpoint backend. */
typedef enum {
    BRIX_CVMFS_SELECT_STATIC = 0,   /* configured order (default)        */
    BRIX_CVMFS_SELECT_GEO,          /* haversine(here, origin coords)    */
    BRIX_CVMFS_SELECT_RTT           /* measured TCP connect RTT (EWMA)   */
} brix_cvmfs_select_e;

/* Fill retry policy when an origin stalls (brix_cvmfs_fill_retry_policy). */
typedef enum {
    BRIX_CVMFS_RETRY_FAILOVER = 0,  /* T11 alternate-endpoint failover   */
    BRIX_CVMFS_RETRY_FORCE_PRIMARY  /* pin preferred origin, never fail  */
} brix_cvmfs_retry_policy_e;

/* Origin HTTP version policy (brix_cvmfs_origin_http_version, phase-85 F11).
 * Values mirror the transport contract in fs/cache/origin/s3_transport.h:
 * UNSET leaves libcurl's own default policy untouched (byte-frozen parity). */
typedef enum {
    BRIX_CVMFS_ORIGIN_HTTP_UNSET = 0,  /* directive absent: libcurl default  */
    BRIX_CVMFS_ORIGIN_HTTP_11    = 11, /* force HTTP/1.1                     */
    BRIX_CVMFS_ORIGIN_HTTP_2     = 20, /* h2 ALPN / h2c Upgrade, 1.1 fallback */
    BRIX_CVMFS_ORIGIN_HTTP_2D    = 21, /* cleartext h2 prior knowledge       */
    BRIX_CVMFS_ORIGIN_HTTP_3     = 30  /* QUIC (needs libcurl HTTP3 support) */
} brix_cvmfs_origin_http_e;

/* Geo API answering mode (brix_cvmfs_geo_answer). */
typedef enum {
    BRIX_CVMFS_GEO_PASSTHROUGH = 0, /* relay upstream GeoAPI verbatim    */
    BRIX_CVMFS_GEO_RTT              /* answer locally, RTT-ranked         */
} brix_cvmfs_geo_answer_e;

/* One brix_cvmfs_origin_coords entry: an entry WITH a port matches only
 * that endpoint; without one it matches every endpoint on that host. */
typedef struct {
    ngx_str_t    host;
    in_port_t    port;             /* 0 = any port on this host              */
    double       lat, lon;
} brix_cvmfs_coord_t;

typedef struct {
    ngx_flag_t   enable;           /* brix_cvmfs on|off (default off)       */
    time_t       manifest_ttl;     /* brix_cvmfs_manifest_ttl (default 61s) */
    time_t       negative_ttl;     /* brix_cvmfs_negative_ttl (default 10s) */
    time_t       offline_ttl;      /* brix_cvmfs_offline_ttl (default 0 = off):
                                      through a total origin outage keep
                                      serving the last verified manifest this
                                      long past its fill (extends the 10x-TTL
                                      stale window, phase-85 F10)             */
    ngx_str_t    quarantine_dir;   /* brix_cvmfs_quarantine_dir (optional)  */
    ngx_str_t    master_key;       /* brix_cvmfs_verify_manifest <pem>: repo
                                      master public key(s); fills of
                                      .cvmfspublished/.cvmfswhitelist must
                                      verify the full signature chain before
                                      publish ("" = off, phase-85 F1)        */
    ngx_array_t *upstream_allow;   /* brix_cvmfs_upstream_allow host…       */
    ngx_uint_t   upstream_max;     /* brix_cvmfs_upstream_max (default 8)   */
    ngx_uint_t   origin_select;    /* brix_cvmfs_origin_select (T19)        */
    ngx_array_t *origin_coords;    /* brix_cvmfs_origin_coords entries      */
    ngx_str_t    here;             /* brix_cvmfs_here lat:lon (geo mode)    */
    time_t       rtt_interval;     /* brix_cvmfs_rtt_interval (default 60)  */
    time_t       client_hold;      /* brix_cvmfs_client_hold (default 25;
                                      MUST stay below the WN CVMFS_TIMEOUT)   */
    time_t       fill_max_life;    /* brix_cvmfs_fill_max_life (default 300)*/
    ngx_flag_t   trace;            /* brix_cvmfs_trace on|off (default off):
                                      promote the client-op + upstream-request
                                      trace lines from DEBUG to INFO          */

    /* upstream stall detection + force-through retry (2026-07-03) */
    time_t       origin_connect_timeout; /* connect ceiling s (default 2)     */
    time_t       origin_stall_timeout;   /* no-first-byte/low-speed s (def 4)  */
    ngx_uint_t   origin_stall_bytes;     /* throughput floor B/s (default 1)   */
    time_t       origin_attempt_timeout; /* per-attempt total cap s (0=off)    */
    ngx_flag_t   origin_reuse_conn;      /* reuse keep-alive conn (default on);
                                            off = fresh conn per request for a
                                            connection-reaping middlebox        */
    ngx_uint_t   fill_retry_policy;      /* failover|force-primary (def fail)  */
    ngx_uint_t   origin_http_version;    /* brix_cvmfs_origin_http_version
                                            1.1|2|2-direct|3 (default unset =
                                            libcurl's own policy, phase-85 F11):
                                            2 = ALPN h2 / h2c Upgrade with an
                                            automatic HTTP/1.1 fallback;
                                            2-direct = cleartext h2 prior
                                            knowledge (origin MUST speak h2);
                                            3 = QUIC, refused at config time
                                            when the linked libcurl lacks it    */
    ngx_flag_t   shared_cache;           /* proxy-mode: share ONE cache across
                                            all upstreams (content-addressed
                                            CVMFS is identical per Stratum-1)  */
    ngx_flag_t   unified_origin;         /* proxy-mode: serve EVERY client-named
                                            Stratum-1 from the ONE configured
                                            multi-endpoint brix_cvmfs_storage_
                                            backend (ranked failover + shared
                                            cache) instead of a per-host backend
                                            — a dead origin is hidden by internal
                                            failover so the client keeps getting
                                            200 and never abandons this proxy    */

    /* server-side geo answering (2026-07-03) */
    ngx_uint_t   geo_answer;       /* off|rtt (default off = passthrough)      */
    time_t       geo_cache_ttl;    /* per-host RTT cache TTL s (default 60)     */
    ngx_uint_t   geo_max_servers;  /* probed-list cap (default 16)             */
} brix_cvmfs_conf_t;

/* One brix_cvmfs_repo_authz entry (phase-85 F3): the named repo (or "*") is
 * served only to holders of a READ-scope token from this issuer registry. */
typedef struct {
    ngx_str_t    repo;             /* fqrn to gate, or "*" = every repo      */
    ngx_str_t    issuers;          /* scitokens.cfg path                     */
    void        *registry;         /* brix_token_registry_t*, built at merge */
} brix_cvmfs_repo_authz_t;

/* One brix_cvmfs_qos class (phase-85 F9): token-subject → fill-rate class.
 * `fills` bounds ORIGIN FILLS per second (token bucket, burst = fills; 0 =
 * unlimited — parity with no QoS). sub.len == 0 is the `default` class:
 * unclassified traffic (no validated bearer, or a subject no class names).
 * The bucket fields are runtime state: conf memory is per-worker after fork
 * (COW) and only touched on the event loop, so a class bounds each worker
 * independently — no locks, no shared memory. */
typedef struct {
    ngx_str_t    name;             /* class label (logs/audit)               */
    ngx_str_t    sub;              /* token subject; "" = default class      */
    ngx_uint_t   fills;            /* max fills/sec; 0 = unlimited           */
    ngx_msec_t   last;             /* bucket: last refill (worker-local)     */
    ngx_int_t    tokens;           /* bucket: milli-fills (1000 = one fill)  */
} brix_cvmfs_qos_t;

typedef struct {
    /* shared per-protocol storage/tier preamble — SAME struct the webdav and
     * s3 loc-confs embed; populated by the brix_cvmfs_storage_backend /
     * brix_cvmfs_cache_store directive family (phase-64 idiom: each
     * protocol registers its own names over the shared struct). */
    ngx_http_brix_shared_conf_t  common;

    brix_cvmfs_conf_t            cvmfs;    /* protocol-specific knobs      */

    /* ---- scvmfs:// (T22, EXPERIMENTAL) — the secure layer ON cvmfs ---- */
    ngx_flag_t   scvmfs;               /* brix_scvmfs on|off (default off) */
    ngx_uint_t   scvmfs_authz;         /* brix_scvmfs_authz none|bearer    */
    ngx_str_t    scvmfs_token_issuers; /* scitokens.cfg path (bearer mode)   */
    void        *scvmfs_registry;      /* brix_token_registry_t*, built at
                                          merge when bearer mode is on       */

    /* ---- token-gated repos (phase-85 F3) ---- */
    ngx_array_t *repo_authz;           /* brix_cvmfs_repo_authz_t entries;
                                          NULL = no repo is gated            */

    /* ---- per-VO/per-job QoS fill throttling (phase-85 F9) ---- */
    ngx_array_t *qos;                  /* brix_cvmfs_qos_t classes;
                                          NULL = no throttling               */
} ngx_http_brix_cvmfs_loc_conf_t;

/* scvmfs client-authz modes (VOMS/GSI client-cert mode is future work —
 * the WebDAV auth_cert machinery needs a conf-independent seam first). */
typedef enum {
    BRIX_SCVMFS_AUTHZ_NONE = 0,     /* TLS transport only, no client auth */
    BRIX_SCVMFS_AUTHZ_BEARER        /* Authorization: Bearer + read scope */
} brix_scvmfs_authz_e;

/* Per-request ctx set by the handler on entry (convention #2 of the phase-68
 * plan). sd_override is the proxy-mode (T14) per-upstream storage instance;
 * NULL means the location's static backend serves the request. */
typedef struct {
    brix_sd_instance_t *sd_override;     /* proxy mode (T14)               */
    const char           *up_root;         /* proxy-mode registry root key   */
    cvmfs_url_info_t      url;             /* classify result                */
    ngx_brix_cvmfs_repo_metrics_t *repo; /* per-fqrn SHM counters (bounded
                                              slot table; NULL = unmapped)   */
    ngx_uint_t            cache_status;    /* HIT/FILL/STALE/NEG — $cvmfs_cache
                                              (T16)                          */
    ngx_str_t             origin_used;     /* host:port of the fill origin —
                                              $cvmfs_origin (T16)            */
    brix_sess_xfer_t      sess_xfer;       /* GET transfer lifecycle record */
    char                  token_sub[256];  /* validated bearer subject (F3/
                                              scvmfs paths); "" = anonymous —
                                              the F9 QoS classification key  */
    unsigned              sess_attempt_logged:1;
    unsigned              sess_xfer_started:1;
    unsigned              secure:1;        /* scvmfs (T22)                   */
} ngx_http_brix_cvmfs_ctx_t;

extern ngx_module_t  ngx_http_brix_cvmfs_module;

/* Content handler — installed by the brix_cvmfs directive on its location
 * (Task 9 implements it; Task 8 ships a 501 stub). */
ngx_int_t ngx_http_brix_cvmfs_handler(ngx_http_request_t *r);

/* Gate — classify + route/reject policy, called BY the handler (Task 9). */
ngx_int_t brix_cvmfs_gate(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* Uncached Geo-API passthrough over the shared HTTP transport (Task 9). */
ngx_int_t brix_cvmfs_geo_passthrough(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* Server-side geo answer (2026-07-03): RTT-rank the client-supplied server list
 * from THIS proxy's vantage and reply with the nearest-first permutation,
 * instead of trusting the upstream GeoAPI. Returns NGX_DONE (async) or falls
 * back to brix_cvmfs_geo_passthrough on any parse/setup failure. */
ngx_int_t brix_cvmfs_geo_answer(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* One timed nonblocking connect → RTT µs, or -1 on any failure. Shared between
 * the background origin RTT probe (origin_probe.c) and the on-demand geo
 * answer (geo_answer.c). */
long brix_cvmfs_connect_rtt_us(const char *host, int port, int timeout_ms);

/* Proxy-mode target extraction (T14): NGX_DECLINED = origin-form (reverse
 * mode), NGX_OK = allowed absolute-form authority (host/port filled), or a
 * final 403/400 status. */
ngx_int_t brix_cvmfs_proxy_target(ngx_http_request_t *r,
    const brix_cvmfs_conf_t *cc, ngx_str_t *host, in_port_t *port);

/* Proxy-mode per-upstream backend (T14): the (host,port)'s synthetic export,
 * built once per worker. On success *up_root_out names its registry root
 * (worker-lifetime storage). NULL + *status set on failure. */
brix_sd_instance_t *brix_cvmfs_upstream_get(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, const ngx_str_t *host,
    in_port_t port, const char **up_root_out, ngx_uint_t *status);

/* Final-status observer (T13): records 404s in the per-worker negative memo.
 * Invoked from the handler's request-finalization hook, so every 404 path —
 * inline open, off-loop fill, future hold/retry — feeds the memo. */
void brix_cvmfs_notify_status(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_uint_t status);

/* scvmfs (T22, EXPERIMENTAL) security preamble: NGX_DECLINED = proceed
 * (transport verified + client authenticated per brix_scvmfs_authz);
 * anything else is a final status (400/401). */
ngx_int_t brix_scvmfs_preamble(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* Token-gated repos (phase-85 F3): evaluate brix_cvmfs_repo_authz for the
 * classified repo. NGX_DECLINED = not gated, or gated and a valid READ-scope
 * bearer was presented — proceed; NGX_HTTP_BAD_REQUEST = gated repo on a
 * cleartext connection (a bearer must never ride cleartext); NGX_HTTP_
 * UNAUTHORIZED = missing/invalid/out-of-scope bearer. Runs AFTER classify
 * (needs ctx->url.repo), covers every class: CAS, metadata, geo. */
ngx_int_t brix_cvmfs_repo_authz_eval(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* Per-VO QoS (phase-85 F9): charge one ORIGIN FILL against the request's
 * class bucket (ctx->token_sub → class, else the `default` class). Called
 * only when a remote miss-fill is about to run — cache hits are never
 * throttled. NGX_DECLINED = proceed (no QoS configured / class unlimited /
 * budget available); NGX_HTTP_TOO_MANY_REQUESTS = this class's fill budget
 * is exhausted this second (the client retries; other classes keep flowing). */
ngx_int_t brix_cvmfs_qos_check(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* T19 rtt mode: record (at config time) that the export at `root_canon` runs
 * the per-worker RTT probe; arm the probe timers at worker init. */
void      brix_cvmfs_rtt_register(const char *root_canon, time_t interval,
    const ngx_str_t *pool_name);
ngx_int_t brix_cvmfs_rtt_init_worker(ngx_cycle_t *cycle);

/* $cvmfs_cache dispositions (request ctx cache_status; 0 = not applicable). */
#define BRIX_CVMFS_CACHE_NONE  0u
#define BRIX_CVMFS_CACHE_HIT   1u
#define BRIX_CVMFS_CACHE_FILL  2u
#define BRIX_CVMFS_CACHE_NEG   3u

#endif /* BRIX_CVMFS_H */
