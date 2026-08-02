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

    /* chunk-bundle batch fetch (phase-87 G2) */
    ngx_flag_t   bundle;           /* brix_cvmfs_bundle on|off (default off):
                                      POST /cvmfs/<repo>/.cvmfs-bundle accepts
                                      a want-list of CAS paths and streams the
                                      CACHE-RESIDENT members back in one framed
                                      response (misses get markers; the client
                                      falls back to single GETs, which fill the
                                      cache). Never fills from the origin, so
                                      the response is bounded and synchronous. */

    /* trained shared-dictionary transfer coding (phase-87 G3) */
    ngx_flag_t   dict;             /* brix_cvmfs_dict on|off (default off):
                                      GET /cvmfs/<repo>/.cvmfs-dict/current
                                      trains (lazily, per worker, from resident
                                      CAS samples) and serves a zstd dictionary;
                                      CAS GETs carrying a matching X-Brix-Dict
                                      header may be answered dict-coded
                                      (Content-Encoding: zstd-dict). The coding
                                      is a reversible wire transform of the
                                      STORED bytes — client-side CAS verify is
                                      untouched, so a wrong dictionary can only
                                      fail decode, never poison data.          */
    void        *dict_state;       /* per-worker lazily-trained dictionary
                                      cache (dict.c owns; COW after fork, so
                                      each worker trains its own — no SHM, no
                                      new globals). NULL until first use.      */

    /* background CAS integrity scrubbing (phase-87 G17) */
    ngx_flag_t   scrub;            /* brix_cvmfs_scrub on|off (default off):
                                      worker-0 timer re-verifies resident CAS
                                      objects against their content address in
                                      bounded windows; a mismatch (local disk
                                      bitrot — never an origin event, no
                                      tamper signal) is evicted so the next
                                      access re-fills verified.               */
    time_t       scrub_interval;   /* brix_cvmfs_scrub_interval (default 60s):
                                      pause between scrub passes              */
    ngx_uint_t   scrub_rate;       /* brix_cvmfs_scrub_rate (default 20, max
                                      256): CAS objects hashed per pass       */

    /* cross-revision delta transfer (phase-87 G10) */
    ngx_flag_t   delta;            /* brix_cvmfs_delta on|off (default off):
                                      a CAS GET carrying X-Brix-Delta-Base
                                      <40-hex> may be answered as a zstd delta
                                      against that base object when the base
                                      is cache-RESIDENT (never an origin
                                      fetch) and the delta is strictly
                                      smaller; the client reconstructs and
                                      CAS-verifies, falling back to a whole-
                                      object refetch on any mismatch.        */

    /* workload-learned predictive prewarm (phase-87 G11) */
    ngx_flag_t   learn;            /* brix_cvmfs_learn on|off (default off):
                                      passively learn per-connection CAS
                                      access sequences (fixed-size Markov
                                      successor table, learn.c) and prewarm
                                      predicted next objects through the
                                      cache-fill seam on the thread pool.
                                      Advisory: never touches the serve that
                                      triggered it, and holds no per-user or
                                      token content (INVARIANT #8).          */

    /* P2P swarm cold-start (phase-87 G12) */
    ngx_flag_t   swarm;            /* brix_cvmfs_swarm on|off (default off):
                                      gossip-maintained dynamic mesh
                                      membership (swarm.c) seeded from the
                                      static brix_cache_peers ring; serves
                                      /cvmfs/.swarm/roster and republishes
                                      the live rendezvous ring into the
                                      cache fill spine. Requires
                                      brix_cache_peers.                      */
    time_t       swarm_interval;   /* brix_cvmfs_swarm_interval <sec>
                                      (default 3): gossip probe cadence.    */
} brix_cvmfs_conf_t;

/* One brix_cvmfs_repo_authz entry (phase-85 F3): the named repo (or "*") is
 * served only to holders of a READ-scope token from this issuer registry. */
typedef struct {
    ngx_str_t    repo;             /* fqrn to gate, or "*" = every repo      */
    ngx_str_t    issuers;          /* scitokens.cfg path                     */
    void        *registry;         /* brix_token_registry_t*, built at merge */
} brix_cvmfs_repo_authz_t;

/* One brix_cvmfs_virtual_repo entry (phase-87 G16): requests naming the
 * virtual fqrn are rewritten to (and served as) the first member repo that
 * has the object — declaration order is the precedence, and only a
 * definitive 404 advances to the next member. */
typedef struct {
    ngx_str_t     fqrn;            /* the virtual (client-facing) repo name  */
    ngx_array_t  *members;         /* ngx_str_t member fqrns, precedence
                                      order                                  */
} brix_cvmfs_virtual_t;

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
    ngx_array_t *scvmfs_x509_dn;       /* ngx_str_t[] EEC-DN allow-globs
                                          (x509 mode); NULL/empty = accept
                                          any verified client cert           */

    /* voms mode: x509 verification PLUS a VOMS-FQAN gate. vomsdir (per-VO LSC)
     * and voms_cert_dir (VOMS signing-CA trust) verify+lift the proxy's VOMS
     * VOs; scvmfs_voms is the allow-glob of VO names (NULL/empty = accept any
     * verified client carrying at least one VO). */
    ngx_str_t    scvmfs_vomsdir;       /* brix_scvmfs_vomsdir <dir>          */
    ngx_str_t    scvmfs_voms_cert_dir; /* brix_scvmfs_voms_cert_dir <dir>    */
    ngx_array_t *scvmfs_voms;          /* ngx_str_t[] VO-name allow-globs    */

    /* ---- token-gated repos (phase-85 F3) ---- */
    ngx_array_t *repo_authz;           /* brix_cvmfs_repo_authz_t entries;
                                          NULL = no repo is gated            */

    /* ---- per-VO/per-job QoS fill throttling (phase-85 F9) ---- */
    ngx_array_t *qos;                  /* brix_cvmfs_qos_t classes;
                                          NULL = no throttling               */

    /* ---- virtual / composed repos (phase-87 G16) ---- */
    ngx_array_t *virtual_repos;        /* brix_cvmfs_virtual_t entries;
                                          NULL = none                        */

    /* ---- runtime provenance attestation (phase-87 G15) ---- */
    void        *attest_pkey;          /* EVP_PKEY* signing key, loaded at
                                          config time; NULL = attest off     */
} ngx_http_brix_cvmfs_loc_conf_t;

/* scvmfs client-authz modes. x509 authenticates the TLS-verified peer by its
 * end-entity (EEC) subject DN — RFC 3820 proxy certs are skipped so a GSI proxy
 * authenticates as its issuing EEC — against an optional DN allow-glob list.
 * voms rides on top of x509: it additionally lifts+verifies the proxy's VOMS
 * VO(s) (per-VO LSC vomsdir + VOMS signing-CA voms_cert_dir) and gates them by
 * the brix_scvmfs_voms allow-glob; a proxy with no VOMS AC fails closed. */
typedef enum {
    BRIX_SCVMFS_AUTHZ_NONE = 0,     /* TLS transport only, no client auth */
    BRIX_SCVMFS_AUTHZ_BEARER,       /* Authorization: Bearer + read scope */
    BRIX_SCVMFS_AUTHZ_X509,         /* verified client cert; EEC DN allow-glob */
    BRIX_SCVMFS_AUTHZ_VOMS          /* x509 + VOMS-VO allow-glob gate */
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
    /* virtual repo composition (phase-87 G16): set by the gate when the
     * request named a virtual fqrn; virt_uri/virt_off preserve the original
     * (virtual-name) uri + the fqrn span so each member attempt rewrites
     * from the same anchor. NULL virt = a direct (non-composed) request. */
    brix_cvmfs_virtual_t *virt;          /* matched entry (conf memory)    */
    ngx_uint_t            virt_idx;      /* member currently being tried   */
    ngx_str_t             virt_uri;      /* original virtual-name uri      */
    size_t                virt_off;      /* fqrn offset within virt_uri    */
    ngx_str_t             attest_label;  /* validated X-Brix-Attest session
                                            label, r->pool copy; len 0 =
                                            untagged request (G15)         */
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

/* postconfig hook: for an scvmfs x509/voms server, set
 * X509_V_FLAG_ALLOW_PROXY_CERTS on its TLS context so a client GSI proxy chain
 * verifies (nginx core rejects proxy certs otherwise). No-op when scvmfs is off,
 * authz is not x509/voms, or the server has no TLS context. cscf is an
 * ngx_http_core_srv_conf_t *; the hook walks the server's location tree for any
 * scvmfs x509/voms location. Keeps the openssl/ssl-module coupling in secure.c
 * (module.c has no SSL includes). */
ngx_int_t brix_scvmfs_postconf_proxy_certs(ngx_conf_t *cf, void *cscf);

/* Token-gated repos (phase-85 F3): evaluate brix_cvmfs_repo_authz for the
 * classified repo. NGX_DECLINED = not gated, or gated and a valid READ-scope
 * bearer was presented — proceed; NGX_HTTP_BAD_REQUEST = gated repo on a
 * cleartext connection (a bearer must never ride cleartext); NGX_HTTP_
 * UNAUTHORIZED = missing/invalid/out-of-scope bearer. Runs AFTER classify
 * (needs ctx->url.repo), covers every class: CAS, metadata, geo. */
ngx_int_t brix_cvmfs_repo_authz_eval(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* Pure gate lookup: non-zero iff `repo` matches a brix_cvmfs_repo_authz
 * entry (exact or "*") in this location. No token evaluation. */
ngx_uint_t brix_cvmfs_repo_authz_gated(ngx_http_brix_cvmfs_loc_conf_t *lcf,
    const char *repo, size_t repo_len);

/* Virtual / composed repos (phase-87 G16). enter: called by the gate right
 * after classification — a uri naming a configured virtual fqrn is rewritten
 * in place to member[0] and re-classified (NGX_DECLINED = proceed with the
 * gate, whether or not a rewrite happened; 500 only on alloc failure).
 * advance: called on a definitive 404 — rewrites to the next member and
 * returns NGX_OK (re-run the handler), or NGX_DECLINED when the request is
 * not composed / the member list is exhausted (the 404 stands). */
ngx_int_t brix_cvmfs_virtual_enter(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);
ngx_int_t brix_cvmfs_virtual_advance(ngx_http_request_t *r);

/* Runtime provenance attestation (phase-87 G15, attest.c). gate: intercepts
 * GET <loc>/.cvmfs-attest?session=<label> (the signed consumed-hash record;
 * pre-classification, like the swarm roster) and captures a data request's
 * X-Brix-Attest session label into ctx. NGX_DECLINED = not the endpoint —
 * proceed with normal gating. observe: request-finalization hook — records
 * the served CAS hash under the tagged session (per-worker table). */
ngx_int_t brix_cvmfs_attest_gate(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);
void brix_cvmfs_attest_observe(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    ngx_uint_t status);

/* Per-VO QoS (phase-85 F9): charge one ORIGIN FILL against the request's
 * class bucket (ctx->token_sub → class, else the `default` class). Called
 * only when a remote miss-fill is about to run — cache hits are never
 * throttled. NGX_DECLINED = proceed (no QoS configured / class unlimited /
 * budget available); NGX_HTTP_TOO_MANY_REQUESTS = this class's fill budget
 * is exhausted this second (the client retries; other classes keep flowing). */
ngx_int_t brix_cvmfs_qos_check(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* Chunk-bundle batch fetch (phase-87 G2, bundle.c): read the POSTed
 * want-list, then stream every cache-resident member back in one framed
 * response (shared/cvmfs/bundle/ wire format). Runs only behind the gate's
 * CVMFS_URL_BUNDLE + brix_cvmfs_bundle-on + POST checks. Returns NGX_DONE
 * (body read parked / response sent by the body callback) or a status. */
ngx_int_t brix_cvmfs_bundle_handle(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* Shared-dictionary endpoint (phase-87 G3, dict.c): GET/HEAD
 * /cvmfs/<repo>/.cvmfs-dict/(current|<40-hex id>) — train the per-worker
 * dictionary from resident CAS samples on first hit, then serve the dict
 * bytes with X-Brix-Dict-Id. Runs only behind the gate's CVMFS_URL_DICT +
 * brix_cvmfs_dict-on checks. Returns a status or the send rc. */
ngx_int_t brix_cvmfs_dict_handle(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* Dict-coded CAS serve attempt (phase-87 G3, dict.c): called from the tier
 * open/respond HIT tail with the object already open. When the request opts
 * in (X-Brix-Dict matching this worker's trained dict id) and the object
 * qualifies (GET, CAS class, no Range, small), respond with the
 * zstd-dict-coded bytes (Content-Encoding: zstd-dict + X-Brix-Dict-Id) and
 * return the send rc — fh is closed. Otherwise returns NGX_DECLINED with fh
 * STILL OPEN and no response state touched; the caller serves identity.
 * (brix_vfs_file_t forward-declared to keep this header vfs.h-free.) */
typedef struct brix_vfs_file_s brix_vfs_file_t;
ngx_int_t brix_cvmfs_dict_try_serve(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    brix_vfs_file_t *fh);

/* Delta-coded CAS serve attempt (phase-87 G10, delta.c): same contract as
 * brix_cvmfs_dict_try_serve — when the request opts in (X-Brix-Delta-Base
 * naming a cache-resident COMPLETE base object) and the delta is strictly
 * smaller than identity, respond zstd-delta-coded (base bytes as the raw
 * zstd dictionary) and return the send rc with fh closed; otherwise
 * NGX_DECLINED with fh still open and no response state touched. */
ngx_int_t brix_cvmfs_delta_try_serve(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    brix_vfs_file_t *fh);

/* T19 rtt mode: record (at config time) that the export at `root_canon` runs
 * the per-worker RTT probe; arm the probe timers at worker init. */
void      brix_cvmfs_rtt_register(const char *root_canon, time_t interval,
    const ngx_str_t *pool_name);
ngx_int_t brix_cvmfs_rtt_init_worker(ngx_cycle_t *cycle);

/* Phase-87 G17 background scrub: record (at config time) that the export at
 * `root_canon` re-verifies resident CAS objects on a schedule; arm the
 * worker-0 scrub timer at worker init (scrub.c). */
void      brix_cvmfs_scrub_register(const char *root_canon, time_t interval,
    ngx_uint_t rate, const ngx_str_t *pool_name);
ngx_int_t brix_cvmfs_scrub_init_worker(ngx_cycle_t *cycle);

/* Phase-87 G11 predictive prewarm (learn.c): config-time export
 * registration, a per-worker model + fill task at worker init, and the
 * passive request-path hook — learn the connection's previous-key → key
 * transition, then prewarm the confident successors via the thread pool.
 * Advisory by contract: every miss condition is a silent no-op. */
void      brix_cvmfs_learn_register(const char *root_canon,
    const ngx_str_t *pool_name);
ngx_int_t brix_cvmfs_learn_init_worker(ngx_cycle_t *cycle);
void      brix_cvmfs_learn_note(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    brix_sd_instance_t *sd, const char *key);

/* Phase-87 G12 P2P swarm (swarm.c): config-time export registration, a
 * per-worker gossip timer + probe task at worker init (EVERY worker — the
 * published ring is per-worker registry state), and the roster endpoint the
 * gate intercepts pre-classification (GET <root>/.swarm/roster; NGX_DECLINED
 * for any other request). */
void      brix_cvmfs_swarm_register(const char *root_canon, time_t interval,
    const ngx_str_t *pool_name);
ngx_int_t brix_cvmfs_swarm_init_worker(ngx_cycle_t *cycle);
ngx_int_t brix_cvmfs_swarm_roster_serve(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* $cvmfs_cache dispositions (request ctx cache_status; 0 = not applicable). */
#define BRIX_CVMFS_CACHE_NONE  0u
#define BRIX_CVMFS_CACHE_HIT   1u
#define BRIX_CVMFS_CACHE_FILL  2u
#define BRIX_CVMFS_CACHE_NEG   3u

#endif /* BRIX_CVMFS_H */
