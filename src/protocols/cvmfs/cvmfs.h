/* cvmfs.h — the cvmfs:// protocol surface.
 *
 * WHAT: loc-conf + request-ctx types, the handler entry, and the gate/geo
 *       prototypes for the dedicated CVMFS protocol plane.
 * WHY:  cvmfs:// is a first-class protocol (peer of webdav/, s3/): its own
 *       module owns configuration and its own content handler owns every
 *       request — WebDAV dispatch is never involved.
 * HOW:  the loc-conf embeds the SAME shared preamble (`common`) the other
 *       HTTP protocols embed, so xrootd_cvmfs_storage_backend /
 *       xrootd_cvmfs_cache_store compose the identical phase-63/64 storage
 *       stack underneath a protocol-specific top.
 */
#ifndef XROOTD_CVMFS_H
#define XROOTD_CVMFS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "classify.h"
#include "core/config/shared_conf.h"
#include "fs/backend/sd.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"

/* T19: origin-selection policy for the multi-endpoint backend. */
typedef enum {
    XROOTD_CVMFS_SELECT_STATIC = 0,   /* configured order (default)        */
    XROOTD_CVMFS_SELECT_GEO,          /* haversine(here, origin coords)    */
    XROOTD_CVMFS_SELECT_RTT           /* measured TCP connect RTT (EWMA)   */
} xrootd_cvmfs_select_e;

/* One xrootd_cvmfs_origin_coords entry: an entry WITH a port matches only
 * that endpoint; without one it matches every endpoint on that host. */
typedef struct {
    ngx_str_t    host;
    in_port_t    port;             /* 0 = any port on this host              */
    double       lat, lon;
} xrootd_cvmfs_coord_t;

typedef struct {
    ngx_flag_t   enable;           /* xrootd_cvmfs on|off (default off)       */
    time_t       manifest_ttl;     /* xrootd_cvmfs_manifest_ttl (default 61s) */
    time_t       negative_ttl;     /* xrootd_cvmfs_negative_ttl (default 10s) */
    ngx_str_t    quarantine_dir;   /* xrootd_cvmfs_quarantine_dir (optional)  */
    ngx_array_t *upstream_allow;   /* xrootd_cvmfs_upstream_allow host…       */
    ngx_uint_t   upstream_max;     /* xrootd_cvmfs_upstream_max (default 8)   */
    ngx_uint_t   origin_select;    /* xrootd_cvmfs_origin_select (T19)        */
    ngx_array_t *origin_coords;    /* xrootd_cvmfs_origin_coords entries      */
    ngx_str_t    here;             /* xrootd_cvmfs_here lat:lon (geo mode)    */
    time_t       rtt_interval;     /* xrootd_cvmfs_rtt_interval (default 60)  */
    time_t       client_hold;      /* xrootd_cvmfs_client_hold (default 25;
                                      MUST stay below the WN CVMFS_TIMEOUT)   */
    time_t       fill_max_life;    /* xrootd_cvmfs_fill_max_life (default 300)*/
} xrootd_cvmfs_conf_t;

typedef struct {
    /* shared per-protocol storage/tier preamble — SAME struct the webdav and
     * s3 loc-confs embed; populated by the xrootd_cvmfs_storage_backend /
     * xrootd_cvmfs_cache_store directive family (phase-64 idiom: each
     * protocol registers its own names over the shared struct). */
    ngx_http_xrootd_shared_conf_t  common;

    xrootd_cvmfs_conf_t            cvmfs;    /* protocol-specific knobs      */

    /* ---- scvmfs:// (T22, EXPERIMENTAL) — the secure layer ON cvmfs ---- */
    ngx_flag_t   scvmfs;               /* xrootd_scvmfs on|off (default off) */
    ngx_uint_t   scvmfs_authz;         /* xrootd_scvmfs_authz none|bearer    */
    ngx_str_t    scvmfs_token_issuers; /* scitokens.cfg path (bearer mode)   */
    void        *scvmfs_registry;      /* xrootd_token_registry_t*, built at
                                          merge when bearer mode is on       */
} ngx_http_xrootd_cvmfs_loc_conf_t;

/* scvmfs client-authz modes (VOMS/GSI client-cert mode is future work —
 * the WebDAV auth_cert machinery needs a conf-independent seam first). */
typedef enum {
    XROOTD_SCVMFS_AUTHZ_NONE = 0,     /* TLS transport only, no client auth */
    XROOTD_SCVMFS_AUTHZ_BEARER        /* Authorization: Bearer + read scope */
} xrootd_scvmfs_authz_e;

/* Per-request ctx set by the handler on entry (convention #2 of the phase-68
 * plan). sd_override is the proxy-mode (T14) per-upstream storage instance;
 * NULL means the location's static backend serves the request. */
typedef struct {
    xrootd_sd_instance_t *sd_override;     /* proxy mode (T14)               */
    const char           *up_root;         /* proxy-mode registry root key   */
    cvmfs_url_info_t      url;             /* classify result                */
    ngx_uint_t            cache_status;    /* HIT/FILL/STALE/NEG — $cvmfs_cache
                                              (T16)                          */
    ngx_str_t             origin_used;     /* host:port of the fill origin —
                                              $cvmfs_origin (T16)            */
    unsigned              secure:1;        /* scvmfs (T22)                   */
} ngx_http_xrootd_cvmfs_ctx_t;

extern ngx_module_t  ngx_http_xrootd_cvmfs_module;

/* Content handler — installed by the xrootd_cvmfs directive on its location
 * (Task 9 implements it; Task 8 ships a 501 stub). */
ngx_int_t ngx_http_xrootd_cvmfs_handler(ngx_http_request_t *r);

/* Gate — classify + route/reject policy, called BY the handler (Task 9). */
ngx_int_t xrootd_cvmfs_gate(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf);

/* Uncached Geo-API passthrough over the shared HTTP transport (Task 9). */
ngx_int_t xrootd_cvmfs_geo_passthrough(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf);

/* Proxy-mode target extraction (T14): NGX_DECLINED = origin-form (reverse
 * mode), NGX_OK = allowed absolute-form authority (host/port filled), or a
 * final 403/400 status. */
ngx_int_t xrootd_cvmfs_proxy_target(ngx_http_request_t *r,
    const xrootd_cvmfs_conf_t *cc, ngx_str_t *host, in_port_t *port);

/* Proxy-mode per-upstream backend (T14): the (host,port)'s synthetic export,
 * built once per worker. On success *up_root_out names its registry root
 * (worker-lifetime storage). NULL + *status set on failure. */
xrootd_sd_instance_t *xrootd_cvmfs_upstream_get(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf, const ngx_str_t *host,
    in_port_t port, const char **up_root_out, ngx_uint_t *status);

/* Final-status observer (T13): records 404s in the per-worker negative memo.
 * Invoked from the handler's request-finalization hook, so every 404 path —
 * inline open, off-loop fill, future hold/retry — feeds the memo. */
void xrootd_cvmfs_notify_status(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf, ngx_uint_t status);

/* scvmfs (T22, EXPERIMENTAL) security preamble: NGX_DECLINED = proceed
 * (transport verified + client authenticated per xrootd_scvmfs_authz);
 * anything else is a final status (400/401). */
ngx_int_t xrootd_scvmfs_preamble(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf);

/* T19 rtt mode: record (at config time) that the export at `root_canon` runs
 * the per-worker RTT probe; arm the probe timers at worker init. */
void      xrootd_cvmfs_rtt_register(const char *root_canon, time_t interval,
    const ngx_str_t *pool_name);
ngx_int_t xrootd_cvmfs_rtt_init_worker(ngx_cycle_t *cycle);

/* $cvmfs_cache dispositions (request ctx cache_status; 0 = not applicable). */
#define XROOTD_CVMFS_CACHE_NONE  0u
#define XROOTD_CVMFS_CACHE_HIT   1u
#define XROOTD_CVMFS_CACHE_FILL  2u
#define XROOTD_CVMFS_CACHE_NEG   3u

#endif /* XROOTD_CVMFS_H */
