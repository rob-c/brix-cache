#ifndef NGX_HTTP_XROOTD_SRR_H
#define NGX_HTTP_XROOTD_SRR_H

/*
 * srr.h — WLCG Storage Resource Reporting (SRR) HTTP/JSON endpoint.
 *
 * WHAT: Public types + entry points for a small standalone HTTP sub-module that
 *   serves the WLCG "storageservice" JSON document (Storage Resource Reporting,
 *   schema v4.x) at an operator-chosen location.  WLCG accounting tooling
 *   (CRIC, the WLCG storage-space accounting harvester, DIRAC occupancy plugins)
 *   pulls this document straight from an HTTP URL to learn a site's total/used
 *   space per share and the protocol endpoints that serve it.
 *
 * WHY: This module deliberately does NOT implement the XRootD UDP f-stream /
 *   g-stream monitoring packet protocol.  WLCG storage accounting is already
 *   HTTP/JSON-native via SRR, so an HTTP endpoint integrates with the existing
 *   WLCG stack with far less effort (and no extra collector/shoveler) than the
 *   binary UDP monitoring stack would.  Transfer/operation counters remain
 *   available on the Prometheus /metrics endpoint (see src/metrics/).
 *
 * HOW: A location with `xrootd_srr on;` binds ngx_http_xrootd_srr_handler.  The
 *   document is built on each request (builder.c): per-share filesystem space
 *   comes from statvfs(2) via xrootd_fs_usage_stat(); identity/share/endpoint
 *   metadata comes from the xrootd_srr_* directives.  Mirrors the /metrics
 *   module pattern (src/metrics/module.c + handler.c).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * One `xrootd_srr_share <name> <path> [vos]` entry.  <path> is BOTH the local
 * filesystem path that is statvfs(2)'d for space AND the namespace path
 * reported in storageshares[].path[].  <vos> is an optional comma-separated VO
 * list ("atlas,cms") emitted as the required storageshares[].vos array.
 */
typedef struct {
    ngx_str_t  name;   /* storageshares[].name                      */
    ngx_str_t  path;   /* statvfs target + storageshares[].path[0]  */
    ngx_str_t  vos;    /* comma-separated VOs (may be empty)        */
} xrootd_srr_share_t;

/*
 * One `xrootd_srr_endpoint <name> <interfacetype> <url>` entry — a protocol
 * door the site exposes, emitted as a storageendpoints[] item.  interfacetype
 * is a free string by schema (e.g. "https", "davs", "xroot", "s3").
 */
typedef struct {
    ngx_str_t  name;           /* storageendpoints[].name          */
    ngx_str_t  interfacetype;  /* storageendpoints[].interfacetype */
    ngx_str_t  url;            /* storageendpoints[].endpointurl   */
} xrootd_srr_endpoint_t;

/* Per-location configuration for the SRR endpoint. */
typedef struct {
    ngx_flag_t    enable;     /* xrootd_srr on|off                          */
    ngx_str_t     name;       /* xrootd_srr_name    — storageservice.name   */
    ngx_str_t     id;         /* xrootd_srr_id      — .id (default = name)   */
    ngx_str_t     quality;    /* xrootd_srr_quality — .qualitylevel          */
    ngx_str_t     version;    /* xrootd_srr_version — .implementationversion */
    ngx_array_t  *shares;     /* of xrootd_srr_share_t                       */
    ngx_array_t  *endpoints;  /* of xrootd_srr_endpoint_t                    */
} ngx_http_xrootd_srr_loc_conf_t;

extern ngx_module_t ngx_http_xrootd_srr_module;

/* Content handler bound by the `xrootd_srr` directive. */
ngx_int_t ngx_http_xrootd_srr_handler(ngx_http_request_t *r);

/*
 * Build the SRR JSON document into a request-pool buffer.  On success returns
 * NGX_OK and sets out and len (the buffer lives in r->pool); returns NGX_ERROR
 * on allocation/serialisation failure.  Never reads request input — the document
 * is a pure function of the location config + current filesystem usage.
 */
ngx_int_t ngx_http_xrootd_srr_build_json(ngx_http_request_t *r,
    ngx_http_xrootd_srr_loc_conf_t *lcf, u_char **out, size_t *len);

#endif /* NGX_HTTP_XROOTD_SRR_H */
