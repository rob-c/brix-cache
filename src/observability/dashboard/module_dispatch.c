#include "dashboard_http.h"
#include "api_admin.h"   /* Phase 23: brix_admin_dispatch */
#include "core/http/http_headers.h"   /* brix_http_source_offer (AGPL sec.13) */

#include "module_internal.h"

/*
 * dashboard/module_dispatch.c - request URI routing for the live monitor.
 *
 * WHAT: The content handler installed at the dashboard location plus its
 *       route-table dispatch machinery, split out of module.c so every
 *       dashboard module translation unit stays under the file-size cap.
 * WHY:  Routing is a cohesive concern with no coupling to the nginx module
 *       glue (command table / module struct stay in module.c); moved out
 *       VERBATIM (zero behavior change).
 */

/* Exact URI match (length and bytes). */
static ngx_int_t
dashboard_uri_eq(ngx_str_t uri, const char *literal)
{
    size_t len = ngx_strlen(literal);

    return uri.len == len && ngx_memcmp(uri.data, literal, len) == 0;
}

/* Strict prefix match: uri must be STRICTLY longer than `literal` (uri.len >
 * len), so a bare collection path does not match its own "<path>/" prefix form —
 * letting _eq and _prefix routes coexist (e.g. ".../transfers" vs
 * ".../transfers/<id>"). */
static ngx_int_t
dashboard_uri_prefix(ngx_str_t uri, const char *literal)
{
    size_t len = ngx_strlen(literal);

    return uri.len > len && ngx_memcmp(uri.data, literal, len) == 0;
}

/*
 * Route-table dispatch (main_handler decomposition).
 *
 * Two ordered `static const` tables replace the former if-ladder while keeping
 * byte-identical routing.  Every match test is either `dashboard_uri_eq` (exact)
 * or `dashboard_uri_prefix` (strictly-longer prefix); both are mutually
 * exclusive across distinct literals, so within a table order does not change
 * which literal a URI matches.  The ORDER BETWEEN groups is what stays frozen:
 * concrete API/handler routes first, then the admin prefix, then the generic
 * "/api/v1/" catch-all, then the page/login tail — most-specific first.
 */

/* How a route row matches its literal against the request URI. */
typedef enum {
    DASH_MATCH_EQ = 0,   /* exact match  (dashboard_uri_eq)     */
    DASH_MATCH_PREFIX    /* strict prefix (dashboard_uri_prefix) */
} dashboard_match_kind_t;

/* A route that dispatches into the versioned JSON API by endpoint id. */
typedef struct {
    dashboard_match_kind_t         match;
    const char                    *literal;
    brix_dashboard_api_endpoint_e  endpoint;
} dashboard_api_route_t;

/* A route that dispatches to a dedicated per-endpoint handler (exact match). */
typedef struct {
    const char *literal;
    ngx_int_t (*handler)(ngx_http_request_t *r);
} dashboard_handler_route_t;

/*
 * Concrete versioned-API routes (compat + /api/v1/ *).  Exact rows are mutually
 * exclusive; the single PREFIX row (".../transfers/") is exclusive from the
 * exact ".../transfers" because prefix requires uri STRICTLY longer.
 */
static const dashboard_api_route_t dashboard_api_routes[] = {
    { DASH_MATCH_EQ,     "/brix/transfers",             BRIX_DASHBOARD_API_COMPAT_TRANSFERS },
    { DASH_MATCH_EQ,     "/brix/api/v1/transfers",      BRIX_DASHBOARD_API_V1_TRANSFERS },
    { DASH_MATCH_PREFIX, "/brix/api/v1/transfers/",     BRIX_DASHBOARD_API_V1_TRANSFER_DETAIL },
    { DASH_MATCH_EQ,     "/brix/api/v1/snapshot",       BRIX_DASHBOARD_API_V1_SNAPSHOT },
    { DASH_MATCH_EQ,     "/brix/api/v1/events",         BRIX_DASHBOARD_API_V1_EVENTS },
    { DASH_MATCH_EQ,     "/brix/api/v1/history",        BRIX_DASHBOARD_API_V1_HISTORY },
    { DASH_MATCH_EQ,     "/brix/api/v1/cluster",        BRIX_DASHBOARD_API_V1_CLUSTER },
    { DASH_MATCH_EQ,     "/brix/api/v1/cache",          BRIX_DASHBOARD_API_V1_CACHE },
    { DASH_MATCH_EQ,     "/brix/api/v1/ratelimit",      BRIX_DASHBOARD_API_V1_RATELIMIT },  /* Phase 25 */
    { DASH_MATCH_EQ,     "/brix/api/v1/cvmfs",          BRIX_DASHBOARD_API_V1_CVMFS },      /* phase-68 */
};

/*
 * Dedicated-handler routes (exact match).  All ALWAYS auth-only inside their
 * handler and 404 when the backing feature is unconfigured:
 *   config   text/plain config download (never anonymous)
 *   files/download    admin file browser, confined to browse_root
 *   vfs*     VFS export browser (brix_dashboard_vfs_browse), all via brix_vfs_*
 *   scan     storage scan/verify/fill engine, confined to scan_root
 * These must all precede the generic "/api/v1/" catch-all.
 */
static const dashboard_handler_route_t dashboard_handler_routes[] = {
    { "/brix/api/v1/config",       ngx_http_brix_dashboard_config_download_handler },
    { "/brix/api/v1/files",        ngx_http_brix_dashboard_files_handler },
    { "/brix/api/v1/download",     ngx_http_brix_dashboard_download_handler },
    { "/brix/api/v1/vfs",          ngx_http_brix_dashboard_vfs_exports_handler },
    { "/brix/api/v1/vfs/files",    ngx_http_brix_dashboard_vfs_files_handler },
    { "/brix/api/v1/vfs/download", ngx_http_brix_dashboard_vfs_download_handler },
    { "/brix/api/v1/scan",         ngx_http_brix_dashboard_scan_handler },
};

/*
 * WHAT: True when `uri` matches `route`'s literal under its match kind.
 * WHY:  Single predicate keeps the two dispatch loops branch-free of the
 *       eq-vs-prefix distinction, preserving the exact original semantics.
 * HOW:  Delegate to the same _eq/_prefix helpers the if-ladder used.
 */
static ngx_int_t
dashboard_api_route_matches(ngx_str_t uri, const dashboard_api_route_t *route)
{
    if (route->match == DASH_MATCH_PREFIX) {
        return dashboard_uri_prefix(uri, route->literal);
    }
    return dashboard_uri_eq(uri, route->literal);
}

/*
 * WHAT: Try the concrete versioned-API routes; on the first match, dispatch to
 *       the JSON API handler for that endpoint and store the result in *out.
 * WHY:  Collapses ten identical eq/prefix -> api_handler branches into one
 *       ordered scan without changing which URI hits which endpoint id.
 * HOW:  Linear scan of dashboard_api_routes (exact rows are mutually exclusive;
 *       order is irrelevant within them). Returns NGX_OK on a match, NGX_DECLINED
 *       when no API route applies so the caller falls through to later groups.
 */
static ngx_int_t
dashboard_dispatch_api_route(ngx_http_request_t *r, ngx_str_t uri,
    ngx_int_t *out)
{
    size_t i;

    for (i = 0; i < sizeof(dashboard_api_routes)
                        / sizeof(dashboard_api_routes[0]); i++) {
        if (dashboard_api_route_matches(uri, &dashboard_api_routes[i])) {
            *out = ngx_http_brix_dashboard_api_handler(r,
                dashboard_api_routes[i].endpoint);
            return NGX_OK;
        }
    }
    return NGX_DECLINED;
}

/*
 * WHAT: Try the dedicated-handler routes; on the first exact match, invoke that
 *       handler and store its result in *out.
 * WHY:  Collapses the config/files/download/vfs* / scan exact-match branches into
 *       one scan; all rows are exact and mutually exclusive.
 * HOW:  Linear scan of dashboard_handler_routes. Returns NGX_OK on a match,
 *       NGX_DECLINED otherwise (caller continues to the prefix/catch-all/tail).
 */
static ngx_int_t
dashboard_dispatch_handler_route(ngx_http_request_t *r, ngx_str_t uri,
    ngx_int_t *out)
{
    size_t i;

    for (i = 0; i < sizeof(dashboard_handler_routes)
                        / sizeof(dashboard_handler_routes[0]); i++) {
        if (dashboard_uri_eq(uri, dashboard_handler_routes[i].literal)) {
            *out = dashboard_handler_routes[i].handler(r);
            return NGX_OK;
        }
    }
    return NGX_DECLINED;
}

/* Main content handler dispatcher */
/*
 * WHAT: Content handler installed at the dashboard location; routes the request
 *       URI to the page, login, compat-JSON, versioned-API, or admin handler.
 * HOW:  Groups are tried MOST-SPECIFIC FIRST so exact matches win over prefix
 *       matches (e.g. ".../transfers" before ".../transfers/<id>", and the
 *       known v1 endpoints before the catch-all "/api/v1/" 404). Per-endpoint
 *       auth lives inside the called handlers, not here. Unmatched -> 404.
 */
ngx_int_t
ngx_http_brix_dashboard_main_handler(ngx_http_request_t *r)
{
    ngx_http_brix_dashboard_loc_conf_t *conf;
    ngx_str_t                           uri;
    ngx_int_t                           rc = NGX_DECLINED;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_dashboard_module);
    if (!conf->enable) {
        return NGX_HTTP_NOT_FOUND;
    }

    /* AGPL-3.0 sec.13: offer remote users the source (X-Source header). */
    brix_http_source_offer(r);

    uri = r->uri;

    if (dashboard_dispatch_api_route(r, uri, &rc) == NGX_OK) {
        return rc;
    }
    if (dashboard_dispatch_handler_route(r, uri, &rc) == NGX_OK) {
        return rc;
    }

    /* Phase 23: admin write API (auth + method routing inside dispatch). */
    if (uri.len >= sizeof("/brix/api/v1/admin/") - 1
        && ngx_memcmp(uri.data, "/brix/api/v1/admin/",
                      sizeof("/brix/api/v1/admin/") - 1) == 0)
    {
        return brix_admin_dispatch(r);
    }

    /* Catch-all for unknown /api/v1/ paths: return the API's structured 404
     * (must come AFTER every concrete v1 route above). */
    if (uri.len > sizeof("/brix/api/v1/") - 1
        && ngx_memcmp(uri.data, "/brix/api/v1/",
                      sizeof("/brix/api/v1/") - 1) == 0)
    {
        return ngx_http_brix_dashboard_api_handler(r,
            BRIX_DASHBOARD_API_V1_NOT_FOUND);
    }

    if (dashboard_uri_eq(uri, "/brix/login"))
    {
        return ngx_http_brix_dashboard_login_handler(r);
    }

    if (dashboard_uri_eq(uri, "/brix") || dashboard_uri_eq(uri, "/brix/")) {
        return ngx_http_brix_dashboard_page_handler(r);
    }

    return NGX_HTTP_NOT_FOUND;
}
