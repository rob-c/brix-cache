/*
 * cvmfs_module_georank.c — cvmfs:// config-time geographic origin ranking and
 * coordinate/allow-list directive parsing.
 *
 * WHAT: The config-parse-time helpers that turn geographic directives into
 *   backend origin ranks and allow-list state:
 *     1. cvmfs_conf_upstream_allow / ngx_http_brix_cvmfs_set_coords — the two
 *        multi-argument directive setters (Stratum-1 allow-list; per-origin
 *        <host[:port]> <lat>:<lon> coordinates).
 *     2. cvmfs_geo_rank_config and its two halves (compute_metrics / apply_ranks)
 *        — T19 geo mode: rank every configured http origin once, at config
 *        time, by great-circle distance from brix_cvmfs_here.
 *     3. cvmfs_parse_latlon — the shared "<lat>:<lon>" parser both setters and
 *        the ranking half rely on.
 *
 * WHY: These were split out of module.c (file-size gate). They form one
 *   cohesive concern — geographic origin selection is entirely a config-parse
 *   activity: it reads directive arguments, validates them, and stamps ranks on
 *   the backend entry. Keeping the pure metric derivation (compute_metrics) apart
 *   from the backend-mutating report (apply_ranks) also holds each half under the
 *   complexity gate. Merge order, defaults, and every nginx -t log line are
 *   byte-frozen against the pre-split module.c.
 *
 * HOW: Verbatim move of the original functions. cvmfs_parse_latlon,
 *   cvmfs_geo_compute_metrics, and cvmfs_geo_apply_ranks stay static (their only
 *   callers live in this file); cvmfs_conf_upstream_allow,
 *   ngx_http_brix_cvmfs_set_coords, and cvmfs_geo_rank_config are exported via
 *   cvmfs_module_internal.h (the directive table in module.c and the export
 *   build in cvmfs_module_build.c call them).
 */

#include "cvmfs.h"
#include "cvmfs_module_internal.h"
#include "core/config/config.h"           /* brix_metrics_ensure_zone */
#include "core/config/root_prepare.h"
#include "core/config/http_rootfd.h"
#include "core/config/http_common.h"       /* unified brix_* directive adoption */
#include "core/compat/alloc_guard.h"
#include "fs/cache/verify.h"               /* brix_cache_verify_mode_e */
#include "fs/vfs/vfs_backend_registry.h"
#include "origin_geo.h"
#include "fs/backend/http/sd_http.h"       /* SD_HTTP_EP_MAX */
#include "auth/token/issuer_registry.h"    /* scvmfs bearer registry (T22) */
#include "fs/backend/cache/sd_cache.h"     /* unwrap for $cvmfs_origin (T16) */
#include "fs/cache/origin/s3_transport.h"  /* brix_origin_trace_set (trace) */

#include <stdlib.h>                        /* strtod (coord parsing) */

/* Parse "<lat>:<lon>" into two doubles. 0 on success. */
static int
cvmfs_parse_latlon(const ngx_str_t *v, double *lat, double *lon)
{
    char  buf[64], *colon, *end;

    if (v->len == 0 || v->len >= sizeof(buf)) {
        return -1;
    }
    ngx_memcpy(buf, v->data, v->len);
    buf[v->len] = '\0';
    colon = strchr(buf, ':');
    if (colon == NULL) {
        return -1;
    }
    *colon = '\0';
    *lat = strtod(buf, &end);
    if (end == buf || *end != '\0' || *lat < -90.0 || *lat > 90.0) {
        return -1;
    }
    *lon = strtod(colon + 1, &end);
    if (end == colon + 1 || *end != '\0' || *lon < -180.0 || *lon > 180.0) {
        return -1;
    }
    return 0;
}

/* brix_cvmfs_upstream_allow <host> [host ...] — append EVERY argument to
 * the allowlist. The stock ngx_conf_set_str_array_slot keeps only the first
 * argument per directive, so a site list written on one line silently
 * allowed just its first Stratum-1 (observed in the field: every other
 * Tier-1 answered 403 and clients failed over to — and pinned on — the sole
 * surviving host). Both forms now work: one directive per host, or one
 * directive listing them all. */
char *
cvmfs_conf_upstream_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_cvmfs_loc_conf_t *c = conf;
    ngx_str_t                        *value, *slot;
    ngx_uint_t                        i;

    (void) cmd;

    if (c->cvmfs.upstream_allow == NGX_CONF_UNSET_PTR) {
        c->cvmfs.upstream_allow = ngx_array_create(cf->pool, 4,
                                                   sizeof(ngx_str_t));
        if (c->cvmfs.upstream_allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        slot = ngx_array_push(c->cvmfs.upstream_allow);
        if (slot == NULL) {
            return NGX_CONF_ERROR;
        }
        *slot = value[i];
    }
    return NGX_CONF_OK;
}

/*
 * cvmfs_geo_calc_t — working state shared between the two halves of geo ranking.
 *
 * WHAT: Carries the parsed "here" coordinates, the per-endpoint great-circle
 *   metric array, and the matched-endpoint count computed by the parse half and
 *   consumed by the apply half.
 *
 * WHY: Bundling this state into one struct keeps each helper's signature at
 *   three parameters (cf, conf, calc) — the state is threaded explicitly, no
 *   file-scope globals, and the two halves stay independently reasoned about.
 */
typedef struct {
    double here_lat;
    double here_lon;
    double metric[SD_HTTP_EP_MAX];
    int    n;
} cvmfs_geo_calc_t;

/*
 * cvmfs_geo_compute_metrics() — parse half of geo ranking.
 *
 * WHAT: Validates brix_cvmfs_here, then walks each configured http endpoint,
 *   matches it to a brix_cvmfs_origin_coords entry (host + optional port), and
 *   fills calc->metric[] with the great-circle distance from here to that
 *   origin. Records the matched-endpoint count in calc->n and the parsed here
 *   coordinates in calc->here_lat / calc->here_lon.
 *
 * WHY: Isolating the input validation + distance computation from the rank/
 *   apply side keeps each half within the complexity gate and makes the pure
 *   metric derivation independently reasoned about. No backend state is
 *   mutated here — this half only reads config and computes.
 *
 * HOW: Same nested match loop as before, factored out verbatim; every config
 *   error emits the identical NGX_LOG_EMERG line and returns NGX_CONF_ERROR so
 *   `nginx -t` output is byte-frozen. On success returns NGX_CONF_OK with calc
 *   populated.
 */
static char *
cvmfs_geo_compute_metrics(ngx_conf_t *cf,
    ngx_http_brix_cvmfs_loc_conf_t *conf, cvmfs_geo_calc_t *calc)
{
    double                here_lat = 0.0, here_lon = 0.0;
    const char           *host;
    int                   port, n;
    brix_cvmfs_coord_t *coords;
    ngx_uint_t            i;

    if (conf->cvmfs.here.len == 0
        || cvmfs_parse_latlon(&conf->cvmfs.here, &here_lat, &here_lon) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_origin_select geo requires brix_cvmfs_here "
            "<lat>:<lon>");
        return NGX_CONF_ERROR;
    }
    if (conf->cvmfs.origin_coords == NULL
        || conf->cvmfs.origin_coords->nelts == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_origin_select geo requires one "
            "brix_cvmfs_origin_coords per configured origin");
        return NGX_CONF_ERROR;
    }
    coords = conf->cvmfs.origin_coords->elts;

    for (n = 0; n < SD_HTTP_EP_MAX; n++) {
        int matched = 0;

        if (brix_vfs_backend_http_endpoint_at(conf->common.root_canon, n,
                                                &host, &port) != 0)
        {
            break;
        }
        for (i = 0; i < conf->cvmfs.origin_coords->nelts; i++) {
            size_t hl = ngx_strlen(host);

            if (coords[i].host.len != hl
                || ngx_strncasecmp(coords[i].host.data, (u_char *) host, hl)
                   != 0)
            {
                continue;
            }
            if (coords[i].port != 0 && (int) coords[i].port != port) {
                continue;
            }
            calc->metric[n] = brix_cvmfs_haversine_km(here_lat, here_lon,
                                                  coords[i].lat,
                                                  coords[i].lon);
            matched = 1;
            break;
        }
        if (!matched) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cvmfs_origin_select geo: no brix_cvmfs_origin_coords "
                "for origin %s:%d", host, port);
            return NGX_CONF_ERROR;
        }
    }
    if (n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_origin_select geo requires an http(s) "
            "brix_storage_backend");
        return NGX_CONF_ERROR;
    }

    calc->here_lat = here_lat;
    calc->here_lon = here_lon;
    calc->n = n;
    return NGX_CONF_OK;
}

/*
 * cvmfs_geo_apply_ranks() — build/apply half of geo ranking.
 *
 * WHAT: Ranks the calc->n computed metrics, records the ranks on the backend
 *   entry, and emits the one-line-per-origin operator selection report.
 *
 * WHY: The apply/report side has no config-validation branches, so splitting
 *   it off drops the orchestrator below the complexity gate while keeping the
 *   emitted report lines and backend mutation exactly as they were.
 *
 * HOW: Zeroes the unused rank slots, calls brix_cvmfs_rank_by_metric +
 *   brix_vfs_backend_set_http_ranks, then re-walks the first calc->n endpoints
 *   to emit the WARN-level selection report (WARN because config-parse NOTICE
 *   is dropped at cf->log ERR level). Byte-frozen against the original tail.
 */
static void
cvmfs_geo_apply_ranks(ngx_conf_t *cf,
    ngx_http_brix_cvmfs_loc_conf_t *conf, const cvmfs_geo_calc_t *calc)
{
    int         ranks[SD_HTTP_EP_MAX];
    const char *host;
    int         port, idx;
    int         n = calc->n;

    for (idx = n; idx < SD_HTTP_EP_MAX; idx++) {
        ranks[idx] = 0;
    }
    brix_cvmfs_rank_by_metric(calc->metric, n, ranks);
    brix_vfs_backend_set_http_ranks(conf->common.root_canon, ranks,
                                      SD_HTTP_EP_MAX);

    /* Record the computed ordering so an operator can confirm at startup that,
     * e.g., RAL really did rank ahead of CERN from this site's coordinates.
     * One line per origin with its great-circle distance and resulting rank.
     * WARN, not NOTICE: at config-parse time cf->log is still the prefix log
     * at NGX_LOG_ERR, so a NOTICE would be silently dropped and never reach
     * `nginx -t` output or the startup log — the level that is actually seen
     * is the point of the line. It fires once and reports a decision, not a
     * fault. */
    for (idx = 0; idx < n; idx++) {
        if (brix_vfs_backend_http_endpoint_at(conf->common.root_canon, idx,
                                                &host, &port) != 0)
        {
            break;
        }
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "brix_cvmfs_origin_select geo [selection report]: origin "
            "%s:%d is %.0f km from here (%.4f:%.4f) -> rank %d%s",
            host, port, calc->metric[idx], calc->here_lat, calc->here_lon,
            ranks[idx],
            (ranks[idx] == 0) ? " (preferred: reads try this origin first)"
                              : " (failover only)");
    }
}

/* Geo mode (T19): every configured endpoint must have coordinates and
 * brix_cvmfs_here must be set — rank once by great-circle distance and
 * record the ranks on the backend entry (applied at instance build). This
 * orchestrator is a flat parse-then-apply sequence over the two halves. */
char *
cvmfs_geo_rank_config(ngx_conf_t *cf, ngx_http_brix_cvmfs_loc_conf_t *conf)
{
    cvmfs_geo_calc_t calc;

    ngx_memzero(&calc, sizeof(calc));
    if (cvmfs_geo_compute_metrics(cf, conf, &calc) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    cvmfs_geo_apply_ranks(cf, conf, &calc);
    return NGX_CONF_OK;
}

/* brix_cvmfs_origin_coords <host[:port]> <lat>:<lon> — geographic position
 * of one origin (multi). An entry with a port matches only that endpoint. */
char *
ngx_http_brix_cvmfs_set_coords(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_brix_cvmfs_loc_conf_t *lcf = conf;
    ngx_str_t                        *value = cf->args->elts;
    brix_cvmfs_coord_t             *c;
    u_char                           *colon;

    (void) cmd;
    if (lcf->cvmfs.origin_coords == NGX_CONF_UNSET_PTR
        || lcf->cvmfs.origin_coords == NULL)
    {
        lcf->cvmfs.origin_coords =
            ngx_array_create(cf->pool, 4, sizeof(brix_cvmfs_coord_t));
        if (lcf->cvmfs.origin_coords == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    c = ngx_array_push(lcf->cvmfs.origin_coords);
    if (c == NULL) {
        return NGX_CONF_ERROR;
    }

    c->host = value[1];
    c->port = 0;
    colon = ngx_strlchr(value[1].data, value[1].data + value[1].len, ':');
    if (colon != NULL) {
        ngx_int_t p = ngx_atoi(colon + 1,
                               (size_t) (value[1].data + value[1].len
                                         - (colon + 1)));

        if (p < 1 || p > 65535) {
            return "has an invalid port";
        }
        c->port = (in_port_t) p;
        c->host.len = (size_t) (colon - value[1].data);
    }
    if (cvmfs_parse_latlon(&value[2], &c->lat, &c->lon) != 0) {
        return "has invalid <lat>:<lon> coordinates";
    }
    return NGX_CONF_OK;
}
