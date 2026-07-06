/*
 * module.c — nginx directive table, config lifecycle, and HTTP module context
 * for the dedicated cvmfs:// protocol plane.
 *
 * WHAT: Three responsibilities, mirroring src/protocols/s3/module.c:
 *   1. Config lifecycle (create_loc_conf / merge_loc_conf): allocates
 *      ngx_http_brix_cvmfs_loc_conf_t (shared preamble + cvmfs knobs),
 *      merges main→srv→loc, and when enable=1 anchors the export root,
 *      registers the composable storage backend + cache/stage tiers.
 *   2. Handler install (ngx_http_brix_cvmfs_set): the "brix_cvmfs"
 *      directive parses its flag and installs ngx_http_brix_cvmfs_handler
 *      as the location's content handler — the location IS the protocol
 *      endpoint; no WebDAV dispatch is involved.
 *   3. Directive table: the brix_cvmfs_* family, including the two
 *      per-protocol tier directives over the shared preamble.
 *
 * WHY: cvmfs:// is a first-class protocol. A CVMFS site cache is read-only
 *      by construction (allow_write is forced off) and typically a PURE cache
 *      node: no local export tree. When no root is configured the root
 *      anchors at "/" (the same pure-cache-node semantics the stream plane
 *      uses): the location serves the "/" namespace, filling from the http
 *      origin backend into the cache store.
 *
 * HOW: create/merge follow the s3 module's manual common.* init/merge idiom
 *      (established phase-64 gotcha: no shared_init). Postconfiguration
 *      resolves the thread pool per server exactly as s3 does — the cache
 *      fill/offload helpers need it.
 */

#include "cvmfs.h"
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

static ngx_int_t ngx_http_brix_cvmfs_postconfiguration(ngx_conf_t *cf);
static char *cvmfs_geo_rank_config(ngx_conf_t *cf,
    ngx_http_brix_cvmfs_loc_conf_t *conf);
static char *brix_cvmfs_reject_unsupported(ngx_conf_t *cf,
    ngx_http_brix_cvmfs_loc_conf_t *conf);

/*
 * Config lifecycle
 */

static void *
ngx_http_brix_cvmfs_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_brix_cvmfs_loc_conf_t *c;

    BRIX_PCALLOC_OR_RETURN(c, cf->pool, sizeof(*c), NULL);

    ngx_http_brix_shared_init(&c->common);

    c->cvmfs.enable         = NGX_CONF_UNSET;
    c->cvmfs.manifest_ttl   = NGX_CONF_UNSET;
    c->cvmfs.negative_ttl   = NGX_CONF_UNSET;
    c->cvmfs.upstream_allow = NGX_CONF_UNSET_PTR;
    c->cvmfs.upstream_max   = NGX_CONF_UNSET_UINT;
    c->cvmfs.origin_select  = NGX_CONF_UNSET_UINT;
    c->cvmfs.origin_coords  = NGX_CONF_UNSET_PTR;
    c->cvmfs.rtt_interval   = NGX_CONF_UNSET;
    c->cvmfs.client_hold    = NGX_CONF_UNSET;
    c->cvmfs.fill_max_life  = NGX_CONF_UNSET;
    c->cvmfs.trace          = NGX_CONF_UNSET;
    c->cvmfs.origin_connect_timeout = NGX_CONF_UNSET;
    c->cvmfs.origin_stall_timeout   = NGX_CONF_UNSET;
    c->cvmfs.origin_stall_bytes     = NGX_CONF_UNSET_UINT;
    c->cvmfs.origin_attempt_timeout = NGX_CONF_UNSET;
    c->cvmfs.origin_reuse_conn      = NGX_CONF_UNSET;
    c->cvmfs.fill_retry_policy      = NGX_CONF_UNSET_UINT;
    c->cvmfs.shared_cache           = NGX_CONF_UNSET;
    c->cvmfs.unified_origin         = NGX_CONF_UNSET;
    c->cvmfs.geo_answer             = NGX_CONF_UNSET_UINT;
    c->cvmfs.geo_cache_ttl          = NGX_CONF_UNSET;
    c->cvmfs.geo_max_servers        = NGX_CONF_UNSET_UINT;
    c->scvmfs               = NGX_CONF_UNSET;
    c->scvmfs_authz         = NGX_CONF_UNSET_UINT;

    return c;
}

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
static char *
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

/* Geo mode (T19): every configured endpoint must have coordinates and
 * brix_cvmfs_here must be set — rank once by great-circle distance and
 * record the ranks on the backend entry (applied at instance build). */
static char *
cvmfs_geo_rank_config(ngx_conf_t *cf, ngx_http_brix_cvmfs_loc_conf_t *conf)
{
    double                here_lat, here_lon;
    double                metric[SD_HTTP_EP_MAX];
    int                   ranks[SD_HTTP_EP_MAX];
    const char           *host;
    int                   port, idx, n;
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
            metric[n] = brix_cvmfs_haversine_km(here_lat, here_lon,
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
    for (idx = n; idx < SD_HTTP_EP_MAX; idx++) {
        ranks[idx] = 0;
    }
    brix_cvmfs_rank_by_metric(metric, n, ranks);
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
            host, port, metric[idx], here_lat, here_lon, ranks[idx],
            (ranks[idx] == 0) ? " (preferred: reads try this origin first)"
                              : " (failover only)");
    }
    return NGX_CONF_OK;
}

/* brix_cvmfs_origin_coords <host[:port]> <lat>:<lon> — geographic position
 * of one origin (multi). An entry with a port matches only that endpoint. */
static char *
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

/*
 * brix_cvmfs_reject_unsupported() — EMERG at config load for storage grammar
 * that cvmfs cannot honour.
 *
 * WHAT: Checks three merged common-preamble fields for features that are
 *   structurally incompatible with a read-only content-addressed site cache:
 *   (1) staging — brix_stage on / brix_stage_store, (2) object slicing —
 *   brix_cache_slice_size, and (3) explicit write permission — brix_allow_write.
 *
 * WHY: Without an explicit rejection at config-load time these directives
 *   silently pass nginx -t, misleading operators into believing their config
 *   is active when it is not.  cvmfs is structurally read-only; writes and
 *   staging have no meaning (CAS objects are immutable whole objects), and
 *   slicing never applies because the cache fill and CAS verification run on
 *   the whole object.  A loud nginx -t rejection surfaces operator mistakes
 *   before traffic is served.
 *
 * HOW: Called at the top of the cvmfs-enabled branch in merge_loc_conf,
 *   after brix_http_common_adopt() and ngx_http_brix_shared_merge() have
 *   resolved unified directive values into conf->common (so brix_stage,
 *   brix_allow_write, and brix_cache_slice_size are visible).  Returns
 *   NGX_CONF_ERROR on any violation; NGX_CONF_OK otherwise.  The caller
 *   must check the return and propagate NGX_CONF_ERROR to nginx.
 */
static char *
brix_cvmfs_reject_unsupported(ngx_conf_t *cf,
    ngx_http_brix_cvmfs_loc_conf_t *conf)
{
    /* Staging (brix_stage on / brix_stage_store) implies mutability: a cvmfs
     * cache is a read-through CAS store; write-back staging makes no sense. */
    if (conf->common.stage_enable == 1 || conf->common.stage_store.len > 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_stage/brix_stage_store: cvmfs is a read-only protocol; "
            "staging is not supported");
        return NGX_CONF_ERROR;
    }

    /* CAS object slicing: cvmfs objects are immutable and must be filled and
     * verified as whole units; per-slice CAS verification is undefined. */
    if (conf->common.cache_slice_size > 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_slice_size: cvmfs CAS objects are immutable whole "
            "objects; slicing is not supported");
        return NGX_CONF_ERROR;
    }

    /* Explicit write permission: the hard force (conf->common.allow_write = 0)
     * below already prevents accidental writes, but an explicit on is a
     * config mistake that deserves a loud rejection rather than silent no-op. */
    if (conf->common.allow_write == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_allow_write on: cvmfs is a read-only protocol; "
            "write permission cannot be granted");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_brix_cvmfs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brix_cvmfs_loc_conf_t *prev = parent;
    ngx_http_brix_cvmfs_loc_conf_t *conf = child;

    /* Unified directives (brix_export, brix_cache_store, brix_cache_verify,
     * ...) live in the common module; pull the merged values for this location
     * into our embedded preamble before protocol merge applies defaults. */
    brix_http_common_adopt(cf, &conf->common);

    /* Merge enable first — before shared_merge — so we can distinguish a
     * cvmfs location from a non-cvmfs one when pre-seeding the verify default
     * below.  enable merges only from prev->cvmfs.enable: it has no dependency
     * on any common.* field set by shared_merge, so this ordering is safe. */
    ngx_conf_merge_value(conf->cvmfs.enable, prev->cvmfs.enable, 0);

    /* cvmfs default: fills are verified against their CAS SHA-1 content
     * address.  Pre-seed before shared_merge, which turns NGX_CONF_UNSET_UINT
     * into 0 (BRIX_CACHE_VERIFY_OFF) and would otherwise suppress this default.
     *
     * brix_http_common_adopt above copied any user-set value from the common
     * module into conf->common.cache_verify_mode.  The common module's own
     * merge is inheritance-only (no defaults), so if the user never touched
     * brix_cache_verify at ANY scope, the common module's conf remains
     * NGX_CONF_UNSET_UINT and nothing is copied — the field is still UNSET
     * here.  If the user DID set it, adopt carried the explicit value over and
     * the guard below will not fire, respecting the operator's choice.
     *
     * prev->common.cache_verify_mode is intentionally NOT checked: at location
     * level, prev is the server-level cvmfs conf, which has already been
     * through shared_merge (setting it to 0), so checking prev would never
     * allow the default to apply.  The UNSET check on conf is sufficient.
     *
     * The guard on cvmfs.enable confines this to cvmfs locations only. */
    if (conf->cvmfs.enable == 1
        && conf->common.cache_verify_mode == NGX_CONF_UNSET_UINT)
    {
        conf->common.cache_verify_mode = BRIX_CACHE_VERIFY_CVMFS_CAS;
    }

    /* Shared common.* preamble. Two deliberate gains over the old manual
     * block: read_only now forces allow_write off (hardening; cvmfs is a
     * read path anyway), and common.ktls merges to its default — inert here
     * (nothing under protocols/cvmfs/ reads it). */
    if (ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_conf_merge_sec_value(conf->cvmfs.manifest_ttl, prev->cvmfs.manifest_ttl,
                             61);
    ngx_conf_merge_sec_value(conf->cvmfs.negative_ttl, prev->cvmfs.negative_ttl,
                             10);
    ngx_conf_merge_str_value(conf->cvmfs.quarantine_dir,
                             prev->cvmfs.quarantine_dir, "");
    ngx_conf_merge_ptr_value(conf->cvmfs.upstream_allow,
                             prev->cvmfs.upstream_allow, NULL);
    ngx_conf_merge_uint_value(conf->cvmfs.upstream_max, prev->cvmfs.upstream_max,
                              8);
    ngx_conf_merge_uint_value(conf->cvmfs.origin_select,
                              prev->cvmfs.origin_select,
                              BRIX_CVMFS_SELECT_RTT);
    ngx_conf_merge_ptr_value(conf->cvmfs.origin_coords,
                             prev->cvmfs.origin_coords, NULL);
    ngx_conf_merge_str_value(conf->cvmfs.here, prev->cvmfs.here, "");
    ngx_conf_merge_sec_value(conf->cvmfs.rtt_interval, prev->cvmfs.rtt_interval,
                             60);
    ngx_conf_merge_sec_value(conf->cvmfs.client_hold, prev->cvmfs.client_hold,
                             25);
    ngx_conf_merge_sec_value(conf->cvmfs.fill_max_life,
                             prev->cvmfs.fill_max_life, 300);
    ngx_conf_merge_value(conf->cvmfs.trace, prev->cvmfs.trace, 0);
    /* Trace promotion is process-wide (the shared origin transport has no
     * per-location handle): any cvmfs location turning it on promotes the
     * upstream-request lines to INFO for every worker (set pre-fork). */
    if (conf->cvmfs.trace) {
        brix_origin_trace_set(1);
    }

    /* Upstream stall detection + force-through retry (2026-07-03). The transport
     * bounds and the force-primary toggle are process-wide operator policy (the
     * shared curl transport / sd_http driver have no per-location handle), set
     * pre-fork here beside the trace flag so every worker inherits them. */
    ngx_conf_merge_sec_value(conf->cvmfs.origin_connect_timeout,
                             prev->cvmfs.origin_connect_timeout, 2);
    ngx_conf_merge_sec_value(conf->cvmfs.origin_stall_timeout,
                             prev->cvmfs.origin_stall_timeout, 4);
    ngx_conf_merge_uint_value(conf->cvmfs.origin_stall_bytes,
                              prev->cvmfs.origin_stall_bytes, 1);
    ngx_conf_merge_sec_value(conf->cvmfs.origin_attempt_timeout,
                             prev->cvmfs.origin_attempt_timeout, 0);
    ngx_conf_merge_value(conf->cvmfs.origin_reuse_conn,
                         prev->cvmfs.origin_reuse_conn, 1);
    ngx_conf_merge_uint_value(conf->cvmfs.fill_retry_policy,
                              prev->cvmfs.fill_retry_policy,
                              BRIX_CVMFS_RETRY_FAILOVER);
    ngx_conf_merge_value(conf->cvmfs.shared_cache, prev->cvmfs.shared_cache, 0);
    ngx_conf_merge_value(conf->cvmfs.unified_origin, prev->cvmfs.unified_origin,
                         0);
    /* unified_origin serves every proxy request from the location's configured
     * origin backend, so that backend MUST be an http(s) origin set (ideally a
     * "|"-separated multi-endpoint one for the failover that hides a dead
     * origin). Fail loudly at config time rather than 500 per request. */
    if (conf->cvmfs.enable && conf->cvmfs.unified_origin
        && (conf->common.storage_backend.len < 4
            || ngx_strncasecmp(conf->common.storage_backend.data,
                               (u_char *) "http", 4) != 0))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_unified_origin on requires brix_storage_backend "
            "to name an http(s) origin set, e.g. "
            "\"http://s1a:8000|http://s1b:8000|http://s1c:8000\" (the '|'-list "
            "is the ranked failover set that hides a dead Stratum-1)");
        return NGX_CONF_ERROR;
    }
    if (conf->cvmfs.enable) {
        brix_s3_origin_timeouts_set(
            (long) conf->cvmfs.origin_connect_timeout * 1000,
            (long) conf->cvmfs.origin_stall_timeout,
            (long) conf->cvmfs.origin_stall_bytes,
            (long) conf->cvmfs.origin_attempt_timeout * 1000);
        brix_s3_origin_reuse_set(conf->cvmfs.origin_reuse_conn ? 1 : 0);
        if (conf->cvmfs.fill_retry_policy == BRIX_CVMFS_RETRY_FORCE_PRIMARY) {
            sd_http_force_primary_set(1);
        }
    }

    /* Server-side geo answering (2026-07-03). */
    ngx_conf_merge_uint_value(conf->cvmfs.geo_answer, prev->cvmfs.geo_answer,
                              BRIX_CVMFS_GEO_PASSTHROUGH);
    ngx_conf_merge_sec_value(conf->cvmfs.geo_cache_ttl, prev->cvmfs.geo_cache_ttl,
                             60);
    ngx_conf_merge_uint_value(conf->cvmfs.geo_max_servers,
                              prev->cvmfs.geo_max_servers, 16);

    ngx_conf_merge_value(conf->scvmfs, prev->scvmfs, 0);
    ngx_conf_merge_uint_value(conf->scvmfs_authz, prev->scvmfs_authz,
                              BRIX_SCVMFS_AUTHZ_NONE);
    ngx_conf_merge_str_value(conf->scvmfs_token_issuers,
                             prev->scvmfs_token_issuers, "");
    if (conf->scvmfs_registry == NULL) {
        conf->scvmfs_registry = prev->scvmfs_registry;
    }

    /* scvmfs (T22, EXPERIMENTAL) is a LAYER on cvmfs — structural, checked
     * at config time. Bearer mode needs the issuer registry to exist. */
    if (conf->scvmfs) {
        if (!conf->cvmfs.enable) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_scvmfs requires brix_cvmfs on");
            return NGX_CONF_ERROR;
        }
        if (conf->scvmfs_authz == BRIX_SCVMFS_AUTHZ_BEARER) {
            if (conf->scvmfs_token_issuers.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "brix_scvmfs_authz bearer requires "
                    "brix_scvmfs_token_issuers <scitokens.cfg>");
                return NGX_CONF_ERROR;
            }
            if (conf->scvmfs_registry == NULL) {
                brix_token_registry_t *reg = NULL;

                if (brix_token_registry_build(cf,
                        (const char *) conf->scvmfs_token_issuers.data,
                        BRIX_AUTHZ_CAPABILITY, &reg) != NGX_OK)
                {
                    return NGX_CONF_ERROR;
                }
                conf->scvmfs_registry = reg;
            }
        }
    }

    if (conf->cvmfs.enable) {
        brix_export_root_opts_t root_opts;

        /* Reject storage grammar cvmfs cannot honour before doing anything
         * else: staging, slicing, and explicit writes make no sense for a
         * read-only content-addressed site cache. */
        if (brix_cvmfs_reject_unsupported(cf, conf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        /* CVMFS is a read-only protocol: no directive can enable writes. */
        conf->common.allow_write = 0;

        /* "posix:<path>" backend names the local export tree (composable
         * brix_root replacement) — same rewrite every protocol applies. */
        brix_storage_backend_posix_root(&conf->common);

        /* Pure cache node (the normal CVMFS shape): no local export tree —
         * anchor the namespace at "/" exactly like the stream plane's pure
         * cache node; the location serves the "/" namespace, filling from
         * the http backend into the cache store. */
        if (conf->common.root.len == 0) {
            ngx_str_set(&conf->common.root, "/");
        }

        root_opts.directive_name = "brix_cvmfs";
        root_opts.allow_write    = 0;
        root_opts.required       = 1;
        root_opts.canon_size     = sizeof(conf->common.root_canon);
        if (brix_prepare_export_root(cf, &conf->common.root, &root_opts,
                                       conf->common.root_canon) != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        /* Persistent confinement rootfd (openat2 RESOLVE_BENEATH anchor). */
        if (brix_http_open_rootfd(cf, &conf->common) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        /* Register the composable storage backend (phase-63): the http(s)
         * Stratum-1 origin URL routes every VFS op to sd_http. */
        if (brix_vfs_backend_config_str(cf, conf->common.root_canon,
                &conf->common.storage_backend, conf->common.pblock_block_size,
                BRIX_AF_AUTO)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        /* Verify-mismatch evidence lands in the protocol's quarantine dir;
         * MANIFEST-class fills get the protocol's TTL stamped (T12). */
        conf->common.cache_quarantine_dir = conf->cvmfs.quarantine_dir;
        conf->common.cache_manifest_ttl   = conf->cvmfs.manifest_ttl;
        /* T20 never-drop deadlines for the shared fill machinery */
        conf->common.cache_client_hold    = conf->cvmfs.client_hold;
        conf->common.cache_fill_max_life  = conf->cvmfs.fill_max_life;

        /* Phase-64: compose the cache/stage tiers over the backend. */
        if (brix_tier_register_stores(cf, &conf->common) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* T19 origin selection: geo ranks compute once at config time;
         * rtt registers the per-worker probe; static keeps configured
         * order (all ranks 0 — the pick is order-stable on ties). */
        if (conf->cvmfs.origin_select == BRIX_CVMFS_SELECT_GEO) {
            if (cvmfs_geo_rank_config(cf, conf) != NGX_CONF_OK) {
                return NGX_CONF_ERROR;
            }
        } else if (conf->cvmfs.origin_select == BRIX_CVMFS_SELECT_RTT) {
            brix_cvmfs_rtt_register(conf->common.root_canon,
                                      conf->cvmfs.rtt_interval,
                                      &conf->common.thread_pool_name);
        }

        /* WARN (not NOTICE — config-parse NOTICE is dropped at cf->log ERR
         * level) when coordinates were supplied but origin_select is not geo:
         * the coordinates are silently ignored in all other modes and the
         * operator may not realise their geo config has no effect. */
        if (conf->cvmfs.origin_select != BRIX_CVMFS_SELECT_GEO
            && conf->cvmfs.origin_coords != NULL)
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "brix_cvmfs_origin_coords set but brix_cvmfs_origin_select "
                "is not geo — coordinates are ignored");
        }
    }

    return NGX_CONF_OK;
}

/* ---- T16: nginx variables ($cvmfs_class / $cvmfs_cache / $cvmfs_origin) ---
 * Backed by the request ctx the handler fills; "-" outside cvmfs requests.
 * $cvmfs_origin queries the http driver's last-answering endpoint (display
 * only — approximate under concurrent fills, exact in the common case). */

static ngx_int_t
cvmfs_var_set(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    const char *val)
{
    size_t  n = ngx_strlen(val);
    u_char *p = ngx_pnalloc(r->pool, n);

    if (p == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(p, val, n);
    v->data = p;
    v->len = n;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
cvmfs_var_class(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    static const char *names[] = { "cas", "manifest", "geo", "reject" };

    (void) data;
    if (ctx == NULL || ctx->url.cls > CVMFS_URL_REJECT) {
        return cvmfs_var_set(r, v, "-");
    }
    return cvmfs_var_set(r, v, names[ctx->url.cls]);
}

static ngx_int_t
cvmfs_var_cache(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    static const char *names[] = { "-", "hit", "fill", "neg" };

    (void) data;
    if (ctx == NULL || ctx->cache_status > BRIX_CVMFS_CACHE_NEG) {
        return cvmfs_var_set(r, v, "-");
    }
    return cvmfs_var_set(r, v, names[ctx->cache_status]);
}

static ngx_int_t
cvmfs_var_origin(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_cvmfs_loc_conf_t *lcf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_cvmfs_module);
    ngx_http_brix_cvmfs_ctx_t      *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    brix_sd_instance_t             *inst;
    char                              buf[300];
    const char                       *root;

    (void) data;
    if (ctx == NULL || ctx->cache_status != BRIX_CVMFS_CACHE_FILL
        || lcf == NULL)
    {
        return cvmfs_var_set(r, v, "-");
    }
    root = (ctx->up_root != NULL) ? ctx->up_root : lcf->common.root_canon;
    inst = brix_vfs_backend_resolve(root, r->connection->log);
    while (inst != NULL && ngx_strcmp(inst->driver->name, "http") != 0) {
        inst = brix_sd_cache_source_instance(inst);
    }
    if (inst == NULL || sd_http_last_origin(inst, buf, sizeof(buf)) != 0) {
        return cvmfs_var_set(r, v, "-");
    }
    return cvmfs_var_set(r, v, buf);
}

static ngx_http_variable_t  ngx_http_brix_cvmfs_vars[] = {
    { ngx_string("cvmfs_class"),  NULL, cvmfs_var_class,  0, 0, 0 },
    { ngx_string("cvmfs_cache"),  NULL, cvmfs_var_cache,  0, 0, 0 },
    { ngx_string("cvmfs_origin"), NULL, cvmfs_var_origin, 0, 0, 0 },
      ngx_http_null_variable
};

static ngx_int_t
ngx_http_brix_cvmfs_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t *v, *nv;

    for (v = ngx_http_brix_cvmfs_vars; v->name.len; v++) {
        nv = ngx_http_add_variable(cf, &v->name, v->flags);
        if (nv == NULL) {
            return NGX_ERROR;
        }
        nv->get_handler = v->get_handler;
        nv->data = v->data;
    }
    return NGX_OK;
}

/*
 * Post-config: resolve the async-I/O thread pool per server (fill/offload
 * helpers need it) — identical mechanics to the s3 module.
 */
static ngx_int_t
ngx_http_brix_cvmfs_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t         *cmcf;
    ngx_http_core_srv_conf_t         **cscfp;
    ngx_http_brix_cvmfs_loc_conf_t  *lcf;
    static ngx_str_t                   default_pool_name = ngx_string("default");
    ngx_str_t                         *pool_name;
    ngx_uint_t                         s;

    /* An HTTP-only cvmfs node has no stream block, so the SHM zones normally
     * created by the stream postconfiguration must be ensured here: the
     * metrics table (or every counter INC is a silent no-op) AND the
     * dashboard transfer/events/history zones (or every live-transfer
     * record silently fails and the dashboard stays empty). Both are
     * idempotent — ngx_shared_memory_add returns an existing zone. */
    if (brix_metrics_ensure_zone(cf) != NGX_OK) {
        return NGX_ERROR;
    }
    if (brix_configure_dashboard(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;

        lcf = ctx->loc_conf[ngx_http_brix_cvmfs_module.ctx_index];
        if (lcf == NULL || !lcf->cvmfs.enable) {
            continue;
        }

        pool_name = (lcf->common.thread_pool_name.len > 0)
                    ? &lcf->common.thread_pool_name
                    : &default_pool_name;

        lcf->common.thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
        if (lcf->common.thread_pool == NULL) {
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "brix_cvmfs: thread pool \"%V\" not found - "
                "async cache fills disabled (add a thread_pool directive)",
                pool_name);
        }
    }

    return NGX_OK;
}

static ngx_http_module_t ngx_http_brix_cvmfs_module_ctx = {
    ngx_http_brix_cvmfs_preconfiguration,  /* preconfiguration     */
    ngx_http_brix_cvmfs_postconfiguration, /* postconfiguration    */
    NULL,                                    /* create main conf     */
    NULL,                                    /* init main conf       */
    NULL,                                    /* create server conf   */
    NULL,                                    /* merge server conf    */
    ngx_http_brix_cvmfs_create_loc_conf,   /* create location conf */
    ngx_http_brix_cvmfs_merge_loc_conf,    /* merge location conf  */
};

/* "brix_cvmfs on" — parse the flag AND make this location a dedicated
 * CVMFS protocol endpoint (same install point the s3 module uses). */
static char *
ngx_http_brix_cvmfs_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char                     *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_brix_cvmfs_handler;

    return NGX_CONF_OK;
}

/*
 * Directives
 */

/* brix_cache_verify (HTTP form) is now owned by ngx_http_brix_common_module,
 * which registers the identical off|cvmfs-cas enum; this module adopts the
 * merged value via brix_http_common_adopt(). */

static ngx_conf_enum_t  brix_scvmfs_authz_enum[] = {
    { ngx_string("none"),   BRIX_SCVMFS_AUTHZ_NONE },
    { ngx_string("bearer"), BRIX_SCVMFS_AUTHZ_BEARER },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t  brix_cvmfs_select_enum[] = {
    { ngx_string("static"), BRIX_CVMFS_SELECT_STATIC },
    { ngx_string("geo"),    BRIX_CVMFS_SELECT_GEO },
    { ngx_string("rtt"),    BRIX_CVMFS_SELECT_RTT },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t  brix_cvmfs_retry_policy_enum[] = {
    { ngx_string("failover"),      BRIX_CVMFS_RETRY_FAILOVER },
    { ngx_string("force-primary"), BRIX_CVMFS_RETRY_FORCE_PRIMARY },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t  brix_cvmfs_geo_answer_enum[] = {
    { ngx_string("off"), BRIX_CVMFS_GEO_PASSTHROUGH },
    { ngx_string("rtt"), BRIX_CVMFS_GEO_RTT },
    { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_brix_cvmfs_commands[] = {

    /* ---- origin resilience directives (split into directives_resilience.inc) ---- */
#include "directives_resilience.inc"

    /* ---- cvmfs core + scvmfs + tier directives (split into directives_core.inc) ---- */
#include "directives_core.inc"

    ngx_null_command
};

/* Worker init: arm the T19 RTT probe timers for every registered export. */
static ngx_int_t
ngx_http_brix_cvmfs_init_process(ngx_cycle_t *cycle)
{
    return brix_cvmfs_rtt_init_worker(cycle);
}

ngx_module_t ngx_http_brix_cvmfs_module = {
    NGX_MODULE_V1,
    &ngx_http_brix_cvmfs_module_ctx,  /* module context     */
    ngx_http_brix_cvmfs_commands,     /* module directives  */
    NGX_HTTP_MODULE,                    /* module type        */
    NULL,                               /* init master        */
    NULL,                               /* init module        */
    ngx_http_brix_cvmfs_init_process, /* init process       */
    NULL,                               /* init thread        */
    NULL,                               /* exit thread        */
    NULL,                               /* exit process       */
    NULL,                               /* exit master        */
    NGX_MODULE_V1_PADDING
};
