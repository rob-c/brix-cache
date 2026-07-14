/*
 * cvmfs_module_merge.c — cvmfs:// location config-field merge.
 *
 * WHAT: The four per-concern merge-field helpers and the orchestrator that
 *   sequences them:
 *     - cvmfs_merge_preamble  — adopt unified directives, merge enable, pre-seed
 *       the CAS verify default, run the shared common.* merge.
 *     - cvmfs_merge_upstreams — manifest/negative TTL, upstream allow/cap,
 *       origin-selection knobs, process-wide trace toggle.
 *     - cvmfs_merge_resilience — origin stall-detection / retry group + its
 *       process-wide transport policy.
 *     - cvmfs_merge_secure    — server-side geo-answer group + scvmfs (T22)
 *       authz layer and bearer-registry build.
 *     - ngx_http_brix_cvmfs_merge_loc_conf — the orchestrator wired into the
 *       module context; runs the four helpers then delegates the enabled-branch
 *       export build to cvmfs_merge_cache (cvmfs_module_build.c).
 *
 * WHY: Split out of module.c (file-size gate). These helpers are one concern —
 *   resolving and merging config fields main→srv→loc — distinct from the
 *   enabled-branch storage build (cvmfs_module_build.c) that mutates persistent
 *   export state. The concerns carry strict ordering dependencies (enable before
 *   the verify pre-seed; field merges before the process-wide transport setters;
 *   scvmfs checks before the export build); the orchestrator makes every one of
 *   those visible as a flat call sequence. Merge order and defaults are
 *   byte-frozen against the pre-split module.c (nginx -t unchanged).
 *
 * HOW: Verbatim move. The four field-merge helpers stay static (called only by
 *   the orchestrator here); the orchestrator is exported via
 *   cvmfs_module_internal.h (the module context in module.c references it) and
 *   imports cvmfs_merge_cache from cvmfs_module_build.c through the same header.
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

/*
 * cvmfs_merge_preamble() — adopt unified directives, merge enable, pre-seed the
 * CAS verify default, and run the shared common.* merge.
 *
 * WHAT: The first four steps of the location merge, in the one order they must
 *   run: brix_http_common_adopt → merge cvmfs.enable → CAS verify pre-seed →
 *   ngx_http_brix_shared_merge.
 *
 * WHY: enable must merge BEFORE shared_merge so the verify pre-seed can tell a
 *   cvmfs location from a non-cvmfs one, and the pre-seed must run before
 *   shared_merge turns NGX_CONF_UNSET_UINT into 0. Grouping the four fixes that
 *   ordering in one place and keeps the orchestrator flat.
 *
 * HOW: Verbatim move of the original head; returns NGX_CONF_ERROR if the
 *   shared merge fails, else NGX_CONF_OK.
 */
static char *
cvmfs_merge_preamble(ngx_conf_t *cf, ngx_http_brix_cvmfs_loc_conf_t *prev,
    ngx_http_brix_cvmfs_loc_conf_t *conf)
{
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
    return NGX_CONF_OK;
}

/*
 * cvmfs_merge_upstreams() — merge the manifest/negative TTL, upstream allow-list
 * and cap, origin-selection knobs, and the process-wide trace toggle.
 *
 * WHAT: The block of plain field merges between shared_merge and the origin
 *   resilience group: manifest_ttl, negative_ttl, quarantine_dir,
 *   upstream_allow, upstream_max, origin_select, origin_coords, here,
 *   rtt_interval, client_hold, fill_max_life, trace (+ its trace_set).
 *
 * WHY: These are pure ngx_conf_merge_* calls with one process-wide side effect
 *   (brix_origin_trace_set) at the tail; collecting them keeps the orchestrator
 *   short. Defaults are byte-frozen so nginx -t is unchanged.
 *
 * HOW: Verbatim merge sequence; trace promotion is applied here because it is
 *   process-wide (the shared origin transport has no per-location handle).
 */
static void
cvmfs_merge_upstreams(ngx_conf_t *cf, ngx_http_brix_cvmfs_loc_conf_t *prev,
    ngx_http_brix_cvmfs_loc_conf_t *conf)
{
    (void) cf;

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
}

/*
 * cvmfs_merge_resilience() — merge the origin stall-detection / retry group and
 * apply its process-wide transport policy.
 *
 * WHAT: origin_connect_timeout, origin_stall_timeout, origin_stall_bytes,
 *   origin_attempt_timeout, origin_reuse_conn, fill_retry_policy, shared_cache,
 *   unified_origin — plus the unified_origin http(s)-backend validation and the
 *   pre-fork process-wide setters (timeouts / reuse / force-primary) when
 *   enabled.
 *
 * WHY: The transport bounds and the force-primary toggle are process-wide
 *   operator policy set pre-fork; keeping the merge and its setters together
 *   preserves the "merge then push to the shared transport" ordering exactly.
 *
 * HOW: Verbatim; returns NGX_CONF_ERROR on the unified_origin misconfiguration
 *   (identical EMERG line), else NGX_CONF_OK after applying the setters.
 */
static char *
cvmfs_merge_resilience(ngx_conf_t *cf, ngx_http_brix_cvmfs_loc_conf_t *prev,
    ngx_http_brix_cvmfs_loc_conf_t *conf)
{
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
    return NGX_CONF_OK;
}

/*
 * cvmfs_merge_secure() — merge the server-side geo-answer group and the scvmfs
 * (T22, experimental) authz layer, validating the bearer registry.
 *
 * WHAT: geo_answer / geo_cache_ttl / geo_max_servers, then scvmfs /
 *   scvmfs_authz / scvmfs_token_issuers / scvmfs_registry, plus the structural
 *   checks: scvmfs requires cvmfs on, and bearer mode requires a token-issuer
 *   file whose registry is built once here.
 *
 * WHY: These two merge groups both run unconditionally after the resilience
 *   group and before the enable block; grouping them keeps the orchestrator a
 *   flat sequence. The scvmfs checks are structural (config-time) and their
 *   EMERG lines are byte-frozen.
 *
 * HOW: Verbatim; returns NGX_CONF_ERROR on any scvmfs misconfiguration or a
 *   failed registry build, else NGX_CONF_OK.
 */
static char *
cvmfs_merge_secure(ngx_conf_t *cf, ngx_http_brix_cvmfs_loc_conf_t *prev,
    ngx_http_brix_cvmfs_loc_conf_t *conf)
{
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
    return NGX_CONF_OK;
}

/*
 * ngx_http_brix_cvmfs_merge_loc_conf() — location merge orchestrator.
 *
 * WHAT: Runs the five per-concern merge helpers in their required order:
 *   preamble (adopt/enable/verify/shared_merge) → upstreams → resilience →
 *   secure (geo-answer + scvmfs) → cache (enabled-only export/backend build).
 *
 * WHY: The concerns have strict ordering dependencies (enable before verify
 *   pre-seed; merges before the process-wide transport setters; scvmfs before
 *   the export build). Expressing the orchestrator as a flat call sequence
 *   keeps every dependency visible in one place while each concern stays under
 *   the complexity gate. Merge order + defaults are byte-frozen (nginx -t).
 *
 * HOW: Each step returns NGX_CONF_OK/ERROR; the orchestrator early-returns on
 *   the first error. The cache step (cvmfs_merge_cache, cvmfs_module_build.c)
 *   runs only for cvmfs-enabled locations.
 */
char *
ngx_http_brix_cvmfs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_brix_cvmfs_loc_conf_t *prev = parent;
    ngx_http_brix_cvmfs_loc_conf_t *conf = child;

    if (cvmfs_merge_preamble(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    cvmfs_merge_upstreams(cf, prev, conf);
    if (cvmfs_merge_resilience(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (cvmfs_merge_secure(cf, prev, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (conf->cvmfs.enable) {
        if (cvmfs_merge_cache(cf, conf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
