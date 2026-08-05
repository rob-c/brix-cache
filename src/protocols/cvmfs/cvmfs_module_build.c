/*
 * cvmfs_module_build.c — cvmfs:// enabled-branch export/backend/cache build.
 *
 * WHAT: The two functions that run only when a location has brix_cvmfs on:
 *     - brix_cvmfs_reject_unsupported — EMERG at config load for storage
 *       grammar cvmfs cannot honour (staging, CAS slicing, explicit writes).
 *     - cvmfs_merge_cache — the enabled-branch build: reject unsupported grammar,
 *       force read-only, rewrite the posix backend, anchor the export root
 *       (defaulting to "/"), open the confinement rootfd, register the
 *       composable http backend, stamp the cache TTL/deadline knobs, compose the
 *       cache/stage tiers, then apply T19 origin selection (geo ranks / rtt
 *       probe registration) and the coords-without-geo warning.
 *
 * WHY: Split out of module.c (file-size gate). This is the one part of the merge
 *   that mutates persistent export state and registers backends — a distinct
 *   concern from the pure config-field merge (cvmfs_module_merge.c). Isolating
 *   it lets the merge orchestrator gate it behind a single enable check while
 *   the build steps stay in their exact original order. Every EMERG/rejection
 *   line and the build-step order are byte-frozen against the pre-split module.c.
 *
 * HOW: Verbatim move. brix_cvmfs_reject_unsupported stays static (its only
 *   caller, cvmfs_merge_cache, lives here); cvmfs_merge_cache is exported via
 *   cvmfs_module_internal.h (the merge orchestrator in cvmfs_module_merge.c
 *   invokes it) and imports cvmfs_geo_rank_config from cvmfs_module_georank.c
 *   through the same header.
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

static char *cvmfs_merge_services(ngx_conf_t *cf,
    ngx_http_brix_cvmfs_loc_conf_t *conf);

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

/*
 * cvmfs_stratum0_apply() — phase-96 S13: resolve the brix_cvmfs_stratum0_root
 * alias.
 *
 * WHAT: When the directive is set, refuse every cache-fill upstream shape in
 *   the same block (an http(s) brix_storage_backend, a brix_cache_store fill
 *   tier, a brix_cvmfs_upstream_allow proxy allowlist) and refuse an
 *   ambiguous double root (brix_export AND the alias), then anchor the
 *   export root at the Stratum-0 tree.
 *
 * WHY: A Stratum-0 has no upstream — it IS the origin. Letting fill grammar
 *   coexist would silently turn the master copy into a cache node; the alias
 *   exists precisely so the intent is visible and enforced at nginx -t.
 *
 * HOW: Runs before the posix-root rewrite so conf->common.root feeds the
 *   normal brix_prepare_export_root path unchanged. No-op when unset.
 */
static char *
cvmfs_stratum0_apply(ngx_conf_t *cf, ngx_http_brix_cvmfs_loc_conf_t *conf)
{
    if (conf->cvmfs.stratum0_root.len == 0) {
        return NGX_CONF_OK;
    }

    if (conf->common.root.len > 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_stratum0_root and brix_export both name an export "
            "root - the alias replaces brix_export; configure exactly one");
        return NGX_CONF_ERROR;
    }

    if (conf->common.storage_backend.len >= 4
        && ngx_strncasecmp(conf->common.storage_backend.data,
                           (u_char *) "http", 4) == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_stratum0_root: a Stratum-0 has no upstream - remove "
            "the http(s) brix_storage_backend from this block");
        return NGX_CONF_ERROR;
    }

    if (conf->common.cache_store.len > 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_stratum0_root: a Stratum-0 serves its published "
            "tree directly - remove brix_cache_store (cache-fill) from "
            "this block");
        return NGX_CONF_ERROR;
    }

    if (conf->cvmfs.upstream_allow != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_stratum0_root: a Stratum-0 has no upstream - remove "
            "brix_cvmfs_upstream_allow (proxy mode) from this block");
        return NGX_CONF_ERROR;
    }

    conf->common.root = conf->cvmfs.stratum0_root;
    return NGX_CONF_OK;
}

/*
 * cvmfs_merge_cache() — the cvmfs-enabled export/backend/cache build block.
 *
 * WHAT: When enable=1: reject unsupported storage grammar, force read-only,
 *   rewrite the posix backend, anchor the export root (defaulting to "/"),
 *   open the confinement rootfd, register the composable http backend, stamp
 *   the cache TTL/deadline knobs, compose the cache/stage tiers, then apply the
 *   T19 origin-selection (geo ranks / rtt probe registration) and the
 *   coords-without-geo warning.
 *
 * WHY: This is the one part of the merge that mutates persistent export state
 *   and registers backends; it only runs for cvmfs-enabled locations. Splitting
 *   it out lets the orchestrator gate it with a single early return while the
 *   build steps stay in their exact original order.
 *
 * HOW: Verbatim move of the `if (conf->cvmfs.enable)` block; returns
 *   NGX_CONF_ERROR on any step failure (identical EMERG/rejection lines), else
 *   NGX_CONF_OK. The caller only invokes it when enable is set.
 */
char *
cvmfs_merge_cache(ngx_conf_t *cf, ngx_http_brix_cvmfs_loc_conf_t *conf)
{
    brix_export_root_opts_t root_opts;

    /* Reject storage grammar cvmfs cannot honour before doing anything
     * else: staging, slicing, and explicit writes make no sense for a
     * read-only content-addressed site cache. */
    if (brix_cvmfs_reject_unsupported(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    /* Phase-96 S13: Stratum-0 alias — refuse cache-fill upstream grammar,
     * then anchor the export root at the published tree. */
    if (cvmfs_stratum0_apply(cf, conf) != NGX_CONF_OK) {
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
    conf->common.cache_offline_ttl    = conf->cvmfs.offline_ttl;
    /* phase-85 F1: the master-key PATH rides the common preamble; the tier
     * registration loads the PEM once at config time into the cache policy. */
    conf->common.cache_cvmfs_master_key = conf->cvmfs.master_key;
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

    return cvmfs_merge_services(cf, conf);
}

/* The phase-87 background-service registrations (scrub / learn / swarm):
 * each rides the RTT-probe lifecycle — registered here at config time, the
 * worker-0 timer / per-worker state arms at init_process. */
static char *
cvmfs_merge_services(ngx_conf_t *cf, ngx_http_brix_cvmfs_loc_conf_t *conf)
{
    /* Phase-87 G17: register the background CAS scrub for this export; the
     * worker-0 timer arms at init_process (scrub.c, RTT-probe lifecycle). */
    if (conf->cvmfs.scrub) {
        brix_cvmfs_scrub_register(conf->common.root_canon,
                                    conf->cvmfs.scrub_interval,
                                    conf->cvmfs.scrub_rate,
                                    &conf->common.thread_pool_name);
    }

    /* Phase-87 G11: register the predictive-prewarm learner for this export;
     * the per-worker model + fill task build at init_process (learn.c). */
    if (conf->cvmfs.learn) {
        brix_cvmfs_learn_register(conf->common.root_canon,
                                    &conf->common.thread_pool_name);
    }

    /* Phase-87 G12: the swarm extends the F8 static mesh — it needs the
     * brix_cache_peers seed ring to know who this node IS. Fail loudly at
     * config time instead of gossiping into the void. */
    if (conf->cvmfs.swarm) {
        if (conf->common.cache_peers == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cvmfs_swarm requires brix_cache_peers (the seed "
                "ring naming this node's own \"self=\" slot)");
            return NGX_CONF_ERROR;
        }
        brix_cvmfs_swarm_register(conf->common.root_canon,
                                    conf->cvmfs.swarm_interval,
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
    return NGX_CONF_OK;
}
