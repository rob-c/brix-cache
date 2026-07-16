/*
 * module_merge.c — per-concern S3 location-merge helpers.
 *
 * WHAT: The four merge concerns invoked by the ngx_http_s3_merge_loc_conf
 *   orchestrator (which stays in module.c as an nginx module-context callback):
 *   preamble (unified-directive adopt + shared common merge), scalars
 *   (protocol-local flag/int/str merges), token (WLCG bearer merge + JWKS load),
 *   and export (the enabled-only export/backend/tier/credential build block),
 *   plus the export's private credential-attach sub-helper.
 *
 * WHY: Split out of module.c VERBATIM for file-size governance. Behavior,
 *   ordering, defaults and diagnostics are byte-frozen — the only change is that
 *   the four orchestrator-called helpers are now non-static (declared in
 *   module_internal.h); s3_export_attach_credential stays file-local static.
 *
 * HOW: Mirrors module.c's include block; the orchestrator in module.c calls
 *   these in order and early-returns NGX_CONF_ERROR on the first failure.
 */

#include "s3.h"
#include "auth/authz/acc/acc.h"            /* XrdAcc engine directives + enum tables */
#include "auth/token/token.h"              /* brix_jwks_load, brix_jwks_register_cleanup */
#include "core/config/root_prepare.h"
#include "core/config/http_rootfd.h"
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "core/config/credential_block.h"   /* §14 brix_credential lookup/bearer */
#include "core/config/http_common.h"        /* unified brix_* directive adoption */
#include "core/config/export_guard.h"       /* brix_assert_dir_outside_export (hard guard) */
#include "fs/vfs/vfs_backend_registry.h"   /* per-export backend registration */
#include "core/compat/alloc_guard.h"
#include "module_internal.h"

/*
 * s3_merge_preamble() — adopt the unified brix_* directives, then run the
 *   shared common.* preamble merge.
 *
 * WHAT: Pulls the location's merged values for the unified directives
 *   (brix_export, brix_cache_store, ...) out of the common module into the
 *   embedded common preamble, then applies the shared common.* merge (hard
 *   read-only enforcement + pmark) with parent-inheritance.
 *
 * WHY: These two steps must run first and in this order — the adopt seeds
 *   conf->common from the common module before the protocol merge applies its
 *   own defaults, and the shared merge folds parent→child on the same struct.
 *   Isolating them keeps the ordering dependency visible and the orchestrator
 *   flat. Merge order + defaults are byte-frozen.
 *
 * HOW: brix_http_common_adopt() copies the common-module values in place;
 *   ngx_http_brix_shared_merge() returns NGX_CONF_OK/ERROR — propagated 1:1.
 */
char *
s3_merge_preamble(ngx_conf_t *cf, ngx_http_s3_loc_conf_t *prev,
    ngx_http_s3_loc_conf_t *conf)
{
    /* Unified directives (brix_export, brix_cache_store, ...) live in the
     * common module; pull the merged values for this location into our
     * embedded preamble before protocol merge applies defaults. */
    brix_http_common_adopt(cf, &conf->common);

    /* Shared common.* preamble (incl. hard read-only enforcement + pmark). */
    if (ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
 * s3_merge_scalars() — merge the protocol-local scalar/string directive group.
 *
 * WHAT: Folds parent→child for the S3 flags, ints, msec, size and string
 *   directives (session-token/chunk-sig/list-cache/max-keys/mpu/zip/bucket/
 *   keys/region), plus the XrdAcc engine merge.
 *
 * WHY: These are independent value merges with fixed defaults and no failure
 *   path; grouping them separates the pure-merge concern from the token and
 *   export-build concerns that can fail. Defaults are byte-frozen.
 *
 * HOW: ngx_conf_merge_* macros apply the frozen default when a value is unset;
 *   brix_acc_http_merge_conf() folds the embedded XrdAcc conf.
 */
void
s3_merge_scalars(ngx_http_s3_loc_conf_t *prev, ngx_http_s3_loc_conf_t *conf)
{
    ngx_conf_merge_value(conf->allow_unsigned_session_token,
                         prev->allow_unsigned_session_token, 0);
    ngx_conf_merge_value(conf->verify_chunk_signatures,
                         prev->verify_chunk_signatures, 0);
    ngx_conf_merge_value(conf->list_cache, prev->list_cache, 0);
    ngx_conf_merge_msec_value(conf->list_cache_ttl, prev->list_cache_ttl,
                              10000);   /* 10s default staleness bound */
    ngx_conf_merge_value(conf->max_keys,    prev->max_keys,    1000);
    ngx_conf_merge_value(conf->mpu_max_age, prev->mpu_max_age, 0);
    ngx_conf_merge_value(conf->zip_access,  prev->zip_access,  0);
    ngx_conf_merge_size_value(conf->zip_cd_max_bytes, prev->zip_cd_max_bytes,
                              16 * 1024 * 1024);
    brix_acc_http_merge_conf(&conf->acc, &prev->acc);
    ngx_conf_merge_str_value(conf->cache_root,       prev->cache_root,       "");
    ngx_conf_merge_str_value(conf->bucket,           prev->bucket,           "");
    ngx_conf_merge_str_value(conf->access_key,       prev->access_key,       "");
    ngx_conf_merge_str_value(conf->secret_key,       prev->secret_key,       "");
    ngx_conf_merge_str_value(conf->region,           prev->region,           "us-east-1");
}

/*
 * s3_merge_token() — merge the WLCG bearer-token group and load the JWKS.
 *
 * WHAT: Folds parent→child for the token enable/jwks/issuer/audience/skew
 *   directives, requires a JWKS path when token auth is on, and when a path is
 *   present loads its keys and registers a pool cleanup for them.
 *
 * WHY: Token auth carries config-time validation and side effects (key load +
 *   cleanup registration) that the pure scalar merge does not; keeping it
 *   separate keeps each concern under the complexity gate. Error strings and
 *   defaults are byte-frozen.
 *
 * HOW: The merges apply frozen defaults; the required-check and key-load emit
 *   the same NGX_LOG_EMERG diagnostics as before and early-return
 *   NGX_CONF_ERROR on the first failure.
 */
char *
s3_merge_token(ngx_conf_t *cf, ngx_http_s3_loc_conf_t *prev,
    ngx_http_s3_loc_conf_t *conf)
{
    /* WLCG bearer-token auth merge */
    ngx_conf_merge_value(conf->token_enable, prev->token_enable, 0);
    ngx_conf_merge_str_value(conf->token_jwks,     prev->token_jwks,     "");
    ngx_conf_merge_str_value(conf->token_issuer,   prev->token_issuer,   "");
    ngx_conf_merge_str_value(conf->token_audience, prev->token_audience, "");
    ngx_conf_merge_value(conf->token_clock_skew, prev->token_clock_skew, 60);

    if (conf->token_enable && conf->token_jwks.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_s3_token: brix_s3_token_jwks is required when "
            "brix_s3_token is on");
        return NGX_CONF_ERROR;
    }

    if (conf->token_enable && conf->token_jwks.len > 0) {
        int key_rc;

        key_rc = brix_jwks_load(cf->log,
                                  (const char *) conf->token_jwks.data,
                                  conf->jwks_keys, BRIX_MAX_JWKS_KEYS);
        if (key_rc <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix_s3_token_jwks: no usable keys in \"%V\"",
                               &conf->token_jwks);
            return NGX_CONF_ERROR;
        }
        conf->jwks_key_count = key_rc;

        if (brix_jwks_register_cleanup(cf->pool, conf->jwks_keys,
                                         &conf->jwks_key_count) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

/*
 * s3_export_attach_credential() — attach a named brix_credential's secrets to
 *   the export's source backend (§14).
 *
 * WHAT: When the export names a brix_credential, resolves it, derives its
 *   bearer token, and hands the bearer plus any x509/CA/S3/SSS secrets to the
 *   VFS backend registered for this export root.
 *
 * WHY: This is the densest sub-concern of the enabled-export build — a lookup,
 *   a bearer derivation, and a fully-populated backend-cred struct. Extracting
 *   it keeps the export orchestrator readable while preserving the exact
 *   deny/error diagnostics.
 *
 * HOW: Copies the credential name into a bounded buffer, looks it up
 *   (missing → NGX_LOG_EMERG + NGX_CONF_ERROR), maps it through the shared
 *   brix_credential_to_backend_cred() (P80.1 — the ONE mapper), then calls
 *   brix_vfs_backend_set_credential().
 */
static char *
s3_export_attach_credential(ngx_conf_t *cf, ngx_http_s3_loc_conf_t *conf)
{
    char                     cred_z[256];
    char                     bearer[4096];
    const brix_credential_t *cred;
    brix_vfs_backend_cred_t  bcred;

    ngx_cpystrn((u_char *) cred_z, conf->common.storage_credential.data,
                ngx_min(conf->common.storage_credential.len + 1,
                        sizeof(cred_z)));
    cred = brix_credential_lookup(cred_z);
    if (cred == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_s3_storage_credential: no brix_credential \"%V\"",
            &conf->common.storage_credential);
        return NGX_CONF_ERROR;
    }
    if (brix_credential_to_backend_cred(cred, bearer, sizeof(bearer),
                                          &bcred, cf->log) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    brix_vfs_backend_set_credential(conf->common.root_canon, &bcred);

    return NGX_CONF_OK;
}

/*
 * s3_merge_export() — the enabled-export config build block.
 *
 * WHAT: For an S3-enabled location: pins the posix backend to the export tree,
 *   canonicalizes the export root, registers the temp reaper + confinement
 *   rootfd, registers the composable storage backend, attaches a named
 *   credential (if any), registers the cache/stage tiers, canonicalizes the
 *   read-through cache root, and enforces the cache-outside-export guard.
 *
 * WHY: This whole block only runs when common.enable is true and chains a set
 *   of config-time build steps that each canonicalize/register/guard, any of
 *   which can fail. Grouping it under one helper keeps the orchestrator flat
 *   and the step order — which is byte-frozen — in one place.
 *
 * HOW: Each step early-returns NGX_CONF_ERROR on failure; the credential
 *   attach is delegated when storage_credential is named; the final guard runs
 *   unconditionally (cache_root_canon empty when no cache root was set).
 */
char *
s3_merge_export(ngx_conf_t *cf, ngx_http_s3_loc_conf_t *conf)
{
    brix_export_root_opts_t root_opts;

    /* posix:<path> backend → the local export tree (composable brix_export). */
    brix_storage_backend_posix_root(&conf->common);

    root_opts.directive_name = "brix_export";
    root_opts.allow_write    = conf->common.allow_write
                             && !brix_storage_backend_is_remote(&conf->common);
    root_opts.required       = 0;
    root_opts.canon_size     = sizeof(conf->common.root_canon);
    if (brix_prepare_export_root(cf, &conf->common.root, &root_opts,
                                   conf->common.root_canon) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    /* SP4: reap interrupted NON-staged direct-write temps under this root. */
    if (conf->common.root_canon[0] != '\0') {
        brix_tmp_reap_register(conf->common.root_canon);
    }

    /* Open the persistent confinement rootfd (kernel openat2
     * RESOLVE_BENEATH anchor); no-op when no brix_s3_root is set. */
    if (brix_http_open_rootfd(cf, &conf->common) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    /* Register the export's composable storage backend (phase-63): a
     * "root://"/"http://" URL or a driver name routes every VFS op (S3 GET
     * goes through brix_vfs_open) to the source backend; default POSIX is a
     * no-op. Mirrors the stream/webdav config paths. */
    if (brix_vfs_backend_config_str(cf, conf->common.root_canon,
            &conf->common.storage_backend, conf->common.pblock_block_size,
            BRIX_AF_AUTO)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    /* §14: attach the named brix_credential's bearer to the source backend. */
    if (conf->common.storage_credential.len > 0) {
        if (s3_export_attach_credential(cf, conf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /* Phase-64: register the composable cache/stage tiers (§4.4 mirror). */
    if (brix_tier_register_stores(cf, &conf->common) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (conf->cache_root.len > 0) {
        brix_export_root_opts_t cache_opts;
        cache_opts.directive_name = "brix_s3_cache_root";
        cache_opts.allow_write    = 0;
        cache_opts.required       = 0;
        cache_opts.canon_size     = sizeof(conf->cache_root_canon);
        if (brix_prepare_export_root(cf, &conf->cache_root, &cache_opts,
                                       conf->cache_root_canon) != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    /* HARD config guard: the read-through cache root must live OUTSIDE the
     * export, or cache sidecars would be exposed in the client namespace. */
    if (brix_assert_dir_outside_export(cf, "brix_s3_cache_root",
            conf->common.root_canon, conf->cache_root_canon) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
