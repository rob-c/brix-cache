/*
 * config_merge.c - WebDAV base directive merge + startup validation cluster.
 *
 * WHAT: the parent→child directive inheritance/default pass (webdav_merge_base_conf)
 *   and the whole "WebDAV enabled" startup-validation chain — export-root prepare,
 *   authz-rule finalize, storage-backend + credential configuration, stage/cache
 *   directory prepare, lock startup sweep, and CA/CRL/CORS/JWKS/TPC path validation
 *   including building the cached X509 CA store.
 * WHY: split VERBATIM out of config.c to keep each translation unit under the
 *   file-size gate; behaviour is unchanged. The two entrypoints called by the
 *   merge glue in config.c (webdav_merge_base_conf, webdav_validate_webdav_enabled)
 *   are declared in config_internal.h.
 * HOW: pure move — same includes, same helpers, same control flow as before.
 */

#include "webdav.h"
#include "auth/crypto/store_policy.h"      /* BRIX_SP_MODE_*, BRIX_CRL_MODE_* defaults */
#include "core/compat/integrity_info.h"   /* §8.x checksum xattr write format */
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "auth/token/issuer_registry.h"   /* phase-59 W1 multi-issuer registry */
#include "proxy_internal.h"
#include "net/mirror/http_mirror.h"
#include "core/config/config.h"
#include "fs/path/path.h"                  /* brix_finalize_{authdb,vo}_rules */
#include "core/config/root_prepare.h"
#include "core/config/http_rootfd.h"
#include "core/config/http_common.h"      /* unified brix_* directive adoption */
#include "core/config/export_guard.h"     /* brix_assert_dir_outside_export (hard guard) */
#include "core/compat/staged_file.h"
#include "fs/backend/sd.h"           /* SD registry: lazy per-worker instance */
#include "fs/vfs/vfs_backend_registry.h" /* per-export backend config + resolve */

#include <openssl/x509.h>

#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include "core/compat/alloc_guard.h"
#include "core/config/credential_block.h"   /* §14 brix_credential lookup/bearer */

#include "config_internal.h"

#define webdav_validate_path          brix_validate_path
#define WEBDAV_PATH_REGULAR_FILE      BRIX_PATH_REGULAR_FILE
#define WEBDAV_PATH_DIRECTORY         BRIX_PATH_DIRECTORY
#define WEBDAV_PATH_FILE_OR_DIRECTORY BRIX_PATH_FILE_OR_DIRECTORY

char *
webdav_merge_base_conf(ngx_conf_t *cf, ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    /* Unified directives (brix_export, brix_cache_store, ...) live in the
     * common module; pull the merged values for this location into our
     * embedded preamble before protocol merge applies defaults. */
    brix_http_common_adopt(cf, &conf->common);

    /* Shared common.* preamble (incl. hard read-only enforcement + pmark);
     * WebDAV exports default to "/" (pure cache nodes serve the whole ns). */
    if (ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "/")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_conf_merge_str_value(conf->cache_root, prev->cache_root, "");
    ngx_conf_merge_str_value(conf->vomsdir, prev->vomsdir, "");
    ngx_conf_merge_str_value(conf->tcp_congestion, prev->tcp_congestion, "");
    ngx_conf_merge_str_value(conf->voms_cert_dir, prev->voms_cert_dir, "");
    ngx_conf_merge_str_value(conf->cadir, prev->cadir, "");
    ngx_conf_merge_str_value(conf->cafile, prev->cafile, "");
    ngx_conf_merge_ptr_value(conf->authdb_rules, prev->authdb_rules, NULL);
    ngx_conf_merge_ptr_value(conf->vo_rules, prev->vo_rules, NULL);
    ngx_conf_merge_str_value(conf->crl, prev->crl, "");
    ngx_conf_merge_uint_value(conf->signing_policy_mode,
                              prev->signing_policy_mode, BRIX_SP_MODE_ON);
    ngx_conf_merge_uint_value(conf->crl_mode, prev->crl_mode, BRIX_CRL_MODE_TRY);
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 10);
    ngx_conf_merge_uint_value(conf->auth, prev->auth,
                              WEBDAV_AUTH_OPTIONAL);
    brix_acc_http_merge_conf(&conf->acc, &prev->acc);
    ngx_conf_merge_value(conf->proxy_certs, prev->proxy_certs, 0);
    ngx_conf_merge_value(conf->tape_rest, prev->tape_rest, 0);
    /* Uploads staged + resumable by DEFAULT.  Set brix_webdav_upload_resume
     * off to opt out. */
    ngx_conf_merge_value(conf->upload_resume, prev->upload_resume, 1);
    ngx_conf_merge_str_value(conf->upload_stage_dir, prev->upload_stage_dir, "");
    ngx_http_brix_webdav_tpc_merge_loc_conf(conf, prev);
    BRIX_MERGE_PTR(conf, prev, cors_origins);
    ngx_conf_merge_value(conf->cors_credentials, prev->cors_credentials, 0);
    ngx_conf_merge_uint_value(conf->cors_max_age, prev->cors_max_age, 86400);
    ngx_conf_merge_uint_value(conf->lock_timeout, prev->lock_timeout, 600);
    ngx_conf_merge_value(conf->lock_startup_sweep, prev->lock_startup_sweep, 0);
    ngx_conf_merge_value(conf->zip_access, prev->zip_access, 0);
    ngx_conf_merge_value(conf->http_query_token, prev->http_query_token, 1);
    ngx_conf_merge_value(conf->macaroon_max_validity,
                         prev->macaroon_max_validity, 86400);
    ngx_conf_merge_str_value(conf->macaroon_location, prev->macaroon_location, "");
    ngx_conf_merge_str_value(conf->checksum_on_write, prev->checksum_on_write, "");
    ngx_conf_merge_uint_value(conf->checksum_xattr_format,
                              prev->checksum_xattr_format, BRIX_CKS_FMT_TEXT);
    if (conf->checksum_xattr_format != BRIX_CKS_FMT_TEXT) {
        /* §8.x: stock-interoperable binary XrdCksData write format (process-wide). */
        brix_integrity_set_xattr_format(conf->checksum_xattr_format);
    }
    ngx_conf_merge_value(conf->dig_enable, prev->dig_enable, 0);
    ngx_conf_merge_ptr_value(conf->dig_exports, prev->dig_exports, NULL);
    ngx_conf_merge_str_value(conf->dig_auth_file, prev->dig_auth_file, "");
    ngx_conf_merge_value(conf->delegation_endpoint,
                         prev->delegation_endpoint, 0);
    ngx_conf_merge_size_value(conf->zip_cd_max_bytes, prev->zip_cd_max_bytes,
                              16 * 1024 * 1024);

    /* Phase 20 caches/limits: inherit parent block when not set locally. */
    if (conf->token_cache_kv == NULL) {
        conf->token_cache_kv = prev->token_cache_kv;
    }
    if (conf->rate_limit.kv == NULL) {
        conf->rate_limit = prev->rate_limit;
    }

    /* Phase 21 Step C: introspection inheritance. */
    ngx_conf_merge_str_value(conf->introspect_url, prev->introspect_url, "");
    ngx_conf_merge_str_value(conf->introspect_loc, prev->introspect_loc, "");
    ngx_conf_merge_uint_value(conf->introspect_ttl, prev->introspect_ttl, 30);
    ngx_conf_merge_value(conf->introspect_fail_open,
                         prev->introspect_fail_open, 1);
    if (conf->revoke_kv == NULL) {
        conf->revoke_kv = prev->revoke_kv;
    }

    ngx_conf_merge_ptr_value(conf->open_file_cache,
                              prev->open_file_cache, NULL);
    ngx_conf_merge_uint_value(conf->open_file_cache_valid,
                              prev->open_file_cache_valid, 60);
    ngx_conf_merge_uint_value(conf->open_file_cache_min_uses,
                              prev->open_file_cache_min_uses, 1);
    ngx_conf_merge_value(conf->open_file_cache_errors,
                         prev->open_file_cache_errors, 0);
    ngx_conf_merge_value(conf->open_file_cache_events,
                         prev->open_file_cache_events, 0);

    ngx_conf_merge_str_value(conf->pwd_file, prev->pwd_file, "");
    ngx_conf_merge_str_value(conf->token_jwks, prev->token_jwks, "");
    ngx_conf_merge_str_value(conf->token_issuer, prev->token_issuer, "");
    ngx_conf_merge_str_value(conf->token_audience, prev->token_audience, "");
    ngx_conf_merge_value(conf->token_clock_skew, prev->token_clock_skew,
                         BRIX_TOKEN_CLOCK_SKEW_SECS);
    if (conf->token_clock_skew < 0 || conf->token_clock_skew > 300) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_webdav_token_clock_skew must be >= 0 and <= 300");
        return NGX_CONF_ERROR;
    }
    ngx_conf_merge_str_value(conf->token_config, prev->token_config, "");
    ngx_conf_merge_ptr_value(conf->token_registry, prev->token_registry, NULL);
    ngx_conf_merge_str_value(conf->token_macaroon_secret,
                             prev->token_macaroon_secret, "");
    ngx_conf_merge_str_value(conf->token_macaroon_secret_old,
                             prev->token_macaroon_secret_old, "");


    return NGX_CONF_OK;
}

static char *
webdav_prepare_export_root(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    brix_export_root_opts_t root_opts;

    brix_storage_backend_posix_root(&conf->common);
    root_opts.directive_name = "brix_export";
    root_opts.allow_write    = conf->common.allow_write
                             && !brix_storage_backend_is_remote(&conf->common);
    root_opts.required       = 1;
    root_opts.canon_size     = sizeof(conf->common.root_canon);
    if (brix_prepare_export_root(cf, &conf->common.root, &root_opts,
                                   conf->common.root_canon) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    brix_tmp_reap_register(conf->common.root_canon);
    return NGX_CONF_OK;
}

static char *
webdav_finalize_authz_rules(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (conf->vomsdir.len > 0) {
        (void) brix_voms_init(cf->log);
    }
    if (conf->authdb_rules != NULL
        && brix_finalize_authdb_rules(cf->log, &conf->common.root,
                                        conf->authdb_rules) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_webdav_authdb: failed to finalize rules for root \"%V\"",
            &conf->common.root);
        return NGX_CONF_ERROR;
    }
    if (conf->vo_rules != NULL
        && brix_finalize_vo_rules(cf->log, &conf->common.root,
                                    conf->vo_rules) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_webdav_require_vo: failed to finalize rules for root \"%V\"",
            &conf->common.root);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
webdav_set_storage_credential(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    char                     cred_z[256];
    char                     bearer[4096];
    const brix_credential_t *cred;
    brix_vfs_backend_cred_t  bcred;

    if (conf->common.storage_credential.len == 0) {
        return NGX_CONF_OK;
    }
    ngx_cpystrn((u_char *) cred_z, conf->common.storage_credential.data,
                ngx_min(conf->common.storage_credential.len + 1,
                        sizeof(cred_z)));
    cred = brix_credential_lookup(cred_z);
    if (cred == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_webdav_storage_credential: no brix_credential \"%V\"",
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

static char *
webdav_configure_storage_backend(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (brix_vfs_backend_config_str(cf, conf->common.root_canon,
            &conf->common.storage_backend, conf->common.pblock_block_size,
            BRIX_AF_AUTO) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    if (conf->common.storage_staging) {
        brix_vfs_backend_set_staging(conf->common.root_canon, 1);
    }
    return webdav_set_storage_credential(cf, conf);
}

static char *
webdav_prepare_stage_and_cache(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (conf->upload_stage_dir.len > 0) {
        brix_export_root_opts_t stage_opts;
        stage_opts.directive_name = "brix_webdav_stage_dir";
        stage_opts.allow_write    = 1;
        stage_opts.required       = 0;
        stage_opts.canon_size     = sizeof(conf->upload_stage_dir_canon);
        if (brix_prepare_export_root(cf, &conf->upload_stage_dir,
                &stage_opts, conf->upload_stage_dir_canon) != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
        brix_stage_dir_register(conf->upload_stage_dir_canon);
    }
    if (brix_assert_dir_outside_export(cf, "brix_webdav_stage_dir",
            conf->common.root_canon, conf->upload_stage_dir_canon) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    if (conf->cache_root.len > 0) {
        brix_export_root_opts_t cache_opts;
        cache_opts.directive_name = "brix_webdav_cache_root";
        cache_opts.allow_write    = 0;
        cache_opts.required       = 0;
        cache_opts.canon_size     = sizeof(conf->cache_root_canon);
        if (brix_prepare_export_root(cf, &conf->cache_root, &cache_opts,
                                       conf->cache_root_canon) != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
        if (brix_assert_dir_outside_export(cf, "brix_webdav_cache_root",
                conf->common.root_canon, conf->cache_root_canon) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}

static void
webdav_run_lock_startup_sweep(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (conf->lock_startup_sweep && !ngx_test_config
        && conf->common.root_canon[0] != '\0')
    {
        ngx_uint_t removed = webdav_lock_startup_sweep(
            cf->pool, cf->log, conf->common.root_canon);
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "brix_webdav: lock startup sweep removed %ui persisted "
            "lock(s) under \"%s\"", removed, conf->common.root_canon);
    }
}

static char *
webdav_validate_auth_paths(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    /* auth optional/required needs at least ONE credential verifier: an x509
     * CA (cadir/cafile), a token verifier (JWKS / issuer registry / macaroon
     * secret), or a Basic password db — otherwise every client is rejected
     * and the misconfiguration should fail `nginx -t`, not surface as 403s. */
    if ((conf->auth == WEBDAV_AUTH_OPTIONAL
         || conf->auth == WEBDAV_AUTH_REQUIRED)
        && conf->cadir.len == 0 && conf->cafile.len == 0
        && conf->token_jwks.len == 0 && conf->token_config.len == 0
        && conf->token_macaroon_secret.len == 0 && conf->pwd_file.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_webdav: auth optional/required needs a credential verifier "
            "— brix_webdav_cadir/cafile, brix_webdav_token_jwks/config/"
            "macaroon_secret, or brix_webdav_pwd_file");
        return NGX_CONF_ERROR;
    }
    if (webdav_validate_path(cf, "brix_webdav_cadir", &conf->cadir,
                             WEBDAV_PATH_DIRECTORY, R_OK | X_OK) != NGX_OK
        || webdav_validate_path(cf, "brix_webdav_cafile", &conf->cafile,
                                WEBDAV_PATH_REGULAR_FILE, R_OK) != NGX_OK
        || webdav_validate_path(cf, "brix_webdav_crl", &conf->crl,
                                WEBDAV_PATH_FILE_OR_DIRECTORY, R_OK) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    if (webdav_validate_cors_origins(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
webdav_build_ca_store_once(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    X509_STORE         *store;
    ngx_pool_cleanup_t *cln;
    int                 crl_count = 0;

    if (conf->auth != WEBDAV_AUTH_OPTIONAL
        && conf->auth != WEBDAV_AUTH_REQUIRED)
    {
        return NGX_CONF_OK;
    }
    /* Token-only / Basic-only exports carry no x509 trust anchors: there is
     * no store to build, and the cert tier declines at request time. */
    if (conf->cadir.len == 0 && conf->cafile.len == 0) {
        return NGX_CONF_OK;
    }
    store = webdav_build_ca_store(cf->log, conf, &crl_count);
    if (store == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_webdav: failed to build cached CA store");
        return NGX_CONF_ERROR;
    }
    (void) webdav_check_pki_consistency(cf->log, conf);
    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        X509_STORE_free(store);
        return NGX_CONF_ERROR;
    }
    cln->handler = webdav_x509_store_cleanup;
    cln->data = store;
    conf->ca_store = store;
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "brix_webdav: cached CA store built for root=\"%V\" crls=%d",
                       &conf->common.root, crl_count);
    return NGX_CONF_OK;
}

static char *
webdav_validate_token_jwks_path(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (conf->token_jwks.len == 0) {
        return NGX_CONF_OK;
    }
    if (conf->token_issuer.len == 0 || conf->token_audience.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_webdav: brix_webdav_token_jwks requires brix_webdav_token_issuer and brix_webdav_token_audience");
        return NGX_CONF_ERROR;
    }
    if (webdav_validate_path(cf, "brix_webdav_token_jwks", &conf->token_jwks,
                             WEBDAV_PATH_REGULAR_FILE, R_OK) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

/* brix_webdav_pwd_file must point at a readable regular file so a typo'd
 * password db fails `nginx -t` instead of silently rejecting every login. */
static char *
webdav_validate_pwd_file_path(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (conf->pwd_file.len == 0) {
        return NGX_CONF_OK;
    }
    if (webdav_validate_path(cf, "brix_webdav_pwd_file", &conf->pwd_file,
                             WEBDAV_PATH_REGULAR_FILE, R_OK) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
webdav_validate_tpc_paths(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (!conf->tpc) {
        return NGX_CONF_OK;
    }
    if (webdav_validate_path(cf, "brix_webdav_tpc_curl", &conf->tpc_curl,
                             WEBDAV_PATH_REGULAR_FILE, X_OK) != NGX_OK
        || webdav_validate_path(cf, "brix_webdav_tpc_cert", &conf->tpc_cert,
                                WEBDAV_PATH_REGULAR_FILE, R_OK) != NGX_OK
        || webdav_validate_path(cf, "brix_webdav_tpc_key", &conf->tpc_key,
                                WEBDAV_PATH_REGULAR_FILE, R_OK) != NGX_OK
        || webdav_validate_path(cf, "brix_webdav_tpc_cadir", &conf->tpc_cadir,
                                WEBDAV_PATH_DIRECTORY, R_OK | X_OK) != NGX_OK
        || webdav_validate_path(cf, "brix_webdav_tpc_cafile", &conf->tpc_cafile,
                                WEBDAV_PATH_REGULAR_FILE, R_OK) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

char *
webdav_validate_webdav_enabled(ngx_conf_t *cf, ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    (void) prev;

    if (!conf->common.enable) {
        return NGX_CONF_OK;
    }
    if (webdav_prepare_export_root(cf, conf) != NGX_CONF_OK
        || webdav_finalize_authz_rules(cf, conf) != NGX_CONF_OK
        || webdav_configure_storage_backend(cf, conf) != NGX_CONF_OK
        || brix_http_open_rootfd(cf, &conf->common) != NGX_CONF_OK
        || brix_tier_register_stores(cf, &conf->common) != NGX_OK
        || webdav_prepare_stage_and_cache(cf, conf) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    webdav_run_lock_startup_sweep(cf, conf);
    if (webdav_validate_auth_paths(cf, conf) != NGX_CONF_OK
        || webdav_build_ca_store_once(cf, conf) != NGX_CONF_OK
        || webdav_validate_token_jwks_path(cf, conf) != NGX_CONF_OK
        || webdav_validate_pwd_file_path(cf, conf) != NGX_CONF_OK
        || webdav_validate_tpc_paths(cf, conf) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
