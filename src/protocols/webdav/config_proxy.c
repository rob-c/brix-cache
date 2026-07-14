/*
 * config_proxy.c - WebDAV token-load + upstream-proxy + traffic-mirror merge cluster.
 *
 * WHAT: the merge-time helpers that load JWKS/multi-issuer token config
 *   (webdav_merge_auth_token_conf), resolve the upstream-proxy backends whether
 *   dynamic-pool or static (webdav_merge_upstream_conf and its helpers), and merge
 *   the Phase-24 traffic-mirror settings then emit the per-endpoint startup summary
 *   (webdav_merge_mirror_and_summary).
 * WHY: split VERBATIM out of config.c to keep each translation unit under the
 *   file-size gate; behaviour is unchanged. The three entrypoints called by the
 *   merge glue in config.c (webdav_merge_auth_token_conf, webdav_merge_upstream_conf,
 *   webdav_merge_mirror_and_summary) are declared in config_internal.h, as are the
 *   summary helpers (webdav_summary_is_new / webdav_log_endpoint_summary) they call
 *   back into.
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
webdav_merge_auth_token_conf(ngx_conf_t *cf, ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (conf->token_jwks.len > 0) {
        int rc;

        rc = brix_jwks_load(cf->log,
                              (const char *) conf->token_jwks.data,
                              conf->jwks_keys, BRIX_MAX_JWKS_KEYS);
        if (rc < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "brix_webdav: failed to load JWKS from \"%V\"",
                               &conf->token_jwks);
            return NGX_CONF_ERROR;
        }
        conf->jwks_key_count = rc;

        if (rc > 0
            && brix_jwks_register_cleanup(cf->pool, conf->jwks_keys,
                                            &conf->jwks_key_count) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    /* Multi-issuer registry (phase-59 W1) — only build it on a leaf location
     * that actually set brix_webdav_token_config (token_registry stays the
     * inherited value otherwise). */
    if (conf->token_config.len > 0 && conf->token_registry == NULL) {
        brix_token_registry_t *reg = NULL;

        if (brix_token_registry_build(cf,
                (const char *) conf->token_config.data,
                BRIX_AUTHZ_CAPABILITY, &reg) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
        conf->token_registry = reg;
    }


    return NGX_CONF_OK;
}

static char *
webdav_validate_proxy_token(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (conf->upstream_auth == WEBDAV_PROXY_AUTH_TOKEN
        && conf->upstream_auth_token.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_webdav_proxy_auth token requires a"
                           " non-empty token value");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
webdav_setup_dynamic_proxy_pool(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (webdav_proxy_pool_setup(cf, conf, prev) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return webdav_validate_proxy_token(cf, conf);
}

static void
webdav_try_inherit_static_backends(ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (conf->upstream_urls == NULL && prev->upstream_urls != NULL) {
        conf->upstream_urls = prev->upstream_urls;
    }
    if (conf->upstream_url.len == 0 && prev->upstream_url.len > 0) {
        conf->upstream_url = prev->upstream_url;
    }
    if (prev->upstream_backends == NULL
        || conf->upstream_urls != prev->upstream_urls
        || prev->upstream_url.len != conf->upstream_url.len
        || (conf->upstream_url.len > 0
            && ngx_memcmp(prev->upstream_url.data, conf->upstream_url.data,
                          conf->upstream_url.len) != 0))
    {
        return;
    }
    conf->upstream_backends  = prev->upstream_backends;
    conf->upstream_resolved  = prev->upstream_resolved;
    conf->upstream_host      = prev->upstream_host;
    conf->upstream_url_base  = prev->upstream_url_base;
    conf->upstream_ssl       = prev->upstream_ssl;
    conf->upstream_conf      = prev->upstream_conf;
#if (NGX_HTTP_SSL)
    conf->upstream_ssl_ctx   = prev->upstream_ssl_ctx;
#endif
}

static char *
webdav_build_static_proxy_backends(ngx_conf_t *cf,
    ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    static ngx_str_t  webdav_proxy_hide_headers[] = {
        ngx_null_string
    };
    ngx_hash_init_t   hh;

    webdav_try_inherit_static_backends(prev, conf);
    if (conf->upstream_backends != NULL) {
        return webdav_validate_proxy_token(cf, conf);
    }

    if (webdav_proxy_build_backends(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    hh.max_size     = 512;
    hh.bucket_size  = ngx_align(64, ngx_cacheline_size);
    hh.name         = "webdav_proxy_hide_headers_hash";
    hh.pool         = cf->pool;
    hh.temp_pool    = NULL;
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream_conf,
            &prev->upstream_conf, webdav_proxy_hide_headers, &hh) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return webdav_validate_proxy_token(cf, conf);
}

char *
webdav_merge_upstream_conf(ngx_conf_t *cf, ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_conf_merge_value(conf->upstream_proxy, prev->upstream_proxy, 0);
    ngx_conf_merge_str_value(conf->upstream_url, prev->upstream_url, "");
    ngx_conf_merge_uint_value(conf->upstream_auth, prev->upstream_auth,
                              WEBDAV_PROXY_AUTH_ANONYMOUS);
    ngx_conf_merge_str_value(conf->upstream_auth_token,
                             prev->upstream_auth_token, "");
    ngx_conf_merge_msec_value(conf->upstream_conf.connect_timeout,
                              prev->upstream_conf.connect_timeout, 0);
    ngx_conf_merge_msec_value(conf->upstream_conf.send_timeout,
                              prev->upstream_conf.send_timeout, 0);
    ngx_conf_merge_msec_value(conf->upstream_conf.read_timeout,
                              prev->upstream_conf.read_timeout, 0);
    ngx_conf_merge_uint_value(conf->upstream_max_fails,
                              prev->upstream_max_fails, 3);
    ngx_conf_merge_msec_value(conf->upstream_fail_timeout,
                              prev->upstream_fail_timeout, 30000);
    ngx_conf_merge_value(conf->proxy_pool_enabled, prev->proxy_pool_enabled, 0);

    if (!conf->upstream_proxy) {
        return NGX_CONF_OK;
    }
    if (conf->proxy_pool_enabled) {
        return webdav_setup_dynamic_proxy_pool(cf, prev, conf);
    }
    if (conf->upstream_backends == NULL) {
        return webdav_build_static_proxy_backends(cf, prev, conf);
    }
    return NGX_CONF_OK;
}

char *
webdav_merge_mirror_and_summary(ngx_conf_t *cf, ngx_http_brix_webdav_loc_conf_t *prev,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    /* Phase 24: traffic mirror — inherit parent targets, derive enabled, and
     * build the shadow upstream conf (timeouts/TLS/hide-headers) when active. */
    if (conf->mirror.targets == NULL) {
        conf->mirror.targets = prev->mirror.targets;
    }
    ngx_conf_merge_str_value(conf->mirror.token, prev->mirror.token, "");
    ngx_conf_merge_uint_value(conf->mirror.sample_pct,  prev->mirror.sample_pct, 100);
    ngx_conf_merge_uint_value(conf->mirror.method_mask, prev->mirror.method_mask,
                              BRIX_MIRROR_M_DEFAULT);
    ngx_conf_merge_value(conf->mirror.strip_auth,  prev->mirror.strip_auth,  1);
    ngx_conf_merge_value(conf->mirror.log_diverge, prev->mirror.log_diverge, 1);
    ngx_conf_merge_msec_value(conf->mirror.timeout_ms, prev->mirror.timeout_ms, 5000);
    ngx_conf_merge_value(conf->mirror.mirror_writes,
                         prev->mirror.mirror_writes, 0);
    conf->mirror.enabled = (conf->mirror.targets != NULL
                            && conf->mirror.targets->nelts > 0) ? 1 : 0;

    if (conf->mirror.enabled
        && conf->mirror_upstream_conf.connect_timeout == 0)
    {
        if (brix_http_mirror_setup(cf, conf, prev) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Friendly per-endpoint startup summary (visible in `nginx -t` output and
     * at boot). Only for a location that actually enables WebDAV and whose
     * config is not merely inherited unchanged from its parent — see
     * webdav_summary_is_new(). Mirrors the root:// banner in the stream
     * postconfiguration.
     */
    if (conf->common.enable && webdav_summary_is_new(conf, prev)) {
        webdav_log_endpoint_summary(cf, conf);
    }


    return NGX_CONF_OK;
}
