/*
 * config_proxy.c - WebDAV token-load + traffic-mirror merge cluster.
 *
 * WHAT: the merge-time helpers that load JWKS/multi-issuer token config
 *   (webdav_merge_auth_token_conf) and merge the Phase-24 traffic-mirror settings
 *   then emit the per-endpoint startup summary (webdav_merge_mirror_and_summary).
 * WHY: split out of config.c to keep each translation unit under the file-size
 *   gate. The two entrypoints called by the merge glue in config.c
 *   (webdav_merge_auth_token_conf, webdav_merge_mirror_and_summary) are declared
 *   in config_internal.h, as are the summary helpers (webdav_summary_is_new /
 *   webdav_log_endpoint_summary) they call back into.
 * NOTE: the WebDAV reverse-proxy transport (brix_webdav_proxy*) was retired; its
 *   merge helpers were removed with it.
 */

#include "webdav.h"
#include "auth/crypto/store_policy.h"      /* BRIX_SP_MODE_*, BRIX_CRL_MODE_* defaults */
#include "core/compat/integrity_info.h"   /* §8.x checksum xattr write format */
#include "core/compat/tmp_path.h"          /* SP4 orphan direct-write temp reaper */
#include "auth/token/issuer_registry.h"   /* phase-59 W1 multi-issuer registry */
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
