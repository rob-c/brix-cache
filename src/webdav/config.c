/*
 * config.c - WebDAV location config create/merge and startup validation.
 */

#include "webdav.h"

#include <openssl/x509.h>

#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum {
    WEBDAV_PATH_REGULAR_FILE,
    WEBDAV_PATH_DIRECTORY,
    WEBDAV_PATH_FILE_OR_DIRECTORY
} webdav_path_kind_t;

static ngx_int_t
webdav_validate_path(ngx_conf_t *cf, const char *label, const ngx_str_t *path,
                     webdav_path_kind_t kind, int access_mode)
{
    struct stat st;

    if (path == NULL || path->len == 0 || path->data == NULL) {
        return NGX_OK;
    }

    if (stat((char *) path->data, &st) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd_webdav: %s path \"%s\" is not accessible",
                           label, path->data);
        return NGX_ERROR;
    }

    switch (kind) {
    case WEBDAV_PATH_REGULAR_FILE:
        if (!S_ISREG(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav: %s path \"%s\" must be a regular file",
                               label, path->data);
            return NGX_ERROR;
        }
        break;

    case WEBDAV_PATH_DIRECTORY:
        if (!S_ISDIR(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav: %s path \"%s\" must be a directory",
                               label, path->data);
            return NGX_ERROR;
        }
        break;

    case WEBDAV_PATH_FILE_OR_DIRECTORY:
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav: %s path \"%s\" must be a file or directory",
                               label, path->data);
            return NGX_ERROR;
        }
        break;
    }

    if (access_mode != 0 && access((char *) path->data, access_mode) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd_webdav: %s path \"%s\" failed permission check",
                           label, path->data);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
webdav_x509_store_cleanup(void *data)
{
    X509_STORE *store = data;

    if (store != NULL) {
        X509_STORE_free(store);
    }
}

static ngx_int_t
webdav_validate_cors_origins(ngx_conf_t *cf,
                             ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_str_t  *origins;
    ngx_uint_t  i;

    if (conf->cors_origins == NULL) {
        return NGX_OK;
    }

    origins = conf->cors_origins->elts;
    for (i = 0; i < conf->cors_origins->nelts; i++) {
        if (origins[i].len == 0
            || webdav_tpc_str_has_ctl(origins[i].data, origins[i].len))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav: invalid CORS origin \"%V\"",
                               &origins[i]);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

void *
ngx_http_xrootd_webdav_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable       = NGX_CONF_UNSET;
    conf->verify_depth = NGX_CONF_UNSET_UINT;
    conf->auth         = NGX_CONF_UNSET_UINT;
    conf->proxy_certs  = NGX_CONF_UNSET;
    conf->allow_write  = NGX_CONF_UNSET;
    conf->ca_store     = NULL;
    conf->cors_origins = NULL;
    conf->cors_credentials = NGX_CONF_UNSET;
    conf->cors_max_age = NGX_CONF_UNSET_UINT;
    conf->lock_timeout = NGX_CONF_UNSET_UINT;
    ngx_http_xrootd_webdav_tpc_create_loc_conf(conf);

    conf->upstream_proxy    = NGX_CONF_UNSET;
    conf->upstream_auth     = (ngx_uint_t) NGX_CONF_UNSET_UINT;
    conf->upstream_resolved = NULL;
    conf->upstream_conf.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream_conf.send_timeout    = NGX_CONF_UNSET_MSEC;
    conf->upstream_conf.read_timeout    = NGX_CONF_UNSET_MSEC;

    return conf;
}

char *
ngx_http_xrootd_webdav_merge_loc_conf(ngx_conf_t *cf,
                                      void *parent, void *child)
{
    ngx_http_xrootd_webdav_loc_conf_t *prev = parent;
    ngx_http_xrootd_webdav_loc_conf_t *conf = child;

    extern ngx_shm_zone_t *webdav_lock_shm_zone;

    conf->lock_shm_zone = webdav_lock_shm_zone;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->root, prev->root, "/");
    ngx_conf_merge_str_value(conf->cadir, prev->cadir, "");
    ngx_conf_merge_str_value(conf->cafile, prev->cafile, "");
    ngx_conf_merge_str_value(conf->crl, prev->crl, "");
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 10);
    ngx_conf_merge_uint_value(conf->auth, prev->auth,
                              WEBDAV_AUTH_OPTIONAL);
    ngx_conf_merge_value(conf->proxy_certs, prev->proxy_certs, 0);
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_http_xrootd_webdav_tpc_merge_loc_conf(conf, prev);
    if (conf->cors_origins == NULL) {
        conf->cors_origins = prev->cors_origins;
    }
    ngx_conf_merge_value(conf->cors_credentials, prev->cors_credentials, 0);
    ngx_conf_merge_uint_value(conf->cors_max_age, prev->cors_max_age, 86400);
    ngx_conf_merge_uint_value(conf->lock_timeout, prev->lock_timeout, 600);

    ngx_conf_merge_str_value(conf->token_jwks, prev->token_jwks, "");
    ngx_conf_merge_str_value(conf->token_issuer, prev->token_issuer, "");
    ngx_conf_merge_str_value(conf->token_audience, prev->token_audience, "");
    ngx_conf_merge_str_value(conf->token_macaroon_secret,
                             prev->token_macaroon_secret, "");
    ngx_conf_merge_str_value(conf->token_macaroon_secret_old,
                             prev->token_macaroon_secret_old, "");

    if (conf->enable) {
        if (webdav_validate_path(cf, "xrootd_webdav_root", &conf->root,
                                 WEBDAV_PATH_DIRECTORY,
                                 conf->allow_write ? (R_OK | W_OK | X_OK)
                                                   : (R_OK | X_OK))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        {
            char root_buf[WEBDAV_MAX_PATH];

            if (conf->root.len >= sizeof(root_buf)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xrootd_webdav: root path too long");
                return NGX_CONF_ERROR;
            }

            ngx_memcpy(root_buf, conf->root.data, conf->root.len);
            root_buf[conf->root.len] = '\0';

            if (realpath(root_buf, conf->root_canon) == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
                                   "xrootd_webdav: cannot resolve root \"%V\"",
                                   &conf->root);
                return NGX_CONF_ERROR;
            }
        }

        if (conf->auth == WEBDAV_AUTH_OPTIONAL
            || conf->auth == WEBDAV_AUTH_REQUIRED)
        {
            if (conf->cadir.len == 0 && conf->cafile.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xrootd_webdav: auth optional/required needs xrootd_webdav_cadir or xrootd_webdav_cafile");
                return NGX_CONF_ERROR;
            }
        }

        if (webdav_validate_path(cf, "xrootd_webdav_cadir", &conf->cadir,
                                 WEBDAV_PATH_DIRECTORY, R_OK | X_OK)
            != NGX_OK
            || webdav_validate_path(cf, "xrootd_webdav_cafile", &conf->cafile,
                                    WEBDAV_PATH_REGULAR_FILE, R_OK)
               != NGX_OK
            || webdav_validate_path(cf, "xrootd_webdav_crl", &conf->crl,
                                    WEBDAV_PATH_FILE_OR_DIRECTORY, R_OK)
               != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (webdav_validate_cors_origins(cf, conf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (conf->auth == WEBDAV_AUTH_OPTIONAL
            || conf->auth == WEBDAV_AUTH_REQUIRED)
        {
            X509_STORE         *store;
            ngx_pool_cleanup_t *cln;
            int                 crl_count = 0;

            store = webdav_build_ca_store(cf->log, conf, &crl_count);
            if (store == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xrootd_webdav: failed to build cached CA store");
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
                               "xrootd_webdav: cached CA store built"
                               " for root=\"%V\" crls=%d",
                               &conf->root, crl_count);
        }

        if (conf->token_jwks.len > 0) {
            if (conf->token_issuer.len == 0
                || conf->token_audience.len == 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xrootd_webdav: xrootd_webdav_token_jwks requires xrootd_webdav_token_issuer and xrootd_webdav_token_audience");
                return NGX_CONF_ERROR;
            }

            if (webdav_validate_path(cf, "xrootd_webdav_token_jwks",
                                     &conf->token_jwks,
                                     WEBDAV_PATH_REGULAR_FILE, R_OK)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        if (conf->tpc) {
            if (webdav_validate_path(cf, "xrootd_webdav_tpc_curl",
                                     &conf->tpc_curl,
                                     WEBDAV_PATH_REGULAR_FILE, X_OK)
                != NGX_OK
                || webdav_validate_path(cf, "xrootd_webdav_tpc_cert",
                                        &conf->tpc_cert,
                                        WEBDAV_PATH_REGULAR_FILE, R_OK)
                   != NGX_OK
                || webdav_validate_path(cf, "xrootd_webdav_tpc_key",
                                        &conf->tpc_key,
                                        WEBDAV_PATH_REGULAR_FILE, R_OK)
                   != NGX_OK
                || webdav_validate_path(cf, "xrootd_webdav_tpc_cadir",
                                        &conf->tpc_cadir,
                                        WEBDAV_PATH_DIRECTORY, R_OK | X_OK)
                   != NGX_OK
                || webdav_validate_path(cf, "xrootd_webdav_tpc_cafile",
                                        &conf->tpc_cafile,
                                        WEBDAV_PATH_REGULAR_FILE, R_OK)
                   != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (conf->token_jwks.len > 0) {
        int rc;

        rc = xrootd_jwks_load(cf->log,
                              (const char *) conf->token_jwks.data,
                              conf->jwks_keys, XROOTD_MAX_JWKS_KEYS);
        if (rc < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav: failed to load JWKS from \"%V\"",
                               &conf->token_jwks);
            return NGX_CONF_ERROR;
        }
        conf->jwks_key_count = rc;
    }

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

    if (conf->upstream_proxy && conf->upstream_resolved == NULL) {
        /* Inherit pre-resolved address from parent if URL is the same */
        if (conf->upstream_url.len == 0 && prev->upstream_url.len > 0) {
            conf->upstream_url = prev->upstream_url;
        }
        if (conf->upstream_resolved == NULL && prev->upstream_resolved != NULL
            && prev->upstream_url.len == conf->upstream_url.len
            && ngx_memcmp(prev->upstream_url.data, conf->upstream_url.data,
                          conf->upstream_url.len) == 0)
        {
            conf->upstream_resolved  = prev->upstream_resolved;
            conf->upstream_host      = prev->upstream_host;
            conf->upstream_url_base  = prev->upstream_url_base;
            conf->upstream_ssl       = prev->upstream_ssl;
            conf->upstream_conf      = prev->upstream_conf;
#if (NGX_HTTP_SSL)
            conf->upstream_ssl_ctx   = prev->upstream_ssl_ctx;
#endif
        }

        if (conf->upstream_resolved == NULL) {
            if (webdav_proxy_parse_upstream_url(cf, conf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

        if (conf->upstream_auth == WEBDAV_PROXY_AUTH_TOKEN
            && conf->upstream_auth_token.len == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav_proxy_auth token requires a"
                               " non-empty token value");
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
