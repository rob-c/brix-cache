#ifndef XROOTD_CONFIG_INTERNAL_H
#define XROOTD_CONFIG_INTERNAL_H

#include "../ngx_xrootd_module.h"

/* Filesystem object kind checked by xrootd_validate_path. */
typedef enum {
    XROOTD_PATH_REGULAR_FILE,      /* path must be an existing regular file */
    XROOTD_PATH_DIRECTORY,         /* path must be an existing directory */
    XROOTD_PATH_FILE_OR_DIRECTORY  /* path must exist; either kind is acceptable */
} xrootd_path_kind_t;

/*
 * xrootd_validate_path — check that a configured path exists, is of the right
 * kind, and is accessible with access_mode (e.g. R_OK).
 *
 * Emits NGX_LOG_EMERG and returns NGX_ERROR on any failure; used during
 * postconfiguration to catch misconfigured paths early.
 */
ngx_int_t xrootd_validate_path(ngx_conf_t *cf, const char *label,
    const ngx_str_t *path, xrootd_path_kind_t kind, int access_mode);

/*
 * xrootd_copy_conf_string — duplicate a C string from an ngx_str_t source
 * into a NUL-terminated ngx_str_t using ngx_pnalloc from cf->pool.
 *
 * Returns NGX_CONF_ERROR on OOM; otherwise the cfg error string returned by
 * the directive setter.  dst->data and dst->len are set on success.
 */
char *xrootd_copy_conf_string(ngx_conf_t *cf, const ngx_str_t *src,
    ngx_str_t *dst);

/* Called from postconfiguration to validate and prepare each server block. */
ngx_int_t xrootd_config_prepare_server(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Load GSI CA store and configure the GSI authentication subsystem. */
ngx_int_t xrootd_configure_gsi(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Resolve xrootd_tls_certificate/key and prepare the SSL_CTX. */
ngx_int_t xrootd_configure_tls(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Load JWKS keys for bearer-token (WLCG/SciToken) authentication. */
ngx_int_t xrootd_configure_token_auth(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Load the SSS key file and validate key length/format. */
ngx_int_t xrootd_configure_sss_auth(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Validate and apply VO ACL rules and group-ownership policies. */
ngx_int_t xrootd_config_finalize_policy(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf);

/* Create or attach to the shared-memory metrics zone. */
ngx_int_t xrootd_configure_metrics(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf);

/* Create or attach to the shared-memory session registry zone. */
ngx_int_t xrootd_configure_session_registry(ngx_conf_t *cf);

/* Create or attach to the shared-memory server registry zone. */
ngx_int_t xrootd_srv_configure_registry(ngx_conf_t *cf, ngx_uint_t slots);

/* Create or attach to the shared-memory pending-locate table zone. */
ngx_int_t xrootd_pending_configure(ngx_conf_t *cf);

#if (NGX_THREADS)
/* Resolve thread-pool names to concrete pool objects for all server blocks. */
ngx_int_t xrootd_configure_thread_pools(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf);
#endif

#endif /* XROOTD_CONFIG_INTERNAL_H */
