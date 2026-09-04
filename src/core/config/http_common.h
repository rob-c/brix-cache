/* http_common.h — unified brix storage/namespace directives (HTTP plane)
 *
 * WHAT: one module owns the bare storage grammar (brix_export,
 *       brix_storage_backend, brix_storage_credential, brix_cache_*,
 *       brix_stage*, brix_thread_pool, brix_cache_verify, brix_allow_write,
 *       brix_read_only, brix_compress) so every brix HTTP protocol shares a
 *       single directive surface.
 * WHY:  nginx's ngx_conf_handler is first-module-wins on directive names,
 *       so a shared name must be registered by exactly one http module.
 * HOW:  values land in this module's ngx_http_brix_shared_conf_t; protocol
 *       modules copy the merged values into their embedded `common` via
 *       brix_http_common_adopt() at merge_loc_conf time.  Module emission
 *       order in ./config puts this module before the protocol modules, so
 *       its merge for a given location always precedes theirs.
 */
#ifndef BRIX_HTTP_COMMON_H
#define BRIX_HTTP_COMMON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "core/config/shared_conf.h"
#include "auth/token/token.h"

typedef struct {
    ngx_http_brix_shared_conf_t  common;
} ngx_http_brix_common_conf_t;

typedef struct {
    ngx_array_t *jwks_refresh_specs; /* brix_jwks_refresh_spec_t[] */
} ngx_http_brix_common_main_conf_t;

extern ngx_module_t  ngx_http_brix_common_module;

/*
 * brix_shared_adopt_unified() — copy every unified field from src into dst
 * where dst is still UNSET and src is set.  Pure, no allocation; both structs
 * must have been ngx_http_brix_shared_init()-initialised so the per-field
 * "unset" sentinels are meaningful.  Only the fields the common module owns a
 * directive for are adopted (protocol-private fields are left untouched).
 */
void brix_shared_adopt_unified(ngx_http_brix_shared_conf_t *dst,
                               const ngx_http_brix_shared_conf_t *src);

/*
 * brix_http_common_adopt() — fetch the common module's conf for the location
 * currently being merged and adopt it into dst.  Call from a protocol's
 * merge_loc_conf BEFORE ngx_http_brix_shared_merge() so the unified values
 * seed the protocol preamble and the protocol's per-field defaults then apply
 * only to still-unset slots.
 */
void brix_http_common_adopt(ngx_conf_t *cf,
                            ngx_http_brix_shared_conf_t *dst);

/* Register one protocol-owned HTTP key array for per-worker JWKS refresh.
 * The common module owns timer startup so WebDAV and S3 share one lifecycle
 * implementation while retaining their existing validation arrays. */
ngx_int_t brix_http_common_register_jwks_refresh(ngx_conf_t *cf,
    const ngx_str_t *path, brix_jwks_key_t *keys, int *key_count,
    ngx_msec_t interval);

/*
 * Hand-written directive setters for the shared preamble (http_common_setters.c).
 * Non-static so the command table in http_common.c can name them; not for use
 * outside that table.
 *   _mint_ca            — "brix_storage_credential_mint_ca <cert> <key>"
 *   _peers              — "brix_cache_peers <url>..."
 *   _backend_tx_endpoint — "brix_backend_token_exchange_endpoint <url>"
 */
char *brix_conf_set_mint_ca(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_conf_set_peers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_conf_set_backend_tx_endpoint(ngx_conf_t *cf, ngx_command_t *cmd,
                                        void *conf);

#endif /* BRIX_HTTP_COMMON_H */
