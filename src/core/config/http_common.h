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

typedef struct {
    ngx_http_brix_shared_conf_t  common;
} ngx_http_brix_common_conf_t;

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

#endif /* BRIX_HTTP_COMMON_H */
