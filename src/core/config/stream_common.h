/* stream_common.h — unified brix storage/x509 grammar (STREAM plane)
 *
 * WHAT: one stream module owns the bare storage + GSI-trust grammar
 *       (brix_export, brix_allow_write, brix_verify_write, brix_storage_backend,
 *       brix_storage_credential, and — stage 2 — the x509 trust family) so
 *       root:// and the gridftp gateway share a single directive surface.
 * WHY:  nginx's ngx_conf_handler is first-module-wins on directive names, so a
 *       shared stream name must be registered by exactly one stream module.
 *       Before phase-101 W3, gridftp could not use the bare names (they routed
 *       to the root module) and so grew 11 prefixed brix_gridftp_* twins.
 * HOW:  values land in this module's ngx_http_brix_shared_conf_t (the
 *       plane-neutral preamble); the root and gridftp modules copy the values
 *       into their own embedded preamble via brix_stream_common_adopt() at
 *       merge_srv_conf time.  The adopt folds the CURRENT server's srv conf
 *       (fields set at parse time), so it is correct regardless of this
 *       module's merge order relative to root/gridftp — which matters because
 *       the module is emitted AFTER ngx_stream_brix_module to preserve the
 *       ngx_stream_brix_module.so name (see ./config).
 */
#ifndef BRIX_STREAM_COMMON_H
#define BRIX_STREAM_COMMON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "core/config/shared_conf.h"

typedef struct {
    brix_shared_conf_t  common;
} ngx_stream_brix_common_conf_t;

extern ngx_module_t  ngx_stream_brix_common_module;

/*
 * brix_stream_common_adopt() — fetch the common module's srv conf for the
 * server currently being merged and adopt its unified values into dst.  Call
 * from a stream protocol's merge_srv_conf BEFORE that protocol applies its own
 * per-field defaults, so the unified values seed the preamble and defaults land
 * only on still-unset slots (mirror of brix_http_common_adopt on the HTTP
 * plane).  Only fills dst slots that are still UNSET.
 */
void brix_stream_common_adopt(ngx_conf_t *cf, brix_shared_conf_t *dst);

/* Detach adopted VO rules before a protocol finalizes resolved paths in-place. */
ngx_int_t brix_shared_clone_vo_rules(ngx_conf_t *cf, brix_shared_conf_t *conf);

#endif /* BRIX_STREAM_COMMON_H */
