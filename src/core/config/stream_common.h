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
    ngx_http_brix_shared_conf_t  common;

    /* phase-101 W3 stage 3: the x509 GSI-trust strings, owned here so root://
     * and gridftp spell them with the bare names (brix_certificate,
     * brix_certificate_key, brix_trusted_ca, brix_vomsdir, brix_voms_cert_dir).
     * These are NOT preamble fields — root and gridftp each read them from their
     * own struct (root: xcf->certificate…; gridftp: conf->certificate…), so
     * brix_stream_common_adopt_gsi() copies these values INTO those existing
     * fields at merge and every downstream reader (GSI SSL_CTX + trust-store
     * build, VOMS validation) is left untouched. */
    ngx_str_t    certificate;
    ngx_str_t    certificate_key;
    ngx_str_t    trusted_ca;
    ngx_str_t    vomsdir;
    ngx_str_t    voms_cert_dir;

    /* phase-101 W3 stage 3b: parsed-but-unfinalized brix_require_vo VO-ACL rules.
     * root and gridftp DEEP-COPY these into their own array and finalize the copy
     * against their own root_canon — never the shared pointer, so no plane
     * mutates another's resolved paths (a VO-ACL mis-resolution would be a silent
     * authz bug). */
    ngx_array_t *vo_rules;
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
void brix_stream_common_adopt(ngx_conf_t *cf, ngx_http_brix_shared_conf_t *dst);

/*
 * brix_stream_common_adopt_gsi() — copy the x509 GSI-trust strings from the
 * current server's common-module conf into the caller's own fields, filling
 * only those still UNSET (len == 0).  Each argument may be NULL to skip that
 * field.  Call from a stream protocol's merge_srv_conf BEFORE it inherits /
 * validates / builds from these paths, so the bare brix_certificate /
 * brix_trusted_ca / brix_vomsdir … land in the protocol's existing fields
 * exactly as its own directive used to.
 */
void brix_stream_common_adopt_gsi(ngx_conf_t *cf,
                                  ngx_str_t *certificate,
                                  ngx_str_t *certificate_key,
                                  ngx_str_t *trusted_ca,
                                  ngx_str_t *vomsdir,
                                  ngx_str_t *voms_cert_dir);

/*
 * brix_stream_common_adopt_vo_rules() — when *dst is empty, DEEP-COPY the common
 * module's parsed brix_require_vo rules into a fresh array at *dst (each rule's
 * .resolved is left empty for the caller to finalize against its own root_canon).
 * A no-op if the common owner has no rules or the caller already has its own.
 * Returns NGX_OK, or NGX_ERROR on allocation failure (the caller must fail the
 * config — silently dropping VO-ACL rules would weaken authorization).
 */
ngx_int_t brix_stream_common_adopt_vo_rules(ngx_conf_t *cf, ngx_array_t **dst);

#endif /* BRIX_STREAM_COMMON_H */
