/* cvmfs_module_internal.h — cross-file seam for the split cvmfs:// module glue.
 *
 * WHAT: Declares the handful of former-static entry points that the cvmfs
 *       module's directive table, config-merge orchestrator, and export-build
 *       step call across the translation units they were split into
 *       (module.c ↔ cvmfs_module_georank.c ↔ cvmfs_module_merge.c ↔
 *       cvmfs_module_build.c).
 * WHY:  module.c grew past the file-size gate, so its directive-parse callbacks,
 *       geographic origin ranking, config-field merge, and enabled-branch
 *       storage build were lifted into sibling files. Every symbol that is
 *       DEFINED in one of those files but CALLED from another must be a
 *       non-static, header-declared prototype — this header is that single
 *       shared declaration point. Nothing here is part of the public cvmfs://
 *       surface (that lives in cvmfs.h); these are module-internal seams only.
 * HOW:  Include after cvmfs.h (it supplies ngx_http_brix_cvmfs_loc_conf_t and
 *       the nginx config types). Each declaration names its defining file so a
 *       reader can jump straight to the implementation.
 */
#ifndef BRIX_CVMFS_MODULE_INTERNAL_H
#define BRIX_CVMFS_MODULE_INTERNAL_H

#include "cvmfs.h"

/* Defined in cvmfs_module_georank.c ------------------------------------------
 *
 * Directive-parse callbacks referenced by ngx_http_brix_cvmfs_commands[] in
 * module.c, plus the geo-ranking orchestrator invoked by the export build. */

/* brix_cvmfs_upstream_allow setter — appends EVERY argument to the allowlist. */
char *cvmfs_conf_upstream_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Defined in secure.c -------------------------------------------------------
 *
 * brix_cvmfs_repo_authz setter (phase-85 F3) — appends one <repo|*> <cfg>
 * gate entry; multi-occurrence. Registries are built at merge time. */
char *cvmfs_conf_repo_authz(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* brix_cvmfs_qos setter (phase-85 F9) — appends one <class> sub=<subject>|
 * default fills=<n> fill-rate class entry; multi-occurrence. */
char *cvmfs_conf_qos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Defined in virtual.c ------------------------------------------------------
 *
 * brix_cvmfs_virtual_repo setter (phase-87 G16) — appends one
 * <virtual-fqrn> <member-fqrn>... union entry; multi-occurrence; rejects
 * duplicate virtual names, duplicate members, and any nesting (a virtual
 * name appearing as a member). */
char *cvmfs_conf_virtual_repo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Defined in attest.c -------------------------------------------------------
 *
 * brix_cvmfs_attest setter (phase-87 G15) — loads the PEM signing private
 * key at config time (fail-fast: an attesting proxy with an unloadable key
 * must not start); cf->pool cleanup frees it on reload. */
char *cvmfs_conf_attest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* brix_cvmfs_origin_coords setter — one geographic origin position (multi). */
char *ngx_http_brix_cvmfs_set_coords(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* T19 geo mode: rank the configured origins once, at config time, by
 * great-circle distance from brix_cvmfs_here and record the ranks. Called from
 * the enabled-branch export build (cvmfs_module_build.c). */
char *cvmfs_geo_rank_config(ngx_conf_t *cf,
    ngx_http_brix_cvmfs_loc_conf_t *conf);

/* Defined in cvmfs_module_build.c --------------------------------------------
 *
 * The cvmfs-enabled export/backend/cache/tier build block, invoked by the merge
 * orchestrator only when the location has brix_cvmfs on. */
char *cvmfs_merge_cache(ngx_conf_t *cf, ngx_http_brix_cvmfs_loc_conf_t *conf);

/* Defined in cvmfs_module_merge.c --------------------------------------------
 *
 * Location merge orchestrator wired into ngx_http_brix_cvmfs_module_ctx. */
char *ngx_http_brix_cvmfs_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

/* Defined in handler.c -------------------------------------------------------
 *
 * Storage-instance resolution (convention #2: the T14 proxy-mode per-upstream
 * override on the request ctx wins, else the location's registered backend).
 * Shared with the phase-87 G2 bundle endpoint (bundle.c). */
brix_sd_instance_t *cvmfs_resolve_sd(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf);

/* Defined in handler_finalize.c ----------------------------------------------
 *
 * Request-finalization observer (sesslog close-out, client trace, T16 metric
 * accounting, G15 attest observe). handler.c registers it as the request's
 * pool cleanup; ngx_pool_cleanup_pt signature. */
void cvmfs_finalize_observe(void *data);

#endif /* BRIX_CVMFS_MODULE_INTERNAL_H */
