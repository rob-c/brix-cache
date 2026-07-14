/*
 * module_internal.h — cross-file declarations for the S3 nginx module glue.
 *
 * WHAT: Declares the per-concern location-merge helpers that are DEFINED in
 *   module_merge.c but REFERENCED from the merge orchestrator in module.c.
 *
 * WHY: The mechanical file-size split moved the merge helper cluster out of
 *   module.c into module_merge.c. The orchestrator (ngx_http_s3_merge_loc_conf,
 *   an nginx module-context callback that must stay in module.c) still calls
 *   these helpers, so they became non-static and need a shared declaration.
 *
 * HOW: Include AFTER "s3.h" (which defines ngx_http_s3_loc_conf_t and pulls in
 *   the nginx core headers). Include-guarded; declarations only.
 */
#ifndef BRIX_S3_MODULE_INTERNAL_H
#define BRIX_S3_MODULE_INTERNAL_H

/* Per-concern location-merge helpers (defined in module_merge.c). */
char *s3_merge_preamble(ngx_conf_t *cf, ngx_http_s3_loc_conf_t *prev,
    ngx_http_s3_loc_conf_t *conf);
void s3_merge_scalars(ngx_http_s3_loc_conf_t *prev,
    ngx_http_s3_loc_conf_t *conf);
char *s3_merge_token(ngx_conf_t *cf, ngx_http_s3_loc_conf_t *prev,
    ngx_http_s3_loc_conf_t *conf);
char *s3_merge_export(ngx_conf_t *cf, ngx_http_s3_loc_conf_t *conf);

#endif /* BRIX_S3_MODULE_INTERNAL_H */
