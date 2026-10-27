/*
 * copy_internal.h - shared internal contract between the WebDAV COPY
 * orchestrator (copy.c) and the collection (directory) COPY machinery
 * (copy_collection.c).  Not part of the public webdav API.
 */

#ifndef BRIX_WEBDAV_COPY_INTERNAL_H
#define BRIX_WEBDAV_COPY_INTERNAL_H

#include "webdav.h"

/*
 * WHAT: The resolved, validated state of one COPY request: the confined source
 * and destination paths, their stat records, and the overwrite/depth flags plus
 * whether the destination already existed.
 *
 * WHY: The COPY handler's pre-flight (parse → resolve → validate) produces a
 * cluster of related values that the file and collection execute paths both
 * consume. Threading them as one struct keeps the orchestrator flat and each
 * pre-flight helper single-purpose, instead of a long function with a dozen
 * loose locals.
 *
 * HOW: Filled incrementally — webdav_copy_parse_request sets the flags and the
 * decoded destination, webdav_copy_resolve_pair fills the paths/stats/existed —
 * then read by the execute helpers. Zero-initialised at declaration.
 */
typedef struct {
    char         src_logical[WEBDAV_MAX_PATH];
    char         src_path[WEBDAV_MAX_PATH];
    char         dst_path[WEBDAV_MAX_PATH];
    char         dest_decoded[WEBDAV_MAX_PATH];
    struct stat  src_sb;
    struct stat  dst_sb;
    int          dst_existed;
    int          overwrite;
    int          depth_infinity;
} webdav_copy_req_t;

/* Request-bound authorization state copied into collection jobs. Logical and
 * resolved roots are stored by value so a synchronous guard never aliases the
 * handler stack and an unrestricted offload never carries dangling paths. */
typedef struct {
    ngx_http_request_t                    *r;
    ngx_http_brix_webdav_loc_conf_t       *conf;
    char                                   src_logical[WEBDAV_MAX_PATH];
    char                                   src_resolved[WEBDAV_MAX_PATH];
    char                                   dst_logical[WEBDAV_MAX_PATH];
    char                                   dst_resolved[WEBDAV_MAX_PATH];
} webdav_copy_authz_ctx_t;

ngx_int_t webdav_copy_probe(ngx_http_request_t *r, const char *path,
    struct stat *sb);
ngx_int_t webdav_copy_authorize(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *logical_path,
    const char *resolved_path, const char *operation, uint32_t needed_privs,
    brix_acc_op_t acc_op, int need_write);
void webdav_copy_authz_init(webdav_copy_authz_ctx_t *authz,
    ngx_http_request_t *r, ngx_http_brix_webdav_loc_conf_t *conf,
    const webdav_copy_req_t *req);
int webdav_copy_authz_has_effective_rules(const webdav_copy_authz_ctx_t *authz);
ngx_int_t webdav_copy_authorize_child(void *cookie, const char *src,
    const char *staged_dst, int is_dir);
ngx_int_t webdav_copy_authorize_delete(void *cookie, const char *path,
    int is_dir);

/*
 * Execute a collection (directory) COPY for a resolved request — offload to the
 * thread pool when possible, else run it inline.  Returns NGX_DONE when queued,
 * NGX_OK on inline success, or an HTTP error status.  Defined in
 * copy_collection.c.
 */
ngx_int_t
webdav_copy_do_collection(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const webdav_copy_req_t *req);

#endif /* BRIX_WEBDAV_COPY_INTERNAL_H */
