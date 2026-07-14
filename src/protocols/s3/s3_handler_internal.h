/*
 * s3_handler_internal.h — declarations shared across the S3 content-handler
 * files after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the handful of S3 content-handler functions that call
 *       across the three handler translation units (handler.c,
 *       handler_dispatch.c, handler_object_route.c). Everything else in those
 *       files stays file-local (static).
 * WHY:  handler.c (976 lines) split into three focused files under the 500-line
 *       cap: handler.c (entry handler + SigV4/XrdAcc auth gate + request
 *       classification + OPTIONS/CORS + delegation/pmark hooks),
 *       handler_dispatch.c (URI parse, token-scope gate, and the bucket/
 *       empty-key/list post-auth dispatch orchestrator), and
 *       handler_object_route.c (object-key method routing: GET/HEAD/PUT/DELETE/
 *       POST on /<bucket>/<key>). Exactly the five symbols below cross a file
 *       boundary and are therefore non-static and declared here — nothing else
 *       is exported beyond the S3 handler unit.
 * HOW:  All three handler .c files include this header; the declared symbols
 *       carry no linkage beyond the S3 handler translation units.
 *
 * Requires: s3.h (ngx_http_s3_loc_conf_t, ngx_http_s3_req_ctx_t, nginx request
 *           types) and auth/authz/acc/acc.h (brix_acc_op_t) are included here.
 */
#ifndef NGX_HTTP_S3_HANDLER_INTERNAL_H
#define NGX_HTTP_S3_HANDLER_INTERNAL_H

#include "s3.h"
#include "auth/authz/acc/acc.h"

/* Defined in handler.c. Maps an S3 request method to the XrdAcc operation it
 * requires. Shared by the XrdAcc gate (handler.c) and the WLCG token-scope gate
 * (handler_dispatch.c). Pure mapping, no side effects. */
brix_acc_op_t s3_method_aop(ngx_http_request_t *r);

/* Defined in handler_dispatch.c. Post-auth S3 op dispatch (parse URI -> route by
 * method); runs inside the caller's impersonation bracket. Called by the entry
 * handler (handler.c). */
ngx_int_t s3_dispatch_after_auth(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, ngx_http_s3_req_ctx_t *s3ctx,
    ngx_uint_t method_slot, int is_list_request,
    ngx_flag_t is_post_object_form);

/* Defined in handler_object_route.c. Routes a resolved object key by HTTP
 * method (GET/HEAD/PUT/DELETE/POST). Called by s3_dispatch_after_auth
 * (handler_dispatch.c). */
ngx_int_t s3_dispatch_object_method(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, ngx_http_s3_req_ctx_t *s3ctx,
    ngx_uint_t method_slot, const u_char *key, char *fs_path);

/* Defined in handler_dispatch.c. Emits the "Write access is disabled." 403 and
 * returns the content-handler rc. Shared by the write-op routers in
 * handler_object_route.c. */
ngx_int_t s3_reject_write_disabled(ngx_http_request_t *r,
    ngx_uint_t method_slot);

/* Defined in handler_dispatch.c. Reads the request body into a single buffer
 * and hands off to the given body handler, threading the method-slot metric.
 * Shared by the write-op routers in handler_object_route.c. */
ngx_int_t s3_read_body_metric(ngx_http_request_t *r, ngx_uint_t method_slot,
    ngx_http_client_body_handler_pt handler);

#endif /* NGX_HTTP_S3_HANDLER_INTERNAL_H */
