/*
 * handler_object_route.c — S3 object-key method routing.
 *
 * WHAT: Routes a resolved object request (/<bucket>/<key>) to the correct S3
 *   sub-handler by HTTP method — GetObject/ListParts/tagging/ACL (GET),
 *   HeadObject (HEAD), PutObject/UploadPart/UploadPartCopy/CopyObject/tagging
 *   (PUT), DeleteObject/AbortMultipartUpload/tagging (DELETE), and
 *   InitiateMultipartUpload/CompleteMultipartUpload (POST). Bucket-level and
 *   list routing live in the sibling handler_dispatch.c; the entry handler and
 *   auth gate live in handler.c.
 *
 * WHY: Split out of handler.c (976 lines) under the phase-79 500-line file-size
 *   cap. Object-key method routing — including the multipart upload-part
 *   preparation and PUT precondition checks — is a self-contained concern,
 *   distinct from URI-parse/bucket dispatch (handler_dispatch.c) and the
 *   entry/auth path (handler.c).
 *
 * HOW: s3_dispatch_object_method() branches on r->method to a per-method router.
 *   Write routers gate on cf->common.allow_write via the shared
 *   s3_reject_write_disabled() helper (in handler_dispatch.c, declared in
 *   s3_handler_internal.h) and stream request bodies through the shared
 *   s3_read_body_metric() helper. Each router returns the content-handler rc
 *   directly (responses are already framed by the sub-handlers).
 */


#include "s3.h"
#include "s3_handler_internal.h"
#include "tagging.h"
#include "auth/impersonate/lifecycle.h"
#include "core/http/http_body.h"
#include "core/http/http_headers.h"
#include "core/http/http_query.h"
#include "protocols/shared/deleg_capture.h"
#include "protocols/shared/backend_async_http.h"
#include "fs/backend/sd.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "auth/authz/acc/acc.h"
#include "core/compat/alloc_guard.h"

static int
s3_upload_id_is_hex(const char *upload_id)
{
    const char *c;

    for (c = upload_id; *c != '\0'; c++) {
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static ngx_int_t
s3_dispatch_object_get(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_uint_t method_slot, const u_char *key, char *fs_path)
{
    char upload_id[128];

    if (s3_has_query_flag(r, "tagging")) {
        return s3_metrics_return_method(r, method_slot,
            s3_handle_get_object_tagging(r, fs_path, cf));
    }
    if (s3_has_query_flag(r, "acl")) {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_get_acl(r, fs_path, cf));
    }
    if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))) {
        return s3_metrics_return_method(r, method_slot,
            s3_handle_list_parts(r, fs_path, cf, (const char *) key));
    }
    return s3_metrics_return_method(r, method_slot,
                                    s3_handle_get(r, fs_path, cf));
}

static ngx_int_t
s3_prepare_upload_part(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_http_s3_req_ctx_t *s3ctx, ngx_uint_t method_slot, char *fs_path)
{
    char upload_id[25];
    char part_num_str[8];
    char *endptr;
    long part_num;
    char mpu_dir[PATH_MAX];
    u_char *p;

    if (!s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))
        || !s3_get_query_param(r, "partNumber", part_num_str,
                               sizeof(part_num_str)))
    {
        return NGX_DECLINED;
    }
    part_num = strtol(part_num_str, &endptr, 10);
    if (*endptr != '\0' || part_num < 1 || part_num > 10000) {
        return s3_metrics_return_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                              "Part number must be an integer between 1 and 10000."));
    }
    if (!s3_has_query_flag(r, "uploads") && !s3_upload_id_is_hex(upload_id)) {
        return s3_metrics_return_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "InvalidArgument",
                              "The uploadId is invalid."));
    }
    if (brix_http_find_header(r, "x-amz-copy-source",
                              sizeof("x-amz-copy-source") - 1) != NULL)
    {
        return s3_metrics_return_method(r, method_slot,
            s3_handle_upload_part_copy(r, fs_path, cf, upload_id, (int) part_num));
    }

    s3_get_mpu_dir(fs_path, upload_id, mpu_dir, sizeof(mpu_dir));
    p = ngx_snprintf((u_char *) fs_path, PATH_MAX - 1, "%s/part.%z",
                     mpu_dir, (size_t) part_num);
    *p = '\0';
    ngx_cpystrn((u_char *) s3ctx->fs_path, (u_char *) fs_path,
                sizeof(s3ctx->fs_path));
    return NGX_OK;
}

static ngx_int_t
s3_apply_put_precondition(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_http_s3_req_ctx_t *s3ctx, ngx_uint_t method_slot, const char *fs_path)
{
    char part_probe[8];
    ngx_int_t rc;

    /* NGX_DECLINED = "no response sent, proceed to the PUT body"; any other rc
     * is a response already flushed (e.g. 412) that must gate dispatch — the
     * send itself returns NGX_OK, so the caller must key on NGX_DECLINED, not
     * NGX_OK (same sentinel convention as s3_dispatch_parse_uri). */
    if (s3_get_query_param(r, "uploadId", part_probe, sizeof(part_probe))) {
        return NGX_DECLINED;
    }
    rc = s3_put_precondition(r, cf->common.root_canon, fs_path);
    if (rc != NGX_DECLINED) {
        return s3_metrics_return_method(r, method_slot, rc);
    }
    s3ctx->exclusive_create = s3_put_is_exclusive_create(r) ? 1 : 0;
    return NGX_DECLINED;
}

static ngx_int_t
s3_dispatch_object_put(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_http_s3_req_ctx_t *s3ctx, ngx_uint_t method_slot, char *fs_path)
{
    ngx_int_t rc;

    if (!cf->common.allow_write) {
        return s3_reject_write_disabled(r, method_slot);
    }
    if (s3_has_query_flag(r, "tagging")) {
        return s3_read_body_metric(r, method_slot,
                                   s3_put_object_tagging_body_handler);
    }
    if (s3_has_query_flag(r, "acl")) {
        return s3_metrics_return_method(r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_NOT_IMPLEMENTED, "NotImplemented",
                "Per-object ACLs are not supported by this gateway."));
    }

    rc = s3_prepare_upload_part(r, cf, s3ctx, method_slot, fs_path);
    if (rc == NGX_DONE || (rc != NGX_OK && rc != NGX_DECLINED)) {
        return rc;
    }
    if (brix_http_find_header(r, "x-amz-copy-source",
                              sizeof("x-amz-copy-source") - 1) != NULL)
    {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_copy_object(r, fs_path, cf));
    }
    rc = s3_apply_put_precondition(r, cf, s3ctx, method_slot, fs_path);
    if (rc != NGX_DECLINED) {
        return rc;   /* precondition response already sent (e.g. 412) */
    }
    return s3_read_body_metric(r, method_slot, s3_put_body_handler);
}

/*
 * Async-queue wake for a deferred object DELETE: render the S3 response for the
 * batch's unlink result and finalise the request. ctx carries the method slot
 * (queue is protocol-agnostic; the slot is opaque to it). Runs on the event loop.
 */
static void
s3_delete_async_render(ngx_http_request_t *r, void *ctx, int op_errno)
{
    ngx_uint_t method_slot = (ngx_uint_t) (uintptr_t) ctx;

    s3_metrics_finalize_request_method(r, method_slot,
                                       s3_delete_respond(r, op_errno));
}

static ngx_int_t
s3_dispatch_object_delete(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_uint_t method_slot, char *fs_path)
{
    char upload_id[128];

    if (!cf->common.allow_write) {
        return s3_reject_write_disabled(r, method_slot);
    }
    if (s3_has_query_flag(r, "tagging")) {
        return s3_metrics_return_method(r, method_slot,
            s3_handle_delete_object_tagging(r, fs_path, cf));
    }
    if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))) {
        return s3_metrics_return_method(r, method_slot,
            s3_handle_multipart_abort(r, fs_path, cf, upload_id));
    }

    /* Async backend: enqueue the unlink and park the request until the batch
     * flushes (write gate already passed above). The queue drives the same
     * confined-VFS primitive the sync path does, so it takes the absolute
     * resolved `fs_path` as its key (exactly as the root:// plane passes its
     * `resolved`). NGX_DECLINED (async off / enqueue failure) falls through to
     * the inline unlink. */
    if (cf->common.backend_async) {
        ngx_int_t rc = brix_baq_http_try(r, &cf->common, BRIX_BAQ_UNLINK,
            cf->common.root_canon, fs_path, NULL, 0,
            s3_delete_async_render, (void *) (uintptr_t) method_slot);
        if (rc == NGX_DONE) {
            return NGX_DONE;
        }
    }

    return s3_metrics_return_method(r, method_slot,
                                    s3_handle_delete(r, fs_path, cf));
}

static ngx_int_t
s3_dispatch_object_post(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_uint_t method_slot, const u_char *key, char *fs_path)
{
    char upload_id[128];

    if (!cf->common.allow_write) {
        return s3_reject_write_disabled(r, method_slot);
    }
    if (s3_has_query_flag(r, "uploads")) {
        return s3_metrics_return_method(r, method_slot,
            s3_handle_multipart_initiate(r, fs_path, cf, (const char *) key));
    }
    if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))) {
        return s3_read_body_metric(r, method_slot,
                                   s3_multipart_complete_body_handler);
    }
    /* A bare POST to an object key (no ?uploads / ?uploadId, and not a
     * POST-object form — that path routes on the empty key earlier) has no S3
     * semantics: 405, not an unhandled NGX_DECLINED that would fall through. */
    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_METHOD_NOT_ALLOWED]);
    return s3_metrics_return_method(r, method_slot, NGX_HTTP_NOT_ALLOWED);
}

ngx_int_t
s3_dispatch_object_method(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_http_s3_req_ctx_t *s3ctx, ngx_uint_t method_slot, const u_char *key,
    char *fs_path)
{
    if (r->method == NGX_HTTP_GET) {
        return s3_dispatch_object_get(r, cf, method_slot, key, fs_path);
    }
    if (r->method == NGX_HTTP_HEAD) {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_head(r, fs_path, cf));
    }
    if (r->method == NGX_HTTP_PUT) {
        return s3_dispatch_object_put(r, cf, s3ctx, method_slot, fs_path);
    }
    if (r->method == NGX_HTTP_DELETE) {
        return s3_dispatch_object_delete(r, cf, method_slot, fs_path);
    }
    if (r->method == NGX_HTTP_POST) {
        return s3_dispatch_object_post(r, cf, method_slot, key, fs_path);
    }

    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_METHOD_NOT_ALLOWED]);
    return s3_metrics_return_method(r, method_slot, NGX_HTTP_NOT_ALLOWED);
}
