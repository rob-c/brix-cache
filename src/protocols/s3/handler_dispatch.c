/*
 * handler_dispatch.c — S3 post-auth dispatch: URI parsing, token-scope gate,
 * and the bucket/empty-key/list routing orchestrator.
 *
 * WHAT: Owns the S3 content handler's post-authentication routing. Parses the
 *   path-style URI (/<bucket>/<key>) into bucket + key, enforces the WLCG
 *   bearer-token scope over the requested path, and dispatches bucket-level
 *   (empty-key) and list operations. Object-key method routing lives in the
 *   sibling handler_object_route.c; the entry handler and auth gate live in
 *   handler.c.
 *
 * WHY: Split out of handler.c (976 lines) under the phase-79 500-line file-size
 *   cap. The URI parser and the after-auth dispatch tree form one cohesive
 *   concern — turning a raw request into (bucket, key) and steering it to the
 *   right family of handlers — distinct from the entry/auth concern (handler.c)
 *   and the object-method concern (handler_object_route.c).
 *
 * HOW: s3_dispatch_after_auth() is the orchestrator: parse URI, apply the
 *   token-scope gate, then branch to list / empty-key(bucket) / object routing.
 *   Each gate returns NGX_DECLINED to continue dispatch; any other value means a
 *   response was already sent and must be returned as-is (see the per-function
 *   doc blocks for that sentinel convention). s3_reject_write_disabled() and
 *   s3_read_body_metric() are shared with handler_object_route.c and so are
 *   non-static (declared in s3_handler_internal.h).
 */


#include "s3.h"
#include "s3_handler_internal.h"
#include "tagging.h"
#include "auth/impersonate/lifecycle.h"
#include "core/http/http_body.h"
#include "core/http/http_headers.h"
#include "core/http/http_query.h"
#include "protocols/shared/deleg_capture.h"
#include "fs/backend/sd.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "auth/authz/acc/acc.h"
#include "core/compat/alloc_guard.h"

/*
 *
 * WHAT: Parses the S3 request URI into bucket name and object key components. Supports
 *       path-style addressing (/<bucket>/<key>) and list requests (/<bucket>/?list-type=2).
 *       Performs URL decoding on the object key portion to handle encoded characters in paths.
 *       Returns 1 for success, 0 for malformed URI, -1 if bucket name doesn't match configured value.
 *
 * WHY: S3 clients use path-style URIs that must be parsed into bucket + key before any filesystem
 *       operations can proceed. The parser handles both object access (GET/PUT) and list requests
 *       uniformly — distinguishing between them happens later via s3_is_list_request(). */
/*
 * HOW: Advances past the leading '/' in the URI, then checks if the remaining prefix matches conf->bucket.len bytes. If bucket match succeeds, advances past '/' to extract the key portion which is URL-decoded via s3_urldecode(). Returns -1 on bucket mismatch (NoSuchBucket), 0 on malformed URI (InvalidURI), 1 on success.
 */
/*
 * Parse the request URI into bucket + key.
 *
 * Path-style: /<bucket>/<key>
 * List:       /<bucket>/?list-type=2[&prefix=...&delimiter=...&...]
 *
 * Returns:
 *   1  - success
 *   0  - malformed URI
 *  -1  - bucket name mismatch
 * */

static int
s3_parse_uri(ngx_http_request_t *r,
             ngx_http_s3_loc_conf_t *cf,
             u_char *key_out, size_t key_sz)
{
    const u_char *uri  = r->uri.data;
    size_t        ulen = r->uri.len;
    size_t        blen = cf->bucket.len;

    if (ulen == 0 || uri[0] != '/') {
        return 0;
    }

    uri++;
    ulen--;

    if (blen > 0) {
        if (ulen < blen || ngx_strncmp(uri, cf->bucket.data, blen) != 0) {
            return -1;
        }
        uri  += blen;
        ulen -= blen;

        if (ulen == 0) {
            /* /bucket with no trailing slash — valid, empty key (e.g. ListObjects) */
            key_out[0] = '\0';
            return 1;
        }
        if (uri[0] != '/') {
            return 0;
        }
        uri++;
        ulen--;
    }

    if (ulen == 0) {
        key_out[0] = '\0';
        return 1;
    }

    if (brix_http_urldecode(uri, ulen, (char *) key_out, key_sz,
            BRIX_URLDECODE_PLUS_TO_SPACE |
            BRIX_URLDECODE_REJECT_NUL) != BRIX_URLDECODE_OK)
    {
        return 0;
    }

    return 1;
}

/*
 * Parse the URI into key.  Returns NGX_DECLINED when key is valid and dispatch
 * may continue.  On a rejected URI the XML error response has already been
 * sent and the value the content handler must return is passed back.  The
 * continue outcome is a distinct sentinel (NGX_DECLINED, which no send path
 * produces) rather than NGX_OK because a fully-sent error body makes
 * ngx_http_output_filter() return NGX_OK — comparing the response rc against
 * NGX_OK would let dispatch fall through with an unwritten key after the
 * request was already answered.
 */
static ngx_int_t
s3_dispatch_parse_uri(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_uint_t method_slot, u_char *key, size_t key_cap)
{
    int parse_rc = s3_parse_uri(r, cf, key, key_cap);

    if (parse_rc == -1) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INVALID_URI]);
        return s3_metrics_return_method(
            r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_NOT_FOUND, "NoSuchBucket",
                              "The specified bucket does not exist."));
    }
    if (parse_rc == 0) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INVALID_URI]);
        return s3_metrics_return_method(
            r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "InvalidURI",
                              "Couldn't parse the specified URI."));
    }
    return NGX_DECLINED;
}

/*
 * Token-scope gate.  Returns NGX_DECLINED when the operation may proceed.  On
 * a scope deny the 403 response has already been sent and the value the
 * content handler must return is passed back (same sentinel convention as
 * s3_dispatch_parse_uri — the response rc itself is NGX_OK once the body is
 * flushed, so it must never gate dispatch).
 */
static ngx_int_t
s3_check_token_scope(ngx_http_request_t *r, ngx_http_s3_req_ctx_t *s3ctx,
    ngx_uint_t method_slot, const u_char *key)
{
    brix_acc_op_t aop;
    int           need_write;
    char          logical[PATH_MAX];

    if (s3ctx->identity == NULL
        || !(s3ctx->identity->auth_method & BRIX_AUTHN_TOKEN))
    {
        return NGX_DECLINED;
    }

    aop = s3_method_aop(r);
    need_write = (aop == BRIX_AOP_CREATE || aop == BRIX_AOP_DELETE);
    (void) ngx_snprintf((u_char *) logical, sizeof(logical), "/%s%Z",
                        (const char *) key);
    if (brix_identity_check_token_scope(s3ctx->identity, logical, need_write)
        == NGX_OK)
    {
        return NGX_DECLINED;
    }
    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_ACCESS_DENIED]);
    return s3_metrics_return_method(r, method_slot,
        s3_send_xml_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                          "token scope does not cover this object"));
}

ngx_int_t
s3_reject_write_disabled(ngx_http_request_t *r, ngx_uint_t method_slot)
{
    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_WRITE_DISABLED]);
    return s3_metrics_return_method(
        r, method_slot,
        s3_send_xml_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                          "Write access is disabled."));
}

ngx_int_t
s3_read_body_metric(ngx_http_request_t *r, ngx_uint_t method_slot,
    ngx_http_client_body_handler_pt handler)
{
    ngx_int_t rc;

    r->request_body_in_single_buf = 1;
    rc = brix_http_read_body(r, handler);
    return (rc == NGX_DONE) ? NGX_DONE : s3_metrics_return_method(r, method_slot, rc);
}

static ngx_int_t
s3_dispatch_empty_post(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_uint_t method_slot, ngx_flag_t is_post_object_form)
{
    if (r->method != NGX_HTTP_POST) {
        return NGX_DECLINED;
    }
    if (s3_has_query_flag(r, "delete")) {
        return cf->common.allow_write
               ? s3_read_body_metric(r, method_slot, s3_delete_objects_body_handler)
               : s3_reject_write_disabled(r, method_slot);
    }
    if (is_post_object_form) {
        return cf->common.allow_write
               ? s3_read_body_metric(r, method_slot, s3_post_object_body_handler)
               : s3_reject_write_disabled(r, method_slot);
    }
    return NGX_DECLINED;
}

static ngx_int_t
s3_dispatch_bucket_get(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_uint_t method_slot)
{
    if (s3_has_query_flag(r, "uploads")) {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_list_multipart_uploads(r, cf));
    }
    if (s3_has_query_flag(r, "location")) {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_get_bucket_location(r, cf));
    }
    if (s3_has_query_flag(r, "versioning")) {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_get_bucket_versioning(r));
    }
    if (s3_has_query_flag(r, "acl")) {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_get_acl(r, cf));
    }
    if (s3_has_query_flag(r, "cors")) {
        return s3_metrics_return_method(r, method_slot, s3_handle_get_cors(r));
    }
    return s3_metrics_return_method(r, method_slot, s3_handle_list_v1(r, cf));
}

static ngx_int_t
s3_dispatch_empty_key(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_uint_t method_slot, ngx_flag_t is_post_object_form)
{
    ngx_int_t rc;

    if (r->method == NGX_HTTP_GET) {
        return s3_dispatch_bucket_get(r, cf, method_slot);
    }
    rc = s3_dispatch_empty_post(r, cf, method_slot, is_post_object_form);
    if (rc != NGX_DECLINED) {
        return rc;
    }
    if (r->method == NGX_HTTP_HEAD) {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_head_bucket(r, cf));
    }
    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INVALID_URI]);
    return s3_metrics_return_method(
        r, method_slot,
        s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "InvalidURI",
                          "Missing object key."));
}

/*
 * Resolve key -> confined fs_path.  Returns NGX_DECLINED when dispatch may
 * continue.  On a confinement deny the 403 response has already been sent and
 * the value the content handler must return is passed back (same sentinel
 * convention as s3_dispatch_parse_uri).
 */
static ngx_int_t
s3_resolve_object_key(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_http_s3_req_ctx_t *s3ctx, ngx_uint_t method_slot, const u_char *key,
    char *fs_path, size_t fs_path_cap)
{
    if (s3_resolve_key(cf->common.root_canon, (const char *) key, fs_path,
                       fs_path_cap))
    {
        ngx_cpystrn((u_char *) s3ctx->fs_path, (u_char *) fs_path,
                    sizeof(s3ctx->fs_path));
        return NGX_DECLINED;
    }
    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_ACCESS_DENIED]);
    return s3_metrics_return_method(
        r, method_slot,
        s3_send_xml_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                          "Access Denied."));
}

/*
 * Post-auth S3 op dispatch (parse URI -> route by method).  Runs inside the
 * caller's impersonation bracket; see ngx_http_s3_handler.
 */
ngx_int_t
s3_dispatch_after_auth(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_http_s3_req_ctx_t *s3ctx, ngx_uint_t method_slot,
    int is_list_request, ngx_flag_t is_post_object_form)
{
    u_char    key[S3_MAX_KEY] = {0};
    char      fs_path[PATH_MAX];
    ngx_int_t rc;

    /* Each gate below returns NGX_DECLINED to continue dispatch; any other
     * value (including NGX_OK) means the response was already sent and must
     * be returned as-is — see s3_dispatch_parse_uri's doc block. */
    rc = s3_dispatch_parse_uri(r, cf, method_slot, key, sizeof(key));
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /*
     * WLCG bearer-token scope enforcement.
     *
     * When a request was authenticated via a bearer token, verify that the
     * token's scope covers the requested path and operation BEFORE dispatching
     * to any sub-handler.  Non-token requests (SigV4, anonymous) are allowed
     * unconditionally by brix_identity_check_token_scope (scopes only apply to
     * token auth).  Empty keys (bucket-level ops, list) map to logical path "/".
     */
    rc = s3_check_token_scope(r, s3ctx, method_slot, key);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    if (is_list_request) {
        return s3_metrics_return_method(r, method_slot, s3_handle_list(r, cf));
    }

    if (key[0] == '\0') {
        return s3_dispatch_empty_key(r, cf, method_slot, is_post_object_form);
    }

    rc = s3_resolve_object_key(r, cf, s3ctx, method_slot, key, fs_path,
                               sizeof(fs_path));
    if (rc != NGX_DECLINED) {
        return rc;
    }
    return s3_dispatch_object_method(r, cf, s3ctx, method_slot, key, fs_path);
}
