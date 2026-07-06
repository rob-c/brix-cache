/*
 * handler.c — S3 content handler: URI parsing, SigV4 auth gate, and method dispatch.
 *
 * WHAT: The nginx HTTP content handler for all S3 REST API operations. Every S3 request
 *   enters here — it parses the path-style URI (/<bucket>/<key>), verifies the AWS
 *   SigV4 signature, resolves the key to a filesystem path, and dispatches to the
 *   appropriate method handler (GetObject, PutObject, DeleteObject, ListObjectsV2, etc.).
 *
 * WHY: S3 clients use path-style URIs that must be parsed into bucket + key before any
 *   filesystem operations. The SigV4 auth gate rejects unsigned requests early without
 *   parsing overhead. Write operations check cf->common.allow_write before body read to reject
 *   writes on read-only endpoints without consuming client bandwidth.
 *
 * HOW:
 *   1. Check cf->common.enable → NGX_DECLINED if disabled
 *   2. Determine method_slot (list vs object) + track bytes_rx metric per IP version
 *   3. Verify SigV4 signature — fail fast with XML error on invalid
 *   4. Parse URI into bucket+key via s3_parse_uri()
 *   5. Dispatch list requests (ListObjectsV2, ListMultipartUploads, ListParts)
 *   6. Check special empty-key flags (uploads → InitiateMPU, delete → DeleteObjects)
 *   7. Reject bare GET /<bucket>/? (empty key without flag) as InvalidURI
 *   8. Resolve key to fs_path via s3_resolve_key() — AccessDenied on escape
 *   9. Dispatch by HTTP method: GET/HEAD/PUT/DELETE/POST → specific handler
 *   10. Unknown methods → 405 Method Not Allowed
 *
 * Pool allocation: path_copy uses ngx_pnalloc(r->pool, PATH_MAX) to survive until the
 *   async PUT/MPU-complete callback fires after body reading completes.
 */


#include "s3.h"
#include "tagging.h"
#include "auth/impersonate/lifecycle.h"
#include "core/http/http_body.h"
#include "core/http/http_headers.h"
#include "core/http/http_query.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "auth/authz/acc/acc.h"
#include "core/compat/alloc_guard.h"

/* Map an S3 request method to the XrdAcc operation it requires. */
static brix_acc_op_t
s3_method_aop(ngx_http_request_t *r)
{
    switch (r->method) {
    case NGX_HTTP_GET:    return BRIX_AOP_READ;    /* GetObject / ListObjects */
    case NGX_HTTP_HEAD:   return BRIX_AOP_STAT;
    case NGX_HTTP_PUT:    return BRIX_AOP_CREATE;
    case NGX_HTTP_POST:   return BRIX_AOP_CREATE;  /* multipart upload */
    case NGX_HTTP_DELETE: return BRIX_AOP_DELETE;
    default:              return BRIX_AOP_STAT;
    }
}

/*
 * s3_acc_check — XrdAcc tier for S3 (when `brix_authdb_format xrdacc`).
 * Returns NGX_OK (allow / not selected) or NGX_HTTP_FORBIDDEN (deny).
 */
static ngx_int_t
s3_acc_check(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
             brix_identity_t *id)
{
    const char *name = "", *vorg = "", *role = "", *grp = "";
    char        host[64], path[1024];
    size_t      n;
    ngx_int_t   rc;

    if (cf->acc.format != BRIX_AUTHDB_FORMAT_XRDACC) {
        return NGX_OK;
    }
    if (id != NULL) {
        name = brix_identity_dn_cstr(id);     /* S3 access key (or subject) */
        vorg = brix_identity_acc_vorg_cstr(id);
        role = brix_identity_acc_role_cstr(id);
        grp  = brix_identity_acc_group_cstr(id);
    }
    n = ngx_min(r->connection->addr_text.len, sizeof(host) - 1);
    ngx_memcpy(host, r->connection->addr_text.data, n);
    host[n] = '\0';

    /* Opt-in reverse DNS for `h <host>`/`h .domain` rules (per request). */
    if (cf->acc.resolve_hosts) {
        char        hbuf[256];
        const char *h = brix_acc_resolve_peer(r->connection->sockaddr,
                                                r->connection->socklen,
                                                hbuf, sizeof(hbuf));
        if (h != NULL) {
            n = ngx_min(ngx_strlen(h), sizeof(host) - 1);
            ngx_memcpy(host, h, n);
            host[n] = '\0';
        }
    }

    n = ngx_min(r->uri.len, sizeof(path) - 1);
    ngx_memcpy(path, r->uri.data, n);
    path[n] = '\0';

    rc = brix_acc_http_authorize(r->pool, r->connection->log,
                                   &cf->acc, name, host, vorg, role, grp,
                                   s3_method_aop(r), path);
    return (rc == NGX_ERROR) ? NGX_HTTP_FORBIDDEN : NGX_OK;
}

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
 *
 * WHAT: Detects whether the HTTP request is a ListObjectsV2 operation by searching for the
 *       "list-type=2" query parameter in the request args. Returns 1 if found, 0 otherwise.
 *       Only checks GET requests with non-empty query arguments — other methods cannot be lists.
 *
 * WHY: ListObjectsV2 has fundamentally different filesystem behavior from GetObject (it returns XML
 *       listing of objects rather than serving a single file). This detection allows the main handler
 *       to dispatch to separate metrics slots and distinct handler functions for list vs object operations. */
/*
 * HOW: Checks that r->method is GET and reads the exact list-type query
 * parameter with the shared query parser. Returns 1 only when list-type=2.
 */
static int
s3_is_list_request(ngx_http_request_t *r)
{
    char list_type[8];

    if (r->method != NGX_HTTP_GET || r->args.len == 0) {
        return 0;
    }

    return brix_http_query_get(r->args, "list-type", list_type,
                                 sizeof(list_type), 0) > 0
           && ngx_strcmp(list_type, "2") == 0;
}

static ngx_flag_t
s3_is_post_object_form(ngx_http_request_t *r)
{
    ngx_table_elt_t *ct;

    if (r->method != NGX_HTTP_POST || r->args.len != 0) {
        return 0;
    }

    ct = brix_http_find_header(r, "Content-Type",
                                 sizeof("Content-Type") - 1);
    if (ct == NULL || ct->value.len < sizeof("multipart/form-data") - 1) {
        return 0;
    }

    return ngx_strncasecmp(ct->value.data, (u_char *) "multipart/form-data",
                           sizeof("multipart/form-data") - 1) == 0;
}

static ngx_uint_t
s3_allow_flags(ngx_http_s3_loc_conf_t *cf)
{
    ngx_uint_t flags;

    flags = BRIX_PROTO_OP_READ | BRIX_PROTO_OP_LIST;
    if (cf->common.allow_write) {
        flags |= BRIX_PROTO_OP_WRITE | BRIX_PROTO_OP_ASYNC_BODY;
    }

    return flags;
}

static ngx_int_t
s3_add_preflight_headers(ngx_http_request_t *r, const ngx_str_t *allow)
{
    ngx_table_elt_t *origin;
    ngx_table_elt_t *req_headers;

    origin = brix_http_find_header(r, "Origin", sizeof("Origin") - 1);
    if (origin == NULL) {
        return NGX_OK;
    }

    if (brix_http_set_header(r, "Access-Control-Allow-Origin", "*", NULL)
        != NGX_OK
        || brix_http_set_header(r, "Vary", "Origin", NULL) != NGX_OK
        || brix_http_set_header_str(r, "Access-Control-Allow-Methods",
                                      allow, 0, NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    req_headers = brix_http_find_header(
        r, "Access-Control-Request-Headers",
        sizeof("Access-Control-Request-Headers") - 1);
    if (req_headers != NULL
        && !brix_http_str_has_ctl(req_headers->value.data,
                                    req_headers->value.len))
    {
        if (brix_http_set_header_str(r, "Access-Control-Allow-Headers",
                                       &req_headers->value, 0, NULL) != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else if (brix_http_set_header(r, "Access-Control-Allow-Headers",
                                      "Authorization, Content-Type, "
                                      "Content-Length, Content-MD5, "
                                      "x-amz-content-sha256, x-amz-date, "
                                      "x-amz-security-token, x-amz-copy-source, "
                                      "x-amz-checksum-crc64nvme, "
                                      "x-amz-checksum-algorithm, "
                                      "x-amz-sdk-checksum-algorithm, "
                                      "Range",
                                      NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return brix_http_set_header(r, "Access-Control-Max-Age", "86400", NULL);
}

static ngx_int_t
s3_handle_options(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf)
{
    ngx_table_elt_t *h;
    ngx_str_t        allow;

    if (brix_http_operation_allow_header(r->pool,
            brix_s3_operations, brix_s3_operations_count,
            s3_allow_flags(cf), &allow) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Allow");
    h->value = allow;

    if (s3_add_preflight_headers(r, &allow) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/*
 * Main content handler - auth gate + method dispatch
 * */

/*
 * ngx_http_s3_handler - nginx HTTP content handler for the S3 API.
 *
 * Implements the AWS S3 path-style API subset needed by XrdClS3 and other
 * HEP data transfer tools.  Dispatch order:
 *
 *   1. Parse the URI into bucket + key using s3_parse_uri().
 *   2. Verify AWS SigV4 signature (s3_verify_sigv4).
 *   3. ListObjectsV2          (GET /<bucket>/?list-type=2) -> s3_handle_list().
 *   4. ListMultipartUploads   (GET /<bucket>/?uploads)     -> s3_handle_list_multipart_uploads().
 *   5. ListParts              (GET /<bucket>/<key>?uploadId=<id>) -> s3_handle_list_parts().
 *   6. GetObject              (GET    /<bucket>/<key>) -> s3_handle_get().
 *   7. HeadObject             (HEAD   /<bucket>/<key>) -> s3_handle_head().
 *   8. PutObject / UploadPart (PUT    /<bucket>/<key>) -> s3_put_body_handler().
 *   9. DeleteObject / Abort   (DELETE /<bucket>/<key>) -> s3_handle_delete().
 *  10. CompleteMultipartUpload (POST  /<bucket>/<key>?uploadId=<id>) -> s3_multipart_complete_body_handler().
 *  11. InitiateMultipartUpload (POST  /<bucket>/<key>?uploads) -> s3_handle_multipart_initiate().
 *
 * The fs_path (filesystem path within conf->common.root_canon) is resolved by
 * s3_resolve_key() and stored in r->pool for the async PUT callback.
 *
 * Pool allocation: path_copy uses ngx_pnalloc(r->pool, PATH_MAX) so it
 *   survives until the PUT body callback fires after body reading completes.
 */
/*
 * WHY: The dispatch order is critical — list requests are checked before object access to avoid treating empty-key GETs as invalid URIs. SigV4 verification happens early so unsigned requests fail fast without parsing overhead. Write operations (PUT/DELETE/POST) check cf->common.allow_write before body read to reject writes on read-only endpoints without consuming client bandwidth.
 *
 * HOW: Gets location config, returns NGX_DECLINED if disabled. Determines method_slot (list vs object). Tracks per-IP-version bytes_rx metric. Verifies SigV4 signature — fails with appropriate XML error if invalid. Parses URI into bucket+key via s3_parse_uri() — rejects mismatched bucket (-1) or malformed URI (0). Checks list-type=2, uploads flag, delete flag before empty-key rejection. Resolves key to fs_path via s3_resolve_key(). Dispatches by HTTP method: GET→list_parts/get; HEAD→head; PUT→upload_part_copy/copy_object/put_body; DELETE→multipart_abort/delete; POST→multipart_initiate/complete. Unknown methods → 405.
 */
static ngx_int_t s3_dispatch_after_auth(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, ngx_http_s3_req_ctx_t *s3ctx,
    ngx_uint_t method_slot, int is_list_request,
    ngx_flag_t is_post_object_form);

ngx_int_t
ngx_http_s3_handler(ngx_http_request_t *r)
{
    ngx_http_s3_loc_conf_t *cf;
    ngx_int_t               rc;
    int                     is_list_request;
    ngx_flag_t              is_post_object_form;
    ngx_uint_t              method_slot;
    ngx_http_s3_req_ctx_t  *s3ctx;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    if (!cf->common.enable) {
        return NGX_DECLINED;
    }

    /* AGPL-3.0 sec.13: offer remote users the source (X-Source header). */
    brix_http_source_offer(r);

    BRIX_PCALLOC_OR_RETURN(s3ctx, r->pool, sizeof(*s3ctx), NGX_HTTP_INTERNAL_SERVER_ERROR);
    s3ctx->identity = brix_identity_alloc(r->pool);
    if (s3ctx->identity == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_set_ctx(r, s3ctx, ngx_http_brix_s3_module);

    /*
     * ListObjectsV2 is an HTTP GET on the wire, but it has very different
     * filesystem behavior from GetObject, so it gets a separate metrics slot.
     */
    is_list_request = s3_is_list_request(r);
    is_post_object_form = s3_is_post_object_form(r);
    method_slot = is_list_request ? BRIX_S3_METHOD_LIST
                                  : s3_metrics_method_slot(r);
    s3_metrics_request_method(method_slot);


    if (r->method == NGX_HTTP_OPTIONS) {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_options(r, cf));
    }

    if (!is_post_object_form) {
        rc = s3_verify_sigv4(r, cf, s3ctx->identity);
        if (rc != NGX_OK) {
            return s3_metrics_return_method(r, method_slot, rc);
        }
    }

    /* XrdAcc engine (when brix_authdb_format xrdacc) */    rc = s3_acc_check(r, cf, s3ctx->identity);
    if (rc != NGX_OK) {
        return s3_metrics_return_method(r, method_slot, rc);
    }

    /*
     * An auth gate that rejected the request by emitting its OWN XML error body
     * (e.g. s3_verify_sigv4's "Missing/Malformed Authorization") returns NGX_OK
     * but leaves r->header_sent set. Continuing to dispatch would let GetObject
     * call ngx_http_send_header a second time ("header already sent" alert) and
     * overwrite the sent 4xx with headers_out.status = 200 — hiding the auth
     * failure from the LOG phase (metrics AND the bad-actor guard). Stop here so
     * the already-sent status stands.
     */
    if (r->header_sent) {
        return s3_metrics_return_method(r, method_slot, NGX_OK);
    }

    /*
     * SciTags packet marking (phase-34).  S3 has no TPC, so only plain
     * GET/PUT are marked, and only when brix_pmark_http_plain is on.
     * Begun here post-SigV4; ended via a request-pool cleanup.
     */
    if (cf->common.pmark.enable && cf->common.pmark.http_plain
        && (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_PUT))
    {
        u_char pth[2048], cgi[512];
        ngx_cpystrn(pth, r->uri.data, ngx_min(r->uri.len + 1, sizeof(pth)));
        if (r->args.len) {
            ngx_cpystrn(cgi, r->args.data, ngx_min(r->args.len + 1, sizeof(cgi)));
        } else {
            cgi[0] = '\0';
        }
        brix_pmark_http_mark(&cf->common.pmark, r->pool, r->connection,
            (r->method == NGX_HTTP_PUT),
            brix_identity_vo_csv_cstr(s3ctx->identity),
            brix_identity_dn_cstr(s3ctx->identity),
            (const char *) pth, (const char *) cgi);
    }

    /*
     * Phase 40: bracket the whole post-auth dispatch with the impersonation
     * principal (now that auth has populated s3ctx->identity).  This covers the
     * SYNCHRONOUS ops (GET/HEAD/DELETE/list/multipart-initiate) — which open /
     * stat / unlink as the mapped user, so e.g. a GetObject cannot read a file
     * the mapped user has no UNIX permission for (a cross-tenant leak when run as
     * the worker).  The async body handlers (PUT/POST/multipart-complete/
     * delete-objects) return NGX_DONE and re-establish the principal in their own
     * callbacks, so clearing it here on return is correct.  No-op unless map mode.
     */
    brix_imp_request_begin(s3ctx->identity);
    rc = s3_dispatch_after_auth(r, cf, s3ctx, method_slot,
                                is_list_request, is_post_object_form);
    brix_imp_request_end();
    return rc;
}

/*
 * Post-auth S3 op dispatch (parse URI -> route by method).  Runs inside the
 * caller's impersonation bracket; see ngx_http_s3_handler.
 */
static ngx_int_t
s3_dispatch_after_auth(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    ngx_http_s3_req_ctx_t *s3ctx, ngx_uint_t method_slot,
    int is_list_request, ngx_flag_t is_post_object_form)
{
    u_char    key[S3_MAX_KEY];
    char      fs_path[PATH_MAX];
    ngx_int_t rc;

    {
        int parse_rc = s3_parse_uri(r, cf, key, sizeof(key));
        if (parse_rc == -1) {
            BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INVALID_URI]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_NOT_FOUND,
                                  "NoSuchBucket",
                                  "The specified bucket does not exist."));
        }
        if (parse_rc == 0) {
            BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INVALID_URI]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                  "InvalidURI",
                                  "Couldn't parse the specified URI."));
        }
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
    if (s3ctx->identity != NULL
        && (s3ctx->identity->auth_method & BRIX_AUTHN_TOKEN))
    {
        brix_acc_op_t aop        = s3_method_aop(r);
        int           need_write = (aop == BRIX_AOP_CREATE
                                    || aop == BRIX_AOP_DELETE);
        char          logical[PATH_MAX];
        u_char       *end;

        end = ngx_snprintf((u_char *) logical, sizeof(logical),
                           "/%s%Z", (const char *) key);
        (void) end;

        if (brix_identity_check_token_scope(s3ctx->identity, logical, need_write)
            != NGX_OK)
        {
            BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_ACCESS_DENIED]);
            return s3_metrics_return_method(r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                                  "token scope does not cover this object"));
        }
    }

    if (is_list_request) {
        return s3_metrics_return_method(r, method_slot, s3_handle_list(r, cf));
    }

    /*
     * ListMultipartUploads: GET /<bucket>/?uploads  (empty key, flag present)
     * Must be checked before the empty-key rejection below.
     */
    if (r->method == NGX_HTTP_GET
        && key[0] == '\0'
        && s3_has_query_flag(r, "uploads"))
    {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_list_multipart_uploads(r, cf));
    }

    /*
     * DeleteObjects: POST /<bucket>/?delete  (empty key, flag present)
     * Must be checked before the empty-key rejection below.
     */
    if (r->method == NGX_HTTP_POST
        && key[0] == '\0'
        && s3_has_query_flag(r, "delete"))
    {
        if (!cf->common.allow_write) {
            BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_WRITE_DISABLED]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                  "AccessDenied",
                                  "Write access is disabled."));
        }
        r->request_body_in_single_buf = 1;
        rc = brix_http_read_body(r, s3_delete_objects_body_handler);
        if (rc != NGX_DONE) {
            return s3_metrics_return_method(r, method_slot, rc);
        }
        return NGX_DONE;
    }

    /*
     * POST Object: browser form upload to /<bucket>/ with multipart/form-data.
     * The authentication material, when configured, is carried in the form's
     * policy/signature fields rather than in the HTTP Authorization header.
     */
    if (r->method == NGX_HTTP_POST && key[0] == '\0' && is_post_object_form) {
        if (!cf->common.allow_write) {
            BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_WRITE_DISABLED]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                  "AccessDenied",
                                  "Write access is disabled."));
        }

        r->request_body_in_single_buf = 1;
        rc = brix_http_read_body(r, s3_post_object_body_handler);
        if (rc != NGX_DONE) {
            return s3_metrics_return_method(r, method_slot, rc);
        }
        return NGX_DONE;
    }

    /*
     * HeadBucket: HEAD /<bucket> (empty key).  SDK clients probe this at session
     * start; answer 200 + region rather than the empty-key InvalidURI below.
     */
    if (r->method == NGX_HTTP_HEAD && key[0] == '\0') {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_head_bucket(r, cf));
    }

    /*
     * Bucket-level GET (empty key).  ListObjectsV2 (list-type=2) and
     * ListMultipartUploads (?uploads) were already routed above; here we route
     * the GetBucketLocation subresource probe and otherwise fall back to the
     * original ListObjects (V1), which older tooling and Rucio still use.
     */
    if (r->method == NGX_HTTP_GET && key[0] == '\0') {
        if (s3_has_query_flag(r, "location")) {
            return s3_metrics_return_method(
                r, method_slot, s3_handle_get_bucket_location(r, cf));
        }
        if (s3_has_query_flag(r, "versioning")) {
            return s3_metrics_return_method(
                r, method_slot, s3_handle_get_bucket_versioning(r));
        }
        if (s3_has_query_flag(r, "acl")) {
            return s3_metrics_return_method(
                r, method_slot, s3_handle_get_acl(r, cf));
        }
        if (s3_has_query_flag(r, "cors")) {
            return s3_metrics_return_method(
                r, method_slot, s3_handle_get_cors(r));
        }
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_list_v1(r, cf));
    }

    if (key[0] == '\0') {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INVALID_URI]);
        return s3_metrics_return_method(
            r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                              "InvalidURI", "Missing object key."));
    }

    if (!s3_resolve_key(cf->common.root_canon,
                        (const char *) key,
                        fs_path, sizeof(fs_path))) {
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_ACCESS_DENIED]);
        return s3_metrics_return_method(
            r, method_slot,
            s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                              "AccessDenied", "Access Denied."));
    }
    ngx_cpystrn((u_char *) s3ctx->fs_path, (u_char *) fs_path,
                sizeof(s3ctx->fs_path));

    if (r->method == NGX_HTTP_GET) {
        char list_parts_upload_id[128];

        if (s3_has_query_flag(r, "tagging")) {
            return s3_metrics_return_method(r, method_slot,
                s3_handle_get_object_tagging(r, fs_path, cf));
        }
        if (s3_has_query_flag(r, "acl")) {
            return s3_metrics_return_method(r, method_slot,
                s3_handle_get_acl(r, cf));
        }
        if (s3_get_query_param(r, "uploadId",
                               list_parts_upload_id,
                               sizeof(list_parts_upload_id)))
        {
            return s3_metrics_return_method(
                r, method_slot,
                s3_handle_list_parts(r, fs_path, cf, (const char *) key));
        }
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_get(r, fs_path, cf));
    }

    if (r->method == NGX_HTTP_HEAD) {
        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_head(r, fs_path, cf));
    }

    if (r->method == NGX_HTTP_PUT) {
        if (!cf->common.allow_write) {
            BRIX_S3_METRIC_INC(
                events_total[BRIX_S3_EVENT_WRITE_DISABLED]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                  "AccessDenied",
                                  "Write access is disabled."));
        }

        /* PutObjectTagging: PUT /key?tagging (XML body). */
        if (s3_has_query_flag(r, "tagging")) {
            r->request_body_in_single_buf = 1;
            rc = brix_http_read_body(r, s3_put_object_tagging_body_handler);
            if (rc != NGX_DONE) {
                return s3_metrics_return_method(r, method_slot, rc);
            }
            return NGX_DONE;
        }
        /* Per-object ACL writes are not supported (authz is XrdAcc/tokens). */
        if (s3_has_query_flag(r, "acl")) {
            return s3_metrics_return_method(r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_NOT_IMPLEMENTED, "NotImplemented",
                    "Per-object ACLs are not supported by this gateway."));
        }

        /* Check for multipart UploadPart: PUT /key?partNumber=N&uploadId=ID */
        char upload_id[25];
        char part_num_str[8];
        if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id)) &&
            s3_get_query_param(r, "partNumber", part_num_str, sizeof(part_num_str)))
        {
            char *endptr;
            long part_num = strtol(part_num_str, &endptr, 10);
            if (*endptr != '\0' || part_num < 1 || part_num > 10000) {
                return s3_metrics_return_method(r, method_slot,
                    s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                      "InvalidArgument",
                                      "Part number must be an integer"
                                      " between 1 and 10000."));
            }
            if (!s3_has_query_flag(r, "uploads")) {
                const char *c;
                for (c = upload_id; *c != '\0'; c++) {
                    if (!((*c >= '0' && *c <= '9')
                          || (*c >= 'a' && *c <= 'f')))
                    {
                        return s3_metrics_return_method(r, method_slot,
                            s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST,
                                              "InvalidArgument",
                                              "The uploadId is invalid."));
                    }
                }
            }

            char    mpu_dir[PATH_MAX];
            u_char *p;

            /* UploadPartCopy: the handler re-derives the staging dir from the
             * DESTINATION KEY fs_path (s3_get_mpu_dir), so it must run BEFORE we
             * overwrite fs_path with the part-file path below.  Calling it after
             * the overwrite fed it the part path and made s3_get_mpu_dir compute
             * the wrong dir — UploadPartCopy always returned NoSuchUpload. */
            if (brix_http_find_header(r, "x-amz-copy-source",
                                        sizeof("x-amz-copy-source") - 1)
                != NULL)
            {
                return s3_metrics_return_method(r, method_slot,
                    s3_handle_upload_part_copy(r, fs_path, cf,
                                               upload_id, (int) part_num));
            }

            s3_get_mpu_dir(fs_path, upload_id, mpu_dir, sizeof(mpu_dir));
            /*
             * nginx's ngx_snprintf (ngx_sprintf) does NOT support the 'l'
             * length modifier.  Use %z (ssize_t/size_t) instead; on 64-bit
             * Linux long and ssize_t are the same width.
             */
            p = ngx_snprintf((u_char *)fs_path, PATH_MAX - 1,
                             "%s/part.%z", mpu_dir, (size_t) part_num);
            *p = '\0';
            /* Sync ctx so the async put body handler sees the part path. */
            ngx_cpystrn((u_char *) s3ctx->fs_path, (u_char *) fs_path,
                        sizeof(s3ctx->fs_path));
        }

        /* CopyObject: PUT /bucket/key  +  x-amz-copy-source (no uploadId) */
        if (brix_http_find_header(r, "x-amz-copy-source",
                                    sizeof("x-amz-copy-source") - 1) != NULL)
        {
            return s3_metrics_return_method(r, method_slot,
                                            s3_handle_copy_object(r, fs_path,
                                                                  cf));
        }

        /*
         * Conditional PutObject (If-None-Match: * create-if-absent / If-Match
         * overwrite-if-match), evaluated before the body is read.  Skipped for
         * UploadPart (conditional writes apply to whole objects only).
         */
        {
            char part_probe[8];
            if (!s3_get_query_param(r, "uploadId", part_probe,
                                    sizeof(part_probe)))
            {
                ngx_int_t prc = s3_put_precondition(r, cf->common.root_canon,
                                                    fs_path);
                if (prc != NGX_DECLINED) {
                    return s3_metrics_return_method(r, method_slot, prc);
                }
                /* W6b: If-None-Match:* asks for atomic create-if-absent — the
                 * commit (any of the 3 PUT body paths) uses an exclusive rename
                 * and maps a concurrent winner (EEXIST) to 412. */
                s3ctx->exclusive_create = s3_put_is_exclusive_create(r) ? 1 : 0;
            }
        }

        r->request_body_in_single_buf = 1;

        rc = brix_http_read_body(r, s3_put_body_handler);
        if (rc != NGX_DONE) {
            return s3_metrics_return_method(r, method_slot, rc);
        }
        return NGX_DONE;
    }

    if (r->method == NGX_HTTP_DELETE) {
        if (!cf->common.allow_write) {
            BRIX_S3_METRIC_INC(
                events_total[BRIX_S3_EVENT_WRITE_DISABLED]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                  "AccessDenied",
                                  "Write access is disabled."));
        }

        if (s3_has_query_flag(r, "tagging")) {
            return s3_metrics_return_method(r, method_slot,
                s3_handle_delete_object_tagging(r, fs_path, cf));
        }

        char upload_id[128];
        if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))) {
            return s3_metrics_return_method(r, method_slot,
                s3_handle_multipart_abort(r, fs_path, cf, upload_id));
        }

        return s3_metrics_return_method(r, method_slot,
                                        s3_handle_delete(r, fs_path, cf));
    }

    if (r->method == NGX_HTTP_POST) {
        if (!cf->common.allow_write) {
            BRIX_S3_METRIC_INC(
                events_total[BRIX_S3_EVENT_WRITE_DISABLED]);
            return s3_metrics_return_method(
                r, method_slot,
                s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                  "AccessDenied",
                                  "Write access is disabled."));
        }

        char upload_id[128];
        if (s3_has_query_flag(r, "uploads")) {
            return s3_metrics_return_method(r, method_slot,
                s3_handle_multipart_initiate(r, fs_path, cf, (const char *)key));
        } else if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))) {
            r->request_body_in_single_buf = 1;

            rc = brix_http_read_body(r, s3_multipart_complete_body_handler);
            if (rc != NGX_DONE) {
                return s3_metrics_return_method(r, method_slot, rc);
            }
            return NGX_DONE;
        }
    }

    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_METHOD_NOT_ALLOWED]);
    return s3_metrics_return_method(r, method_slot, NGX_HTTP_NOT_ALLOWED);
}
