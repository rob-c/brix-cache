/* auth_acc.c — the XrdAcc authorization tier for the S3 plane.
 * WHAT: Map an S3 method to an XrdAcc operation, then ask the acc engine
 * whether this identity may perform it on this URI.
 * WHY: Sits beside its auth siblings (auth_bearer.c, auth_sigv4_*.c) rather
 * than inside handler.c, which owns classification and dispatch and had grown
 * past the file-size contract carrying this gate as well.
 * HOW: Two entry points declared in s3_handler_internal.h; the deny path emits
 * the same XML error vocabulary every other S3 refusal uses.
 */

#include "s3.h"
#include "s3_handler_internal.h"

#include "auth/authz/acc/acc.h"

/* Map an S3 request method to the XrdAcc operation it requires. */
brix_acc_op_t
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

/* ---- Identify the body-addressed DeleteObjects operation ----
 *
 * WHAT: Returns non-zero only for POST ?delete on the configured bucket root,
 * either /bucket or /bucket/. Object-key POST requests always return zero.
 *
 * WHY: DeleteObjects cannot be authorized at the ordinary request gate because
 * its resources arrive later in XML. The exemption must be just as narrow as
 * the dispatcher route so an object-key query spelling cannot skip XrdAcc.
 *
 * HOW: Require POST and the parsed delete query flag, then byte-compare r->uri
 * with the two bucket-root spellings accepted by the path-style URI parser.
 */
ngx_flag_t
s3_is_delete_objects_request(ngx_http_request_t *r,
    const ngx_http_s3_loc_conf_t *cf)
{
    size_t root_len;

    if (r->method != NGX_HTTP_POST || !s3_has_query_flag(r, "delete")) {
        return 0;
    }

    if (cf->bucket.len > (size_t) -2) {
        return 0;
    }
    root_len = cf->bucket.len + 1;
    if (r->uri.len != root_len && r->uri.len != root_len + 1) {
        return 0;
    }
    if (r->uri.data[0] != '/') {
        return 0;
    }
    if (cf->bucket.len != 0
        && ngx_strncmp(r->uri.data + 1, cf->bucket.data, cf->bucket.len) != 0)
    {
        return 0;
    }
    return r->uri.len == root_len || r->uri.data[root_len] == '/';
}

/* ---- Authorize one exact S3 logical resource through XrdAcc ----
 *
 * WHAT: Returns NGX_OK when XrdAcc is not selected or grants `op` on `path`;
 * returns NGX_ERROR on denial. It never writes an HTTP response.
 *
 * WHY: Body- and header-addressed S3 operations need authorization after their
 * resource is decoded. Sharing the identity/peer construction with the request
 * gate prevents those late decisions from drifting in host or VO semantics.
 *
 * HOW: Build the same entity and peer tuple used by the request gate, replace
 * the peer with its cached reverse name when configured, and call the shared
 * XrdAcc HTTP decision engine with the caller's exact operation and path.
 */
ngx_int_t
s3_acc_authorize_path(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    brix_identity_t *id, brix_acc_op_t op, const char *path)
{
    const char *name = "", *vorg = "", *role = "", *grp = "";
    char        host[BRIX_S3_HANDLER_HOST_BUF];
    size_t      host_len;

    if (cf->common.acc.format != BRIX_AUTHDB_FORMAT_XRDACC) {
        return NGX_OK;
    }
    if (id != NULL) {
        name = brix_identity_dn_cstr(id);
        vorg = brix_identity_acc_vorg_cstr(id);
        role = brix_identity_acc_role_cstr(id);
        grp  = brix_identity_acc_group_cstr(id);
    }

    host_len = ngx_min(r->connection->addr_text.len, sizeof(host) - 1);
    ngx_memcpy(host, r->connection->addr_text.data, host_len);
    host[host_len] = '\0';

    if (cf->common.acc.resolve_hosts) {
        char reverse_name[BRIX_DNS_REVERSE_NAME_LEN];

        if (brix_acc_resolve_peer(cf->common.dns.policy,
                                  r->connection->sockaddr,
                                  r->connection->socklen,
                                  reverse_name, sizeof(reverse_name)) == NGX_OK)
        {
            host_len = ngx_min(ngx_strlen(reverse_name), sizeof(host) - 1);
            ngx_memcpy(host, reverse_name, host_len);
            host[host_len] = '\0';
        }
    }

    return brix_acc_http_authorize(r->pool, r->connection->log,
                                   &cf->common.acc, name, host, vorg, role, grp,
                                   op, path);
}

/*
 * s3_acc_check — XrdAcc tier for S3 (when `brix_acc_format xrdacc`).
 *
 * Returns NGX_OK when the request may proceed (allowed, or the engine is not
 * selected) — and, on a DENY, the result of the XML error it has already sent,
 * which is NGX_OK too.  The caller distinguishes them by r->header_sent, the
 * same contract s3_verify_sigv4 has; see the comment at the call site.
 *
 * Denying by RETURNING NGX_HTTP_FORBIDDEN, as this gate used to, is what every
 * other refusal in this module deliberately does not do: nginx then renders its
 * own 403 page, so the response carries no <Error><Code> at all.  An S3 client
 * reads the code, not the prose — boto3 raises ClientError off it, and the
 * multi-user oracle infers the deciding TIER from it — so a bodyless 403 is
 * indistinguishable from a proxy's, and this tier's verdict could not be told
 * apart from an authentication failure.  Every sibling gate (bearer, SigV4,
 * token scope, write-disabled, the resolver) answers with AccessDenied; this
 * one now does as well.
 */
ngx_int_t
s3_acc_check(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
             brix_identity_t *id)
{
    char        path[BRIX_S3_HANDLER_PATH_BUF];
    size_t      n;
    ngx_int_t   rc;

    if (cf->common.acc.format != BRIX_AUTHDB_FORMAT_XRDACC) {
        return NGX_OK;
    }

    /* The body parser performs one exact DELETE decision per resolved key
     * before the VFS batch. Authorizing the bucket URI here would either ask
     * for the wrong CREATE privilege or reject legitimate delete-only grants. */
    if (s3_is_delete_objects_request(r, cf)) {
        return NGX_OK;
    }

    n = ngx_min(r->uri.len, sizeof(path) - 1);
    ngx_memcpy(path, r->uri.data, n);
    path[n] = '\0';

    rc = s3_acc_authorize_path(r, cf, id, s3_method_aop(r), path);
    if (rc != NGX_ERROR) {
        return NGX_OK;
    }

    return s3_fail(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                   "xrdacc denied", BRIX_S3_EVENT_ACCESS_DENIED);
}
