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
    const char *name = "", *vorg = "", *role = "", *grp = "";
    char        host[BRIX_S3_HANDLER_HOST_BUF], path[BRIX_S3_HANDLER_PATH_BUF];
    size_t      n;
    ngx_int_t   rc;

    if (cf->common.acc.format != BRIX_AUTHDB_FORMAT_XRDACC) {
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

    /* Opt-in reverse DNS for `h <host>`/`h .domain` rules: a cache probe —
     * the PREACCESS wait (core/http/http_peer_name.c) fetched the answer. */
    if (cf->common.acc.resolve_hosts) {
        char  hbuf[BRIX_DNS_REVERSE_NAME_LEN];

        if (brix_acc_resolve_peer(cf->common.dns.policy,
                                  r->connection->sockaddr,
                                  r->connection->socklen,
                                  hbuf, sizeof(hbuf)) == NGX_OK)
        {
            n = ngx_min(ngx_strlen(hbuf), sizeof(host) - 1);
            ngx_memcpy(host, hbuf, n);
            host[n] = '\0';
        }
    }

    n = ngx_min(r->uri.len, sizeof(path) - 1);
    ngx_memcpy(path, r->uri.data, n);
    path[n] = '\0';

    rc = brix_acc_http_authorize(r->pool, r->connection->log,
                                   &cf->common.acc, name, host, vorg, role, grp,
                                   s3_method_aop(r), path);
    if (rc != NGX_ERROR) {
        return NGX_OK;
    }

    return s3_fail(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                   "xrdacc denied", BRIX_S3_EVENT_ACCESS_DENIED);
}
