/*
 * rpm_gate.c — method policing, path classification, cache-key derivation.
 *
 * WHAT: the first step of every request on a brix_rpm_mirror location.
 *       Refuses write-class methods (a pull-through mirror is GET/HEAD only),
 *       classifies the URI through the shared grammar kernel, and copies the
 *       URI into the request's canonical cache key.
 * WHY:  the classifier verdict is what every later decision reads — the
 *       freshness window (mutable vs immutable), the metric row, and whether
 *       the cache tier's rpm-repodata verify has a digest to check — so it
 *       must be computed exactly once, at the edge, on the only bytes the
 *       client controls. Refusing a write here is the same discipline the OCI
 *       mirror applies: a PUT that quietly 200s at a mirror is an operator
 *       believing a package was published that nothing holds.
 * HOW:  an early-return ladder. NGX_DECLINED means "a routable object" and is
 *       the only non-terminal verdict; everything else is an HTTP status the
 *       caller returns unchanged (the core paints the body).
 */

#include "rpm.h"

#include "core/http/http_headers.h"
#include "protocols/shared/guard_audit_http.h"

/* A write-class method aimed at a read-only mirror: the spec-shaped 405 +
 * Allow for the client, and one audit line for the operator's jail. */
static ngx_int_t
rpm_refuse_write(ngx_http_request_t *r, ngx_http_brix_rpm_ctx_t *ctx)
{
    ctx->disp = BRIX_RPM_OUT_REFUSED;

    brix_http_guard_audit(r, "rpm", GUARD_R_RPMWRITE, GUARD_OP_WRITE,
                          NGX_HTTP_NOT_ALLOWED);

    if (brix_http_set_header(r, "Allow", "GET, HEAD", NULL) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return NGX_HTTP_NOT_ALLOWED;
}


/* Classifier refusal → HTTP status. A path this grammar will not accept is a
 * malformed request, not a missing file: answering 404 would tell a traversal
 * probe that its shape was legal and only the target was absent. */
static ngx_uint_t
rpm_bad_status(brix_rpm_err_t err)
{
    return (err == BRIX_RPM_ERR_PATH_TOO_LONG)
           ? NGX_HTTP_REQUEST_URI_TOO_LARGE : NGX_HTTP_BAD_REQUEST;
}


ngx_int_t
brix_rpm_gate(ngx_http_request_t *r, ngx_http_brix_rpm_ctx_t *ctx)
{
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return rpm_refuse_write(r, ctx);
    }

    /* The URI is the key, so the cap is checked here rather than trusted:
     * classify() enforces the same bound, but the copy below must be safe on
     * its own terms — the two are one number (BRIX_RPM_KEY_MAX). */
    if (r->uri.len == 0 || r->uri.len >= sizeof(ctx->key)) {
        ctx->disp = BRIX_RPM_OUT_REFUSED;
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }
    ngx_memcpy(ctx->key, r->uri.data, r->uri.len);
    ctx->key[r->uri.len] = '\0';
    ctx->key_len         = r->uri.len;

    if (brix_rpm_classify(ctx->key, ctx->key_len, &ctx->req) != 0) {
        ctx->classified = 1;               /* BAD is a class, and it counts  */
        ctx->disp       = BRIX_RPM_OUT_REFUSED;
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "rpm: refusing \"%V\" - not a legal repository path", &r->uri);
        return (ngx_int_t) rpm_bad_status(ctx->req.err);
    }
    ctx->classified = 1;

    return NGX_DECLINED;
}
