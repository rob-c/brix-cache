/*
 * oci_gate.c — method policing, route classification, locally-answered routes.
 *
 * WHAT: the first step of every request on an brix_oci_mirror location.
 *       Refuses write-class methods (a pull-through mirror is GET/HEAD only),
 *       classifies the URI through the shared kernel, answers the two routes
 *       that never touch an upstream object store (`GET /v2/` and an upload
 *       session that cannot exist here), routes tags/list to the uncached
 *       passthrough, and lets manifests and blobs fall through to the cache.
 * WHY:  a mirror that quietly accepted a push would be a supply-chain hole
 *       with a 200 on it: `podman push` would report success, the operator
 *       would believe the image was published, and nothing would hold it.
 *       So the refusal is loud on three channels at once — the spec's 405 +
 *       Allow for the client, the UNSUPPORTED envelope for the tooling, and
 *       one GUARD_R_OCIPUSH audit line for the operator's fail2ban jail.
 *       Classifying here (once, at the edge) is the other half: everything
 *       downstream builds paths out of `name` and `reference`, and this is
 *       the only place those wire bytes are ever validated.
 * HOW:  early-return ladder over the classifier verdict. NGX_DECLINED means
 *       "a cacheable object route" — the handler's tier path takes it from
 *       there; every other return is terminal and has already written its
 *       response.
 */

#include "oci.h"
#include "oci_module_internal.h"

#include "core/http/http_headers.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"

/* The API-root probe body: an empty JSON object is what every conformant
 * registry answers, and what podman/docker use to decide a host speaks v2. */
static const u_char  oci_api_root_body[] = "{}";

/* Classifier verdict → HTTP status. NAME_UNKNOWN is the one 404 in the set:
 * the grammar was legal but named nothing this registry could route. */
static ngx_uint_t
oci_bad_status(brix_oci_err_t err)
{
    return (err == BRIX_OCI_ERR_NAME_UNKNOWN) ? NGX_HTTP_NOT_FOUND
                                              : NGX_HTTP_BAD_REQUEST;
}

/* Route → metric traffic class (INVARIANT #8: a fixed enum, never the name). */
static brix_oci_mclass_metric_e
oci_mclass_of(brix_oci_class_t cls)
{
    switch (cls) {
    case BRIX_OCI_REQ_API_ROOT:       return BRIX_OCI_MCLASS_API;
    case BRIX_OCI_REQ_MANIFEST:       return BRIX_OCI_MCLASS_MANIFEST;
    case BRIX_OCI_REQ_BLOB:           return BRIX_OCI_MCLASS_BLOB;
    case BRIX_OCI_REQ_UPLOAD_START:   return BRIX_OCI_MCLASS_UPLOAD;
    case BRIX_OCI_REQ_UPLOAD_SESSION: return BRIX_OCI_MCLASS_UPLOAD;
    case BRIX_OCI_REQ_TAGS_LIST:      return BRIX_OCI_MCLASS_TAGS;
    case BRIX_OCI_REQ_REFERRERS:      return BRIX_OCI_MCLASS_REFERRERS;
    default:                          return BRIX_OCI_MCLASS_BAD;
    }
}

/* A write-class method aimed at a read-only mirror. Three channels, one
 * event: the spec's 405 + Allow, the UNSUPPORTED envelope, and the audit
 * line the [brix-oci-push] jail bans on. */
static ngx_int_t
oci_refuse_push(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx)
{
    ctx->disp   = BRIX_OCI_OUT_REFUSED;
    ctx->mclass = BRIX_OCI_MCLASS_BAD;

    brix_oci_guard_emit(r, GUARD_R_OCIPUSH, GUARD_OP_WRITE,
                        NGX_HTTP_NOT_ALLOWED);

    if (brix_http_set_header(r, "Allow", "GET, HEAD", NULL) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return brix_oci_error(r, NGX_HTTP_NOT_ALLOWED, BRIX_OCI_ERR_UNSUPPORTED,
                          "this endpoint is a read-only pull-through mirror");
}

/* `GET /v2/` — answered here, with zero upstream traffic. The probe is what
 * every client issues before its first pull; forwarding it would multiply
 * one image pull into two upstream round-trips and, worse, would make the
 * mirror's own availability depend on the upstream being reachable. */
static ngx_int_t
oci_answer_api_root(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx)
{
    ctx->disp = BRIX_OCI_OUT_LOCAL;

    return brix_oci_send_body(r, NGX_HTTP_OK, "application/json",
                              oci_api_root_body,
                              sizeof(oci_api_root_body) - 1);
}

/* Validate and classify r->uri into ctx->req. NGX_OK, or a terminal rc whose
 * response has already been written. Shared by both surfaces: the grammar is
 * the same on the read and the write side, and two copies of it would be two
 * chances to disagree about what a legal repository name is.
 *
 * The spans in ctx->req point into `uri`, so it is the CALLER's buffer — a
 * classifier verdict does not outlive the storage it describes. */
static ngx_int_t
oci_classify_uri(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    char *uri, size_t uri_size)
{
    size_t  n;

    /* The classifier is a pure kernel over a NUL-terminated span; r->uri is
     * neither NUL-terminated nor bounded by our key cap. A URI that cannot
     * fit a legal route cannot BE a legal route. */
    if (r->uri.len >= uri_size) {
        ctx->disp   = BRIX_OCI_OUT_REFUSED;
        ctx->mclass = BRIX_OCI_MCLASS_BAD;
        return brix_oci_error(r, NGX_HTTP_REQUEST_URI_TOO_LARGE,
                              BRIX_OCI_ERR_NAME_INVALID, NULL);
    }
    n = r->uri.len;
    ngx_memcpy(uri, r->uri.data, n);
    uri[n] = '\0';

    if (brix_oci_classify(uri, n, &ctx->req) != 0) {
        ctx->classified = 1;
        ctx->mclass     = BRIX_OCI_MCLASS_BAD;
        ctx->disp       = BRIX_OCI_OUT_REFUSED;
        return brix_oci_error(r, oci_bad_status(ctx->req.err), ctx->req.err,
                              NULL);
    }
    ctx->classified = 1;
    ctx->mclass     = oci_mclass_of(ctx->req.cls);

    return NGX_OK;
}

ngx_int_t
brix_oci_gate(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    ngx_http_brix_oci_ctx_t *ctx)
{
    char       uri[BRIX_OCI_KEY_MAX];
    ngx_int_t  rc;

    /* GET/HEAD only. Everything else — PUT, POST, PATCH, DELETE and the
     * long tail — is a push attempt or a probe, and both get the same
     * answer. Ordering matters: police the METHOD before parsing the URI,
     * so a push at a malformed path is still audited as a push. */
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return oci_refuse_push(r, ctx);
    }

    rc = oci_classify_uri(r, ctx, uri, sizeof(uri));
    if (rc != NGX_OK) {
        return rc;
    }

    switch (ctx->req.cls) {

    case BRIX_OCI_REQ_API_ROOT:
        return oci_answer_api_root(r, ctx);

    case BRIX_OCI_REQ_TAGS_LIST:
    case BRIX_OCI_REQ_REFERRERS:
        /* Never cached: both are mutable listings whose staleness the client
         * cannot detect. Forwarded verbatim, pagination and filters and all.
         * Gated FIRST in delegate mode — a listing is exactly where a
         * private repository's metadata would otherwise leak (D16), and
         * ctx->req's name span is only alive inside this frame. */
        rc = brix_oci_delegate_gate(r, lcf, ctx);
        if (rc != NGX_DECLINED) {
            return rc;
        }
        return brix_oci_listing_passthrough(r, lcf, ctx);

    case BRIX_OCI_REQ_UPLOAD_START:
    case BRIX_OCI_REQ_UPLOAD_SESSION:
        /* A GET here is a client resuming an upload it believes it started.
         * On a mirror it never did — and saying "unknown session" is both
         * true and exactly what makes the client abandon cleanly instead of
         * retrying its PATCH loop against a surface that will 405 it. */
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        return brix_oci_error(r, NGX_HTTP_NOT_FOUND,
                              BRIX_OCI_ERR_BLOB_UPLOAD_UNKNOWN, NULL);

    case BRIX_OCI_REQ_MANIFEST:
    case BRIX_OCI_REQ_BLOB:
        break;                            /* the cacheable object routes */

    default:
        ctx->mclass = BRIX_OCI_MCLASS_BAD;
        ctx->disp   = BRIX_OCI_OUT_REFUSED;
        return brix_oci_error(r, NGX_HTTP_BAD_REQUEST,
                              BRIX_OCI_ERR_NAME_UNKNOWN, NULL);
    }

    rc = brix_oci_build_key(lcf, ctx);
    if (rc != NGX_OK) {
        ctx->disp = BRIX_OCI_OUT_REFUSED;
        return brix_oci_error(r, (ngx_uint_t) rc, BRIX_OCI_ERR_NAME_INVALID,
                              "canonical route exceeds the key cap");
    }
    ctx->keyed = 1;

    return NGX_DECLINED;
}


/* The registry surface's gate. Same grammar, no method refusal: here a POST
 * IS the point. The API root is still answered locally — a push client probes
 * `/v2/` exactly like a pull client does, and it must get the same answer
 * before it has any credential to present. */
ngx_int_t
brix_oci_registry_gate(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    char *uri, size_t uri_size)
{
    ngx_int_t  rc;

    rc = oci_classify_uri(r, ctx, uri, uri_size);
    if (rc != NGX_OK) {
        return rc;
    }
    if (ctx->req.cls == BRIX_OCI_REQ_API_ROOT) {
        return oci_answer_api_root(r, ctx);
    }
    return NGX_DECLINED;
}
