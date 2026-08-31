/*
 * authz_endpoint.c — the auth_request endpoint (phase-106 W4) and the
 * X-Accel-Redirect handoff (phase-106 W3).
 *
 * WHAT: Two content-phase behaviours for a location that brix gates but does
 *       not serve:
 *         brix_webdav_authz on            -> answer 204 + X-Brix-* identity
 *                                            headers, for nginx's auth_request
 *         brix_webdav_accel_redirect PFX  -> answer X-Accel-Redirect: PFX<uri>
 *                                            with no body, handing the request
 *                                            to an nginx `internal` location
 *
 * WHY:  brix owns a large authz corpus — WLCG tokens, VOMS FQANs, macaroons,
 *       GSI/X.509 chains, ZTN — and before this file NONE of it was reachable
 *       unless brix also served the bytes. Adoption was all-or-nothing. These
 *       two seams let an operator put brix's authorization in front of an
 *       existing nginx deployment and keep their own data path.
 *
 * HOW:  Neither behaviour performs a single authorization check of its own.
 *       nginx runs the ACCESS phase before the CONTENT phase, and webdav's
 *       access handler (access.c) has by then already run
 *       access_authenticate() plus the write-method, token-scope and XrdAcc
 *       gates — returning 401/403 itself on refusal. So reaching the content
 *       phase IS the verdict, and these handlers only REPORT it. That is the
 *       property that makes them safe: there is no second, weaker copy of the
 *       policy to drift out of step with the first.
 *
 *       SECURITY, the load-bearing points:
 *         - A refused request never reaches here at all, so neither seam can
 *           turn a denial into a serve.
 *         - X-Accel-Redirect is only honoured by nginx on a response from an
 *           upstream/handler, and the target MUST be an `internal` location.
 *           A client cannot inject it: request headers do not become response
 *           headers, and this handler builds the value itself from a
 *           CONFIGURED prefix — never from anything the client sent.
 *         - The X-Brix-* headers carry the SUBJECT of an identity (DN, VO,
 *           issuer, sub) and never the credential that proved it, so an
 *           operator copying them onward with auth_request_set cannot leak a
 *           bearer token or a proxy key.
 */
#include "authz_endpoint.h"
#include "webdav_module_internal.h"
#include "core/http/http_headers.h"


/*
 * webdav_authz_set_header — add one X-Brix-* response header.
 *
 * Skips an empty value entirely rather than emitting an empty header: an
 * absent header and an empty one are different things to auth_request_set,
 * and "no VO" should read as absent.
 */
static ngx_int_t
webdav_authz_set_header(ngx_http_request_t *r, const char *name,
    const ngx_str_t *value)
{
    ngx_table_elt_t *h;

    if (value == NULL || value->len == 0) {
        return NGX_OK;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    h->key.len = ngx_strlen(name);
    h->key.data = (u_char *) name;
    h->value = *value;
    return NGX_OK;
}


/*
 * webdav_authz_identity_headers — publish the authenticated SUBJECT.
 *
 * Only subject attributes: DN, VO, token issuer, token subject. Never the
 * bearer token, the macaroon, or the proxy key — an auth_request consumer
 * routinely copies these into an upstream request with auth_request_set, so a
 * credential here would be forwarded to a backend that has no business seeing
 * it.
 */
static ngx_int_t
webdav_authz_identity_headers(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    brix_identity_t *id;

    if (rx == NULL || rx->identity == NULL) {
        return NGX_OK;                    /* anonymous: no subject to report */
    }
    id = rx->identity;

    if (webdav_authz_set_header(r, "X-Brix-DN", &id->dn) != NGX_OK
        || webdav_authz_set_header(r, "X-Brix-Sub", &id->subject) != NGX_OK
        || webdav_authz_set_header(r, "X-Brix-Issuer", &id->issuer) != NGX_OK
        || webdav_authz_set_header(r, "X-Brix-VO", &id->vo_csv) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * webdav_authz_enforce — make sure the policy has actually run.
 *
 * SECURITY, load-bearing. nginx SKIPS the entire ACCESS phase for subrequests:
 *
 *     ngx_http_core_access_phase()
 *         if (r != r->main) { r->phase_handler = ph->next; return NGX_AGAIN; }
 *
 * and auth_request issues exactly such a subrequest. So "reaching the CONTENT
 * phase means the ACCESS phase admitted me" — true for a main request — is
 * FALSE for the one case this endpoint exists to serve. Relying on it would
 * make the endpoint answer 204 unconditionally: brix would become a rubber
 * stamp that admits every request an auth_request consumer sends it, which is
 * an authorization bypass in the security-critical direction. (This is not
 * hypothetical: the first version of this file had that bug, and the
 * "refusing target denies the outer location" test is what caught it.)
 *
 * So when the access phase was skipped, run the SAME handler explicitly. It is
 * the identical code path a main request takes — auth gate, token scope,
 * XrdAcc, rate limit — so there is no second copy of the policy to drift.
 *
 * NGX_DECLINED means the location is not brix-enabled and therefore has no
 * policy to apply. That fails CLOSED (403): an authorization endpoint with no
 * configured authorization must never admit.
 */
static ngx_int_t
webdav_authz_enforce(ngx_http_request_t *r)
{
    ngx_int_t rc;

    if (r == r->main) {
        return NGX_OK;              /* the access phase already ran */
    }

    rc = ngx_http_brix_webdav_access_handler(r);
    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "brix_webdav_authz: no brix policy on this location — "
                      "refusing (an authz endpoint must fail closed)");
        return NGX_HTTP_FORBIDDEN;
    }
    return rc;
}


/*
 * webdav_authz_endpoint — the auth_request target.
 *
 * Reaching the content phase means the ACCESS phase admitted the request, so
 * the answer is 204 plus the subject headers. 204 (not 200) because
 * auth_request treats any 2xx as success and a body would be pointless — the
 * subrequest's body is discarded.
 */
ngx_int_t
webdav_authz_endpoint(ngx_http_request_t *r)
{
    ngx_int_t rc;

    rc = webdav_authz_enforce(r);
    if (rc != NGX_OK) {
        return rc;
    }

    if (webdav_authz_identity_headers(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    return ngx_http_send_header(r);
}


/*
 * webdav_accel_redirect — hand the admitted request to an internal location.
 *
 * MECHANISM NOTE. X-Accel-Redirect is an UPSTREAM-RESPONSE feature: nginx acts
 * on it when it appears in a response the upstream module received, not when a
 * content handler sets it on its own response. A handler that merely emits the
 * header produces a 200 with an empty body — which is precisely what the first
 * version of this function did. The handler-side primitive is
 * ngx_http_internal_redirect(), so that is what this uses; the directive keeps
 * the familiar X-Accel-Redirect NAME because that is the concept operators
 * know, and the observable behaviour is the same.
 *
 * The target is <configured prefix><request uri>. The prefix comes from the
 * config and the URI is nginx's already-normalised r->uri (traversal resolved
 * by nginx's own parser before any handler runs), so nothing the client sends
 * can steer the request outside the operator's chosen internal namespace.
 */
ngx_int_t
webdav_accel_redirect(ngx_http_request_t *r, const ngx_str_t *prefix)
{
    ngx_str_t  target;
    u_char    *p;

    target.len = prefix->len + r->uri.len;
    p = ngx_pnalloc(r->pool, target.len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(p, prefix->data, prefix->len);
    ngx_memcpy(p + prefix->len, r->uri.data, r->uri.len);
    target.data = p;

    /* Same subrequest protection as the authz endpoint: never hand off on a
     * request whose access phase nginx skipped. */
    if (webdav_authz_enforce(r) != NGX_OK) {
        return NGX_HTTP_FORBIDDEN;
    }

    /* Publish the subject before handing off, so the internal location (or an
     * upstream behind it) can be given the identity with proxy_set_header. */
    if (webdav_authz_identity_headers(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_internal_redirect(r, &target, &r->args);
}


/*
 * webdav_gate_only_dispatch — run whichever gate-only seam this location
 * configures, or NGX_DECLINED when it configures neither.
 *
 * Lives here rather than inline in dispatch.c so the branch sits next to the
 * handlers it selects (and so dispatch.c stays under the 600-line ratchet).
 */
ngx_int_t
webdav_gate_only_dispatch(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    if (conf->authz_endpoint) {
        return webdav_authz_endpoint(r);
    }
    if (conf->accel_redirect.len > 0) {
        return webdav_accel_redirect(r, &conf->accel_redirect);
    }
    return NGX_DECLINED;
}
