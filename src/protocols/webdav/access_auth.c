/*
 * access_auth.c - WebDAV access-phase authentication gate.
 *
 * WHAT: The credential-source tier of the WebDAV access phase: GSI proxy
 * cert, bearer token, and Basic password sources, the RFC 7617 Basic
 * challenge for browser clients, and the policy gate (access_authenticate)
 * that runs them in order and applies auth=required/optional/none.
 *
 * WHY: Split out of access.c so the authentication surface is grouped by
 * concern and individually reviewable while access.c keeps the access-phase
 * orchestration and the XrdAcc/authdb authorization tiers.
 *
 * HOW: access_authenticate is the sole cross-split entry point (declared in
 * access_internal.h); the per-source wrappers and the Basic challenge stay
 * file-local statics.  Each outcome increments exactly the same metric slot
 * as before the decomposition.
 */

#include "webdav.h"
#include "observability/metrics/unified.h"
#include "auth/authz/acc/acc.h"
#include "fs/path/path.h"   /* brix_check_authdb_identity, brix_check_vo_acl_identity */
#include "webdav_tpc.h"     /* webdav_tpc_find_header — COPY PULL/PUSH direction */
#include "protocols/shared/deleg_capture.h"  /* phase-70 §5.1 proxy header capture */
#include "fs/backend/sd.h"  /* enum brix_cred_mode / BRIX_CRED_SELECT */
#include "auth/protbind/protbind.h"  /* per-host credential-source binding */
#include "redirect.h"                /* §6.1: signed redirect-CGI source */
#include "access_internal.h"

/*
 * access_try_cert — GSI proxy-certificate credential source.
 *
 * WHAT: Attempts client-certificate authentication and records the cert-OK
 * metrics on success.
 *
 * WHY: The cert tier is tried FIRST (before bearer token), matching the
 * root:// auth ordering; metrics must attribute the session to GSI.
 *
 * HOW: Thin wrapper over webdav_verify_proxy_cert; returns its verdict.
 */
static ngx_int_t
access_try_cert(ngx_http_request_t *r,
                ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_verify_proxy_cert(r, conf);

    if (rc == NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_CERT_OK]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_GSI, 1);
    }
    return rc;
}

/*
 * access_try_token — bearer-token credential source.
 *
 * WHAT: Attempts bearer-token authentication and records the token-OK metrics
 * on success.
 *
 * WHY: Tried only after the cert tier fails; metrics must attribute the
 * session to TOKEN.
 *
 * HOW: Thin wrapper over webdav_verify_bearer_token; returns its verdict.
 */
static ngx_int_t
access_try_token(ngx_http_request_t *r,
                 ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_verify_bearer_token(r, conf);

    if (rc == NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_TOKEN_OK]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_TOKEN, 1);
    }
    return rc;
}

/*
 * access_try_basic — Basic-password credential source.
 *
 * WHAT: Attempts HTTP Basic authentication against the configured pwd db and
 * records the pwd-OK metrics on success.
 *
 * WHY: Tried LAST (after cert and token) so stronger credentials always win;
 * metrics must attribute the session to PWD.
 *
 * HOW: Thin wrapper over webdav_verify_basic_pwd; returns its verdict.
 */
static ngx_int_t
access_try_basic(ngx_http_request_t *r,
                 ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_int_t rc = webdav_verify_basic_pwd(r, conf);

    if (rc == NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_PWD_OK]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_PWD, 1);
    }
    return rc;
}

/*
 * access_basic_challenge — RFC 7617 Basic challenge for browser clients.
 *
 * WHAT: Attaches `WWW-Authenticate: Basic realm="brix"` to the response and
 * returns NGX_HTTP_UNAUTHORIZED, or NGX_HTTP_INTERNAL_SERVER_ERROR on
 * allocation failure.
 *
 * WHY: A browser only shows its login prompt (and re-prompts after a wrong
 * password) on 401 + a challenge header; a bare 403 is a dead end.  Emitted
 * only when Basic is actually enabled on the export, so cert/token-only
 * exports keep their historical 403 and never invite a password prompt that
 * cannot succeed.
 *
 * HOW: The same headers_out wiring nginx's own auth_basic module uses — push
 * the header and point headers_out.www_authenticate at it so the special-
 * response path emits it.
 */
static ngx_int_t
access_basic_challenge(ngx_http_request_t *r)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "WWW-Authenticate");
    ngx_str_set(&h->value, "Basic realm=\"brix\"");
    r->headers_out.www_authenticate = h;
    return NGX_HTTP_UNAUTHORIZED;
}

/*
 * webdav_bearer_enabled — does this export accept bearer tokens?
 *
 * WHAT: true when JWKS keys, a macaroon secret, or a token registry is
 * configured on the location.
 * WHY: RFC 6750 challenge semantics (401 + WWW-Authenticate: Bearer) apply only
 * on a bearer-protected resource; a cert-only export keeps its historical 403.
 * HOW: mirrors the DECLINED guard in webdav_verify_bearer_token.
 */
static int
webdav_bearer_enabled(ngx_http_brix_webdav_loc_conf_t *conf)
{
    return conf->jwks_key_count > 0
           || conf->common.token_macaroon_secret.len > 0
           || conf->token_registry != NULL;
}

/*
 * access_bearer_challenge — RFC 6750 §3 Bearer challenge / error response.
 *
 * WHAT: attaches `WWW-Authenticate: Bearer realm="brix"` (optionally with an
 * `error="..."` attribute) and returns the given HTTP status.
 * WHY: RFC 6750 §3 requires an unauthenticated/invalid-token request on a
 * bearer-protected resource to return 401 + WWW-Authenticate: Bearer (not 403,
 * which means insufficient_scope); a dual-transport request returns
 * 400 invalid_request.  The header lets a client discover the scheme and, for
 * invalid_token, know it should refresh rather than escalate.
 * HOW: same headers_out wiring nginx's auth_basic uses — push the header and
 * point headers_out.www_authenticate at it so the special-response path emits it.
 */
static ngx_int_t
access_bearer_challenge(ngx_http_request_t *r, ngx_int_t status,
                        const char *error)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "WWW-Authenticate");
    if (error != NULL) {
        h->value.data = ngx_pnalloc(r->pool,
            sizeof("Bearer realm=\"brix\", error=\"\"") - 1 + ngx_strlen(error));
        if (h->value.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        h->value.len = ngx_sprintf(h->value.data,
            "Bearer realm=\"brix\", error=\"%s\"", error) - h->value.data;
    } else {
        ngx_str_set(&h->value, "Bearer realm=\"brix\"");
    }
    r->headers_out.www_authenticate = h;
    return status;
}

/*
 * access_try_proto — run the HTTP credential source bound to one protbind id.
 *
 * WHAT: Maps a BRIX_AUTH_* protocol id onto its HTTP transport and runs it;
 * returns NGX_DECLINED for an id with no HTTP transport at all.
 *
 * WHY: protbind is protocol-agnostic, so a rule may legitimately name a scheme
 * that only exists on the root:// wire (sss, unix, krb5, host).  Skipping it
 * here — rather than rejecting it at parse time — lets a site write ONE
 * `<host> only gsi ztn sss` policy and have each frontend honour the part it
 * can actually speak, which is exactly what XRootD's shared sec.protbind does.
 *
 * HOW: A switch over the three ids with an HTTP transport; the wrappers above
 * keep their metric attribution unchanged.
 */
static ngx_int_t
access_try_proto(ngx_uint_t proto, ngx_http_request_t *r,
                 ngx_http_brix_webdav_loc_conf_t *conf)
{
    switch (proto) {
    case BRIX_AUTH_GSI:   return access_try_cert(r, conf);
    case BRIX_AUTH_TOKEN: return access_try_token(r, conf);
    case BRIX_AUTH_PWD:   return access_try_basic(r, conf);
    default:              return NGX_DECLINED;   /* no HTTP transport */
    }
}

/*
 * access_protbind_set — resolve this request's ordered credential-source set.
 *
 * WHAT: Fills *out with the protocols this peer may authenticate with, in the
 * order they are to be tried.
 *
 * WHY: Without any brix_webdav_protbind rule the answer must be byte-identical
 * to the historical gate — cert, then token, then Basic, enabled iff auth is
 * not `none` — so an existing config cannot change behaviour.
 *
 * HOW: Build that historical order as the base set, hand the resolver the peer
 * IP (always available) plus the reverse-resolved hostname (only when some
 * template actually needs one — the wildcard-only case must never pay for DNS),
 * and let the shared engine apply the first matching rule.
 */
static void
access_protbind_set(ngx_http_request_t *r,
                    ngx_http_brix_webdav_loc_conf_t *conf,
                    brix_protbind_set_t *out)
{
    brix_protbind_set_t   base;
    char                  peer_ip[NGX_INET6_ADDRSTRLEN + 1];
    char                  host_buf[256];
    const char           *peer_host = NULL;
    size_t                n;

    brix_protbind_http_base(conf->auth != WEBDAV_AUTH_NONE, &base);

    n = ngx_min(r->connection->addr_text.len, sizeof(peer_ip) - 1);
    ngx_memcpy(peer_ip, r->connection->addr_text.data, n);
    peer_ip[n] = '\0';

    if (brix_protbind_needs_hostname(conf->common.protbind)) {
        peer_host = brix_acc_resolve_peer(r->connection->sockaddr,
                                          r->connection->socklen,
                                          host_buf, sizeof(host_buf));
    }

    brix_protbind_resolve(conf->common.protbind, &base, peer_host, peer_ip, out);
}

/* ---- Run the bound authentication schemes in order ----
 *
 * WHAT: Returns the first NGX_OK, else the last rejection; *token_rc carries
 *       the bearer leg's own result so the caller can shape the challenge.
 *
 * WHY:  RFC 6750 §2 (SEC MUST): a dual-transport bearer token (header + query)
 *       is a hard 400 invalid_request — it must NOT fall through to a weaker
 *       source, nor to anonymous.  That is the one rejection that stops the
 *       walk rather than continuing it.
 *
 * HOW:  1. Try each bound scheme in binding order.
 *       2. Stop on success.
 *       3. Record the bearer result, and stop early on the 400.
 */
static ngx_int_t
access_run_bound(ngx_http_request_t *r,
                 ngx_http_brix_webdav_loc_conf_t *conf,
                 const brix_protbind_set_t *bound, ngx_int_t *token_rc)
{
    ngx_int_t   auth_rc = NGX_DECLINED;
    ngx_uint_t  index;

    for (index = 0; index < bound->count; index++) {
        auth_rc = access_try_proto(bound->protos[index], r, conf);
        if (auth_rc == NGX_OK) {
            break;
        }
        if (bound->protos[index] == BRIX_AUTH_TOKEN) {
            *token_rc = auth_rc;
            if (*token_rc == NGX_HTTP_BAD_REQUEST) {
                break;
            }
        }
    }

    return auth_rc;
}


/* ---- Pick the rejection an auth=required export must answer with ----
 *
 * WHAT: Returns the challenge/status for a request that reached the end of the
 *       bound schemes without authenticating.
 *
 * WHY:  A challenge is only offered for a scheme this peer is actually bound
 *       to — challenging Basic on a host whose binding excludes pwd would
 *       invite a password that can never be accepted.
 *
 * HOW:  1. Password file + pwd bound → Basic challenge.
 *       2. RFC 6750 §3 (MUST): on a bearer-protected export, no/invalid
 *          credential → 401 + WWW-Authenticate: Bearer (403 =
 *          insufficient_scope, emitted by the authz tier for a
 *          valid-but-unscoped token).  Attribute error="invalid_token" only
 *          when a bearer was actually presented but failed validation
 *          (token_rc == 401); a missing credential gets the bare challenge.
 *       3. Cert-only exports keep the historical 403.
 */
static ngx_int_t
access_required_challenge(ngx_http_request_t *r,
                          ngx_http_brix_webdav_loc_conf_t *conf,
                          const brix_protbind_set_t *bound,
                          ngx_int_t token_rc)
{
    const char  *err;

    if (conf->common.pwd_file.len > 0
        && brix_protbind_allows(bound, BRIX_AUTH_PWD))
    {
        return access_basic_challenge(r);
    }

    if (webdav_bearer_enabled(conf)
        && brix_protbind_allows(bound, BRIX_AUTH_TOKEN))
    {
        err = (token_rc == NGX_HTTP_UNAUTHORIZED) ? "invalid_token" : NULL;
        return access_bearer_challenge(r, NGX_HTTP_UNAUTHORIZED, err);
    }

    return NGX_HTTP_FORBIDDEN;
}


/*
 * access_authenticate — the authentication gate.
 *
 * WHAT: Runs the credential sources bound to this peer, in order, and applies
 * the location's auth policy to the outcome.  With no brix_webdav_protbind
 * rule that order is the historical one: GSI proxy cert, bearer token, then
 * Basic password.
 *
 * WHY: auth=required rejects unauthenticated requests — with a 401 Basic
 * challenge when a pwd db is configured (so browsers prompt for credentials),
 * else the historical 403; auth=optional lets them proceed as anonymous;
 * auth=none (or a `<host> none` binding) skips verification entirely.  Each
 * outcome increments exactly the same metric slot as before the decomposition.
 *
 * HOW: Returns NGX_OK to continue (authenticated or anonymous) or the
 * metrics-counted rejection.  A challenge is only offered for a scheme this
 * peer is actually bound to — challenging Basic on a host whose binding
 * excludes pwd would invite a password that can never be accepted.
 */
ngx_int_t
access_authenticate(ngx_http_request_t *r,
                    ngx_http_brix_webdav_loc_conf_t *conf)
{
    brix_protbind_set_t  bound;
    ngx_int_t            auth_rc = NGX_DECLINED;
    ngx_int_t            token_rc = NGX_DECLINED;

    /* §6.1: a signed redirect handoff (brixrdr.* CGI, verified against
     * brix_http_secretkey) IS this request's authentication — the manager
     * already authenticated the client.  Tried FIRST and fail-closed: a bad
     * MAC is a 403, never a fall-through to weaker sources. */
    auth_rc = webdav_redirect_signed_auth(r, conf);
    if (auth_rc == NGX_OK) {
        return NGX_OK;
    }
    if (auth_rc != NGX_DECLINED) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_REJECTED]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 0);
        return webdav_metrics_return(r, auth_rc);
    }
    access_protbind_set(r, conf, &bound);

    if (!bound.require_auth) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_NONE]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 1);
        return NGX_OK;
    }

    auth_rc = access_run_bound(r, conf, &bound, &token_rc);

    if (token_rc == NGX_HTTP_BAD_REQUEST) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_REJECTED]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 0);
        return webdav_metrics_return(r,
            access_bearer_challenge(r, NGX_HTTP_BAD_REQUEST, "invalid_request"));
    }

    if (auth_rc != NGX_OK && conf->auth == WEBDAV_AUTH_REQUIRED) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_REJECTED]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 0);
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_webdav: unauthenticated request rejected"
                      " (auth=required)");
        return webdav_metrics_return(r,
            access_required_challenge(r, conf, &bound, token_rc));
    }

    if (auth_rc != NGX_OK) {
        BRIX_WEBDAV_METRIC_INC(
            auth_total[BRIX_WEBDAV_AUTH_RESULT_ANONYMOUS]);
        brix_metric_auth(BRIX_PROTO_WEBDAV, BRIX_AUTHN_NONE, 1);
    }

    return NGX_OK;
}
