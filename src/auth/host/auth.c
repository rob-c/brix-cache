#include "core/ngx_xrootd_module.h"
#include "session/registry.h"
#include "auth/authz/acc/acc.h"          /* xrootd_acc_resolve_peer (breaker-bounded) */

#include <string.h>
#include <sys/socket.h>

/*
 * auth.c — XRootD `host` (host-based) authentication handler — Phase 52 WS-C.
 *
 * WHAT: Implements the kXR_auth handler for the XRootD `host` security protocol.
 *       The client merely SELECTS `host`; it asserts no identity.  The server
 *       reverse-resolves the peer's socket address to a hostname and checks it
 *       against the configured allowlist (xrootd_host_allow: exact hostnames or
 *       ".suffix" domain suffixes).  On a match the peer is authenticated AS that
 *       hostname (ctx->dn).
 *
 * WHY:  `host` is XRootD's weakest, oldest scheme — a hostname (or DNS, lacking
 *       DNSSEC) is spoofable, so it is for trusted closed networks only.  It is
 *       therefore fail-closed: it must be explicitly selected (conf->auth ==
 *       XROOTD_AUTH_HOST), an allowlist MUST be configured (empty = deny all),
 *       and the identity comes from the SOCKET reverse-DNS, never from any
 *       client-asserted name.  Isolating it here keeps the spoofable surface in
 *       one auditable place.
 *
 * HOW:  Downstream of kXR_login, inside the kXR_auth dispatcher (../gsi/auth.c)
 *       once it matched the "host" credtype.  Reverse-resolve via
 *       xrootd_acc_resolve_peer() (the same getnameinfo path used by XrdAcc host
 *       rules, now circuit-breaker-bounded), match host_match(), set the identity
 *       + register + metrics, return kXR_ok — else kXR_NotAuthorized.
 */

/*
 * Match a reverse-resolved peer hostname against one allowlist pattern.
 *   - a leading '.' pattern (".cern.ch") matches any host ending in it
 *     (case-insensitive), i.e. a domain suffix;
 *   - otherwise an exact (case-insensitive) hostname match.
 */
static ngx_flag_t
xrootd_host_pattern_match(const char *host, const ngx_str_t *pat)
{
    size_t hlen = ngx_strlen(host);

    if (pat->len == 0) {
        return 0;
    }
    if (pat->data[0] == '.') {
        /* domain suffix: host must be longer than the suffix and end with it */
        if (hlen <= pat->len) {
            return 0;
        }
        return ngx_strncasecmp((u_char *) host + (hlen - pat->len),
                               pat->data, pat->len) == 0;
    }
    return hlen == pat->len
           && ngx_strncasecmp((u_char *) host, pat->data, pat->len) == 0;
}

static ngx_flag_t
xrootd_host_allowed(ngx_stream_xrootd_srv_conf_t *conf, const char *host)
{
    ngx_str_t  *pats;
    ngx_uint_t  i;

    if (conf->host_allow == NULL || conf->host_allow->nelts == 0) {
        return 0;                          /* empty allowlist = deny all */
    }
    pats = conf->host_allow->elts;
    for (i = 0; i < conf->host_allow->nelts; i++) {
        if (xrootd_host_pattern_match(host, &pats[i])) {
            return 1;
        }
    }
    return 0;
}

/*
 * Public entry point for the XRootD `host` auth scheme.  Reverse-resolves the
 * peer, matches the allowlist, and authenticates the connection AS the resolved
 * hostname.  Returns kXR_ok via XROOTD_RETURN_OK or kXR_NotAuthorized on any
 * failure (no allowlist match, resolution failure, malformed credential).
 */
ngx_int_t
xrootd_handle_host_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    char  host[256];
    char  safe_host[256 * 4];

    /* The credential merely tags the protocol; the identity is the socket's. */
    if (ctx->payload == NULL || ctx->cur_dlen < 4
        || ngx_strncmp(ctx->payload, "host", 4) != 0)
    {
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_HOST, 0);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "host",
                          kXR_NotAuthorized, "malformed host credential");
    }

    if (c->sockaddr == NULL
        || xrootd_acc_resolve_peer(c->sockaddr, c->socklen,
                                   host, sizeof(host)) == NULL)
    {
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_HOST, 0);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "host",
                          kXR_NotAuthorized,
                          "host auth: peer reverse-DNS failed");
    }

    if (!xrootd_host_allowed(conf, host)) {
        xrootd_sanitize_log_string(host, safe_host, sizeof(safe_host));
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                      "xrootd: host auth denied for \"%s\" "
                      "(not in xrootd_host_allow)", safe_host);
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_HOST, 0);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "host",
                          kXR_NotAuthorized, "host not authorized");
    }

    ctx->auth_done = 1;
    ctx->token_auth = 0;
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) host, sizeof(ctx->dn));
    ctx->vo_list[0] = '\0';
    ctx->primary_vo[0] = '\0';

    if (ctx->identity != NULL
        && xrootd_identity_set_dn(ctx->identity, c->pool, ctx->dn,
                                  XROOTD_AUTHN_HOST) != NGX_OK)
    {
        return xrootd_send_error(ctx, c, kXR_NoMemory,
                                 "identity allocation failed");
    }

    xrootd_session_register(ctx->sessid, ctx->dn, ctx->vo_list, 0);

    xrootd_sanitize_log_string(host, safe_host, sizeof(safe_host));
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: host auth OK host=\"%s\"", safe_host);

    xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_HOST, 1);
    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "host", 0);
}
