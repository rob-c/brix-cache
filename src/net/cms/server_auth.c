#include "core/compat/log_event.h"
#include "server.h"
#include "server_recv_internal.h"
#include "core/compat/net_target.h"
#include "auth/sss/sss_internal.h"

/* ---- Require a valid state for starting/repeating LOGIN ----
 * WHAT: Return NGX_OK for a permitted state; otherwise log and close the peer.
 * WHY: A repeated LOGIN must not bypass an outstanding SSS challenge; unknown
 *      states must also fail closed rather than publish a selectable node.
 * HOW: Allow NONE, REQUESTED and DONE only; refuse before parsing/registration.
 */
ngx_int_t
brix_cms_srv_require_login_state(brix_cms_srv_ctx_t *ctx)
{
    if (ctx->auth_state == CMS_AUTH_NONE || ctx->auth_state == CMS_AUTH_REQUESTED
        || ctx->auth_state == CMS_AUTH_DONE) {
        return NGX_OK;
    }
    cms_srv_log_auth_fail(ctx, "login-during-auth");
    cms_srv_fail_close(ctx, BRIX_SESS_END_ERROR);
    return NGX_ERROR;
}

/*
 * server_auth.c — CMS registration authentication (Phase 28 W1).
 *
 * WHAT: Authentication/authorisation gates applied to a data node before it is
 *       allowed into the manager's server registry (and therefore before the
 *       manager will redirect clients to it). Two alternative/composable
 *       admission controls plus unconditional host validation, all compatible
 *       with vanilla XRootD:
 *         W1a — real cmsd sss credential check (kYR_xauth handshake), reusing
 *               the shared SSS verifier in src/sss.
 *         W1b — accept-time CIDR allowlist of permitted data-node IPs.
 *         W1c — host-character validation at registration store time
 *               (brix_net_host_chars_valid, called from registry.c).
 *
 * WHY:  Without these, any peer that can reach the CMS port can self-report an
 *       arbitrary host:port:paths and have the manager redirect clients to it
 *       (redirect poisoning — the critical finding). At least one control is
 *       mandatory: a vanilla cmsd from a trusted subnet can use W1b alone,
 *       while W1a provides cryptographic cluster authentication.
 */

/* Credential freshness window for the cluster sss handshake.  The credential
 * is generated fresh by the data node at each login, so this only needs to
 * exceed connect latency + clock skew; a generous hour avoids false rejects. */
#define CMS_SSS_LIFETIME  BRIX_CMS_SSS_LIFETIME_SECS

ngx_int_t
brix_cms_srv_check_peer(ngx_connection_t *c,
    ngx_stream_brix_cms_srv_conf_t *conf)
{
    if (conf->allow == NULL) {
        /* SSS-only listeners admit the TCP peer here and authenticate it before
         * registration.  The impossible no-policy state is still refused as a
         * runtime tripwire in case a future config path bypasses merge. */
        return (conf->sss_keys != NULL && conf->sss_keys->nelts > 0)
               ? NGX_OK : NGX_DECLINED;
    }

    if (c->sockaddr != NULL
        && ngx_cidr_match(c->sockaddr, conf->allow) == NGX_OK)
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

ngx_int_t
brix_cms_srv_verify_xauth(brix_cms_srv_ctx_t *ctx,
    const u_char *payload, size_t payload_len)
{
    brix_sss_identity_t   id;
    const brix_sss_key_t *key;
    char                    err[160];
    ngx_int_t               rc;

    ngx_memzero(&id, sizeof(id));

    rc = brix_sss_verify_blob(ctx->conf->sss_keys, CMS_SSS_LIFETIME,
                                payload, payload_len, &id, &key,
                                err, sizeof(err));
    if (rc != NGX_OK) {
        BRIX_LOG(NGX_LOG_NOTICE, ctx->c->log, 0,
                      "brix: CMS server: sss auth rejected for %s: %s",
                      ctx->host, err);
        return NGX_ERROR;
    }

    {
        char safe_user[BRIX_IP_STR_LEN];
        brix_sanitize_log_string(id.name[0] ? id.name : "-",
                                   safe_user, sizeof(safe_user));
        BRIX_LOG(NGX_LOG_INFO, ctx->c->log, 0,
                      "brix: CMS server: sss auth OK for %s (id=\"%s\")",
                      ctx->host, safe_user);
    }

    return NGX_OK;
}
