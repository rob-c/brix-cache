#include "server.h"
#include "core/compat/net_target.h"
#include "sss/sss_internal.h"

/*
 * server_auth.c — CMS registration authentication (Phase 28 W1).
 *
 * WHAT: Authentication/authorisation gates applied to a data node before it is
 *       allowed into the manager's server registry (and therefore before the
 *       manager will redirect clients to it).  Three layered, individually
 *       vanilla-XRootD-compatible controls:
 *         W1a — real cmsd sss credential check (kYR_xauth handshake), reusing
 *               the shared SSS verifier in src/sss.
 *         W1b — accept-time CIDR allowlist of permitted data-node IPs.
 *         W1c — host-character validation at registration store time
 *               (xrootd_net_host_chars_valid, called from registry.c).
 *
 * WHY:  Without these, any peer that can reach the CMS port can self-report an
 *       arbitrary host:port:paths and have the manager redirect clients to it
 *       (redirect poisoning — the critical finding).  The controls are
 *       opt-in/compatible: a vanilla cmsd from a trusted subnet (W1b) carrying
 *       a valid cluster sss credential (W1a) is admitted unchanged.
 */

/* Credential freshness window for the cluster sss handshake.  The credential
 * is generated fresh by the data node at each login, so this only needs to
 * exceed connect latency + clock skew; a generous hour avoids false rejects. */
#define CMS_SSS_LIFETIME  3600

ngx_int_t
xrootd_cms_srv_check_peer(ngx_connection_t *c,
    ngx_stream_xrootd_cms_srv_conf_t *conf)
{
    static ngx_uint_t warned;

    if (conf->allow == NULL) {
        /*
         * Back-compat: no allowlist configured → accept as before, but warn
         * once so operators know the CMS port is unauthenticated at the
         * network layer.  (SSS auth, when configured, still gates separately.)
         */
        if (!warned && conf->sss_keytab.len == 0) {
            warned = 1;
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: CMS server has no xrootd_cms_server_allow "
                          "and no xrootd_cms_server_sss_keytab — any host may "
                          "register; set an allowlist or sss keytab to harden");
        }
        return NGX_OK;
    }

    if (c->sockaddr != NULL
        && ngx_cidr_match(c->sockaddr, conf->allow) == NGX_OK)
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}

ngx_int_t
xrootd_cms_srv_verify_xauth(xrootd_cms_srv_ctx_t *ctx,
    const u_char *payload, size_t payload_len)
{
    xrootd_sss_identity_t   id;
    const xrootd_sss_key_t *key;
    char                    err[160];
    ngx_int_t               rc;

    ngx_memzero(&id, sizeof(id));

    rc = xrootd_sss_verify_blob(ctx->conf->sss_keys, CMS_SSS_LIFETIME,
                                payload, payload_len, &id, &key,
                                err, sizeof(err));
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->c->log, 0,
                      "xrootd: CMS server: sss auth rejected for %s: %s",
                      ctx->host, err);
        return NGX_ERROR;
    }

    {
        char safe_user[256];
        xrootd_sanitize_log_string(id.name[0] ? id.name : "-",
                                   safe_user, sizeof(safe_user));
        ngx_log_error(NGX_LOG_INFO, ctx->c->log, 0,
                      "xrootd: CMS server: sss auth OK for %s (id=\"%s\")",
                      ctx->host, safe_user);
    }

    return NGX_OK;
}
