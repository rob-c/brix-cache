#include "../ngx_xrootd_module.h"
#include "../metrics/unified.h"
#include "../session/registry.h"

#include <string.h>

#if (XROOTD_HAVE_KRB5)
static const char *
xrootd_krb5_error(ngx_stream_xrootd_srv_conf_t *conf, krb5_error_code rc)
{
    return conf->krb5_context != NULL
           ? krb5_get_error_message(conf->krb5_context, rc)
           : NULL;
}

static void
xrootd_krb5_free_error(ngx_stream_xrootd_srv_conf_t *conf, const char *msg)
{
    if (conf->krb5_context != NULL && msg != NULL) {
        krb5_free_error_message(conf->krb5_context, msg);
    }
}

static ngx_int_t
xrootd_krb5_peer_addr(ngx_connection_t *c, krb5_address *addr)
{
    if (c == NULL || c->sockaddr == NULL || addr == NULL) {
        return NGX_DECLINED;
    }

    if (c->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) c->sockaddr;
        addr->addrtype = ADDRTYPE_INET;
        addr->length = sizeof(sin->sin_addr);
        addr->contents = (krb5_octet *) &sin->sin_addr;
        return NGX_OK;
    }

    if (c->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) c->sockaddr;
        addr->addrtype = ADDRTYPE_INET6;
        addr->length = sizeof(sin6->sin6_addr);
        addr->contents = (krb5_octet *) &sin6->sin6_addr;
        return NGX_OK;
    }

    return NGX_DECLINED;
}

static ngx_int_t
xrootd_krb5_client_name(ngx_stream_xrootd_srv_conf_t *conf,
    krb5_ticket *ticket, char *dst, size_t dst_len)
{
    krb5_error_code rc;
    char           *principal;

    if (ticket == NULL || ticket->enc_part2 == NULL
        || ticket->enc_part2->client == NULL || dst == NULL || dst_len == 0)
    {
        return NGX_ERROR;
    }

    rc = krb5_aname_to_localname(conf->krb5_context,
                                 ticket->enc_part2->client,
                                 (int) dst_len - 1, dst);
    if (rc == 0) {
        dst[dst_len - 1] = '\0';
        return NGX_OK;
    }

    principal = NULL;
    rc = krb5_unparse_name(conf->krb5_context, ticket->enc_part2->client,
                           &principal);
    if (rc != 0 || principal == NULL) {
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) dst, (u_char *) principal, dst_len);
    krb5_free_unparsed_name(conf->krb5_context, principal);
    return NGX_OK;
}

static void
xrootd_krb5_track_identity(xrootd_ctx_t *ctx)
{
    ngx_xrootd_metrics_t *shm;

    shm = xrootd_metrics_shared();
    if (shm == NULL || ctx->dn[0] == '\0') {
        return;
    }

    xrootd_track_unique_user(shm, ctx->dn, strlen(ctx->dn));
}
#endif

ngx_int_t
xrootd_handle_krb5_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
#if (XROOTD_HAVE_KRB5)
    krb5_auth_context auth_ctx;
    krb5_address      peer_addr;
    krb5_data         inbuf;
    krb5_ticket      *ticket;
    krb5_error_code   rc;
    const char       *kmsg;
    char              cname[512];
    char              safe_cname[1024];

    if (conf->krb5_context == NULL || conf->krb5_principal_obj == NULL
        || conf->krb5_keytab_obj == NULL)
    {
        xrootd_log_access(ctx, c, "AUTH", "-", "krb5",
                          0, kXR_NotAuthorized, "krb5 not configured", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_KRB5, 0);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "krb5 not configured");
    }

    if (ctx->payload == NULL || ctx->cur_dlen <= 4
        || ngx_strncmp(ctx->payload, "krb5", 4) != 0)
    {
        xrootd_log_access(ctx, c, "AUTH", "-", "krb5",
                          0, kXR_NotAuthorized, "malformed krb5 credential", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_KRB5, 0);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "malformed krb5 credential");
    }

    auth_ctx = NULL;
    ticket = NULL;

    rc = krb5_auth_con_init(conf->krb5_context, &auth_ctx);
    if (rc != 0) {
        kmsg = xrootd_krb5_error(conf, rc);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: krb5 auth context init failed: %s",
                      kmsg ? kmsg : "unknown");
        xrootd_krb5_free_error(conf, kmsg);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_KRB5, 0);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "krb5 authentication failed");
    }

    if (conf->krb5_ip_check) {
        if (xrootd_krb5_peer_addr(c, &peer_addr) != NGX_OK) {
            krb5_auth_con_free(conf->krb5_context, auth_ctx);
            xrootd_log_access(ctx, c, "AUTH", "-", "krb5",
                              0, kXR_NotAuthorized,
                              "cannot bind krb5 peer address", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
            xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_KRB5, 0);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "cannot bind krb5 peer address");
        }

        rc = krb5_auth_con_setaddrs(conf->krb5_context, auth_ctx,
                                    NULL, &peer_addr);
        if (rc != 0) {
            kmsg = xrootd_krb5_error(conf, rc);
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: krb5 peer address check setup failed: %s",
                          kmsg ? kmsg : "unknown");
            xrootd_krb5_free_error(conf, kmsg);
            krb5_auth_con_free(conf->krb5_context, auth_ctx);
            XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
            xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_KRB5, 0);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "krb5 authentication failed");
        }
    }

    inbuf.length = (unsigned int) (ctx->cur_dlen - 4);
    inbuf.data = (char *) (ctx->payload + 4);

    rc = krb5_rd_req(conf->krb5_context, &auth_ctx, &inbuf,
                     conf->krb5_principal_obj, conf->krb5_keytab_obj,
                     NULL, &ticket);
    if (rc != 0) {
        kmsg = xrootd_krb5_error(conf, rc);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: krb5 credential verification failed: %s",
                      kmsg ? kmsg : "unknown");
        xrootd_krb5_free_error(conf, kmsg);
        krb5_auth_con_free(conf->krb5_context, auth_ctx);
        xrootd_log_access(ctx, c, "AUTH", "-", "krb5",
                          0, kXR_NotAuthorized,
                          "krb5 credential verification failed", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_KRB5, 0);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "krb5 authentication failed");
    }

    if (xrootd_krb5_client_name(conf, ticket, cname, sizeof(cname))
        != NGX_OK)
    {
        krb5_free_ticket(conf->krb5_context, ticket);
        krb5_auth_con_free(conf->krb5_context, auth_ctx);
        xrootd_log_access(ctx, c, "AUTH", "-", "krb5",
                          0, kXR_NotAuthorized,
                          "cannot map krb5 client principal", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_KRB5, 0);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "cannot map krb5 client principal");
    }

    krb5_free_ticket(conf->krb5_context, ticket);
    krb5_auth_con_free(conf->krb5_context, auth_ctx);

    ctx->auth_done = 1;
    ctx->token_auth = 0;
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) cname, sizeof(ctx->dn));

    if (ctx->identity != NULL) {
        if (xrootd_identity_set_dn(ctx->identity, c->pool, ctx->dn,
                                   XROOTD_AUTHN_KRB5) != NGX_OK)
        {
            return xrootd_send_error(ctx, c, kXR_NoMemory,
                                     "identity allocation failed");
        }
    }

    xrootd_session_register(ctx->sessid, ctx->dn, ctx->vo_list, 0);
    xrootd_krb5_track_identity(ctx);

    xrootd_sanitize_log_string(cname, safe_cname, sizeof(safe_cname));
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: krb5 auth OK principal=\"%s\"", safe_cname);

    xrootd_log_access(ctx, c, "AUTH", "-", "krb5", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_AUTH);
    xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_KRB5, 1);

    return xrootd_send_ok(ctx, c, NULL, 0);
#else
    xrootd_log_access(ctx, c, "AUTH", "-", "krb5",
                      0, kXR_NotAuthorized,
                      "krb5 support is not compiled in", 0);
    XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
    xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_KRB5, 0);
    return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                             "krb5 support is not compiled in");
#endif
}
