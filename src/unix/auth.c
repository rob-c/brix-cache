#include "../ngx_xrootd_module.h"
#include "../metrics/unified.h"
#include "../session/registry.h"

#include <string.h>

static ngx_flag_t
xrootd_unix_peer_is_loopback(ngx_connection_t *c)
{
    if (c == NULL || c->sockaddr == NULL) {
        return 0;
    }

    if (c->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) c->sockaddr;
        return ((ntohl(sin->sin_addr.s_addr) >> 24) == 127);
    }

    if (c->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) c->sockaddr;
        return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
    }

    return c->sockaddr->sa_family == AF_UNIX;
}

static ngx_flag_t
xrootd_unix_name_byte_ok(u_char ch)
{
    return ((ch >= 'A' && ch <= 'Z')
            || (ch >= 'a' && ch <= 'z')
            || (ch >= '0' && ch <= '9')
            || ch == '_' || ch == '-' || ch == '.' || ch == '@' || ch == '+');
}

static ngx_int_t
xrootd_unix_copy_name(char *dst, size_t dst_len, const u_char *src,
    size_t len)
{
    size_t i;

    if (dst == NULL || dst_len == 0 || src == NULL || len == 0
        || len >= dst_len)
    {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        if (!xrootd_unix_name_byte_ok(src[i])) {
            return NGX_ERROR;
        }
    }

    ngx_memcpy(dst, src, len);
    dst[len] = '\0';
    return NGX_OK;
}

static void
xrootd_unix_track_identity(xrootd_ctx_t *ctx)
{
    ngx_xrootd_metrics_t *shm;

    shm = xrootd_metrics_shared();
    if (shm == NULL) {
        return;
    }

    if (ctx->primary_vo[0] != '\0') {
        xrootd_track_vo_activity(shm, ctx->primary_vo, 0, 0);
    }
    if (ctx->dn[0] != '\0') {
        xrootd_track_unique_user(shm, ctx->dn, strlen(ctx->dn));
    }
}

ngx_int_t
xrootd_handle_unix_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    const u_char *p, *end, *user_start, *group_start;
    size_t        user_len, group_len;
    char          user[XROOTD_SSS_USER_MAX];
    char          group[XROOTD_SSS_GROUP_MAX];
    char          safe_user[XROOTD_SSS_USER_MAX * 4];
    char          safe_group[XROOTD_SSS_GROUP_MAX * 4];

    if (!conf->unix_trust_remote && !xrootd_unix_peer_is_loopback(c)) {
        xrootd_log_access(ctx, c, "AUTH", "-", "unix",
                          0, kXR_NotAuthorized,
                          "unix auth is restricted to loopback peers", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_UNIX, 0);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "unix auth is restricted to loopback peers");
    }

    if (ctx->payload == NULL || ctx->cur_dlen < 6
        || ngx_strncmp(ctx->payload, "unix", 4) != 0
        || ctx->payload[4] != '\0')
    {
        xrootd_log_access(ctx, c, "AUTH", "-", "unix",
                          0, kXR_NotAuthorized, "malformed unix credential", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_UNIX, 0);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "malformed unix credential");
    }

    p = ctx->payload + 5;
    end = ctx->payload + ctx->cur_dlen;
    while (p < end && *p == ' ') {
        p++;
    }
    user_start = p;
    while (p < end && *p != '\0' && *p != ' ') {
        p++;
    }
    user_len = (size_t) (p - user_start);

    group[0] = '\0';
    if (p < end && *p == ' ') {
        while (p < end && *p == ' ') {
            p++;
        }
        group_start = p;
        while (p < end && *p != '\0' && *p != ' ') {
            p++;
        }
        group_len = (size_t) (p - group_start);
        if (group_len > 0
            && xrootd_unix_copy_name(group, sizeof(group), group_start,
                                     group_len) != NGX_OK)
        {
            xrootd_log_access(ctx, c, "AUTH", "-", "unix",
                              0, kXR_NotAuthorized,
                              "invalid unix group", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
            xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_UNIX, 0);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "invalid unix group");
        }
    }

    if (xrootd_unix_copy_name(user, sizeof(user), user_start, user_len)
        != NGX_OK)
    {
        xrootd_log_access(ctx, c, "AUTH", "-", "unix",
                          0, kXR_NotAuthorized,
                          "invalid unix user", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_UNIX, 0);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "invalid unix user");
    }

    ctx->auth_done = 1;
    ctx->token_auth = 0;
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) user, sizeof(ctx->dn));
    if (group[0] != '\0') {
        ngx_cpystrn((u_char *) ctx->vo_list, (u_char *) group,
                    sizeof(ctx->vo_list));
        ngx_cpystrn((u_char *) ctx->primary_vo, (u_char *) group,
                    sizeof(ctx->primary_vo));
    }

    if (ctx->identity != NULL) {
        if (xrootd_identity_set_dn(ctx->identity, c->pool, ctx->dn,
                                   XROOTD_AUTHN_UNIX) != NGX_OK
            || xrootd_identity_set_vos_csv(ctx->identity, c->pool,
                                           ctx->vo_list) != NGX_OK)
        {
            return xrootd_send_error(ctx, c, kXR_NoMemory,
                                     "identity allocation failed");
        }
    }

    xrootd_session_register(ctx->sessid, ctx->dn, ctx->vo_list, 0);
    xrootd_unix_track_identity(ctx);

    xrootd_sanitize_log_string(user, safe_user, sizeof(safe_user));
    xrootd_sanitize_log_string(group[0] ? group : "-", safe_group,
                               sizeof(safe_group));
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: unix auth OK user=\"%s\" group=\"%s\"",
                  safe_user, safe_group);

    xrootd_log_access(ctx, c, "AUTH", "-", "unix", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_AUTH);
    xrootd_metric_auth(XROOTD_PROTO_STREAM, XROOTD_AUTHN_UNIX, 1);

    return xrootd_send_ok(ctx, c, NULL, 0);
}
