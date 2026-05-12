#include "../ngx_xrootd_module.h"
#include "../upstream/upstream.h"
#include "../manager/registry.h"
#include "../manager/pending.h"
#include "../cms/cms_internal.h"

#include <arpa/inet.h>

ngx_int_t
xrootd_handle_locate(xrootd_ctx_t *ctx, ngx_connection_t *c,
                     ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientLocateRequest *req = (ClientLocateRequest *) ctx->hdr_buf;
    char                 reqpath_buf[XROOTD_MAX_PATH + 1];
    char                 resolved[PATH_MAX];
    struct sockaddr_in  *sin;
    char                 loc_buf[256];
    int                  loc_len;
    int                  is_wildcard;
    uint16_t             port;
    char                 access_char;

    (void) req;

    if (ctx->cur_dlen == 0 || ctx->payload == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_LOCATE);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath_buf, sizeof(reqpath_buf), 1))
    {
        XROOTD_OP_ERR(ctx, XROOTD_OP_LOCATE);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    is_wildcard = (reqpath_buf[0] == '*' && reqpath_buf[1] == '\0');

    if (conf->manager_mode && !is_wildcard) {
        char     redir_host[256];
        uint16_t redir_port;
        if (xrootd_srv_select(reqpath_buf, 0, redir_host,
                              sizeof(redir_host), &redir_port)) {
            xrootd_log_access(ctx, c, "LOCATE", reqpath_buf, "registry",
                              1, 0, NULL, 0);
            XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);
            return xrootd_send_redirect(ctx, c, redir_host, redir_port);
        }

        /* Registry miss — ask the CMS parent via kYR_locate. */
        if (conf->cms_ctx != NULL) {
            uint32_t  streamid;

            streamid = ngx_xrootd_cms_next_streamid(conf->cms_ctx);
            if (ngx_xrootd_cms_send_locate(conf->cms_ctx, streamid,
                                           reqpath_buf) == NGX_OK
                && xrootd_pending_insert(streamid, ngx_pid, c->fd,
                                         conf->cms_locate_timeout) == NGX_OK)
            {
                ctx->cms_wait_streamid = streamid;
                ctx->state = XRD_ST_WAITING_CMS;
                ngx_add_timer(c->read, conf->cms_locate_timeout);
                return NGX_AGAIN;
            }
            /* Fall through to static-map / notFound if suspend fails. */
        }
    }

    if (!is_wildcard && conf->manager_map != NULL) {
        const xrootd_manager_map_t *m;

        m = xrootd_find_manager_map(reqpath_buf, conf->manager_map);
        if (m != NULL) {
            xrootd_log_access(ctx, c, "LOCATE", reqpath_buf, "redirect",
                              1, 0, NULL, 0);
            XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);
            return xrootd_send_redirect(ctx, c, (const char *) m->host.data,
                                        m->port);
        }
    }

    if (!is_wildcard) {
        if (!xrootd_resolve_path(c->log, &conf->root, reqpath_buf,
                                 resolved, sizeof(resolved)))
        {
            if (conf->upstream_host.len > 0) {
                xrootd_log_access(ctx, c, "LOCATE", reqpath_buf,
                                  "upstream", 1, 0, NULL, 0);
                XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);
                return xrootd_upstream_start(ctx, c, conf);
            }

            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_LOCATE, "LOCATE",
                              reqpath_buf, "-", kXR_NotFound, "file not found");
        }

        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                ctx->vo_list) != NGX_OK)
        {
            XROOTD_OP_ERR(ctx, XROOTD_OP_LOCATE);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "VO not authorized");
        }

        if (xrootd_check_token_scope(ctx, reqpath_buf, 0) != NGX_OK) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_LOCATE, "LOCATE",
                              reqpath_buf, "-",
                              kXR_NotAuthorized, "token scope denied");
        }
    }

    access_char = conf->allow_write ? 'w' : 'r';

    if (c->local_sockaddr != NULL
        && c->local_sockaddr->sa_family == AF_INET)
    {
        char ipbuf[INET_ADDRSTRLEN];
        sin = (struct sockaddr_in *) c->local_sockaddr;
        port = ntohs(sin->sin_port);
        inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
        loc_len = snprintf(loc_buf, sizeof(loc_buf), "S%c%s:%d",
                           access_char, ipbuf, (int) port);
    } else if (c->local_sockaddr != NULL
               && c->local_sockaddr->sa_family == AF_INET6)
    {
        char                 ipbuf[INET6_ADDRSTRLEN];
        struct sockaddr_in6 *sin6;
        sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
        port = ntohs(sin6->sin6_port);
        inet_ntop(AF_INET6, &sin6->sin6_addr, ipbuf, sizeof(ipbuf));
        loc_len = snprintf(loc_buf, sizeof(loc_buf), "S%c[%s]:%d",
                           access_char, ipbuf, (int) port);
    } else {
        loc_len = snprintf(loc_buf, sizeof(loc_buf), "S%clocalhost",
                           access_char);
    }

    xrootd_log_access(ctx, c, "LOCATE", reqpath_buf, loc_buf,
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);

    return xrootd_send_ok(ctx, c, loc_buf, (uint32_t) (loc_len + 1));
}

