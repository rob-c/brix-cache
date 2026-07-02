/*
 * locate.c — kXR_locate (3027) opcode handler: resolve a path to a serving endpoint.
 *
 * WHAT: Implements xrootd_handle_locate(), the protocol handler for kXR_locate.
 *       For a given client path it answers "which server should you talk to?" by
 *       returning either a kXR_redirect to another host (manager/CMS modes) or a
 *       kXR_ok carrying an "Sx<host>:<port>" location token (data-server mode),
 *       where the leading S marks a server and the access char ('w' if
 *       conf->common.allow_write, else 'r') advertises read/write capability.
 *       Also handles the "*" wildcard form (locate the local server itself).
 *
 * WHY:  kXR_locate underpins XRootD's redirection/clustering model: clients query
 *       a manager to discover the data server holding a file before opening it.
 *       This handler centralises that discovery across the module's deployment
 *       modes (standalone data server, static manager map, dynamic registry,
 *       and CMS-backed cluster) so callers get a single consistent answer.
 *
 * HOW:  Parse and confine the request path via xrootd_extract_path(), reject
 *       over-deep paths with xrootd_count_path_depth(). In manager_mode (non-
 *       wildcard) try, in order: the collapse-redir cache
 *       (xrootd_redir_cache_lookup), the live server registry (xrootd_srv_select,
 *       seeding the cache on hit), then an async kYR_locate to the CMS parent —
 *       which suspends the stream (XRD_ST_WAITING_CMS, pending registry +
 *       cms_locate_timeout timer) and returns NGX_AGAIN until the reply arrives.
 *       Falling through, consult the static manager_map (xrootd_find_manager_map),
 *       then in data-server mode stat the file beneath conf->rootfd
 *       (xrootd_stat_beneath) — redirecting to an upstream if configured and
 *       missing, else 404 — and enforce read access via xrootd_auth_gate before
 *       formatting the local "Sx..." location from c->local_sockaddr (IPv4/IPv6/
 *       fallback) and replying with xrootd_send_ok.
 */

#include "core/ngx_xrootd_module.h"
#include "net/upstream/upstream.h"
#include "protocols/root/path/op_path.h"
#include "net/manager/registry.h"
#include "net/manager/redir_cache.h"
#include "net/manager/pending.h"
#include "net/cms/cms_internal.h"

#include <arpa/inet.h>

ngx_int_t
xrootd_handle_locate(xrootd_ctx_t *ctx, ngx_connection_t *c,
                     ngx_stream_xrootd_srv_conf_t *conf)
{
    xrdw_locate_req_t    req;
    char                 reqpath_buf[XROOTD_MAX_PATH + 1];
    struct sockaddr_in  *sin;
    char                 loc_buf[256];
    int                  loc_len;
    int                  is_wildcard;
    uint16_t             port;
    char                 access_char;

    /* options: kXR_prefname (0x0100) = prefer DNS names over IPs in response.
     * We always store the server's registered hostname so this is the default.
     * Parse the field so the compiler sees req as used. */
    xrdw_locate_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    (void) req.options;

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

    /* Reject any ".." component (the reference does not normalize ".."); locate
     * resolves through the kernel RESOLVE_BENEATH which would collapse it.
     * The "*" wildcard locate carries no path to traverse. */
    if (!is_wildcard
        && xrootd_reject_dotdot_path(ctx, c, XROOTD_OP_LOCATE, "LOCATE",
                                     reqpath_buf)) {
        return ctx->write_rc;
    }

    if (!is_wildcard && xrootd_count_path_depth(reqpath_buf) != NGX_OK) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_LOCATE);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "path exceeds maximum depth");
    }

    if (conf->manager_mode && !is_wildcard) {

        /* Collapse-redir cache: fast path — single recently-resolved server. */
        if (conf->collapse_redir) {
            char     redir_host[256];
            uint16_t redir_port;
            if (xrootd_redir_cache_lookup(reqpath_buf, redir_host,
                                          sizeof(redir_host), &redir_port)) {
                xrootd_log_access(ctx, c, "LOCATE", reqpath_buf,
                                  "redir-cache", 1, 0, NULL, 0);
                XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);
                return xrootd_send_redirect(ctx, c, redir_host, redir_port);
            }
        }

        /* Registry: redirect to the best available server for this path. */
        {
            char     redir_host[256];
            uint16_t redir_port;
            if (xrootd_srv_select(reqpath_buf, 0, redir_host,
                                  sizeof(redir_host), &redir_port)) {
                if (conf->collapse_redir) {
                    xrootd_redir_cache_insert(reqpath_buf, redir_host,
                                              redir_port,
                                              conf->collapse_redir_ttl);
                }
                xrootd_log_access(ctx, c, "LOCATE", reqpath_buf,
                                  "registry", 1, 0, NULL, 0);
                XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);
                return xrootd_send_redirect(ctx, c, redir_host, redir_port);
            }
        }

        /* Registry miss — ask the CMS parent via kYR_locate. */
        if (conf->cms_ctx != NULL) {
            uint32_t  streamid;

            streamid = ngx_xrootd_cms_next_streamid(conf->cms_ctx);
            if (xrootd_pending_insert(streamid, ngx_pid, c->fd,
                                      c->number,
                                      ctx->cur_streamid,
                                      conf->cms_locate_timeout) == NGX_OK)
            {
                ctx->cms_wait_streamid = streamid;
                ctx->state = XRD_ST_WAITING_CMS;
                ngx_add_timer(c->read, conf->cms_locate_timeout);
                if (ngx_xrootd_cms_send_locate(conf->cms_ctx, streamid,
                                               reqpath_buf) == NGX_OK)
                {
                    return NGX_AGAIN;
                }
                ngx_del_timer(c->read);
                ctx->state = XRD_ST_REQ_HEADER;
                xrootd_pending_remove(streamid, ngx_pid);
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
        struct stat _st;

        if (xrootd_stat_beneath(conf->rootfd, reqpath_buf, &_st) != 0) {
            if (conf->upstream_host.len > 0) {
                xrootd_log_access(ctx, c, "LOCATE", reqpath_buf,
                                  "upstream", 1, 0, NULL, 0);
                XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);
                return xrootd_upstream_start(ctx, c, conf);
            }

            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_LOCATE, "LOCATE",
                              reqpath_buf, "-", kXR_NotFound, "file not found");
        }

        {
            char full_path[PATH_MAX];
            xrootd_beneath_full_path(conf->common.root_canon, reqpath_buf,
                                     full_path, sizeof(full_path));
            if (xrootd_auth_gate(ctx, c, XROOTD_OP_LOCATE, "LOCATE",
                                 reqpath_buf, full_path, conf,
                                 XROOTD_AUTH_READ, 0) != NGX_OK) {
                return ctx->write_rc;
            }
        }
    }

    access_char = conf->common.allow_write ? 'w' : 'r';

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
