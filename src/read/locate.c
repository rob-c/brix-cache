/* ------------------------------------------------------------------ */
/* Endpoint Locate — kXR_locate handler                                     */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_locate opcode — querying endpoint location for a path within the export root. Two modes exist based on manager configuration: static map mode (conf->manager_map configured) returns redirect to registered data server via prefix matching; dynamic registry mode (conf->manager_mode enabled) queries CMS parent via upstream locate request with pending timeout tracking; wildcard mode (path='*') handles global endpoint enumeration requests. Wire format uses ClientLocateRequest payload containing logical path or '*' wildcard.
 *
 * WHY: Locate enables clients to discover which data server holds a specific file without requiring network-wide broadcast — critical for distributed HEP storage architectures where files may be spread across multiple servers in different geographical locations. Static map mode provides fast prefix-based redirection without CMS involvement; dynamic registry mode enables real-time server availability tracking via CMS heartbeat mechanism allowing load-balancing based on current server health status. Wildcard mode handles global endpoint enumeration requests for site-wide file discovery scenarios.
 *
 * HOW: Two-mode locate → parse payload (extract/clean path from ClientLocateRequest) — if wildcard ('*'): handle global enumeration request; if manager_mode enabled + not wildcard: query CMS parent via upstream locate with pending timeout tracking (xrootd_pending_insert); else if static_map configured: prefix-based redirect via xrootd_srv_select() selecting best registered server; return kXR_ok with host:port redirect body payload or kXR_Overloaded error if no available server found. Access-log detail format "registry" for manager mode redirects, "upstream" for CMS query mode. */

/* ------------------------------------------------------------------ */
/* Section: Static Map Redirect                                             */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_handle_locate() performs static map redirect when conf->manager_map is configured and path does not match wildcard ('*'). Uses xrootd_srv_select() to select best registered data server for the requested path based on prefix matching in manager map configuration. Returns kXR_ok with host:port redirect body payload enabling client to reconnect to the identified data server instead of querying this manager node.
 *
 * WHY: Static map provides fast prefix-based redirection without CMS involvement — avoids network round-trip latency when manager nodes have pre-configured prefix-to-server mappings enabling immediate client reconnection to appropriate data server without dynamic availability query overhead. Prefix matching allows hierarchical path organization where subdirectories may be served by different servers than parent directories, enabling geographic distribution of storage assets across multiple sites. */

/* ------------------------------------------------------------------ */
/* Section: Dynamic Registry Query                                          */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_handle_locate() performs dynamic registry query when conf->manager_mode is enabled and path does not match wildcard ('*'). Queries CMS parent via upstream locate request with pending timeout tracking (xrootd_pending_insert) — client enters waiting state (ctx->state = XRD_ST_WAITING_CMS) while CMS server responds with best available data server. Timeout configured via conf->cms_locate_timeout ensures stale queries don't hang indefinitely when CMS response fails or network partition occurs.
 *
 * WHY: Dynamic registry enables real-time server availability tracking via CMS heartbeat mechanism allowing load-balancing based on current server health status rather than static prefix mappings. When servers go offline or become overloaded, dynamic registry can redistribute requests to healthy nodes without requiring configuration changes — critical for high-availability deployments where server maintenance or failures must be transparent to clients. Pending timeout ensures stale queries don't hang indefinitely when CMS response fails or network partition occurs, preventing client connection exhaustion from failed locate attempts. */

/* ------------------------------------------------------------------ */
/* Section: Wildcard Global Enumeration                                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_handle_locate() handles wildcard ('*') requests for global endpoint enumeration — all manager nodes respond to wildcard queries regardless of whether they have the specific file requested, enabling site-wide file discovery scenarios where clients want to know which servers participate in a distributed storage system. Returns kXR_ok with redirect body payload containing this server's host:port identifying it as part of the managed cluster.
 *
 * WHY: Wildcard enumeration enables clients to discover all participating servers in a distributed HEP storage architecture without requiring individual queries against each node — critical for site-wide file discovery scenarios where clients want to know which servers participate in a distributed storage system before attempting specific locate requests. Manager nodes all respond identically to wildcard queries regardless of whether they have the specific file requested, enabling client-side load-balancing decisions based on available server count and geographic distribution. */

/* ---- Function: xrootd_handle_locate() ----
 *
 * WHAT: Handles the kXR_locate opcode — querying endpoint location for a path within the export root supporting two modes: static map redirect (conf->manager_map configured) returns redirect to registered data server via prefix matching; dynamic registry query (conf->manager_mode enabled + not wildcard) queries CMS parent via upstream locate request with pending timeout tracking; wildcard mode (path='*') handles global endpoint enumeration requests. Wire format uses ClientLocateRequest payload containing logical path or '*' wildcard. Returns kXR_ok with host:port redirect body payload or kXR_Overloaded error if no available server found. Access-log detail format "registry" for manager mode redirects, "upstream" for CMS query mode.
 *
 * WHY: Locate enables clients to discover which data server holds a specific file without requiring network-wide broadcast — critical for distributed HEP storage architectures where files may be spread across multiple servers in different geographical locations. Static map mode provides fast prefix-based redirection without CMS involvement; dynamic registry mode enables real-time server availability tracking via CMS heartbeat mechanism allowing load-balancing based on current server health status. Wildcard mode handles global endpoint enumeration requests for site-wide file discovery scenarios.
 *
 * HOW: Two-mode locate → parse payload (extract/clean path from ClientLocateRequest) — if wildcard ('*'): handle global enumeration request; if manager_mode enabled + not wildcard: query CMS parent via upstream locate with pending timeout tracking (xrootd_pending_insert); else if static_map configured: prefix-based redirect via xrootd_srv_select() selecting best registered server; return kXR_ok with host:port redirect body payload or kXR_Overloaded error if no available server found. Access-log detail format "registry" for manager mode redirects, "upstream" for CMS query mode. */

#include "../ngx_xrootd_module.h"
#include "../upstream/upstream.h"
#include "../manager/registry.h"
#include "../manager/redir_cache.h"
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

    if (!is_wildcard && xrootd_count_path_depth(reqpath_buf) != NGX_OK) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_LOCATE);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "path exceeds maximum depth");
    }

    if (conf->manager_mode && !is_wildcard) {
        char     redir_host[256];
        uint16_t redir_port;

        /* Collapse-redir cache: skip CMS for recently resolved paths. */
        if (conf->collapse_redir
            && xrootd_redir_cache_lookup(reqpath_buf, redir_host,
                                         sizeof(redir_host), &redir_port)) {
            xrootd_log_access(ctx, c, "LOCATE", reqpath_buf, "redir-cache",
                              1, 0, NULL, 0);
            XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);
            return xrootd_send_redirect(ctx, c, redir_host, redir_port);
        }

        if (xrootd_srv_select(reqpath_buf, 0, redir_host,
                              sizeof(redir_host), &redir_port)) {
            if (conf->collapse_redir) {
                xrootd_redir_cache_insert(reqpath_buf, redir_host, redir_port,
                                          conf->collapse_redir_ttl);
            }
            xrootd_log_access(ctx, c, "LOCATE", reqpath_buf, "registry",
                              1, 0, NULL, 0);
            XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);
            return xrootd_send_redirect(ctx, c, redir_host, redir_port);
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
        if (!xrootd_resolve_path(c->log, &conf->common.root, reqpath_buf,
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

        if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                                         ctx->identity) != NGX_OK)
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
