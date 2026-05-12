#include "cms_internal.h"
#include "../manager/registry.h"

#include <unistd.h>


static ngx_int_t
ngx_xrootd_cms_send_all(ngx_xrootd_cms_ctx_t *ctx, const u_char *buf,
    size_t len)
{
    ngx_connection_t  *c;
    ssize_t            n;
    size_t             sent;

    c = ctx->connection;
    sent = 0;

    while (sent < len) {
        n = c->send(c, (u_char *) buf + sent, len - sent);

        if (n == NGX_AGAIN || n == 0) {
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        sent += (size_t) n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_xrootd_cms_send_frame(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid,
    u_char code, u_char modifier, const u_char *payload, size_t payload_len)
{
    u_char  hdr[NGX_XROOTD_CMS_HDR_LEN];

    if (ctx->connection == NULL || payload_len > 65535) {
        return NGX_ERROR;
    }

    ngx_xrootd_cms_put32(hdr, streamid);
    hdr[4] = code;
    hdr[5] = modifier;
    ngx_xrootd_cms_put16(hdr + 6, (uint16_t) payload_len);

    if (ngx_xrootd_cms_send_all(ctx, hdr, sizeof(hdr)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (payload_len > 0
        && ngx_xrootd_cms_send_all(ctx, payload, payload_len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_xrootd_cms_send_login(ngx_xrootd_cms_ctx_t *ctx)
{
    u_char     payload[1024];
    u_char    *payload_cursor;
    ngx_str_t  paths;
    size_t     path_len;
    uint32_t   total_gb;
    uint32_t   free_mb;
    uint32_t   util_pct;

    paths = ngx_xrootd_cms_export_paths(ctx->conf);
    path_len = paths.len;
    if (path_len > 512) {
        path_len = 512;
    }

    total_gb = 0;
    free_mb = 0;
    util_pct = 0;
    (void) ngx_xrootd_cms_stat_space(ctx->conf, &total_gb, &free_mb,
                                     &util_pct);

    if (ctx->conf->manager_mode) {
        uint32_t agg_free = 0, agg_util = 0;
        xrootd_srv_aggregate_space(&agg_free, &agg_util);
        if (agg_free > 0 || agg_util > 0) {
            free_mb  = agg_free;
            util_pct = agg_util;
        }
    }

    /*
     * CMS login uses a packed type/value payload, not a C struct.  Keep writes
     * in wire order so the field sequence can be checked against the protocol
     * notes without mentally following pointer arithmetic.
     */
    payload_cursor = payload;
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor,
                                              CMS_LOGIN_VERSION);
    payload_cursor = ngx_xrootd_cms_put_int(
        payload_cursor,
        CMS_LOGIN_MODE
        | (ctx->conf->manager_mode ? CMS_LOGIN_MODE_MANAGER : 0));
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor,
                                            (uint32_t) getpid());
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, total_gb);
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, free_mb);
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor,
                                            NGX_XROOTD_CMS_MIN_FREE_MB);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 1);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor,
                                              (uint16_t) util_pct);
    payload_cursor = ngx_xrootd_cms_put_short(
        payload_cursor, (uint16_t) ctx->conf->listen_port);

    /* Reserved protocol fields currently sent as zero. */
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 0);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 0);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor,
                                              (uint16_t) path_len);

    if (path_len > 0) {
        ngx_memcpy(payload_cursor, paths.data, path_len);
        payload_cursor += path_len;
    }

    /* Empty manager host/port trailer fields. */
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 0);
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 0);

    return ngx_xrootd_cms_send_frame(ctx, 0, CMS_RR_LOGIN, 0, payload,
                                     (size_t) (payload_cursor - payload));
}


ngx_int_t
ngx_xrootd_cms_send_load(ngx_xrootd_cms_ctx_t *ctx)
{
    u_char    payload[32];
    u_char   *payload_cursor;
    uint32_t  free_mb;

    free_mb = 0;
    (void) ngx_xrootd_cms_stat_space(ctx->conf, NULL, &free_mb, NULL);

    if (ctx->conf->manager_mode) {
        uint32_t agg_free = 0, agg_util = 0;
        xrootd_srv_aggregate_space(&agg_free, &agg_util);
        if (agg_free > 0) {
            free_mb = agg_free;
        }
    }

    payload_cursor = payload;
    payload_cursor = ngx_xrootd_cms_put_short(payload_cursor, 6);
    ngx_memzero(payload_cursor, 6);
    payload_cursor += 6;
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, free_mb);

    return ngx_xrootd_cms_send_frame(ctx, 0, CMS_RR_LOAD, 0, payload,
                                     (size_t) (payload_cursor - payload));
}


ngx_int_t
ngx_xrootd_cms_send_avail(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid)
{
    u_char    payload[16];
    u_char   *payload_cursor;
    uint32_t  free_mb;
    uint32_t  util_pct;

    free_mb = 0;
    util_pct = 0;
    (void) ngx_xrootd_cms_stat_space(ctx->conf, NULL, &free_mb, &util_pct);

    if (ctx->conf->manager_mode) {
        uint32_t agg_free = 0, agg_util = 0;
        xrootd_srv_aggregate_space(&agg_free, &agg_util);
        if (agg_free > 0 || agg_util > 0) {
            free_mb  = agg_free;
            util_pct = agg_util;
        }
    }

    payload_cursor = payload;
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, free_mb);
    payload_cursor = ngx_xrootd_cms_put_int(payload_cursor, util_pct);

    return ngx_xrootd_cms_send_frame(ctx, streamid, CMS_RR_AVAIL, 0, payload,
                                     (size_t) (payload_cursor - payload));
}


ngx_int_t
ngx_xrootd_cms_send_pong(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid)
{
    return ngx_xrootd_cms_send_frame(ctx, streamid, CMS_RR_PONG, 0, NULL, 0);
}


uint32_t
ngx_xrootd_cms_next_streamid(ngx_xrootd_cms_ctx_t *ctx)
{
    if (ctx->next_streamid == UINT32_MAX) {
        ctx->next_streamid = 1;
    } else {
        ctx->next_streamid++;
    }
    return ctx->next_streamid;
}


ngx_int_t
ngx_xrootd_cms_send_locate(ngx_xrootd_cms_ctx_t *ctx,
    uint32_t streamid, const char *path)
{
    u_char  payload[XROOTD_SRV_MAX_PATHS];
    size_t  plen;

    plen = ngx_strlen(path) + 1;   /* include NUL terminator */
    if (plen > sizeof(payload)) {
        return NGX_ERROR;
    }

    ngx_memcpy(payload, path, plen);
    return ngx_xrootd_cms_send_frame(ctx, streamid, CMS_RR_LOCATE, 0,
                                     payload, plen);
}
