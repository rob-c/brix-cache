#include "query_internal.h"

/*
 * kXR_QStats, kXR_Qxattr, kXR_QFinfo, and plugin/fctl-style queries.
 */

static ngx_int_t
xrootd_query_arg_missing(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *tag, ngx_uint_t op)
{
    xrootd_log_access(ctx, c, "QUERY", "-", tag,
                      0, kXR_ArgMissing,
                      "Required query argument not present", 0);
    XROOTD_OP_ERR(ctx, op);
    return xrootd_send_error(ctx, c, kXR_ArgMissing,
                             "Required query argument not present");
}


static ngx_int_t
xrootd_query_fsctl_unsupported(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *path, const char *tag, ngx_uint_t op)
{
    xrootd_log_access(ctx, c, "QUERY", path ? path : "-", tag,
                      0, kXR_Unsupported,
                      "FSctl operation not supported", 0);
    XROOTD_OP_ERR(ctx, op);
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "FSctl operation not supported");
}


static ngx_int_t
xrootd_query_fctl_unsupported(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *path, const char *tag, ngx_uint_t op)
{
    xrootd_log_access(ctx, c, "QUERY", path ? path : "-", tag,
                      0, kXR_Unsupported,
                      "fctl operation not supported", 0);
    XROOTD_OP_ERR(ctx, op);
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "fctl operation not supported");
}


static ngx_flag_t
xrootd_query_payload_equals(xrootd_ctx_t *ctx, const char *text)
{
    size_t len, text_len;

    if (ctx->payload == NULL) {
        return 0;
    }

    len = ctx->cur_dlen;
    if (len > 0 && ctx->payload[len - 1] == '\0') {
        len--;
    }

    text_len = strlen(text);
    return (len == text_len
            && ngx_memcmp(ctx->payload, text, text_len) == 0);
}

ngx_int_t
xrootd_query_stats(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    char   resp[1024];
    int    port = 0;
    long   conns_active = 0, conns_total = 0;
    long   bytes_in = 0, bytes_out = 0;
    time_t now = time(NULL);
    int    n;

    if (ctx->metrics) {
        port = (int) ctx->metrics->port;
        conns_active = (long) ctx->metrics->connections_active;
        conns_total = (long) ctx->metrics->connections_total;
        bytes_in = (long) ctx->metrics->bytes_rx_total;
        bytes_out = (long) ctx->metrics->bytes_tx_total;
    }

    if (port == 0 && c->local_sockaddr != NULL) {
        if (c->local_sockaddr->sa_family == AF_INET) {
            struct sockaddr_in *sin =
                (struct sockaddr_in *) c->local_sockaddr;
            port = (int) ntohs(sin->sin_port);
        } else if (c->local_sockaddr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 =
                (struct sockaddr_in6 *) c->local_sockaddr;
            port = (int) ntohs(sin6->sin6_port);
        }
    }

    n = snprintf(resp, sizeof(resp) - 1,
        "<statistics id=\"xrootd\" ver=\"5.2.0\" tos=\"%ld\" pgm=\"nginx-xrootd\">"
        "<stats id=\"info\"><host>localhost</host><port>%d</port>"
        "<name>nginx-xrootd</name></stats>"
        "<stats id=\"link\"><num>%ld</num><tot>%ld</tot>"
        "<in>%ld</in><out>%ld</out><ctime>0</ctime>"
        "<ltime>0</ltime><sfps>0</sfps></stats>"
        "</statistics>",
        (long) now, port,
        conns_active, conns_total,
        bytes_in, bytes_out);

    xrootd_log_access(ctx, c, "QUERY", "-", "stats", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_STATS);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) (n + 1));
}


ngx_int_t
xrootd_query_xattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    char    pathbuf[XROOTD_MAX_PATH + 1];
    char    resolved[PATH_MAX];
    char    resp[4096];
    int     pos = 0;
    char    raw_list[4096];
    ssize_t list_sz;

    if (ctx->cur_dlen == 0 || ctx->payload == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
        return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                 "xattr: path required");
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             pathbuf, sizeof(pathbuf), 1)) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "invalid path");
    }

    if (!xrootd_resolve_path(c->log, &conf->root, pathbuf,
                             resolved, sizeof(resolved))) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
        return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
    }

    if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_READ) != NGX_OK) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized, "not authorized");
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                            ctx->vo_list) != NGX_OK) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "VO not authorized");
    }

    list_sz = listxattr(resolved, raw_list, sizeof(raw_list));
    if (list_sz > 0) {
        char *lp = raw_list;
        char *lend = raw_list + list_sz;

        while (lp < lend && pos < (int) sizeof(resp) - 256) {
            size_t nlen = strlen(lp);

            if (strncmp(lp, "user.U.", 7) == 0 && nlen > 7) {
                char    val[1024];
                ssize_t vlen;

                vlen = getxattr(resolved, lp, val, sizeof(val) - 1);
                if (vlen >= 0) {
                    val[vlen] = '\0';
                    pos += snprintf(resp + pos, sizeof(resp) - pos - 1,
                                    "%s=%.*s\n", lp + 5, (int) vlen, val);
                }
            }

            lp += nlen + 1;
        }
    }

    xrootd_log_access(ctx, c, "QUERY", pathbuf, "xattr", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_XATTR);
    if (pos == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    return xrootd_send_ok(ctx, c, resp, (uint32_t) (pos + 1));
}


ngx_int_t
xrootd_query_finfo(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    xrootd_log_access(ctx, c, "QUERY", "-", "finfo", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_FINFO);
    return xrootd_send_ok(ctx, c, "0", 2);
}


ngx_int_t
xrootd_query_visa(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ClientQueryRequest *req)
{
    int       idx;
    ngx_int_t rc;

    idx = (int) (unsigned char) req->fhandle[0];
    if (!xrootd_validate_file_handle(ctx, c, idx, "QUERY",
                                     XROOTD_OP_QUERY_VISA, &rc)) {
        return rc;
    }

    return xrootd_query_fctl_unsupported(ctx, c, ctx->files[idx].path,
                                         "visa", XROOTD_OP_QUERY_VISA);
}


ngx_int_t
xrootd_query_opaque(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_query_arg_missing(ctx, c, "opaque",
                                        XROOTD_OP_QUERY_OPAQUE);
    }

    return xrootd_query_fsctl_unsupported(ctx, c, "-", "opaque",
                                          XROOTD_OP_QUERY_OPAQUE);
}


ngx_int_t
xrootd_query_opaquf(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    char pathbuf[XROOTD_MAX_PATH + 1];
    char resolved[PATH_MAX];

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_query_arg_missing(ctx, c, "opaquf",
                                        XROOTD_OP_QUERY_OPAQUF);
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             pathbuf, sizeof(pathbuf), 1)) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_OPAQUF, "QUERY", "-",
                          "opaquf", kXR_ArgInvalid, "invalid path");
    }

    if (!xrootd_resolve_path_noexist(c->log, &conf->root, pathbuf,
                                     resolved, sizeof(resolved))) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_OPAQUF, "QUERY", pathbuf,
                          "opaquf", kXR_NotFound, "invalid path");
    }

    if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_READ) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_OPAQUF, "QUERY", pathbuf,
                          "opaquf", kXR_NotAuthorized, "not authorized");
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                            ctx->vo_list) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_OPAQUF, "QUERY", pathbuf,
                          "opaquf", kXR_NotAuthorized, "VO not authorized");
    }

    return xrootd_query_fsctl_unsupported(ctx, c, pathbuf, "opaquf",
                                          XROOTD_OP_QUERY_OPAQUF);
}


ngx_int_t
xrootd_query_opaqug(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ClientQueryRequest *req)
{
    int       idx;
    ngx_int_t rc;

    idx = (int) (unsigned char) req->fhandle[0];
    if (!xrootd_validate_file_handle(ctx, c, idx, "QUERY",
                                     XROOTD_OP_QUERY_OPAQUG, &rc)) {
        return rc;
    }

    if (xrootd_query_payload_equals(ctx, "ofs.tpc cancel")) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_OPAQUG, "QUERY",
                          ctx->files[idx].path, "opaqug",
                          kXR_FSError, "tpc operation not found");
    }

    return xrootd_query_fctl_unsupported(ctx, c, ctx->files[idx].path,
                                         "opaqug", XROOTD_OP_QUERY_OPAQUG);
}
