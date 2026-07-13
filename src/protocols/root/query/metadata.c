#include "query_internal.h"
#include "core/ident.h"

/*
 * WHAT: kXR_QStats, kXR_Qxattr, kXR_QFinfo, kXR_QFSinfo, kXR_Qvisa, kXR_Qopaque, kXR_Qopaquf, kXR_Qopaqug — metadata and plugin-style query handlers.
 *       QStats returns XML-formatted server statistics (connections, bytes, uptime); Qxattr lists extended attributes on a file path;
 *       QFinfo returns "0" as placeholder; QFSinfo delegates to space handler; Qvisa/opaques return FSctl/fctl unsupported responses
 *       matching reference XRootD behavior since nginx-xrootd does not embed the XrdOfs plugin layer.
 *
 * WHY:  These queries provide server observability (stats), filesystem metadata (xattr, finfo), and extension hooks (visa/opaques) that clients use
 *       to discover server capabilities and file properties. QStats XML matches reference format for monitoring dashboards; xattr returns oss.* key-value
 *       pairs including file type, size, timestamps, and user.U.* extended attributes for HEP data provenance tracking. Opaque queries return unsupported
 *       to maintain protocol compatibility with clients that send FSctl/fctl requests expecting a consistent response shape.
 *
 * HOW:  Three shared static helpers handle common patterns: arg_missing() logs + sends kXR_ArgMissing error; fsctl_unsupported()/fctl_unsupported()
 *       log + send kXR_Unsupported for plugin operations. payload_equals() compares wire payload against expected text with null-termination handling.
 * Public APIs follow security chain (extract_path → resolve_path → authdb → vo_acl) where applicable, then delegate to stat/listxattr/getxattr syscalls
 * or return placeholder/unsupported responses. QStats reads metrics struct + local socket address for port extraction; xattr builds oss.* key-value string
 * with listxattr iteration filtering user.U.* prefixes.
 */

static ngx_int_t
brix_query_arg_missing(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *tag, ngx_uint_t op)
{
    BRIX_RETURN_ERR(ctx, c, op, "QUERY", "-", tag,
                      kXR_ArgMissing, "Required query argument not present");
}

static ngx_int_t
brix_query_fsctl_unsupported(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *path, const char *tag, ngx_uint_t op)
{
    BRIX_RETURN_ERR(ctx, c, op, "QUERY", path ? path : "-", tag,
                      kXR_Unsupported, "FSctl operation not supported");
}

static ngx_int_t
brix_query_fctl_unsupported(brix_ctx_t *ctx, ngx_connection_t *c,
    const char *path, const char *tag, ngx_uint_t op)
{
    BRIX_RETURN_ERR(ctx, c, op, "QUERY", path ? path : "-", tag,
                      kXR_Unsupported, "fctl operation not supported");
}

static ngx_flag_t
brix_query_payload_equals(brix_ctx_t *ctx, const char *text)
{
    size_t len, text_len;

    if (ctx->recv.payload == NULL) {
        return 0;
    }

    len = ctx->recv.cur_dlen;
    if (len > 0 && ctx->recv.payload[len - 1] == '\0') {
        len--;
    }

    text_len = strlen(text);
    return (len == text_len
            && ngx_memcmp(ctx->recv.payload, text, text_len) == 0);
}

/* brix_query_stats — kXR_QStats: XML server statistics (active/total
 * connections, bytes rx/tx, timestamp, listening port). */
ngx_int_t
brix_query_stats(brix_ctx_t *ctx, ngx_connection_t *c)
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
        "<statistics id=\"xrootd\" ver=\"" BRIX_SERVER_VERSION "\""
        " tos=\"%ld\" pgm=\"" BRIX_SERVER_NAME "\">"
        "<stats id=\"info\"><host>localhost</host><port>%d</port>"
        "<name>" BRIX_SERVER_NAME "</name></stats>"
        "<stats id=\"link\"><num>%ld</num><tot>%ld</tot>"
        "<in>%ld</in><out>%ld</out><ctime>0</ctime>"
        "<ltime>0</ltime><sfps>0</sfps></stats>"
        "</statistics>",
        (long) now, port,
        conns_active, conns_total,
        bytes_in, bytes_out);

    brix_log_access(ctx, c, "QUERY", "-", "stats", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_QUERY_STATS);
    return brix_send_ok(ctx, c, resp, (uint32_t) (n + 1));
}

/* brix_query_xattr — kXR_Qxattr: list a path's extended attributes through the
 * full security chain (extract → resolve → authdb → VO ACL → stat), returning the
 * oss.* key-values plus any user.U.*-prefixed xattrs. */
ngx_int_t
brix_query_xattr(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char              pathbuf[BRIX_MAX_PATH + 1];
    char              full_path[PATH_MAX];
    char              resp[4096];
    int               pos = 0;
    char              raw_list[4096];
    ssize_t           list_sz;
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;
    char              ftype;
    char              facc;

    if (ctx->recv.cur_dlen == 0 || ctx->recv.payload == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_XATTR);
        return brix_send_error(ctx, c, kXR_ArgMissing,
                                 "xattr: path required");
    }

    if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                             pathbuf, sizeof(pathbuf), 1)) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_XATTR);
        return brix_send_error(ctx, c, kXR_ArgInvalid, "invalid path");
    }

    /* phase74-fp: pathbuf is the request path, full_path the output buf. */
    brix_beneath_full_path(conf->common.root_canon, pathbuf,  /* NOLINT(readability-suspicious-call-argument) */
                              full_path, sizeof(full_path));

    if (brix_auth_gate(ctx, c, BRIX_OP_QUERY_XATTR, "QUERY",
                         pathbuf, full_path, conf,
                         BRIX_AUTH_READ, 0) != NGX_OK) {
        return ctx->write_rc;
    }

    /* Stat + xattr list/get all flow through the VFS (one ctx, confined to the
     * export root). probe (follow) replaces the raw stat; the OP_STAT metric is
     * suppressed (probe) so only the enclosing QUERY op is accounted. */
    brix_vfs_ctx_init(&vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL, conf->common.allow_write,
        0 /* is_tls */, NULL, full_path);

    if (brix_vfs_probe(&vctx, 0 /* follow */, &vst) != NGX_OK) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_XATTR);
        return brix_send_error(ctx, c, brix_kxr_from_errno(errno),
                                 strerror(errno));
    }

    if (vst.is_regular) {
        ftype = 'f';
    } else if (vst.is_directory) {
        ftype = 'd';
    } else {
        ftype = 'o';
    }

    facc = (vst.mode & S_IWUSR) ? 'w' : 'r';

    pos = snprintf(resp, sizeof(resp) - 1,
                   "oss.cgroup=default&oss.type=%c&oss.used=%lld"
                   "&oss.mt=%ld&oss.ct=%ld&oss.at=%ld"
                   "&oss.u=*&oss.g=*&oss.fs=%c",
                   ftype, (long long) vst.size,
                   (long) vst.mtime, (long) vst.ctime, (long) vst.atime,
                   facc);

    list_sz = brix_vfs_listxattr(&vctx, raw_list, sizeof(raw_list));
    if (list_sz > 0) {
        char *lp = raw_list;
        char *lend = raw_list + list_sz;

        while (lp < lend && pos < (int) sizeof(resp) - 256) {
            size_t nlen = strlen(lp);

            if (strncmp(lp, "user.U.", 7) == 0 && nlen > 7) {
                char    val[1024];
                ssize_t vlen;

                vlen = brix_vfs_getxattr(&vctx, lp, val, sizeof(val) - 1);
                if (vlen >= 0) {
                    val[vlen] = '\0';
                    pos += snprintf(resp + pos, sizeof(resp) - pos - 1,
                                    "&%s=%.*s", lp + 5, (int) vlen, val);
                }
            }

            lp += nlen + 1;
        }
    }

    brix_log_access(ctx, c, "QUERY", pathbuf, "xattr", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_QUERY_XATTR);

    return brix_send_ok(ctx, c, resp, (uint32_t) (pos + 1));
}

/* brix_query_finfo — kXR_QFinfo: returns "0" placeholder (matches reference
 * XRootD, which serves this via the XrdOfs plugin layer nginx-xrootd lacks). */
ngx_int_t
brix_query_finfo(brix_ctx_t *ctx, ngx_connection_t *c)
{
    brix_log_access(ctx, c, "QUERY", "-", "finfo", 1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_QUERY_FINFO);
    return brix_send_ok(ctx, c, "0", 2);
}

/* brix_query_visa — kXR_Qvisa: validate the fhandle, then return FSctl-
 * unsupported (matches reference XRootD without the XrdOfs plugin layer). */
ngx_int_t
brix_query_visa(brix_ctx_t *ctx, ngx_connection_t *c,
    const xrdw_query_req_t *req)
{
    int       idx;
    ngx_int_t rc;

    idx = (int) (unsigned char) req->fhandle[0];
    if (!brix_validate_file_handle(ctx, c, idx, "QUERY",
                                     BRIX_OP_QUERY_VISA, &rc)) {
        return rc;
    }

    return brix_query_fctl_unsupported(ctx, c, ctx->files[idx].path,
                                         "visa", BRIX_OP_QUERY_VISA);
}

/* brix_query_opaque — kXR_Qopaque: validate payload presence, then return
 * FSctl-unsupported (matches reference XRootD without the XrdOfs plugin layer). */
ngx_int_t
brix_query_opaque(brix_ctx_t *ctx, ngx_connection_t *c)
{
    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        return brix_query_arg_missing(ctx, c, "opaque",
                                        BRIX_OP_QUERY_OPAQUE);
    }

    return brix_query_fsctl_unsupported(ctx, c, "-", "opaque",
                                          BRIX_OP_QUERY_OPAQUE);
}

/* brix_query_opaquf — kXR_Qopaquf: run the security chain (extract →
 * resolve_noexist → authdb → VO ACL), then return fctl-unsupported (reference parity). */
ngx_int_t
brix_query_opaquf(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char pathbuf[BRIX_MAX_PATH + 1];
    char full_path[PATH_MAX];

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        return brix_query_arg_missing(ctx, c, "opaquf",
                                        BRIX_OP_QUERY_OPAQUF);
    }

    if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                             pathbuf, sizeof(pathbuf), 1)) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_QUERY_OPAQUF, "QUERY", "-",
                          "opaquf", kXR_ArgInvalid, "invalid path");
    }

    /* phase74-fp: pathbuf is the request path, full_path the output buf. */
    brix_beneath_full_path(conf->common.root_canon, pathbuf,  /* NOLINT(readability-suspicious-call-argument) */
                              full_path, sizeof(full_path));

    if (brix_auth_gate(ctx, c, BRIX_OP_QUERY_OPAQUF, "QUERY",
                         pathbuf, full_path, conf,
                         BRIX_AUTH_READ, 0) != NGX_OK) {
        return ctx->write_rc;
    }

    return brix_query_fsctl_unsupported(ctx, c, pathbuf, "opaquf",
                                          BRIX_OP_QUERY_OPAQUF);
}

/* brix_query_opaqug — kXR_Qopaqug: validate the fhandle and detect TPC
 * cancellation ("ofs.tpc cancel", else kXR_FSError), then return fctl-unsupported. */
ngx_int_t
brix_query_opaqug(brix_ctx_t *ctx, ngx_connection_t *c,
    const xrdw_query_req_t *req)
{
    int       idx;
    ngx_int_t rc;

    idx = (int) (unsigned char) req->fhandle[0];
    if (!brix_validate_file_handle(ctx, c, idx, "QUERY",
                                     BRIX_OP_QUERY_OPAQUG, &rc)) {
        return rc;
    }

    if (brix_query_payload_equals(ctx, "ofs.tpc cancel")) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_QUERY_OPAQUG, "QUERY",
                          ctx->files[idx].path, "opaqug",
                          kXR_FSError, "tpc operation not found");
    }

    return brix_query_fctl_unsupported(ctx, c, ctx->files[idx].path,
                                         "opaqug", BRIX_OP_QUERY_OPAQUG);

}
