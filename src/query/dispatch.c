#include "query_internal.h"

/*
 * kXR_query dispatcher. The infotype field selects a query sub-protocol.
 */

ngx_int_t
xrootd_handle_query(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientQueryRequest *req = (ClientQueryRequest *) ctx->hdr_buf;
    uint16_t            infotype = ntohs(req->infotype);

    if (infotype == kXR_QPrep) {
        return xrootd_query_prep_status(ctx, c, conf);
    }

    if (infotype == kXR_Qcksum) {
        return xrootd_query_cksum(ctx, c, conf, req);
    }

    if (infotype == kXR_Qckscan) {
        return xrootd_query_ckscan(ctx, c, conf);
    }

    if (infotype == kXR_Qspace) {
        return xrootd_query_space(ctx, c, conf);
    }

    if (infotype == kXR_Qconfig) {
        return xrootd_query_config(ctx, c, conf);
    }

    if (infotype == kXR_QStats) {
        return xrootd_query_stats(ctx, c);
    }

    if (infotype == kXR_Qxattr) {
        return xrootd_query_xattr(ctx, c, conf);
    }

    if (infotype == kXR_QFinfo) {
        return xrootd_query_finfo(ctx, c);
    }

    if (infotype == kXR_QFSinfo) {
        return xrootd_query_fsinfo(ctx, c, conf);
    }

    if (infotype == kXR_Qvisa) {
        if (ctx->cur_dlen != 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_VISA, "QUERY",
                              "-", "visa", kXR_ArgInvalid,
                              "Invalid information query type code");
        }

        return xrootd_query_visa(ctx, c, req);
    }

    if (infotype == kXR_Qopaque) {
        return xrootd_query_opaque(ctx, c);
    }

    if (infotype == kXR_Qopaquf) {
        return xrootd_query_opaquf(ctx, c, conf);
    }

    if (infotype == kXR_Qopaqug) {
        return xrootd_query_opaqug(ctx, c, req);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_query unsupported infotype=%d",
                   (int) infotype);
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "query type not supported");
}
