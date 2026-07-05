/*
 * WHAT: Dispatch the kXR_query opcode to one of 14+ sub-handlers based on the request's infotype field. Each infotype value routes to a specialized handler: checksum computation, filesystem space inquiry, server configuration query, statistics collection, extended attribute listing, file info retrieval, and various opaque/visa extension hooks. Returns kXR_Unsupported for unrecognized infotypes with debug logging.
 */

/* WHY: The XRootD query protocol consolidates diverse server-side operations into a single opcode (kXR_query) rather than requiring separate opcodes for each operation type. This reduces wire protocol complexity while enabling flexible sub-protocol extension — new query types can be added by registering handlers without changing the core dispatcher or client code. The typedef struct brix_ckscan_aio_t and extern declarations cross-reference checksum scan AIO infrastructure defined in separate files (checksum_ckscan_common.c, checksum_ckscan_async.c) to maintain modular architecture while keeping dispatcher self-contained. */

/* HOW: Sequential infotype comparison chain using ntohs() to convert big-endian 16-bit value from wire format into host byte order. Each if-block calls a dedicated handler function (brix_query_prep_status through brix_query_opaqug) — handlers return NGX_OK/NGX_ERROR or send error responses directly. The last kXR_Qvisa case includes an additional precondition check: ctx->recv.cur_dlen must be zero (no pending data length) before proceeding to visa query. After all comparisons, debug log the unsupported infotype value and call brix_send_error() with kXR_Unsupported status. */

#include "query_internal.h"
#include "protocols/ssi/ssi.h"   /* §7 XrdSsi response-wait via kXR_query(Qopaqug) */

/*
 * kXR_query dispatcher. The infotype field selects a query sub-protocol.
 */

ngx_int_t
brix_handle_query(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    xrdw_query_req_t    req;
    uint16_t            infotype;

    xrdw_query_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    infotype = req.infotype;

    if (infotype == kXR_QPrep) {
        return brix_query_prep_status(ctx, c, conf);
    }

    if (infotype == kXR_Qcksum) {
        return brix_query_cksum(ctx, c, conf, &req);
    }

    if (infotype == kXR_Qckscan) {
        return brix_query_ckscan(ctx, c, conf);
    }

    if (infotype == kXR_Qspace) {
        return brix_query_space(ctx, c, conf);
    }

    if (infotype == kXR_Qconfig) {
        return brix_query_config(ctx, c, conf);
    }

    if (infotype == kXR_QStats) {
        return brix_query_stats(ctx, c);
    }

    if (infotype == kXR_Qxattr) {
        return brix_query_xattr(ctx, c, conf);
    }

    if (infotype == kXR_QFinfo) {
        return brix_query_finfo(ctx, c);
    }

    if (infotype == kXR_QFSinfo) {
        return brix_query_fsinfo(ctx, c, conf);
    }

    if (infotype == kXR_Qvisa) {
        if (ctx->recv.cur_dlen != 0) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_QUERY_VISA, "QUERY",
                              "-", "visa", kXR_ArgInvalid,
                              "Invalid information query type code");
        }

        return brix_query_visa(ctx, c, &req);
    }

    if (infotype == kXR_Qopaque) {
        return brix_query_opaque(ctx, c);
    }

    if (infotype == kXR_Qopaquf) {
        return brix_query_opaquf(ctx, c, conf);
    }

    if (infotype == kXR_Qopaqug) {
        /* §7 XrdSsi: libXrdSsi waits for / cancels a response with a
         * File::Fcntl == kXR_query(kXR_Qopaqug) whose fhandle is the SSI session
         * and whose body is an XrdSsiRRInfo. Route those to the SSI engine; all
         * other opaqug queries keep the generic handler. */
        int fh = (int) (unsigned char) req.fhandle[0];
        if (fh >= 0 && fh < BRIX_MAX_FILES && ctx->files[fh].ssi != NULL) {
            return brix_ssi_query(ctx, c, fh, ctx->recv.payload, ctx->recv.cur_dlen);
        }
        return brix_query_opaqug(ctx, c, &req);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXR_query unsupported infotype=%d",
                   (int) infotype);
    return brix_send_error(ctx, c, kXR_Unsupported,
                             "query type not supported");
}
