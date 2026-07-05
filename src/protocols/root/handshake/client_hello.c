#include "handshake.h"
#include "core/compat/alloc_guard.h"

/*
 * brix_process_handshake
 *
 * Validates the 20-byte client handshake and sends the server reply.
 *
 * In XRootD v5 the client sends handshake + kXR_protocol together in a
 * single 44-byte TCP segment. We send a proper ServerResponseHdr
 * (streamid={0,0}, status=ok, dlen=8) followed by 8 bytes of protover+msgval.
 */
ngx_int_t
brix_process_handshake(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ClientInitHandShake  *hs;
    ServerResponseHdr    *hdr;
    u_char               *buf;
    u_char               *body;
    size_t                total;

    /* Fixed v5-compatible body: protocol version + server role. */
    static const size_t BODY_LEN = 8;

    hs = (ClientInitHandShake *) ctx->recv.hdr_buf;

    /*
     * The client hello has mostly fixed magic values; we only validate the
     * fields this implementation actually relies on before switching into the
     * normal request/response framing.
     */
    if (ntohl(hs->fourth) != 4 || ntohl(hs->fifth) != ROOTD_PQ) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: invalid handshake magic "
                      "(fourth=%u fifth=%u)",
                      ntohl(hs->fourth), ntohl(hs->fifth));
        return NGX_ERROR;
    }

    total = XRD_RESPONSE_HDR_LEN + BODY_LEN;
    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    /* The initial reply uses streamid={0,0} because no request header exists yet. */
    hdr = (ServerResponseHdr *) buf;
    hdr->streamid[0] = 0;
    hdr->streamid[1] = 0;
    hdr->status = htons(kXR_ok);
    hdr->dlen = htonl((kXR_unt32) BODY_LEN);

    /* Body layout is exactly two 32-bit words: protocol version then server type. */
    body = buf + XRD_RESPONSE_HDR_LEN;
    *(kXR_unt32 *)(body + 0) = htonl(kXR_PROTOCOLVERSION);
    *(kXR_unt32 *)(body + 4) = htonl(kXR_DataServer);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: handshake ok, sending standard-format response");

    return brix_queue_response(ctx, c, buf, total);
}
