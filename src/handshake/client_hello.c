#include "handshake.h"
#include "../compat/alloc_guard.h"

/* ------------------------------------------------------------------ */
/* Initial Handshake — TCP Connection Entry Point                        */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the initial XRootD handshake — the first interaction between a client and server after raw TCP connection establishment. The client sends a 20-byte ClientInitHandShake containing magic values that identify itself as an XRootD v5+ compatible client. The server validates these magic values, then returns a fixed 8-byte ServerResponseBody containing protocol version (kXR_PROTOCOLVERSION) and server role (kXR_DataServer).
 *
 * WHY: This handshake establishes protocol compatibility before any further interaction can occur. In XRootD v5+, clients send handshake + kXR_protocol together in a single 44-byte TCP segment, so the server must respond with proper ServerResponseHdr framing immediately to enable normal request/response communication. The streamid={0,0} response indicates no prior request exists — all subsequent opcodes will use their own streamid values.
 *
 * HOW: Two-phase handshake → validate client magic values (fourth=4 AND fifth=ROOTD_PQ) — reject with NGX_ERROR if invalid — build ServerResponseHdr with streamid={0,0}, status=kXR_ok, dlen=8 — populate body with kXR_PROTOCOLVERSION + kXR_DataServer — queue response via xrootd_queue_response(). Only the two magic fields are validated; other handshake bytes are accepted without check since this implementation relies solely on these values. */

/* ------------------------------------------------------------------ */
/* Section: Handshake Validation                                          */
/* ------------------------------------------------------------------ */
/*
 * WHAT: The client hello contains mostly fixed magic values that identify XRootD v5+ protocol compatibility. This validation only checks the two fields this implementation actually relies on before switching into normal request/response framing: fourth=4 (protocol version indicator) and fifth=ROOTD_PQ (XRootD identifier). Invalid magic values cause immediate rejection with NGX_ERROR, preventing any further interaction from proceeding.
 *
 * WHY: Ensures protocol compatibility at connection establishment time. Without validation, clients using incompatible protocol versions could attempt unsupported opcodes or send malformed payloads that would confuse the request/response framing layer. The four=4 and fifth=ROOTD_PQ values are fixed constants in XRootD v5+ — any deviation indicates an incompatible client implementation. */

/* ------------------------------------------------------------------ */
/* Section: Handshake Response Body                                       */
/* ------------------------------------------------------------------ */
/*
 * WHAT: The handshake response body is exactly two 32-bit words encoded as big-endian integers: kXR_PROTOCOLVERSION followed by kXR_DataServer. These are the first eight bytes of every server reply and establish the protocol version and server role before any further interaction can proceed. The ServerResponseHdr uses streamid={0,0} because no prior request header exists at this stage — subsequent opcodes will use their own streamid values in their ClientRequestHeaders.
 *
 * WHY: Provides clients with immediate confirmation that they're communicating with a compatible XRootD data server. The protocol version enables clients to determine which opcode set is available; the kXR_DataServer role indicates this node serves files locally rather than redirecting requests (that would be kXR_isManager). */

/* ---- Function: xrootd_process_handshake() ----
 *
 * WHAT: Handles the initial XRootD handshake — validates 20-byte client ClientInitHandShake magic values (fourth=4 AND fifth=ROOTD_PQ), then returns a fixed 8-byte ServerResponseBody containing protocol version (kXR_PROTOCOLVERSION) and server role (kXR_DataServer). Uses streamid={0,0} in the ServerResponseHdr because no prior request header exists at this stage. Only two magic fields are validated; other handshake bytes are accepted without check since this implementation relies solely on these values for protocol compatibility determination.
 *
 * WHY: Establishes protocol compatibility before any further interaction can occur. In XRootD v5+, clients send handshake + kXR_protocol together in a single 44-byte TCP segment, so the server must respond with proper ServerResponseHdr framing immediately to enable normal request/response communication. The streamid={0,0} response indicates no prior request exists — all subsequent opcodes will use their own streamid values.
 *
 * HOW: Two-phase handshake → validate client magic values (fourth=4 AND fifth=ROOTD_PQ) — reject with NGX_ERROR if invalid — build ServerResponseHdr with streamid={0,0}, status=kXR_ok, dlen=8 — populate body with kXR_PROTOCOLVERSION + kXR_DataServer — queue response via xrootd_queue_response(). */

/*
 * xrootd_process_handshake
 *
 * Validates the 20-byte client handshake and sends the server reply.
 *
 * In XRootD v5 the client sends handshake + kXR_protocol together in a
 * single 44-byte TCP segment. We send a proper ServerResponseHdr
 * (streamid={0,0}, status=ok, dlen=8) followed by 8 bytes of protover+msgval.
 */
ngx_int_t
xrootd_process_handshake(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientInitHandShake  *hs;
    ServerResponseHdr    *hdr;
    u_char               *buf;
    u_char               *body;
    size_t                total;

    /* Fixed v5-compatible body: protocol version + server role. */
    static const size_t BODY_LEN = 8;

    hs = (ClientInitHandShake *) ctx->hdr_buf;

    /*
     * The client hello has mostly fixed magic values; we only validate the
     * fields this implementation actually relies on before switching into the
     * normal request/response framing.
     */
    if (ntohl(hs->fourth) != 4 || ntohl(hs->fifth) != ROOTD_PQ) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: invalid handshake magic "
                      "(fourth=%u fifth=%u)",
                      ntohl(hs->fourth), ntohl(hs->fifth));
        return NGX_ERROR;
    }

    total = XRD_RESPONSE_HDR_LEN + BODY_LEN;
    XROOTD_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

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
                   "xrootd: handshake ok, sending standard-format response");

    return xrootd_queue_response(ctx, c, buf, total);
}
