#include "core/ngx_brix_module.h"
#include "core/compat/alloc_guard.h"

/*
 *
 * WHAT: Builds XRootD wire protocol response header (ServerResponseHdr) from
 *       components. Sets streamid bytes copied directly from caller-provided
 *       pointer for connection tracking. Converts status opcode and dlen to
 *       network byte order via htons()/htonl() ensuring correct wire format.
 *       All fields written in fixed positions per XRootD protocol spec.
 *
 * WHY: Every handler calls this to construct the 8-byte response header
 *      before payload. Streamid consistency prevents cross-stream confusion
 *      with concurrent operations on same connection. Network byte order
 *      ensures wire-format correctness across architectures.
 *
 * HOW: Copy streamid[0..1] → out->streamid; htons(status) → out->status;
 *      htonl(dlen) → out->dlen. Pure function, no shared state. Sets streamid bytes (0 and 1) copied directly from caller-provided streamid pointer for connection tracking. Converts status opcode to network byte order via htons() ensuring correct wire format across architectures. Converts dlen (data length) to network byte order via htonl() — this includes body size only, not header overhead. All fields written in fixed positions within ServerResponseHdr structure following XRootD protocol specification. Caller must provide pre-allocated out buffer with sufficient capacity for the struct. Thread safety: pure function with no shared state — operates only on provided streamid pointer and local out struct during response construction. */

/*
 *
 * WHAT: Sends XRootD kXR_ok (opcode 1) success response with optional payload body. Calculates total size = header length + bodylen, allocates buffer from connection pool via ngx_palloc(). Builds response header using brix_build_resp_hdr() with ctx->recv.cur_streamid and status=kXR_ok, dlen=bodylen. If bodylen > 0 AND body != NULL, copies body payload to buffer after header via ngx_memcpy(); if bodylen == 0 or body is NULL skips copy (zero-length success responses valid). Queues complete response for wire delivery via brix_queue_response() with total size including header + body. Returns NGX_ERROR only on allocation failure; always succeeds when memory available. Per AGENTS.md INVARIANT: all wire paths → brix_queue_response() before sending — this function delegates to the queueing infrastructure for partial write/EAGAIN handling.
 *
 * WHY: kXR_ok success responses are sent after successful open/read/write/close/stat operations — the optional body allows returning metadata alongside confirmation (e.g., file size in stat response, or path string in rename response). The kXR_ok opcode indicates operation completed without error, enabling clients to proceed with subsequent requests. Streamid consistency via ctx->recv.cur_streamid prevents cross-stream confusion when multiple concurrent operations are active on same connection. Thread safety: operates only on local stack variables (buf) and provided ctx/c connection; no shared state modification during response construction. */

/*
 *
 * WHAT: Sends XRootD kXR_error (opcode -1) failure response containing error code and human-readable message. Calculates body length = 4 bytes error code + strlen(msg) + 1 NUL terminator (total msglen). Total size = header length + body length. Allocates buffer from connection pool via ngx_palloc(). Builds response header using brix_build_resp_hdr() with ctx->recv.cur_streamid and status=kXR_error, dlen=bodylen. Error code converted to network byte order via htonl(), copied after header. Message string (including NUL terminator) copied immediately after error code — trailing NUL matters because several clients treat the text as a C string requiring proper termination. Logs debug-level entry showing error code and message before sending for observability. Queues complete response for wire delivery via brix_queue_response() with total size including header + 4-byte error code + null-terminated message. Returns NGX_ERROR only on allocation failure; always succeeds when memory available. Per AGENTS.md errno→kXR mapping: ENOENT→kXR_NotFound, EACCES/EPERM→kXR_NotAuthorized, EINVAL→kXR_ArgInvalid, EIO→kXR_IOError, ENOMEM→kXR_NoMemory.
 *
 * WHY: Error responses must include both numeric code and human-readable message — clients use the code for programmatic error handling while operators use the message for debugging. The trailing NUL terminator is critical because multiple XRootD clients parse error messages as C strings without explicit length field; omitting it would cause buffer over-reads on client side. kXR_error opcode distinguishes failure from success responses, enabling clients to detect operation failures and retry or abort accordingly. Debug-level logging provides observability for troubleshooting without increasing log verbosity in production (debug level only). Thread safety: operates only on local stack variables (buf) and provided ctx/c connection; no shared state modification during response construction. */

void
brix_build_resp_hdr(const u_char *streamid, uint16_t status,
    uint32_t dlen, ServerResponseHdr *out)
{
    out->streamid[0] = streamid[0];
    out->streamid[1] = streamid[1];
    out->status      = htons(status);
    out->dlen        = htonl(dlen);
}

ngx_int_t
brix_send_ok(brix_ctx_t *ctx, ngx_connection_t *c,
    const void *body, uint32_t bodylen)
{
    size_t   total;
    u_char  *buf;

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    buf = ngx_palloc(c->pool, total);

    if (buf == NULL) {
        return NGX_ERROR;
    }

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok, bodylen,
        (ServerResponseHdr *) buf);

    if (bodylen > 0 && body != NULL) {
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, bodylen);
    }

    return brix_queue_response(ctx, c, buf, total);
}

ngx_int_t
brix_send_error(brix_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *msg)
{
    size_t    msglen, bodylen, total;
    uint32_t  ecode;
    u_char   *buf;

    /*
     * kXR_error bodies are [errnum:4B BE][errmsg:NUL-terminated text].
     * The trailing NUL matters because several clients treat the text as a C string.
     */
    msglen = strlen(msg) + 1;
    bodylen = sizeof(kXR_int32) + msglen;
    total = XRD_RESPONSE_HDR_LEN + bodylen;

    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_error, (uint32_t) bodylen,
        (ServerResponseHdr *) buf);

    ecode = htonl(errcode);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &ecode, sizeof(ecode));
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ecode), msg, msglen);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
        "brix: sending error %d: %s", (int) errcode, msg);

    return brix_queue_response(ctx, c, buf, total);
}
