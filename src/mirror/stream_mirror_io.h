/*
 * stream_mirror_io.h — shared shadow-socket framing primitives for the two
 * stream mirrors.
 *
 * WHAT: The read mirror (stream_mirror.c) and the write mirror
 *       (stream_wmirror.c) drive the same tiny async TCP exchange against a
 *       shadow XRootD server: drain a write buffer non-blocking, then read one
 *       8-byte ServerResponseHdr plus a bounded body, both resumable across
 *       NGX_AGAIN. Those two primitives were duplicated byte-for-byte; they live
 *       here once and operate on plain field pointers so neither mirror has to
 *       expose its context struct.
 *
 * WHY:  The framing is security-sensitive (the body length is attacker-supplied
 *       and must be capped) and lifetime-sensitive (cursors must survive partial
 *       reads). One copy means one place to audit and fix.
 *
 * HOW:  Callers pass their own connection plus pointers to the cursor/buffer
 *       fields embedded in their context. The helpers never touch dispatch,
 *       teardown, or timers — those stay per-mirror.
 */
#ifndef XROOTD_MIRROR_STREAM_MIRROR_IO_H
#define XROOTD_MIRROR_STREAM_MIRROR_IO_H

#include "../ngx_xrootd_module.h"

/* Upper bound on a shadow response body, so a hostile/buggy shadow cannot make
 * us allocate an arbitrary buffer. */
#define XROOTD_MIRROR_MAX_RESP_BODY  65536

/*
 * Drain wbuf[*wbuf_pos .. wbuf_len) to the shadow socket without blocking.
 * Advances *wbuf_pos by the bytes written. Returns NGX_OK when fully drained
 * (and the read event has been re-armed), NGX_AGAIN when the socket is full (and
 * the write event has been re-armed), or NGX_ERROR on send/event-arm failure.
 */
ngx_int_t xrootd_mirror_io_flush(ngx_connection_t *c, const u_char *wbuf,
    size_t wbuf_len, size_t *wbuf_pos);

/*
 * Read one ServerResponseHdr (XRD_RESPONSE_HDR_LEN bytes) followed by a
 * dlen-byte body from the shadow. Resumable: the two cursors (*rhdr_pos,
 * *resp_body_pos) survive NGX_AGAIN so a frame split across recv()s is
 * reassembled across wakeups. The header is parsed exactly once (when *rhdr_pos
 * first reaches the full header length) to latch *resp_status / *resp_dlen and
 * allocate *resp_body from c->pool. Returns NGX_AGAIN until the whole frame is
 * in hand, NGX_OK when complete, NGX_ERROR on EOF or an oversize body
 * (> XROOTD_MIRROR_MAX_RESP_BODY).
 *
 * rhdr must point at a caller-owned buffer of at least XRD_RESPONSE_HDR_LEN
 * bytes; all cursors must be zeroed before the first frame.
 */
ngx_int_t xrootd_mirror_io_recv_frame(ngx_connection_t *c, u_char *rhdr,
    size_t *rhdr_pos, uint16_t *resp_status, uint32_t *resp_dlen,
    u_char **resp_body, size_t *resp_body_pos);

#endif /* XROOTD_MIRROR_STREAM_MIRROR_IO_H */
