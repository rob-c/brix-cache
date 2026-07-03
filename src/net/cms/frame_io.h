#ifndef BRIX_CMS_FRAME_IO_H
#define BRIX_CMS_FRAME_IO_H

#include "cms_internal.h"

/* ---- CMS frame send helpers — shared wire transmission routines ----
 *
 * WHAT: Interface for sending CMS manager protocol frames over a persistent
 *       TCP connection. Two primitives: send_all (looping buffer transmit)
 *       and send_frame (header construction + payload dispatch).
 *
 * WHY: The CMS heartbeat protocol requires every outgoing message to carry an
 *      8-byte big-endian header followed by variable-length payload. Callers
 *      in send.c build payloads but delegate transmission to these helpers,
 *      avoiding duplicated send-loop logic across login/load/avail/pong frames.
 *
 * HOW: brix_cms_send_all() loops c->send() until len bytes are transmitted;
 *      returns NGX_AGAIN on partial write (caller retries), NGX_ERROR on failure,
 *      NGX_OK on full success. brix_cms_send_frame() constructs the header
 *      via ngx_brix_cms_put32/put16 from cms_internal.h then dispatches both
 *      header and payload through send_all(). */

ngx_int_t brix_cms_send_all(ngx_connection_t *c, const u_char *buf,
    size_t len);
ngx_int_t brix_cms_send_frame(ngx_connection_t *c, uint32_t streamid,
    u_char code, u_char modifier, const u_char *payload, size_t payload_len);

#endif /* BRIX_CMS_FRAME_IO_H */
