/*
 * frame_io.c - shared CMS frame send helpers.
 */

#include "frame_io.h"

/*
 * brix_cms_send_all — send a contiguous buffer over an nginx connection.
 *
 * WHAT: Loop c->send() until the entire buf is transmitted or an error occurs.
 * WHY: nginx's c->send() may return NGX_AGAIN (partial write) or 0 on idle;
 *      the caller needs a single result indicating complete success, partial,
 *      or failure rather than polling the event loop manually.
 * HOW: Accumulate sent bytes in a while-loop; each iteration advances buf+sent
 *      and reduces len-sent. Returns NGX_AGAIN when send returns 0 or NGX_AGAIN
 *      (caller must retry on next event), NGX_ERROR on NGX_ERROR, NGX_OK when
 *      sent == len.
 */
ngx_int_t
brix_cms_send_all(ngx_connection_t *c, const u_char *buf, size_t len)
{
    size_t sent;

    if (c == NULL) {
        return NGX_ERROR;
    }

    sent = 0;
    while (sent < len) {
        ssize_t n;

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

/*
 * brix_cms_send_frame — build and transmit a CMS wire frame.
 *
 * WHAT: Construct an 8-byte big-endian header (streamid, code, modifier,
 *      payload_len) followed by the payload, then send both via
 *      brix_cms_send_all().
 * WHY: The CMS manager protocol requires every message to carry a fixed-size
 *      header that encodes the target stream and frame type before the actual
 *      payload; this helper encapsulates header construction + sequential
 *      transmission so callers (send.c) emit frames with one function call.
 * HOW: Validate c != NULL and payload_len <= 65535 (fits in uint16). Encode
 *      streamid via ngx_brix_cms_put32(), code/modifier as raw bytes,
 *      payload_len via ngx_brix_cms_put16(). Send header first; if
 *      payload_len > 0 send payload second. Returns NGX_OK on full success,
 *      NGX_ERROR on any brix_cms_send_all failure.
 */
ngx_int_t
brix_cms_send_frame(ngx_connection_t *c, uint32_t streamid, u_char code,
    u_char modifier, const u_char *payload, size_t payload_len)
{
    u_char hdr[NGX_BRIX_CMS_HDR_LEN];

    if (c == NULL || payload_len > 65535) {
        return NGX_ERROR;
    }

    ngx_brix_cms_put32(hdr, streamid);
    hdr[4] = code;
    hdr[5] = modifier;
    ngx_brix_cms_put16(hdr + 6, (uint16_t) payload_len);

    if (brix_cms_send_all(c, hdr, sizeof(hdr)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (payload_len > 0
        && brix_cms_send_all(c, payload, payload_len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}
