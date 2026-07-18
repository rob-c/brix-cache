#include "ftp_ev.h"

/*
 * ftp_ev_reply.c — reply framing for the event engine.
 *
 * WHAT: append-only reply helpers that write into the connection's outbound
 * buffer (->ob): a printf-style status reply, an AUTH/ADAT token continuation,
 * plus the base64 codecs the RFC 2228 handshake needs.
 *
 * WHY: the engine is non-blocking, so replies are never written inline — they are
 * queued into ->ob and drained by brix_ftp_ev_flush() under the event loop.  Once
 * the GSI security layer is active every status reply is transparently GSS-wrapped
 * into a 631/632/633 safe/private frame; the pre-auth handshake (220/334/335/235)
 * is emitted while ->sec_active is still 0 and so goes out cleartext.
 *
 * HOW: ev_out_put() is the single choke point that copies bytes into ->ob with a
 * hard capacity check.  Because commands are processed lock-step (the engine
 * drains ->ob before framing the next command), at most one command's replies are
 * resident at a time, so the fixed 64 KiB buffer cannot be overrun by a
 * well-behaved reply path.
 */


/* Copy `len` reply bytes into the outbound buffer.  Fails closed (NGX_ERROR) if
 * the reply would exceed the buffer — a reply that large is a bug, not traffic. */
static ngx_int_t
ev_out_put(ftp_ev_t *fc, const u_char *data, size_t len)
{
    if (len > BRIX_FTP_EV_OB_CAP - fc->ob_len) {
        ngx_log_error(NGX_LOG_ERR, fc->c->log, 0,
                      "brix: GridFTP(ev) reply exceeds outbound buffer (%uz)",
                      len);
        return NGX_ERROR;
    }
    ngx_memcpy(fc->ob + fc->ob_len, data, len);
    fc->ob_len += len;
    return NGX_OK;
}


/* base64-encode raw bytes into a pool buffer. */
static ngx_int_t
ev_b64_encode(ngx_pool_t *pool, const u_char *data, size_t len, ngx_str_t *out)
{
    ngx_str_t src;

    src.data = (u_char *) data;
    src.len  = len;
    out->data = ngx_pnalloc(pool, ngx_base64_encoded_length(len));
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    ngx_encode_base64(out, &src);
    return NGX_OK;
}


/* base64-decode a NUL-terminated ADAT/MIC/ENC argument into a pool buffer. */
ngx_int_t
brix_ftp_ev_b64_decode(ngx_pool_t *pool, const char *b64, ngx_str_t *out)
{
    ngx_str_t src;

    src.data = (u_char *) b64;
    src.len  = ngx_strlen(b64);
    out->data = ngx_pnalloc(pool, ngx_base64_decoded_length(src.len));
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    return ngx_decode_base64(out, &src);
}


/* GSS-wrap `n` reply bytes and queue them as an RFC 2228 safe/private reply
 * ("631/632/633 <b64>") over the protected control channel. */
static ngx_int_t
ev_reply_wrapped(ftp_ev_t *fc, const u_char *plain, size_t n)
{
    ngx_str_t  tok, b64;
    u_char    *line, *p;
    size_t     need;

    if (brix_gssapi_wrap(fc->gss, plain, n, &tok) != NGX_OK
        || ev_b64_encode(fc->c->pool, tok.data, tok.len, &b64) != NGX_OK)
    {
        return NGX_ERROR;
    }
    need = b64.len + ngx_strlen(fc->wrap_code) + sizeof(" \r\n");
    line = ngx_pnalloc(fc->c->pool, need);
    if (line == NULL) {
        return NGX_ERROR;
    }
    p = ngx_slprintf(line, line + need, "%s %V\r\n", fc->wrap_code, &b64);
    return ev_out_put(fc, line, (size_t) (p - line));
}


/* Format-and-queue a status reply.  GSS-wrapped once the security layer is up. */
ngx_int_t
brix_ftp_ev_reply(ftp_ev_t *fc, const char *fmt, ...)
{
    u_char   line[BRIX_FTP_EV_LINE_MAX];
    u_char  *p;
    va_list  ap;

    va_start(ap, fmt);
    p = ngx_vslprintf(line, line + sizeof(line) - 1, fmt, ap);
    va_end(ap);

    if (fc->sec_active) {
        return ev_reply_wrapped(fc, line, (size_t) (p - line));
    }
    return ev_out_put(fc, line, (size_t) (p - line));
}


/* Queue an AUTH/ADAT continuation ("335/235 ADAT=<b64>").  Handshake tokens far
 * exceed the fixed reply buffer used by brix_ftp_ev_reply(), so the encoded line
 * is built in a pool buffer sized to the token before being copied into ->ob. */
ngx_int_t
brix_ftp_ev_send_adat(ftp_ev_t *fc, int code, ngx_str_t *tok)
{
    ngx_str_t  b64;
    u_char    *line, *p;
    size_t     need;

    if (tok->len == 0) {
        u_char small[32];
        p = ngx_slprintf(small, small + sizeof(small), "%d ADAT=\r\n", code);
        return ev_out_put(fc, small, (size_t) (p - small));
    }
    if (ev_b64_encode(fc->c->pool, tok->data, tok->len, &b64) != NGX_OK) {
        return NGX_ERROR;
    }
    need = b64.len + sizeof("### ADAT=\r\n");
    line = ngx_pnalloc(fc->c->pool, need);
    if (line == NULL) {
        return NGX_ERROR;
    }
    p = ngx_slprintf(line, line + need, "%d ADAT=%V\r\n", code, &b64);
    return ev_out_put(fc, line, (size_t) (p - line));
}
