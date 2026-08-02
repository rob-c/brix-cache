/*
 * auth/krb5/kxr_wire.c — kXR krb5 auth wire codec (§5.7). See kxr_wire.h.
 *
 * The frame vocabulary is byte-frozen and rendered by hand here (no XProtocol
 * structs) so the unit links into both nginx and the standalone krb5 harness:
 *
 *   ClientAuthRequest (24 bytes, sent per leg):
 *     [0..1]   streamid   = {0,1} (the connector stream)
 *     [2..3]   requestid  = kXR_auth, big-endian
 *     [4..15]  reserved   = 0
 *     [16..19] credtype   = "krb5"
 *     [20..23] dlen       = token length, big-endian
 *     then <dlen> credential (GSS token) bytes.
 *
 *   ServerResponseHeader (8 bytes, read per leg):
 *     [0..1] streamid  (echoed, ignored here)
 *     [2..3] status    big-endian (kXR_ok / kXR_authmore / kXR_error / ...)
 *     [4..7] dlen      big-endian — the reply token (or error body) length.
 */
#include "auth/krb5/kxr_wire.h"

#include "protocols/root/protocol/opcodes.h"   /* kXR_auth, kXR_ok, kXR_authmore */

#include <stdlib.h>
#include <string.h>

#ifndef kXR_error
#define kXR_error 4003
#endif

/* Network-order render/parse over unaligned frame buffers (UB-free byte ops). */
static void
put_u16_be(u_char *p, uint16_t v)
{
    p[0] = (u_char) (v >> 8);
    p[1] = (u_char) v;
}

static void
put_u32_be(u_char *p, uint32_t v)
{
    p[0] = (u_char) (v >> 24);
    p[1] = (u_char) (v >> 16);
    p[2] = (u_char) (v >> 8);
    p[3] = (u_char) v;
}

static uint16_t
get_u16_be(const u_char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | (uint16_t) p[1]);
}

static uint32_t
get_u32_be(const u_char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)  | (uint32_t) p[3];
}


ngx_int_t
brix_krb5_kxr_classify(uint16_t status, u_char *body, uint32_t dlen,
    ngx_str_t *in_token, int *done)
{
    in_token->data = NULL;
    in_token->len  = 0;
    *done          = 0;

    if (status == kXR_authmore) {
        in_token->data = body;      /* borrowed; feed back to gss_init_sec_context */
        in_token->len  = dlen;
        *done          = 0;
        return NGX_OK;
    }
    if (status == kXR_ok) {
        in_token->data = body;      /* may carry a final AP-REP; may be empty */
        in_token->len  = dlen;
        *done          = 1;
        return NGX_OK;
    }
    return NGX_ERROR;               /* kXR_error or any unexpected status */
}


ngx_int_t
brix_krb5_kxr_wire(void *wire_ctx, const ngx_str_t *out_token,
    ngx_str_t *in_token, int *done, ngx_log_t *log)
{
    brix_krb5_kxr_wire_t *w = wire_ctx;
    u_char                hdr[24];
    u_char                rhdr[8];
    uint16_t              status;
    uint32_t              dlen;
    u_char               *body = NULL;

    in_token->data = NULL;
    in_token->len  = 0;
    *done          = 0;

    /* Release the previous leg's reply — the engine has consumed it by now. */
    if (w->reply != NULL) {
        free(w->reply);
        w->reply = NULL;
    }

    /* ClientAuthRequest header + credential payload. */
    memset(hdr, 0, sizeof hdr);
    hdr[1] = 1;                                     /* connector stream */
    put_u16_be(hdr + 2, (uint16_t) kXR_auth);
    memcpy(hdr + 16, "krb5", 4);
    put_u32_be(hdr + 20, (uint32_t) out_token->len);

    if (w->send(w->io, hdr, sizeof hdr) != NGX_OK
        || (out_token->len > 0
            && w->send(w->io, out_token->data, out_token->len) != NGX_OK))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix: krb5 origin leg - auth request write failed");
        return NGX_ERROR;
    }

    /* ServerResponseHeader. */
    if (w->recv(w->io, rhdr, sizeof rhdr) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix: krb5 origin leg - reply header read failed");
        return NGX_ERROR;
    }
    status = get_u16_be(rhdr + 2);
    dlen   = get_u32_be(rhdr + 4);

    if (dlen > w->max_body) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix: krb5 origin leg - reply body %uD exceeds cap %uD",
            dlen, w->max_body);
        return NGX_ERROR;
    }
    if (dlen > 0) {
        body = malloc(dlen);
        if (body == NULL) {
            return NGX_ERROR;
        }
        if (w->recv(w->io, body, dlen) != NGX_OK) {
            free(body);
            ngx_log_error(NGX_LOG_ERR, log, 0,
                "brix: krb5 origin leg - reply body read failed");
            return NGX_ERROR;
        }
        w->reply = body;      /* borrowed by the engine until the next call/end */
    }

    if (brix_krb5_kxr_classify(status, body, dlen, in_token, done) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix: krb5 origin leg - origin rejected token (status %ui)",
            (ngx_uint_t) status);
        return NGX_ERROR;
    }
    return NGX_OK;
}
