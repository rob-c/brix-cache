/*
 * wire_codec_meta.c — metadata-family wire-body codec. See wire_codec.h.
 *
 * stat / statx / dirlist / query / locate request bodies. Each operates on the
 * 16-byte ClientRequestHdr body region; offsets are the single source of truth
 * for both the module (parse) and the native client (build). Pure C, ngx-free.
 */
#include "wire_codec.h"

#include <string.h>

/* ---- kXR_stat: options(1) reserved(7) wants(4) fhandle(4) -------------- */

int
xrdw_stat_req_pack(const xrdw_stat_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    body[0] = r->options;
    xrdw_put_u32(body + 8, r->wants);
    memcpy(body + 12, r->fhandle, XRDW_FHANDLE_LEN);
    return XRDW_BODY_LEN;
}

int
xrdw_stat_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_stat_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->options = body[0];
    r->wants   = xrdw_get_u32(body + 8);
    memcpy(r->fhandle, body + 12, XRDW_FHANDLE_LEN);
    return XRDW_OK;
}

/* ---- kXR_statx: options(1) reserved(11) fhandle(4) --------------------- */

int
xrdw_statx_req_pack(const xrdw_statx_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    body[0] = r->options;
    memcpy(body + 12, r->fhandle, XRDW_FHANDLE_LEN);
    return XRDW_BODY_LEN;
}

int
xrdw_statx_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_statx_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->options = body[0];
    memcpy(r->fhandle, body + 12, XRDW_FHANDLE_LEN);
    return XRDW_OK;
}

/* ---- kXR_dirlist: reserved(15) options(1) ------------------------------ */

int
xrdw_dirlist_req_pack(const xrdw_dirlist_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    body[15] = r->options;
    return XRDW_BODY_LEN;
}

int
xrdw_dirlist_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_dirlist_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->options = body[15];
    return XRDW_OK;
}

/* ---- kXR_query: infotype(2) reserved(2) fhandle(4) reserved(8) --------- */

int
xrdw_query_req_pack(const xrdw_query_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    xrdw_put_u16(body, r->infotype);
    memcpy(body + 4, r->fhandle, XRDW_FHANDLE_LEN);
    return XRDW_BODY_LEN;
}

int
xrdw_query_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_query_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->infotype = xrdw_get_u16(body);
    memcpy(r->fhandle, body + 4, XRDW_FHANDLE_LEN);
    return XRDW_OK;
}

/* ---- kXR_locate: options(2) reserved(14) ------------------------------- */

int
xrdw_locate_req_pack(const xrdw_locate_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    xrdw_put_u16(body, r->options);
    return XRDW_BODY_LEN;
}

int
xrdw_locate_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_locate_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->options = xrdw_get_u16(body);
    return XRDW_OK;
}

/* ---- kXR_fattr: fhandle(4) subcode(1) numattr(1) options(1) reserved(9) - */

int
xrdw_fattr_req_pack(const xrdw_fattr_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body, r->fhandle, XRDW_FHANDLE_LEN);
    body[4] = r->subcode;
    body[5] = r->numattr;
    body[6] = r->options;
    return XRDW_BODY_LEN;
}

int
xrdw_fattr_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_fattr_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->fhandle, body, XRDW_FHANDLE_LEN);
    r->subcode = body[4];
    r->numattr = body[5];
    r->options = body[6];
    return XRDW_OK;
}
