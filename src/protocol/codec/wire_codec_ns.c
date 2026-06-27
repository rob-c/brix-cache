/*
 * wire_codec_ns.c — namespace-family wire-body codec. See wire_codec.h.
 *
 * mkdir / chmod / set / (mv, symlink, link via the shared two-path body) /
 * (rm, rmdir, readlink, setattr, ping via the empty body). The variable path
 * payload — and the setattr 44-byte attribute prefix (vendor_ext) — stay at the
 * edge; this file owns only the fixed body fields. Pure C.
 */
#include "wire_codec.h"

#include <string.h>

/* ---- kXR_mkdir: options(1) reserved(13) mode(2) ---------------------- */

int
xrdw_mkdir_req_pack(const xrdw_mkdir_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    body[0] = r->options;
    xrdw_put_u16(body + 14, r->mode);
    return XRDW_BODY_LEN;
}

int
xrdw_mkdir_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_mkdir_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->options = body[0];
    r->mode    = xrdw_get_u16(body + 14);
    return XRDW_OK;
}

/* ---- kXR_chmod: reserved(14) mode(2) --------------------------------- */

int
xrdw_chmod_req_pack(const xrdw_chmod_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    xrdw_put_u16(body + 14, r->mode);
    return XRDW_BODY_LEN;
}

int
xrdw_chmod_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_chmod_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->mode = xrdw_get_u16(body + 14);
    return XRDW_OK;
}

/* ---- kXR_set: modifier(1) reserved(15) ------------------------------- */

int
xrdw_set_req_pack(const xrdw_set_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    body[0] = r->modifier;
    return XRDW_BODY_LEN;
}

int
xrdw_set_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_set_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->modifier = body[0];
    return XRDW_OK;
}

/* ---- kXR_mv / kXR_symlink / kXR_link: reserved(14) arg1len(2) --------- */

int
xrdw_twopath_req_pack(const xrdw_twopath_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    xrdw_put_u16(body + 14, (uint16_t) r->arg1len);
    return XRDW_BODY_LEN;
}

int
xrdw_twopath_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_twopath_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->arg1len = (int16_t) xrdw_get_u16(body + 14);
    return XRDW_OK;
}

/* ---- empty body (kXR_rm/rmdir/readlink/setattr/ping): all reserved ---- */

int
xrdw_empty_req_pack(uint8_t body[XRDW_BODY_LEN])
{
    if (body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    return XRDW_BODY_LEN;
}

int
xrdw_empty_req_unpack(const uint8_t body[XRDW_BODY_LEN])
{
    return (body == NULL) ? XRDW_EINVAL : XRDW_OK;
}
