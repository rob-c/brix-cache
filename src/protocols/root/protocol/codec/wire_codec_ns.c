/*
 * wire_codec_ns.c — namespace-family wire-body codec. See wire_codec.h.
 *
 * mkdir / chmod / set / (mv, symlink, link via the shared two-path body) /
 * (rm, rmdir, readlink, setattr, ping via the empty body). The variable path
 * payload — and the setattr 44-byte attribute prefix (vendor_ext) — stay at the
 * edge; this file owns only the fixed body fields, each expressed as a field
 * table driven by the shared engine in wire_codec.h. Pure C.
 */
#include "wire_codec.h"

#include <stddef.h>
#include <string.h>

/* ---- kXR_mkdir: options(1) reserved(13) mode(2) ---------------------- */

static const xrdw_field_t xrdw_mkdir_fields[] = {
    {  0, XRDW_F_U8,  0, offsetof(xrdw_mkdir_req_t, options) },
    { 14, XRDW_F_U16, 0, offsetof(xrdw_mkdir_req_t, mode) },
};

int
xrdw_mkdir_req_pack(const xrdw_mkdir_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_mkdir_fields,
                            XRDW_NFIELDS(xrdw_mkdir_fields));
}

int
xrdw_mkdir_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_mkdir_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_mkdir_fields,
                              XRDW_NFIELDS(xrdw_mkdir_fields));
}

/* ---- kXR_chmod: reserved(14) mode(2) --------------------------------- */

static const xrdw_field_t xrdw_chmod_fields[] = {
    { 14, XRDW_F_U16, 0, offsetof(xrdw_chmod_req_t, mode) },
};

int
xrdw_chmod_req_pack(const xrdw_chmod_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_chmod_fields,
                            XRDW_NFIELDS(xrdw_chmod_fields));
}

int
xrdw_chmod_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_chmod_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_chmod_fields,
                              XRDW_NFIELDS(xrdw_chmod_fields));
}

/* ---- kXR_set: modifier(1) reserved(15) ------------------------------- */

static const xrdw_field_t xrdw_set_fields[] = {
    { 0, XRDW_F_U8, 0, offsetof(xrdw_set_req_t, modifier) },
};

int
xrdw_set_req_pack(const xrdw_set_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_set_fields,
                            XRDW_NFIELDS(xrdw_set_fields));
}

int
xrdw_set_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_set_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_set_fields,
                              XRDW_NFIELDS(xrdw_set_fields));
}

/* ---- kXR_mv / kXR_symlink / kXR_link: reserved(14) arg1len(2) --------- */

static const xrdw_field_t xrdw_twopath_fields[] = {
    { 14, XRDW_F_U16, 0, offsetof(xrdw_twopath_req_t, arg1len) },
};

int
xrdw_twopath_req_pack(const xrdw_twopath_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_twopath_fields,
                            XRDW_NFIELDS(xrdw_twopath_fields));
}

int
xrdw_twopath_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_twopath_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_twopath_fields,
                              XRDW_NFIELDS(xrdw_twopath_fields));
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
