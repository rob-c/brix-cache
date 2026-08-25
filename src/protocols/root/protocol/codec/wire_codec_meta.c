/*
 * wire_codec_meta.c — metadata-family wire-body codec. See wire_codec.h.
 *
 * stat / statx / dirlist / query / locate / fattr request bodies. Each
 * message's byte layout is one field table over the 16-byte ClientRequestHdr
 * body region; the shared engine in wire_codec.h drives both the module
 * (parse) and the native client (build) off the same table. Pure C, ngx-free.
 */
#include "wire_codec.h"

#include <stddef.h>

/* ---- kXR_stat: options(1) reserved(7) wants(4) fhandle(4) -------------- */

static const xrdw_field_t xrdw_stat_fields[] = {
    {  0, XRDW_F_U8,    0,                offsetof(xrdw_stat_req_t, options) },
    {  8, XRDW_F_U32,   0,                offsetof(xrdw_stat_req_t, wants) },
    { 12, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_stat_req_t, fhandle) },
};

int
xrdw_stat_req_pack(const xrdw_stat_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_stat_fields,
                            XRDW_NFIELDS(xrdw_stat_fields));
}

int
xrdw_stat_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_stat_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_stat_fields,
                              XRDW_NFIELDS(xrdw_stat_fields));
}

/* ---- kXR_statx: options(1) reserved(11) fhandle(4) --------------------- */

static const xrdw_field_t xrdw_statx_fields[] = {
    {  0, XRDW_F_U8,    0,                offsetof(xrdw_statx_req_t, options) },
    { 12, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_statx_req_t, fhandle) },
};

int
xrdw_statx_req_pack(const xrdw_statx_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_statx_fields,
                            XRDW_NFIELDS(xrdw_statx_fields));
}

int
xrdw_statx_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_statx_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_statx_fields,
                              XRDW_NFIELDS(xrdw_statx_fields));
}

/* ---- kXR_dirlist: reserved(15) options(1) ------------------------------ */

static const xrdw_field_t xrdw_dirlist_fields[] = {
    { 15, XRDW_F_U8, 0, offsetof(xrdw_dirlist_req_t, options) },
};

int
xrdw_dirlist_req_pack(const xrdw_dirlist_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_dirlist_fields,
                            XRDW_NFIELDS(xrdw_dirlist_fields));
}

int
xrdw_dirlist_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_dirlist_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_dirlist_fields,
                              XRDW_NFIELDS(xrdw_dirlist_fields));
}

/* ---- kXR_query: infotype(2) reserved(2) fhandle(4) reserved(8) --------- */

static const xrdw_field_t xrdw_query_fields[] = {
    { 0, XRDW_F_U16,   0,                offsetof(xrdw_query_req_t, infotype) },
    { 4, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_query_req_t, fhandle) },
};

int
xrdw_query_req_pack(const xrdw_query_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_query_fields,
                            XRDW_NFIELDS(xrdw_query_fields));
}

int
xrdw_query_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_query_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_query_fields,
                              XRDW_NFIELDS(xrdw_query_fields));
}

/* ---- kXR_locate: options(2) reserved(14) ------------------------------- */

static const xrdw_field_t xrdw_locate_fields[] = {
    { 0, XRDW_F_U16, 0, offsetof(xrdw_locate_req_t, options) },
};

int
xrdw_locate_req_pack(const xrdw_locate_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_locate_fields,
                            XRDW_NFIELDS(xrdw_locate_fields));
}

int
xrdw_locate_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_locate_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_locate_fields,
                              XRDW_NFIELDS(xrdw_locate_fields));
}

/* ---- kXR_fattr: fhandle(4) subcode(1) numattr(1) options(1) reserved(9) - */

static const xrdw_field_t xrdw_fattr_fields[] = {
    { 0, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_fattr_req_t, fhandle) },
    { 4, XRDW_F_U8,    0,                offsetof(xrdw_fattr_req_t, subcode) },
    { 5, XRDW_F_U8,    0,                offsetof(xrdw_fattr_req_t, numattr) },
    { 6, XRDW_F_U8,    0,                offsetof(xrdw_fattr_req_t, options) },
};

int
xrdw_fattr_req_pack(const xrdw_fattr_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_fattr_fields,
                            XRDW_NFIELDS(xrdw_fattr_fields));
}

int
xrdw_fattr_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_fattr_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_fattr_fields,
                              XRDW_NFIELDS(xrdw_fattr_fields));
}
