/*
 * wire_codec_file.c — file-family wire-body codec. See wire_codec.h.
 *
 * open / close / read / pgread / write / pgwrite / sync / truncate / writev /
 * clone / chkpoint request bodies. These carry the hot-path multi-byte integer
 * fields (i64 offsets, i32 lengths) — each message's byte layout is one field
 * table, and the shared engine in wire_codec.h drives both directions off it.
 * Pure C.
 */
#include "wire_codec.h"

#include <stddef.h>

/* ---- kXR_open: mode(2) options(2) optiont(2) reserved(6) fhtemplt(4) --- */

static const xrdw_field_t xrdw_open_fields[] = {
    {  0, XRDW_F_U16,   0,                offsetof(xrdw_open_req_t, mode) },
    {  2, XRDW_F_U16,   0,                offsetof(xrdw_open_req_t, options) },
    {  4, XRDW_F_U16,   0,                offsetof(xrdw_open_req_t, optiont) },
    { 12, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_open_req_t, fhtemplt) },
};

int
xrdw_open_req_pack(const xrdw_open_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_open_fields,
                            XRDW_NFIELDS(xrdw_open_fields));
}

int
xrdw_open_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_open_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_open_fields,
                              XRDW_NFIELDS(xrdw_open_fields));
}

/* ---- kXR_close / kXR_sync: fhandle(4) reserved(12) -------------------- */

static const xrdw_field_t xrdw_close_fields[] = {
    { 0, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_close_req_t, fhandle) },
};

int
xrdw_close_req_pack(const xrdw_close_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_close_fields,
                            XRDW_NFIELDS(xrdw_close_fields));
}

int
xrdw_close_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_close_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_close_fields,
                              XRDW_NFIELDS(xrdw_close_fields));
}

static const xrdw_field_t xrdw_sync_fields[] = {
    { 0, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_sync_req_t, fhandle) },
};

int
xrdw_sync_req_pack(const xrdw_sync_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_sync_fields,
                            XRDW_NFIELDS(xrdw_sync_fields));
}

int
xrdw_sync_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_sync_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_sync_fields,
                              XRDW_NFIELDS(xrdw_sync_fields));
}

/* ---- kXR_read / kXR_pgread: fhandle(4) offset(8) rlen(4) -------------- */

static const xrdw_field_t xrdw_read_fields[] = {
    {  0, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_read_req_t, fhandle) },
    {  4, XRDW_F_U64,   0,                offsetof(xrdw_read_req_t, offset) },
    { 12, XRDW_F_U32,   0,                offsetof(xrdw_read_req_t, rlen) },
};

int
xrdw_read_req_pack(const xrdw_read_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_read_fields,
                            XRDW_NFIELDS(xrdw_read_fields));
}

int
xrdw_read_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_read_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_read_fields,
                              XRDW_NFIELDS(xrdw_read_fields));
}

static const xrdw_field_t xrdw_pgread_fields[] = {
    {  0, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_pgread_req_t, fhandle) },
    {  4, XRDW_F_U64,   0,                offsetof(xrdw_pgread_req_t, offset) },
    { 12, XRDW_F_U32,   0,                offsetof(xrdw_pgread_req_t, rlen) },
};

int
xrdw_pgread_req_pack(const xrdw_pgread_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_pgread_fields,
                            XRDW_NFIELDS(xrdw_pgread_fields));
}

int
xrdw_pgread_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_pgread_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_pgread_fields,
                              XRDW_NFIELDS(xrdw_pgread_fields));
}

/* ---- kXR_write: fhandle(4) offset(8) pathid(1) reserved(3) ------------ */

static const xrdw_field_t xrdw_write_fields[] = {
    {  0, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_write_req_t, fhandle) },
    {  4, XRDW_F_U64,   0,                offsetof(xrdw_write_req_t, offset) },
    { 12, XRDW_F_U8,    0,                offsetof(xrdw_write_req_t, pathid) },
};

int
xrdw_write_req_pack(const xrdw_write_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_write_fields,
                            XRDW_NFIELDS(xrdw_write_fields));
}

int
xrdw_write_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_write_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_write_fields,
                              XRDW_NFIELDS(xrdw_write_fields));
}

/* ---- kXR_pgwrite: fhandle(4) offset(8) pathid(1) reqflags(1) reserved(2) */

static const xrdw_field_t xrdw_pgwrite_fields[] = {
    {  0, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_pgwrite_req_t, fhandle) },
    {  4, XRDW_F_U64,   0,                offsetof(xrdw_pgwrite_req_t, offset) },
    { 12, XRDW_F_U8,    0,                offsetof(xrdw_pgwrite_req_t, pathid) },
    { 13, XRDW_F_U8,    0,                offsetof(xrdw_pgwrite_req_t, reqflags) },
};

int
xrdw_pgwrite_req_pack(const xrdw_pgwrite_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_pgwrite_fields,
                            XRDW_NFIELDS(xrdw_pgwrite_fields));
}

int
xrdw_pgwrite_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_pgwrite_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_pgwrite_fields,
                              XRDW_NFIELDS(xrdw_pgwrite_fields));
}

/* ---- kXR_truncate: fhandle(4) offset(8) reserved(4) ------------------- */

static const xrdw_field_t xrdw_truncate_fields[] = {
    { 0, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_truncate_req_t, fhandle) },
    { 4, XRDW_F_U64,   0,                offsetof(xrdw_truncate_req_t, offset) },
};

int
xrdw_truncate_req_pack(const xrdw_truncate_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_truncate_fields,
                            XRDW_NFIELDS(xrdw_truncate_fields));
}

int
xrdw_truncate_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_truncate_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_truncate_fields,
                              XRDW_NFIELDS(xrdw_truncate_fields));
}

/* ---- kXR_writev: options(1) reserved(15) ----------------------------- */

static const xrdw_field_t xrdw_writev_fields[] = {
    { 0, XRDW_F_U8, 0, offsetof(xrdw_writev_req_t, options) },
};

int
xrdw_writev_req_pack(const xrdw_writev_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_writev_fields,
                            XRDW_NFIELDS(xrdw_writev_fields));
}

int
xrdw_writev_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_writev_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_writev_fields,
                              XRDW_NFIELDS(xrdw_writev_fields));
}

/* ---- kXR_clone: dst_fhandle(4) reserved(12) -------------------------- */

static const xrdw_field_t xrdw_clone_fields[] = {
    { 0, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_clone_req_t, dst_fhandle) },
};

int
xrdw_clone_req_pack(const xrdw_clone_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_clone_fields,
                            XRDW_NFIELDS(xrdw_clone_fields));
}

int
xrdw_clone_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_clone_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_clone_fields,
                              XRDW_NFIELDS(xrdw_clone_fields));
}

/* ---- kXR_chkpoint: fhandle(4) reserved(11) opcode(1) ----------------- */

static const xrdw_field_t xrdw_chkpoint_fields[] = {
    {  0, XRDW_F_BYTES, XRDW_FHANDLE_LEN, offsetof(xrdw_chkpoint_req_t, fhandle) },
    { 15, XRDW_F_U8,    0,                offsetof(xrdw_chkpoint_req_t, opcode) },
};

int
xrdw_chkpoint_req_pack(const xrdw_chkpoint_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    return xrdw_pack_fields(r, body, xrdw_chkpoint_fields,
                            XRDW_NFIELDS(xrdw_chkpoint_fields));
}

int
xrdw_chkpoint_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_chkpoint_req_t *r)
{
    return xrdw_unpack_fields(body, r, xrdw_chkpoint_fields,
                              XRDW_NFIELDS(xrdw_chkpoint_fields));
}
