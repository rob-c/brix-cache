/*
 * wire_codec_file.c — file-family wire-body codec. See wire_codec.h.
 *
 * open / close / read / pgread / write / pgwrite / sync / truncate / writev /
 * clone / chkpoint request bodies. These carry the hot-path multi-byte integer
 * fields (i64 offsets, i32 lengths) — the byte-order contract that previously
 * lived as scattered htonl/ntohl on both sides now lives here once. Pure C.
 */
#include "wire_codec.h"

#include <string.h>

/* ---- kXR_open: mode(2) options(2) optiont(2) reserved(6) fhtemplt(4) --- */

int
xrdw_open_req_pack(const xrdw_open_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    xrdw_put_u16(body + 0, r->mode);
    xrdw_put_u16(body + 2, r->options);
    xrdw_put_u16(body + 4, r->optiont);
    memcpy(body + 12, r->fhtemplt, XRDW_FHANDLE_LEN);
    return XRDW_BODY_LEN;
}

int
xrdw_open_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_open_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->mode    = xrdw_get_u16(body + 0);
    r->options = xrdw_get_u16(body + 2);
    r->optiont = xrdw_get_u16(body + 4);
    memcpy(r->fhtemplt, body + 12, XRDW_FHANDLE_LEN);
    return XRDW_OK;
}

/* ---- kXR_close / kXR_sync: fhandle(4) reserved(12) -------------------- */

int
xrdw_close_req_pack(const xrdw_close_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body, r->fhandle, XRDW_FHANDLE_LEN);
    return XRDW_BODY_LEN;
}

int
xrdw_close_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_close_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->fhandle, body, XRDW_FHANDLE_LEN);
    return XRDW_OK;
}

int
xrdw_sync_req_pack(const xrdw_sync_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body, r->fhandle, XRDW_FHANDLE_LEN);
    return XRDW_BODY_LEN;
}

int
xrdw_sync_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_sync_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->fhandle, body, XRDW_FHANDLE_LEN);
    return XRDW_OK;
}

/* ---- kXR_read / kXR_pgread: fhandle(4) offset(8) rlen(4) -------------- */

int
xrdw_read_req_pack(const xrdw_read_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body, r->fhandle, XRDW_FHANDLE_LEN);
    xrdw_put_u64(body + 4, (uint64_t) r->offset);
    xrdw_put_u32(body + 12, (uint32_t) r->rlen);
    return XRDW_BODY_LEN;
}

int
xrdw_read_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_read_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->fhandle, body, XRDW_FHANDLE_LEN);
    r->offset = (int64_t) xrdw_get_u64(body + 4);
    r->rlen   = (int32_t) xrdw_get_u32(body + 12);
    return XRDW_OK;
}

int
xrdw_pgread_req_pack(const xrdw_pgread_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body, r->fhandle, XRDW_FHANDLE_LEN);
    xrdw_put_u64(body + 4, (uint64_t) r->offset);
    xrdw_put_u32(body + 12, (uint32_t) r->rlen);
    return XRDW_BODY_LEN;
}

int
xrdw_pgread_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_pgread_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->fhandle, body, XRDW_FHANDLE_LEN);
    r->offset = (int64_t) xrdw_get_u64(body + 4);
    r->rlen   = (int32_t) xrdw_get_u32(body + 12);
    return XRDW_OK;
}

/* ---- kXR_write: fhandle(4) offset(8) pathid(1) reserved(3) ------------ */

int
xrdw_write_req_pack(const xrdw_write_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body, r->fhandle, XRDW_FHANDLE_LEN);
    xrdw_put_u64(body + 4, (uint64_t) r->offset);
    body[12] = r->pathid;
    return XRDW_BODY_LEN;
}

int
xrdw_write_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_write_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->fhandle, body, XRDW_FHANDLE_LEN);
    r->offset = (int64_t) xrdw_get_u64(body + 4);
    r->pathid = body[12];
    return XRDW_OK;
}

/* ---- kXR_pgwrite: fhandle(4) offset(8) pathid(1) reqflags(1) reserved(2) */

int
xrdw_pgwrite_req_pack(const xrdw_pgwrite_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body, r->fhandle, XRDW_FHANDLE_LEN);
    xrdw_put_u64(body + 4, (uint64_t) r->offset);
    body[12] = r->pathid;
    body[13] = r->reqflags;
    return XRDW_BODY_LEN;
}

int
xrdw_pgwrite_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_pgwrite_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->fhandle, body, XRDW_FHANDLE_LEN);
    r->offset   = (int64_t) xrdw_get_u64(body + 4);
    r->pathid   = body[12];
    r->reqflags = body[13];
    return XRDW_OK;
}

/* ---- kXR_truncate: fhandle(4) offset(8) reserved(4) ------------------- */

int
xrdw_truncate_req_pack(const xrdw_truncate_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body, r->fhandle, XRDW_FHANDLE_LEN);
    xrdw_put_u64(body + 4, (uint64_t) r->offset);
    return XRDW_BODY_LEN;
}

int
xrdw_truncate_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_truncate_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->fhandle, body, XRDW_FHANDLE_LEN);
    r->offset = (int64_t) xrdw_get_u64(body + 4);
    return XRDW_OK;
}

/* ---- kXR_writev: options(1) reserved(15) ----------------------------- */

int
xrdw_writev_req_pack(const xrdw_writev_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    body[0] = r->options;
    return XRDW_BODY_LEN;
}

int
xrdw_writev_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_writev_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    r->options = body[0];
    return XRDW_OK;
}

/* ---- kXR_clone: dst_fhandle(4) reserved(12) -------------------------- */

int
xrdw_clone_req_pack(const xrdw_clone_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body, r->dst_fhandle, XRDW_FHANDLE_LEN);
    return XRDW_BODY_LEN;
}

int
xrdw_clone_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_clone_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->dst_fhandle, body, XRDW_FHANDLE_LEN);
    return XRDW_OK;
}

/* ---- kXR_chkpoint: fhandle(4) reserved(11) opcode(1) ----------------- */

int
xrdw_chkpoint_req_pack(const xrdw_chkpoint_req_t *r, uint8_t body[XRDW_BODY_LEN])
{
    if (r == NULL || body == NULL) {
        return XRDW_EINVAL;
    }
    memset(body, 0, XRDW_BODY_LEN);
    memcpy(body, r->fhandle, XRDW_FHANDLE_LEN);
    body[15] = r->opcode;
    return XRDW_BODY_LEN;
}

int
xrdw_chkpoint_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_chkpoint_req_t *r)
{
    if (body == NULL || r == NULL) {
        return XRDW_EINVAL;
    }
    memcpy(r->fhandle, body, XRDW_FHANDLE_LEN);
    r->opcode = body[15];
    return XRDW_OK;
}
