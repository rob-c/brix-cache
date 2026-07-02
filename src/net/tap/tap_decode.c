/*
 * tap_decode.c — XRootD frame header decode for the tap core.
 *
 * Reuses the single-source BE accessors (frame_hdr.h) and opcode constants
 * (opcodes.h). A request header is 24B (streamid[2] + requestid[2] + body[16] +
 * dlen[4]); a response header is 8B (streamid[2] + status[2] + dlen[4]). For a
 * path-bearing request the path is the data payload at offset XRD_REQUEST_HDR_LEN.
 */

#include "tap.h"
#include "protocols/root/protocol/opcodes.h"
#include "protocols/root/protocol/frame_hdr.h"

/* True for request opcodes whose data payload is (or begins with) a path. */
int
xrootd_tap_opcode_has_path(uint16_t op)
{
    switch (op) {
    case kXR_open:
    case kXR_stat:
    case kXR_statx:
    case kXR_mkdir:
    case kXR_rm:
    case kXR_rmdir:
    case kXR_mv:
    case kXR_truncate:
    case kXR_dirlist:
    case kXR_locate:
        return 1;
    default:
        return 0;
    }
}

size_t
xrootd_tap_decode_request(const uint8_t *buf, size_t len,
    xrootd_tap_frame_t *out)
{
    if (buf == NULL || out == NULL || len < XRD_REQUEST_HDR_LEN) {
        return 0;
    }

    out->is_request = 1;
    out->streamid   = xrd_get_u16_be(buf);
    out->opcode     = xrd_get_u16_be(buf + 2);
    out->status     = 0;
    out->errnum     = 0;
    out->dlen       = xrd_get_u32_be(buf + 20);
    out->path       = NULL;
    out->path_len   = 0;

    if (out->dlen > 0 && xrootd_tap_opcode_has_path(out->opcode)) {
        size_t avail = len - XRD_REQUEST_HDR_LEN;
        size_t plen  = (out->dlen < avail) ? out->dlen : avail;
        if (plen > 0) {
            out->path     = buf + XRD_REQUEST_HDR_LEN;
            out->path_len = plen;
        }
    }
    return XRD_REQUEST_HDR_LEN;
}

size_t
xrootd_tap_decode_response(const uint8_t *buf, size_t len,
    xrootd_tap_frame_t *out)
{
    if (buf == NULL || out == NULL || len < 8) {
        return 0;
    }

    out->is_request = 0;
    out->opcode     = 0;
    out->errnum     = 0;
    out->path       = NULL;
    out->path_len   = 0;
    xrd_resp_hdr_unpack(buf, &out->streamid, &out->status, &out->dlen);

    /* A kXR_error body is errnum[4 BE] + errmsg; surface the errnum when the
     * payload bytes are present so consumers (the bad-actor guard) can map
     * kXR_NotFound / kXR_NotAuthorized without re-parsing. */
    if (out->status == kXR_error && out->dlen >= 4 && len >= 8 + 4) {
        out->errnum = xrd_get_u32_be(buf + 8);
    }
    return 8;
}
