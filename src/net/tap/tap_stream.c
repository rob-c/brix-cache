/*
 * tap_stream.c — chunk-wise streaming frame decoder for the byte relay.
 *
 * The relay hands us bytes as they arrive off the wire (arbitrary chunk sizes).
 * A two-phase state machine reassembles each frame: collect the fixed header
 * (24B request / 8B response), decode it, then consume `dlen` payload bytes —
 * capturing the first XROOTD_TAP_PATH_CAP of them as the path for a path-bearing
 * request. A path frame emits once its path bytes are in; every other frame emits
 * the moment its header completes, so a large write/read payload is skipped, never
 * buffered.
 */

#include "tap.h"
#include "protocols/root/protocol/opcodes.h"   /* kXR_writev, kXR_chkpoint */

#include <string.h>

void
xrootd_tap_stream_init(xrootd_tap_stream_t *st, xrootd_tap_ctx_t *tap,
    xrootd_tap_dir_t dir)
{
    memset(st, 0, sizeof(*st));
    st->tap           = tap;
    st->dir           = dir;
    st->preamble_skip = (dir == XROOTD_TAP_C2U) ? XROOTD_TAP_C2U_PREAMBLE : 0;
    st->hdr_need      = (dir == XROOTD_TAP_C2U) ? 24 : 8;
}

/* Header complete: decode it, set up payload accounting + path capture. */
static void
tap_stream_on_header(xrootd_tap_stream_t *st)
{
    if (st->dir == XROOTD_TAP_C2U) {
        xrootd_tap_decode_request(st->hdr, st->hdr_need, &st->cur);
    } else {
        xrootd_tap_decode_response(st->hdr, st->hdr_need, &st->cur);
    }
    st->in_payload   = 1;
    st->payload_left = st->cur.dlen;
    st->emitted      = 0;
    st->path_got     = 0;
    st->path_cap     = 0;

    /* kXR_writev stock framing: dlen frames only the 16-byte write_list
     * descriptors; sum(wlen) segment-data bytes stream after the frame.  Sum
     * the wlen fields as the descriptors pass through so the trailing data can
     * be consumed afterwards, keeping the stream aligned on the next header.
     * (A non-16-aligned dlen is malformed — the server drops that link — so no
     * extension is attempted and plain dlen consumption is fine.) */
    st->wv_active   = (st->dir == XROOTD_TAP_C2U
                       && st->cur.opcode == kXR_writev
                       && st->cur.dlen > 0
                       && st->cur.dlen % 16 == 0);
    st->wv_desc_got = 0;
    st->wv_extra    = 0;

    /* kXR_chkpoint/ckpXeq stock framing: dlen covers only the embedded
     * 24-byte sub-request header; the sub-request body streams after the
     * frame (see chkpoint_xeq.c).  Capture the embedded header as it passes
     * so the trailing byte count can be recovered once the frame completes.
     * The ckpXeq opcode byte sits at header offset 19 (kXR_ckpXeq == 4). */
    st->ckp_active  = (st->dir == XROOTD_TAP_C2U
                       && st->cur.opcode == kXR_chkpoint
                       && st->hdr[19] == 4
                       && st->cur.dlen == 24);
    st->ckp_hdr_got = 0;

    /* The path lives in the payload that follows the header (not in our 24B hdr
     * buffer), so decide path-capture from the opcode and capture it ourselves. */
    st->cur.path     = NULL;
    st->cur.path_len = 0;
    if (st->dir == XROOTD_TAP_C2U && st->cur.dlen > 0
        && xrootd_tap_opcode_has_path(st->cur.opcode))
    {
        st->path_cap = (st->cur.dlen < XROOTD_TAP_PATH_CAP)
                     ? st->cur.dlen : XROOTD_TAP_PATH_CAP;
    }

    /* A kXR_error body is errnum[4 BE] + errmsg — capture just the errnum
     * (reusing the path-capture machinery) so the frame emits with the error
     * code (kXR_NotFound, …) the bad-actor guard classifies on. */
    if (st->dir == XROOTD_TAP_U2C && st->cur.status == kXR_error
        && st->cur.dlen > 0)
    {
        st->path_cap = (st->cur.dlen < 4) ? st->cur.dlen : 4;
    }

    if (st->path_cap == 0) {                 /* nothing to wait for → emit now */
        xrootd_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
        st->emitted = 1;
        if (st->payload_left == 0) {         /* whole frame done */
            st->in_payload = 0;
            st->hdr_got    = 0;
        }
    }
}

void
xrootd_tap_stream_feed(xrootd_tap_stream_t *st, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        if (st->preamble_skip > 0) {            /* skip the 20-byte handshake */
            size_t take = (len < st->preamble_skip) ? len : st->preamble_skip;
            st->preamble_skip -= take;
            buf += take;
            len -= take;
            continue;
        }
        if (!st->in_payload) {
            size_t need = st->hdr_need - st->hdr_got;
            size_t take = (len < need) ? len : need;
            memcpy(st->hdr + st->hdr_got, buf, take);
            st->hdr_got += take;
            buf += take;
            len -= take;
            if (st->hdr_got == st->hdr_need) {
                tap_stream_on_header(st);
            }
            continue;
        }

        /* in payload: capture path bytes (if any left), then skip the rest */
        {
            size_t take = (len < st->payload_left)
                        ? len : (size_t) st->payload_left;
            if (st->path_cap > st->path_got) {
                size_t cap = st->path_cap - st->path_got;
                if (cap > take) { cap = take; }
                memcpy(st->pathbuf + st->path_got, buf, cap);
                st->path_got += cap;
            }

            /* ckpXeq embedded-header pass: capture the 24-byte sub-request
             * header (it is the entire dlen-framed payload). */
            if (st->ckp_active && st->ckp_hdr_got < sizeof(st->ckp_hdr)) {
                size_t cap = sizeof(st->ckp_hdr) - st->ckp_hdr_got;
                if (cap > take) { cap = take; }
                memcpy(st->ckp_hdr + st->ckp_hdr_got, buf, cap);
                st->ckp_hdr_got += cap;
            }

            /* writev descriptor pass: fold each completed 16-byte descriptor's
             * big-endian wlen (offset 4) into the trailing-data total. */
            if (st->wv_active) {
                size_t k;
                for (k = 0; k < take; k++) {
                    st->wv_desc[st->wv_desc_got++] = buf[k];
                    if (st->wv_desc_got == sizeof(st->wv_desc)) {
                        st->wv_extra += ((uint64_t) st->wv_desc[4] << 24)
                                      | ((uint64_t) st->wv_desc[5] << 16)
                                      | ((uint64_t) st->wv_desc[6] << 8)
                                      |  (uint64_t) st->wv_desc[7];
                        st->wv_desc_got = 0;
                    }
                }
            }

            buf += take;
            len -= take;
            st->payload_left -= take;

            if (!st->emitted && st->path_got >= st->path_cap) {
                if (st->dir == XROOTD_TAP_U2C) {
                    /* captured bytes = the kXR_error errnum, not a path */
                    if (st->path_got >= 4) {
                        st->cur.errnum = ((uint32_t) st->pathbuf[0] << 24)
                                       | ((uint32_t) st->pathbuf[1] << 16)
                                       | ((uint32_t) st->pathbuf[2] << 8)
                                       |  (uint32_t) st->pathbuf[3];
                    }
                } else {
                    st->cur.path     = st->pathbuf;
                    st->cur.path_len = st->path_got;
                }
                xrootd_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
                st->emitted = 1;
            }
            if (st->payload_left == 0) {
                /* ckpXeq embedded header done: the sub-request body
                 * (sub_dlen bytes) streams next.  Mirror the server framing
                 * (xrootd_ckpxeq_body_extra): only extend for the embeds and
                 * bounds the server itself accepts — anything else makes the
                 * server drop the link, which tears the relay down too.
                 * An embedded writev extends by its descriptor block and
                 * arms the wv_* machinery, which then extends again by
                 * sum(wlen) exactly like a standalone writev. */
                if (st->ckp_active) {
                    uint16_t sub_reqid = ((uint16_t) st->ckp_hdr[2] << 8)
                                       |  (uint16_t) st->ckp_hdr[3];
                    uint64_t sub_dlen  = ((uint64_t) st->ckp_hdr[20] << 24)
                                       | ((uint64_t) st->ckp_hdr[21] << 16)
                                       | ((uint64_t) st->ckp_hdr[22] << 8)
                                       |  (uint64_t) st->ckp_hdr[23];

                    st->ckp_active = 0;
                    if (sub_dlen > 0 && st->ckp_hdr_got == sizeof(st->ckp_hdr)) {
                        if ((sub_reqid == kXR_write || sub_reqid == kXR_pgwrite)
                            && sub_dlen <= 16u * 1024 * 1024) /* MAX_WRITE_PAYLOAD */
                        {
                            st->payload_left = sub_dlen;
                            continue;
                        }
                        if (sub_reqid == kXR_writev
                            && sub_dlen % 16 == 0
                            && sub_dlen <= 1024 * 16)  /* MAXSEGS * SEGSIZE */
                        {
                            st->payload_left = sub_dlen;
                            st->wv_active    = 1;
                            st->wv_desc_got  = 0;
                            st->wv_extra     = 0;
                            continue;
                        }
                    }
                }

                /* Descriptors done: the segment data (sum(wlen) bytes) streams
                 * next — extend consumption instead of closing the frame. */
                if (st->wv_active) {
                    st->wv_active = 0;
                    if (st->wv_extra > 0) {
                        st->payload_left = st->wv_extra;
                        continue;
                    }
                }
                if (!st->emitted) {          /* defensive: emit even if no path */
                    xrootd_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
                }
                st->in_payload = 0;
                st->hdr_got    = 0;
            }
        }
    }
}
