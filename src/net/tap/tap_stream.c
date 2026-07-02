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
            buf += take;
            len -= take;
            st->payload_left -= take;

            if (!st->emitted && st->path_got >= st->path_cap) {
                st->cur.path     = st->pathbuf;
                st->cur.path_len = st->path_got;
                xrootd_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
                st->emitted = 1;
            }
            if (st->payload_left == 0) {
                if (!st->emitted) {          /* defensive: emit even if no path */
                    xrootd_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
                }
                st->in_payload = 0;
                st->hdr_got    = 0;
            }
        }
    }
}
