/*
 * tap_stream.c — chunk-wise streaming frame decoder for the byte relay.
 *
 * The relay hands us bytes as they arrive off the wire (arbitrary chunk sizes).
 * A two-phase state machine reassembles each frame: collect the fixed header
 * (24B request / 8B response), decode it, then consume `dlen` payload bytes —
 * capturing the first BRIX_TAP_PATH_CAP of them as the path for a path-bearing
 * request. A path frame emits once its path bytes are in; every other frame emits
 * the moment its header completes, so a large write/read payload is skipped, never
 * buffered.
 */

#include "tap.h"
#include "protocols/root/protocol/opcodes.h"   /* kXR_writev, kXR_chkpoint */

#include <string.h>

void
brix_tap_stream_init(brix_tap_stream_t *st, brix_tap_ctx_t *tap,
    brix_tap_dir_t dir)
{
    memset(st, 0, sizeof(*st));
    st->tap           = tap;
    st->dir           = dir;
    st->preamble_skip = (dir == BRIX_TAP_C2U) ? BRIX_TAP_C2U_PREAMBLE : 0;
    st->hdr_need      = (dir == BRIX_TAP_C2U) ? 24 : 8;
}

/*
 * WHAT: decode the just-completed fixed header into st->cur and reset the
 *       per-frame payload accounting.
 * WHY:  every framing/path decision below reads a freshly-decoded st->cur; this
 *       is the one place the wire header is parsed, keeping request/response
 *       decode symmetric and the payload counters zeroed for the new frame.
 * HOW:  dispatch on direction to the request/response decoder, then clear the
 *       payload/path/framing counters (pure state init — no I/O).
 */
static void
tap_header_decode(brix_tap_stream_t *st)
{
    if (st->dir == BRIX_TAP_C2U) {
        brix_tap_decode_request(st->hdr, st->hdr_need, &st->cur);
    } else {
        brix_tap_decode_response(st->hdr, st->hdr_need, &st->cur);
    }
    st->in_payload   = 1;
    st->payload_left = st->cur.dlen;
    st->emitted      = 0;
    st->path_got     = 0;
    st->path_cap     = 0;
}

/*
 * WHAT: classify the frame's stock-framing quirks (writev / chkpoint-ckpXeq) and
 *       arm the descriptor/embedded-header capture machinery for them.
 * WHY:  a few opcodes frame only a prefix in dlen and stream more data after; the
 *       decoder must recover the trailing byte count from bytes seen in the
 *       payload pass, so the arming decision is made once here at header time.
 * HOW:  set wv_active / ckp_active from the opcode + dlen shape and zero their
 *       accumulators (pure state — the payload pass does the byte capture).
 */
static void
tap_header_classify_framing(brix_tap_stream_t *st)
{
    /* kXR_writev stock framing: dlen frames only the 16-byte write_list
     * descriptors; sum(wlen) segment-data bytes stream after the frame.  Sum
     * the wlen fields as the descriptors pass through so the trailing data can
     * be consumed afterwards, keeping the stream aligned on the next header.
     * (A non-16-aligned dlen is malformed — the server drops that link — so no
     * extension is attempted and plain dlen consumption is fine.) */
    st->wv_active   = (st->dir == BRIX_TAP_C2U
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
    st->ckp_active  = (st->dir == BRIX_TAP_C2U
                       && st->cur.opcode == kXR_chkpoint
                       && st->hdr[19] == 4
                       && st->cur.dlen == 24);
    st->ckp_hdr_got = 0;
}

/*
 * WHAT: decide how many leading payload bytes to capture (path for a path-bearing
 *       request, or errnum for a kXR_error response) into st->path_cap.
 * WHY:  the path/errnum lives in the payload after our header buffer, so the
 *       amount to buffer must be derived from the opcode/status before the
 *       payload pass and clamped to BRIX_TAP_PATH_CAP / 4.
 * HOW:  clear st->cur.path, then set path_cap from the request-path or the
 *       error-errnum rule (pure computation — no I/O).
 */
static void
tap_header_set_capture(brix_tap_stream_t *st)
{
    /* The path lives in the payload that follows the header (not in our 24B hdr
     * buffer), so decide path-capture from the opcode and capture it ourselves. */
    st->cur.path     = NULL;
    st->cur.path_len = 0;
    if (st->dir == BRIX_TAP_C2U && st->cur.dlen > 0
        && brix_tap_opcode_has_path(st->cur.opcode))
    {
        st->path_cap = (st->cur.dlen < BRIX_TAP_PATH_CAP)
                     ? st->cur.dlen : BRIX_TAP_PATH_CAP;
    }

    /* A kXR_error body is errnum[4 BE] + errmsg — capture just the errnum
     * (reusing the path-capture machinery) so the frame emits with the error
     * code (kXR_NotFound, …) the bad-actor guard classifies on. */
    if (st->dir == BRIX_TAP_U2C && st->cur.status == kXR_error
        && st->cur.dlen > 0)
    {
        st->path_cap = (st->cur.dlen < 4) ? st->cur.dlen : 4;
    }
}

/*
 * WHAT: header complete — decode it, arm framing/capture, and emit immediately if
 *       nothing in the payload needs to be waited for.
 * WHY:  a frame with no path/errnum to capture emits the moment its header
 *       completes (large read/write payloads are skipped, never buffered); one
 *       place must sequence decode → classify → capture → early-emit.
 * HOW:  call the three pure setup helpers, then when path_cap == 0 emit now and,
 *       if the payload is empty too, close the frame back to header state.
 */
static void
tap_stream_on_header(brix_tap_stream_t *st)
{
    tap_header_decode(st);
    tap_header_classify_framing(st);
    tap_header_set_capture(st);

    if (st->path_cap == 0) {                 /* nothing to wait for → emit now */
        brix_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
        st->emitted = 1;
        if (st->payload_left == 0) {         /* whole frame done */
            st->in_payload = 0;
            st->hdr_got    = 0;
        }
    }
}

/*
 * WHAT: consume `st->preamble_skip` leading bytes of the current buffer chunk.
 * WHY:  a C2U stream opens with a 20-byte handshake preamble that is not a frame
 *       and must be swallowed before header reassembly begins.
 * HOW:  advance buf/len by min(len, preamble_skip) and shrink the counter
 *       (pure pointer/length arithmetic).
 */
static void
tap_feed_preamble(brix_tap_stream_t *st, const uint8_t **buf, size_t *len)
{
    size_t take = (*len < st->preamble_skip) ? *len : st->preamble_skip;
    st->preamble_skip -= take;
    *buf += take;
    *len -= take;
}

/*
 * WHAT: accumulate header bytes from the buffer chunk; on completion decode the
 *       frame.
 * WHY:  the fixed header (24B/8B) arrives across arbitrary chunk boundaries and
 *       must be reassembled before it can be decoded.
 * HOW:  memcpy min(len, remaining-header) into st->hdr, advance buf/len, and
 *       when the header is full invoke tap_stream_on_header (its only side
 *       effect is the early-emit path).
 */
static void
tap_feed_header(brix_tap_stream_t *st, const uint8_t **buf, size_t *len)
{
    size_t need = st->hdr_need - st->hdr_got;
    size_t take = (*len < need) ? *len : need;
    memcpy(st->hdr + st->hdr_got, *buf, take);
    st->hdr_got += take;
    *buf += take;
    *len -= take;
    if (st->hdr_got == st->hdr_need) {
        tap_stream_on_header(st);
    }
}

/*
 * WHAT: from the next `take` payload bytes, capture the path prefix, the ckpXeq
 *       embedded header, and each writev descriptor's wlen (as applicable).
 * WHY:  the path/errnum, the ckpXeq sub-request header, and the writev
 *       trailing-data total all live in bytes that pass through the payload; they
 *       must be snapshot as they go by since the payload is otherwise skipped.
 * HOW:  copy the still-needed prefix into st->pathbuf and st->ckp_hdr, and for an
 *       active writev fold each completed 16-byte descriptor's big-endian wlen
 *       (offset 4) into st->wv_extra (pure capture — no I/O, no *buf advance).
 */
static void
tap_payload_capture(brix_tap_stream_t *st, const uint8_t *buf, size_t take)
{
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
}

/*
 * WHAT: once the awaited leading bytes are in, finalize path/errnum on st->cur
 *       and emit the frame (exactly once).
 * WHY:  a path-bearing request emits after its path bytes arrive, and a kXR_error
 *       response emits after its 4-byte errnum — both reuse the same capture
 *       buffer and must be interpreted per direction before the single emit.
 * HOW:  when not yet emitted and the capture is satisfied, decode the U2C errnum
 *       (BE) or attach the C2U path pointer/length, then emit and latch emitted.
 */
static void
tap_payload_emit_if_ready(brix_tap_stream_t *st)
{
    if (st->emitted || st->path_got < st->path_cap) {
        return;
    }
    if (st->dir == BRIX_TAP_U2C) {
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
    brix_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
    st->emitted = 1;
}

/*
 * WHAT: at a completed ckpXeq frame, decode the embedded sub-request and, for the
 *       write/pgwrite/writev embeds the server accepts, extend payload_left to
 *       cover the sub-request body.
 * WHY:  ckpXeq frames only its 24-byte embedded header in dlen; the sub-request
 *       body streams after and must be consumed (mirroring brix_ckpxeq_body_extra)
 *       to keep the stream aligned, bounded to what the server itself accepts.
 * HOW:  read sub_reqid/sub_dlen from st->ckp_hdr; on a bounded write/pgwrite set
 *       payload_left, on a bounded writev also re-arm wv_*; return 1 if the frame
 *       was extended (caller must `continue`), 0 otherwise.
 */
static int
tap_payload_extend_ckpxeq(brix_tap_stream_t *st)
{
    uint16_t sub_reqid;
    uint64_t sub_dlen;

    if (!st->ckp_active) {
        return 0;
    }
    sub_reqid = ((uint16_t) st->ckp_hdr[2] << 8)
              |  (uint16_t) st->ckp_hdr[3];
    sub_dlen  = ((uint64_t) st->ckp_hdr[20] << 24)
              | ((uint64_t) st->ckp_hdr[21] << 16)
              | ((uint64_t) st->ckp_hdr[22] << 8)
              |  (uint64_t) st->ckp_hdr[23];

    st->ckp_active = 0;
    if (sub_dlen == 0 || st->ckp_hdr_got != sizeof(st->ckp_hdr)) {
        return 0;
    }
    if ((sub_reqid == kXR_write || sub_reqid == kXR_pgwrite)
        && sub_dlen <= 16u * 1024 * 1024) /* MAX_WRITE_PAYLOAD */
    {
        st->payload_left = sub_dlen;
        return 1;
    }
    if (sub_reqid == kXR_writev
        && sub_dlen % 16 == 0
        && sub_dlen <= 1024 * 16)  /* MAXSEGS * SEGSIZE */
    {
        st->payload_left = sub_dlen;
        st->wv_active    = 1;
        st->wv_desc_got  = 0;
        st->wv_extra     = 0;
        return 1;
    }
    return 0;
}

/*
 * WHAT: at a completed writev descriptor block, extend payload_left to cover the
 *       trailing segment data (sum(wlen) bytes).
 * WHY:  writev frames only its descriptors in dlen; the segment data streams
 *       after and must be consumed to realign on the next header.
 * HOW:  clear wv_active; if any wlen total was summed, set payload_left to it and
 *       return 1 (caller must `continue`), else return 0.
 */
static int
tap_payload_extend_writev(brix_tap_stream_t *st)
{
    if (!st->wv_active) {
        return 0;
    }
    st->wv_active = 0;
    if (st->wv_extra > 0) {
        st->payload_left = st->wv_extra;
        return 1;
    }
    return 0;
}

/*
 * WHAT: the current frame's payload is fully consumed — apply the stock-framing
 *       extensions, or close the frame back to header state.
 * WHY:  ckpXeq and writev extend the byte run past dlen; only when no extension
 *       applies is the frame truly done and (defensively) emitted.
 * HOW:  try the ckpXeq then writev extension (each returns 1 to keep consuming);
 *       otherwise emit if not already emitted and reset to header collection.
 *       Returns 1 if the loop should `continue`, 0 if the frame closed.
 */
static int
tap_payload_on_frame_end(brix_tap_stream_t *st)
{
    /* ckpXeq embedded header done: the sub-request body (sub_dlen bytes)
     * streams next.  Mirror the server framing (brix_ckpxeq_body_extra): only
     * extend for the embeds and bounds the server itself accepts — anything
     * else makes the server drop the link, which tears the relay down too.
     * An embedded writev extends by its descriptor block and arms the wv_*
     * machinery, which then extends again by sum(wlen) like a standalone one. */
    if (tap_payload_extend_ckpxeq(st)) {
        return 1;
    }

    /* Descriptors done: the segment data (sum(wlen) bytes) streams next —
     * extend consumption instead of closing the frame. */
    if (tap_payload_extend_writev(st)) {
        return 1;
    }

    if (!st->emitted) {              /* defensive: emit even if no path */
        brix_tap_emit(st->tap, &st->cur, st->dir, NULL, 0);
    }
    st->in_payload = 0;
    st->hdr_got    = 0;
    return 0;
}

/*
 * WHAT: consume the next `take` payload bytes of the current frame.
 * WHY:  payload bytes are captured (path/ckp/wv) and skipped, the frame emits
 *       once its awaited prefix is in, and the frame's end triggers the framing
 *       extensions — this is the per-chunk payload step of the state machine.
 * HOW:  capture, advance buf/len and payload_left by `take`, emit-if-ready,
 *       and on payload exhaustion run the frame-end logic; return that helper's
 *       continue signal (0 while the frame is still filling).
 */
static int
tap_feed_payload(brix_tap_stream_t *st, const uint8_t **buf, size_t *len)
{
    size_t take = (*len < st->payload_left) ? *len : (size_t) st->payload_left;

    tap_payload_capture(st, *buf, take);

    *buf += take;
    *len -= take;
    st->payload_left -= take;

    tap_payload_emit_if_ready(st);

    if (st->payload_left == 0) {
        return tap_payload_on_frame_end(st);
    }
    return 0;
}

void
brix_tap_stream_feed(brix_tap_stream_t *st, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        if (st->preamble_skip > 0) {            /* skip the 20-byte handshake */
            tap_feed_preamble(st, &buf, &len);
            continue;
        }
        if (!st->in_payload) {
            tap_feed_header(st, &buf, &len);
            continue;
        }
        /* in payload: capture path bytes (if any left), then skip the rest */
        tap_feed_payload(st, &buf, &len);
    }
}
