/*
 * ops_file_rw.c - extracted concern
 * Phase-38 split of ops_file.c; behavior-identical.
 */
#include "ops_internal.h"


/*
 * phase-42 W4 — inflate one inline-compressed kXR_read frame.  The server
 * compressed `out_cap`-bounded plaintext as a single self-contained codec frame,
 * so a guard with out_cap = the requested length is sufficient (the data is our
 * own server's, so the expansion-ratio bomb guard is left off).  Returns the
 * plaintext length produced, or -1 on a malformed/oversized frame.
 */
ssize_t
brix_inflate_frame(uint8_t codec, const uint8_t *comp, size_t comp_len,
                   void *out, size_t out_cap, brix_status *st)
{
    brix_codec_guard_t   guard;
    brix_codec_stream_t *s;
    size_t                 in_pos = 0, out_pos = 0;

    if (comp_len == 0) {
        return 0;   /* empty frame ⇒ zero plaintext bytes (EOF / empty range) */
    }

    memset(&guard, 0, sizeof(guard));
    guard.out_cap   = out_cap;   /* plaintext cannot exceed the requested len */
    guard.max_ratio = 0;

    s = brix_codec_open((brix_codec_id_t) codec,
                          BRIX_CODEC_DIR_DECOMPRESS, -1, &guard);
    if (s == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "inline read decompression unavailable (codec %u)",
                        (unsigned) codec);
        return -1;
    }

    for (;;) {
        size_t            prev_in = in_pos, prev_out = out_pos;
        brix_codec_rc_t rc = brix_codec_step(s, comp, comp_len, &in_pos,
                                                 (uint8_t *) out, out_cap,
                                                 &out_pos, 1 /* finish */);
        if (rc == BRIX_CODEC_END) {
            break;
        }
        if (rc != BRIX_CODEC_OK
            || (in_pos == prev_in && out_pos == prev_out))
        {
            brix_codec_close(s);
            brix_status_set(st, XRDC_EPROTO, 0,
                            "corrupt inline-compressed read frame");
            return -1;
        }
    }

    brix_codec_close(s);
    return (ssize_t) out_pos;
}


ssize_t
brix_file_read(brix_conn *c, brix_file *f, int64_t offset, void *buf, size_t len,
               brix_status *st)
{
    ClientReadRequest req;
    uint16_t          sid, status;
    size_t            total = 0;
    uint8_t          *comp = NULL;   /* accumulated codec frame (compressed only) */
    size_t            comp_cap = 0;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_read);
    {
        xrdw_read_req_t b = { .offset = offset, .rlen = (int32_t) len };
        memcpy(b.fhandle, f->fhandle, XRD_FHANDLE_LEN);
        xrdw_read_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    if (brix_send(c, &req, NULL, &sid, st) != 0) {
        return -1;
    }

    /* One or more frames (kXR_oksofar* then kXR_ok) make up the read result.
     * Plaintext handles copy straight into buf; compressed handles accumulate
     * the whole frame into `comp` and inflate it once the final kXR_ok arrives. */
    for (;;) {
        uint8_t *body = NULL;
        uint32_t blen = 0;
        brix_resp_out out = { &status, &body, &blen };
        if (brix_recv(c, sid, &out, st) != 0) {
            free(comp);
            return -1;
        }
        if (blen > 0) {
            if (f->read_codec == 0) {
                if (total + blen > len) {
                    free(body);
                    brix_status_set(st, XRDC_EPROTO, 0,
                                    "read returned more than requested");
                    return -1;
                }
                memcpy((uint8_t *) buf + total, body, blen);
                total += blen;
            } else {
                /* Accumulate compressed bytes (cap at 2x len + slack — a frame
                 * of plaintext <= len cannot legitimately exceed that). */
                size_t max_comp = len + (len / 2) + 4096;
                if (total + blen > max_comp) {
                    free(body);
                    free(comp);
                    brix_status_set(st, XRDC_EPROTO, 0,
                                    "compressed read frame too large");
                    return -1;
                }
                if (total + blen > comp_cap) {
                    size_t ncap = comp_cap ? comp_cap * 2 : 65536;
                    uint8_t *p;
                    while (ncap < total + blen) {
                        ncap *= 2;
                    }
                    p = (uint8_t *) realloc(comp, ncap);
                    if (p == NULL) {
                        free(body);
                        free(comp);
                        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
                        return -1;
                    }
                    comp = p;
                    comp_cap = ncap;
                }
                memcpy(comp + total, body, blen);
                total += blen;
            }
        }
        free(body);
        if (status == kXR_ok) {
            break;
        }
    }

    if (f->read_codec == 0) {
        return (ssize_t) total;
    }

    {
        ssize_t plain = brix_inflate_frame(f->read_codec, comp, total,
                                           buf, len, st);
        free(comp);
        return plain;
    }
}


/*
 * phase-42 W5: compress `in_len` plaintext bytes as ONE self-contained codec
 * frame for an inline-write upload (the inverse of brix_inflate_frame).  Returns
 * a malloc'd buffer (caller frees) and sets *out_len, or NULL on failure.
 */
uint8_t *
brix_deflate_frame(uint8_t codec, const void *in, size_t in_len, size_t *out_len,
                   brix_status *st)
{
    size_t                 cap = in_len + in_len / 2 + 4096;
    uint8_t               *out = malloc(cap);
    brix_codec_stream_t *s;
    size_t                 in_pos = 0, out_pos = 0;

    if (out == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return NULL;
    }
    s = brix_codec_open((brix_codec_id_t) codec,
                          BRIX_CODEC_DIR_COMPRESS, -1, NULL);
    if (s == NULL) {
        free(out);
        brix_status_set(st, XRDC_EPROTO, 0,
                        "inline write compression unavailable (codec %u)",
                        (unsigned) codec);
        return NULL;
    }
    for ( ;; ) {
        size_t            prev_in = in_pos, prev_out = out_pos;
        brix_codec_rc_t rc = brix_codec_step(s, in, in_len, &in_pos,
                                                 out, cap, &out_pos, 1 /*finish*/);
        uint8_t *p;
        if (rc == BRIX_CODEC_END) {
            break;
        }
        if (rc != BRIX_CODEC_OK
            || (in_pos == prev_in && out_pos == prev_out))
        {
            brix_codec_close(s);
            free(out);
            brix_status_set(st, XRDC_EPROTO, 0, "compress failed");
            return NULL;
        }
        /* OK with room remaining: the codec made progress but isn't finished (e.g.
         * lz4 consumes its input in chunks) — call again into the same buffer.
         * Only a genuinely full buffer needs a grow (preserving bytes via realloc).
         * cap is pre-sized to > the worst-case compressed size, so growth is rare. */
        if (out_pos < cap) {
            continue;
        }
        cap *= 2;
        p = realloc(out, cap);
        if (p == NULL) {
            brix_codec_close(s);
            free(out);
            brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
            return NULL;
        }
        out = p;
    }
    brix_codec_close(s);
    *out_len = out_pos;
    return out;
}


int
brix_file_write(brix_conn *c, brix_file *f, int64_t offset, const void *buf,
                size_t len, brix_status *st)
{
    ClientWriteRequest req;
    uint16_t           sid, status;
    uint8_t           *body = NULL;
    uint32_t           blen = 0;
    const void        *payload = buf;
    size_t             plen = len;
    uint8_t           *frame = NULL;

    /* phase-42 W5: a compression-negotiated write handle compresses each payload
     * as a self-contained frame; the server decompresses it on ingest and stores
     * the plaintext.  The request offset stays the PLAINTEXT offset. */
    if (f->write_codec != 0 && len > 0) {
        size_t flen = 0;
        frame = brix_deflate_frame(f->write_codec, buf, len, &flen, st);
        if (frame == NULL) {
            return -1;
        }
        payload = frame;
        plen = flen;
    }

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_write);
    {
        xrdw_write_req_t b = { .offset = offset, .pathid = 0 };
        memcpy(b.fhandle, f->fhandle, XRD_FHANDLE_LEN);
        xrdw_write_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    /* dlen is set by brix_send from the payload length. */

    {
        brix_payload pl = { payload, (uint32_t) plen };
        if (brix_send(c, &req, &pl, &sid, st) != 0) {
            free(frame);
            return -1;
        }
    }
    free(frame);
    {
        brix_resp_out out = { &status, &body, &blen };
        if (brix_recv(c, sid, &out, st) != 0) {
            return -1;
        }
    }
    free(body);
    return 0;
}


/* ---- Accumulate a kXR_readv reply into one contiguous buffer ----
 *
 * WHAT: Reads the kXR_oksofar* then terminal kXR_ok frames of an in-flight
 * kXR_readv response into a single heap buffer, returning 0 with *out_acc /
 * *out_len set (caller frees *out_acc) or -1 on recv/allocation/size-cap
 * failure (buffer freed internally, so the caller must NOT free on -1).
 *
 * WHY: The readv reply may be split across many kXR_oksofar frames; segment
 * scatter needs the whole reply as one linear span. Splitting accumulation out
 * of brix_file_readv keeps both the receive loop and the segment walk below the
 * complexity cap without altering the wire behaviour.
 *
 * HOW:
 *   1. Loop receiving frames with brix_recv into a growable buffer `acc`.
 *   2. Reject any reply that would exceed XRDC_VEC_MAXBYTES.
 *   3. Grow capacity by doubling (from 65536) when the next frame won't fit,
 *      preserving already-accumulated bytes via realloc.
 *   4. Append each frame body, then stop once a kXR_ok status is seen.
 */
static int
brix_readv_accumulate(brix_conn *c, uint16_t sid, uint8_t **out_acc,
                      size_t *out_len, brix_status *st)
{
    uint8_t *acc = NULL;
    size_t   acc_len = 0, acc_cap = 0;
    uint16_t status;

    for (;;) {                          /* accumulate kXR_oksofar* then kXR_ok */
        uint8_t *body = NULL;
        uint32_t blen = 0;
        brix_resp_out out = { &status, &body, &blen };
        if (brix_recv(c, sid, &out, st) != 0) {
            free(acc);
            return -1;
        }
        if (blen > 0) {
            if (acc_len + blen > XRDC_VEC_MAXBYTES) {
                free(body); free(acc);
                brix_status_set(st, XRDC_EPROTO, 0, "readv: response too large");
                return -1;
            }
            if (acc_len + blen > acc_cap) {
                size_t   nc = acc_cap ? acc_cap : 65536;
                uint8_t *na;
                while (nc < acc_len + blen) { nc *= 2; }
                na = (uint8_t *) realloc(acc, nc);
                if (na == NULL) {
                    free(body); free(acc);
                    brix_status_set(st, XRDC_EPROTO, 0, "readv: out of memory");
                    return -1;
                }
                acc = na; acc_cap = nc;
            }
            memcpy(acc + acc_len, body, blen);
            acc_len += blen;
        }
        free(body);
        if (status == kXR_ok) {
            break;
        }
    }
    *out_acc = acc;
    *out_len = acc_len;
    return 0;
}


/* ---- Scatter an accumulated kXR_readv reply into caller segment buffers ----
 *
 * WHAT: Walks the accumulated reply `acc` (length acc_len) in request order,
 * copying each segment's data into segs[i].buf and recording the actual byte
 * count in segs[i].got. Returns the total bytes scattered, or -1 on a truncated
 * segment header or body. Does not free `acc` (the caller owns it).
 *
 * WHY: The reply interleaves, per segment, a 16-byte readahead_list header
 * carrying the ACTUAL read length followed by that many data bytes; segments
 * must be recovered in request order. Isolating this walk from the receive loop
 * keeps brix_file_readv under the complexity cap with no behaviour change.
 *
 * HOW:
 *   1. For each of the nseg segments, verify a full 16-byte header remains.
 *   2. Decode the per-segment length rl via the shared segment codec.
 *   3. Verify rl data bytes remain, then copy min(rl, segs[i].len) into the
 *      segment buffer and set segs[i].got.
 *   4. Advance the cursor past the data and sum the copied bytes.
 */
static ssize_t
brix_readv_scatter(const uint8_t *acc, size_t acc_len,
                   brix_readv_seg *segs, size_t nseg, brix_status *st)
{
    size_t  i, cursor = 0;
    ssize_t total = 0;

    for (i = 0; i < nseg; i++) {         /* [readahead_list 16B][data rlen] per seg */
        uint32_t rl;
        size_t   cp;
        if (cursor + BRIX_READV_SEGSIZE > acc_len) {
            brix_status_set(st, XRDC_EPROTO, 0, "readv: truncated segment header");
            return -1;
        }
        rl = brix_readv_seg_rlen(acc + cursor);   /* shared segment codec */
        cursor += BRIX_READV_SEGSIZE;
        if (cursor + rl > acc_len) {
            brix_status_set(st, XRDC_EPROTO, 0, "readv: truncated segment data");
            return -1;
        }
        cp = (rl <= segs[i].len) ? rl : segs[i].len;
        memcpy(segs[i].buf, acc + cursor, cp);
        segs[i].got = cp;            /* actual bytes for this segment (≤ len) */
        total += (ssize_t) cp;
        cursor += rl;
    }
    return total;
}


/*
 * kXR_readv (3025) — scatter-gather read. The request payload is nseg readahead_list
 * entries (fhandle[4] + rlen[4 BE] + offset[8 BE]); the response interleaves, per
 * segment, a 16-byte header (with the ACTUAL read length) then that many data bytes,
 * possibly split across kXR_oksofar frames. We accumulate the whole reply, then walk
 * the segments in request order into each seg.buf. Returns total bytes read.
 */
ssize_t
brix_file_readv(brix_conn *c, brix_file *f, brix_readv_seg *segs,
                size_t nseg, brix_status *st)
{
    ClientRequestHdr req;
    uint8_t         *payload;
    uint16_t         sid;
    uint8_t         *acc = NULL;
    size_t           acc_len = 0, i;
    ssize_t          total;

    if (nseg == 0 || nseg > XRDC_VEC_MAXSEGS) {
        brix_status_set(st, XRDC_EUSAGE, 0, "readv: bad segment count");
        return -1;
    }
    payload = (uint8_t *) malloc(nseg * BRIX_READV_SEGSIZE);
    if (payload == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "readv: out of memory");
        return -1;
    }
    for (i = 0; i < nseg; i++) {
        /* Shared segment-header codec — same layout the server packs/parses. */
        brix_readv_seg_pack(payload + i * BRIX_READV_SEGSIZE, f->fhandle,
                              (uint32_t) segs[i].len, (uint64_t) segs[i].offset);
    }
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_readv);
    xrdw_empty_req_pack(((ClientRequestHdr *) &req)->body);
    {
        brix_payload pl = { payload, (uint32_t) (nseg * BRIX_READV_SEGSIZE) };
        if (brix_send(c, &req, &pl, &sid, st) != 0) {
            free(payload);
            return -1;
        }
    }
    free(payload);

    if (brix_readv_accumulate(c, sid, &acc, &acc_len, st) != 0) {
        return -1;
    }

    total = brix_readv_scatter(acc, acc_len, segs, nseg, st);
    free(acc);
    return total;
}


/*
 * kXR_writev (3031) — scatter-gather write. Wire framing (stock
 * XrdXrootdProtocol::do_WriteV): the header dlen covers ONLY the nseg*16-byte
 * write_list descriptor block (fhandle[4] + wlen[4 BE] + offset[8 BE]
 * back-to-back); the concatenated segment data streams immediately after the
 * frame and the server recovers its length as sum(wlen).  Counting the data
 * inside dlen is rejected by stock servers with kXR_ArgInvalid ("Write vector
 * is invalid") followed by a link drop.  do_sync sets kXR_wv_doSync (fsync
 * each touched handle).  The write is all-or-nothing.
 */
int
brix_file_writev(brix_conn *c, brix_file *f, const brix_writev_seg *segs,
                 size_t nseg, int do_sync, brix_status *st)
{
    ClientWriteVRequest req;
    uint8_t            *payload, *p;
    uint16_t            sid, status;
    uint8_t            *body = NULL;
    uint32_t            blen = 0;
    size_t              i, total_data = 0, plen;

    if (nseg == 0 || nseg > XRDC_VEC_MAXSEGS) {
        brix_status_set(st, XRDC_EUSAGE, 0, "writev: bad segment count");
        return -1;
    }
    /* Bound the aggregate payload so the size_t sum can't wrap and plen stays
     * inside the uint32_t wire dlen field (256MiB, matching readv's response cap). */
    for (i = 0; i < nseg; i++) {
        if (segs[i].len > XRDC_VEC_MAXBYTES
            || total_data > XRDC_VEC_MAXBYTES - segs[i].len) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "writev: payload exceeds %u bytes", XRDC_VEC_MAXBYTES);
            return -1;
        }
        total_data += segs[i].len;
    }
    plen = nseg * 16 + total_data;
    payload = (uint8_t *) malloc(plen);
    if (payload == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "writev: out of memory");
        return -1;
    }
    for (i = 0; i < nseg; i++) {              /* descriptor block */
        uint8_t *e  = payload + i * 16;
        uint32_t wl = htonl((uint32_t) segs[i].len);
        uint64_t of = htobe64((uint64_t) segs[i].offset);
        memcpy(e, f->fhandle, XRD_FHANDLE_LEN);
        memcpy(e + 4, &wl, 4);
        memcpy(e + 8, &of, 8);
    }
    p = payload + nseg * 16;                  /* concatenated data block */
    for (i = 0; i < nseg; i++) {
        memcpy(p, segs[i].data, segs[i].len);
        p += segs[i].len;
    }
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_writev);
    {
        xrdw_writev_req_t b = { .options = (uint8_t) (do_sync ? kXR_wv_doSync : 0) };
        xrdw_writev_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
    /* dlen frames only the descriptor block; the data bytes ride after it. */
    {
        brix_payload_ext pe = { payload, (uint32_t) plen,
                                (uint32_t) (nseg * 16) };
        if (brix_send_ext(c, &req, &pe, &sid, st) != 0) {
            free(payload);
            return -1;
        }
    }
    free(payload);
    {
        brix_resp_out out = { &status, &body, &blen };
        if (brix_recv(c, sid, &out, st) != 0) {
            return -1;
        }
    }
    free(body);
    return 0;
}
