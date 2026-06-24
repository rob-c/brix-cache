/*
 * ops_file.c — file operations: open / read / write / close.
 *
 * WHAT: kXR_open (read or write modes), kXR_read (with kXR_oksofar accumulation),
 *       kXR_write, kXR_close.
 * WHY:  These back xrdcp download (M2: open-read/read/close) and upload
 *       (M3: open-write/write/close).
 * HOW:  The path is the open request payload (dlen=strlen). The file handle from
 *       the open response is echoed in every subsequent read/write/close. Offsets
 *       are 64-bit big-endian; large reads may arrive as several kXR_oksofar
 *       frames before the final kXR_ok.
 *
 * wire: XProtocol.hh ClientOpenRequest — mode[2] options[2] optiont[2] ... fhtemplt[4];
 * wire: XProtocol.hh ServerOpenBody — fhandle[4] cpsize[4] cptype[4];
 * wire: XProtocol.hh ClientReadRequest — fhandle[4] offset[8] rlen[4].
 */
#include "xrdc.h"
#include "compat/crc32c.h"   /* xrootd_crc32c_value (libxrdproto) — per-page CRC */
#include "compat/pgio.h"     /* shared kXR page-mode encode/decode (libxrdproto) */
#include "compat/codec_core.h" /* phase-42 W4 inline read decompression */
#include "protocol/frame_hdr.h" /* shared resp-hdr / error codecs (libxrdproto) */
#include "protocol/open_flags.h" /* shared kXR_open option-bit semantics */
#include "protocol/readv_seg.h"  /* shared kXR_readv segment-header codec */

#include <arpa/inet.h>
#include <endian.h>
#include <string.h>
#include <stdlib.h>

/* open_read/open_write are the no-opaque cases of xrdc_file_open_opaque (defined
 * below); keep them as thin wrappers so the open framing lives in one place. */
int
xrdc_file_open_read(xrdc_conn *c, const char *path, xrdc_file *f, xrdc_status *st)
{
    return xrdc_file_open_opaque(c, path, NULL, 0, 0, 0, f, st);
}

int
xrdc_file_open_write(xrdc_conn *c, const char *path, int force, int posc,
                     xrdc_file *f, xrdc_status *st)
{
    return xrdc_file_open_opaque(c, path, NULL, 1, force, posc, f, st);
}

int
xrdc_file_open_update(xrdc_conn *c, const char *path, int posc,
                      xrdc_file *f, xrdc_status *st)
{
    /* force==2: open an EXISTING file for read+write IN PLACE (no truncate, no
     * create) — kXR_open_updt only. Enables random writes over existing content. */
    return xrdc_file_open_opaque(c, path, NULL, 1, 2, posc, f, st);
}

/*
 * phase-42 W4 — inflate one inline-compressed kXR_read frame.  The server
 * compressed `out_cap`-bounded plaintext as a single self-contained codec frame,
 * so a guard with out_cap = the requested length is sufficient (the data is our
 * own server's, so the expansion-ratio bomb guard is left off).  Returns the
 * plaintext length produced, or -1 on a malformed/oversized frame.
 */
ssize_t
xrdc_inflate_frame(uint8_t codec, const uint8_t *comp, size_t comp_len,
                   void *out, size_t out_cap, xrdc_status *st)
{
    xrootd_codec_guard_t   guard;
    xrootd_codec_stream_t *s;
    size_t                 in_pos = 0, out_pos = 0;

    if (comp_len == 0) {
        return 0;   /* empty frame ⇒ zero plaintext bytes (EOF / empty range) */
    }

    memset(&guard, 0, sizeof(guard));
    guard.out_cap   = out_cap;   /* plaintext cannot exceed the requested len */
    guard.max_ratio = 0;

    s = xrootd_codec_open((xrootd_codec_id_t) codec,
                          XROOTD_CODEC_DIR_DECOMPRESS, -1, &guard);
    if (s == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "inline read decompression unavailable (codec %u)",
                        (unsigned) codec);
        return -1;
    }

    for (;;) {
        size_t            prev_in = in_pos, prev_out = out_pos;
        xrootd_codec_rc_t rc = xrootd_codec_step(s, comp, comp_len, &in_pos,
                                                 (uint8_t *) out, out_cap,
                                                 &out_pos, 1 /* finish */);
        if (rc == XROOTD_CODEC_END) {
            break;
        }
        if (rc != XROOTD_CODEC_OK
            || (in_pos == prev_in && out_pos == prev_out))
        {
            xrootd_codec_close(s);
            xrdc_status_set(st, XRDC_EPROTO, 0,
                            "corrupt inline-compressed read frame");
            return -1;
        }
    }

    xrootd_codec_close(s);
    return (ssize_t) out_pos;
}

ssize_t
xrdc_file_read(xrdc_conn *c, xrdc_file *f, int64_t offset, void *buf, size_t len,
               xrdc_status *st)
{
    ClientReadRequest req;
    uint16_t          sid, status;
    size_t            total = 0;
    uint64_t          off_be = htobe64((uint64_t) offset);
    uint8_t          *comp = NULL;   /* accumulated codec frame (compressed only) */
    size_t            comp_cap = 0;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_read);
    memcpy(req.fhandle, f->fhandle, XRD_FHANDLE_LEN);
    memcpy(&req.offset, &off_be, 8);
    req.rlen = (kXR_int32) htonl((uint32_t) len);

    if (xrdc_send(c, &req, NULL, 0, &sid, st) != 0) {
        return -1;
    }

    /* One or more frames (kXR_oksofar* then kXR_ok) make up the read result.
     * Plaintext handles copy straight into buf; compressed handles accumulate
     * the whole frame into `comp` and inflate it once the final kXR_ok arrives. */
    for (;;) {
        uint8_t *body = NULL;
        uint32_t blen = 0;
        if (xrdc_recv(c, sid, &status, &body, &blen, st) != 0) {
            free(comp);
            return -1;
        }
        if (blen > 0) {
            if (f->read_codec == 0) {
                if (total + blen > len) {
                    free(body);
                    xrdc_status_set(st, XRDC_EPROTO, 0,
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
                    xrdc_status_set(st, XRDC_EPROTO, 0,
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
                        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
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
        ssize_t plain = xrdc_inflate_frame(f->read_codec, comp, total,
                                           buf, len, st);
        free(comp);
        return plain;
    }
}

/*
 * phase-42 W5: compress `in_len` plaintext bytes as ONE self-contained codec
 * frame for an inline-write upload (the inverse of xrdc_inflate_frame).  Returns
 * a malloc'd buffer (caller frees) and sets *out_len, or NULL on failure.
 */
uint8_t *
xrdc_deflate_frame(uint8_t codec, const void *in, size_t in_len, size_t *out_len,
                   xrdc_status *st)
{
    size_t                 cap = in_len + in_len / 2 + 4096;
    uint8_t               *out = malloc(cap);
    xrootd_codec_stream_t *s;
    size_t                 in_pos = 0, out_pos = 0;

    if (out == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return NULL;
    }
    s = xrootd_codec_open((xrootd_codec_id_t) codec,
                          XROOTD_CODEC_DIR_COMPRESS, -1, NULL);
    if (s == NULL) {
        free(out);
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "inline write compression unavailable (codec %u)",
                        (unsigned) codec);
        return NULL;
    }
    for ( ;; ) {
        size_t            prev_in = in_pos, prev_out = out_pos;
        xrootd_codec_rc_t rc = xrootd_codec_step(s, in, in_len, &in_pos,
                                                 out, cap, &out_pos, 1 /*finish*/);
        uint8_t *p;
        if (rc == XROOTD_CODEC_END) {
            break;
        }
        if (rc != XROOTD_CODEC_OK
            || (in_pos == prev_in && out_pos == prev_out))
        {
            xrootd_codec_close(s);
            free(out);
            xrdc_status_set(st, XRDC_EPROTO, 0, "compress failed");
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
            xrootd_codec_close(s);
            free(out);
            xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
            return NULL;
        }
        out = p;
    }
    xrootd_codec_close(s);
    *out_len = out_pos;
    return out;
}

int
xrdc_file_write(xrdc_conn *c, xrdc_file *f, int64_t offset, const void *buf,
                size_t len, xrdc_status *st)
{
    ClientWriteRequest req;
    uint16_t           sid, status;
    uint8_t           *body = NULL;
    uint32_t           blen = 0;
    uint64_t           off_be = htobe64((uint64_t) offset);
    const void        *payload = buf;
    size_t             plen = len;
    uint8_t           *frame = NULL;

    /* phase-42 W5: a compression-negotiated write handle compresses each payload
     * as a self-contained frame; the server decompresses it on ingest and stores
     * the plaintext.  The request offset stays the PLAINTEXT offset. */
    if (f->write_codec != 0 && len > 0) {
        size_t flen = 0;
        frame = xrdc_deflate_frame(f->write_codec, buf, len, &flen, st);
        if (frame == NULL) {
            return -1;
        }
        payload = frame;
        plen = flen;
    }

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_write);
    memcpy(req.fhandle, f->fhandle, XRD_FHANDLE_LEN);
    memcpy(&req.offset, &off_be, 8);
    /* dlen is set by xrdc_send from the payload length. */

    if (xrdc_send(c, &req, payload, (uint32_t) plen, &sid, st) != 0) {
        free(frame);
        return -1;
    }
    free(frame);
    if (xrdc_recv(c, sid, &status, &body, &blen, st) != 0) {
        return -1;
    }
    free(body);
    return 0;
}

/*
 * kXR_readv (3025) — scatter-gather read. The request payload is nseg readahead_list
 * entries (fhandle[4] + rlen[4 BE] + offset[8 BE]); the response interleaves, per
 * segment, a 16-byte header (with the ACTUAL read length) then that many data bytes,
 * possibly split across kXR_oksofar frames. We accumulate the whole reply, then walk
 * the segments in request order into each seg.buf. Returns total bytes read.
 */
ssize_t
xrdc_file_readv(xrdc_conn *c, xrdc_file *f, xrdc_readv_seg *segs,
                size_t nseg, xrdc_status *st)
{
    ClientRequestHdr req;
    uint8_t         *payload;
    uint16_t         sid, status;
    uint8_t         *acc = NULL;
    size_t           acc_len = 0, acc_cap = 0, i, cursor;
    ssize_t          total = 0;

    if (nseg == 0 || nseg > XRDC_VEC_MAXSEGS) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "readv: bad segment count");
        return -1;
    }
    payload = (uint8_t *) malloc(nseg * XROOTD_READV_SEGSIZE);
    if (payload == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "readv: out of memory");
        return -1;
    }
    for (i = 0; i < nseg; i++) {
        /* Shared segment-header codec — same layout the server packs/parses. */
        xrootd_readv_seg_pack(payload + i * XROOTD_READV_SEGSIZE, f->fhandle,
                              (uint32_t) segs[i].len, (uint64_t) segs[i].offset);
    }
    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_readv);
    if (xrdc_send(c, &req, payload, (uint32_t) (nseg * XROOTD_READV_SEGSIZE),
                  &sid, st) != 0) {
        free(payload);
        return -1;
    }
    free(payload);

    for (;;) {                          /* accumulate kXR_oksofar* then kXR_ok */
        uint8_t *body = NULL;
        uint32_t blen = 0;
        if (xrdc_recv(c, sid, &status, &body, &blen, st) != 0) {
            free(acc);
            return -1;
        }
        if (blen > 0) {
            if (acc_len + blen > XRDC_VEC_MAXBYTES) {
                free(body); free(acc);
                xrdc_status_set(st, XRDC_EPROTO, 0, "readv: response too large");
                return -1;
            }
            if (acc_len + blen > acc_cap) {
                size_t   nc = acc_cap ? acc_cap : 65536;
                uint8_t *na;
                while (nc < acc_len + blen) { nc *= 2; }
                na = (uint8_t *) realloc(acc, nc);
                if (na == NULL) {
                    free(body); free(acc);
                    xrdc_status_set(st, XRDC_EPROTO, 0, "readv: out of memory");
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

    cursor = 0;
    for (i = 0; i < nseg; i++) {         /* [readahead_list 16B][data rlen] per seg */
        uint32_t rl;
        size_t   cp;
        if (cursor + XROOTD_READV_SEGSIZE > acc_len) {
            free(acc);
            xrdc_status_set(st, XRDC_EPROTO, 0, "readv: truncated segment header");
            return -1;
        }
        rl = xrootd_readv_seg_rlen(acc + cursor);   /* shared segment codec */
        cursor += XROOTD_READV_SEGSIZE;
        if (cursor + rl > acc_len) {
            free(acc);
            xrdc_status_set(st, XRDC_EPROTO, 0, "readv: truncated segment data");
            return -1;
        }
        cp = (rl <= segs[i].len) ? rl : segs[i].len;
        memcpy(segs[i].buf, acc + cursor, cp);
        segs[i].got = cp;            /* actual bytes for this segment (≤ len) */
        total += (ssize_t) cp;
        cursor += rl;
    }
    free(acc);
    return total;
}

/*
 * kXR_writev (3031) — scatter-gather write. Payload = nseg write_list descriptors
 * (fhandle[4] + wlen[4 BE] + offset[8 BE]) back-to-back, then the concatenated data
 * for every segment (the server recovers N from n*16 + sum(wlen) == dlen). do_sync
 * sets kXR_wv_doSync (fsync each touched handle). The write is all-or-nothing.
 */
int
xrdc_file_writev(xrdc_conn *c, xrdc_file *f, const xrdc_writev_seg *segs,
                 size_t nseg, int do_sync, xrdc_status *st)
{
    ClientWriteVRequest req;
    uint8_t            *payload, *p;
    uint16_t            sid, status;
    uint8_t            *body = NULL;
    uint32_t            blen = 0;
    size_t              i, total_data = 0, plen;

    if (nseg == 0 || nseg > XRDC_VEC_MAXSEGS) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "writev: bad segment count");
        return -1;
    }
    /* Bound the aggregate payload so the size_t sum can't wrap and plen stays
     * inside the uint32_t wire dlen field (256MiB, matching readv's response cap). */
    for (i = 0; i < nseg; i++) {
        if (segs[i].len > XRDC_VEC_MAXBYTES
            || total_data > XRDC_VEC_MAXBYTES - segs[i].len) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "writev: payload exceeds %u bytes", XRDC_VEC_MAXBYTES);
            return -1;
        }
        total_data += segs[i].len;
    }
    plen = nseg * 16 + total_data;
    payload = (uint8_t *) malloc(plen);
    if (payload == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "writev: out of memory");
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
    req.options = (kXR_char) (do_sync ? kXR_wv_doSync : 0);
    if (xrdc_send(c, &req, payload, (uint32_t) plen, &sid, st) != 0) {
        free(payload);
        return -1;
    }
    free(payload);
    if (xrdc_recv(c, sid, &status, &body, &blen, st) != 0) {
        return -1;
    }
    free(body);
    return 0;
}

int
xrdc_file_close(xrdc_conn *c, xrdc_file *f, xrdc_status *st)
{
    ClientCloseRequest req;
    uint16_t           sid, status;
    uint8_t           *body = NULL;
    uint32_t           blen = 0;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_close);
    memcpy(req.fhandle, f->fhandle, XRD_FHANDLE_LEN);

    if (xrdc_send(c, &req, NULL, 0, &sid, st) != 0) {
        return -1;
    }
    if (xrdc_recv(c, sid, &status, &body, &blen, st) != 0) {
        return -1;
    }
    free(body);
    return 0;
}

/* ---- TPC helpers (M8): open-with-opaque + sync (arm/trigger) ---- */

int
xrdc_file_open_opaque(xrdc_conn *c, const char *path, const char *opaque,
                      int write, int force, int posc, xrdc_file *f,
                      xrdc_status *st)
{
    ClientOpenRequest req;
    uint16_t          status, options;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;
    char             *payload;
    size_t            need;
    int               plen;

    /* kXR_open option bits come from the shared builder (protocol/open_flags.h)
     * so this request and the server's POSIX-flag decode share one definition of
     * the create/truncate/in-place (`force`) semantics. Writes always make parent
     * dirs (mkpath). */
    options = xrootd_open_options_build(write, force, posc, /*mkpath=*/1);

    /* The server splits "<path>?<opaque>" — open_extract_opaque (src/read).
     * Heap-size to the actual lengths; no opaque ⇒ bare path (open_read/write). */
    need = strlen(path) + 1 + (opaque ? strlen(opaque) : 0) + 1;
    payload = (char *) malloc(need);
    if (payload == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    plen = (opaque != NULL && opaque[0] != '\0')
           ? snprintf(payload, need, "%s?%s", path, opaque)
           : snprintf(payload, need, "%s", path);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_open);
    req.mode      = write ? htons(0644) : 0;
    req.options   = htons(options);

    if (xrdc_roundtrip(c, &req, payload, (uint32_t) plen,
                       &status, &body, &blen, st) != 0) {
        free(payload);
        return -1;
    }
    free(payload);
    if (blen < XRD_FHANDLE_LEN) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "open reply too short (%u bytes)", blen);
        free(body);
        return -1;
    }
    memcpy(f->fhandle, body, XRD_FHANDLE_LEN);

    /*
     * phase-42 W4/W5 — inline read/write compression.  The ServerOpenBody is
     * fhandle[4] cpsize[4] cptype[4]; a server that confirmed compression sets
     * BOTH cpsize = XROOTD_INLINE_CMP_MAGIC (big-endian) AND cptype[0] = codec
     * ordinal (the dual-check contract in codec_core.h).  Require the cpsize magic
     * before trusting cptype[0]: cptype is a legacy XRootD field, so a stock or
     * non-cooperating server may place an arbitrary small byte there — adopting it
     * without the magic would make us inflate PLAINTEXT responses and corrupt the
     * transfer.  Both halves must agree, else fall back to plaintext.
     */
    f->read_codec = 0;
    f->write_codec = 0;
    if (blen >= 12) {
        uint32_t cpsize = ((uint32_t) body[4] << 24) | ((uint32_t) body[5] << 16)
                        | ((uint32_t) body[6] << 8)  |  (uint32_t) body[7];
        uint8_t  cid    = body[8];   /* cptype[0] */
        if (cpsize == XROOTD_INLINE_CMP_MAGIC && cid >= 1 && cid < XROOTD_CODEC_MAX) {
            /* The server CONFIRMED inline compression with codec `cid` and WILL
             * send compressed frames (read) or expect them (write).  If this
             * client build cannot handle that codec we must FAIL the open: silently
             * falling back to the plaintext branch would copy the still-compressed
             * bytes verbatim and corrupt the transfer (asymmetric build). */
            if (!xrootd_codec_available(cid)) {
                xrdc_status_set(st, XRDC_EUNSUPPORTED, 0,
                    "server negotiated inline-compression codec %u that this "
                    "client build cannot decode", (unsigned) cid);
                free(body);
                return -1;
            }
            /* W4 read opens compress responses; W5 write opens compress the
             * payloads this client sends.  At most one direction is negotiated. */
            if (write) {
                f->write_codec = cid;
            } else {
                f->read_codec = cid;
            }
        }
    }

    free(body);
    return 0;
}

int
xrdc_file_sync(xrdc_conn *c, xrdc_file *f, xrdc_status *st)
{
    ClientSyncRequest req;
    uint16_t          sid, status;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_sync);
    memcpy(req.fhandle, f->fhandle, XRD_FHANDLE_LEN);

    if (xrdc_send(c, &req, NULL, 0, &sid, st) != 0) {
        return -1;
    }
    if (xrdc_recv(c, sid, &status, &body, &blen, st) != 0) {
        return -1;
    }
    free(body);
    return 0;
}

/* ---- paged I/O with per-page CRC32c (kXR_pgread / kXR_pgwrite, M6) ----
 *
 * Both replies use kXR_status (4007) framing, NOT the kXR_ok path, so they are
 * read here rather than via xrdc_recv. One status frame is:
 *   ServerResponseHdr{status=kXR_status, dlen=24}
 *   ServerResponseBody_Status{crc32c[4], streamID[2], requestid[1], resptype[1],
 *                             reserved[4], dlen[4]}   (16 bytes)
 *   trailing offset[8]                                 (pgRead/pgWrite body)
 * The header crc32c covers the 20 bytes streamID..offset; bdy.dlen is the size of
 * the page-data that follows the 24-byte body (0 for pgwrite). Page units are
 * [crc32c_be 4][data ≤4096], aligned to the FILE offset (short first page).
 */

#define XRDC_PG_STATUSBODY 24   /* ServerResponseBody_Status(16) + offset(8) */

/* Read and validate one kXR_status frame's 24-byte body. On success sets
 * *resptype (0=Final,1=Partial), *pgdlen (page-data bytes that follow), and
 * *foff (the frame's file offset). kXR_error is surfaced via st. 0 / -1. */
static int
read_status_frame(xrdc_conn *c, uint16_t want_sid, uint8_t *resptype,
                  uint32_t *pgdlen, int64_t *foff, xrdc_status *st)
{
    uint8_t  hdr[XRD_RESPONSE_HDR_LEN];
    uint8_t  sb[XRDC_PG_STATUSBODY];
    uint16_t sid, stat;
    uint32_t dlen, want_crc, got_crc;
    uint64_t off_be;

    if (xrdc_read_full(&c->io, hdr, sizeof(hdr), st) != 0) {
        return -1;
    }
    xrd_resp_hdr_unpack(hdr, &sid, &stat, &dlen);   /* unaligned-safe */

    if (stat == kXR_error) {
        uint8_t *eb = NULL;
        int      errnum = 0;
        if (dlen > 0 && dlen <= XRDC_DLEN_MAX) {
            eb = (uint8_t *) malloc(dlen);
            if (eb != NULL && xrdc_read_full(&c->io, eb, dlen, st) == 0) {
                const char *emsg = "";
                size_t      emlen = 0;
                /* bounded msg slice — eb is not NUL-terminated. */
                xrd_error_body_decode(eb, dlen, &errnum, &emsg, &emlen);
                xrdc_status_set(st, errnum, 0, "%.*s (%s)", (int) emlen,
                                emsg ? emsg : "", xrdc_kxr_name(errnum));
            }
        }
        free(eb);
        if (st->kxr == 0) {
            xrdc_status_set(st, XRDC_EPROTO, 0, "pg op error (status %u)", stat);
        }
        return -1;
    }
    if (stat != kXR_status) {
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "expected kXR_status, got %u", stat);
        return -1;
    }
    if (want_sid != 0xffff && sid != want_sid) {
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "stream id mismatch (got %u, want %u)", sid, want_sid);
        return -1;
    }
    if (dlen != XRDC_PG_STATUSBODY) {
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "bad kXR_status body length %u (want %d)",
                        dlen, XRDC_PG_STATUSBODY);
        return -1;
    }
    if (xrdc_read_full(&c->io, sb, sizeof(sb), st) != 0) {
        return -1;
    }

    /* crc32c covers sb[4..24): streamID(2) requestid(1) resptype(1) reserved(4)
     * dlen(4) offset(8) = 20 bytes. */
    want_crc = xrd_get_u32_be(sb);                  /* unaligned-safe */
    got_crc  = xrootd_crc32c_value(sb + 4, XRDC_PG_STATUSBODY - 4);
    if (want_crc != got_crc) {
        xrdc_status_set(st, XRDC_EINTEGRITY, 0,
                        "kXR_status header CRC mismatch (got %08x want %08x)",
                        got_crc, want_crc);
        return -1;
    }

    *resptype = sb[7];
    *pgdlen   = xrd_get_u32_be(sb + 12);            /* unaligned-safe */
    memcpy(&off_be, sb + 16, 8);
    *foff = (int64_t) be64toh(off_be);
    return 0;
}

/* Decode one frame's page-data buffer (units of [crc 4][data], file-offset
 * aligned at file_off) into dst, verifying each page's CRC32c. Returns decoded
 * data bytes, or -1 (st set) on a CRC mismatch or malformed framing. */
static ssize_t
decode_pages(const uint8_t *pg, uint32_t pglen, int64_t file_off,
             uint8_t *dst, size_t dstcap, xrdc_status *st)
{
    int64_t bad = file_off;
    ssize_t n   = xrdp_pg_decode(pg, (size_t) pglen, file_off, dst, dstcap, &bad);

    if (n == -1) {
        xrdc_status_set(st, XRDC_EINTEGRITY, 0,
                        "pgread CRC mismatch at offset %lld", (long long) bad);
        return -1;
    }
    if (n < 0) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "pgread malformed page framing");
        return -1;
    }
    return n;
}

ssize_t
xrdc_file_pgread(xrdc_conn *c, xrdc_file *f, int64_t offset, void *buf,
                 size_t len, xrdc_status *st)
{
    ClientPgReadRequest req;
    uint16_t            sid;
    uint64_t            off_be = htobe64((uint64_t) offset);
    size_t              total = 0;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_pgread);
    memcpy(req.fhandle, f->fhandle, XRD_FHANDLE_LEN);
    memcpy(&req.offset, &off_be, 8);
    req.rlen = (kXR_int32) htonl((uint32_t) len);
    /* dlen (offset 20) is set to 0 by xrdc_send (no args payload). */

    if (xrdc_send(c, &req, NULL, 0, &sid, st) != 0) {
        return -1;
    }

    /* Accumulate kXR_status frames until resptype=Final (the module sends one
     * Final frame per request; Partial is handled defensively). */
    for (;;) {
        uint8_t  resptype = 0;
        uint32_t pgdlen = 0;
        int64_t  foff = 0;
        uint8_t *pg;
        ssize_t  decoded;

        if (read_status_frame(c, sid, &resptype, &pgdlen, &foff, st) != 0) {
            return -1;
        }
        if (pgdlen == 0) {
            if (resptype == kXR_FinalResult) {
                break;
            }
            continue;
        }
        pg = (uint8_t *) malloc(pgdlen);
        if (pg == NULL) {
            xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (%u)", pgdlen);
            return -1;
        }
        if (xrdc_read_full(&c->io, pg, pgdlen, st) != 0) {
            free(pg);
            return -1;
        }
        decoded = decode_pages(pg, pgdlen, foff,
                               (uint8_t *) buf + total, len - total, st);
        free(pg);
        if (decoded < 0) {
            return -1;
        }
        total += (size_t) decoded;
        if (resptype == kXR_FinalResult) {
            break;
        }
    }
    return (ssize_t) total;
}

/* Max kXR_pgRetry attempts per corrupt page before giving up (fast-fail). */
#define XRDC_PGW_MAX_RETRY 3

/* Resend one page (kXR_pgRetry) from the original buffer and report the server's
 * verdict.  pgoff is the page's file offset; the page data is sliced out of buf
 * at (pgoff - base).  Returns 0 = corrected, 1 = still bad, -1 = error (st set). */
static int
pgwrite_retry_one(xrdc_conn *c, xrdc_file *f, const uint8_t *buf, int64_t base,
                  size_t len, int64_t pgoff, xrdc_status *st)
{
    ClientPgWriteRequest req;
    uint16_t  sid;
    uint64_t  off_be = htobe64((uint64_t) pgoff);
    uint8_t   rp[kXR_pgPageSZ + 4];
    size_t    doff = (size_t) (pgoff - base);
    size_t    to_boundary = (size_t) kXR_pgPageSZ
                            - (size_t) (pgoff & (int64_t) (kXR_pgPageSZ - 1));
    size_t    remaining, page_len, rplen;
    uint8_t   resptype = 0;
    uint32_t  pgdlen = 0;
    int64_t   foff = 0;

    if (pgoff < base || doff >= len) {
        xrdc_status_set(st, XRDC_EPROTO, 0,
                        "pgwrite CSE offset %lld out of range", (long long) pgoff);
        return -1;
    }
    remaining = len - doff;
    page_len  = remaining < to_boundary ? remaining : to_boundary;
    rplen     = xrdp_pg_encode(buf + doff, page_len, pgoff, rp);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_pgwrite);
    memcpy(req.fhandle, f->fhandle, XRD_FHANDLE_LEN);
    memcpy(&req.offset, &off_be, 8);
    req.pathid   = 0;
    req.reqflags = kXR_pgRetry;

    if (xrdc_send(c, &req, rp, (uint32_t) rplen, &sid, st) != 0) {
        return -1;
    }
    if (read_status_frame(c, sid, &resptype, &pgdlen, &foff, st) != 0) {
        return -1;
    }
    if (pgdlen != 0) {
        /* Still bad — drain and discard the CSE trailer, report not-yet-clean. */
        uint8_t *cse = (uint8_t *) malloc(pgdlen);
        if (cse != NULL) {
            (void) xrdc_read_full(&c->io, cse, pgdlen, st);
            free(cse);
        }
        return 1;
    }
    return 0;
}

int
xrdc_file_pgwrite(xrdc_conn *c, xrdc_file *f, int64_t offset, const void *buf,
                  size_t len, xrdc_status *st)
{
    ClientPgWriteRequest req;
    uint16_t             sid;
    uint64_t             off_be = htobe64((uint64_t) offset);
    uint8_t             *payload = NULL;
    size_t               cap, plen = 0;
    uint8_t              resptype = 0;
    uint32_t             pgdlen = 0;
    int64_t              foff = 0;

    /* Worst case: one 4-byte CRC per page plus a short first/last page → at most
     * (len/pagesz + 2) checksums. Build the [crc][data] payload via the shared
     * page-mode encoder (libxrdproto) so client-encode == server-decode. */
    cap = len + ((len / kXR_pgPageSZ) + 2) * 4;
    payload = (uint8_t *) malloc(cap);
    if (payload == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (%zu)", cap);
        return -1;
    }
    plen = xrdp_pg_encode((const uint8_t *) buf, len, offset, payload);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_pgwrite);
    memcpy(req.fhandle, f->fhandle, XRD_FHANDLE_LEN);
    memcpy(&req.offset, &off_be, 8);
    req.pathid   = 0;
    req.reqflags = 0;
    /* dlen (offset 20) is set to plen by xrdc_send. */

    if (xrdc_send(c, &req, payload, (uint32_t) plen, &sid, st) != 0) {
        free(payload);
        return -1;
    }
    if (read_status_frame(c, sid, &resptype, &pgdlen, &foff, st) != 0) {
        free(payload);   /* kXR_ChkSumErr (CRC rejected) surfaces here */
        return -1;
    }
    if (pgdlen != 0) {
        /* CSE: the server wrote the data but reported pages that failed CRC32c
         * (typically wire corruption — our encode is always correct).  Read the
         * retransmit list and resend each page with kXR_pgRetry until the server
         * accepts it or we exhaust the bounded attempts. */
        uint8_t *cse = (uint8_t *) malloc(pgdlen);
        size_t   nbad, i;
        int      rc_ret = 0;

        if (cse == NULL || xrdc_read_full(&c->io, cse, pgdlen, st) != 0) {
            free(cse);
            free(payload);
            if (cse == NULL) {
                xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (%u)", pgdlen);
            }
            return -1;
        }

        /* Trailer: cseCRC(4) dlFirst(2) dlLast(2) then int64 bof[n]. */
        if (pgdlen < 8 || ((pgdlen - 8) % 8) != 0) {
            free(cse);
            free(payload);
            xrdc_status_set(st, XRDC_EPROTO, 0,
                            "malformed pgwrite CSE trailer (%u bytes)", pgdlen);
            return -1;
        }
        nbad = (size_t) (pgdlen - 8) / 8;

        for (i = 0; i < nbad && rc_ret == 0; i++) {
            uint64_t bo_be;
            int64_t  bo;
            int      attempt, verdict = 1;

            memcpy(&bo_be, cse + 8 + i * 8, 8);
            bo = (int64_t) be64toh(bo_be);

            for (attempt = 0; attempt < XRDC_PGW_MAX_RETRY; attempt++) {
                verdict = pgwrite_retry_one(c, f, (const uint8_t *) buf, offset,
                                            len, bo, st);
                if (verdict <= 0) {
                    break;   /* 0 = corrected, -1 = error */
                }
            }
            if (verdict > 0) {
                xrdc_status_set(st, XRDC_EINTEGRITY, 0,
                    "pgwrite page %lld uncorrectable after %d retries",
                    (long long) bo, XRDC_PGW_MAX_RETRY);
                rc_ret = -1;
            } else if (verdict < 0) {
                rc_ret = -1;
            }
        }

        free(cse);
        free(payload);
        return rc_ret;
    }
    free(payload);
    return 0;
}
