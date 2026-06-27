/*
 * ops_file_pg.c - extracted concern
 * Phase-38 split of ops_file.c; behavior-identical.
 */
#include "ops_internal.h"


/* paged I/O with per-page CRC32c (kXR_pgread / kXR_pgwrite, M6) *
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


/* Read and validate one kXR_status frame's 24-byte body. On success sets
 * *resptype (0=Final,1=Partial), *pgdlen (page-data bytes that follow), and
 * *foff (the frame's file offset). kXR_error is surfaced via st. 0 / -1. */
int
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
ssize_t
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
    size_t              total = 0;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_pgread);
    {
        xrdw_pgread_req_t b = { .offset = offset, .rlen = (int32_t) len };
        memcpy(b.fhandle, f->fhandle, XRD_FHANDLE_LEN);
        xrdw_pgread_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
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

/* Resend one page (kXR_pgRetry) from the original buffer and report the server's
 * verdict.  pgoff is the page's file offset; the page data is sliced out of buf
 * at (pgoff - base).  Returns 0 = corrected, 1 = still bad, -1 = error (st set). */
int
pgwrite_retry_one(xrdc_conn *c, xrdc_file *f, const uint8_t *buf, int64_t base,
                  size_t len, int64_t pgoff, xrdc_status *st)
{
    ClientPgWriteRequest req;
    uint16_t  sid;
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
    {
        xrdw_pgwrite_req_t b = { .offset = pgoff, .pathid = 0,
                                 .reqflags = kXR_pgRetry };
        memcpy(b.fhandle, f->fhandle, XRD_FHANDLE_LEN);
        xrdw_pgwrite_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

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
    {
        xrdw_pgwrite_req_t b = { .offset = offset, .pathid = 0, .reqflags = 0 };
        memcpy(b.fhandle, f->fhandle, XRD_FHANDLE_LEN);
        xrdw_pgwrite_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }
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
