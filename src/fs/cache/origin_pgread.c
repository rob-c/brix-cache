#include "platform/platform_api.h"
/*
 * origin_pgread.c — page-verified origin reads (kXR_pgread) for the cache fill.
 *
 * WHAT: brix_cache_origin_pgread_chunk() — the integrity-checking sibling of
 *       brix_cache_origin_read_chunk().  It asks the origin for the SAME byte
 *       range with kXR_pgread instead of kXR_read, so the reply carries a
 *       CRC32c for every 4 KiB page, and it verifies each of those CRCs before
 *       one byte reaches the sink.
 *
 * WHY:  a cache fill over plain kXR_read trusts the wire completely.  TCP's
 *       checksum is 16 bits and covers only what the endpoints agree on; a
 *       flipped bit in a switch, a mis-behaving on-path box, or an active MITM
 *       on a cleartext `root://` link all produce bytes the fill would commit
 *       and then serve — permanently, to every later client, as a good hit.
 *       The whole-file digest check (verify.h) closes that hole ONLY for a
 *       fill that reads a complete file AND an origin that can answer
 *       kXR_Qcksum; a slice/block fill, a range read, and a digest-less origin
 *       are all unprotected.  Per-page CRC32c protects every read, verified
 *       BEFORE the bytes are written, and it is the mechanism XRootD itself
 *       standardised for exactly this (INVARIANT #1).
 *
 * HOW:  one kXR_pgread request, then a train of kXR_status(4007) frames:
 *         [ServerResponseHdr 8B  status=kXR_status, dlen=24]
 *         [ServerResponseBody_Status 16B  crc32c, streamID, requestid,
 *                                         resptype, reserved, dlen]
 *         [ServerResponseBody_pgRead 8B   file offset]
 *         ---- bdy.dlen page bytes follow, NOT counted in hdr.dlen ----
 *       The body's own crc32c covers the 20 bytes streamID..offset; the page
 *       bytes are units of [CRC32c-BE 4][data <= 4096] aligned to the FILE
 *       offset.  Decoding + per-page verification is NOT reimplemented here:
 *       it is xrdp_pg_decode() from core/compat/pgio.h, the same kernel the
 *       server encodes with and the native client decodes with, so producer
 *       and consumer agree by construction.  resptype kXR_PartialResult keeps
 *       the train going; kXR_FinalResult ends it.
 *
 *       Capability, not trial and error: the bootstrap records the origin's
 *       kXR_protocol advert in oc->srv_flags, so an origin that never claimed
 *       kXR_suppgrw is answered from that flag with no wasted round trip.  An
 *       origin that advertises the capability and then refuses the request
 *       (kXR_Unsupported / kXR_InvalidRequest) is treated identically.  Both
 *       return BRIX_CACHE_PGREAD_UNSUPPORTED and set NO task error — the
 *       caller owns the fall-back-or-fail decision, because only it knows
 *       whether the operator asked for best-effort or require.
 */

#include "cache_internal.h"
#include "core/compat/pgio.h"                     /* xrdp_pg_decode (shared)  */
#include "core/compat/crc32c.h"                   /* brix_crc32c_value        */
#include "protocols/root/protocol/frame_hdr.h"    /* xrd_get_u32/u64_be, error decode */
#include "protocols/root/protocol/flags.h"        /* kXR_pgPageSZ, kXR_suppgrw */

/* macOS doesn't have endian.h - use libkern/OSByteOrder.h */
#if defined(__APPLE__) && defined(__MACH__)
#elif defined(__linux__)
/* PAL endian ops now in platform_api.h
 * brix_plat_htobe64/brix_plat_be64toh cross-platform
 */
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* The fixed status body of a pgread frame: ServerResponseBody_Status (16) +
 * ServerResponseBody_pgRead (8).  hdr.dlen is exactly this — the page data is
 * NOT counted in it (see the wire contract in root/response/status.c). */
#define PG_BODY_LEN        24u
/* The body's crc32c covers everything after itself: streamID..offset = 20 B. */
#define PG_BODY_CRC_LEN    (PG_BODY_LEN - 4u)
/* Byte offsets inside that body (the layout above, read unaligned-safe). */
#define PG_OFF_RESPTYPE     7u
#define PG_OFF_DLEN        12u
#define PG_OFF_FILEOFF     16u
/* resptype values: the train continues on PARTIAL, ends on FINAL. */
#define PG_RESP_FINAL       0u
#define PG_RESP_PARTIAL     1u
/* A kXR_error body is a message, not a status frame: read up to this much of
 * it so the origin's own text survives into the task error. */
#define PG_ERR_BODY_MAX    512u

/* One parsed kXR_status frame head. */
typedef struct {
    uint8_t   resptype;   /* PG_RESP_FINAL | PG_RESP_PARTIAL          */
    uint32_t  pgdlen;     /* page bytes that follow this frame's body */
    uint64_t  foff;       /* FILE offset those pages are aligned to   */
} pg_frame_t;

/* The largest page-data blob a reply to `want` bytes can legitimately carry:
 * the data plus one 4-byte CRC per page, plus one extra page's worth of CRC
 * for an unaligned first fragment. */
static uint32_t
pg_max_pgdlen(size_t want)
{
    size_t pages = want / kXR_pgPageSZ + 2;

    return (uint32_t) (want + pages * 4);
}

/* Send the kXR_pgread request for rng. Returns 0 / -1 (task error set). */
static int
pg_send_request(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN], const brix_cache_read_range_t *rng)
{
    ClientPgReadRequest req;

    /* slots: 1 bootstrap, 2 open, 3 read, 4 pgread */
    xrd_creq_begin(&req, sizeof(req), 4, kXR_pgread);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) brix_plat_htobe64(rng->read_off);
    req.rlen = htonl((kXR_int32) rng->want);
    req.dlen = 0;                         /* no request args (no pathid/retry) */

    if (brix_cache_io_send(oc, &req, sizeof(req)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin pgread write failed");
        return -1;
    }
    return 0;
}

/* 1 iff a kXR_error body says "I do not implement this request" — the two
 * codes a pre-5.x (or deliberately restricted) origin answers kXR_pgread with.
 * Anything else is a real error about the FILE, not about the capability. */
static int
pg_error_is_unsupported(u_char *body, uint32_t dlen)
{
    int          errnum = 0;
    const char  *msg = NULL;
    size_t       msglen = 0;

    if (xrd_error_body_decode(body, dlen, &errnum, &msg, &msglen) != 0) {
        return 0;
    }
    return errnum == kXR_Unsupported || errnum == kXR_InvalidRequest;
}

/* Validate the 24-byte status body and fill fr. Returns 0 / -1 (error set). */
static int
pg_parse_body(brix_cache_fill_t *t, u_char *body, pg_frame_t *fr)
{
    uint32_t want_crc, got_crc;

    want_crc = xrd_get_u32_be(body);
    got_crc  = brix_crc32c_value(body + 4, PG_BODY_CRC_LEN);
    if (want_crc != got_crc) {
        brix_cache_set_error(t, kXR_ChkSumErr, 0,
            "cache origin pgread status header CRC mismatch");
        return -1;
    }

    fr->resptype = body[PG_OFF_RESPTYPE];
    fr->pgdlen   = xrd_get_u32_be(body + PG_OFF_DLEN);
    fr->foff     = xrd_get_u64_be(body + PG_OFF_FILEOFF);

    if (fr->resptype != PG_RESP_FINAL && fr->resptype != PG_RESP_PARTIAL) {
        brix_cache_set_error(t, kXR_ServerError, 0,
            "cache origin pgread returned an unknown resptype");
        return -1;
    }
    return 0;
}

/* Read one frame of the kXR_status train.
 * Returns 0 (fr valid), -1 (task error set), or BRIX_CACHE_PGREAD_UNSUPPORTED. */
static int
pg_read_frame(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    pg_frame_t *fr)
{
    uint16_t  status;
    uint32_t  dlen;
    u_char   *body = NULL;
    int       rc;

    if (brix_cache_read_response(t, oc, &status, &body, &dlen,
                                   PG_ERR_BODY_MAX) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        rc = pg_error_is_unsupported(body, dlen)
             ? BRIX_CACHE_PGREAD_UNSUPPORTED : -1;
        if (rc == -1) {
            brix_cache_set_origin_error(t, body, dlen,
                                          "cache origin pgread failed");
        }
        free(body);
        return rc;
    }

    if (status != kXR_status || dlen != PG_BODY_LEN) {
        free(body);
        brix_cache_set_error(t, kXR_ServerError, 0,
            "cache origin pgread returned an invalid status frame");
        return -1;
    }

    rc = pg_parse_body(t, body, fr);
    free(body);
    return rc;
}

/* Bounds-check one frame against the request before a byte is read:
 * the pages must belong to the offset we are next expecting, and they must fit
 * in what is left of the request.  An origin that answers with a DIFFERENT
 * file offset would otherwise scatter its bytes into parts of the object the
 * caller never asked about — a write-anywhere primitive handed to the origin.
 * Returns 0 / -1 (task error set). */
static int
pg_check_frame(brix_cache_fill_t *t, const brix_cache_read_range_t *rng,
    const pg_frame_t *fr)
{
    if (fr->foff != rng->read_off + rng->got) {
        brix_cache_set_error(t, kXR_ServerError, 0,
            "cache origin pgread returned pages for an unrequested offset");
        return -1;
    }
    if (fr->pgdlen > pg_max_pgdlen(rng->want - rng->got)) {
        brix_cache_set_error(t, kXR_ServerError, 0,
            "cache origin pgread returned too much data");
        return -1;
    }
    /* A PARTIAL frame promises more to come, so an empty one advances nothing:
     * an origin could hold a fill thread on this socket forever by sending them.
     * The train has to make progress or end. */
    if (fr->pgdlen == 0 && fr->resptype == PG_RESP_PARTIAL) {
        brix_cache_set_error(t, kXR_ServerError, 0,
            "cache origin pgread sent an empty partial frame");
        return -1;
    }
    return 0;
}

/* Decode one frame's page buffer, verifying every page's CRC32c. Sets *n_out to
 * the decoded byte count. Returns 0 / -1 (task error set: kXR_ChkSumErr naming
 * the offending FILE offset, or kXR_ServerError for malformed framing). */
static int
pg_decode_verify(brix_cache_fill_t *t, const pg_frame_t *fr,
    const u_char *pg, u_char *dst, ssize_t *n_out)
{
    int64_t  bad = 0;
    ssize_t  n;
    char     msg[128];

    n = xrdp_pg_decode(pg, fr->pgdlen, (int64_t) fr->foff, dst,
                       fr->pgdlen, &bad);
    if (n == -1) {
        ngx_snprintf((u_char *) msg, sizeof(msg),
            "cache origin pgread CRC mismatch at file offset %L%Z", bad);
        brix_cache_set_error(t, kXR_ChkSumErr, 0, msg);
        return -1;
    }
    if (n < 0) {
        brix_cache_set_error(t, kXR_ServerError, 0,
            "cache origin pgread returned malformed page framing");
        return -1;
    }
    *n_out = n;
    return 0;
}

/* Write n verified bytes into the sink at the range's next write position.
 * Returns 0 / -1 (task error set). */
static int
pg_commit(brix_cache_fill_t *t, brix_cache_sink_t *sink,
    brix_cache_read_range_t *rng, const u_char *data, size_t n)
{
    if (n > rng->want - rng->got) {
        brix_cache_set_error(t, kXR_ServerError, 0,
            "cache origin pgread returned too much data");
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    if (brix_cache_sink_pwrite(sink, data, n,
                                 (off_t) (rng->dst_off + rng->got)) != 0)
    {
        brix_cache_set_syserror(t, kXR_IOError, "cache file write failed");
        return -1;
    }
    rng->got += n;
    return 0;
}

/* Receive, verify and write one frame's page data. Returns 0 / -1 (error set).
 * The two buffers are allocated and freed on ONE straight line here so the
 * verify/commit steps above can stay pure decisions. */
static int
pg_consume_pages(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    brix_cache_sink_t *sink, brix_cache_read_range_t *rng,
    const pg_frame_t *fr)
{
    u_char  *pg, *dst;
    ssize_t  n = 0;
    int      rc = -1;

    pg  = malloc(fr->pgdlen);
    dst = malloc(fr->pgdlen);            /* decoded is always < encoded */
    if (pg == NULL || dst == NULL) {
        free(pg);
        free(dst);
        brix_cache_set_error(t, kXR_NoMemory, 0,
                               "cache origin pgread allocation failed");
        return -1;
    }

    if (brix_cache_io_recv_exact(oc, pg, fr->pgdlen) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin pgread page read failed");
    } else if (pg_decode_verify(t, fr, pg, dst, &n) == 0) {
        rc = pg_commit(t, sink, rng, dst, (size_t) n);
    }

    free(pg);
    free(dst);
    return rc;
}

int
brix_cache_origin_pgread_chunk(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    brix_cache_sink_t *sink, brix_cache_read_range_t *rng)
{
    pg_frame_t  fr;
    int         rc;

    rng->got = 0;

    /* The advert decides before the wire does: an origin that never claimed
     * kXR_suppgrw is not asked, so a pre-5.x federation costs one bootstrap
     * flag test per read instead of a refused round trip per chunk. */
    if (!(oc->srv_flags & kXR_suppgrw)) {
        return BRIX_CACHE_PGREAD_UNSUPPORTED;
    }

    if (pg_send_request(t, oc, fhandle, rng) != 0) {
        return -1;
    }

    for ( ;; ) {
        rc = pg_read_frame(t, oc, &fr);
        if (rc != 0) {
            /* An UNSUPPORTED verdict is only honest while nothing has been
             * written: past the first frame the caller cannot re-read the
             * range with kXR_read without double-writing, so a late refusal
             * is a protocol error, not a capability answer. */
            if (rc == BRIX_CACHE_PGREAD_UNSUPPORTED && rng->got > 0) {
                brix_cache_set_error(t, kXR_ServerError, 0,
                    "cache origin abandoned pgread mid-train");
                return -1;
            }
            return rc;
        }

        if (pg_check_frame(t, rng, &fr) != 0) {
            return -1;
        }

        if (fr.pgdlen > 0 && pg_consume_pages(t, oc, sink, rng, &fr) != 0) {
            return -1;
        }

        if (fr.resptype == PG_RESP_FINAL) {
            return 0;
        }
    }
}
