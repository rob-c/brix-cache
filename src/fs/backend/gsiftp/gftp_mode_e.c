/* GridFTP MODE E for the outbound gsiftp driver — see gftp_mode_e.h. */

#include "gftp_mode_e.h"
#include "protocols/gridftp/ftp_eblock.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>

#define GFTP_EB_CHUNK 65536

/* Per-connection reassembly state: MODE E blocks are framed independently on
 * each data connection, so a partially-read header or payload belongs to ONE
 * connection and never to the transfer as a whole. */
typedef struct {
    uint8_t  hdr[FTP_EB_HDR];
    size_t   hdr_got;
    uint64_t remain;      /* payload bytes still owed for the current block */
    uint64_t pos;         /* absolute offset of the next payload byte       */
    int      done;        /* EOD seen, or the peer closed                   */
} gftp_eb_conn_t;

typedef struct {
    gftp_mode_e_req_t *req;
    gftp_eb_conn_t    *cs;
    ftp_eb_range_t    *ranges;
    size_t             nranges;
    uint64_t           eod_seen;
    long               eof_total;   /* -1 until an EOF block arrives */
    int                stopped;     /* window edge reached; stop, do not fail */
} gftp_eb_recv_t;


/* Claim [lo, hi) for this transfer.  Refuses a block outside the requested
 * window and any block overlapping bytes already committed — see the security
 * note in gftp_mode_e.h.  Returns 0 / -1. */
static int
gftp_eb_claim(gftp_session_t *session, gftp_eb_recv_t *r, uint64_t off,
    uint64_t count)
{
    uint64_t base = (uint64_t) r->req->start;

    if (off < base || off - base > r->req->limit
        || count > r->req->limit - (off - base))
    {
        gftp_set_error(session, EPROTO,
            "GridFTP MODE E block at %llu is outside the requested window",
            (unsigned long long) off);
        return -1;
    }
    if (ftp_eb_range_overlaps(r->ranges, r->nranges, (off_t) off,
                              (off_t) (off + count)))
    {
        gftp_set_error(session, EPROTO,
            "GridFTP MODE E block at %llu overlaps committed bytes",
            (unsigned long long) off);
        return -1;
    }
    if (r->nranges == GFTP_EB_MAX_RANGES) {
        gftp_set_error(session, EPROTO,
            "GridFTP MODE E transfer is too fragmented (%d ranges)",
            GFTP_EB_MAX_RANGES);
        return -1;
    }
    r->ranges[r->nranges].lo = (off_t) off;
    r->ranges[r->nranges].hi = (off_t) (off + count);
    r->nranges++;
    return 0;
}


/* Is this block pure surplus - bytes the caller never asked for, from an origin
 * that was never told where to stop?
 *
 * Only on an UNBOUNDED transfer (REST+RETR names no length), only once every
 * byte of the window is committed, and only for a block that BEGINS at or past
 * the end.  All three are needed.  Dropping the third would let an origin skip
 * bytes and call the hole surplus; dropping the second would stop the receiver
 * the moment the window happened to fill, which on any object smaller than the
 * window is at EOF - and the `overlap` fault's replayed block arrives after
 * exactly that point, so the refusal it exists to prove would never fire. */
static int
gftp_eb_surplus(const gftp_eb_recv_t *r, u_char desc, uint64_t off)
{
    uint64_t end = (uint64_t) r->req->start + r->req->limit;

    return !r->req->bounded
        && (desc & FTP_EB_EOF) == 0
        && r->req->received >= r->req->limit
        && off >= end;
}


/* How much of a block starting inside the window may be committed.
 *
 * Only ever shrinks, and only on an unbounded transfer: a 64 KiB chunk answering
 * a 256-byte Range request straddles the end, and the bytes inside the window
 * are still exactly the ones that were asked for.  Committing the head of a
 * straddling block leaves the connection mid-payload, so the caller stops
 * immediately afterwards - the next 17 bytes on that socket are data, and
 * reading them as a header would invent a block out of the file's contents. */
static uint64_t
gftp_eb_window_clamp(const gftp_eb_recv_t *r, uint64_t off, uint64_t count)
{
    uint64_t end = (uint64_t) r->req->start + r->req->limit;

    if (r->req->bounded || off >= end || count <= end - off) {
        return count;
    }
    return end - off;
}


/* A complete 17-byte header arrived on connection `i`: set up its block. */
static int
gftp_eb_header(gftp_session_t *session, gftp_eb_recv_t *r, unsigned i)
{
    gftp_eb_conn_t *c = &r->cs[i];
    uint64_t        count;
    uint64_t        offset;
    u_char          desc;

    ftp_eb_unpack(c->hdr, &desc, &count, &offset);
    c->hdr_got = 0;

    if (gftp_eb_surplus(r, desc, offset)) {
        r->stopped = 1;
        return 0;
    }
    if (desc & FTP_EB_EOF) {
        r->eof_total = (long) offset;   /* no payload; EOD total is in OFFSET */
    }
    if ((desc & FTP_EB_EOF) == 0 && count > 0) {
        uint64_t take = gftp_eb_window_clamp(r, offset, count);

        if (gftp_eb_claim(session, r, offset, take) != 0) {
            return -1;
        }
        r->stopped = (take < count) ? 1 : r->stopped;
        c->remain  = take;
        c->pos     = offset;
    }
    if (desc & FTP_EB_EOD) {
        r->eod_seen++;
        /* Any payload on an EOD block is drained first; the connection retires
         * once `remain` reaches zero, which is why `done` is set here and the
         * drain loop still runs. */
        c->done = 1;
    }
    return 0;
}


/* Move up to one read's worth of payload from connection `i` to the sink. */
static int
gftp_eb_payload(gftp_session_t *session, gftp_eb_recv_t *r, unsigned i)
{
    uint8_t         buf[GFTP_EB_CHUNK];
    gftp_eb_conn_t *c = &r->cs[i];
    size_t          want = sizeof(buf);
    ssize_t         n;

    if (c->remain < (uint64_t) want) {
        want = (size_t) c->remain;
    }
    n = gftp_dc_read(session, &r->req->conns[i], buf, want);
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        gftp_set_error(session, EPROTO,
            "GridFTP MODE E connection closed mid-block");
        return -1;
    }
    if (r->req->sink(r->req->ctx, (off_t) (c->pos - (uint64_t) r->req->start),
                     buf, (size_t) n) != 0)
    {
        return -1;
    }
    c->pos           += (uint64_t) n;
    c->remain        -= (uint64_t) n;
    r->req->received += (uint64_t) n;
    return 0;
}


/* One readable event on connection `i`: header bytes, then payload bytes. */
static int
gftp_eb_step(gftp_session_t *session, gftp_eb_recv_t *r, unsigned i)
{
    gftp_eb_conn_t *c = &r->cs[i];
    ssize_t         n;

    if (c->remain > 0) {
        return gftp_eb_payload(session, r, i);
    }
    n = gftp_dc_read(session, &r->req->conns[i], c->hdr + c->hdr_got,
                     FTP_EB_HDR - c->hdr_got);
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        if (c->hdr_got != 0) {
            gftp_set_error(session, EPROTO,
                "GridFTP MODE E connection closed mid-header");
            return -1;
        }
        c->done = 1;                 /* clean close with no block pending */
        return 0;
    }
    c->hdr_got += (size_t) n;
    if (c->hdr_got < FTP_EB_HDR) {
        return 0;
    }
    return gftp_eb_header(session, r, i);
}


/* True once every connection has retired and the EOF block's promised EOD count
 * has been met.  An EOF that promises more EODs than ever arrive leaves this
 * false — a truncated transfer is never reported as complete.  It is
 * gftp_eb_poll() that then ends the transfer, as a failure: see the no-live-
 * connection branch there. */
static int
gftp_eb_complete(const gftp_eb_recv_t *r)
{
    unsigned i;

    for (i = 0; i < r->req->nconns; i++) {
        if (!r->cs[i].done || r->cs[i].remain > 0) {
            return 0;
        }
    }
    return r->eof_total < 0 || r->eod_seen >= (uint64_t) r->eof_total;
}


/* Poll every live connection once; step each readable one. */
static int
gftp_eb_poll(gftp_session_t *session, gftp_eb_recv_t *r)
{
    struct pollfd fds[GFTP_STREAMS_MAX];
    unsigned      map[GFTP_STREAMS_MAX];
    nfds_t        n = 0;
    unsigned      i;
    int           rc;

    for (i = 0; i < r->req->nconns; i++) {
        if (r->cs[i].done && r->cs[i].remain == 0) {
            continue;
        }
        fds[n].fd = r->req->conns[i].fd;
        fds[n].events = POLLIN;
        fds[n].revents = 0;
        map[n] = i;
        n++;
    }
    if (n == 0) {
        /* Every connection has retired, yet the caller only polls while the
         * transfer is INCOMPLETE — so the EOF block promised more EOD blocks
         * than ever arrived.  Nothing can still read: returning 0 here would
         * spin `while (!gftp_eb_complete())` forever, burning a whole worker
         * thread on an origin that merely has to lie about its EOD count once.
         * A truncated transfer has to end, and it has to end as a failure. */
        gftp_set_error(session, EPROTO,
            "GridFTP MODE E transfer ended after %llu of %ld promised EOD blocks",
            (unsigned long long) r->eod_seen, r->eof_total);
        return -1;
    }
    do {
        rc = poll(fds, n, session->timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc <= 0) {
        gftp_set_error(session, (rc == 0) ? ETIMEDOUT : EIO,
            "GridFTP MODE E data channel %s", (rc == 0) ? "timed out" : "failed");
        return -1;
    }
    for (i = 0; i < (unsigned) n; i++) {
        if (fds[i].revents != 0
            && gftp_eb_step(session, r, map[i]) != 0)
        {
            return -1;
        }
    }
    return 0;
}


int
gftp_mode_e_receive(gftp_session_t *session, gftp_mode_e_req_t *req)
{
    gftp_eb_recv_t  r;
    gftp_eb_conn_t  cs[GFTP_STREAMS_MAX];
    int             rc = 0;

    req->received = 0;
    if (req->nconns == 0 || req->nconns > GFTP_STREAMS_MAX) {
        gftp_set_error(session, EINVAL, "GridFTP MODE E stream count is invalid");
        return -1;
    }
    memset(&r, 0, sizeof(r));
    memset(cs, 0, sizeof(cs));
    r.req = req;
    r.cs = cs;
    r.eof_total = -1;
    r.ranges = calloc(GFTP_EB_MAX_RANGES, sizeof(*r.ranges));
    if (r.ranges == NULL) {
        gftp_set_error(session, ENOMEM, "cannot allocate GridFTP MODE E ranges");
        return -1;
    }
    while (rc == 0 && !r.stopped && !gftp_eb_complete(&r)) {
        rc = gftp_eb_poll(session, &r);
    }
    /* A straddling block is drained to the window edge before the stop takes
     * effect, so the loop runs while `stopped` is set and `remain` is non-zero
     * on the connection carrying it. */
    while (rc == 0 && r.stopped && r.cs[0].remain > 0) {
        rc = gftp_eb_poll(session, &r);
    }
    req->stopped_early = r.stopped;
    free(r.ranges);
    return rc;
}


int
gftp_mode_e_send(gftp_session_t *session, gftp_dc_t *dc, gftp_source_fn source,
    void *ctx)
{
    uint8_t  buf[GFTP_EB_CHUNK];
    uint8_t  hdr[FTP_EB_HDR];
    uint64_t off = 0;

    for (;;) {
        ssize_t n = source(ctx, buf, sizeof(buf));

        if (n < 0) {
            return -1;
        }
        if (n == 0) {
            break;
        }
        ftp_eb_pack(hdr, 0 /* data */, (uint64_t) n, off);
        if (gftp_dc_write_all(session, dc, hdr, sizeof(hdr)) != 0
            || gftp_dc_write_all(session, dc, buf, (size_t) n) != 0)
        {
            return -1;
        }
        off += (uint64_t) n;
    }
    /* One connection, so one EOD, and the EOF block promises exactly that —
     * the same trailer the inbound door emits (ev/ftp_ev_mode_e.c). */
    ftp_eb_pack(hdr, (uint8_t) (FTP_EB_EOF | FTP_EB_EOD), 0, 1);
    return gftp_dc_write_all(session, dc, hdr, sizeof(hdr));
}
