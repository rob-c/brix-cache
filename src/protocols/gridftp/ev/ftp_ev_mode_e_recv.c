#include "ftp_ev.h"
#include "ftp_ev_mode_e_internal.h"

#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_ops.h"

#include <stdint.h>    /* INT64_MAX for the offset+count overflow guard */

/*
 * ftp_ev_mode_e_recv.c — non-blocking MODE E (GFD.020 §3.4) STOR reassembly.
 *
 * WHAT: the STOR reassembly receiver — accept up to `Parallelism` passive data
 * streams and fold their out-of-order extended blocks into the VFS writer, plus
 * the 111 restart / 112 range markers the sink emits.
 *
 * HOW: STOR installs brix_ftp_ev_eb_accept() as the passive listener's read
 * handler (in place of the single-stream ev_accept_handler): it accepts every
 * pending stream, wraps each in a child connection, optionally starts its PROT P
 * handshake, and arms a per-stream block reader.  Child readers are kicked via
 * ngx_post_event so a transfer that completes on the last EOD tears down the
 * listener from a *posted* stack, never nested inside the accept loop.  The
 * committed-range table (shared on the parent dc) rejects overlapping/overflowing
 * blocks; the transfer completes once the EOF-declared number of EODs has been
 * seen, and the writer commit runs the whole-object read-back verify.
 */


#define FTP_EV_EB_MARKER_MAX_RANGES 32         /* cap the 111 range-list length  */


/* Per-child MODE E data-stream state.  Each passive data connection runs its own
 * header/payload accumulator; the committed ranges + EOD/EOF bookkeeping live on
 * the parent dc, shared across streams (event handlers never run concurrently, so
 * the shared state is touched atomically within one handler). */
typedef struct {
    ftp_ev_dc_t      *dc;          /* parent transfer (shared reassembly state)  */
    ngx_connection_t *c;           /* this data stream                           */
    ngx_pool_t       *pool;        /* per-child TLS pool (PROT P), else NULL      */
    int               in_use;

    u_char            hdr[FTP_EB_HDR];
    size_t            hdr_got;      /* header bytes accumulated                   */
    int               have_hdr;     /* header parsed, payload in flight           */
    u_char            desc;         /* current block descriptor                   */
    uint64_t          count;        /* payload bytes remaining in this block      */
    off_t             at;           /* absolute offset for the next payload byte  */
} ftp_ev_eb_conn_t;


static int
ev_eb_range_cmp(const void *a, const void *b)
{
    const ftp_eb_range_t *ra = a, *rb = b;
    if (ra->lo < rb->lo) { return -1; }
    if (ra->lo > rb->lo) { return  1; }
    return 0;
}


/* Emit a GridFTP 111 restart/range marker: the contiguous byte ranges committed
 * so far, coalesced, so a client can resume from what the sink already holds.  The
 * list is capped so a fragmented transfer cannot produce an unbounded reply. */
static void
ev_eb_marker_range(ftp_ev_dc_t *dc)
{
    ftp_ev_t *fc = dc->fc;
    u_char    line[64 * FTP_EV_EB_MARKER_MAX_RANGES + 32];
    u_char   *p   = line;
    u_char   *end = line + sizeof(line);
    size_t    n   = dc->eb_nranges, i, merged;

    if (n == 0) {
        return;
    }
    ngx_memcpy(dc->eb_scratch, dc->eb_ranges, n * sizeof(ftp_eb_range_t));
    ngx_qsort(dc->eb_scratch, n, sizeof(ftp_eb_range_t), ev_eb_range_cmp);

    /* Merge touching/adjacent ranges in place; rejected overlaps mean the sorted
     * set only ever touches (hi == next.lo) or gaps, never crosses. */
    merged = 0;
    for (i = 1; i < n; i++) {
        if (dc->eb_scratch[i].lo <= dc->eb_scratch[merged].hi) {
            if (dc->eb_scratch[i].hi > dc->eb_scratch[merged].hi) {
                dc->eb_scratch[merged].hi = dc->eb_scratch[i].hi;
            }
        } else {
            dc->eb_scratch[++merged] = dc->eb_scratch[i];
        }
    }
    merged++;                             /* count, not top index                 */

    p = ngx_slprintf(p, end, "111 Range Marker ");
    for (i = 0; i < merged && i < FTP_EV_EB_MARKER_MAX_RANGES; i++) {
        p = ngx_slprintf(p, end, "%s%O-%O", i ? "," : "",
                         dc->eb_scratch[i].lo, dc->eb_scratch[i].hi);
    }
    *p = '\0';
    (void) brix_ftp_ev_reply(fc, "%s\r\n", line);
    (void) brix_ftp_ev_flush(fc);
}


/* ---- STOR: reassemble parallel extended-block streams ---------------------- */

/* Release one child stream (quiet TLS teardown, close, free its pool). */
static void
ev_eb_child_close(ftp_ev_eb_conn_t *ch)
{
    if (ch->c != NULL) {
        if (ch->c->ssl != NULL) {
            ch->c->ssl->no_wait_shutdown = 1;
            ch->c->ssl->no_send_shutdown = 1;
            (void) ngx_ssl_shutdown(ch->c);
        }
        ngx_close_connection(ch->c);              /* also cancels a posted read */
        ch->c = NULL;
    }
    if (ch->pool != NULL) {
        ngx_destroy_pool(ch->pool);
        ch->pool = NULL;
    }
    ch->in_use = 0;
    ch->dc->eb_nconns--;
}


void
brix_ftp_ev_eb_teardown(ftp_ev_dc_t *dc)
{
    ftp_ev_eb_conn_t *conns = dc->eb_conns;
    int               i;

    if (conns == NULL) {
        return;
    }
    for (i = 0; i < BRIX_FTP_EV_EB_MAX_CONNS; i++) {
        if (conns[i].in_use) {
            ev_eb_child_close(&conns[i]);
        }
    }
}


/* A completed MODE E reassembly must tile the object gaplessly from offset 0.
 * Every accepted block was overlap-checked, so the sorted ranges only ever touch
 * (hi == next.lo) or leave a gap — they never cross.  A gap means the sink holds a
 * region the sender never delivered: a corrupted/forged EBLOCK offset (an in-path
 * bit-flip of the 17-byte header past the TCP checksum), or a stream that emitted
 * its EOD without covering its share.  Committing then would publish a file with
 * silently zero-filled holes as "complete" — the MODE E analogue of a truncated
 * cache object accepted as whole.  Require exactly one coalesced range
 * [0, high-water) whose length equals the bytes actually received. */
static int
ev_eb_ranges_contiguous(ftp_ev_dc_t *dc)
{
    size_t  n = dc->eb_nranges, i, merged;

    if (n == 0) {
        return dc->eb_received == 0;      /* empty object: valid iff zero bytes   */
    }
    ngx_memcpy(dc->eb_scratch, dc->eb_ranges, n * sizeof(ftp_eb_range_t));
    ngx_qsort(dc->eb_scratch, n, sizeof(ftp_eb_range_t), ev_eb_range_cmp);

    merged = 0;
    for (i = 1; i < n; i++) {
        if (dc->eb_scratch[i].lo <= dc->eb_scratch[merged].hi) {
            if (dc->eb_scratch[i].hi > dc->eb_scratch[merged].hi) {
                dc->eb_scratch[merged].hi = dc->eb_scratch[i].hi;
            }
        } else {
            dc->eb_scratch[++merged] = dc->eb_scratch[i];   /* a hole opens here   */
        }
    }
    merged++;                             /* count, not top index                 */

    return merged == 1
        && dc->eb_scratch[0].lo == 0
        && dc->eb_scratch[0].hi == dc->eb_received;
}


/* Retire a finished stream, then complete the transfer once every declared EOD
 * has been seen (commit runs the whole-object read-back verify). */
static void
ev_eb_child_done(ftp_ev_eb_conn_t *ch)
{
    ftp_ev_dc_t *dc = ch->dc;

    ev_eb_child_close(ch);

    if (dc->eb_eof_total >= 0 && dc->eb_eod_seen >= dc->eb_eof_total) {
        ngx_int_t rc;

        if (!ev_eb_ranges_contiguous(dc)) {
            /* Every declared EOD is in, yet the tiling has a hole: the client
             * asserted the object is complete, so this partial is not an
             * interrupted transfer awaiting a range-resume — it is a finished,
             * holed poison (a forged/corrupted EBLOCK offset, or a short sender).
             * The in-place random writer would otherwise leave the zero-filled
             * object at the final path; abort it and unlink so nothing is
             * published, then fail the transfer (550). */
            brix_vfs_ctx_t vctx;

            brix_vfs_writer_abort(dc->writer);
            dc->writer = NULL;
            brix_ftp_ev_vfs_ctx(dc->fc, dc->abs, &vctx);
            (void) brix_vfs_unlink(&vctx);
            brix_ftp_ev_data_finish(dc, NGX_ERROR);
            return;
        }
        rc = brix_vfs_writer_commit(dc->writer);
        dc->writer = NULL;                        /* finish must not abort it   */
        brix_ftp_ev_data_finish(dc, rc);          /* closes listener + resumes  */
    }
}


static ngx_int_t
ev_eb_arm_read(ngx_connection_t *c)
{
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    ngx_add_timer(c->read, BRIX_FTP_EV_IO_TIMEO);
    return NGX_OK;
}


/* One step of the block reader's state machine.  RET means the helper already
 * completed the transfer (finish/done/arm) and the caller must return; MORE means
 * the header is still partial and the caller should loop again; OK means proceed. */
typedef enum {
    EV_EB_STEP_RET = 0,
    EV_EB_STEP_MORE,
    EV_EB_STEP_OK
} ev_eb_step_t;


/* A fully-unpacked payload block: bounds-check its extent, reject overflow or a
 * range overlapping an already-reserved one, then reserve it (before reading the
 * payload, so a concurrent stream's overlap check sees it) and arm ch to drain. */
static ev_eb_step_t
ev_eb_reserve_range(ftp_ev_eb_conn_t *ch, ftp_ev_dc_t *dc,
                    uint64_t count, uint64_t offset)
{
    off_t lo, hi;

    if (count > (uint64_t) INT64_MAX
        || offset > (uint64_t) INT64_MAX - count)
    {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);       /* overflow */
        return EV_EB_STEP_RET;
    }
    lo = (off_t) offset;
    hi = (off_t) (offset + count);
    if (dc->eb_nranges >= BRIX_FTP_EV_EB_MAX_RANGES
        || ftp_eb_range_overlaps(dc->eb_ranges, dc->eb_nranges, lo, hi))
    {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);       /* overlap */
        return EV_EB_STEP_RET;
    }
    dc->eb_ranges[dc->eb_nranges].lo = lo;
    dc->eb_ranges[dc->eb_nranges].hi = hi;
    dc->eb_nranges++;
    ch->count = count;
    ch->at    = lo;
    return EV_EB_STEP_OK;
}


/* Accumulate the 17-byte extended-block header; once complete, unpack it and set
 * up the next block (EOF descriptors carry the EOD total in OFFSET and no payload;
 * a non-empty block reserves its range). */
static ev_eb_step_t
ev_eb_recv_header(ngx_connection_t *c, ftp_ev_eb_conn_t *ch, ftp_ev_dc_t *dc)
{
    uint64_t count, offset;
    ssize_t  n = c->recv(c, ch->hdr + ch->hdr_got, FTP_EB_HDR - ch->hdr_got);

    if (n == NGX_AGAIN) {
        if (ev_eb_arm_read(c) != NGX_OK) {
            brix_ftp_ev_data_finish(dc, NGX_ERROR);
        }
        return EV_EB_STEP_RET;
    }
    if (n == 0) {
        if (ch->hdr_got == 0) {
            ev_eb_child_done(ch);                     /* clean close at a boundary  */
        } else {
            brix_ftp_ev_data_finish(dc, NGX_ERROR);   /* EOF mid-header */
        }
        return EV_EB_STEP_RET;
    }
    if (n < 0) {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return EV_EB_STEP_RET;
    }
    ch->hdr_got += (size_t) n;
    if (ch->hdr_got < FTP_EB_HDR) {
        return EV_EB_STEP_MORE;
    }

    /* Full header: unpack and set up the block. */
    ftp_eb_unpack(ch->hdr, &ch->desc, &count, &offset);
    ch->hdr_got  = 0;
    ch->have_hdr = 1;
    ch->count    = 0;

    if (ch->desc & FTP_EB_EOF) {
        dc->eb_eof_total = (long) offset;   /* no payload; EOD total is in OFFSET */
        return EV_EB_STEP_OK;
    }
    if (count > 0) {
        return ev_eb_reserve_range(ch, dc, count, offset);
    }
    return EV_EB_STEP_OK;
}


/* Drain this block's reserved payload into the writer at its absolute offset. */
static ev_eb_step_t
ev_eb_drain_payload(ngx_connection_t *c, ftp_ev_eb_conn_t *ch, ftp_ev_dc_t *dc)
{
    while (ch->count > 0) {
        size_t  want = (ch->count > BRIX_FTP_EV_XFER_BUF)
                       ? BRIX_FTP_EV_XFER_BUF : (size_t) ch->count;
        ssize_t n    = c->recv(c, dc->buf, want);
        if (n == NGX_AGAIN) {
            if (ev_eb_arm_read(c) != NGX_OK) {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
            }
            return EV_EB_STEP_RET;
        }
        if (n <= 0) {
            brix_ftp_ev_data_finish(dc, NGX_ERROR);   /* EOF mid-payload / err */
            return EV_EB_STEP_RET;
        }
        if (brix_vfs_writer_write(dc->writer, dc->buf, (size_t) n, ch->at)
            != NGX_OK)
        {
            brix_ftp_ev_data_finish(dc, NGX_ERROR);
            return EV_EB_STEP_RET;
        }
        ch->at          += n;
        ch->count       -= (uint64_t) n;
        dc->eb_received += n;
    }
    return EV_EB_STEP_OK;
}


/* Per-stream block reader: accumulate the 17-byte header, then drain `count`
 * payload bytes into the writer at their absolute offset, block after block,
 * until an EOD ends the stream or a clean close lands on a block boundary. */
static void
ev_eb_child_read(ngx_event_t *rev)
{
    ngx_connection_t *c  = rev->data;
    ftp_ev_eb_conn_t *ch = c->data;
    ftp_ev_dc_t      *dc = ch->dc;
    ftp_ev_t         *fc = dc->fc;

    if (rev->timedout) {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    for ( ;; ) {
        if (!ch->have_hdr) {
            ev_eb_step_t st = ev_eb_recv_header(c, ch, dc);
            if (st == EV_EB_STEP_RET) {
                return;
            }
            if (st == EV_EB_STEP_MORE) {
                continue;
            }
        }

        if (ev_eb_drain_payload(c, ch, dc) == EV_EB_STEP_RET) {
            return;
        }

        /* Block complete: emit progress markers on the marker threshold. */
        if (dc->eb_received - dc->eb_marked >= FTP_EV_EB_MARKER_BYTES) {
            ev_eb_marker_range(dc);
            ev_eb_marker_perf(fc, dc->eb_received);
            dc->eb_marked = dc->eb_received;
        }

        if (ch->desc & FTP_EB_EOD) {
            dc->eb_eod_seen++;
            ev_eb_child_done(ch);                 /* last block on this stream  */
            return;
        }
        ch->have_hdr = 0;                         /* next block on this stream  */
    }
}


/* PROT P child: the handshake settled — enforce the DN pin, then arm the block
 * reader off a posted event (TLS may have buffered the first block already, and a
 * completion reached from the accept loop must not tear the listener down inline). */
static void
ev_eb_child_tls_done(ngx_connection_t *c)
{
    ftp_ev_eb_conn_t *ch = c->data;
    ftp_ev_dc_t      *dc = ch->dc;

    if (brix_ftp_ev_tls_verify(dc->fc, c) != NGX_OK) {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }
    c->read->handler = ev_eb_child_read;
    if (ev_eb_arm_read(c) != NGX_OK) {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }
    ngx_post_event(c->read, &ngx_posted_events);
}


/* Find a free child slot (linear over a small fixed table). */
static ftp_ev_eb_conn_t *
ev_eb_slot(ftp_ev_dc_t *dc)
{
    ftp_ev_eb_conn_t *conns = dc->eb_conns;
    int               i;

    for (i = 0; i < BRIX_FTP_EV_EB_MAX_CONNS; i++) {
        if (!conns[i].in_use) {
            return &conns[i];
        }
    }
    return NULL;
}


/* Lazily open the writer + reassembly tables on the first accepted stream. */
static ngx_int_t
ev_eb_receiver_open(ftp_ev_dc_t *dc)
{
    ftp_ev_t       *fc = dc->fc;
    brix_vfs_ctx_t  vctx;
    int             verr = 0;

    dc->eb_ranges  = ngx_pnalloc(fc->c->pool,
                        BRIX_FTP_EV_EB_MAX_RANGES * sizeof(ftp_eb_range_t));
    dc->eb_scratch = ngx_pnalloc(fc->c->pool,
                        BRIX_FTP_EV_EB_MAX_RANGES * sizeof(ftp_eb_range_t));
    dc->eb_conns   = ngx_pcalloc(fc->c->pool,
                        BRIX_FTP_EV_EB_MAX_CONNS * sizeof(ftp_ev_eb_conn_t));
    if (dc->eb_ranges == NULL || dc->eb_scratch == NULL || dc->eb_conns == NULL) {
        return NGX_ERROR;
    }

    brix_ftp_ev_vfs_ctx(fc, dc->abs, &vctx);
    dc->writer = brix_vfs_writer_open(&vctx, dc->flags, dc->verify, &verr);
    return (dc->writer != NULL) ? NGX_OK : NGX_ERROR;
}


/* Passive listener read handler for a MODE E STOR: accept every pending stream,
 * bring each up (PROT P handshake or straight), and arm its block reader.  The
 * listener stays open across the whole transfer — globus opens all parallel
 * streams at once, so we must not retire it after the first accept. */
void
brix_ftp_ev_eb_accept(ngx_event_t *rev)
{
    ngx_connection_t *lc = rev->data;
    ftp_ev_dc_t      *dc = lc->data;
    ftp_ev_t         *fc = dc->fc;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, fc->c->log, NGX_ETIMEDOUT,
                      "brix: GridFTP(ev) MODE E passive accept timeout");
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    if (dc->writer == NULL && ev_eb_receiver_open(dc) != NGX_OK) {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }

    for ( ;; ) {
        ftp_ev_eb_conn_t *ch;
        ngx_connection_t *c;
        int               dfd = accept(lc->fd, NULL, NULL);

        if (dfd < 0) {
            if (ngx_socket_errno == NGX_EAGAIN) {
                break;                            /* drained pending accepts    */
            }
            if (ngx_socket_errno == NGX_ECONNABORTED) {
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, fc->c->log, ngx_socket_errno,
                          "brix: GridFTP(ev) MODE E accept failed");
            brix_ftp_ev_data_finish(dc, NGX_ERROR);
            return;
        }

        if (dc->eb_nconns >= BRIX_FTP_EV_EB_MAX_CONNS
            || (ch = ev_eb_slot(dc)) == NULL)
        {
            (void) close(dfd);                    /* stream cap — refuse extra  */
            continue;
        }
        if (ngx_nonblocking(dfd) == -1) {
            (void) close(dfd);
            brix_ftp_ev_data_finish(dc, NGX_ERROR);
            return;
        }
        c = brix_ftp_ev_wrap_conn(fc, dfd);
        if (c == NULL) {
            (void) close(dfd);
            brix_ftp_ev_data_finish(dc, NGX_ERROR);
            return;
        }

        ngx_memzero(ch, sizeof(*ch));
        ch->dc     = dc;
        ch->in_use = 1;
        ch->c      = c;
        c->data    = ch;
        dc->eb_nconns++;

        if (fc->prot == 'P') {
            /* Passive accept → TLS server role; completion arms the reader. */
            if (brix_ftp_ev_tls_begin(fc, c, &ch->pool, 0 /* server */,
                                      ev_eb_child_tls_done) == NGX_ERROR)
            {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
                return;
            }
        } else {
            c->read->handler = ev_eb_child_read;
            if (ev_eb_arm_read(c) != NGX_OK) {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
                return;
            }
            /* Kick the reader off a posted event: a completion reached here must
             * not tear the listener down from inside the accept loop. */
            ngx_post_event(c->read, &ngx_posted_events);
        }
    }

    /* Keep listening for the remaining parallel streams. */
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }
    ngx_add_timer(rev, BRIX_FTP_EV_IO_TIMEO);
}
