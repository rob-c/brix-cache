#include "ftp_ev.h"

#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_ops.h"

#include <stdint.h>    /* INT64_MAX for the offset+count overflow guard */

/*
 * ftp_ev_mode_e.c — non-blocking MODE E (GFD.020 §3.4) extended-block transfers.
 *
 * WHAT: the RETR framing pump (frame the source as offset-addressed extended
 * blocks over one data connection) and the STOR reassembly receiver (accept up to
 * `Parallelism` passive data streams and fold their out-of-order blocks into the
 * VFS writer), plus the 111 restart / 112 perf markers both sides emit.
 *
 * WHY: the sync engine drives MODE E with a blocking poll() across the listener
 * and every live stream (ftp_stor_mode_e).  Here each stream is its own nginx
 * connection with its own read event, and the listener keeps accepting: globus
 * opens all parallel streams at once and handshakes their TLS concurrently, so the
 * receiver must bring them up promptly and interleave their reads under the event
 * loop — never draining one before accepting the next.
 *
 * HOW: RETR reuses the single data connection (ftp_ev_data.c brings it up, TLS and
 * all); brix_ftp_ev_retr_mode_e_start() installs a write pump that prepends the
 * 17-byte header to each chunk and closes with an EOF|EOD trailer.  STOR installs
 * brix_ftp_ev_eb_accept() as the passive listener's read handler (in place of the
 * single-stream ev_accept_handler): it accepts every pending stream, wraps each in
 * a child connection, optionally starts its PROT P handshake, and arms a per-stream
 * block reader.  Child readers are kicked via ngx_post_event so a transfer that
 * completes on the last EOD tears down the listener from a *posted* stack, never
 * nested inside the accept loop.  The committed-range table (shared on the parent
 * dc) rejects overlapping/overflowing blocks; the transfer completes once the
 * EOF-declared number of EODs has been seen, and the writer commit runs the
 * whole-object read-back verify.
 */


#define FTP_EV_EB_MARKER_BYTES      (1 << 20)  /* emit 111/112 each ~1 MiB moved */
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


/* ---- progress markers (best-effort; never fail a transfer) ----------------- */

/* Emit a GridFTP 112 perf marker (bytes moved) on the control channel. */
static void
ev_eb_marker_perf(ftp_ev_t *fc, off_t bytes)
{
    (void) brix_ftp_ev_reply(fc,
        "112-Perf Marker\r\n"
        " Timestamp: %T.0\r\n"
        " Stripe Index: 0\r\n"
        " Stripe Bytes Transferred: %O\r\n"
        " Total Stripe Count: 1\r\n"
        "112 End\r\n",
        (time_t) ngx_time(), bytes);
    (void) brix_ftp_ev_flush(fc);    /* leftover flushes with the trailing 226   */
}


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


/* ---- RETR: frame the source over the single data connection ---------------- */

/* The unused read side of the half-duplex send: a stray level-triggered wakeup
 * must not touch transfer state. */
static void
ev_eb_send_idle(ngx_event_t *ev)
{
    (void) ev;
}


static void
ev_retr_mode_e_write(ngx_event_t *wev)
{
    ngx_connection_t *c  = wev->data;
    ftp_ev_dc_t      *dc = c->data;
    ftp_ev_t         *fc = dc->fc;

    if (wev->timedout) {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    for ( ;; ) {
        if (dc->buf_pos < dc->buf_len) {
            ssize_t n = c->send(c, dc->buf + dc->buf_pos,
                                dc->buf_len - dc->buf_pos);
            if (n > 0) {
                dc->buf_pos += (size_t) n;
                continue;
            }
            if (n == NGX_AGAIN) {
                if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                    brix_ftp_ev_data_finish(dc, NGX_ERROR);
                    return;
                }
                ngx_add_timer(wev, BRIX_FTP_EV_IO_TIMEO);
                return;
            }
            brix_ftp_ev_data_finish(dc, NGX_ERROR);   /* NGX_ERROR or peer EOF */
            return;
        }

        if (dc->eb_phase == 2) {                      /* trailer sent          */
            brix_ftp_ev_data_finish(dc, NGX_OK);
            return;
        }
        if (dc->eb_phase == 1) {                      /* frame the EOF|EOD end  */
            /* No payload; the OFFSET field carries the total EOD count (1). */
            ftp_eb_pack(dc->buf, (u_char) (FTP_EB_EOF | FTP_EB_EOD), 0, 1);
            dc->buf_len  = FTP_EB_HDR;
            dc->buf_pos  = 0;
            dc->eb_phase = 2;
            continue;
        }

        if (dc->off >= dc->size) {                    /* whole file framed      */
            dc->eb_phase = 1;
            continue;
        }
        {
            size_t  want = (dc->size - dc->off > BRIX_FTP_EV_XFER_BUF)
                           ? BRIX_FTP_EV_XFER_BUF
                           : (size_t) (dc->size - dc->off);
            ssize_t got  = brix_vfs_file_pread(dc->fh, dc->buf + FTP_EB_HDR,
                                               want, dc->off);
            if (got <= 0) {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
                return;
            }
            ftp_eb_pack(dc->buf, 0 /* data */, (uint64_t) got, (uint64_t) dc->off);
            dc->off    += got;
            dc->buf_len = FTP_EB_HDR + (size_t) got;
            dc->buf_pos = 0;
            if (dc->off - dc->eb_marked >= FTP_EV_EB_MARKER_BYTES) {
                ev_eb_marker_perf(fc, dc->off);
                dc->eb_marked = dc->off;
            }
        }
    }
}


void
brix_ftp_ev_retr_mode_e_start(ftp_ev_dc_t *dc)
{
    dc->eb_phase  = 0;
    dc->eb_marked = 0;
    dc->dconn->read->handler  = ev_eb_send_idle;
    dc->dconn->write->handler = ev_retr_mode_e_write;
    ev_retr_mode_e_write(dc->dconn->write);
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


/* Retire a finished stream, then complete the transfer once every declared EOD
 * has been seen (commit runs the whole-object read-back verify). */
static void
ev_eb_child_done(ftp_ev_eb_conn_t *ch)
{
    ftp_ev_dc_t *dc = ch->dc;

    ev_eb_child_close(ch);

    if (dc->eb_eof_total >= 0 && dc->eb_eod_seen >= dc->eb_eof_total) {
        ngx_int_t rc = brix_vfs_writer_commit(dc->writer);
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
            ssize_t n = c->recv(c, ch->hdr + ch->hdr_got,
                                FTP_EB_HDR - ch->hdr_got);
            if (n == NGX_AGAIN) {
                if (ev_eb_arm_read(c) != NGX_OK) {
                    brix_ftp_ev_data_finish(dc, NGX_ERROR);
                }
                return;
            }
            if (n == 0) {
                if (ch->hdr_got == 0) {
                    ev_eb_child_done(ch);         /* clean close at a boundary  */
                } else {
                    brix_ftp_ev_data_finish(dc, NGX_ERROR);   /* EOF mid-header */
                }
                return;
            }
            if (n < 0) {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
                return;
            }
            ch->hdr_got += (size_t) n;
            if (ch->hdr_got < FTP_EB_HDR) {
                continue;
            }

            /* Full header: unpack and set up the block. */
            {
                uint64_t count, offset;
                ftp_eb_unpack(ch->hdr, &ch->desc, &count, &offset);
                ch->hdr_got  = 0;
                ch->have_hdr = 1;
                ch->count    = 0;

                if (ch->desc & FTP_EB_EOF) {
                    /* No payload; globus puts the total EOD count in OFFSET. */
                    dc->eb_eof_total = (long) offset;

                } else if (count > 0) {
                    off_t lo, hi;
                    if (count > (uint64_t) INT64_MAX
                        || offset > (uint64_t) INT64_MAX - count)
                    {
                        brix_ftp_ev_data_finish(dc, NGX_ERROR);   /* overflow    */
                        return;
                    }
                    lo = (off_t) offset;
                    hi = (off_t) (offset + count);
                    if (dc->eb_nranges >= BRIX_FTP_EV_EB_MAX_RANGES
                        || ftp_eb_range_overlaps(dc->eb_ranges, dc->eb_nranges,
                                                 lo, hi))
                    {
                        brix_ftp_ev_data_finish(dc, NGX_ERROR);   /* overlap      */
                        return;
                    }
                    /* Reserve the range before reading the payload so a concurrent
                     * stream's overlap check sees it. */
                    dc->eb_ranges[dc->eb_nranges].lo = lo;
                    dc->eb_ranges[dc->eb_nranges].hi = hi;
                    dc->eb_nranges++;
                    ch->count = count;
                    ch->at    = lo;
                }
            }
        }

        /* Drain this block's payload into the writer at its absolute offset. */
        while (ch->count > 0) {
            size_t  want = (ch->count > BRIX_FTP_EV_XFER_BUF)
                           ? BRIX_FTP_EV_XFER_BUF : (size_t) ch->count;
            ssize_t n    = c->recv(c, dc->buf, want);
            if (n == NGX_AGAIN) {
                if (ev_eb_arm_read(c) != NGX_OK) {
                    brix_ftp_ev_data_finish(dc, NGX_ERROR);
                }
                return;
            }
            if (n <= 0) {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);   /* EOF mid-payload / err */
                return;
            }
            if (brix_vfs_writer_write(dc->writer, dc->buf, (size_t) n, ch->at)
                != NGX_OK)
            {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
                return;
            }
            ch->at          += n;
            ch->count       -= (uint64_t) n;
            dc->eb_received += n;
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
