#include "ftp_ev.h"
#include "ftp_ev_mode_e_internal.h"

#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_ops.h"

#include <stdint.h>    /* INT64_MAX for the offset+count overflow guard */

/*
 * ftp_ev_mode_e.c — non-blocking MODE E (GFD.020 §3.4) extended-block transfers.
 *
 * WHAT: the RETR framing pump (frame the source as offset-addressed extended
 * blocks over one data connection), plus the 111 restart / 112 perf markers the
 * sender emits.  The STOR reassembly receiver lives in ftp_ev_mode_e_recv.c.
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
 * 17-byte header to each chunk and closes with an EOF|EOD trailer.
 */


/* ---- progress markers (best-effort; never fail a transfer) ----------------- */

/* Emit a GridFTP 112 perf marker (bytes moved) on the control channel. */
void
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
