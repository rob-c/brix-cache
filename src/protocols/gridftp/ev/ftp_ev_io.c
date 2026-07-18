#include "ftp_ev.h"

#include <unistd.h>    /* close() for the passive listener on teardown */

/*
 * ftp_ev_io.c — the non-blocking control-channel engine.
 *
 * WHAT: the session entry point installed as the stream content handler, the
 * read/write event handlers, the buffered-reply flusher, the command-framing
 * loop, and idempotent session teardown.
 *
 * WHY: this is the piece that makes the gateway event-driven.  Where the sync
 * engine blocks in read()/write(), here every I/O either completes or yields
 * NGX_AGAIN back to nginx's event loop, so one worker interleaves many sessions.
 *
 * HOW: brix_ftp_ev_process() is the heart — a single loop that (1) drains any
 * queued reply, (2) frames one complete command line out of the inbound buffer
 * and dispatches it, or (3) reads more bytes.  It runs until an operation would
 * block (arm the matching event + idle timer and return) or the session ends.
 * Both event handlers funnel into it, so the flush-then-frame ordering is
 * identical whether we were woken to read or to write.
 */


/* Try to frame one CRLF-terminated command line out of buf[bpos..blen).
 *
 * On success returns a NUL-terminated pointer into ->buf (CRLF stripped) and
 * advances ->bpos past the line.  Returns NULL when no complete line is buffered
 * yet; sets *too_long when the buffer is full with no newline in sight (an
 * unterminated over-long line — the caller drops the session). */
static char *
ev_take_line(ftp_ev_t *fc, int *too_long)
{
    u_char *nl;
    size_t  linelen;

    *too_long = 0;

    if (fc->bpos < fc->blen) {
        nl = memchr(fc->buf + fc->bpos, '\n', fc->blen - fc->bpos);
        if (nl != NULL) {
            u_char *line = fc->buf + fc->bpos;
            linelen = (size_t) (nl - line);          /* bytes before the '\n' */
            fc->bpos += linelen + 1;                 /* consume through '\n'  */
            if (linelen > 0 && line[linelen - 1] == '\r') {
                linelen--;                           /* strip CR              */
            }
            line[linelen] = '\0';
            return (char *) line;
        }
    }

    /* No newline in the buffered bytes.  Compact the consumed prefix so the next
     * recv() has room; if the whole buffer is then full, the peer sent an
     * over-long unterminated line. */
    if (fc->bpos > 0) {
        ngx_memmove(fc->buf, fc->buf + fc->bpos, fc->blen - fc->bpos);
        fc->blen -= fc->bpos;
        fc->bpos = 0;
    }
    if (fc->blen == sizeof(fc->buf)) {
        *too_long = 1;
    }
    return NULL;
}


/* Send as much of the queued reply as the socket accepts.  Returns NGX_OK once
 * the buffer is fully drained (and reset), NGX_AGAIN if the socket is full, or
 * NGX_ERROR on a send failure / peer close. */
ngx_int_t
brix_ftp_ev_flush(ftp_ev_t *fc)
{
    ngx_connection_t *c = fc->c;

    while (fc->ob_pos < fc->ob_len) {
        ssize_t n = c->send(c, fc->ob + fc->ob_pos, fc->ob_len - fc->ob_pos);
        if (n > 0) {
            fc->ob_pos += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }
        return NGX_ERROR;                            /* NGX_ERROR or 0 (EOF)  */
    }
    fc->ob_pos = fc->ob_len = 0;
    return NGX_OK;
}


/* Idempotent teardown: release the passive listener and finalize the session. */
void
brix_ftp_ev_finalize(ftp_ev_t *fc, ngx_int_t rc)
{
    if (fc->destroyed) {
        return;
    }
    fc->destroyed = 1;

    if (fc->pasv_fd >= 0) {
        (void) close(fc->pasv_fd);
        fc->pasv_fd = -1;
    }

    ngx_log_error(NGX_LOG_INFO, fc->c->log, 0,
                  "brix: GridFTP(ev) gateway session end");
    ngx_stream_finalize_session(fc->s, (ngx_uint_t) rc);
}


/* The command→reply state machine.  Drives one step at a time until an operation
 * would block (arm the relevant event and return) or the session is finalized. */
static void
brix_ftp_ev_process(ftp_ev_t *fc)
{
    ngx_connection_t *c = fc->c;

    for ( ;; ) {
        char      *line;
        int        too_long;
        ngx_int_t  rc;
        ssize_t    n;

        /* (1) Drain any queued reply before touching the next command. */
        if (fc->ob_len > fc->ob_pos) {
            rc = brix_ftp_ev_flush(fc);
            if (rc == NGX_AGAIN) {
                if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                    brix_ftp_ev_finalize(fc, NGX_STREAM_INTERNAL_SERVER_ERROR);
                }
                ngx_add_timer(c->write, BRIX_FTP_EV_IO_TIMEO);
                return;
            }
            if (rc == NGX_ERROR) {
                brix_ftp_ev_finalize(fc, NGX_STREAM_OK);
                return;
            }
            if (fc->state == FTP_EV_ST_CLOSING) {   /* QUIT reply delivered  */
                brix_ftp_ev_finalize(fc, NGX_STREAM_OK);
                return;
            }
        }

        /* A data transfer holds the control channel half-open: once its 150 has
         * drained, the data connection's own events drive the transfer to a 226/
         * 550 (brix_ftp_ev_data_finish resumes us).  Don't frame the next command
         * meanwhile — FTP is half-duplex, and reading ahead would race the pump. */
        if (fc->state == FTP_EV_ST_XFER) {
            return;
        }

        /* (2) Frame and dispatch one complete command line. */
        line = ev_take_line(fc, &too_long);
        if (too_long) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "brix: GridFTP(ev) over-long command line — closing");
            brix_ftp_ev_finalize(fc, NGX_STREAM_OK);
            return;
        }
        if (line != NULL) {
            if (line[0] == '\0') {
                continue;                            /* ignore blank line     */
            }
            rc = brix_ftp_ev_dispatch(fc, line);
            if (rc == NGX_ERROR) {
                brix_ftp_ev_finalize(fc, NGX_STREAM_OK);
                return;
            }
            if (rc == NGX_DONE) {
                fc->state = FTP_EV_ST_CLOSING;       /* flush, then close     */
            }
            continue;                                /* loop: flush the reply */
        }

        /* (3) No complete line buffered — read more. */
        n = c->recv(c, fc->buf + fc->blen, sizeof(fc->buf) - fc->blen);
        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                brix_ftp_ev_finalize(fc, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }
            ngx_add_timer(c->read, BRIX_FTP_EV_IO_TIMEO);
            return;
        }
        if (n == 0 || n == NGX_ERROR) {
            brix_ftp_ev_finalize(fc, NGX_STREAM_OK);
            return;
        }
        fc->blen += (size_t) n;
    }
}


/* Re-enter the control state machine after a data transfer completes.  The data
 * channel runs on its own connection/events; when it finishes it queues the 226/
 * 550 result and calls this to flush the result and resume framing commands. */
void
brix_ftp_ev_resume(ftp_ev_t *fc)
{
    if (fc->destroyed) {
        return;
    }
    brix_ftp_ev_process(fc);
}


/* Read-event handler: enforce the idle deadline, then run the state machine. */
static void
brix_ftp_ev_read_handler(ngx_event_t *rev)
{
    ngx_connection_t     *c  = rev->data;
    ngx_stream_session_t *s  = c->data;
    ftp_ev_t             *fc = ngx_stream_get_module_ctx(s,
                                   ngx_stream_brix_ftp_module);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "brix: GridFTP(ev) control channel idle timeout");
        c->timedout = 1;
        brix_ftp_ev_finalize(fc, NGX_STREAM_OK);
        return;
    }
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }
    brix_ftp_ev_process(fc);
}


/* Write-event handler: enforce the deadline, then resume the state machine
 * (which flushes the pending reply before framing the next command). */
static void
brix_ftp_ev_write_handler(ngx_event_t *wev)
{
    ngx_connection_t     *c  = wev->data;
    ngx_stream_session_t *s  = c->data;
    ftp_ev_t             *fc = ngx_stream_get_module_ctx(s,
                                   ngx_stream_brix_ftp_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "brix: GridFTP(ev) control channel write timeout");
        c->timedout = 1;
        brix_ftp_ev_finalize(fc, NGX_STREAM_OK);
        return;
    }
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }
    brix_ftp_ev_process(fc);
}


/* Stream content handler: stand up the per-connection state, wire the event
 * handlers, queue the greeting, and hand control to the event loop. */
void
brix_ftp_ev_handler(ngx_stream_session_t *s)
{
    ngx_connection_t               *c = s->connection;
    ngx_stream_brix_ftp_srv_conf_t *conf;
    ftp_ev_t                       *fc;

    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_brix_ftp_module);

    fc = ngx_pcalloc(c->pool, sizeof(ftp_ev_t));
    if (fc == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
    fc->ob = ngx_pnalloc(c->pool, BRIX_FTP_EV_OB_CAP);
    if (fc->ob == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
    fc->s       = s;
    fc->c       = c;
    fc->conf    = conf;
    fc->state   = FTP_EV_ST_CMD;
    fc->pasv_fd = -1;
    fc->prot    = 'C';
    fc->cwd[0]  = '/';
    fc->cwd[1]  = '\0';

    ngx_stream_set_ctx(s, fc, ngx_stream_brix_ftp_module);

    c->read->handler  = brix_ftp_ev_read_handler;
    c->write->handler = brix_ftp_ev_write_handler;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: GridFTP(ev) gateway session start (export=%s write=%d)",
                  conf->root_canon, conf->allow_write ? 1 : 0);

    if (brix_ftp_ev_reply(fc, "220 BriX GridFTP Gateway ready\r\n") != NGX_OK) {
        brix_ftp_ev_finalize(fc, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
    fc->greeted = 1;

    brix_ftp_ev_process(fc);
}
