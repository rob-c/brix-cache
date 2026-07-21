#include "ftp_ev.h"

#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_ops.h"

#include <string.h>    /* memcpy */

/*
 * ftp_ev_xfer.c — data-transfer verbs and the non-blocking RETR/STOR/LIST pump.
 *
 * WHAT: the dispatch entry for every data verb (PASV/EPSV/PORT/EPRT delegate to
 * ftp_ev_data.c; RETR/STOR/APPE/LIST/NLST/MLSD run here), the transfer set-up
 * (validate, resolve the write offset, send 150, open the data channel), and the
 * three event-driven pumps that move bytes between the data socket and the VFS.
 *
 * WHY: the sync engine blocks the worker inside one transfer's read/write loop.
 * Here each transfer is a small state machine hung off the data connection's
 * read/write events, so the worker interleaves it with other sessions.  The VFS
 * side is opened once the socket is up (matching the sync order: 150 → connect →
 * open → move bytes → 226) and the socket side never blocks — a full socket
 * yields NGX_AGAIN and re-arms the event.  Local VFS reads/writes are performed
 * inline (fast POSIX/pblock syscalls); a thread-pool offload for slow object
 * backends is future work (P82.2 note in the phase-82 doc).
 *
 * HOW: brix_ftp_ev_do_transfer() validates and queues the 150, then arms the data
 * channel and yields; the control loop parks in FTP_EV_ST_XFER.  When the socket
 * becomes ready ftp_ev_data.c calls brix_ftp_ev_data_ready(), which opens the VFS
 * handle and kicks the matching pump.  Each pump drains its buffer to the sink,
 * refills from the source, and on completion/failure calls
 * brix_ftp_ev_data_finish(), which emits the 226/550 and resumes the control loop.
 */


/* The unused direction of a half-duplex transfer never gets armed, so its handler
 * is a no-op guard (a stray level-triggered wakeup must not touch transfer state). */
static void
ev_data_idle(ngx_event_t *ev)
{
    (void) ev;
}


/* ---- RETR: stream the file to the data socket ------------------------------ */

static void
ev_retr_write(ngx_event_t *wev)
{
    ngx_connection_t *c  = wev->data;
    ftp_ev_dc_t      *dc = c->data;

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

        /* Buffer drained — refill from the VFS handle (an object backend
         * reassembles its block files through the driver; a raw pread would only
         * see block 0). */
        if (dc->off >= dc->size) {
            brix_ftp_ev_data_finish(dc, NGX_OK);      /* whole file sent       */
            return;
        }
        {
            size_t  want = (dc->size - dc->off > BRIX_FTP_EV_XFER_BUF)
                           ? BRIX_FTP_EV_XFER_BUF
                           : (size_t) (dc->size - dc->off);
            ssize_t got  = brix_vfs_file_pread(dc->fh, dc->buf, want, dc->off);
            if (got <= 0) {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
                return;
            }
            dc->off    += got;
            dc->buf_len = (size_t) got;
            dc->buf_pos = 0;
        }
    }
}


/* ---- STOR/APPE: drain the data socket into the file ------------------------ */

static void
ev_stor_read(ngx_event_t *rev)
{
    ngx_connection_t *c  = rev->data;
    ftp_ev_dc_t      *dc = c->data;

    if (rev->timedout) {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    for ( ;; ) {
        ssize_t n = c->recv(c, dc->buf, BRIX_FTP_EV_XFER_BUF);

        if (n > 0) {
            if (brix_vfs_writer_write(dc->writer, dc->buf, (size_t) n, dc->off)
                != NGX_OK)
            {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
                return;
            }
            dc->off += n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
                return;
            }
            ngx_add_timer(rev, BRIX_FTP_EV_IO_TIMEO);
            return;
        }
        if (n == 0) {
            /* Client closed the data channel → EOF.  In stream mode a bare close
             * is the *only* completion signal, so it is indistinguishable from a
             * mid-flight truncation (a hostile middlebox dropping the connection).
             * When the client declared the size via ALLO and the operator opted
             * into brix_gridftp_require_allo_size, hold the transfer to exactly
             * that many bytes: a short (or over-long) delivery fails 550 rather
             * than committing a truncated object as complete.  The clean prefix
             * is left in place (unlike the MODE E declared-complete-but-holed
             * case) so a REST-resume can continue from dc->off. */
            ngx_int_t rc;

            if (dc->fc->conf->require_allo_size && dc->allo_size >= 0
                && dc->off != dc->allo_size)
            {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
                return;
            }
            /* Commit runs the read-back verify (and unlinks a mismatch); a NULL
             * writer skips abort in finish. */
            rc = brix_vfs_writer_commit(dc->writer);
            dc->writer = NULL;
            brix_ftp_ev_data_finish(dc, rc);
            return;
        }
        brix_ftp_ev_data_finish(dc, NGX_ERROR);       /* NGX_ERROR             */
        return;
    }
}


/* ---- LIST/NLST/MLSD: stream a directory listing to the data socket --------- */

/* Refill the transfer buffer with as many formatted entries as fit whole; sets
 * src_eof once the directory is exhausted.  Each line is bounded by PATH_MAX+128,
 * so we stop before the last line that could overflow — no entry is ever split. */
static void
ev_list_fill(ftp_ev_dc_t *dc)
{
    ngx_str_t       name;
    brix_vfs_stat_t st;

    dc->buf_pos = 0;
    dc->buf_len = 0;

    while (!dc->src_eof
           && dc->buf_len + PATH_MAX + 128 <= BRIX_FTP_EV_XFER_BUF)
    {
        u_char *p   = dc->buf + dc->buf_len;
        u_char *end = dc->buf + BRIX_FTP_EV_XFER_BUF;

        if (brix_vfs_readdir(dc->dh, &name, &st) != NGX_OK) {
            dc->src_eof = 1;
            break;
        }
        if (name.len == 1 && name.data[0] == '.') { continue; }
        if (name.len == 2 && name.data[0] == '.' && name.data[1] == '.') {
            continue;
        }

        if (dc->ls_mode == FTP_EV_LS_LONG) {
            p = ngx_snprintf(p, end - p,
                    "%crw%cr--r-- 1 brix brix %O Jan  1 00:00 %V\r\n",
                    st.is_directory ? 'd' : '-',
                    st.is_directory ? 'x' : '-',
                    st.size, &name);
        } else if (dc->ls_mode == FTP_EV_LS_MLSD) {
            p = ngx_snprintf(p, end - p,
                    "type=%s;size=%O;perm=%s; %V\r\n",
                    st.is_directory ? "dir" : "file",
                    st.size,
                    st.is_directory ? "el" : "r",
                    &name);
        } else {
            p = ngx_snprintf(p, end - p, "%V\r\n", &name);
        }
        dc->buf_len = (size_t) (p - dc->buf);
    }
}


static void
ev_list_write(ngx_event_t *wev)
{
    ngx_connection_t *c  = wev->data;
    ftp_ev_dc_t      *dc = c->data;

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
            brix_ftp_ev_data_finish(dc, NGX_ERROR);
            return;
        }

        if (dc->src_eof) {
            brix_ftp_ev_data_finish(dc, NGX_OK);      /* listing complete      */
            return;
        }
        ev_list_fill(dc);                             /* buffer the next batch */
    }
}


/* ---- transfer start-up ----------------------------------------------------- */

/* The data connection is up: open the VFS side and start the matching pump. */
void
brix_ftp_ev_data_ready(ftp_ev_dc_t *dc)
{
    ftp_ev_t       *fc = dc->fc;
    brix_vfs_ctx_t  vctx;
    int             verr = 0;

    brix_ftp_ev_vfs_ctx(fc, dc->abs, &vctx);

    switch (dc->op) {
    case FTP_EV_OP_RETR:
        dc->fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, &verr);
        if (dc->fh == NULL) {
            brix_ftp_ev_data_finish(dc, NGX_ERROR);
            return;
        }
        dc->size = brix_vfs_file_size(dc->fh);
        if (!(dc->off > 0 && dc->off <= dc->size)) {  /* clamp a stale REST    */
            dc->off = 0;
        }
        if (dc->mode_e) {
            brix_ftp_ev_retr_mode_e_start(dc);        /* extended-block framing */
            return;
        }
        dc->dconn->read->handler  = ev_data_idle;
        dc->dconn->write->handler = ev_retr_write;
        ev_retr_write(dc->dconn->write);
        return;

    case FTP_EV_OP_STOR:
    case FTP_EV_OP_APPE:
        dc->writer = brix_vfs_writer_open(&vctx, dc->flags, dc->verify, &verr);
        if (dc->writer == NULL) {
            brix_ftp_ev_data_finish(dc, NGX_ERROR);
            return;
        }
        dc->dconn->write->handler = ev_data_idle;
        dc->dconn->read->handler  = ev_stor_read;
        ev_stor_read(dc->dconn->read);
        return;

    default:  /* FTP_EV_OP_LIST / NLST / MLSD */
        dc->dh = brix_vfs_opendir(&vctx, &verr);
        if (dc->dh == NULL) {
            brix_ftp_ev_data_finish(dc, NGX_ERROR);
            return;
        }
        dc->dconn->read->handler  = ev_data_idle;
        dc->dconn->write->handler = ev_list_write;
        ev_list_write(dc->dconn->write);
        return;
    }
}


/* Pre-transfer guards: write permission, an armed data channel, and the MODE E
 * upload/passive constraint.  Returns NGX_DECLINED to proceed; otherwise the
 * queued-reply result the caller must return. */
static ngx_int_t
ev_xfer_guards(ftp_ev_t *fc, int writing)
{
    if (writing && !fc->conf->allow_write) {
        return brix_ftp_ev_reply(fc,
            "550 Permission denied (read-only export)\r\n");
    }
    if (!fc->active && fc->pasv_fd < 0) {
        return brix_ftp_ev_reply(fc, "425 Use PASV or PORT first\r\n");
    }

    /* MODE E STOR reassembles up to `Parallelism` inbound data streams, so it
     * requires a passive listener the peer opens all its streams to; an active
     * single connect cannot carry the fan-out. */
    if (fc->mode_e && writing && fc->active) {
        fc->rest_off = 0;
        return brix_ftp_ev_reply(fc,
            "504 MODE E upload requires passive mode\r\n");
    }
    return NGX_DECLINED;
}


/* Resolve the absolute path and the per-op write start / source validation
 * (before the 150).  Fills abs/start/flags/verify.  Returns NGX_DECLINED to
 * proceed; otherwise the queued-reply result the caller must return. */
static ngx_int_t
ev_xfer_resolve_start(ftp_ev_t *fc, int op, const char *arg,
                      char *abs, size_t abscap,
                      off_t *start, unsigned *flags, int *verify)
{
    int code = brix_ftp_ev_resolve(fc, arg, abs, abscap);
    if (code != 0) {
        fc->rest_off = 0;
        return brix_ftp_ev_reply(fc, "%d Failed to resolve path\r\n", code);
    }

    if (op == FTP_EV_OP_STOR) {
        *start  = fc->rest_off;
        *flags  = (fc->rest_off == 0) ? BRIX_VFS_O_TRUNC : 0;
        *verify = (fc->conf->verify_write && *start == 0) ? 1 : 0;
    } else if (op == FTP_EV_OP_APPE) {
        brix_vfs_ctx_t  vctx;
        brix_vfs_stat_t st;
        brix_ftp_ev_vfs_ctx(fc, abs, &vctx);
        if (brix_vfs_stat(&vctx, &st) == NGX_OK && !st.is_directory) {
            *start = st.size;
        }
    } else if (op == FTP_EV_OP_RETR) {
        brix_vfs_ctx_t  vctx;
        brix_vfs_stat_t st;
        brix_ftp_ev_vfs_ctx(fc, abs, &vctx);
        if (brix_vfs_stat(&vctx, &st) != NGX_OK || st.is_directory) {
            fc->rest_off = 0;
            return brix_ftp_ev_reply(fc, "550 No such file\r\n");
        }
        *start = fc->rest_off;
    }
    fc->rest_off = 0;                                  /* REST is one-shot      */
    return NGX_DECLINED;
}


/* Allocate and populate the data-channel state for a validated transfer.
 * Returns NULL on OOM (both the struct and its buffer). */
static ftp_ev_dc_t *
ev_xfer_alloc_dc(ftp_ev_t *fc, int op, const char *abs,
                 off_t start, unsigned flags, int verify, off_t allo)
{
    ftp_ev_dc_t *dc = ngx_pcalloc(fc->c->pool, sizeof(ftp_ev_dc_t));
    if (dc == NULL) {
        return NULL;
    }
    /* +FTP_EB_HDR: MODE E RETR frames each chunk as [17-byte header][payload] in
     * one buffer, so it must hold a full payload chunk plus the header. */
    dc->buf = ngx_pnalloc(fc->c->pool, BRIX_FTP_EV_XFER_BUF + FTP_EB_HDR);
    if (dc->buf == NULL) {
        return NULL;
    }
    dc->fc      = fc;
    dc->op      = op;
    dc->writing = (op == FTP_EV_OP_STOR || op == FTP_EV_OP_APPE);
    dc->off     = start;
    dc->flags   = flags;
    dc->verify  = verify;
    /* ALLO completeness enforcement is stream-mode STOR only: MODE E validates
     * completeness structurally (gapless tiling), and RETR/APPE have no ALLO. */
    dc->allo_size = (op == FTP_EV_OP_STOR && !fc->mode_e) ? allo : -1;
    dc->mode_e  = fc->mode_e;
    dc->eb_eof_total = -1;               /* set by the EOF block (MODE E STOR)    */
    dc->ls_mode = (op == FTP_EV_OP_LIST) ? FTP_EV_LS_LONG
                : (op == FTP_EV_OP_MLSD) ? FTP_EV_LS_MLSD
                :                          FTP_EV_LS_NLST;
    memcpy(dc->abs, abs, ngx_strlen(abs) + 1);
    return dc;
}


/* Validate a transfer verb, resolve the write offset, send the 150, and arm the
 * data channel.  Returns NGX_OK (transfer running or a queued 5xx), NGX_DONE is
 * never used, NGX_ERROR only on a fatal reply-buffer failure. */
static ngx_int_t
ev_begin_transfer(ftp_ev_t *fc, int op, const char *arg)
{
    char         abs[PATH_MAX];
    int          writing = (op == FTP_EV_OP_STOR || op == FTP_EV_OP_APPE);
    off_t        start   = 0;
    unsigned     flags   = 0;
    int          verify  = 0;
    off_t        allo    = fc->allo_size;         /* one-shot, per this command */
    ngx_int_t    rc;
    ftp_ev_dc_t *dc;

    fc->allo_size = -1;                           /* consume ALLO unconditionally */

    rc = ev_xfer_guards(fc, writing);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    rc = ev_xfer_resolve_start(fc, op, arg, abs, sizeof(abs),
                               &start, &flags, &verify);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    dc = ev_xfer_alloc_dc(fc, op, abs, start, flags, verify, allo);
    if (dc == NULL) {
        return brix_ftp_ev_reply(fc, "425 Cannot open data connection\r\n");
    }

    fc->dc    = dc;
    fc->state = FTP_EV_ST_XFER;

    if (brix_ftp_ev_reply(fc, "150 Opening %s mode data connection\r\n",
                          fc->type_binary ? "BINARY" : "ASCII") != NGX_OK)
    {
        fc->dc    = NULL;
        fc->state = FTP_EV_ST_CMD;
        return NGX_ERROR;
    }

    if (brix_ftp_ev_data_open(dc) != NGX_OK) {
        /* Synchronous set-up failure (before any async event): the 150 is already
         * queued — append the 550 and let the control loop flush both.  Don't
         * call data_finish here; it would re-enter the control loop we're inside. */
        fc->dc    = NULL;
        fc->state = FTP_EV_ST_CMD;
        return brix_ftp_ev_reply(fc, "425 Cannot open data connection\r\n");
    }
    return NGX_OK;
}


/* Data-verb dispatch entry: negative sentinels are the passive/active set-up
 * verbs (handled in ftp_ev_data.c); the FTP_EV_OP_* selectors start a transfer. */
ngx_int_t
brix_ftp_ev_do_transfer(ftp_ev_t *fc, int kind, const char *arg)
{
    if (kind < 0) {
        return brix_ftp_ev_data_setup(fc, kind, arg);
    }
    return ev_begin_transfer(fc, kind, arg);
}
