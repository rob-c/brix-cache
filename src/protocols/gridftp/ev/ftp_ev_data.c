#include "ftp_ev.h"

#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_ops.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>     /* close() */

/*
 * ftp_ev_data.c — non-blocking data-channel lifecycle for the event engine.
 *
 * WHAT: the event-driven bring-up of a data connection (accept a passive client,
 * or connect out in active mode) and the idempotent transfer teardown.  The
 * verbs that nominate the endpoint live in ftp_ev_data_setup.c.
 *
 * WHY: the sync engine blocks in accept()/connect() and then in the read/write
 * loop, monopolising the worker for one transfer.  Here the listener and the
 * connect socket are wrapped in nginx connections and driven by their own
 * read/write events, so the worker keeps serving other sessions while a transfer
 * proceeds.
 *
 * HOW: brix_ftp_ev_data_open() is called once a transfer verb has sent its 150:
 * it wraps the listener PASV/EPSV left in fc->pasv_fd (passive) or a fresh
 * connect() socket aimed at fc->active_sa (active) in an ngx_connection_t and
 * arms the accept/connect event.  When the data socket is ready the handler
 * hands off to brix_ftp_ev_data_ready() (ftp_ev_xfer.c), which opens the VFS
 * side and starts the pump.  Every transfer, whatever its shape, ends in
 * brix_ftp_ev_data_finish() — the single place the CNS note and the
 * {proto="gridftp"} metrics record are emitted.
 */




/* ---- data-connection bring-up ---------------------------------------------- */

/* Wrap an already-open data fd in an nginx connection with the standard
 * send/recv vtable, ready for the pump to arm read/write events on it.  Exported
 * so the MODE E receiver (ftp_ev_mode_e.c) wraps its child streams identically. */
ngx_connection_t *
brix_ftp_ev_wrap_conn(ftp_ev_t *fc, int fd)
{
    ngx_connection_t *c = ngx_get_connection(fd, fc->c->log);

    if (c == NULL) {
        return NULL;
    }
    c->recv       = ngx_recv;
    c->send       = ngx_send;
    c->recv_chain = ngx_recv_chain;
    c->send_chain = ngx_send_chain;
    c->log        = fc->c->log;
    c->read->log  = fc->c->log;
    c->write->log = fc->c->log;
    return c;
}


/* Passive listener read event: a client has connected — accept it, retire the
 * listener, and hand the data socket to the pump. */
static void
ev_accept_handler(ngx_event_t *rev)
{
    ngx_connection_t *lc = rev->data;
    ftp_ev_dc_t      *dc = lc->data;
    ftp_ev_t         *fc = dc->fc;
    int               dfd;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, fc->c->log, NGX_ETIMEDOUT,
                      "brix: GridFTP(ev) passive data accept timeout");
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }

    dfd = accept(lc->fd, NULL, NULL);
    if (dfd < 0) {
        if (ngx_socket_errno == NGX_EAGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
            }
            return;                              /* spurious wakeup — wait    */
        }
        ngx_log_error(NGX_LOG_ERR, fc->c->log, ngx_socket_errno,
                      "brix: GridFTP(ev) passive accept failed");
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }

    /* Retire the listener (closes fc->pasv_fd) — one transfer, one accept. */
    if (rev->timer_set) { ngx_del_timer(rev); }
    ngx_close_connection(lc);
    fc->pasv_fd = -1;
    dc->lc = NULL;

    if (ngx_nonblocking(dfd) == -1) {
        (void) close(dfd);
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }
    dc->dconn = brix_ftp_ev_wrap_conn(fc, dfd);
    if (dc->dconn == NULL) {
        (void) close(dfd);
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }
    dc->dconn->data = dc;
    if (fc->prot == 'P') {
        brix_ftp_ev_dc_start_tls(dc);            /* GSI-secure the data channel */
    } else {
        brix_ftp_ev_data_ready(dc);
    }
}


/* Active-mode connect completion: confirm the non-blocking connect() succeeded,
 * then hand the data socket to the pump. */
static void
ev_connect_handler(ngx_event_t *wev)
{
    ngx_connection_t *c  = wev->data;
    ftp_ev_dc_t      *dc = c->data;
    ftp_ev_t         *fc = dc->fc;
    int               soerr = 0;
    socklen_t         slen  = sizeof(soerr);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, fc->c->log, NGX_ETIMEDOUT,
                      "brix: GridFTP(ev) active data connect timeout");
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0
        || soerr != 0)
    {
        ngx_log_error(NGX_LOG_ERR, fc->c->log, soerr,
                      "brix: GridFTP(ev) active data connect failed");
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return;
    }

    if (wev->timer_set) { ngx_del_timer(wev); }
    dc->connecting = 0;
    if (fc->prot == 'P') {
        brix_ftp_ev_dc_start_tls(dc);            /* GSI-secure the data channel */
    } else {
        brix_ftp_ev_data_ready(dc);
    }
}


/* ev_data_open_passive — PASV/EPSV: the listener fd is already open and
 * non-blocking, so wrap it in a connection and arm its accept event. */
static ngx_int_t
ev_data_open_passive(ftp_ev_dc_t *dc)
{
    ftp_ev_t *fc = dc->fc;

    if (fc->pasv_fd < 0) {
        return NGX_ERROR;
    }
    dc->lc = ngx_get_connection(fc->pasv_fd, fc->c->log);
    if (dc->lc == NULL) {
        (void) close(fc->pasv_fd);
        fc->pasv_fd = -1;
        return NGX_ERROR;
    }
    dc->lc->log         = fc->c->log;
    dc->lc->read->log   = fc->c->log;
    dc->lc->data        = dc;
    /* MODE E STOR keeps the listener open to accept every parallel stream; all
     * other transfers take a single connection and retire the listener. */
    dc->lc->read->handler = (dc->mode_e && dc->writing)
                            ? brix_ftp_ev_eb_accept
                            : ev_accept_handler;
    if (ngx_handle_read_event(dc->lc->read, 0) != NGX_OK) {
        ngx_close_connection(dc->lc);            /* also closes pasv_fd    */
        fc->pasv_fd = -1;
        dc->lc = NULL;
        return NGX_ERROR;
    }
    ngx_add_timer(dc->lc->read, BRIX_FTP_EV_IO_TIMEO);
    return NGX_OK;
}


/* ev_data_open_active — PORT/EPRT: dial the armed, peer-pinned target from a
 * fresh non-blocking socket sourced on the control channel's local IP. */
static ngx_int_t
ev_data_open_active(ftp_ev_dc_t *dc)
{
    ftp_ev_t           *fc = dc->fc;
    struct sockaddr_in  local;
    socklen_t           llen = sizeof(local);
    int                 dfd;
    int                 rc;

    fc->active = 0;                          /* one-shot: consume the arm  */
    ngx_memzero(&local, sizeof(local));      /* getsockname may leave it   */

    dfd = socket(AF_INET, SOCK_STREAM, 0);
    if (dfd < 0) {
        return NGX_ERROR;
    }
    if (ngx_nonblocking(dfd) == -1) {
        (void) close(dfd);
        return NGX_ERROR;
    }
    if (getsockname(fc->c->fd, (struct sockaddr *) &local, &llen) == 0
        && local.sin_family == AF_INET)
    {
        local.sin_port = 0;                  /* ephemeral source port      */
        /* Best-effort source pinning: if the bind fails the kernel picks
         * the source address itself, which is still a usable data leg —
         * so log it and carry on rather than failing the transfer. */
        if (bind(dfd, (struct sockaddr *) &local, sizeof(local)) != 0) {
            ngx_log_error(NGX_LOG_INFO, fc->c->log, ngx_errno,
                          "brix: gsiftp(ev) data-leg source bind failed; "
                          "letting the kernel choose");
        }
    }

    dc->dconn = brix_ftp_ev_wrap_conn(fc, dfd);
    if (dc->dconn == NULL) {
        (void) close(dfd);
        return NGX_ERROR;
    }
    dc->dconn->data          = dc;
    dc->dconn->write->handler = ev_connect_handler;
    dc->connecting            = 1;
    dc->tls_client            = 1;   /* we dialled out: TLS client role    */

    rc = connect(dfd, (struct sockaddr *) &fc->active_sa,
                 sizeof(fc->active_sa));
    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        ngx_log_error(NGX_LOG_ERR, fc->c->log, ngx_socket_errno,
                      "brix: GridFTP(ev) active data connect() failed");
        ngx_close_connection(dc->dconn);
        dc->dconn = NULL;
        return NGX_ERROR;
    }
    if (ngx_handle_write_event(dc->dconn->write, 0) != NGX_OK) {
        ngx_close_connection(dc->dconn);
        dc->dconn = NULL;
        return NGX_ERROR;
    }
    /* Whether connect() returned 0 (immediate, loopback) or EINPROGRESS, let
     * the write event drive ev_connect_handler — running the hand-off out of
     * this stack keeps us from re-entering the control loop synchronously. */
    ngx_add_timer(dc->dconn->write, BRIX_FTP_EV_IO_TIMEO);
    return NGX_OK;
}


/* Bring the data connection up under the event loop; NGX_OK once the relevant
 * event is armed (completion is asynchronous), NGX_ERROR if the socket could
 * not be set up.  The arm is one-shot: ev_data_open_active consumes fc->active
 * so a second transfer without a fresh PORT/EPRT falls back to passive. */
ngx_int_t
brix_ftp_ev_data_open(ftp_ev_dc_t *dc)
{
    return dc->fc->active ? ev_data_open_active(dc) : ev_data_open_passive(dc);
}


/* ---- teardown -------------------------------------------------------------- */

/* Finish a transfer: release the VFS side, close the data socket and any pending
 * listener, emit the control-channel result (226 / 550), and resume the control
 * state machine.  Idempotent-safe: the pump only calls it once per transfer. */
void
brix_ftp_ev_data_finish(ftp_ev_dc_t *dc, ngx_int_t rc)
{
    ftp_ev_t *fc        = dc->fc;
    int       committed = (rc == NGX_OK);

    if (dc->eb_conns != NULL) {
        brix_ftp_ev_eb_teardown(dc);                 /* close live MODE E streams */
    }
    if (dc->fh != NULL) {
        (void) brix_vfs_close(dc->fh, fc->c->log);
        dc->fh = NULL;
    }
    if (dc->dh != NULL) {
        (void) brix_vfs_closedir(dc->dh, fc->c->log);
        dc->dh = NULL;
    }
    if (dc->writer != NULL) {
        /* A writer still open here means the transfer failed before commit. */
        brix_vfs_writer_abort(dc->writer);
        dc->writer = NULL;
        committed  = 0;                  /* nothing was published              */
    }

    /* phase-97 §5: this is the single completion for every transfer shape
     * (stream, MODE E, active, passive) and it runs on the event loop, so one
     * report here covers a committed STOR/APPE however it was carried.  Only for
     * a transfer that both succeeded and got past the commit — an aborted writer
     * left the path untouched. */
    if (committed && dc->writing) {
        brix_ftp_ev_cns_note_stored(fc, dc->abs);
    }

    /* The one unified-metrics record per transfer, for the same reason: every
     * shape lands here exactly once, with the offsets still intact. */
    brix_ftp_ev_metric_xfer(dc, rc);

    if (dc->dconn != NULL) {
        if (dc->dconn->ssl != NULL) {
            /* Quiet, non-blocking teardown: free the SSL synchronously (no
             * close_notify round trip) before closing the socket. */
            dc->dconn->ssl->no_wait_shutdown = 1;
            dc->dconn->ssl->no_send_shutdown = 1;
            (void) ngx_ssl_shutdown(dc->dconn);
        }
        ngx_close_connection(dc->dconn);
        dc->dconn = NULL;
    }
    if (dc->lc != NULL) {
        ngx_close_connection(dc->lc);            /* also closes fc->pasv_fd    */
        fc->pasv_fd = -1;
        dc->lc = NULL;
    }
    if (dc->dpool != NULL) {
        ngx_destroy_pool(dc->dpool);             /* the TLS conn's pool         */
        dc->dpool = NULL;
    }

    fc->dc    = NULL;
    fc->state = FTP_EV_ST_CMD;

    (void) brix_ftp_ev_reply(fc, (rc == NGX_OK)
                                 ? "226 Transfer complete\r\n"
                                 : "550 Transfer failed\r\n");

    /* Resume the control channel: flush the result and frame the next command. */
    brix_ftp_ev_resume(fc);
}


/* brix_ftp_ev_send_drain — shared send-side pump head for the data-channel
 * write handlers (stream RETR and MODE E RETR): handle the idle timeout,
 * clear a pending timer, then push dc->buf[buf_pos..buf_len) to the socket.
 * NGX_OK: buffer fully drained — the caller refills and calls again.
 * NGX_AGAIN: backpressure — write event re-armed + IO timer set, caller
 * returns.  NGX_ERROR: the transfer was already finished with an error
 * (send failure, peer EOF, or event-arm failure), caller returns. */
ngx_int_t
brix_ftp_ev_send_drain(ngx_event_t *wev)
{
    ngx_connection_t *c  = wev->data;
    ftp_ev_dc_t      *dc = c->data;

    if (wev->timedout) {
        brix_ftp_ev_data_finish(dc, NGX_ERROR);
        return NGX_ERROR;
    }
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    while (dc->buf_pos < dc->buf_len) {
        ssize_t n = c->send(c, dc->buf + dc->buf_pos,
                            dc->buf_len - dc->buf_pos);

        if (n > 0) {
            dc->buf_pos += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                brix_ftp_ev_data_finish(dc, NGX_ERROR);
                return NGX_ERROR;
            }
            ngx_add_timer(wev, BRIX_FTP_EV_IO_TIMEO);
            return NGX_AGAIN;
        }
        brix_ftp_ev_data_finish(dc, NGX_ERROR);       /* NGX_ERROR or peer EOF */
        return NGX_ERROR;
    }

    return NGX_OK;
}
