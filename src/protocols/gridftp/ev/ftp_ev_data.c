#include "ftp_ev.h"

#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_ops.h"
#include "core/compat/net_target.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>      /* sscanf for PORT */
#include <stdlib.h>     /* strtoul for EPRT */
#include <unistd.h>     /* close() */

/*
 * ftp_ev_data.c — non-blocking data-channel lifecycle for the event engine.
 *
 * WHAT: the passive/active setup verbs (PASV/EPSV/PORT/EPRT), the event-driven
 * bring-up of a data connection (accept a passive client, or connect out in
 * active mode), and idempotent transfer teardown.
 *
 * WHY: the sync engine blocks in accept()/connect() and then in the read/write
 * loop, monopolising the worker for one transfer.  Here the listener and the
 * connect socket are wrapped in nginx connections and driven by their own
 * read/write events, so the worker keeps serving other sessions while a transfer
 * proceeds.  The confinement and anti-bounce/SSRF rules are ported verbatim from
 * the sync engine (ftp_do_pasv/ftp_do_port) so both engines expose the same
 * data-channel security boundary during the transition.
 *
 * HOW: PASV/EPSV open a non-blocking listener bound to the control channel's own
 * IP and stash its fd in fc->pasv_fd; PORT/EPRT pin+screen a client-nominated
 * target into fc->active_sa.  brix_ftp_ev_data_open() is called once a transfer
 * verb has sent its 150: it wraps the listener (passive) or a fresh connect()
 * socket (active) in an ngx_connection_t and arms the accept/connect event.  When
 * the data socket is ready the handler hands off to brix_ftp_ev_data_ready()
 * (ftp_ev_xfer.c), which opens the VFS side and starts the pump.
 */


/* ---- passive / active setup verbs ------------------------------------------ */

/* PASV/EPSV: open a non-blocking listener bound to the control connection's local
 * IP and an ephemeral port; `extended` selects the RFC 2428 (229) vs RFC 959
 * (227) reply.  Mirrors the sync ftp_do_pasv, but the socket is non-blocking so
 * the later accept runs under the event loop. */
static ngx_int_t
ev_do_pasv(ftp_ev_t *fc, int extended)
{
    struct sockaddr_in  local;
    socklen_t           llen = sizeof(local);
    struct sockaddr_in  bindaddr;
    socklen_t           blen = sizeof(bindaddr);
    int                 fd;
    unsigned char       ip[4];
    unsigned            port;

    fc->active = 0;                             /* PASV/EPSV overrides PORT   */

    if (fc->pasv_fd >= 0) {
        (void) close(fc->pasv_fd);
        fc->pasv_fd = -1;
    }

    if (getsockname(fc->c->fd, (struct sockaddr *) &local, &llen) != 0
        || local.sin_family != AF_INET)
    {
        return brix_ftp_ev_reply(fc, "425 Cannot open passive connection\r\n");
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return brix_ftp_ev_reply(fc, "425 Cannot open passive connection\r\n");
    }
    if (ngx_nonblocking(fd) == -1) {
        (void) close(fd);
        return brix_ftp_ev_reply(fc, "425 Cannot open passive connection\r\n");
    }

    ngx_memzero(&bindaddr, sizeof(bindaddr));
    bindaddr.sin_family = AF_INET;
    bindaddr.sin_addr   = local.sin_addr;      /* same host as control       */
    bindaddr.sin_port   = 0;                   /* ephemeral                  */

    /* Backlog spans a full MODE E stream fan-out (globus opens all parallel
     * data connections at once), matching the sync engine. */
    if (bind(fd, (struct sockaddr *) &bindaddr, sizeof(bindaddr)) != 0
        || listen(fd, BRIX_FTP_EV_DATA_BACKLOG) != 0
        || getsockname(fd, (struct sockaddr *) &bindaddr, &blen) != 0)
    {
        (void) close(fd);
        return brix_ftp_ev_reply(fc, "425 Cannot open passive connection\r\n");
    }

    fc->pasv_fd = fd;
    ngx_memcpy(ip, &bindaddr.sin_addr.s_addr, 4);
    port = ntohs(bindaddr.sin_port);

    if (extended) {
        return brix_ftp_ev_reply(fc,
            "229 Entering Extended Passive Mode (|||%ud|)\r\n",
            (ngx_uint_t) port);
    }
    return brix_ftp_ev_reply(fc,
        "227 Entering Passive Mode (%ud,%ud,%ud,%ud,%ud,%ud)\r\n",
        (ngx_uint_t) ip[0], (ngx_uint_t) ip[1],
        (ngx_uint_t) ip[2], (ngx_uint_t) ip[3],
        (ngx_uint_t) (port >> 8), (ngx_uint_t) (port & 0xff));
}


/* PORT/EPRT: arm an active-mode target.  The nominated address is pinned to the
 * control peer (anti FTP-bounce; relaxed only for a DCAU-A TPC leg) and screened
 * through the SSRF policy — identical to the sync ftp_do_port. */
static ngx_int_t
ev_do_port(ftp_ev_t *fc, const char *arg, int extended)
{
    struct sockaddr_in       peer;
    socklen_t                plen = sizeof(peer);
    struct sockaddr_in       tgt;
    brix_net_target_policy_t pol;
    char                     err[128];
    unsigned                 h[4], p[2];
    in_addr_t                addr;
    unsigned                 port;

    ngx_memzero(&tgt, sizeof(tgt));
    tgt.sin_family = AF_INET;

    if (!extended) {
        if (sscanf(arg, "%u,%u,%u,%u,%u,%u",
                   &h[0], &h[1], &h[2], &h[3], &p[0], &p[1]) != 6
            || (h[0] | h[1] | h[2] | h[3]) > 255 || (p[0] | p[1]) > 255)
        {
            return brix_ftp_ev_reply(fc, "501 Bad PORT argument\r\n");
        }
        {
            unsigned char b[4] = { (unsigned char) h[0], (unsigned char) h[1],
                                   (unsigned char) h[2], (unsigned char) h[3] };
            ngx_memcpy(&addr, b, 4);
        }
        port = (p[0] << 8) | p[1];
    } else {
        char        d = arg[0];
        const char *fam, *ip, *pt, *end;
        char        ipbuf[64];
        size_t      iplen;

        if (d == '\0') { return brix_ftp_ev_reply(fc, "501 Bad EPRT argument\r\n"); }
        fam = arg + 1;
        ip  = strchr(fam, d);
        if (ip == NULL) { return brix_ftp_ev_reply(fc, "501 Bad EPRT argument\r\n"); }
        ip++;
        pt = strchr(ip, d);
        if (pt == NULL) { return brix_ftp_ev_reply(fc, "501 Bad EPRT argument\r\n"); }
        end = strchr(pt + 1, d);
        if (end == NULL) { return brix_ftp_ev_reply(fc, "501 Bad EPRT argument\r\n"); }
        if (fam[0] != '1') {
            return brix_ftp_ev_reply(fc, "522 Only IPv4 (|1|) supported\r\n");
        }
        iplen = (size_t) (pt - ip);
        if (iplen == 0 || iplen >= sizeof(ipbuf)) {
            return brix_ftp_ev_reply(fc, "501 Bad EPRT address\r\n");
        }
        ngx_memcpy(ipbuf, ip, iplen);
        ipbuf[iplen] = '\0';
        if (inet_pton(AF_INET, ipbuf, &addr) != 1) {
            return brix_ftp_ev_reply(fc, "501 Bad EPRT address\r\n");
        }
        port = (unsigned) strtoul(pt + 1, NULL, 10);
    }

    if (port == 0 || port > 65535) {
        return brix_ftp_ev_reply(fc, "501 Bad data port\r\n");
    }
    tgt.sin_addr.s_addr = addr;
    tgt.sin_port        = htons((unsigned short) port);

    /* Anti-bounce pin: a plain active transfer must target the control peer; an
     * off-peer target is only allowed as a GSI-authenticated (DCAU A) TPC leg. */
    if (getpeername(fc->c->fd, (struct sockaddr *) &peer, &plen) != 0
        || peer.sin_family != AF_INET)
    {
        return brix_ftp_ev_reply(fc, "500 Cannot determine control peer\r\n");
    }
    fc->active_offpeer = (peer.sin_addr.s_addr != tgt.sin_addr.s_addr);
    if (fc->active_offpeer && !(fc->sec_active && fc->dcau_a)) {
        ngx_log_error(NGX_LOG_WARN, fc->c->log, 0,
                      "brix: gsiftp(ev) rejected active-mode target != control "
                      "peer (no DCAU A; possible FTP-bounce)");
        return brix_ftp_ev_reply(fc, "500 Data address must match control peer\r\n");
    }

    ngx_memzero(&pol, sizeof(pol));
    pol.allow_local   = 1;
    pol.allow_private = 1;
    if (brix_net_target_check_addr((struct sockaddr *) &tgt, &pol,
                                   err, sizeof(err)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, fc->c->log, 0,
                      "brix: gsiftp(ev) active-mode target blocked: %s", err);
        return brix_ftp_ev_reply(fc, "500 Data address not permitted\r\n");
    }

    if (fc->pasv_fd >= 0) { (void) close(fc->pasv_fd); fc->pasv_fd = -1; }
    fc->active_sa = tgt;
    fc->active    = 1;
    return brix_ftp_ev_reply(fc, "200 %s command successful\r\n",
                             extended ? "EPRT" : "PORT");
}


/* Dispatch the four setup verbs (negative kind sentinels from the dispatcher). */
ngx_int_t
brix_ftp_ev_data_setup(ftp_ev_t *fc, int kind, const char *arg)
{
    switch (kind) {
    case -1: return ev_do_pasv(fc, 0 /* PASV */);
    case -2: return ev_do_pasv(fc, 1 /* EPSV */);
    case -3: return ev_do_port(fc, arg, 0 /* PORT */);
    default: return ev_do_port(fc, arg, 1 /* EPRT */);
    }
}


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


/* Bring the data connection up under the event loop.  Passive: wrap the pending
 * listener and arm its accept event.  Active: open a non-blocking socket bound to
 * the control channel's local IP, start the connect, and arm the write event.
 * Returns NGX_OK once the relevant event is armed (completion is asynchronous)
 * or NGX_ERROR if the socket could not be set up. */
ngx_int_t
brix_ftp_ev_data_open(ftp_ev_dc_t *dc)
{
    ftp_ev_t *fc = dc->fc;

    if (!fc->active) {
        /* Passive: the listener fd is already open (PASV/EPSV) and non-blocking. */
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

    /* Active: connect out to the armed, peer-pinned target. */
    {
        struct sockaddr_in local;
        socklen_t          llen = sizeof(local);
        int                dfd;
        int                rc;

        fc->active = 0;                          /* one-shot: consume the arm  */

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
            (void) bind(dfd, (struct sockaddr *) &local, sizeof(local));
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
}


/* ---- teardown -------------------------------------------------------------- */

/* Finish a transfer: release the VFS side, close the data socket and any pending
 * listener, emit the control-channel result (226 / 550), and resume the control
 * state machine.  Idempotent-safe: the pump only calls it once per transfer. */
void
brix_ftp_ev_data_finish(ftp_ev_dc_t *dc, ngx_int_t rc)
{
    ftp_ev_t *fc = dc->fc;

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
    }
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
