#include "ftp_ev.h"

#include "core/compat/net_target.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>      /* sscanf for PORT */
#include <stdlib.h>     /* strtoul for EPRT */
#include <unistd.h>     /* close() */
#include <errno.h>      /* EADDRINUSE/EADDRNOTAVAIL — passive-range bind walk */

/*
 * ftp_ev_data_setup.c — the four data-channel setup verbs (PASV/EPSV/PORT/EPRT).
 *
 * WHAT: parse and answer the verbs that *nominate* a data endpoint, before any
 * transfer verb runs: PASV/EPSV open a non-blocking listener and publish its
 * address; PORT/EPRT pin and screen a client-nominated target.
 *
 * WHY: split out of ftp_ev_data.c (coding-standards §1) because nomination and
 * bring-up are separate concerns with separate risk profiles — this half is
 * argument parsing and the anti-bounce/SSRF boundary, the other half is event
 * plumbing and teardown.  Keeping the screen beside its two parsers means the
 * security rule and the strings it validates are read together.
 *
 * HOW: state is deposited on the session (fc->pasv_fd for passive,
 * fc->active_sa + fc->active for active) and consumed later by
 * brix_ftp_ev_data_open() in ftp_ev_data.c.  The confinement rules are ported
 * verbatim from the sync engine (ftp_do_pasv/ftp_do_port) so both engines expose
 * the same data-channel security boundary.
 */


/* Create the non-blocking listen socket and report the control connection's own
 * local address in `local` — the listener must bind the same host the client is
 * already talking to.  Returns the fd, or -1 (nothing left open) on any failure. */
static int
ev_pasv_open_socket(ftp_ev_t *fc, struct sockaddr_in *local)
{
    socklen_t llen = sizeof(*local);
    int       fd;

    ngx_memzero(local, sizeof(*local));         /* getsockname may leave it   */

    if (getsockname(fc->c->fd, (struct sockaddr *) local, &llen) != 0
        || local->sin_family != AF_INET)
    {
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (ngx_nonblocking(fd) == -1) {
        (void) close(fd);
        return -1;
    }
    return fd;
}


/* Bind `fd` to the first free port of the configured passive range, updating
 * `addr` in place.  0 on success; -1 when the window is exhausted (or a
 * non-contention error ended the walk, which the next port would not clear). */
static int
ev_pasv_bind_range(ftp_ev_t *fc, int fd, struct sockaddr_in *addr)
{
    ngx_int_t p;

    for (p = fc->conf->pasv_port_lo; p <= fc->conf->pasv_port_hi; p++) {
        addr->sin_port = htons((unsigned short) p);
        if (bind(fd, (struct sockaddr *) addr, sizeof(*addr)) == 0) {
            return 0;
        }
        if (errno != EADDRINUSE && errno != EADDRNOTAVAIL) {
            break;
        }
    }
    return -1;
}


/* Start listening and read back the address actually bound (the port is only
 * known here in the ephemeral case).  0 on success, -1 otherwise. */
static int
ev_pasv_listen(int fd, struct sockaddr_in *addr)
{
    socklen_t blen = sizeof(*addr);

    /* Backlog spans a full MODE E stream fan-out (globus opens all parallel data
     * connections at once), matching the sync engine. */
    if (listen(fd, BRIX_FTP_EV_DATA_BACKLOG) != 0
        || getsockname(fd, (struct sockaddr *) addr, &blen) != 0)
    {
        return -1;
    }
    return 0;
}


/* Publish the listener: RFC 2428 (229, port only) or RFC 959 (227, h1..h4,p1,p2). */
static ngx_int_t
ev_pasv_reply(ftp_ev_t *fc, const struct sockaddr_in *addr, int extended)
{
    unsigned char ip[4];
    unsigned      port = ntohs(addr->sin_port);

    if (extended) {
        return brix_ftp_ev_reply(fc,
            "229 Entering Extended Passive Mode (|||%ud|)\r\n",
            (ngx_uint_t) port);
    }

    ngx_memcpy(ip, &addr->sin_addr.s_addr, 4);
    return brix_ftp_ev_reply(fc,
        "227 Entering Passive Mode (%ud,%ud,%ud,%ud,%ud,%ud)\r\n",
        (ngx_uint_t) ip[0], (ngx_uint_t) ip[1],
        (ngx_uint_t) ip[2], (ngx_uint_t) ip[3],
        (ngx_uint_t) (port >> 8), (ngx_uint_t) (port & 0xff));
}


/* PASV/EPSV: open a non-blocking listener bound to the control connection's local
 * IP and an ephemeral port; `extended` selects the RFC 2428 (229) vs RFC 959
 * (227) reply.  Mirrors the sync ftp_do_pasv, but the socket is non-blocking so
 * the later accept runs under the event loop. */
static ngx_int_t
ev_do_pasv(ftp_ev_t *fc, int extended)
{
    struct sockaddr_in  local;
    struct sockaddr_in  bindaddr;
    int                 fd;

    fc->active = 0;                             /* PASV/EPSV overrides PORT   */

    if (fc->pasv_fd >= 0) {
        (void) close(fc->pasv_fd);
        fc->pasv_fd = -1;
    }

    fd = ev_pasv_open_socket(fc, &local);
    if (fd < 0) {
        return brix_ftp_ev_reply(fc, "425 Cannot open passive connection\r\n");
    }

    ngx_memzero(&bindaddr, sizeof(bindaddr));
    bindaddr.sin_family = AF_INET;
    bindaddr.sin_addr   = local.sin_addr;      /* same host as control       */

    /* Bind the listener. With a configured passive range (brix_gridftp_pasv_port_range)
     * we walk it and take the first free port so the peer only ever has to reach a
     * firewall-opened window; unset (lo == 0) keeps the kernel-ephemeral bind. A
     * fully-occupied range fails the transfer (rather than falling back to a
     * random, un-firewalled port) so a locked-down deployment stays predictable. */
    if (fc->conf->pasv_port_lo > 0) {
        if (ev_pasv_bind_range(fc, fd, &bindaddr) != 0) {
            (void) close(fd);
            return brix_ftp_ev_reply(fc,
                "425 No free passive port in configured range\r\n");
        }
    } else {
        bindaddr.sin_port = 0;                 /* ephemeral                  */
        if (bind(fd, (struct sockaddr *) &bindaddr, sizeof(bindaddr)) != 0) {
            (void) close(fd);
            return brix_ftp_ev_reply(fc, "425 Cannot open passive connection\r\n");
        }
    }

    if (ev_pasv_listen(fd, &bindaddr) != 0) {
        (void) close(fd);
        return brix_ftp_ev_reply(fc, "425 Cannot open passive connection\r\n");
    }

    fc->pasv_fd = fd;
    return ev_pasv_reply(fc, &bindaddr, extended);
}


/* Parse a classic "h1,h2,h3,h4,p1,p2" PORT argument into (addr, port). Returns
 * NGX_DECLINED on success (fields filled); on a malformed argument it emits the
 * 501 reply and returns that reply's status for the caller to propagate. */
static ngx_int_t
ev_port_parse_classic(ftp_ev_t *fc, const char *arg, in_addr_t *addr,
    unsigned *port)
{
    unsigned      h[4], p[2];
    unsigned char b[4];

    if (sscanf(arg, "%u,%u,%u,%u,%u,%u",
               &h[0], &h[1], &h[2], &h[3], &p[0], &p[1]) != 6
        || (h[0] | h[1] | h[2] | h[3]) > 255 || (p[0] | p[1]) > 255)
    {
        return brix_ftp_ev_reply(fc, "501 Bad PORT argument\r\n");
    }
    b[0] = (unsigned char) h[0]; b[1] = (unsigned char) h[1];
    b[2] = (unsigned char) h[2]; b[3] = (unsigned char) h[3];
    ngx_memcpy(addr, b, 4);
    *port = (p[0] << 8) | p[1];
    return NGX_DECLINED;
}

/* Parse an "|1|ip|port|" EPRT argument (IPv4 only) into (addr, port). Same
 * NGX_DECLINED-on-success / reply-status-on-error contract as the classic form. */
static ngx_int_t
ev_port_parse_extended(ftp_ev_t *fc, const char *arg, in_addr_t *addr,
    unsigned *port)
{
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
    if (inet_pton(AF_INET, ipbuf, addr) != 1) {
        return brix_ftp_ev_reply(fc, "501 Bad EPRT address\r\n");
    }
    *port = (unsigned) strtoul(pt + 1, NULL, 10);
    return NGX_DECLINED;
}

/* Anti-bounce pin + SSRF screen for an active-mode target. A plain transfer must
 * target the control peer; an off-peer target is only allowed as a GSI (DCAU A)
 * TPC leg. Returns NGX_DECLINED when the target is permitted (fc->active_offpeer
 * recorded), else the emitted reply's status. */
static ngx_int_t
ev_port_screen_target(ftp_ev_t *fc, const struct sockaddr_in *tgt)
{
    struct sockaddr_in       peer;
    socklen_t                plen = sizeof(peer);
    brix_net_target_policy_t pol;
    char                     err[128];

    ngx_memzero(&peer, sizeof(peer));           /* getpeername may leave it   */
    if (getpeername(fc->c->fd, (struct sockaddr *) &peer, &plen) != 0
        || peer.sin_family != AF_INET)
    {
        return brix_ftp_ev_reply(fc, "500 Cannot determine control peer\r\n");
    }
    fc->active_offpeer = (peer.sin_addr.s_addr != tgt->sin_addr.s_addr);
    if (fc->active_offpeer && !(fc->sec_active && fc->dcau_a)) {
        ngx_log_error(NGX_LOG_WARN, fc->c->log, 0,
                      "brix: gsiftp(ev) rejected active-mode target != control "
                      "peer (no DCAU A; possible FTP-bounce)");
        return brix_ftp_ev_reply(fc, "500 Data address must match control peer\r\n");
    }

    ngx_memzero(&pol, sizeof(pol));
    pol.allow_local   = 1;
    pol.allow_private = 1;
    if (brix_net_target_check_addr((struct sockaddr *) tgt, &pol,
                                   err, sizeof(err)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, fc->c->log, 0,
                      "brix: gsiftp(ev) active-mode target blocked: %s", err);
        return brix_ftp_ev_reply(fc, "500 Data address not permitted\r\n");
    }
    return NGX_DECLINED;
}

/* PORT/EPRT: arm an active-mode target.  The nominated address is pinned to the
 * control peer (anti FTP-bounce; relaxed only for a DCAU-A TPC leg) and screened
 * through the SSRF policy — identical to the sync ftp_do_port. */
static ngx_int_t
ev_do_port(ftp_ev_t *fc, const char *arg, int extended)
{
    struct sockaddr_in tgt;
    in_addr_t          addr = 0;
    unsigned           port = 0;
    ngx_int_t          rc;

    /* Seeded, not merely declared: the parsers write (addr, port) only on their
     * success path, so a helper that ever signalled an error as NGX_DECLINED
     * would leave the caller dialling an uninitialised address.  Zero makes that
     * degrade into the "501 Bad data port" arm below instead. */
    ngx_memzero(&tgt, sizeof(tgt));
    tgt.sin_family = AF_INET;

    rc = extended ? ev_port_parse_extended(fc, arg, &addr, &port)
                  : ev_port_parse_classic(fc, arg, &addr, &port);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    if (port == 0 || port > 65535) {
        return brix_ftp_ev_reply(fc, "501 Bad data port\r\n");
    }
    tgt.sin_addr.s_addr = addr;
    tgt.sin_port        = htons((unsigned short) port);

    rc = ev_port_screen_target(fc, &tgt);
    if (rc != NGX_DECLINED) {
        return rc;
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
