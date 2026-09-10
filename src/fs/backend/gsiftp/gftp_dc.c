/* One outbound GridFTP data connection: passive open, protection, I/O.
 * See gftp_dc.h for the WHAT/WHY/HOW. */

#include "gftp_dc.h"
#include "gftp_reply.h"
#include "protocols/root/connection/netconnect.h"
#include "net/dns/dns.h"          /* brix_dns_parse_literal: numeric peer only */

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int
gftp_dc_port(gftp_session_t *session, unsigned *port)
{
    unsigned char ignored[4];

    if (gftp_command(session, "EPSV") != 0) {
        return -1;
    }
    if (session->code == 229) {
        if (gftp_reply_parse_epsv(session->text, strlen(session->text), port)
            == 0) {
            return 0;
        }
        gftp_set_error(session, EPROTO, "GridFTP EPSV reply is malformed");
        return -1;
    }
    if (gftp_command(session, "PASV") != 0 || session->code != 227) {
        gftp_set_error(session, EPROTO, "GridFTP passive mode was refused");
        return -1;
    }
    if (gftp_reply_parse_pasv(session->text, strlen(session->text), ignored,
                              port) != 0) {
        gftp_set_error(session, EPROTO, "GridFTP PASV reply is malformed");
        return -1;
    }
    return 0;
}

/* Dial one already-decided data target.  `ip` is a NUMERIC address string —
 * a literal parse, never a name lookup (phase-116) — and the caller is the one
 * that decided it may be dialled: gftp_dc_open() pins it to the control
 * channel's own peer, and gftp_spas.c refuses any stripe that is not that same
 * peer before it ever reaches here. */
static int
gftp_dc_dial(gftp_session_t *session, const char *ip, unsigned port)
{
    brix_dns_addr_t  addr;
    ngx_str_t        peer;
    int              fd;

    if (port < 1024 || port > 65535 || ip[0] == '\0') {
        gftp_set_error(session, EACCES,
            "refusing unsafe GridFTP passive data target");
        return -1;
    }
    peer.data = (u_char *) ip;
    peer.len = strlen(ip);
    if (brix_dns_parse_literal(&peer, &addr) != NGX_OK) {
        gftp_set_error(session, EHOSTUNREACH,
            "cannot resolve pinned GridFTP data peer");
        return -1;
    }
    ngx_inet_set_port((struct sockaddr *) &addr.ss, (in_port_t) port);
    fd = socket(addr.ss.ss_family, SOCK_STREAM, 0);
    if (fd >= 0 && brix_connect_fd_deadline(fd, (struct sockaddr *) &addr.ss,
            addr.len, session->timeout_ms) != 0) {
        close(fd);
        fd = -1;
    }
    if (fd < 0) {
        gftp_set_error(session, ECONNREFUSED,
            "cannot connect to pinned GridFTP data peer");
    }
    return fd;
}

void
gftp_dc_init(gftp_dc_t *dc)
{
    dc->fd = -1;
    dc->tls = NULL;
}

int
gftp_dc_open_at(gftp_session_t *session, gftp_dc_t *dc, const char *ip,
    unsigned port)
{
    gftp_dc_init(dc);
    dc->fd = gftp_dc_dial(session, ip, port);

    return dc->fd < 0 ? -1 : 0;
}

int
gftp_dc_secure(gftp_session_t *session, gftp_dc_t *dc)
{
    if (session->prot != GFTP_DPROT_P) {
        return 0;                       /* a clear channel needs no handshake */
    }
    /* A protected channel that cannot complete its handshake is CLOSED, never
     * demoted: the caller has no way to reach the clear path from here. */
    if (gftp_dc_tls_start(session, dc) != 0) {
        gftp_dc_close(dc);
        return -1;
    }
    return 0;
}

int
gftp_dc_open(gftp_session_t *session, gftp_dc_t *dc)
{
    unsigned port;

    gftp_dc_init(dc);
    if (gftp_dc_port(session, &port) != 0) {
        return -1;
    }
    /* EPSV gives only a port and PASV's address is discarded on purpose: the
     * data peer is the control channel's own peer, always. */
    return gftp_dc_open_at(session, dc, session->peer_ip, port);
}

ssize_t
gftp_dc_read(gftp_session_t *session, gftp_dc_t *dc, void *buf, size_t cap)
{
    if (dc->tls != NULL) {
        return gftp_dc_tls_read(session, dc, buf, cap);
    }
    return gftp_socket_read(session, dc->fd, buf, cap);
}

int
gftp_dc_write_all(gftp_session_t *session, gftp_dc_t *dc, const void *buf,
    size_t len)
{
    if (dc->tls != NULL) {
        return gftp_dc_tls_write_all(session, dc, buf, len);
    }
    return gftp_socket_write_all(session, dc->fd, buf, len);
}

void
gftp_dc_finish_write(gftp_dc_t *dc)
{
    if (dc->tls != NULL) {
        gftp_dc_tls_finish_write(dc);
        return;
    }
    if (dc->fd >= 0) {
        (void) shutdown(dc->fd, SHUT_WR);
    }
}

void
gftp_dc_close(gftp_dc_t *dc)
{
    if (dc->tls != NULL) {
        gftp_dc_tls_free(dc);
    }
    if (dc->fd >= 0) {
        close(dc->fd);
        dc->fd = -1;
    }
}
