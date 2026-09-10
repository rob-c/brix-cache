#ifndef BRIX_GFTP_DC_H
#define BRIX_GFTP_DC_H

/*
 * gftp_dc.h — one outbound GridFTP data connection.
 *
 * WHAT: open a passive data connection to the origin (EPSV, falling back to
 * PASV), optionally raise it to PROT P, and read/write/close it.  A gftp_dc_t is
 * the ONLY handle the transfer code (gftp_data.c, gftp_mode_e.c) holds on the
 * data socket.
 *
 * WHY:  before phase-115 the data socket was a bare int and every transfer
 * called recv()/send() on it directly.  PROT P puts a TLS session in front of
 * that socket, and MODE E opens several of them at once; both changes would have
 * to be made in each transfer function separately if the fd stayed bare.  One
 * handle with one open/read/write/close surface means the protection decision is
 * made once, at open time, and a caller cannot accidentally write cleartext onto
 * a channel the store line asked to protect.
 *
 * HOW:  gftp_dc_open() runs EPSV/PASV and connects to the control channel's
 * PINNED numeric peer (never a fresh name lookup — the reply's address is
 * attacker-influenced).  On a PROT P session the TLS handshake is a SEPARATE
 * step, gftp_dc_secure(), which the transfer code runs only AFTER the transfer
 * command has been accepted — see the note on that function for why the order
 * is not free.  read/write dispatch on dc->tls, so a protected connection
 * cannot fall back to the clear path: if the handshake fails the connection is
 * closed and the transfer fails.
 */

#include "gftp_client.h"

typedef struct {
    int   fd;    /* -1 when closed                                          */
    void *tls;   /* SSL* when the channel is PROT P, NULL when it is clear  */
} gftp_dc_t;

/* Put `dc` in the closed state.  Always call before any other operation so an
 * error path can call gftp_dc_close() unconditionally. */
void gftp_dc_init(gftp_dc_t *dc);

/* Open one passive data connection for the session's current protection level:
 * EPSV (or PASV), then a dial of the CONTROL channel's peer at the port the
 * reply named.  Returns 0 with dc->fd >= 0, or -1 with the session error set. */
int gftp_dc_open(gftp_session_t *session, gftp_dc_t *dc);

/* Open one data connection to an ALREADY-DECIDED numeric target, otherwise
 * exactly as gftp_dc_open().  Split out for the striped channel (gftp_spas.c),
 * which learns several targets from one reply and must screen each of them
 * BEFORE dialling: this function dials what it is given, so the address policy
 * stays with the caller that can express it. */
int gftp_dc_open_at(gftp_session_t *session, gftp_dc_t *dc, const char *ip,
    unsigned port);

/* Raise an already-dialled connection to PROT P, or do nothing on a clear
 * session.  Returns 0 (secured, or nothing to do) or -1 with the session error
 * set and `dc` closed.
 *
 * CALL IT AFTER THE TRANSFER COMMAND, never at dial time.  A passive FTP server
 * has no reason to look at the data connection until it has a transfer to run:
 * it accepts and starts its side of the handshake when RETR/STOR arrives, not
 * when the socket appears.  A client that handshakes at dial time is waiting
 * for a ServerHello the server will not send until it reads a command the
 * client has not sent yet, and both sides sit there until something times out.
 * That is not a slow path — it is a deadlock, and it is what made every PROT P
 * transfer fail: the origin logged an idle control channel and the client an
 * SSL_connect with an empty error queue, neither of which names the cause. */
int gftp_dc_secure(gftp_session_t *session, gftp_dc_t *dc);

/* Read up to `cap` bytes.  Returns the byte count, 0 at end of data, or -1. */
ssize_t gftp_dc_read(gftp_session_t *session, gftp_dc_t *dc, void *buf,
    size_t cap);

/* Write all `len` bytes.  Returns 0 or -1. */
int gftp_dc_write_all(gftp_session_t *session, gftp_dc_t *dc, const void *buf,
    size_t len);

/* Signal end of data to the peer: a TLS close_notify on a protected channel, a
 * TCP half-close on a clear one.  GridFTP receivers treat either as EOD. */
void gftp_dc_finish_write(gftp_dc_t *dc);

/* Close the connection and release its TLS session.  Idempotent. */
void gftp_dc_close(gftp_dc_t *dc);

/* ---- implemented in gftp_dc_tls.c (PROT P) ------------------------------- */

/* Raise `dc` to a protected data channel: present the same X.509 proxy the
 * control channel authenticated with, PKIX-verify the peer's chain, and pin its
 * subject DN to the control channel's peer DN.  Returns 0 or -1. */
int gftp_dc_tls_start(gftp_session_t *session, gftp_dc_t *dc);

ssize_t gftp_dc_tls_read(gftp_session_t *session, gftp_dc_t *dc, void *buf,
    size_t cap);
int gftp_dc_tls_write_all(gftp_session_t *session, gftp_dc_t *dc,
    const void *buf, size_t len);
void gftp_dc_tls_finish_write(gftp_dc_t *dc);
void gftp_dc_tls_free(gftp_dc_t *dc);

#endif /* BRIX_GFTP_DC_H */
