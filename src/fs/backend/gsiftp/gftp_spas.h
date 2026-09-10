/*
 * gftp_spas.h — GridFTP striped passive data channels (GFD.020 §5.1) for the
 * outbound gsiftp storage driver.
 *
 * WHAT: `SPAS` asks the origin for SEVERAL data-channel listeners at once and
 * answers with one address per stripe; the driver connects to all of them and
 * reassembles the single MODE E block stream that arrives across them.  This
 * header owns the connection GROUP a transfer runs over, striped or not, so the
 * transfer code never has to know which of the two it got.
 *
 * WHY:  one TCP connection is one congestion window.  On the transatlantic
 * paths this driver exists for, a single stream leaves most of the link unused
 * no matter how large the socket buffers are, and striping is the accepted
 * remedy — it is why GridFTP has extended block mode at all.  The receiver
 * (gftp_mode_e.c) was written for the general case from the start, so what was
 * missing was only the way to ASK.
 *
 * WHY IT IS A CEILING, NOT A REQUIREMENT: `mode=` and `prot=` say what the
 * bytes ARE — how they are framed, whether they are protected — and an origin
 * that will not honour them fails the transfer, because serving under weaker
 * terms would give the operator neither the property nor a diagnostic.
 * `streams=<n>` says how FAST the same, identically verified bytes arrive.  An
 * origin that does not advertise SPAS, answers it with an error, offers more
 * stripes than the operator budgeted, or names an address that may not be
 * dialled is therefore served by the single pinned connection instead of
 * failing — exactly as an origin without `ERET` is (gftp_feat.h).
 *
 * WHY THE ADDRESS CHECK IS THE WHOLE SECURITY STORY: a SPAS reply is the one
 * place in this protocol where an origin hands the client a LIST of addresses
 * to dial.  gftp_dc_open() never trusted even the single PASV address — it
 * discards it and dials the control channel's own peer — and striping does not
 * get to relax that: a stripe naming any other address is the classic FTP
 * bounce, turning the storage driver into a port scanner aimed wherever the
 * origin (or whoever spoofed its reply) likes.  Every stripe must be the
 * control peer; one that is not abandons the striped attempt entirely, and
 * nothing is dialled.  The cost is that a genuinely MULTI-HOST striped server
 * is read over one connection rather than several, which is a performance
 * limit and never a correctness one.
 *
 * HOW: gftp_dc_group_open() is the only entry point the transfer code uses.  It
 * decides whether striping is wanted at all (store line, MODE E, FEAT), issues
 * SPAS, screens every stripe, dials the ones it kept through gftp_dc_open_at(),
 * and falls back to a single gftp_dc_open() whenever any of that does not hold.
 */
#ifndef BRIX_GFTP_SPAS_H
#define BRIX_GFTP_SPAS_H

#include "gftp_dc.h"

/* The data connections of ONE transfer.  `n` is 1 for an unstriped transfer, so
 * a caller never branches on how the group was opened. */
typedef struct {
    gftp_dc_t conns[GFTP_STREAMS_MAX];
    unsigned  n;
} gftp_dc_group_t;

/* Open the data connections for one retrieve.  Returns 0 with group->n >= 1, or
 * -1 with the session error set.  Never returns a partially-open group: on
 * failure every connection is closed. */
int gftp_dc_group_open(gftp_session_t *session, gftp_dc_group_t *group);

/* Raise every connection in the group to PROT P, or do nothing on a clear
 * session.  Returns 0, or -1 with the group closed and the session error set.
 *
 * Separate from the open, and called only AFTER the transfer command, for the
 * reason gftp_dc_secure() states: the origin starts its side of each stripe's
 * handshake when the transfer begins, not when the socket arrives. */
int gftp_dc_group_secure(gftp_session_t *session, gftp_dc_group_t *group);

/* Close every connection in the group.  Idempotent. */
void gftp_dc_group_close(gftp_dc_group_t *group);

#endif /* BRIX_GFTP_SPAS_H */
