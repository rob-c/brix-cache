#ifndef BRIX_GFTP_MODE_E_H
#define BRIX_GFTP_MODE_E_H

/*
 * gftp_mode_e.h — GridFTP MODE E on the OUTBOUND gsiftp storage driver.
 *
 * WHAT: the extended-block receiver (RETR) and sender (STOR) the driver uses
 * once the store line asks for `mode=e`.
 *
 * WHY:  MODE S is one byte stream on one socket: a ranged read costs a REST and
 * a fresh transfer, a whole-file read cannot use more than one TCP connection,
 * and there is no in-band way for the origin to say where a byte belongs.  MODE
 * E — GFD.020 §3.4, what every production GridFTP mover actually negotiates —
 * frames the transfer as offset-addressed blocks that may arrive out of order
 * across up to `Parallelism` data connections.  It is the difference between
 * "we speak the protocol" and "we can pull from a real endpoint at rate".
 *
 * WHY IT IS A SECURITY BOUNDARY: because blocks carry their own offsets, a
 * block that overlaps an already-committed range is not a benign retransmit —
 * it is either corruption or a deliberate attempt to rewrite bytes the receiver
 * has already accepted (and, for a fill, already checksummed).  The receiver
 * therefore keeps every committed range and fails the transfer on the first
 * overlap, exactly as the inbound door does; the shared test is
 * ftp_eb_range_overlaps() in protocols/gridftp/ftp_eblock.h.
 *
 * HOW:  the receiver polls all data connections at once, tracking per-connection
 * header/payload state, and sinks each payload at `offset - start`.  It stops
 * when every connection has sent its EOD and the count promised by the EOF block
 * has been met.  The sender frames each chunk the source hands it at the running
 * offset and closes with the combined EOF|EOD trailer the door's own MODE E
 * receiver expects.
 */

#include "gftp_dc.h"

/* Committed-range table cap.  A well-behaved sender produces few ranges (one per
 * connection, growing contiguously); a table this size is reached only by a peer
 * scattering blocks, which is refused rather than tracked without bound. */
#define GFTP_EB_MAX_RANGES 4096

typedef struct {
    gftp_dc_t   *conns;      /* nconns open data connections               */
    unsigned     nconns;
    off_t        start;      /* absolute file offset the transfer begins at */
    uint64_t     limit;      /* refuse anything past start + limit          */
    gftp_sink_fn sink;
    void        *ctx;
    uint64_t     received;   /* OUT: bytes committed to the sink            */
    /* Did the retrieve command DECLARE this window to the origin?  ERET P
     * carries offset and length, so a block past the end is the origin
     * exceeding what it was told and stays a refusal.  REST+RETR carries only
     * the restart marker: RFC 959 RETR has no length and the origin sends the
     * whole tail, so bytes past the end are the protocol working as specified
     * and the receiver stops at the edge instead of failing the transfer. */
    int          bounded;
    /* OUT: 1 when the receiver stopped at the window edge with the origin still
     * sending, so the caller must NOT wait for a completion reply - the same
     * contract MODE S signals by returning 0 from gftp_retrieve_stream(). */
    int          stopped_early;
} gftp_mode_e_req_t;

/* Receive one MODE E transfer.  Returns 0 with req->received set, or -1 with the
 * session error set (EPROTO on a malformed/overlapping/out-of-window block). */
int gftp_mode_e_receive(gftp_session_t *session, gftp_mode_e_req_t *req);

/* Send one MODE E transfer over `dc`, pulling bytes from `source` until it
 * returns 0.  Returns 0 or -1. */
int gftp_mode_e_send(gftp_session_t *session, gftp_dc_t *dc,
    gftp_source_fn source, void *ctx);

#endif /* BRIX_GFTP_MODE_E_H */
