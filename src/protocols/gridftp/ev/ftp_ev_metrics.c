#include "ftp_ev.h"

/*
 * ftp_ev_metrics.c — the GridFTP gateway's data-plane seam into the shared
 * {proto="gridftp"} metrics zone.
 *
 * WHAT: the FTP data verb → brix_metric_op_t map, the per-transfer byte/duration
 * accounting, and the two record points every transfer passes through — one for a
 * transfer that reached the data channel, one for a transfer refused before it.
 *
 * WHY: the VFS meters what it owns.  Every namespace verb this gateway issues
 * (SIZE/MDTM/MLST → STAT, MKD → MKDIR, DELE/RMD → DELETE, RNFR+RNTO → RENAME,
 * LIST/NLST/MLSD → DIRLIST) is observed exactly once inside brix_vfs_* under the
 * ctx built by brix_ftp_ev_vfs_ctx(), so it already lands under this label and a
 * second op row here would double-count it.  What the VFS deliberately does NOT
 * meter is the data plane: brix_vfs_file_pread / brix_vfs_writer_write book only
 * per-backend bytes, and brix_vfs_staged_commit leaves "the unified WRITE op row
 * to the owning protocol".  That row is this file's job — the same split WebDAV
 * makes (GET→READ, PUT→WRITE recorded protocol-side, everything else left to the
 * VFS).
 *
 * HOW: the transfer's own state carries the accounting, so the hot pumps stay
 * untouched — no per-chunk counter, no extra branch in the send/recv loops.  A
 * transfer's byte total is derived at completion from the offsets the pumps
 * already maintain, and its duration from ngx_current_msec sampled when the verb
 * started (a signed diff, so a clock step or msec wrap reads as 0, never as a
 * bogus multi-hour sample).
 */


/* Only RETR (READ) and STOR/APPE (WRITE) are the gateway's own rows; the listing
 * verbs map to DIRLIST, which the VFS already observed at brix_vfs_opendir. */
brix_metric_op_t
brix_ftp_ev_metric_op(int ftp_op)
{
    switch (ftp_op) {
    case FTP_EV_OP_RETR:
        return BRIX_METRIC_OP_READ;
    case FTP_EV_OP_STOR:
    case FTP_EV_OP_APPE:
        return BRIX_METRIC_OP_WRITE;
    default:
        return BRIX_METRIC_OP_DIRLIST;
    }
}


/* Payload bytes this transfer actually moved.
 *
 * MODE E STOR commits out-of-order blocks at their own offsets, so ->off never
 * advances and eb_received is its committed-byte counter.  Every other shape
 * advances ->off from the transfer's start offset (non-zero after a REST resume),
 * and for RETR that is exactly the payload pulled from the VFS — the same volume
 * brix_metric_backend_bytes booked, so the per-proto and per-backend series stay
 * comparable.  A failed transfer reports what it moved before it failed: those
 * bytes were read or written for real, and the backend ledger already counted
 * them. */
static off_t
ev_metric_bytes(const ftp_ev_dc_t *dc)
{
    if (dc->writing && dc->mode_e) {
        return dc->eb_received;
    }
    return (dc->off > dc->start_off) ? dc->off - dc->start_off : 0;
}


void
brix_ftp_ev_metric_xfer(const ftp_ev_dc_t *dc, ngx_int_t rc)
{
    brix_metric_op_t op = brix_ftp_ev_metric_op(dc->op);
    ngx_msec_int_t   elapsed;

    if (op != BRIX_METRIC_OP_READ && op != BRIX_METRIC_OP_WRITE) {
        return;                  /* a listing: the VFS owns that op row */
    }

    /* Measured from the verb, so it spans the data-channel set-up (PASV accept
     * or active connect) as well as the bytes — that wait is part of what the
     * client experienced as the transfer. */
    elapsed = (ngx_msec_int_t) (ngx_current_msec - dc->start_msec);
    if (elapsed < 0) {
        elapsed = 0;
    }

    /* The class matches the reply the client just received: a transfer that got
     * this far and failed did so on the data channel or in the VFS.  The refusals
     * that carry a permission or not-found verdict never reach here — they are
     * recorded by brix_ftp_ev_metric_refused() before any dc exists. */
    brix_metric_op_done(BRIX_PROTO_GRIDFTP, op, (size_t) ev_metric_bytes(dc),
                        (ngx_msec_t) elapsed * 1000,
                        (rc == NGX_OK) ? BRIX_ERR_NONE : BRIX_ERR_IO);
}


/* A refused listing IS recorded here, unlike a successful one: the refusal
 * happens before brix_vfs_opendir, so the VFS never saw the op and there is
 * nothing to double-count — leaving it out would hide every denied LIST. */
void
brix_ftp_ev_metric_refused(int ftp_op, brix_err_class_t err)
{
    /* op_count, not op_done: nothing ran, so there is no duration — filing a 0 µs
     * sample would drag the lowest latency bucket down with refusals. */
    brix_metric_op_count(BRIX_PROTO_GRIDFTP, brix_ftp_ev_metric_op(ftp_op), err);
}
