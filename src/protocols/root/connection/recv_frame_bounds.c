/*
 * recv_frame_bounds.c — pure XRootD request-framing bounds (see the header).
 *
 * brix_max_payload_for_request() was carved out of recv_process.c so the
 * per-opcode dlen cap — and the "reject before allocation" invariant built on it
 * — can be fuzzed standalone (hyper-hardening C-2). Behaviour is byte-identical;
 * recv_process.c now calls this and keeps its allocation path unchanged.
 *
 * Depends only on the wire opcode numbers (opcodes.h), the readv geometry
 * (flags.h), and the payload-size tunables (tunables.h) — all nginx-free, so this
 * TU builds against libc alone.
 */
#include "recv_frame_bounds.h"

#include "protocols/root/protocol/opcodes.h"
#include "protocols/root/protocol/flags.h"   /* BRIX_READV_SEGSIZE / _MAXSEGS */
#include "core/types/tunables.h"             /* BRIX_MAX_* payload caps */

uint32_t
brix_max_payload_for_request(uint16_t reqid)
/* WHAT: per-opcode payload size limit, checked BEFORE any allocation so an
 *       oversized dlen is rejected without allocating.
 * WHY:  each opcode has a legitimate maximum body; a hostile dlen beyond it must
 *       never reach the payload allocator.
 * HOW:  table of the opcodes that carry large bodies (writes, readv segments,
 *       auth, prepare); everything else is a path plus a small fixed body. */
{
    /* A plain kXR_write is delivered in bounded chunks (see BRIX_WRITE_STREAM_*),
     * so its dlen may legitimately exceed the buffered 16 MiB cap; bound it only
     * by the streaming ceiling.  pgwrite/writev/chkpoint still buffer the whole
     * body (per-page CRC / descriptor structure), so they keep the 16 MiB cap. */
    if (reqid == kXR_write) {
        return BRIX_MAX_WRITE_STREAM;
    }

    if (reqid == kXR_pgwrite || reqid == kXR_writev
        || reqid == kXR_chkpoint) {
        return BRIX_MAX_WRITE_PAYLOAD;
    }

    if (reqid == kXR_readv) {
        /* Each segment is BRIX_READV_SEGSIZE (16) bytes. */
        return BRIX_READV_MAXSEGS * BRIX_READV_SEGSIZE;
    }

    if (reqid == kXR_auth) {
        return BRIX_MAX_AUTH_PAYLOAD;
    }

    if (reqid == kXR_prepare) {
        return BRIX_MAX_PREPARE_PAYLOAD;
    }

    /* All other requests carry only a path (BRIX_MAX_PATH) plus a small
     * fixed-size body.  The +64 covers opcode-specific extras (e.g. the
     * kXR_login info field that follows the username in the payload). */
    return BRIX_MAX_PATH + 64;
}

int
brix_root_frame_dlen_ok(const unsigned char *hdr, size_t len,
                        uint16_t *reqid_out, uint32_t *dlen_out)
/* WHAT: decode the 24-byte ClientRequestHdr and test its dlen against the
 *       per-opcode cap — the executable form of "reject an oversized dlen before
 *       allocating a payload buffer".
 * WHY:  this is the exact bound recv_process.c enforces on the first untrusted
 *       bytes of every request; a harness driving arbitrary headers proves no
 *       reqid/dlen combination overflows the cap arithmetic or slips past.
 * HOW:  require a full 24-byte header; read requestid (BE16 @2) and dlen (BE32
 *       @20) exactly as the wire decoder does (streamid @0 is opaque, ignored);
 *       return dlen <= brix_max_payload_for_request(reqid). Pure. */
{
    uint16_t reqid;
    uint32_t dlen;

    if (hdr == NULL || len < 24) {
        return 0;
    }

    reqid = (uint16_t) ((hdr[2] << 8) | hdr[3]);
    dlen  = ((uint32_t) hdr[20] << 24) | ((uint32_t) hdr[21] << 16)
          | ((uint32_t) hdr[22] << 8) | (uint32_t) hdr[23];

    if (reqid_out != NULL) { *reqid_out = reqid; }
    if (dlen_out != NULL)  { *dlen_out = dlen; }

    return dlen <= brix_max_payload_for_request(reqid);
}
