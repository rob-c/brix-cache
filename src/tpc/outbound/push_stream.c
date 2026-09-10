#include "tpc/engine/tpc_internal.h"
#include "source_internal.h"
#include "protocols/root/protocol/frame_hdr.h"  /* xrd_error_body_decode */
#include "fs/vfs/vfs.h"                         /* INVARIANT 12: the read seam */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* File: push_stream.c — F16 push, the byte mover.
 *
 * WHAT: tpc_push_stream() streams the whole local file (t->dst_fd / t->dst_obj,
 * open READ-ONLY) to an already-opened remote handle at the destination, in
 * rounds of `nslots` TPC_CHUNK_SIZE windows at consecutive offsets, where
 * nslots = 1 primary + t->nsub bound sub-streams.
 *
 * WHY: a push cannot reuse the pull's loop even though the shape rhymes. The
 * pull's slot arithmetic (tpc_stream_plan_round) exists because a READ reply is
 * ambiguous — a short frame may mean EOF, a partial window, or a stopped source,
 * and only the source knows which. A WRITE has no such ambiguity: the peer
 * answers kXR_ok or it fails. What IS ambiguous on this side is the local read,
 * so the completion signal is t->push_size (the size captured on the event loop
 * from the handle that authorized this transfer) and a local short read before
 * that offset is a hard error, not an EOF.
 *
 * HOW (wire): ClientWriteRequest is 24 bytes — streamid[2], requestid,
 * fhandle[4], int64 offset, pathid, reserved[3], int32 dlen — header then the
 * payload bytes. We tag streamid[1]=3 (the data tag, as the pull's reads do) and
 * send pathid 0 on every frame: a server that accepted our kXR_bind treats a
 * whole kXR_write arriving on a BOUND socket as belonging to that socket's
 * session and never inspects the pathid byte, whereas a non-zero pathid on the
 * PRIMARY connection is refused ("send data inline"). So the sub-stream carries
 * the frame; the pathid stays 0.
 *
 * Each round: read nslots local chunks at consecutive offsets → send one write
 * frame per slot on that slot's socket → drain one ack per slot → advance. Any
 * failed ack fails the whole push: a hole in a destination file is never
 * acceptable, and there is no partial-success outcome to report.
 */

/* The local read+send buffer is one allocation of TPC_CHUNK_SIZE * nslots. At
 * the TPC_STREAMS_MAX ceiling that is 15 MiB, which is an operator-chosen
 * maximum (brix_tpc_streams defaults to 1 = 1 MiB). */
typedef struct {
    u_char    *buf;         /* nslots * TPC_CHUNK_SIZE                     */
    size_t     got[TPC_STREAMS_MAX];  /* bytes read for each slot this round */
    int        nslots;
    uint64_t   offset;      /* file offset of slot 0 this round            */
} tpc_push_round_t;

/* The socket a slot sends on: slot 0 is the primary, slot i>0 the (i-1)th
 * bound sub-stream. Mirrors source_stream_multi.c's mapping exactly. */
static int
tpc_push_slot_fd(brix_tpc_pull_t *t, int primary_fd, int slot)
{
    return (slot == 0) ? primary_fd : t->sub[slot - 1].fd;
}

/*
 * WHAT: fill this round's buffer from the local file through the VFS seam.
 * WHY: INVARIANT 12 — the local file may be a block-striped or object-store
 * export, not a POSIX fd, so the bytes must come through brix_vfs_* and the
 * handle's copied sd_obj, never a bare pread. A short read BEFORE push_size is
 * a truncated source (someone raced us) and must fail rather than silently
 * publish a short file at the destination.
 * HOW: one read job per slot at offset + slot*TPC_CHUNK_SIZE, clamped to the
 * bytes remaining before push_size. Returns 0 with r->got[] filled, or -1 with
 * t->err_msg / t->xrd_error set.
 */
static int
tpc_push_fill_round(brix_tpc_pull_t *t, tpc_push_round_t *r)
{
    int slot;

    for (slot = 0; slot < r->nslots; slot++) {
        brix_vfs_job_t job;
        uint64_t       at   = r->offset + (uint64_t) slot * TPC_CHUNK_SIZE;
        uint64_t       left;
        size_t         want;

        r->got[slot] = 0;
        if (at >= t->push_size) {
            continue;                       /* past EOF: this slot idles */
        }

        left = t->push_size - at;
        want = (left < (uint64_t) TPC_CHUNK_SIZE) ? (size_t) left
                                                  : (size_t) TPC_CHUNK_SIZE;

        brix_vfs_job_read_init(&job, t->dst_fd, (off_t) at, want,
                               r->buf + (size_t) slot * TPC_CHUNK_SIZE,
                               want, 0);
        brix_vfs_job_set_obj(&job, &t->dst_obj);
        brix_vfs_io_execute(&job);

        if (job.io_errno != 0 || job.nio < 0) {
            int err = job.io_errno != 0 ? job.io_errno : EIO;

            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC push source read failed: %s", strerror(err));
            t->xrd_error = kXR_IOError;
            return -1;
        }
        if ((size_t) job.nio != want) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC push source shrank at offset %llu",
                     (unsigned long long) at);
            t->xrd_error = kXR_IOError;
            return -1;
        }
        r->got[slot] = want;
    }

    return 0;
}

/*
 * WHAT: send one kXR_write frame (header + payload) for one slot.
 * WHY: kept separate so the header layout is stated once and the send loop
 * stays flat.
 * HOW: 24-byte ClientWriteRequest, offset in network byte order via htobe64,
 * dlen counting only the payload, pathid 0 (see the file docblock).
 */
static int
tpc_push_send_slot(brix_tpc_pull_t *t, int fd, const u_char *fhandle,
                   uint64_t at, const u_char *data, size_t len)
{
    ClientWriteRequest wreq;

    xrd_creq_begin(&wreq, sizeof(wreq), 3, kXR_write);
    ngx_memcpy(wreq.fhandle, fhandle, XRD_FHANDLE_LEN);
    wreq.offset      = (kXR_int64) htobe64(at);
    wreq.pathid      = 0;
    wreq.dlen        = htonl((kXR_int32) len);

    if (tpc_send_all(t, fd, &wreq, sizeof(wreq)) != 0
        || tpc_send_all(t, fd, data, len) != 0)
    {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC push kXR_write send failed at offset %llu",
                 (unsigned long long) at);
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    return 0;
}

/*
 * WHAT: read one kXR_write acknowledgement off a slot's socket.
 * WHY: a write is only delivered once the destination says so; treating an
 * unread ack as success would let a refused write (quota, EROFS, a revoked
 * handle) pass as a completed copy.
 * HOW: one response frame; kXR_ok is the only accepted status, and a kXR_error
 * body is decoded so the client sees the destination's real reason.
 */
static int
tpc_push_recv_ack(brix_tpc_pull_t *t, int fd, uint64_t at)
{
    uint16_t     status = 0;
    uint32_t     dlen   = 0;
    u_char      *body   = NULL;
    int          code   = kXR_ServerError;
    const char  *msg    = "";
    size_t       msglen = 0;

    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC push write reply failed at offset %llu",
                 (unsigned long long) at);
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    if (status == kXR_ok) {
        free(body);
        return 0;
    }

    if (status == kXR_error) {
        (void) xrd_error_body_decode(body, dlen, &code, &msg, &msglen);
    }

    /* `msg` is a bounded slice INTO body — format before the free. */
    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC push destination refused write at offset %llu: %.*s",
             (unsigned long long) at, (int) msglen, msg);
    free(body);

    t->xrd_error = code;
    return -1;
}

/*
 * WHAT: send every filled slot of one round, then drain every ack.
 * WHY: sending all slots before reading any ack is what makes the extra streams
 * worth having — nslots windows are in flight at once. Draining in the same slot
 * order keeps each ack matched to the socket that carries it.
 * HOW: two passes over the slots; the first failure in either wins and the
 * round fails. A failed send still drains the acks for slots already sent, so
 * the sockets are not left holding an unread frame before the close ladder.
 */
static int
tpc_push_exchange_round(brix_tpc_pull_t *t, int primary_fd,
                        const u_char *fhandle, tpc_push_round_t *r)
{
    int rc = 0;
    int sent = 0;
    int slot;

    for (slot = 0; slot < r->nslots && r->got[slot] > 0; slot++) {
        uint64_t at = r->offset + (uint64_t) slot * TPC_CHUNK_SIZE;

        if (tpc_push_send_slot(t, tpc_push_slot_fd(t, primary_fd, slot),
                               fhandle, at,
                               r->buf + (size_t) slot * TPC_CHUNK_SIZE,
                               r->got[slot]) != 0)
        {
            rc = -1;
            break;
        }
        sent++;
    }

    for (slot = 0; slot < sent; slot++) {
        uint64_t at = r->offset + (uint64_t) slot * TPC_CHUNK_SIZE;

        if (tpc_push_recv_ack(t, tpc_push_slot_fd(t, primary_fd, slot), at)
            != 0)
        {
            rc = -1;               /* keep draining: never leave a stray frame */
        } else if (rc == 0) {
            t->bytes_written += r->got[slot];
        }
    }

    return rc;
}

/*
 * WHAT: how many bytes this round proved, and whether the file is exhausted.
 * WHY: with writes there is no short-frame ambiguity to judge, so this is plain
 * arithmetic over what we chose to read — but it stays a named step so the
 * "advance" and "done" decisions are visible rather than inlined in the loop.
 */
static size_t
tpc_push_round_advance(const tpc_push_round_t *r)
{
    size_t total = 0;
    int    slot;

    for (slot = 0; slot < r->nslots; slot++) {
        total += r->got[slot];
    }
    return total;
}

/*
 * tpc_push_stream — stream the local file out to the remote handle.
 * Returns 0 with t->result = NGX_OK once every byte through t->push_size has
 * been acknowledged, or -1 with t->err_msg / t->xrd_error set.
 */
int
tpc_push_stream(brix_tpc_pull_t *t, int fd, const u_char *fhandle)
{
    tpc_push_round_t r;
    time_t           started = time(NULL);
    int              rc      = 0;

    ngx_memzero(&r, sizeof(r));
    r.nslots = 1 + t->nsub;
    if (r.nslots < 1) {
        r.nslots = 1;
    }
    if (r.nslots > TPC_STREAMS_MAX) {
        r.nslots = TPC_STREAMS_MAX;
    }

    r.buf = malloc((size_t) r.nslots * TPC_CHUNK_SIZE);
    if (r.buf == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC push buffer allocation failed");
        t->xrd_error = kXR_NoMemory;
        return -1;
    }

    while (r.offset < t->push_size) {
        size_t advance;

        if (tpc_stream_check_deadline(t, started, r.offset) != 0) {
            rc = -1;
            break;
        }
        if (tpc_push_fill_round(t, &r) != 0) {
            rc = -1;
            break;
        }
        if (tpc_push_exchange_round(t, fd, fhandle, &r) != 0) {
            rc = -1;
            break;
        }

        advance = tpc_push_round_advance(&r);
        if (advance == 0) {
            /* Unreachable while offset < push_size (fill_round always reads at
             * least one byte for slot 0), but a zero advance would spin
             * forever — fail closed instead. */
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC push made no progress at offset %llu",
                     (unsigned long long) r.offset);
            t->xrd_error = kXR_IOError;
            rc = -1;
            break;
        }
        r.offset += advance;
    }

    free(r.buf);

    if (rc != 0) {
        t->result = NGX_ERROR;
        return -1;
    }

    /*
     * Completion gate: every byte the handle claimed must have been
     * acknowledged. bytes_written counts only ACKED payload, so this rejects a
     * transfer whose acks went missing as firmly as one that stopped early.
     */
    if ((uint64_t) t->bytes_written != t->push_size) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC push incomplete: %llu of %llu bytes acknowledged",
                 (unsigned long long) t->bytes_written,
                 (unsigned long long) t->push_size);
        t->xrd_error = kXR_IOError;
        t->result = NGX_ERROR;
        return -1;
    }

    t->result    = NGX_OK;
    t->xrd_error = 0;
    return 0;
}
