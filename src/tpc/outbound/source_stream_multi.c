#include "platform/platform_api.h"
/* File: source_stream_multi.c — native TPC multi-stream read loop
 * WHAT: tpc_stream_to_dst_multi() streams the source into the destination with
 *       one kXR_read window in flight per stream (the primary plus every bound
 *       sub-stream), demultiplexing replies by streamid across the sockets, and
 *       finishes through the same completion gate / fsync as the single-stream
 *       loop in source_stream.c.
 *
 * WHY (release-2.0 F7): parallel windows let a WAN pull use more than one
 *      socket's worth of bandwidth-delay product (stock xrootd `ofs.tpc streams`).
 *      The loop shares the frame classifier, the positional writer, the deadline
 *      and the finish gate with the single-stream loop so the two cannot drift.
 *
 * HOW: a round issues N reads at consecutive TPC_CHUNK_SIZE offsets, ALL on the
 *      primary socket, each tagged streamid {slot, 3} and carrying the 8-byte
 *      read_args whose pathid steers slot i's reply out of sub-stream i-1 (0 =
 *      the primary). Replies are drained with poll() over every socket (plus a
 *      TLS-buffered-bytes check, since poll cannot see data OpenSSL already read),
 *      each frame written at round_base + slot*CHUNK + bytes-so-far; a source that
 *      answers on the primary instead (cross-worker bind, oversize read) is
 *      handled identically because demux keys on the streamid, not the socket.
 *      tpc_stream_plan_round() judges the round: contiguous advance, EOF, or a
 *      hole (which fails the pull rather than commit a sparse file). */
#include "tpc/engine/tpc_internal.h"
#include "source_internal.h"

#include <stdlib.h>
#include <string.h>

/* macOS doesn't have endian.h - use libkern/OSByteOrder.h */
#if defined(__APPLE__) && defined(__MACH__)
#else
#endif
#include <poll.h>
#include <time.h>

#if defined(__linux__)
#endif

/* Read replies carry streamid[1] == 3 (source_stream.c's tag); slot in [0]. */
#define TPC_STREAM_READ_TAG 3

/* WHAT: everything one round of windowed reads needs to send, drain and judge. */
typedef struct {
    int           fd;                       /* primary socket */
    const u_char *fhandle;
    uint64_t      base;                     /* file offset of slot 0 */
    int           nslots;                   /* 1 + t->nsub */
    int           pending;                  /* slots without a terminal kXR_ok */
    size_t        got[TPC_STREAMS_MAX];     /* bytes delivered per slot */
    unsigned char done[TPC_STREAMS_MAX];    /* slot saw its terminal kXR_ok */
    struct pollfd pfd[TPC_STREAMS_MAX];     /* primary + every sub-stream */
} tpc_multi_round_t;

/* WHAT: the fd a slot's reply is EXPECTED on (only used to build the poll set;
 * demux never trusts it). */
static int
tpc_multi_slot_fd(const brix_tpc_pull_t *t, int primary_fd, int slot)
{
    return (slot == 0) ? primary_fd : t->sub[slot - 1].fd;
}

/* WHAT: issue slot's kXR_read for this round on the primary: header + the
 * read_args payload naming the sub-stream that should carry the reply. */
static int
tpc_multi_send_slot(brix_tpc_pull_t *t, tpc_multi_round_t *r, int slot)
{
    u_char             frame[sizeof(ClientReadRequest) + TPC_READ_ARGS_LEN];
    ClientReadRequest *rdreq  = (ClientReadRequest *) frame;
    uint64_t           offset = r->base + (uint64_t) slot * TPC_CHUNK_SIZE;
    unsigned char      pathid = (slot == 0) ? 0 : t->sub[slot - 1].pathid;

    ngx_memzero(frame, sizeof(frame));
    rdreq->streamid[0] = (u_char) slot;
    rdreq->streamid[1] = TPC_STREAM_READ_TAG;
    rdreq->requestid   = htons(kXR_read);
    ngx_memcpy(rdreq->fhandle, r->fhandle, XRD_FHANDLE_LEN);
    rdreq->offset = (kXR_int64) brix_plat_htobe64(offset);
    rdreq->rlen   = htonl((kXR_int32) TPC_CHUNK_SIZE);
    rdreq->dlen   = htonl((kXR_int32) TPC_READ_ARGS_LEN);
    tpc_stream_plan_read_args(frame + sizeof(ClientReadRequest), pathid);

    if (tpc_send_all(t, r->fd, frame, sizeof(frame)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC kXR_read send failed at offset %llu (stream %d)",
                 (unsigned long long) offset, slot);
        t->xrd_error = kXR_IOError;
        return -1;
    }
    return 0;
}

/* WHAT: receive one frame from `fd` and account it to the slot its streamid
 * names. Returns 0, or -1 with t->err_msg / t->xrd_error set. */
static int
tpc_multi_recv_frame(brix_tpc_pull_t *t, tpc_multi_round_t *r, int fd)
{
    u_char    sid[2];
    uint16_t  status;
    uint32_t  dlen = 0;
    u_char   *body = NULL;
    int       slot;
    uint64_t  offset;

    if (tpc_recv_response_sid(t, fd, sid, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC kXR_read recv failed at offset %llu",
                 (unsigned long long) r->base);
        t->xrd_error = kXR_IOError;
        return -1;
    }

    slot = (int) sid[0];
    if (sid[1] != TPC_STREAM_READ_TAG || slot >= r->nslots || r->done[slot]) {
        free(body);
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC multi-stream reply for unexpected stream %u/%u",
                 (unsigned) sid[0], (unsigned) sid[1]);
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    offset = r->base + (uint64_t) slot * TPC_CHUNK_SIZE;
    if (tpc_stream_classify_frame(t, status, body, dlen, offset) != 0) {
        free(body);
        return -1;
    }
    if (dlen > 0 && body != NULL
        && tpc_stream_write_frame(t, offset, &r->got[slot], body, dlen) != 0)
    {
        free(body);
        return -1;
    }
    free(body);

    if (status == kXR_ok) {
        r->done[slot] = 1;
        r->pending--;
    }
    return 0;
}

/* WHAT: pick the sockets that can be read without blocking: any with bytes
 * already buffered inside its TLS session wins outright (poll cannot see
 * those); otherwise poll the whole set. Returns the number ready, 0 on the
 * idle timeout, -1 on a poll error. */
static int
tpc_multi_wait_ready(brix_tpc_pull_t *t, tpc_multi_round_t *r)
{
    int i, ready = 0;

    for (i = 0; i < r->nslots; i++) {
        r->pfd[i].revents = 0;
        if (tpc_io_pending(t, r->pfd[i].fd) > 0) {
            r->pfd[i].revents = POLLIN;
            ready++;
        }
    }
    if (ready > 0) {
        return ready;
    }
    return poll(r->pfd, (nfds_t) r->nslots, TPC_IO_TIMEOUT_SEC * 1000);
}

/* WHAT: drain every reply of the round, whichever socket it arrives on. */
static int
tpc_multi_drain_round(brix_tpc_pull_t *t, tpc_multi_round_t *r)
{
    while (r->pending > 0) {
        int i, ready = tpc_multi_wait_ready(t, r);

        if (ready <= 0) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC multi-stream read %s at offset %llu",
                     ready == 0 ? "timed out" : "poll failed",
                     (unsigned long long) r->base);
            t->xrd_error = kXR_IOError;
            return -1;
        }
        for (i = 0; i < r->nslots; i++) {
            if ((r->pfd[i].revents & (POLLIN | POLLERR | POLLHUP)) == 0) {
                continue;
            }
            if (tpc_multi_recv_frame(t, r, r->pfd[i].fd) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

/* WHAT: send + drain + judge one round. Returns 1 to continue at *base
 * advanced, 0 at EOF, -1 on failure (t->err_msg / t->xrd_error set). */
static int
tpc_multi_round(brix_tpc_pull_t *t, tpc_multi_round_t *r)
{
    size_t advance = 0;
    int    slot, eof = 0;

    ngx_memzero(r->got, sizeof(r->got));
    ngx_memzero(r->done, sizeof(r->done));
    r->pending = r->nslots;

    for (slot = 0; slot < r->nslots; slot++) {
        if (tpc_multi_send_slot(t, r, slot) != 0) {
            return -1;
        }
    }
    if (tpc_multi_drain_round(t, r) != 0) {
        return -1;
    }
    if (tpc_stream_plan_round(r->got, r->nslots, TPC_CHUNK_SIZE,
                              &advance, &eof) != 0)
    {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC multi-stream round left a hole after offset %llu",
                 (unsigned long long) r->base);
        t->xrd_error = kXR_IOError;
        return -1;
    }
    r->base += advance;
    return eof ? 0 : 1;
}

int
tpc_stream_to_dst_multi(brix_tpc_pull_t *t, int fd, const u_char *fhandle)
{
    tpc_multi_round_t r;
    time_t            pull_start = time(NULL);
    int               slot, rc;

    ngx_memzero(&r, sizeof(r));
    r.fd      = fd;
    r.fhandle = fhandle;
    r.nslots  = 1 + t->nsub;
    for (slot = 0; slot < r.nslots; slot++) {
        r.pfd[slot].fd     = tpc_multi_slot_fd(t, fd, slot);
        r.pfd[slot].events = POLLIN;
    }

    do {
        if (tpc_stream_check_deadline(t, pull_start, r.base) != 0) {
            return -1;
        }
        /* Every socket is quiet between rounds — the only point a renewal
         * kXR_auth can be carried on the primary (W8.2). */
        if (tpc_cred_renew_if_due(t, fd) != 0) {
            return -1;
        }
        rc = tpc_multi_round(t, &r);
    } while (rc > 0);

    if (rc < 0) {
        return -1;
    }
    return tpc_stream_finish(t);
}
