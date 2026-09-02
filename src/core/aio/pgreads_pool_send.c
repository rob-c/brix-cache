#include "core/ngx_brix_module.h"
#include "pgreads_internal.h"
#include "protocols/root/read/read.h"
#include <poll.h>   /* §1.2 pool-send: POLLOUT wait between short send()s */

/*
 * pgreads_pool_send.c — the §1.2/§1.3 pool-thread send engine for stream
 * kXR_pgread.
 *
 * WHAT: The half of the pgread offload that runs ON THE POOL THREAD and owns
 *       the secondary's cleartext socket for the duration of one frame: the
 *       budgeted POLLOUT send loop (brix_pool_send_range), the single-frame
 *       sender (brix_pgread_pool_send), and the chunked read+CRC+send
 *       streamer (brix_pgread_pool_stream) with its chunk-sizing and
 *       read-error framing helpers.
 *
 * WHY:  Split out of pgreads.c along the thread/loop seam when the §1.3
 *       streamer pushed that file over the 600-line cap (coding-standards
 *       §1): everything here touches only the brix_pgread_aio_t task and the
 *       socket fd; everything left in pgreads.c is thread entry plus
 *       completion-side protocol/state mutation on the event loop.
 */


/* §1.2 pool-send pacing: one POLLOUT wait quantum and the wait budget after
 * which the worker hands the unsent tail back to the event loop (a slow
 * reader must not park a pool thread indefinitely — xrootd blocks its writer
 * threads here; we bound the wait and fall back to the out-ring). */
#define BRIX_POOL_SEND_WAIT_MS   25
#define BRIX_POOL_SEND_WAIT_MAX  12

/*
 * brix_pool_send_range — §1.2 budgeted send of the wire image bytes
 * [base + t->pool_sent, base + end) on the SECONDARY's cleartext socket.
 *
 * The watermark t->pool_sent advances as bytes land; the wait budget counts
 * CONSECUTIVE zero-progress polls (reset on any progress) so it measures a
 * genuinely stalled reader (~BRIX_POOL_SEND_WAIT_MAX × _MS), never frame
 * size.  Returns NGX_OK (watermark reached end), NGX_AGAIN (budget
 * exhausted — the caller hands the tail to the ring), NGX_ERROR (hard
 * socket error, t->pool_send_errno set).
 */
static ngx_int_t
brix_pool_send_range(brix_pgread_aio_t *t, const u_char *base, size_t end)
{
    ssize_t        n;
    ngx_uint_t     waits;
    struct pollfd  pfd;

    waits = 0;

    while (t->pool_sent < end) {
        n = send(t->sec_c->fd, base + t->pool_sent, end - t->pool_sent,
                 MSG_NOSIGNAL);

        if (n > 0) {
            t->pool_sent += (size_t) n;
            waits = 0;
            continue;
        }

        if (n == -1 && errno == EINTR) {
            continue;
        }

        if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (waits >= BRIX_POOL_SEND_WAIT_MAX) {
                return NGX_AGAIN;   /* stalled reader: hand the tail over */
            }
            waits++;
            pfd.fd = t->sec_c->fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            (void) poll(&pfd, 1, BRIX_POOL_SEND_WAIT_MS);
            continue;
        }

        t->pool_send_errno = (n == -1 && errno != 0) ? errno : EPIPE;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * brix_pgread_pool_send — §1.2: send the finished single [status|pages] frame
 * on the SECONDARY's cleartext socket from THIS pool thread (the data is
 * cache-hot from the read+CRC pass; the event loop never touches the bytes).
 *
 * Concurrency contract: the per-connection send token (CAS) plus send_busy —
 * a busy ring means the head frame may be mid-send, and interleaving into it
 * would corrupt the stream (whole frames may legally reorder, frame BYTES may
 * not).  Declining is always safe: the done epilogue queues the frame on the
 * ring exactly as before pool-send existed.
 *
 * Reports through t->pool_sent / pool_sent_all / pool_token_held /
 * pool_send_errno; on a short send within the wait budget the token is KEPT
 * (pool_token_held) so the done epilogue can park the remainder at the ring
 * HEAD before releasing it.
 */
void
brix_pgread_pool_send(brix_pgread_aio_t *t)
{
    brix_ctx_t *sec = t->sec_ctx;
    u_char       *p;
    ngx_int_t     rc;

    if (t->nread < 0) {
        return;   /* I/O error: the done handler answers on the PRIMARY
                   * control stream; the secondary wire stays untouched */
    }

    if (!ngx_atomic_cmp_set(&sec->out.send_token, 0, 1)) {
        return;   /* the event loop owns the socket — ring path serves it */
    }

    if (sec->out.send_busy) {
        /* Parked frames exist and the head one may be mid-frame: sending now
         * could interleave into it.  Decline; the ring keeps wire order. */
        sec->out.send_token = 0;
        return;
    }

    p = t->scratch - sizeof(ServerStatusResponse_pgRead);
    brix_build_pgread_status_sid(t->streamid, t->offset,
                                   (uint32_t) t->out_size, kXR_FinalResult,
                                   (ServerStatusResponse_pgRead *) p);
    t->pool_image_len = sizeof(ServerStatusResponse_pgRead) + t->out_size;
    t->pool_frames = 1;

    rc = brix_pool_send_range(t, p, t->pool_image_len);

    if (rc == NGX_OK) {
        t->pool_sent_all = 1;
        sec->out.send_token = 0;
        return;
    }

    if (rc == NGX_ERROR) {
        sec->out.send_token = 0;   /* dead socket: nothing more rides it */
        return;
    }

    /* Short send inside the wait budget: keep the token — the done epilogue
     * parks the remainder at the ring head, THEN releases it (a worker that
     * wins the token next must already see send_busy = 1). */
    t->pool_token_held = 1;
}

/* §1.3 chunk sizing: cuts land on the ABSOLUTE 4 KiB page grid (the
 * client's page accounting is grid-absolute), so a chunk runs from cur to
 * the next grid line at most BRIX_PGREAD_STREAM_CHUNK away, capped by the
 * bytes remaining. */
static size_t
brix_pgread_chunk_len(off_t cur, size_t left)
{
    off_t  grid_end;
    size_t clen;

    grid_end = (off_t) (((uint64_t) cur + (uint64_t) BRIX_PGREAD_STREAM_CHUNK)
                        & ~((uint64_t) kXR_pgPageSZ - 1));
    clen = (size_t) (grid_end - cur);
    return (clen > left) ? left : clen;
}

/* Read error inside the §1.3 chunk loop.  Wire untouched → classic error
 * shape (token released, nread = -1, not chunked; the done handler answers
 * on the PRIMARY control stream).  After a committed partial → latch
 * chunk_error so the done epilogue terminates the train with kXR_error on
 * the SECONDARY under the request sid.  Returns 1 when the caller must
 * return (classic shape), 0 when it must break out of the loop. */
static ngx_flag_t
brix_pgread_stream_read_error(brix_pgread_aio_t *t, int err)
{
    t->io_errno = err;
    if (t->pool_sent == 0) {
        t->sec_ctx->out.send_token = 0;
        t->nread = -1;
        t->pool_chunked = 0;
        return 1;
    }
    t->chunk_error = 1;
    return 0;
}

/*
 * brix_pgread_pool_stream — §1.3 chunked pgread streaming: read, CRC-encode
 * and SEND the reply as a train of kXR_PartialResult status frames (final
 * chunk kXR_FinalResult), all from THIS pool thread under one send-token
 * hold.
 *
 * WHY: with one request in flight per substream, per-request wall latency IS
 * the throughput; a monolithic frame makes the client wait the full
 * read+CRC of the request before its first byte.  Chunking overlaps the
 * client's receive+verify of chunk k with this thread's read+CRC of chunk
 * k+1 — exactly how the reference server streams ~1.4 MiB partials.
 *
 * HOW: chunk frames are laid out back-to-back in the slot buffer
 * ([hdr|enc][hdr|enc]…), so the already-parked/park-front machinery applies
 * verbatim to the image tail: t->pool_sent is a single watermark into the
 * image and a stall parks [pool_sent, pool_image_len) at the ring head.
 * Chunk cuts land on the absolute 4 KiB page grid (the client's page
 * accounting is grid-absolute); a stall stops sending but keeps BUILDING the
 * remaining chunks so the parked tail is always a complete frame train.
 * A read error before any byte hit the wire reports the classic error shape
 * (error on the PRIMARY); after a committed partial it sets t->chunk_error
 * and the done epilogue queues kXR_error on the SECONDARY under the request
 * sid, behind any parked tail.
 *
 * Returns 1 when this thread took ownership of the reply (the caller must
 * not run the classic read path), 0 when the token was unavailable — the
 * classic single-frame path serves the request unchanged.
 */
ngx_flag_t
brix_pgread_pool_stream(brix_pgread_aio_t *t)
{
    brix_ctx_t     *sec = t->sec_ctx;
    u_char         *base, *w;
    off_t             cur;
    size_t            left, clen, image;
    u_char            resptype;
    ngx_flag_t        stalled;
    ngx_int_t         rc;
    brix_vfs_job_t  job;

    if (!ngx_atomic_cmp_set(&sec->out.send_token, 0, 1)) {
        return 0;
    }

    if (sec->out.send_busy) {
        sec->out.send_token = 0;
        return 0;
    }

    t->pool_chunked = 1;
    base = t->scratch - sizeof(ServerStatusResponse_pgRead);
    w = base;
    cur = t->offset;
    left = t->rlen;
    image = 0;
    t->nread = 0;
    stalled = 0;

    while (left > 0) {
        clen = brix_pgread_chunk_len(cur, left);

        brix_vfs_job_read_init(&job, t->fd, cur, clen,
                                 w + sizeof(ServerStatusResponse_pgRead),
                                 clen, 0);
        job.op = BRIX_VFS_IO_PGREAD;
        brix_vfs_job_set_obj(&job, &t->obj);
        brix_vfs_io_execute(&job);

        if (job.nio < 0) {
            if (brix_pgread_stream_read_error(t, job.io_errno)) {
                return 1;
            }
            break;
        }

        resptype = (clen == left || (size_t) job.nio < clen)
                   ? kXR_FinalResult : kXR_PartialResult;
        brix_build_pgread_status_sid(t->streamid, (int64_t) cur,
                                       (uint32_t) job.out_size, resptype,
                                       (ServerStatusResponse_pgRead *) w);
        t->nread += job.nio;
        t->out_size += job.out_size;
        image += sizeof(ServerStatusResponse_pgRead) + job.out_size;
        t->pool_frames++;

        if (!stalled) {
            rc = brix_pool_send_range(t, base, image);
            if (rc == NGX_ERROR) {
                break;   /* socket dead: no point reading further chunks */
            }
            if (rc == NGX_AGAIN) {
                stalled = 1;   /* keep building; the done epilogue parks */
            }
        }

        if ((size_t) job.nio < clen) {
            break;   /* EOF: that frame already went out as kXR_FinalResult */
        }
        w += sizeof(ServerStatusResponse_pgRead) + job.out_size;
        cur += (off_t) clen;
        left -= clen;
    }

    t->pool_image_len = image;

    if (t->pool_send_errno != 0) {
        sec->out.send_token = 0;   /* dead socket: nothing more rides it */
        return 1;
    }

    if (t->pool_sent == image) {
        if (!t->chunk_error) {
            t->pool_sent_all = 1;
        }
        sec->out.send_token = 0;
        return 1;
    }

    /* Unsent image tail (stall, possibly plus a later chunk_error): keep the
     * token — the done epilogue parks the tail at the ring head, THEN
     * releases it (§1.2). */
    t->pool_token_held = 1;
    return 1;
}
