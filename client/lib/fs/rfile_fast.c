/*
 * rfile_fast.c — pipelined (many-reads-in-flight) fast path for brix_rfile.
 *
 * WHAT: brix_rfile_stream_fast() streams a byte range of an already-open
 *       resilient file to a brix_rfile_sink_fn while keeping several kXR_read
 *       requests in flight on ONE connection, delivering the chunks to the sink
 *       in strict file order.  It returns 0 (range complete / EOF / sink asked
 *       to stop), BRIX_RFILE_FAST_OFF (nothing was attempted — the caller must
 *       run its ordinary serial loop), or -1 with *moved holding the bytes that
 *       WERE delivered, so the caller resumes serially from there.
 * WHY:  the serial pump (brix_rfile_pump / transfer_pump) issues exactly one
 *       kXR_read and then blocks on the reply, so the link idles for a whole
 *       round trip per chunk and the sink write never overlaps the next read.
 *       On a fast link that is the single largest cost in the client.  Keeping
 *       N reads outstanding hides both the RTT and the server's per-request
 *       work, which is what every other fast XRootD client does.
 * HOW:  the existing async transport core (core/aio) already owns an epoll loop
 *       that pipelines many requests over one socket and demultiplexes replies
 *       by streamid — this file only drives it.  The connection is handed to a
 *       loop with brix_aconn_attach, a ring of `depth` slots each carries one
 *       outstanding kXR_read, the loop thread parks each reply in its slot and
 *       signals, and the calling thread consumes slots strictly in ring order.
 *       On teardown the connection is detached and its fd put back in blocking
 *       mode so the ordinary synchronous helpers own it again.
 *
 * Fallback: a connection with GSI request signing active cannot go async (see
 * core/aio/aio.h), and paged/inline-compressed reads have their own framing —
 * all three return BRIX_RFILE_FAST_OFF so the serial path handles them.
 *
 * This file is the session around the pipeline: eligibility, the env tunables,
 * attach/detach and the socket's blocking mode.  The ring and the fill → wait →
 * deliver loop over it are in rfile_fast_ring.c, behind rfile_fast.h.
 */
#include "brix.h"
#include "rfile_fast.h"
#include "brix_ops.h"
#include "core/aio/aio.h"
#include "protocols/root/protocol/protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Per-request read size and how many of them ride the wire at once.  4 MiB × 4
 * keeps ~16 MiB outstanding: enough to cover a LAN round trip plus the server's
 * page-cache read at multi-GiB/s, while staying small enough that a chunk is
 * handed to the sink long before the whole file is buffered. */
#define FAST_CHUNK_DEFAULT (4u * 1024u * 1024u)
#define FAST_CHUNK_MIN     (64u * 1024u)
#define FAST_CHUNK_MAX     (32u * 1024u * 1024u)
#define FAST_DEPTH_DEFAULT 4u
#define FAST_DEPTH_MAX     32u


/* ---- Read an unsigned tunable from the environment ----
 *
 * WHAT: Returns the value of environment variable `name` clamped to
 *       [lo, hi], or `dflt` when it is unset, empty or unparseable.
 *
 * WHY:  The chunk size and pipeline depth are the two knobs whose best value
 *       depends on the link (RTT × bandwidth) and on the server's read-ahead.
 *       Exposing them as environment overrides lets a deployment tune without a
 *       rebuild, while the clamp keeps a typo from asking for a 4 GiB request.
 *
 * HOW:  1. getenv; return dflt when absent or empty.
 *       2. strtoul; return dflt when nothing was consumed.
 *       3. Clamp into [lo, hi] and return.
 */
static unsigned
fast_env_u(const char *name, unsigned dflt, unsigned lo, unsigned hi)
{
    const char   *text = getenv(name);
    char         *end = NULL;
    unsigned long value;

    if (text == NULL || text[0] == '\0') {
        return dflt;
    }
    value = strtoul(text, &end, 10);
    if (end == text) {
        return dflt;
    }
    if (value < (unsigned long) lo) {
        return lo;
    }
    if (value > (unsigned long) hi) {
        return hi;
    }
    return (unsigned) value;
}


/* ---- One line of pipeline diagnostics, when asked for ----
 *
 * WHAT: Writes "brix pipeline: <what> ..." to stderr when $XRDC_PIPELINE_TRACE
 *       is set, and nothing otherwise.
 *
 * WHY:  Whether a given transfer took the pipelined path — and with what depth
 *       and chunk, or for what reason it declined — is invisible from the
 *       outside: both paths produce identical bytes. A single opt-in line turns
 *       "is the fast path even running?" from a rebuild into one run, which is
 *       exactly the question every throughput investigation starts with.
 *
 * HOW:  getenv guard, then fprintf; `detail` is a number whose meaning depends
 *       on `what` (bytes, depth, or the status code that declined it).
 */
static void
fast_trace(const char *what, long long a, long long b)
{
    if (getenv("XRDC_PIPELINE_TRACE") != NULL) {
        fprintf(stderr, "brix pipeline: %s %lld %lld\n", what, a, b);
    }
}




/* ---- Poison a session that is no longer frame-aligned ----
 *
 * WHAT: Shuts the socket down in both directions, ignoring failures.
 *
 * WHY:  When the pipelined reader has to abandon requests whose replies are
 *       still on the wire, the next synchronous read would take those bytes for
 *       the answer to its own request — silent cross-talk, and with a hostile or
 *       merely confused peer a frame boundary the caller never validated. There
 *       is no way to re-synchronise a stream whose remaining length is unknown,
 *       so the only safe move is to make the session unusable: every later
 *       operation then fails with an ordinary transport error, which is exactly
 *       what the serial pump's reconnect+reopen+resume loop already handles.
 *
 * HOW:  shutdown(2) both directions; a negative fd is a no-op. The fd itself is
 *       left open — the connection is the caller's to close or reconnect.
 */
static void
fast_poison_session(int fd)
{
    if (fd >= 0) {
        (void) shutdown(fd, SHUT_RDWR);
    }
}


/* ---- Put a socket back into blocking mode ----
 *
 * WHAT: Clears O_NONBLOCK on `fd`, ignoring failures.
 *
 * WHY:  brix_aconn_attach switches the connection's fd to non-blocking and owns
 *       it for as long as it is attached; the synchronous helpers that run
 *       afterwards (close, checksum query, the serial resume pump) assume a
 *       blocking socket.  Restoring the flag at exactly one place — the fast
 *       path's teardown — keeps that contract local to the code that broke it.
 *
 * HOW:  F_GETFL then F_SETFL without O_NONBLOCK; a negative fd is a no-op.
 */
static void
fast_restore_blocking(int fd)
{
    int flags;

    if (fd < 0) {
        return;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        (void) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }
}


/* ---- Is this file eligible for the pipelined path? ----
 *
 * WHAT: Returns 1 when `rf` is a plain (non-paged, non-compressed) read handle
 *       on a live connection, 0 otherwise.
 *
 * WHY:  kXR_pgread replies use kXR_status framing with per-page CRC32c and
 *       inline-compressed reads arrive as codec frames; both are decoded by
 *       their own synchronous readers, not by the generic reply path this file
 *       drives.  Rather than duplicate that decoding, those handles keep the
 *       serial pump — correctness first, speed only where it is free.
 *
 * HOW:  Require a connection, pgrw == 0 and a zero read_codec.
 */
static int
fast_eligible(const brix_rfile *rf)
{
    return rf != NULL && rf->c != NULL && rf->pgrw == 0
           && rf->f.read_codec == 0;
}


/* ---- Stream a range with several reads in flight ----
 *
 * WHAT: Public entry point.  Streams [offset, offset+limit) (or to EOF when
 *       limit < 0) of the open resilient file `rf` to `sink`, keeping several
 *       kXR_reads outstanding.  Returns 0 on a complete range / EOF / sink stop,
 *       BRIX_RFILE_FAST_OFF when the fast path was not attempted at all, or -1
 *       with *st set.  *moved (never NULL-checked away) always reports the bytes
 *       actually delivered, so a caller can resume serially after a failure.
 *
 * WHY:  The serial pump leaves one request on the wire at a time; this is the
 *       whole point of the file (see the header block).  Returning the partial
 *       progress instead of retrying internally is deliberate: the serial pump
 *       already owns reconnect + reopen + adaptive shrink, so the fast path
 *       stays a pure accelerator and there is exactly one retry policy.
 *
 * HOW:  1. Reject ineligible handles and zero-length ranges up front.
 *       2. Create a loop and attach the connection (signing-active connections
 *          are refused here — that is the documented async limitation).
 *       3. Size the ring, run the pipeline, then close the aconn (which fails
 *          anything still outstanding) and destroy the loop.
 *       4. Restore blocking mode, sweep the ring, report moved + rc.
 */
int
brix_rfile_stream_fast(brix_rfile *rf, int64_t offset, int64_t limit,
                       brix_rfile_sink_fn sink, void *arg, int64_t *moved,
                       brix_status *st)
{
    brix_loop  *loop;
    brix_aconn *ac;
    fast_ring   ring;
    fast_state  state;
    fast_job    job;
    int         rc;
    int         fd;
    int         aligned;

    if (moved != NULL) {
        *moved = 0;
    }
    if (!fast_eligible(rf) || sink == NULL || offset < 0 || limit == 0
        || fast_env_u("XRDC_PIPELINE", 1, 0, 1) == 0) {
        fast_trace("off (ineligible) pgrw/codec", rf ? rf->pgrw : -1,
                   rf ? rf->f.read_codec : -1);
        return BRIX_RFILE_FAST_OFF;
    }

    memset(&job, 0, sizeof(job));
    job.rf          = rf;
    job.sink        = sink;
    job.arg         = arg;
    job.offset      = offset;
    job.limit       = limit;
    job.chunk       = fast_env_u("XRDC_PIPELINE_CHUNK", FAST_CHUNK_DEFAULT,
                                 FAST_CHUNK_MIN, FAST_CHUNK_MAX);
    job.depth       = fast_env_u("XRDC_PIPELINE_DEPTH", FAST_DEPTH_DEFAULT,
                                 1, FAST_DEPTH_MAX);
    job.deadline_ms = rf->max_stall_ms;

    loop = brix_loop_create(st);
    if (loop == NULL) {
        fast_trace("off (no loop)", 0, 0);
        brix_status_clear(st);
        return BRIX_RFILE_FAST_OFF;
    }
    fd = rf->c->io.fd;
    ac = brix_aconn_attach(loop, rf->c, st);
    if (ac == NULL) {
        fast_trace("off (attach refused)", 0, 0);
        brix_loop_destroy(loop);
        brix_status_clear(st);
        return BRIX_RFILE_FAST_OFF;
    }
    if (fast_ring_init(&ring, job.depth, job.chunk, st) != 0) {
        brix_aconn_close(ac);
        brix_loop_destroy(loop);
        fast_restore_blocking(fd);
        return -1;
    }

    fast_trace("on depth/chunk", (long long) job.depth, (long long) job.chunk);
    memset(&state, 0, sizeof(state));
    rc = fast_run(ac, &job, &ring, &state, st);
    /* Only a clean finish can leave the socket frame-aligned; on any failure the
     * still-outstanding replies are abandoned in the pipe (see fast_drain). */
    aligned = (rc == 0) ? fast_drain(&job, &ring, &state) : 0;

    brix_aconn_close(ac);     /* synchronous: fails every still-open request */
    brix_loop_destroy(loop);
    fast_restore_blocking(fd);
    fast_ring_free(&ring);

    if (!aligned) {
        fast_poison_session(fd);   /* replies still in flight: never read them */
    }
    fast_trace("done rc/moved", (long long) rc, (long long) state.moved);
    if (moved != NULL) {
        *moved = state.moved;
    }
    return rc;
}
