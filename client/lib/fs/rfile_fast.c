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
 */
#include "brix.h"
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

/* Slot lifecycle: IDLE (no request) → BUSY (submitted) → READY (reply parked by
 * the loop thread) → IDLE again once the calling thread has drained it. */
enum { FAST_SLOT_IDLE = 0, FAST_SLOT_BUSY, FAST_SLOT_READY };

typedef struct fast_ring fast_ring;

/* One outstanding kXR_read plus the reply the loop thread parks in it.  `buf`
 * is the slot's own landing buffer: the engine reads the reply body straight
 * into it (brix_aio_opts.dst), so a byte is copied out of the socket once and
 * then handed to the sink — no per-chunk malloc and no intermediate staging. */
typedef struct {
    fast_ring  *ring;      /* owner, for lock/condvar (set once at init) */
    uint8_t    *buf;       /* landing buffer, `chunk` bytes, owned by the ring */
    int64_t     offset;    /* absolute file offset this request covers */
    uint32_t    want;      /* bytes requested */
    uint32_t    blen;      /* bytes the reply actually delivered into buf */
    int         state;     /* FAST_SLOT_* */
    int         failed;    /* 1 ⇒ st below explains why */
    brix_status st;
} fast_slot;

struct fast_ring {
    pthread_mutex_t lock;
    pthread_cond_t  cv;
    fast_slot      *slots;
    unsigned        depth;
    uint8_t        *pool;   /* depth × chunk bytes, carved into the slots */
};

/* The immutable description of one pipelined stream, bundled so the driver
 * helpers stay under the five-parameter gate. */
typedef struct {
    brix_rfile        *rf;
    brix_rfile_sink_fn sink;
    void              *arg;
    int64_t            offset;      /* first byte of the range */
    int64_t            limit;       /* bytes to stream, or -1 = to EOF */
    uint32_t           chunk;
    unsigned           depth;
    int                deadline_ms;
} fast_job;

/* Mutable progress of one pipelined stream. */
typedef struct {
    int64_t  issued;   /* bytes covered by requests already submitted */
    int64_t  moved;    /* bytes handed to the sink */
    unsigned head;     /* ring index of the next chunk to deliver */
    unsigned tail;     /* ring index of the next chunk to submit */
    unsigned inflight; /* slots between head and tail */
    int      eof;      /* a short reply proved end-of-file */
    int      stop;     /* the sink asked to stop (success) */
    int      rc;       /* 0 so far, -1 once *st is set */
} fast_state;


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


/* ---- Completion callback: park one reply in its slot ----
 *
 * WHAT: Records the reply length (or the failure) for the slot this request was
 *       submitted against, marks it READY and wakes the consuming thread.  The
 *       bytes are already in slot->buf — the engine read them there — so `body`
 *       aliases it and is never freed.
 *
 * WHY:  The async engine invokes this inline on its loop thread, so it must not
 *       block or do I/O — parking the pointer and signalling is the whole job.
 *       Any status other than a plain kXR_ok (redirect, wait, authmore) belongs
 *       to the synchronous roundtrip layer, not here, so it is recorded as a
 *       failure and the caller falls back rather than mis-framing the stream.
 *
 * HOW:  1. Take the ring lock.
 *       2. Store body/blen; on rc != 0 copy the transport status, on an
 *          unexpected kXR_* build one.
 *       3. Mark the slot READY, broadcast, unlock.
 */
static void
fast_on_reply(void *ctx, int rc, uint16_t kxr, uint8_t *body, uint32_t blen,
              const brix_status *st)
{
    fast_slot *slot = (fast_slot *) ctx;
    fast_ring *ring = slot->ring;

    (void) body;   /* aliases slot->buf: the engine wrote straight into it */
    pthread_mutex_lock(&ring->lock);
    slot->blen   = blen;
    slot->failed = 0;
    if (rc != 0) {
        slot->failed = 1;
        if (st != NULL) {
            slot->st = *st;
        } else {
            brix_status_set(&slot->st, XRDC_ESOCK, 0, "pipelined read failed");
        }
    } else if (kxr != kXR_ok) {
        slot->failed = 1;
        brix_status_set(&slot->st, XRDC_EPROTO, 0,
                        "unexpected read reply status %u", (unsigned) kxr);
    }
    slot->state = FAST_SLOT_READY;
    pthread_cond_broadcast(&ring->cv);
    pthread_mutex_unlock(&ring->lock);
}


/* ---- Submit one kXR_read for a slot ----
 *
 * WHAT: Builds the 24-byte kXR_read request for [slot->offset, +slot->want)
 *       against `fhandle` and hands it to the async engine with fast_on_reply
 *       bound to `slot`.  Returns 0 (queued) or -1 (st set, slot left IDLE).
 *
 * WHY:  kXR_read is self-addressing (fhandle + offset + length), so a reply can
 *       be matched purely by streamid and the requests need no ordering on the
 *       wire — that is exactly what lets several ride at once.  Requests are NOT
 *       marked retry_safe: they are handle-bound, so a transparent re-issue
 *       after a reconnect would quote a dead fhandle.
 *
 * HOW:  1. Zero a ClientReadRequest, set requestid = kXR_read.
 *       2. Pack fhandle/offset/rlen into its body with the shared packer.
 *       3. Reset the slot's reply fields, mark it BUSY and submit.
 */
static int
fast_submit(brix_aconn *ac, const uint8_t *fhandle, fast_slot *slot,
            int deadline_ms, brix_status *st)
{
    ClientReadRequest req;
    xrdw_read_req_t   body = { .offset = slot->offset,
                               .rlen   = (int32_t) slot->want };
    brix_aio_opts     opts = { deadline_ms, -1, 0, slot->buf, slot->want };

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_read);
    memcpy(body.fhandle, fhandle, XRD_FHANDLE_LEN);
    xrdw_read_req_pack(&body, ((ClientRequestHdr *) &req)->body);

    slot->blen   = 0;
    slot->failed = 0;
    slot->state  = FAST_SLOT_BUSY;
    if (brix_aio_submit_ex(ac, &req, NULL, 0, &opts, fast_on_reply, slot,
                           st) != 0) {
        slot->state = FAST_SLOT_IDLE;
        return -1;
    }
    return 0;
}


/* ---- Bytes of the requested range still unrequested ----
 *
 * WHAT: Returns how many bytes of the job's range have not yet been covered by
 *       a submitted request — LLONG-large for an EOF-driven (limit < 0) job.
 *
 * WHY:  The fill loop needs one predicate for both the sized case (stop exactly
 *       at limit) and the EOF-driven case (keep reading past the end and let a
 *       short reply prove EOF), and expressing "unbounded" as a huge remainder
 *       keeps that loop free of a second branch.
 *
 * HOW:  limit < 0 → INT64_MAX; else limit - issued clamped at 0.
 */
static int64_t
fast_remaining(const fast_job *job, int64_t issued)
{
    if (job->limit < 0) {
        return INT64_MAX;
    }
    return (issued >= job->limit) ? 0 : job->limit - issued;
}


/* ---- Keep the pipeline full ----
 *
 * WHAT: Submits reads into free ring slots until `depth` are outstanding, the
 *       range is fully requested, or EOF was proven.  Returns 0, or -1 with
 *       *st set when a submit failed.
 *
 * WHY:  Refilling from the same place that primes the ring keeps exactly one
 *       copy of the "next offset, next slot" arithmetic, so a chunk can never be
 *       issued twice or skipped — the ordering the in-order delivery depends on.
 *
 * HOW:  While there is room and work: size the chunk against the remainder,
 *       fill the tail slot's offset/want, submit, advance issued/tail/inflight.
 */
static int
fast_fill(brix_aconn *ac, const fast_job *job, fast_ring *ring,
          fast_state *state, brix_status *st)
{
    const uint8_t *fhandle = job->rf->f.fhandle;

    while (state->inflight < job->depth && !state->eof) {
        int64_t    left = fast_remaining(job, state->issued);
        fast_slot *slot = &ring->slots[state->tail];

        if (left <= 0) {
            return 0;
        }
        slot->offset = job->offset + state->issued;
        slot->want   = (left < (int64_t) job->chunk) ? (uint32_t) left
                                                     : job->chunk;
        if (fast_submit(ac, fhandle, slot, job->deadline_ms, st) != 0) {
            return -1;
        }
        state->issued  += slot->want;
        state->tail     = (state->tail + 1) % job->depth;
        state->inflight += 1;
    }
    return 0;
}


/* ---- Wait until the head slot's reply has arrived ----
 *
 * WHAT: Blocks the calling thread until the slot at `index` is READY, then
 *       returns it.  Never fails: every submitted request completes exactly
 *       once, including with an error when the connection is torn down.
 *
 * WHY:  Delivery must be in file order even though replies may complete in any
 *       order, so the consumer always waits for one specific slot rather than
 *       "any completion" — that single rule is what keeps the sink seeing a
 *       strictly ascending, gap-free byte stream.
 *
 * HOW:  Take the lock, cond_wait while the state is not READY, unlock, return.
 */
static fast_slot *
fast_wait_head(fast_ring *ring, unsigned index)
{
    fast_slot *slot = &ring->slots[index];

    pthread_mutex_lock(&ring->lock);
    while (slot->state != FAST_SLOT_READY) {
        pthread_cond_wait(&ring->cv, &ring->lock);
    }
    pthread_mutex_unlock(&ring->lock);
    return slot;
}


/* ---- Hand one completed slot to the sink ----
 *
 * WHAT: Validates and delivers the head slot's reply, frees its body and
 *       returns the slot to IDLE.  Updates state->moved / eof / stop / rc and
 *       sets *st on failure.
 *
 * WHY:  This is the only place a byte leaves the pipeline, so the short-reply
 *       EOF rule, the over-long-reply guard and the sink's stop/fail contract
 *       all live together where they can be read as one policy.
 *
 * HOW:  1. A failed slot copies its status and fails the stream.
 *       2. blen > want is a protocol violation (a server returning more than
 *          asked) and fails the stream.
 *       3. blen < want proves EOF; blen > 0 is passed to the sink.
 *       4. A positive sink return stops the stream successfully, a negative one
 *          fails it (the sink set *st).
 */
static void
fast_deliver(const fast_job *job, fast_slot *slot, fast_state *state,
             brix_status *st)
{
    int sink_rc = 0;

    if (slot->failed) {
        *st = slot->st;
        state->rc = -1;
    } else if (slot->blen > slot->want) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "read returned more than requested (%u > %u)",
                        slot->blen, slot->want);
        state->rc = -1;
    } else {
        if (slot->blen < slot->want) {
            state->eof = 1;
        }
        if (slot->blen > 0) {
            sink_rc = job->sink(slot->buf, slot->blen, slot->offset,
                                job->arg, st);
            state->moved += slot->blen;
        }
        if (sink_rc < 0) {
            state->rc = -1;
        } else if (sink_rc > 0) {
            state->stop = 1;
        }
    }
    slot->blen  = 0;
    slot->state = FAST_SLOT_IDLE;
}


/* ---- Drive the pipeline to completion ----
 *
 * WHAT: Runs fill → wait → deliver until the range is done, EOF is proven, the
 *       sink stops it, the operator cancels, or a failure sets *st.  Returns 0
 *       or -1; state->moved always holds the bytes delivered.
 *
 * WHY:  Keeping the loop itself tiny (four named steps) is what lets the
 *       ordering invariant — deliver slot `head`, then advance — be checked by
 *       eye; every other concern is in one of the helpers it calls.
 *
 * HOW:  1. Honour the file's cancel predicate between chunks.
 *       2. Refill the pipeline; stop when nothing is outstanding.
 *       3. Wait for the head slot, deliver it, advance head, drop inflight.
 */
static int
fast_run(brix_aconn *ac, const fast_job *job, fast_ring *ring,
         fast_state *state, brix_status *st)
{
    brix_rfile *rf = job->rf;

    while (state->rc == 0 && !state->stop) {
        if (rf->cancel != NULL && rf->cancel()) {
            brix_status_set(st, XRDC_EUSAGE, ECANCELED, "transfer canceled");
            return -1;
        }
        if (fast_fill(ac, job, ring, state, st) != 0) {
            return -1;
        }
        if (state->inflight == 0) {
            return 0;
        }
        fast_deliver(job, fast_wait_head(ring, state->head), state, st);
        state->head      = (state->head + 1) % job->depth;
        state->inflight -= 1;
    }
    return state->rc;
}


/* ---- Consume the replies still on the wire ----
 *
 * WHAT: Waits for and discards every still-outstanding reply, returning 1 when
 *       they all arrived cleanly and 0 when any of them failed.
 *
 * WHY:  The connection is handed back to the SYNCHRONOUS helpers (close, a
 *       checksum query, the serial resume pump) the moment this file is done
 *       with it, and those read the socket frame by frame with no streamid
 *       demultiplexing.  A reply still in the pipe would be read as the answer
 *       to the next request and corrupt the session, so a stream that ends while
 *       requests are outstanding (EOF proven early, or the sink asking to stop)
 *       must first pull those replies off the wire.  A failed reply means the
 *       alignment is already lost, which the caller repairs by reopening.
 *
 * HOW:  Walk the ring from head, waiting for each slot, freeing its body and
 *       returning it to IDLE until nothing is in flight.
 */
static int
fast_drain(const fast_job *job, fast_ring *ring, fast_state *state)
{
    int clean = 1;

    while (state->inflight > 0) {
        fast_slot *slot = fast_wait_head(ring, state->head);

        if (slot->failed) {
            clean = 0;
        }
        slot->blen  = 0;
        slot->state = FAST_SLOT_IDLE;
        state->head      = (state->head + 1) % job->depth;
        state->inflight -= 1;
    }
    return clean;
}


/* ---- Allocate and initialise the slot ring ----
 *
 * WHAT: Allocates `depth` zeroed slots plus their mutex/condvar, each slot
 *       pointing back at the ring.  Returns 0 or -1 (st set).
 *
 * WHY:  Every slot must know its ring before any request is submitted, because
 *       the loop thread reaches the lock only through the slot it was handed.
 *
 * HOW:  calloc the slots, init the mutex and condvar, back-link each slot.
 */
static int
fast_ring_init(fast_ring *ring, unsigned depth, uint32_t chunk, brix_status *st)
{
    unsigned i;

    ring->slots = (fast_slot *) calloc(depth, sizeof(*ring->slots));
    ring->pool  = (uint8_t *) malloc((size_t) depth * chunk);
    if (ring->slots == NULL || ring->pool == NULL) {
        free(ring->slots);
        free(ring->pool);
        ring->slots = NULL;
        ring->pool  = NULL;
        brix_status_set(st, XRDC_EIO, ENOMEM, "pipelined read: out of memory");
        return -1;
    }
    ring->depth = depth;
    pthread_mutex_init(&ring->lock, NULL);
    pthread_cond_init(&ring->cv, NULL);
    for (i = 0; i < depth; i++) {
        ring->slots[i].ring = ring;
        ring->slots[i].buf  = ring->pool + (size_t) i * chunk;
    }
    return 0;
}


/* ---- Release the ring ----
 *
 * WHAT: Frees the slot array, the landing-buffer pool and the synchronisation
 *       primitives.
 *
 * WHY:  The slot buffers are the landing zone the async engine writes replies
 *       into, so they MUST outlive every outstanding request: call this only
 *       after the aconn is closed, when no callback can still be running.
 *
 * HOW:  Destroy the condvar + mutex, then free the slot array and the pool.
 */
static void
fast_ring_free(fast_ring *ring)
{
    pthread_cond_destroy(&ring->cv);
    pthread_mutex_destroy(&ring->lock);
    free(ring->slots);
    free(ring->pool);
    ring->slots = NULL;
    ring->pool  = NULL;
    ring->depth = 0;
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
