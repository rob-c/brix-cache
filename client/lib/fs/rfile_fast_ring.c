/*
 * rfile_fast_ring.c — the slot ring and the pipeline that drives it.
 *
 * WHAT: Everything between "a request is submitted" and "its bytes reach the
 *       sink": the completion callback the loop thread parks replies with,
 *       kXR_read submission, the fill -> wait -> deliver loop, the drain that
 *       consumes replies still on the wire after an abort, and the ring's own
 *       allocation and release.
 * WHY:  Split out of rfile_fast.c, which had grown past the size limit holding
 *       both this and the session around it (eligibility, attach/detach, socket
 *       mode, the env tunables).  The session half now reaches the engine only
 *       through the four entry points in rfile_fast.h - behaviour-identical.
 * HOW:  The calling thread owns ring order strictly: it submits at `tail`,
 *       consumes at `head`, and the loop thread only ever writes the slot it
 *       was handed.  All shared state changes under ring->lock with a
 *       broadcast on ring->cv.
 */
#include "rfile_fast.h"

#include "brix_ops.h"
#include "protocols/root/protocol/protocol.h"

#include <arpa/inet.h>   /* htons, for the request header this file builds */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


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
int
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
int
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
int
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
void
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
