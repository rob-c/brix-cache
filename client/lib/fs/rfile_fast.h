/*
 * rfile_fast.h — private contract between the two halves of the fast path.
 *
 * WHAT: The ring/job/state types and the four entry points rfile_fast.c uses to
 *       drive the pipeline that lives in rfile_fast_ring.c.
 * WHY:  rfile_fast.c had grown past the size limit carrying both the session
 *       (eligibility, attach/detach, socket mode, the env tunables) and the
 *       engine (the slot ring and the fill/wait/deliver loop over it).  They
 *       share only these types, so the seam costs one header and no behaviour.
 * HOW:  Private to client/lib/fs — nothing outside the fast path includes it;
 *       the public entry point is still brix_rfile_stream_fast() in brix.h.
 */
#ifndef BRIX_CLIENT_FS_RFILE_FAST_H
#define BRIX_CLIENT_FS_RFILE_FAST_H

#include "brix.h"
#include "core/aio/aio.h"

#include <pthread.h>
#include <stdint.h>

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


/* rfile_fast_ring.c */
int fast_ring_init(fast_ring *ring, unsigned depth, uint32_t chunk, brix_status *st);
void fast_ring_free(fast_ring *ring);
int fast_run(brix_aconn *ac, const fast_job *job, fast_ring *ring,
             fast_state *state, brix_status *st);
int fast_drain(const fast_job *job, fast_ring *ring, fast_state *state);

#endif /* BRIX_CLIENT_FS_RFILE_FAST_H */
