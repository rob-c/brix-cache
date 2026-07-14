#include "core/ngx_brix_module.h"
#include "aio.h"
#include "uring.h"
#include "uring_internal.h"

#if (BRIX_HAVE_LIBURING)
#include <sys/eventfd.h>
#include <unistd.h>
#include <poll.h>

/* Budget for the startup eventfd-delivery self-test (step 4).  The NOP
 * completes in microseconds; a full second is a generous ceiling that only
 * ever expires on a kernel that does not signal the registered eventfd. */
#define BRIX_URING_EVENTFD_SELFTEST_MS  1000

/* IORING_RESTRICTION_SQE_OP is an enum value (preprocessor-invisible), so gate
 * on IORING_SETUP_R_DISABLED — a real #define that arrived alongside the
 * restrictions API (kernel 5.10 / matching liburing). */
#if defined(IORING_SETUP_R_DISABLED)
#define BRIX_URING_HAVE_RESTRICTIONS 1
#else
#define BRIX_URING_HAVE_RESTRICTIONS 0
#endif

/* Self-test sentinel — never collides with a real slot cookie (those carry a
 * slot index < queue_depth in the low 32 bits). */
#define BRIX_URING_NOP_COOKIE  0xffffffffffffffffULL
#endif

/* File: src/core/aio/uring_bringup.c — the ordered register-phase bring-up
 * steps for the per-worker io_uring ring (phase-79 split from uring.c).
 * WHAT: The six step helpers driven in order by brix_uring_init_worker()
 *       (uring.c): create+notify-wire+restrict+enable the ring, the two
 *       eventfd-delivery self-tests, the epoll bridge, and the completion-slot
 *       table allocation.  Each returns NULL on success or the failing step's
 *       name so the orchestrator's single fallback point (brix_uring_init_fail)
 *       decides NGX_OK (auto) vs NGX_ERROR (on).
 *
 * WHY:  The register-phase operations must happen in one exact order — register
 *       ops are denied once a restricted ring is enabled, and the kernel-quirk
 *       self-tests (does the registered eventfd actually deliver, even when
 *       saturated?) must run before the ring is trusted with real traffic.
 *
 * HOW:  Entirely under #if (BRIX_HAVE_LIBURING); in a stub build no ring is
 *       ever created, so none of this is reachable and the file is empty. */

#if (BRIX_HAVE_LIBURING)

#if (BRIX_URING_HAVE_RESTRICTIONS)
/*
 * brix_uring_apply_restrictions — lock the ring to the fd-only data opcodes
 * the backend actually submits (NOP for the self-test + READ/WRITE/READV/
 * WRITEV/FSYNC).  With no OPENAT/STATX/UNLINKAT allowed, the ring can neither
 * open nor traverse a path — which is what makes the unprivileged-worker
 * containment sound.  Requires the ring to have been created R_DISABLED;
 * caller enables it afterwards.  Returns NGX_OK iff restrictions were applied.
 */
static ngx_int_t
brix_uring_apply_restrictions(struct io_uring *ring)
{
    struct io_uring_restriction res[6];

    ngx_memzero(res, sizeof(res));
    res[0].opcode = IORING_RESTRICTION_SQE_OP; res[0].sqe_op = IORING_OP_NOP;
    res[1].opcode = IORING_RESTRICTION_SQE_OP; res[1].sqe_op = IORING_OP_READ;
    res[2].opcode = IORING_RESTRICTION_SQE_OP; res[2].sqe_op = IORING_OP_WRITE;
    res[3].opcode = IORING_RESTRICTION_SQE_OP; res[3].sqe_op = IORING_OP_READV;
    res[4].opcode = IORING_RESTRICTION_SQE_OP; res[4].sqe_op = IORING_OP_WRITEV;
    res[5].opcode = IORING_RESTRICTION_SQE_OP; res[5].sqe_op = IORING_OP_FSYNC;

    return io_uring_register_restrictions(ring, res, 6) == 0
           ? NGX_OK : NGX_ERROR;
}
#endif

/*
 * uring_setup_rings — create, notify-wire, restrict, and enable the ring.
 *
 * WHAT: Bring-up steps 1-3: io_uring_queue_init_params (R_DISABLED first when
 *       restricting), eventfd creation + io_uring_register_eventfd, then
 *       best-effort restrictions and ring enable.
 * WHY:  These are the register-phase operations that must happen in this
 *       exact order — register ops are denied once a restricted ring is
 *       enabled, so the eventfd registration has to precede restrict+enable.
 * HOW:  Early-returns the failing step's name for brix_uring_init_fail (the
 *       caller owns the single fallback decision), NULL on success.  Sets
 *       u->ring_active / u->eventfd / u->restrict_ops as each step lands.
 *       Non-static: driven by brix_uring_init_worker() in uring.c.
 */
const char *
uring_setup_rings(brix_uring_t *u, ngx_uint_t want_restrict)
{
    struct io_uring_params  params;

#if !(BRIX_URING_HAVE_RESTRICTIONS)
    (void) want_restrict;   /* no restrictions API in this liburing/kernel */
#endif

    /* 1. create the ring (R_DISABLED first when we will register restrictions). */
    ngx_memzero(&params, sizeof(params));
#if (BRIX_URING_HAVE_RESTRICTIONS)
    if (want_restrict) {
        params.flags |= IORING_SETUP_R_DISABLED;
    }
#endif
    if (io_uring_queue_init_params((unsigned) u->queue_depth, &u->ring,
                                   &params) < 0)
    {
        return "io_uring_queue_init_params";
    }
    u->ring_active = 1;

    /*
     * 2. Register the CQE-notifier eventfd BEFORE applying restrictions /
     * enabling the ring.  io_uring_register_eventfd is a *register* op: once the
     * ring is restricted+enabled, register ops are denied (EINVAL) unless
     * explicitly allowed, and while the ring is R_DISABLED register ops are
     * permitted — so this must happen here, not after enable.
     */
    u->eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (u->eventfd < 0) {
        return "eventfd";
    }
    if (io_uring_register_eventfd(&u->ring, u->eventfd) < 0) {
        return "io_uring_register_eventfd";
    }

    /* 3. restrictions (best-effort) then enable the ring. */
#if (BRIX_URING_HAVE_RESTRICTIONS)
    if (want_restrict) {
        if (brix_uring_apply_restrictions(&u->ring) == NGX_OK) {
            u->restrict_ops = 1;
        } else {
            ngx_log_error(NGX_LOG_NOTICE, u->log, 0,
                "brix: io_uring_register_restrictions unavailable "
                "(kernel < 5.10?); ring runs unrestricted — containment still "
                "holds via the unprivileged worker + confined fd");
        }
        if (io_uring_enable_rings(&u->ring) < 0) {
            return "io_uring_enable_rings";
        }
    }
#endif

    return NULL;
}

/*
 * uring_selftest_nop — prove submit -> complete -> eventfd delivery works.
 *
 * WHAT: Bring-up step 4: submit one NOP and require the completion to arrive
 *       via the REGISTERED EVENTFD (poll), then verify the CQE.
 * WHY:  The reaper is driven ENTIRELY by the eventfd becoming readable in the
 *       worker's epoll; a synchronous io_uring_wait_cqe here would prove the
 *       ring computes completions but NOT that this kernel signals the
 *       registered eventfd on a CQE.  Some kernels (and some restricted-ring /
 *       seccomp / virtualisation configs) support every opcode the probe
 *       checks yet never fire the eventfd — the backend then wedges silently
 *       after exactly queue_depth in-flight ops (no CQE ever reaped), which
 *       presents as a hung transfer, not an error.  Test the real delivery
 *       path here and fall back to the thread pool cleanly when it does not
 *       work.
 * HOW:  Wait on the eventfd itself (not the CQE): submit the NOP, then poll
 *       the registered eventfd — exactly what the epoll reaper relies on.
 *       Early-returns the failing step's name for brix_uring_init_fail, NULL
 *       on success.  Non-static: driven by brix_uring_init_worker() in uring.c.
 */
const char *
uring_selftest_nop(brix_uring_t *u)
{
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    struct pollfd        pfd = { .fd = u->eventfd, .events = POLLIN,
                                 .revents = 0 };
    uint64_t             counter;
    ssize_t              rn;
    int                  pr;

    sqe = io_uring_get_sqe(&u->ring);
    if (sqe == NULL) {
        return "io_uring_get_sqe(NOP)";
    }
    io_uring_prep_nop(sqe);
    io_uring_sqe_set_data64(sqe, BRIX_URING_NOP_COOKIE);
    if (io_uring_submit(&u->ring) < 0) {
        return "io_uring NOP submit";
    }

    do {
        pr = poll(&pfd, 1, BRIX_URING_EVENTFD_SELFTEST_MS);
    } while (pr < 0 && errno == EINTR);

    if (pr <= 0) {
        /* The kernel accepted the NOP but never signalled the registered
         * eventfd — the reaper would never run.  Fall back to the pool. */
        return "io_uring eventfd delivery self-test (kernel does not signal "
               "the registered eventfd on completion — using the thread pool; "
               "set brix_io_uring off to silence, or use a kernel whose "
               "io_uring delivers registered-eventfd notifications)";
    }

    rn = read(u->eventfd, &counter, sizeof(counter));
    (void) rn;                       /* clear the signal; value unused */

    if (io_uring_peek_cqe(&u->ring, &cqe) < 0) {
        return "io_uring NOP self-test (eventfd fired, no CQE)";
    }
    if (io_uring_cqe_get_data64(cqe) != BRIX_URING_NOP_COOKIE
        || cqe->res != 0)
    {
        io_uring_cqe_seen(&u->ring, cqe);
        return "io_uring NOP self-test (unexpected CQE)";
    }
    io_uring_cqe_seen(&u->ring, cqe);

    return NULL;
}

/*
 * uring_selftest_burst — UNDER-LOAD delivery self-test.
 *
 * WHAT: Bring-up step 4b: fill the ring with queue_depth NOPs and require
 *       EVERY completion to arrive via the eventfd within the deadline.
 * WHY:  A single NOP passing does not prove the backend is usable: on some
 *       kernels the registered eventfd signals the FIRST completion but stops
 *       signalling once the ring is saturated, so a real transfer wedges
 *       after exactly queue_depth in-flight ops (256 x 32 KiB = 8 MiB) with a
 *       worker spinning on an eventfd that never fires again — and any op
 *       still in flight at teardown becomes a late-CQE use-after-free.
 * HOW:  Reproduce that saturation here (a burst of NOPs) and drain it exactly
 *       as the reaper would (poll eventfd -> read counter -> peek all CQEs);
 *       if the full burst does not drain in time, this kernel cannot be
 *       trusted with the backend.  Early-returns the failing step's name for
 *       brix_uring_init_fail, NULL on success.  Non-static: driven by
 *       brix_uring_init_worker() in uring.c.
 */
const char *
uring_selftest_burst(brix_uring_t *u)
{
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    uint32_t             want = u->queue_depth;
    uint32_t             got  = 0;
    uint64_t             deadline_ms = BRIX_URING_EVENTFD_SELFTEST_MS;
    uint32_t             i;

    for (i = 0; i < want; i++) {
        sqe = io_uring_get_sqe(&u->ring);
        if (sqe == NULL) {           /* ring smaller than want: submit what fit */
            want = i;
            break;
        }
        io_uring_prep_nop(sqe);
        io_uring_sqe_set_data64(sqe, BRIX_URING_NOP_COOKIE);
    }
    if (want > 0 && io_uring_submit(&u->ring) < 0) {
        return "io_uring burst self-test submit";
    }
    while (got < want) {
        struct pollfd  pfd = { .fd = u->eventfd, .events = POLLIN, .revents = 0 };
        uint64_t       counter;
        ssize_t        rn;
        int            pr;

        do {
            pr = poll(&pfd, 1, (int) deadline_ms);
        } while (pr < 0 && errno == EINTR);
        if (pr <= 0) {
            return "io_uring under-load delivery self-test (kernel stops "
                   "signalling the registered eventfd once the ring is "
                   "saturated — the backend would wedge after queue_depth "
                   "in-flight ops; using the thread pool)";
        }
        rn = read(u->eventfd, &counter, sizeof(counter));
        (void) rn;                   /* edge cleared; count the actual CQEs */
        while (got < want && io_uring_peek_cqe(&u->ring, &cqe) == 0) {
            io_uring_cqe_seen(&u->ring, cqe);
            got++;
        }
    }

    return NULL;
}

/*
 * uring_install_eventfd — bridge the ring's eventfd into the worker's epoll.
 *
 * WHAT: Bring-up step 5: wrap the registered eventfd in a fake nginx
 *       connection whose read handler is the completion reaper, and add it to
 *       the event loop.
 * WHY:  nginx has no native io_uring integration; the fake-connection bridge
 *       is the same pattern core uses for the libaio eventfd, so completions
 *       wake the worker exactly like socket readability.
 * HOW:  ngx_get_connection on the eventfd, wire handler/log/data, then
 *       ngx_add_event.  Early-returns the failing step's name for
 *       brix_uring_init_fail, NULL on success.  Non-static: driven by
 *       brix_uring_init_worker() in uring.c.
 */
const char *
uring_install_eventfd(brix_uring_t *u, ngx_cycle_t *cycle)
{
    ngx_connection_t *evc;

    evc = ngx_get_connection(u->eventfd, cycle->log);
    if (evc == NULL) {
        return "ngx_get_connection";
    }
    evc->read->handler = brix_uring_eventfd_handler;
    evc->read->log     = cycle->log;
    evc->data          = u;
    u->evc             = evc;
    if (ngx_add_event(evc->read, NGX_READ_EVENT, 0) != NGX_OK) {
        return "ngx_add_event";
    }

    return NULL;
}

/*
 * uring_register_buffers — allocate the completion-slot table.
 *
 * WHAT: Bring-up step 6: the queue_depth-sized slot table that maps CQE
 *       cookies back to in-flight tasks (the UAF-safe generation scheme).
 * WHY:  Slots are the only per-op state the reaper trusts; they must exist
 *       before the first submission and live as long as the worker.
 * HOW:  ngx_pcalloc from the cycle pool (freed with the cycle — never
 *       manually).  Early-returns the failing step's name for
 *       brix_uring_init_fail, NULL on success.  Non-static: driven by
 *       brix_uring_init_worker() in uring.c.
 */
const char *
uring_register_buffers(brix_uring_t *u, ngx_cycle_t *cycle)
{
    u->slots = ngx_pcalloc(cycle->pool,
                           u->queue_depth * sizeof(brix_uring_slot_t));
    if (u->slots == NULL) {
        return "slot table alloc";
    }

    return NULL;
}

#endif /* BRIX_HAVE_LIBURING */
