#include "core/ngx_brix_module.h"
#include "aio.h"
#include "uring.h"

#if (BRIX_HAVE_LIBURING)
#include <sys/eventfd.h>
#include <unistd.h>
#include <poll.h>

/* Budget for the startup eventfd-delivery self-test (step 4).  The NOP
 * completes in microseconds; a full second is a generous ceiling that only
 * ever expires on a kernel that does not signal the registered eventfd. */
#define BRIX_URING_EVENTFD_SELFTEST_MS  1000
#endif

/* File: src/aio/uring.c — optional io_uring disk-I/O backend (Phase 44)
 * WHAT: Implements the runtime capability probe, the §32 startup fail-fast
 *       validator, and the per-worker ring lifecycle for the optional io_uring
 *       disk-I/O backend.  Submission and completion live in uring_submit.c
 *       (SB-W3/W4); this TU owns detection, gating, and the ring singleton.
 *
 * WHY:  The backend must be invisible unless explicitly built (pkg-config
 *       liburing) and runtime-available (opcode probe).  `auto`/`off` always
 *       start and silently fall back; `on` is a hard requirement that fails
 *       startup when it cannot be provided — caught at config time so even a
 *       stub build flags it under `nginx -t` with no kernel needed.
 *
 * HOW:  All liburing-specific code is under #if (BRIX_HAVE_LIBURING).  When
 *       the macro is undefined the file compiles to inert stubs that report the
 *       backend as unavailable and hard-fail any `brix_io_uring on` block. */

/*
 * brix_uring_any_block_on — scan all stream server blocks for a block whose
 * merged io_uring mode is ON.
 *
 * Returns 1 if at least one enabled block requires io_uring, 0 otherwise.
 */
static ngx_int_t
brix_uring_any_block_on(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                     i;

    cmcf  = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    if (cmcf == NULL) {
        return 0;
    }

    cscfp = cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                  ngx_stream_brix_module);
        if (xcf->common.enable && xcf->io_uring == BRIX_IO_URING_ON) {
            return 1;
        }
    }

    return 0;
}

#if (BRIX_HAVE_LIBURING)

/* The per-worker ring singleton.  File-static — reached only via the accessor
 * below, never as an exported global.  Zeroed at process start; .enabled stays
 * 0 until brix_uring_init_worker() brings the ring up (SB-W2). */
static brix_uring_t  brix_uring_worker_ring;

brix_uring_t *
brix_uring_worker(void)
{
    return brix_uring_worker_ring.enabled ? &brix_uring_worker_ring : NULL;
}

/*
 * brix_uring_runtime_available — authoritative, memoized opcode probe.
 *
 * Stands up a throwaway 8-entry ring, asks io_uring_get_probe whether every
 * required server data opcode (READ/WRITE/READV/WRITEV/FSYNC) is supported,
 * tears it down, and caches the verdict for the lifetime of the process.  Never
 * parses a kernel version: containers/seccomp routinely block io_uring_setup
 * even on new kernels, so only an actual setup+probe is trustworthy.
 *
 * Returns 1 iff a ring can be created and all required opcodes are supported.
 */
ngx_int_t
brix_uring_runtime_available(void)
{
    static const int required[] = {
        IORING_OP_READ, IORING_OP_WRITE, IORING_OP_READV,
        IORING_OP_WRITEV, IORING_OP_FSYNC
    };
    static ngx_int_t   cached      = -1;   /* -1 = not yet probed */
    struct io_uring    ring;
    struct io_uring_probe *probe;
    ngx_int_t          ok = 1;
    ngx_uint_t         i;

    if (cached != -1) {
        return cached;
    }

    if (io_uring_queue_init(8, &ring, 0) < 0) {
        cached = 0;                         /* seccomp / no syscall / old kernel */
        return 0;
    }

    probe = io_uring_get_probe_ring(&ring);
    if (probe == NULL) {
        io_uring_queue_exit(&ring);
        cached = 0;
        return 0;
    }

    for (i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        if (!io_uring_opcode_supported(probe, required[i])) {
            ok = 0;
            break;
        }
    }

    io_uring_free_probe(probe);
    io_uring_queue_exit(&ring);

    cached = ok;
    return cached;
}

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

/* completion-slot table (UAF-safe task mapping) */
/* brix_uring_slot_at — bounds-checked slot lookup; NULL if idx is out of
 * range (a corrupt/forged user_data). */
static brix_uring_slot_t *
brix_uring_slot_at(brix_uring_t *u, uint32_t idx)
{
    return idx < u->queue_depth ? &u->slots[idx] : NULL;
}

/* brix_uring_slot_acquire — claim the first free slot.  The selector checks
 * inflight < queue_depth before calling, so a free slot always exists; the
 * linear scan over <=4096 entries is negligible.  Returns NULL only if the
 * table is unexpectedly full (caller then falls back to the thread pool).
 * Non-static: also called from uring_submit.c. */
brix_uring_slot_t *
brix_uring_slot_acquire(brix_uring_t *u, uint32_t *idx_out)
{
    uint32_t i;

    for (i = 0; i < u->queue_depth; i++) {
        if (!u->slots[i].in_use) {
            u->slots[i].in_use = 1;
            *idx_out = i;
            return &u->slots[i];
        }
    }

    return NULL;
}

/* brix_uring_slot_release — free a slot and bump its generation so any later
 * CQE carrying the old generation is recognised as stale and dropped.
 * Non-static: also called from uring_submit.c. */
void
brix_uring_slot_release(brix_uring_t *u, uint32_t idx)
{
    brix_uring_slot_t *s = &u->slots[idx];

    s->in_use     = 0;
    s->task       = NULL;
    s->done_fn    = NULL;
    s->owner      = NULL;
    s->orphaned   = 0;
    s->generation++;
    (void) u;
}

/* brix_uring_orphan_owner — mark every in-flight slot owned by a dying
 * connection so the reaper drops its late CQE without touching the task (freed
 * with the connection pool) or posting its completion event.  See uring.h. */
void
brix_uring_orphan_owner(void *owner)
{
    brix_uring_t *u = brix_uring_worker();
    uint32_t        i;

    if (u == NULL || !u->ring_active || owner == NULL) {
        return;
    }
    for (i = 0; i < u->queue_depth; i++) {
        if (u->slots[i].in_use && u->slots[i].owner == owner) {
            u->slots[i].orphaned = 1;
        }
    }
}

/*
 * brix_uring_apply_cqe — translate cqe->res into the task's OUT fields, the
 * same fields the worker-thread fn would have set.  io_uring reports failures
 * as a negative -errno in cqe->res (it does NOT set errno).
 *
 * Returns 1 when the task is fully complete and its done-callback should be
 * posted, 0 when more CQEs are still expected for this task (the linked
 * writev+fsync chain, added in SB-W4).  READV/WRITEV cases also land in SB-W4;
 * READ/WRITE are handled here so the reaper is complete for the hot path.
 */
static ngx_int_t
brix_uring_apply_cqe(brix_uring_slot_t *slot, struct io_uring_cqe *cqe)
{
    ngx_thread_task_t *task = slot->task;
    int32_t            res  = cqe->res;

    switch (slot->op_kind) {

    case XRD_URING_OP_READ: {
        brix_read_aio_t *t = task->ctx;
        if (res < 0) { t->nread = -1;  t->io_errno = -res; }
        else         { t->nread = res; t->io_errno = 0;    }
        return 1;
    }

    case XRD_URING_OP_WRITE: {
        brix_write_aio_t *t = task->ctx;
        if (res < 0) { t->nwritten = -1;  t->io_errno = -res; }
        else         { t->nwritten = res; t->io_errno = 0;    }
        return 1;
    }

    case XRD_URING_OP_READV: {
        brix_readv_aio_t *t = task->ctx;
        size_t              total = 0, i;

        /* Single contiguous group (op_for gated it): one IORING_OP_READV
         * scattered into the per-segment payload pointers.  The wire segment
         * headers were already written at plan-build, so nothing to fix up here
         * — only the totals + error state, matching brix_readv_aio_thread. */
        for (i = 0; i < t->segment_count; i++) {
            total += t->segments[i].read_length;
        }
        if (res < 0) {
            t->io_error = 1; t->bytes_read_total = 0; t->response_bytes = 0;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "readv I/O error: %s", strerror(-res));
        } else if ((size_t) res != total) {
            t->io_error = 1; t->bytes_read_total = 0; t->response_bytes = 0;
            snprintf(t->err_msg, sizeof(t->err_msg), "readv past EOF");
        } else {
            t->io_error = 0;
            t->bytes_read_total = (size_t) res;
            t->response_bytes   = t->segment_count * BRIX_READV_SEGSIZE
                                  + (size_t) res;
        }
        return 1;
    }

    case XRD_URING_OP_WRITEV: {
        brix_writev_aio_t *t = task->ctx;
        size_t               total = 0, i;

        /* Single contiguous same-fd group: one IORING_OP_WRITEV gathering the
         * segment buffers.  io_error encodes the failure kind exactly as
         * brix_writev_write_aio_thread (1 = hard error, 2 = short write).  A
         * trailing FSYNC (when do_sync) is a separate linked SQE whose CQE the
         * reaper drops — best-effort, matching the pool path's ignored return. */
        for (i = 0; i < t->n_segs; i++) {
            total += t->segs[i].wlen;
        }
        if (res < 0) {
            t->io_error = 1; t->bytes_total = 0;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "writev I/O error: %s", strerror(-res));
        } else if ((size_t) res < total) {
            t->io_error = 2; t->bytes_total = (size_t) res;
            snprintf(t->err_msg, sizeof(t->err_msg), "writev short write");
        } else {
            t->io_error = 0; t->bytes_total = (size_t) res;
        }
        return 1;
    }

    default:
        /* pgread/dirlist are never routed to io_uring (op_for -> NONE). */
        return 1;
    }
}

/*
 * uring_cqe_retire — acknowledge one CQE and balance the in-flight counter.
 *
 * WHAT: Marks the CQE seen (returning its ring slot to the kernel) and
 *       decrements the inflight gauge that the submission selector consults.
 * WHY:  Every CQE — real completion, stale generation, orphan, or trailing
 *       FSYNC — must be retired exactly once; centralising the pair keeps the
 *       accounting impossible to miss on any per-CQE early return.
 * HOW:  io_uring_cqe_seen + a guarded decrement (never underflows).
 */
static void
uring_cqe_retire(brix_uring_t *u, struct io_uring_cqe *cqe)
{
    io_uring_cqe_seen(&u->ring, cqe);
    if (u->inflight > 0) { u->inflight--; }
}

/*
 * uring_complete_one — classify and complete a single harvested CQE.
 *
 * WHAT: The per-CQE body of the completion reaper: decode the slot cookie,
 *       run the generation/orphan guards, translate the result into the task
 *       and post its done-callback.
 * WHY:  Extracted from brix_uring_eventfd_handler so the reaper loop stays a
 *       trivial drain and each guard reads as one early return.
 * HOW:  Early-return ladder — trailing-FSYNC drop, stale-generation drop,
 *       orphaned-owner drop (slot recycled, task never touched), then the
 *       normal translate + ngx_post_event path.  Every exit retires the CQE
 *       via uring_cqe_retire; done-callbacks are never invoked inline.
 */
static void
uring_complete_one(brix_uring_t *u, struct io_uring_cqe *cqe)
{
    uint64_t             ud = io_uring_cqe_get_data64(cqe);
    uint32_t             idx;
    uint32_t             gen;
    brix_uring_slot_t *slot;

    /* 2-pre. trailing FSYNC of a linked writev+fsync chain: carries no slot;
     * fsync is best-effort (the pool path ignores its return), so drop the
     * CQE and just balance inflight. */
    if (ud == BRIX_URING_FSYNC_COOKIE) {
        uring_cqe_retire(u, cqe);
        return;
    }

    idx  = (uint32_t) (ud & 0xffffffffULL);
    gen  = (uint32_t) (ud >> 32);
    slot = brix_uring_slot_at(u, idx);

    /* 2a. generation guard: a stale CQE for a recycled/dead slot is dropped
     * safely.  (The done-callback's own ctx->destroyed check remains the
     * authoritative guard for the connection.) */
    if (slot == NULL || !slot->in_use || slot->generation != gen) {
        uring_cqe_retire(u, cqe);
        return;
    }

    /* 2a'. orphaned slot: the owning connection was torn down while this
     * op was in flight — the task's memory died with the connection pool.
     * Drop the CQE without dereferencing the task or posting its (equally
     * dead) completion event, and recycle the slot. */
    if (slot->orphaned) {
        brix_uring_slot_release(u, idx);
        uring_cqe_retire(u, cqe);
        return;
    }

    /* 2b. translate + post (the done-callback is task->event.handler, set
     * at brix_task_bind time). */
    if (brix_uring_apply_cqe(slot, cqe)) {
        ngx_thread_task_t *task = slot->task;

        task->event.complete = 1;
        ngx_post_event(&task->event, &ngx_posted_events);
        brix_uring_slot_release(u, idx);
    }

    uring_cqe_retire(u, cqe);
}

/*
 * brix_uring_eventfd_handler — the completion reaper.
 *
 * Wired into the worker's epoll as the read handler of the fake connection that
 * wraps the ring's registered eventfd.  This is the public-API analogue of
 * nginx core's ngx_epoll_eventfd_handler() (the libaio bridge): drain the
 * eventfd counter, then harvest every ready CQE — validating each slot's
 * generation, translating the result into the task, and posting the task's
 * done-callback to ngx_posted_events.  Done-callbacks are NEVER invoked inline
 * here: nginx's posted-events drain runs them after process_events, so a
 * callback that re-submits the next read window never re-enters the harvest
 * loop (re-entrancy-safe).
 */
static void
brix_uring_eventfd_handler(ngx_event_t *ev)
{
    ngx_connection_t    *evc = ev->data;
    brix_uring_t      *u   = evc->data;
    struct io_uring_cqe *cqe;
    uint64_t             counter;
    ssize_t              n;

    /* 1. drain the eventfd counter (mirrors core's first step). */
    n = read(u->eventfd, &counter, sizeof(counter));
    if (n != (ssize_t) sizeof(counter)) {
        if (n == -1 && (ngx_errno == NGX_EAGAIN || ngx_errno == NGX_EINTR)) {
            return;
        }
        ngx_log_error(NGX_LOG_ALERT, evc->log, ngx_errno,
                      "brix: io_uring eventfd read() failed");
        return;
    }

    /* 2. harvest all ready completions. */
    while (io_uring_peek_cqe(&u->ring, &cqe) == 0) {
        uring_complete_one(u, cqe);
    }
}

/* bring-up helpers */
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
 * brix_uring_teardown — release every ring resource that has been brought up,
 * in reverse order, idempotently (driven by which fields are set).  Mirrors
 * nginx core's eventfd cleanup: ngx_free_connection + close(fd) rather than
 * ngx_close_connection, to avoid double-closing the eventfd.  No goto.
 */
static void
brix_uring_teardown(brix_uring_t *u)
{
    if (u->ring_active && u->eventfd >= 0) {
        io_uring_unregister_eventfd(&u->ring);
    }

    if (u->evc != NULL) {
        if (u->evc->read->active) {
            (void) ngx_del_event(u->evc->read, NGX_READ_EVENT, 0);
        }
        ngx_free_connection(u->evc);
        u->evc->fd = (ngx_socket_t) -1;
        u->evc = NULL;
    }

    if (u->eventfd >= 0) {
        close(u->eventfd);
        u->eventfd = -1;
    }

    if (u->ring_active) {
        io_uring_queue_exit(&u->ring);
        u->ring_active = 0;
    }

    u->enabled = 0;
    u->slots   = NULL;   /* pool-owned; freed with the worker cycle pool */
}

/*
 * brix_uring_init_fail — log the bring-up failure, tear down whatever was set
 * up, and return the right verdict: NGX_ERROR under `on` (the worker refuses to
 * run on the thread pool — master respawns; the §32.7 backstop) or NGX_OK under
 * `auto` (silent degrade to the thread pool).
 */
static ngx_int_t
brix_uring_init_fail(brix_uring_t *u, ngx_cycle_t *cycle, ngx_uint_t mode_on,
    const char *what)
{
    /* Hoist the level into a variable: the ngx_log_error macro does not
     * parenthesize its level argument, so a raw ternary would bind under >=. */
    ngx_uint_t level = mode_on ? NGX_LOG_EMERG : NGX_LOG_NOTICE;

    ngx_log_error(level, cycle->log, ngx_errno,
        "brix: io_uring bring-up failed at %s%s", what,
        mode_on
            ? " — \"brix_io_uring on\" requires it; this worker refuses to run"
            : "; falling back to the thread pool");

    brix_uring_teardown(u);
    return mode_on ? NGX_ERROR : NGX_OK;
}

/* Merged per-worker io_uring demand, folded across every enabled server
 * block by uring_scan_conf() and consumed by uring_probe_features(). */
typedef struct {
    ngx_uint_t  mode_on;        /* any block requires io_uring (mode `on`)  */
    ngx_uint_t  want_restrict;  /* 0 iff any wanting block disabled it      */
    ngx_int_t   depth;          /* max requested queue depth (pre-clamp)    */
    ngx_str_t   panic_file;     /* first configured kill-switch path        */
} brix_uring_scan_t;

/*
 * uring_scan_conf — fold every enabled server block's io_uring settings.
 *
 * WHAT: Scans the stream server blocks and merges their io_uring demand into
 *       *scan: whether any block wants the ring, whether any requires it
 *       (`on`), the max queue depth, the restriction preference, and the
 *       first configured panic-file path.
 * WHY:  The ring is a per-worker singleton, so per-block settings must be
 *       folded into one verdict before bring-up.
 * HOW:  Linear scan skipping disabled/off blocks; max for depth, AND for
 *       restrictions, first-wins for the panic file.
 *
 * Returns 1 if at least one enabled block wants io_uring, 0 otherwise.
 */
static ngx_int_t
uring_scan_conf(ngx_cycle_t *cycle, brix_uring_scan_t *scan)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_brix_srv_conf_t  *xcf;
    ngx_uint_t                     i;
    ngx_int_t                      want = 0;

    cmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_core_module);
    if (cmcf == NULL) {
        return 0;
    }

    cscfp = cmcf->servers.elts;
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                  ngx_stream_brix_module);
        if (!xcf->common.enable || xcf->io_uring == BRIX_IO_URING_OFF) {
            continue;
        }
        want = 1;
        if (xcf->io_uring == BRIX_IO_URING_ON) {
            scan->mode_on = 1;
        }
        if (xcf->io_uring_queue_depth > scan->depth) {
            scan->depth = xcf->io_uring_queue_depth;
        }
        if (!xcf->io_uring_restrict) {
            scan->want_restrict = 0;
        }
        if (scan->panic_file.len == 0 && xcf->io_uring_panic_file.len > 0) {
            scan->panic_file = xcf->io_uring_panic_file;
        }
    }

    return want;
}

/*
 * uring_probe_features — decide whether this worker should bring a ring up.
 *
 * WHAT: Folds the configuration (uring_scan_conf) and the kernel capability
 *       probe into one go/no-go verdict, clamping the queue depth.
 * WHY:  Both "nobody wants io_uring" and "auto blocks on a host without it"
 *       are silent thread-pool outcomes that must be decided BEFORE any ring
 *       resource exists — keeping the post-creation fallback decision point
 *       (brix_uring_init_fail) single.
 * HOW:  Early-returns NGX_DECLINED for either skip reason (logging the
 *       `auto`-unavailable NOTICE), otherwise clamps depth into [8,4096] and
 *       returns NGX_OK to proceed with bring-up.
 */
static ngx_int_t
uring_probe_features(ngx_cycle_t *cycle, brix_uring_scan_t *scan)
{
    scan->mode_on       = 0;
    scan->want_restrict = 1;
    scan->depth         = BRIX_IO_URING_QUEUE_DEPTH;
    ngx_str_null(&scan->panic_file);

    if (!uring_scan_conf(cycle, scan)) {
        return NGX_DECLINED;   /* every enabled block has io_uring off */
    }

    /* AUTO blocks need the per-process probe (seccomp-accurate); ON blocks
     * already passed it at config time but re-checking is cheap + memoized. */
    if (!scan->mode_on && !brix_uring_runtime_available()) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
            "brix: io_uring unavailable on this host; using the thread pool");
        return NGX_DECLINED;
    }

    if (scan->depth < 8)    { scan->depth = 8;    }
    if (scan->depth > 4096) { scan->depth = 4096; }

    return NGX_OK;
}

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
 */
static const char *
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
 *       on success.
 */
static const char *
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
 *       brix_uring_init_fail, NULL on success.
 */
static const char *
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
 *       brix_uring_init_fail, NULL on success.
 */
static const char *
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
 *       brix_uring_init_fail, NULL on success.
 */
static const char *
uring_register_buffers(brix_uring_t *u, ngx_cycle_t *cycle)
{
    u->slots = ngx_pcalloc(cycle->pool,
                           u->queue_depth * sizeof(brix_uring_slot_t));
    if (u->slots == NULL) {
        return "slot table alloc";
    }

    return NULL;
}

/*
 * brix_uring_init_worker — create this worker's ring after fork.
 *
 * Scans every enabled server block: the ring is created if any block wants
 * io_uring (mode on/auto); queue depth is the max requested; restrictions are
 * applied unless any wanting block turned them off.  Bring-up sequence:
 * queue_init [R_DISABLED if restricting] -> register restrictions + enable ->
 * NOP self-test -> eventfd + register_eventfd -> fake-connection epoll bridge ->
 * slot table.  Any failure routes through brix_uring_init_fail (NGX_OK under
 * auto, NGX_ERROR under on).  When no block wants io_uring this is a no-op.
 */
ngx_int_t
brix_uring_init_worker(ngx_cycle_t *cycle)
{
    brix_uring_t       *u = &brix_uring_worker_ring;
    brix_uring_scan_t   scan;
    const char           *what;

    if (uring_probe_features(cycle, &scan) != NGX_OK) {
        return NGX_OK;   /* nobody wants a ring / auto blocks on a bare host */
    }

    u->log         = cycle->log;
    u->eventfd     = -1;
    u->evc         = NULL;
    u->slots       = NULL;
    u->inflight    = 0;
    u->ring_active = 0;
    u->enabled     = 0;
    u->restrict_ops = 0;
    u->queue_depth = (uint32_t) scan.depth;

    /* 1-3. create + notify-wire + restrict + enable the ring. */
    what = uring_setup_rings(u, scan.want_restrict);
    if (what != NULL) {
        return brix_uring_init_fail(u, cycle, scan.mode_on, what);
    }

    /* 4. NOP self-test: prove submit -> complete works AND that the registered
     * eventfd actually delivers the completion notification. */
    what = uring_selftest_nop(u);
    if (what != NULL) {
        return brix_uring_init_fail(u, cycle, scan.mode_on, what);
    }

    /* 4b. UNDER-LOAD delivery self-test: fill the ring with queue_depth ops and
     * require EVERY completion to arrive via the eventfd within the deadline. */
    what = uring_selftest_burst(u);
    if (what != NULL) {
        return brix_uring_init_fail(u, cycle, scan.mode_on, what);
    }

    /* 5. wire the eventfd into the worker's epoll via a fake connection. */
    what = uring_install_eventfd(u, cycle);
    if (what != NULL) {
        return brix_uring_init_fail(u, cycle, scan.mode_on, what);
    }

    /* 6. completion-slot table (pool-owned; freed with the cycle). */
    what = uring_register_buffers(u, cycle);
    if (what != NULL) {
        return brix_uring_init_fail(u, cycle, scan.mode_on, what);
    }

    /* SB-W5b: attach the cross-worker kill-switch flag (NULL if the zone was
     * not registered — the selector then reads "enabled") and arm the
     * panic-file poll timer if a path was configured. */
    u->disabled_flag = brix_uring_killswitch_ptr();
    (void) brix_uring_panicfile_arm(cycle, &scan.panic_file);

    u->enabled = 1;
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
        "brix: io_uring disk-I/O backend active (queue_depth=%ui%s)",
        (ngx_uint_t) u->queue_depth,
        u->restrict_ops ? ", restricted" : "");

    return NGX_OK;
}

/*
 * brix_uring_exit_worker — tear the ring down at worker shutdown.  Safe to
 * call when the ring was never brought up (no-op).
 */
void
brix_uring_exit_worker(ngx_cycle_t *cycle)
{
    brix_uring_t *u = &brix_uring_worker_ring;

    (void) cycle;

    if (!u->ring_active && u->eventfd < 0 && u->evc == NULL) {
        return;
    }
    brix_uring_teardown(u);
}

#else  /* !BRIX_HAVE_LIBURING */

ngx_int_t
brix_uring_runtime_available(void)
{
    return 0;
}

/* No ring in a stub build — the selector accessor isn't even declared, so the
 * thread-pool tier is the only path.  Lifecycle is a no-op. */
ngx_int_t
brix_uring_init_worker(ngx_cycle_t *cycle)
{
    (void) cycle;
    return NGX_OK;
}

void
brix_uring_exit_worker(ngx_cycle_t *cycle)
{
    (void) cycle;
}

#endif /* BRIX_HAVE_LIBURING */

/*
 * brix_uring_validate_conf — §32 startup fail-fast (ADR-16).
 *
 * If any enabled server block requests `brix_io_uring on`, io_uring MUST be
 * provided or startup fails (NGX_ERROR -> nginx -t exits non-zero, master
 * refuses to start).  Two independent gates:
 *   (1) compile-time: a stub build can never satisfy `on` — caught with no
 *       kernel needed, so CI / `nginx -t` flags it anywhere;
 *   (2) runtime: a liburing build whose probe fails (old kernel / seccomp).
 * `off` and `auto` always pass (auto degrades silently per worker).
 *
 * Returns NGX_OK to allow startup, NGX_ERROR to abort it.
 */
ngx_int_t
brix_uring_validate_conf(ngx_conf_t *cf)
{
    if (!brix_uring_any_block_on(cf)) {
        return NGX_OK;
    }

#if !(BRIX_HAVE_LIBURING)
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "\"brix_io_uring on\" requires a build with liburing, but this binary "
        "was compiled WITHOUT it. Rebuild with BRIX_ENABLE_IO_URING=1 and "
        "liburing-devel installed, or set \"brix_io_uring auto\" to allow "
        "silent fallback to the thread pool.");
    return NGX_ERROR;
#else
    if (!brix_uring_runtime_available()) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"brix_io_uring on\" requested but io_uring is unavailable on "
            "this host (io_uring_setup/opcode probe failed). This is typically a "
            "seccomp policy (Docker/containerd default profiles block io_uring) "
            "or a kernel older than %d.%d. Set \"brix_io_uring auto\" to fall "
            "back to the thread pool, or enable io_uring at the host/container "
            "level.",
            BRIX_IO_URING_MIN_KERNEL_MAJOR, BRIX_IO_URING_MIN_KERNEL_MINOR);
        return NGX_ERROR;
    }
    return NGX_OK;
#endif
}
