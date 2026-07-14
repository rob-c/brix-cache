#include "core/ngx_brix_module.h"
#include "aio.h"
#include "uring.h"
#include "uring_internal.h"

#if (BRIX_HAVE_LIBURING)
#include <unistd.h>   /* close() in brix_uring_teardown */
#endif

/* File: src/core/aio/uring.c — the io_uring per-worker ring singleton and the
 * init/exit lifecycle orchestrator (phase-79 split from the original 1033-line
 * uring.c).
 * WHAT: Owns the file-static per-worker ring singleton + its accessor, and the
 *       two lifecycle entry points: brix_uring_init_worker (drive the ordered
 *       bring-up steps then publish the ring) and brix_uring_exit_worker (tear
 *       it down).  The ordered register-phase steps live in uring_bringup.c;
 *       detection/gating in uring_probe.c; the CQE reaper + slot table in
 *       uring_reap.c; submission in uring_submit.c.
 *
 * WHY:  The backend must be invisible unless explicitly built (pkg-config
 *       liburing) and runtime-available (opcode probe).  `auto`/`off` always
 *       start and silently fall back; `on` is a hard requirement — this
 *       orchestrator is the §32.7 backstop that refuses to run a worker that
 *       cannot honour `on` (brix_uring_init_fail returns NGX_ERROR under `on`).
 *
 * HOW:  All liburing-specific code is under #if (BRIX_HAVE_LIBURING).  When the
 *       macro is undefined the lifecycle entry points compile to inert stubs. */

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
