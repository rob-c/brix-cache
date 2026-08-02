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

/* P44-A quiesce support: the winning bring-up conf, saved so a runtime
 * re-enable can re-create the ring after a kill-switch teardown, and a flag
 * marking that this worker ever brought a ring up (a worker whose bring-up
 * failed or was never wanted must stay ringless — quiesce ticks no-op). */
static brix_uring_scan_t  brix_uring_saved_scan;
static ngx_uint_t         brix_uring_rearm_ok;

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
    /* u->slots is deliberately KEPT: the table is cycle-pool-owned (freed with
     * the worker, never manually) and is reused verbatim by a P44-A re-enable,
     * so repeated kill-switch flips cannot grow the cycle pool. */
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
 * brix_uring_bring_up — run the ordered bring-up steps and publish the ring.
 *
 * Shared by the after-fork init (brix_uring_init_worker) and the P44-A
 * runtime re-enable (brix_uring_quiesce_tick): queue_init [R_DISABLED if
 * restricting] -> register restrictions + enable -> NOP self-test -> burst
 * self-test -> fake-connection epoll bridge -> slot table -> kill-switch
 * attach.  Returns NULL with u->enabled = 1 on success, or the failing step's
 * name with partial state left for the caller to tear down (the two callers
 * differ in verdict: init_fail vs retry-next-tick).
 */
static const char *
brix_uring_bring_up(brix_uring_t *u, ngx_cycle_t *cycle,
    const brix_uring_scan_t *scan)
{
    const char  *what;

    u->log         = cycle->log;
    u->eventfd     = -1;
    u->evc         = NULL;
    u->inflight    = 0;
    u->ring_active = 0;
    u->enabled     = 0;
    u->restrict_ops = 0;
    u->queue_depth = (uint32_t) scan->depth;

    /* 1-3. create + notify-wire + restrict + enable the ring. */
    what = uring_setup_rings(u, scan->want_restrict);
    if (what != NULL) {
        return what;
    }

    /* 4. NOP self-test: prove submit -> complete works AND that the registered
     * eventfd actually delivers the completion notification. */
    what = uring_selftest_nop(u);
    if (what != NULL) {
        return what;
    }

    /* 4b. UNDER-LOAD delivery self-test: fill the ring with queue_depth ops and
     * require EVERY completion to arrive via the eventfd within the deadline. */
    what = uring_selftest_burst(u);
    if (what != NULL) {
        return what;
    }

    /* 5. wire the eventfd into the worker's epoll via a fake connection. */
    what = uring_install_eventfd(u, cycle);
    if (what != NULL) {
        return what;
    }

    /* 6. completion-slot table (pool-owned, reused across quiesce cycles). */
    what = uring_register_buffers(u, cycle);
    if (what != NULL) {
        return what;
    }

    /* SB-W5b: attach the cross-worker kill-switch flag (NULL if the zone was
     * not registered — the selector then reads "enabled"). */
    u->disabled_flag = brix_uring_killswitch_ptr();

    u->enabled = 1;
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
        "brix: io_uring disk-I/O backend active (queue_depth=%ui%s)",
        (ngx_uint_t) u->queue_depth,
        u->restrict_ops ? ", restricted" : "");

    return NULL;
}

/*
 * brix_uring_init_worker — create this worker's ring after fork.
 *
 * Scans every enabled server block: the ring is created if any block wants
 * io_uring (mode on/auto); queue depth is the max requested; restrictions are
 * applied unless any wanting block turned them off.  Any bring-up failure
 * routes through brix_uring_init_fail (NGX_OK under auto, NGX_ERROR under on).
 * When no block wants io_uring this is a no-op.
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

    what = brix_uring_bring_up(u, cycle, &scan);
    if (what != NULL) {
        return brix_uring_init_fail(u, cycle, scan.mode_on, what);
    }

    /* P44-A: save the winning conf so a runtime quiesce can re-create the
     * ring, then start the per-worker maintenance timer (quiesce/re-enable
     * driver) and the panic-file mirror if a path was configured. */
    brix_uring_saved_scan = scan;
    brix_uring_rearm_ok   = 1;
    (void) brix_uring_panicfile_arm(cycle, &scan.panic_file);
    (void) brix_uring_maint_arm(cycle);

    return NGX_OK;
}

/*
 * brix_uring_quiesce_tick — P44-A ring quiesce-and-teardown (§36 tier).
 *
 * Driven by the per-worker maintenance timer (uring_admin.c, 2 s cadence).
 * While the kill switch merely stops NEW submissions at the selector, the
 * quiesce goes further: once every in-flight CQE has drained, the ring and
 * its eventfd are torn down so the kernel attack surface (the ring fds)
 * disappears from the process, not just from the hot path.  When the switch
 * clears, the ring is re-created from the saved bring-up conf — including the
 * full self-test ladder, so a re-enable can never resurrect a ring the worker
 * would not have trusted at boot.  A failed re-enable is logged and retried
 * on the next tick (never fatal at runtime, even under mode `on`: the kill
 * switch is an incident tool and the pool tier keeps serving).
 */
void
brix_uring_quiesce_tick(void)
{
    brix_uring_t  *u = &brix_uring_worker_ring;
    ngx_cycle_t   *cycle = (ngx_cycle_t *) ngx_cycle;
    const char    *what;

    if (!brix_uring_rearm_ok) {
        return;             /* this worker never had a ring: nothing to manage */
    }

    if (brix_uring_killswitch_get()) {
        /* Disabled: the ring stays alive only while ops are still in flight
         * (the reaper needs it); the moment the last CQE drains, drop it. */
        if (u->enabled && u->inflight == 0) {
            brix_uring_teardown(u);
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                "brix: io_uring ring quiesced (kill switch): "
                "ring + eventfd released");
        }
        return;
    }

    if (u->enabled) {
        return;                                     /* running normally */
    }

    what = brix_uring_bring_up(u, cycle, &brix_uring_saved_scan);
    if (what != NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
            "brix: io_uring re-enable failed at %s; "
            "retrying on the next maintenance tick", what);
        brix_uring_teardown(u);
    }
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

void
brix_uring_quiesce_tick(void)
{
    /* no ring in a stub build — the maintenance timer only mirrors the
     * panic file into the (unconfigured) kill switch */
}

#endif /* BRIX_HAVE_LIBURING */
