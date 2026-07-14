#include "core/ngx_brix_module.h"
#include "aio.h"
#include "uring.h"
#include "uring_internal.h"

/* File: src/core/aio/uring_probe.c — io_uring detection, gating, and the §32
 * startup fail-fast validator (phase-79 split from uring.c).
 * WHAT: Owns the "should this build/host/worker use io_uring at all" decisions:
 *       the memoized runtime opcode probe, the per-block config scan folded into
 *       one per-worker verdict, and the config-time hard-fail for `brix_io_uring
 *       on`.  The ring singleton and its bring-up live in uring.c; the CQE
 *       reaper lives in uring_reap.c.
 *
 * WHY:  The backend must be invisible unless explicitly built (pkg-config
 *       liburing) and runtime-available (opcode probe).  `auto`/`off` always
 *       start and silently fall back; `on` is a hard requirement that fails
 *       startup when it cannot be provided — caught at config time so even a
 *       stub build flags it under `nginx -t` with no kernel needed.
 *
 * HOW:  All liburing-specific code is under #if (BRIX_HAVE_LIBURING).  When the
 *       macro is undefined this file compiles to inert stubs: the probe reports
 *       the backend unavailable and the validator hard-fails any `on` block. */

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
 *       returns NGX_OK to proceed with bring-up.  Non-static: also called from
 *       brix_uring_init_worker() in uring.c.
 */
ngx_int_t
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

#else  /* !BRIX_HAVE_LIBURING */

ngx_int_t
brix_uring_runtime_available(void)
{
    return 0;
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
