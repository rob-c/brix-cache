/*
 * uring_internal.h — declarations shared across the io_uring backend files
 * after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the two entry points and the one scan struct that cross
 *       file boundaries between uring.c (ring singleton + bring-up/lifecycle),
 *       uring_probe.c (gating + capability probe + startup validation), and
 *       uring_reap.c (completion reaper + completion-slot table).
 * WHY:  uring.c (1033 lines) split into four focused files under the 500-line
 *       cap: uring.c keeps the per-worker ring singleton and the init/exit
 *       lifecycle orchestrator; uring_bringup.c owns the ordered register-phase
 *       bring-up steps (create/eventfd/restrict/enable/self-tests/epoll-bridge/
 *       slot-table); uring_probe.c owns detection, per-block gating, and the
 *       §32 fail-fast validator; uring_reap.c owns the eventfd-driven CQE
 *       reaper and the UAF-safe slot table.  Exactly the symbols that cross
 *       those boundaries become non-static and are declared here — nothing else.
 * HOW:  All three .c files include this header.  Its contents are gated on
 *       BRIX_HAVE_LIBURING because the scan struct and both entry points exist
 *       only in a liburing build; a stub build never reaches them.
 *
 * Requires: core/ngx_brix_module.h and uring.h included before this header.
 */
#ifndef BRIX_CORE_AIO_URING_INTERNAL_H
#define BRIX_CORE_AIO_URING_INTERNAL_H

#include "core/ngx_brix_module.h"
#include "uring.h"

#if (BRIX_HAVE_LIBURING)

/* Merged per-worker io_uring demand, folded across every enabled server block
 * by uring_scan_conf() (uring_probe.c) and consumed by uring_probe_features()
 * (uring_probe.c) and brix_uring_init_worker() (uring.c). */
typedef struct {
    ngx_uint_t  mode_on;        /* any block requires io_uring (mode `on`)  */
    ngx_uint_t  want_restrict;  /* 0 iff any wanting block disabled it      */
    ngx_int_t   depth;          /* max requested queue depth (pre-clamp)    */
    ngx_str_t   panic_file;     /* first configured kill-switch path        */
} brix_uring_scan_t;

/* Defined in uring_probe.c.  Folds the configuration and the kernel capability
 * probe into one go/no-go verdict for this worker, clamping the queue depth.
 * Returns NGX_OK to proceed with bring-up, NGX_DECLINED to skip it. */
ngx_int_t uring_probe_features(ngx_cycle_t *cycle, brix_uring_scan_t *scan);

/* Defined in uring_reap.c.  The completion reaper: the read handler of the fake
 * connection wrapping the ring's registered eventfd (installed by
 * uring_install_eventfd).  Drains the eventfd counter, then harvests every ready
 * CQE. */
void brix_uring_eventfd_handler(ngx_event_t *ev);

/* Register-phase bring-up steps, defined in uring_bringup.c and driven in order
 * by brix_uring_init_worker() (uring.c).  Each mutates *u as its step lands and
 * returns NULL on success or the failing step's name for brix_uring_init_fail. */
const char *uring_setup_rings(brix_uring_t *u, ngx_uint_t want_restrict);
const char *uring_selftest_nop(brix_uring_t *u);
const char *uring_selftest_burst(brix_uring_t *u);
const char *uring_install_eventfd(brix_uring_t *u, ngx_cycle_t *cycle);
const char *uring_register_buffers(brix_uring_t *u, ngx_cycle_t *cycle);

#endif /* BRIX_HAVE_LIBURING */

#endif /* BRIX_CORE_AIO_URING_INTERNAL_H */
