#ifndef BRIX_PROCESS_INTERNAL_H
#define BRIX_PROCESS_INTERNAL_H
/*
 * process_internal.h — cross-file entry points for the per-worker process
 * lifecycle, split (phase-79 file-size cap) out of the former 925-line
 * process.c.
 *
 * WHAT: Declares the handful of symbols that cross the process.c /
 *       process_timers.c / process_server_init.c file boundary — the two
 *       maintenance-timer callbacks armed from a server's init ladder
 *       (brix_crl_reload_handler, brix_cache_reap_handler), the three
 *       worker-scoped timer-arming entry points the init_process orchestrator
 *       calls, and the per-server init ladder entry point. Everything else in
 *       each file stays file-local (static).
 * WHY:  process.c owned the crypto/stage/uring bring-up, every maintenance
 *       timer callback, and the full per-server init ladder in one file, far
 *       over the 500-line cap. Splitting the timer machinery and the per-server
 *       ladder into two focused siblings keeps each concern reviewable in
 *       isolation while preserving the EXACT frozen worker-init order the
 *       reload-semantics contract depends on. Only the symbols listed here are
 *       non-static and shared; the static timer event globals stay private to
 *       process_timers.c, co-located with both their handler and their arming
 *       function.
 * HOW:  Requires "config.h" (for ngx_event_t / ngx_cycle_t / ngx_uint_t /
 *       ngx_int_t / ngx_stream_brix_srv_conf_t) before inclusion. The timer
 *       callbacks + arming entry points live in process_timers.c; the
 *       per-server ladder lives in process_server_init.c; the orchestrator
 *       (ngx_stream_brix_init_process) and teardown (brix_exit_process) stay in
 *       process.c.
 */

/*
 * Cache-state reaper cadence (shared): the first-tick delay is used by the
 * per-server arming functions in process_server_init.c (stale-dirty reaper +
 * watermark LRU reaper), while the steady-state interval is used by the
 * stale-dirty handler in process_timers.c — the pair now spans both files, so
 * it lives here to stay a single source of truth.
 */
#define BRIX_CACHE_REAP_FIRST_MS     5000
#define BRIX_CACHE_REAP_INTERVAL_MS  3600000   /* hourly */

/* Maintenance-timer callbacks defined in process_timers.c but armed from a
 * server's init ladder in process_server_init.c (via ngx_event_t->handler). */
void brix_crl_reload_handler(ngx_event_t *ev);
void brix_cache_reap_handler(ngx_event_t *ev);

/* Worker-scoped timer-arming entry points defined in process_timers.c and
 * called by the ngx_stream_brix_init_process orchestrator in process.c:
 *   - stage-flush scheduler (armed in every worker, incl. HTTP-only)
 *   - worker-0 CMS pending-locate reaper (managers only)
 *   - worker-0 upload stage-out reaper. */
void brix_init_stage_sched_timer(ngx_cycle_t *cycle);
void brix_init_pending_reap_timer(ngx_cycle_t *cycle, ngx_uint_t manager_seen);
void brix_init_stage_reap_timer(ngx_cycle_t *cycle);

/* Per-server worker-init ladder defined in process_server_init.c and called
 * once per enabled server block by the init_process orchestrator. Returns
 * NGX_OK, or NGX_ERROR to abort worker startup. */
ngx_int_t brix_init_one_server(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *xcf);

#endif /* BRIX_PROCESS_INTERNAL_H */
