/*
 * process_stage_retry.c — 2.0 F1 (ADR-3b): apply the process-wide stage
 * engine settings the brix_frm_* directives publish, and arm the worker-0
 * brix_frm_fail_backoff retry sweep.
 *
 * WHAT: brix_stage_engine_conf_apply() turns the merge-time snapshot
 *       (brix_frm_engine_conf) into the engine's runtime state: it creates the
 *       brix_frm_queue_path journal directory, installs brix_frm_copymax /
 *       brix_frm_fail_retries as the engine limits and returns the journal dir
 *       to init the engine with, and opens the brix_frm_stagemsg StageEvents
 *       feed (2.0 F2, stage_events.c). brix_init_stage_retry_timer() arms a worker-0
 *       timer that re-drives FAILED journal records every
 *       brix_frm_fail_backoff (a record that keeps failing is dead-lettered at
 *       brix_frm_fail_retries attempts).
 *
 * WHY:  Until 2.0 those knobs were parsed and merged but never read; the
 *       engine was driven by $BRIX_STAGE_JOURNAL_DIR and compile-time
 *       constants, and a FAILED record was only re-driven by a restart. The
 *       directives now own the engine (ADR-3b in phase-89 §D.1); the env var
 *       stays as the fallback when no `brix_frm on` server publishes.
 *
 * HOW:  1. No published snapshot -> NULL (caller falls back to the env var);
 *          the retry timer stays unarmed so env-only journals keep their
 *          restart-only re-drive semantics.
 *       2. mkdir(queue_path, 0700), EEXIST ok; ERR + NULL (in-memory engine)
 *          on any other failure — a broken tape config must not take the
 *          worker down.
 *       3. Timer period = max(fail_backoff, BRIX_FRM_FAIL_BACKOFF_MIN_MS),
 *          first tick after brix_cache_reap_delay(); each tick sweeps records
 *          older than the period and re-arms unless exiting.
 */

#include "config.h"
#include "process_internal.h"
#include "core/config/tape_stage_conf.h"  /* brix_frm_engine_conf */
#include "fs/xfer/stage_engine.h"          /* brix_stage_engine_* + retry sweep */
#include "fs/xfer/stage_events.h"          /* 2.0 F2 StageEvents feed */

#include <errno.h>
#include <sys/stat.h>

typedef struct {
    ngx_event_t  ev;
    ngx_msec_t   period_ms;
} brix_stage_retry_timer_t;

const char *
brix_stage_engine_conf_apply(ngx_cycle_t *cycle)
{
    const brix_frm_engine_conf_t *fe = brix_frm_engine_conf(cycle);

    if (fe == NULL) {
        return NULL;
    }
    brix_stage_engine_set_limits(fe->copymax, fe->fail_retries);
    if (fe->stagemsg[0] != '\0'
        && brix_stage_events_open(fe->stagemsg, cycle->log) == NGX_OK)
    {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "brix: stage engine: StageEvents feed \"%s\"",
                      fe->stagemsg);
    }
    if (fe->queue_path[0] == '\0') {
        return NULL;                         /* unreachable: brix_frm on demands it */
    }
    if (mkdir(fe->queue_path, BRIX_CRED_STAGE_DIR_MODE) != 0 && errno != EEXIST) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, errno,
            "brix: brix_frm_queue_path \"%s\": mkdir failed; the stage "
            "journal is in-memory only (no restart recovery)", fe->queue_path);
        return NULL;
    }
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
        "brix: stage engine: journal=\"%s\" copymax=%ui fail_retries=%ui "
        "fail_backoff=%M ms copy_timeout=%M ms",
        fe->queue_path, fe->copymax, fe->fail_retries, fe->fail_backoff_ms,
        fe->copy_timeout_ms);
    return fe->queue_path;
}

static void
brix_stage_retry_tick(ngx_event_t *ev)
{
    brix_stage_retry_timer_t *t = ev->data;

    (void) brix_stage_retry_sweep(t->period_ms / 1000, ev->log);
    if (!ngx_exiting) {
        ngx_add_timer(ev, t->period_ms);
    }
}

ngx_int_t
brix_init_stage_retry_timer(ngx_cycle_t *cycle)
{
    const brix_frm_engine_conf_t *fe = brix_frm_engine_conf(cycle);
    brix_stage_retry_timer_t     *t;

    if (fe == NULL || ngx_worker != 0
        || brix_stage_engine_journal_dir()[0] == '\0')
    {
        return NGX_OK;
    }
    t = ngx_pcalloc(cycle->pool, sizeof(*t));
    if (t == NULL) {
        return NGX_ERROR;
    }
    t->period_ms = fe->fail_backoff_ms;
    if (t->period_ms < BRIX_FRM_FAIL_BACKOFF_MIN_MS) {
        t->period_ms = BRIX_FRM_FAIL_BACKOFF_MIN_MS;
    }
    t->ev.handler    = brix_stage_retry_tick;
    t->ev.data       = t;
    t->ev.log        = cycle->log;
    t->ev.cancelable = 1;                      /* don't delay graceful shutdown */
    ngx_add_timer(&t->ev, brix_cache_reap_delay(t->period_ms));

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
        "brix: stage retry sweep armed (brix_frm_fail_backoff=%M ms, "
        "brix_frm_fail_retries=%ui)", t->period_ms, fe->fail_retries);
    return NGX_OK;
}
