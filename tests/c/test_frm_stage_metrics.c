/*
 * test_frm_stage_metrics.c — O-1: the durable stage-request registry lifecycle
 * writes the brix_frm_* tape-stage counters.
 *
 * Prior to phase-92 the BRIX_FRM_METRIC_* macros had ZERO callsites, so every
 * brix_frm_* series the exporter (frm_metrics.c) publishes was frozen at 0. This
 * unit installs a fake metrics SHM zone (ngx_brix_shm_zone->data pointing at a
 * stack ngx_brix_metrics_t), drives a real on-disk registry through its admit /
 * set-status / delete lifecycle, and asserts the counters move exactly once per
 * transition:
 *   success:      add            -> requests_total++, in_flight++
 *                 set_status DONE -> stage_success_total++, in_flight--, latency++
 *   error:        set_status FAILED -> stage_fail_total[OTHER]++, in_flight--
 *   security-neg: set_status/delete on an UNKNOWN reqid, and a repeated terminal
 *                 set_status, leave every counter untouched (no gauge underflow,
 *                 no double count); a NULL SHM zone is a safe no-op (no crash).
 *
 * The registry substrate routes its file I/O through the POSIX Storage-Driver
 * seam (brix_sd_posix_wrap -> obj->driver->pread/pwrite), so we supply a minimal
 * brix_sd_posix_driver whose pread/pwrite slots are plain positioned syscalls —
 * enough for the durable store, without dragging in the full backend closure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/xfer/stage_request_registry.h"
#include "observability/metrics/metrics.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- test doubles --------------------------------------------------------- */

/* Minimal POSIX SD driver: the registry only ever reaches obj->fd via
 * pread/pwrite, so those two slots over the plain fd are sufficient. */
static ssize_t
stub_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    return pread(obj->fd, buf, len, off);
}

static ssize_t
stub_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    return pwrite(obj->fd, buf, len, off);
}

const brix_sd_driver_t brix_sd_posix_driver = {
    .name   = "posix",
    .pread  = stub_pread,
    .pwrite = stub_pwrite,
};

/* nginx runtime doubles pulled in by the registry substrate. */
ngx_pid_t ngx_pid = 4242;
volatile ngx_cycle_t *ngx_cycle = NULL;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/* ngx_string.o references these but the registry hot path never calls them. */
void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) log;
    return malloc(size);
}

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool; (void) size;
    abort();
}

/* The metrics SHM zone the FRM macros resolve through brix_metrics_shared(). */
ngx_shm_zone_t *ngx_brix_shm_zone = NULL;

/* ---- helpers -------------------------------------------------------------- */

static ngx_brix_metrics_t   g_metrics;
static ngx_shm_zone_t       g_zone;

static unsigned long
frm_u(ngx_atomic_t *c)
{
    return (unsigned long) *c;
}

int
main(void)
{
    char                       dir[] = "/tmp/brix_frm_metrics.XXXXXX";
    char                       reqid_a[BRIX_STAGE_REQID_LEN];
    char                       reqid_b[BRIX_STAGE_REQID_LEN];
    brix_stage_request_view_t  view;
    brix_stage_registry_t     *reg;

    assert(mkdtemp(dir) != NULL);

    /* Phase A — NULL SHM zone: the macros must be a safe no-op (no crash) and the
     * admit still succeeds. Do this BEFORE installing the fake zone so this
     * request's in_flight is never accounted and cannot skew later gauge math. */
    assert(ngx_brix_shm_zone == NULL);
    assert(brix_stage_registry_init(dir, NULL) == NGX_OK);
    reg = brix_stage_registry_singleton();
    assert(reg != NULL);

    memset(&view, 0, sizeof(view));
    view.lfn = "/data/anon_before_zone";
    assert(brix_stage_request_add(reg, &view, reqid_a, sizeof(reqid_a), NULL)
           == NGX_OK);
    /* park it terminal while still unmetered so it never transitions later */
    assert(brix_stage_request_set_status(reg, reqid_a, BRIX_STAGE_REQ_DONE, NULL)
           == NGX_OK);

    /* Install the fake metrics zone. */
    memset(&g_metrics, 0, sizeof(g_metrics));
    memset(&g_zone, 0, sizeof(g_zone));
    g_zone.data = &g_metrics;
    ngx_brix_shm_zone = &g_zone;

    /* Phase B — success: admit then complete ONLINE. */
    memset(&view, 0, sizeof(view));
    view.lfn = "/data/recall_ok";
    assert(brix_stage_request_add(reg, &view, reqid_a, sizeof(reqid_a), NULL)
           == NGX_OK);
    assert(frm_u(&g_metrics.frm.requests_total) == 1);
    assert(frm_u(&g_metrics.frm.in_flight) == 1);

    assert(brix_stage_request_set_status(reg, reqid_a, BRIX_STAGE_REQ_DONE, NULL)
           == NGX_OK);
    assert(frm_u(&g_metrics.frm.stage_success_total) == 1);
    assert(frm_u(&g_metrics.frm.in_flight) == 0);
    assert(frm_u(&g_metrics.frm.stage_latency_count) == 1);
    /* fresh admission lands in the <=1s bucket (added==now) */
    assert(frm_u(&g_metrics.frm.stage_latency_bucket[0]) == 1);

    /* Phase C — error: admit then FAIL. */
    memset(&view, 0, sizeof(view));
    view.lfn = "/data/recall_fail";
    assert(brix_stage_request_add(reg, &view, reqid_b, sizeof(reqid_b), NULL)
           == NGX_OK);
    assert(frm_u(&g_metrics.frm.requests_total) == 2);
    assert(frm_u(&g_metrics.frm.in_flight) == 1);

    assert(brix_stage_request_set_status(reg, reqid_b, BRIX_STAGE_REQ_FAILED,
                                         NULL) == NGX_OK);
    assert(frm_u(&g_metrics.frm.stage_fail_total[BRIX_FRM_FAIL_OTHER]) == 1);
    assert(frm_u(&g_metrics.frm.in_flight) == 0);
    /* a failure is NOT a success and books no latency sample */
    assert(frm_u(&g_metrics.frm.stage_success_total) == 1);
    assert(frm_u(&g_metrics.frm.stage_latency_count) == 1);

    /* Phase D — security-neg / idempotency: nothing must move. */
    {
        ngx_brix_frm_metrics_t before = g_metrics.frm;

        /* unknown reqid: set_status DECLINES, delete is a benign no-op */
        assert(brix_stage_request_set_status(reg, "0.0@nohost",
                   BRIX_STAGE_REQ_DONE, NULL) == NGX_DECLINED);
        assert(brix_stage_request_delete(reg, "0.0@nohost", NULL) == NGX_OK);

        /* repeated terminal set_status on an already-ONLINE record: the OLD-status
         * guard keeps the gauge and success counter from double-moving */
        assert(brix_stage_request_set_status(reg, reqid_a,
                   BRIX_STAGE_REQ_DONE, NULL) == NGX_OK);

        assert(memcmp(&before, &g_metrics.frm, sizeof(before)) == 0);
    }

    printf("test_frm_stage_metrics: ALL PASS\n");
    return 0;
}
