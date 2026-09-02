/*
 * test_staged_contract_tiers.c — the staged_commit OWNERSHIP contract for the two
 * tier-side drivers that publish through a second stage: sd_stage (the write-stage
 * decorator) and sd_frm (nearline/tape migrate).
 *
 * CONTRACT (src/fs/vfs/vfs_staged.c; already enforced for posix by
 * test_staged_commit_contract.c, and for remote/pblock by their own comments):
 * driver->staged_commit consumes (frees) the heap handle ONLY on success. On
 * failure the handle STAYS VALID and the caller releases it with
 * driver->staged_abort — every caller does exactly that (stage_engine_move,
 * cstb_pump_and_commit in compat/staged_file_commit.c, cache fetch.c).
 *
 * Both drivers here violated it before this test existed:
 *   - sd_stage_staged_commit freed ss+st on the SYNC write-back tail even when the
 *     inline flush FAILED, and its abort then aborted an ALREADY-CONSUMED inner
 *     store handle → use-after-free + double free (twice over).
 *   - sd_frm_staged_commit freed ss+st unconditionally, so a failed MSS migrate
 *     left the caller aborting freed memory (and purging through a dangling fd).
 *
 * Hermetic: the stage store/source are fake in-test drivers with scripted
 * failures, the stage engine entry points are stubbed, and frm's adapter
 * selectors are overridden to bind a scriptable MSS. Built under ASan so the
 * pre-fix double-free aborts loudly rather than passing silently.
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/backend/stage/sd_stage_internal.h"
#include "fs/backend/frm/sd_frm.h"
#include "fs/backend/frm/sd_frm_internal.h"
#include "fs/xfer/stage_engine.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
#define CHECK(cond, msg) \
    do { if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (errno=%d %s)\n", (msg), errno, strerror(errno)); \
        failures++; \
    } } while (0)

/* ---- ngx / audit stubs reached from the linked objects -------------------- */

volatile ngx_cycle_t *ngx_cycle;

u_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) { return dst; }
    while (--n) { if ((*dst = *src) == '\0') { return dst; } dst++; src++; }
    *dst = '\0';
    return dst;
}
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...) { (void) level; (void) log; (void) err; (void) fmt; }
void brix_xfer_finish(void) { }
/* W4 C5: the tier cases never declare a size, so the frm online-buffer reserve
 * arm is dead here — satisfy the link only. */
ngx_int_t sd_posix_reserve(brix_sd_obj_t *obj, off_t size)
{ (void) obj; (void) size; return NGX_OK; }

/* sd_stage_write.c stamps write-back objects with this descriptor; the staged
 * path never dispatches through it, so an empty table satisfies the link. */
const brix_sd_driver_t brix_sd_stage_driver = { .name = "stage" };

/* ---- scriptable stage STORE driver ---------------------------------------- */

static int g_inner_commit_rc;   /* NGX_OK | NGX_ERROR returned by the store   */
static int g_inner_live;        /* store handles allocated and not released   */
static int g_inner_aborts;      /* store staged_abort calls                   */
static int g_store_unlinks;     /* stage-buffer drops (success path only)     */

static brix_sd_staged_t *
fake_store_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, off_t declared_size, int *err_out)
{
    brix_sd_staged_t *h = calloc(1, sizeof(*h));

    (void) final_path; (void) mode; (void) declared_size;
    if (h == NULL) { if (err_out) { *err_out = ENOMEM; } return NULL; }
    h->inst  = inst;
    h->state = calloc(1, 16);            /* a real allocation ASan can track */
    g_inner_live++;
    return h;
}

static ngx_int_t
fake_store_staged_commit(brix_sd_staged_t *st, brix_sd_precond_t *pre)
{
    (void) pre;
    if (g_inner_commit_rc != NGX_OK) {
        errno = EIO;                     /* contract: handle left VALID */
        return NGX_ERROR;
    }
    free(st->state);
    free(st);
    g_inner_live--;
    return NGX_OK;
}

static void
fake_store_staged_abort(brix_sd_staged_t *st)
{
    g_inner_aborts++;
    free(st->state);
    free(st);
    g_inner_live--;
}

static ngx_int_t
fake_store_unlink(brix_sd_instance_t *inst, const char *path, int is_dir)
{
    (void) inst; (void) path; (void) is_dir;
    g_store_unlinks++;
    return NGX_OK;
}

static const brix_sd_driver_t fake_store_driver = {
    .name          = "fakestore",
    .unlink        = fake_store_unlink,
    .staged_open   = fake_store_staged_open,
    .staged_commit = fake_store_staged_commit,
    .staged_abort  = fake_store_staged_abort,
};

static const brix_sd_driver_t fake_source_driver = { .name = "fakesource" };

/* ---- stage-engine stubs (the flush that sd_stage_staged_commit drives) ----- */

static ngx_int_t g_flush_rc;
static int       g_flush_calls;
static int       g_submit_calls;

ngx_int_t
brix_stage_run_inline_cred(brix_stage_kind_t kind, brix_sd_instance_t *src,
    const char *src_key, brix_sd_instance_t *dst, const char *dst_key,
    const brix_stage_cred_t *cred)
{
    (void) kind; (void) src; (void) src_key; (void) dst; (void) dst_key;
    (void) cred;
    g_flush_calls++;
    if (g_flush_rc != NGX_OK) { errno = EIO; }
    return g_flush_rc;
}

const char *
brix_stage_submit(brix_stage_kind_t kind, brix_sd_instance_t *src,
    const char *src_key, brix_sd_instance_t *dst, const char *dst_key,
    const brix_stage_opts_t *opts)
{
    (void) kind; (void) src; (void) src_key; (void) dst; (void) dst_key;
    (void) opts;
    g_submit_calls++;
    return "";
}

/* ---- scriptable frm MSS adapter (bound in place of the built-in stub) ------ */

static int g_migrate_rc;
static int g_migrates;
static int g_purges;

static int mss_migrate(void *mss, const char *key)
{
    (void) mss; (void) key;
    g_migrates++;
    return g_migrate_rc;
}
static int mss_purge(void *mss, const char *key)
{
    (void) mss; (void) key;
    g_purges++;
    return 0;
}
static int mss_create_online(void *mss, const char *key, mode_t mode)
{
    (void) mss; (void) key; (void) mode;
    return open("/dev/null", O_WRONLY);
}
static void mss_destroy(void *mss) { (void) mss; }

static const brix_mss_adapter_t fake_mss = {
    .name          = "faketape",
    .migrate       = mss_migrate,
    .purge         = mss_purge,
    .create_online = mss_create_online,
    .destroy       = mss_destroy,
};

int frm_select_lib_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log)
{
    (void) st; (void) adapter; (void) location; (void) log;
    return 0;                     /* declined: st->mss stays NULL, try the next */
}
int frm_select_exec_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log)
{
    (void) st; (void) adapter; (void) location; (void) log;
    return 0;                                              /* declined likewise */
}
int frm_select_stub_adapter(sd_frm_state *st, const char *adapter,
    const char *location, ngx_log_t *log)
{
    (void) adapter; (void) location;
    st->mss     = &fake_mss;
    st->mss_ctx = NULL;
    st->log     = log;
    return 0;
}

/* ---- sd_stage arms -------------------------------------------------------- */

static void
stage_reset(int inner_rc, ngx_int_t flush_rc)
{
    g_inner_commit_rc = inner_rc;
    g_flush_rc        = flush_rc;
    g_inner_live = g_inner_aborts = g_store_unlinks = 0;
    g_flush_calls = g_submit_calls = 0;
}

static void
run_stage_arms(void)
{
    brix_sd_instance_t  store, source, stage;
    sd_stage_inst_state is;

    memset(&store, 0, sizeof store);
    memset(&source, 0, sizeof source);
    memset(&stage, 0, sizeof stage);
    memset(&is, 0, sizeof is);
    store.driver  = &fake_store_driver;
    source.driver = &fake_source_driver;
    is.source     = &source;
    is.store      = &store;
    stage.driver  = &brix_sd_stage_driver;
    stage.state   = &is;

    /* A. SYNC success — the flush lands, the stage buffer copy is dropped, and
     *    the handle is consumed exactly once (no abort may follow). */
    {
        int                err = 0;
        brix_sd_staged_t *h;

        is.policy.flush_mode = BRIX_WT_MODE_SYNC;
        stage_reset(NGX_OK, NGX_OK);
        h = sd_stage_staged_open(&stage, "/obj_ok", 0644, 0, &err);
        CHECK(h != NULL, "stage staged_open (sync ok)");
        if (h != NULL) {
            CHECK(sd_stage_staged_commit(h, NULL) == NGX_OK, "sync commit succeeds");
            CHECK(g_flush_calls == 1, "sync commit flushes exactly once");
            CHECK(g_store_unlinks == 1, "stage buffer dropped after a good flush");
            CHECK(g_inner_live == 0, "inner handle consumed by its own commit");
        }
    }

    /* B. SYNC flush FAILURE — the regression. The commit must report failure and
     *    LEAVE the handle valid; the caller's mandatory abort then releases it
     *    exactly once, and must NOT re-abort the inner handle the store's commit
     *    already consumed. Pre-fix this was a UAF plus two double-frees. */
    {
        int                err = 0;
        brix_sd_staged_t *h;

        is.policy.flush_mode = BRIX_WT_MODE_SYNC;
        stage_reset(NGX_OK, NGX_ERROR);
        h = sd_stage_staged_open(&stage, "/obj_flushfail", 0644, 0, &err);
        CHECK(h != NULL, "stage staged_open (flush-fail)");
        if (h != NULL) {
            CHECK(sd_stage_staged_commit(h, NULL) != NGX_OK,
                  "a failed inline flush must fail the commit");
            CHECK(g_store_unlinks == 0,
                  "stage buffer KEPT for retry when the flush failed");
            sd_stage_staged_abort(h);           /* must not UAF / double free */
            CHECK(g_inner_aborts == 0,
                  "abort must not re-abort the already-published inner handle");
            CHECK(g_inner_live == 0, "no inner handle left outstanding");
        }
    }

    /* C. INNER (stage store) commit failure — nothing was published, so the
     *    handle including its inner slot stays valid for the abort. SECURITY-
     *    NEGATIVE: a stage publish that failed must never push bytes onward to
     *    the backend, so the flush must not have run at all. */
    {
        int                err = 0;
        brix_sd_staged_t *h;

        is.policy.flush_mode = BRIX_WT_MODE_SYNC;
        stage_reset(NGX_ERROR, NGX_OK);
        h = sd_stage_staged_open(&stage, "/obj_innerfail", 0644, 0, &err);
        CHECK(h != NULL, "stage staged_open (inner-fail)");
        if (h != NULL) {
            CHECK(sd_stage_staged_commit(h, NULL) != NGX_OK,
                  "a failed store publish must fail the commit");
            CHECK(g_flush_calls == 0,
                  "SECURITY: no flush to the backend after a failed publish");
            sd_stage_staged_abort(h);
            CHECK(g_inner_aborts == 1,
                  "abort releases the unpublished inner handle exactly once");
            CHECK(g_inner_live == 0, "no inner handle left outstanding");
        }
    }

    /* D. ASYNC write-back — durable on the store, so the commit succeeds
     *    immediately, hands the flush to the scheduler and consumes the handle. */
    {
        int                err = 0;
        brix_sd_staged_t *h;

        is.policy.flush_mode = BRIX_WT_MODE_ASYNC;
        stage_reset(NGX_OK, NGX_OK);
        h = sd_stage_staged_open(&stage, "/obj_async", 0644, 0, &err);
        CHECK(h != NULL, "stage staged_open (async)");
        if (h != NULL) {
            CHECK(sd_stage_staged_commit(h, NULL) == NGX_OK, "async commit succeeds");
            CHECK(g_submit_calls == 1, "async commit queues exactly one flush");
            CHECK(g_flush_calls == 0, "async commit does not flush inline");
            CHECK(g_store_unlinks == 0,
                  "async keeps the stage copy until the scheduler drains it");
        }
    }
}

/* ---- sd_frm arms ---------------------------------------------------------- */

static void
run_frm_arms(void)
{
    brix_sd_instance_t *inst = brix_sd_frm_create("stub", "/tmp", NULL);

    CHECK(inst != NULL, "brix_sd_frm_create");
    if (inst == NULL) { return; }

    /* E. migrate FAILURE — the regression: report failure WITHOUT freeing, so
     *    the caller's abort releases the still-valid handle exactly once. */
    {
        int                err = 0;
        brix_sd_staged_t *h;

        g_migrate_rc = -1;
        g_migrates = g_purges = 0;
        h = inst->driver->staged_open(inst, "/tape_fail", 0644, 0, &err);
        CHECK(h != NULL, "frm staged_open (migrate-fail)");
        if (h != NULL) {
            CHECK(inst->driver->staged_write(h, "x", 1, 0) == 1, "frm staged_write");
            CHECK(inst->driver->staged_commit(h, NULL) != NGX_OK,
                  "a failed migrate must fail the commit");
            inst->driver->staged_abort(h);      /* must not UAF / double free */
            CHECK(g_migrates == 1 && g_purges == 1,
                  "one migrate attempt, one purge of the online buffer");
        }
    }

    /* F. migrate SUCCESS — published to tape and the handle consumed exactly
     *    once (no abort may follow), with no stray purge of the live object. */
    {
        int                err = 0;
        brix_sd_staged_t *h;

        g_migrate_rc = 0;
        g_migrates = g_purges = 0;
        h = inst->driver->staged_open(inst, "/tape_ok", 0644, 0, &err);
        CHECK(h != NULL, "frm staged_open (ok)");
        if (h != NULL) {
            CHECK(inst->driver->staged_commit(h, NULL) == NGX_OK,
                  "a clean migrate must succeed");
            CHECK(g_migrates == 1 && g_purges == 0,
                  "published object is not purged from the online buffer");
        }
    }
    brix_sd_frm_destroy(inst);
}

int main(void)
{
    run_stage_arms();
    run_frm_arms();

    if (failures) { fprintf(stderr, "%d check(s) failed\n", failures); return 1; }
    printf("sd_stage + sd_frm staged-commit ownership contract: PASS\n");
    return 0;
}
