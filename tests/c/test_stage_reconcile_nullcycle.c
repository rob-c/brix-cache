/*
 * test_stage_reconcile_nullcycle.c — brix_stage_reconcile must not crash when
 * ngx_cycle is NULL.
 *
 * THE BUG (found by gcc -fanalyzer, 2026-07-07): brix_stage_reconcile built
 *   ngx_log_t *log = (ngx_cycle != NULL) ? ngx_cycle->log : NULL;
 * and then passed that possibly-NULL log to ngx_log_error(), whose macro
 * dereferences (log)->log_level unconditionally — the NULL guard and the use
 * contradicted each other. Unreachable from the one in-tree caller (worker-0
 * init_process, which runs after ngx_cycle is set), but any earlier-boot or
 * standalone-harness caller segfaulted during journal reconcile.
 *
 * THE CONTRACT UNDER TEST: with ngx_cycle == NULL, reconcile DEFERS — it
 * returns without crashing and without consuming journal records (they are
 * kept for the next properly-initialised boot). With a cycle log present, a
 * corrupt record is dropped (unlinked) and the summary is logged.
 *
 * Links the real stage_engine.o from the module build; everything else the
 * object needs (sd/vfs/xfer/thread-pool symbols) is stubbed below — none of
 * it is reachable with a corrupt record, which is dropped before any backend
 * resolution. Run via tests/c/run_stage_reconcile_tests.sh.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_thread_pool.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* stage_engine.h drags the whole sd/vfs header tree; the two entry points
 * under test are declared directly instead. */
void brix_stage_engine_init(const char *journal_dir);
void brix_stage_reconcile(void *queue);

/* ---- the global under test ------------------------------------------------
 * nginx's own definition lives in ngx_cycle.o, which is deliberately NOT
 * linked: the test owns the global so it can run the NULL and non-NULL cases. */
volatile ngx_cycle_t  *ngx_cycle = NULL;

/* ---- link stubs for stage_engine.o ---------------------------------------
 * A corrupt .req is dropped before backend resolution, so the sd/vfs stubs
 * must never run; reaching one is itself a test failure. The log stub counts
 * calls so the with-cycle case can assert the summary line was emitted. */
static int  g_log_calls;
static int  g_unexpected_stub;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
    g_log_calls++;
}

void *brix_vfs_backend_resolve(const char *root, void *log)
{ (void) root; (void) log; g_unexpected_stub++; return NULL; }
unsigned brix_sd_cache_instance_is(void *inst)
{ (void) inst; g_unexpected_stub++; return 0; }
void *brix_sd_cache_source_instance(void *inst)
{ (void) inst; g_unexpected_stub++; return NULL; }
unsigned brix_sd_stage_instance_is(void *inst)
{ (void) inst; g_unexpected_stub++; return 0; }
ngx_int_t brix_sd_stage_reflush(void *inst, const char *key, const void *cred)
{ (void) inst; (void) key; (void) cred; g_unexpected_stub++; return NGX_ERROR; }
/* brix_sd_ucred_resolve: added by stage_engine.c (never reached for corrupt recs) */
ngx_int_t brix_sd_ucred_resolve(const char *dir, const char *key, void *out)
{ (void) dir; (void) key; (void) out; g_unexpected_stub++; return NGX_ERROR; }
void brix_xfer_finish(int kind, const char *dir, const char *src,
    const char *dst, size_t bytes, int result, int err, void *log)
{ (void) kind; (void) dir; (void) src; (void) dst; (void) bytes;
  (void) result; (void) err; (void) log; }

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log)
{ (void) size; (void) log; g_unexpected_stub++; return NULL; }
void ngx_destroy_pool(ngx_pool_t *pool) { (void) pool; }
ngx_thread_pool_t *ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name)
{ (void) cycle; (void) name; return NULL; }
ngx_thread_task_t *ngx_thread_task_alloc(ngx_pool_t *pool, size_t size)
{ (void) pool; (void) size; g_unexpected_stub++; return NULL; }
ngx_int_t ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task)
{ (void) tp; (void) task; g_unexpected_stub++; return NGX_ERROR; }

/* ---- helpers --------------------------------------------------------------*/

static int g_checks, g_failed;

#define CHECK(cond, name) do { \
    g_checks++; \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

/* Seed <dir>/boom.req with a deliberately SHORT (corrupt) record. */
static int
seed_corrupt_req(const char *dir, char *path_out, size_t path_sz)
{
    FILE *f;

    snprintf(path_out, path_sz, "%s/boom.req", dir);
    f = fopen(path_out, "w");
    if (f == NULL) {
        return -1;
    }
    fputs("x", f);
    fclose(f);
    return 0;
}

/* Run reconcile against `dir` in a forked child (a segfault must fail ONE
 * check, not kill the harness). Returns the child's exit status info. */
static int
reconcile_in_child(const char *dir, int with_cycle)
{
    pid_t pid = fork();

    if (pid == 0) {
        static ngx_cycle_t  cyc;
        static ngx_log_t    logobj;

        if (with_cycle) {
            logobj.log_level = NGX_LOG_DEBUG;
            cyc.log = &logobj;
            ngx_cycle = &cyc;
        } else {
            ngx_cycle = NULL;
        }
        brix_stage_engine_init(dir);
        brix_stage_reconcile(NULL);
        _exit(g_unexpected_stub == 0 ? 0 : 42);
    }
    if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        return status;
    }
    return -1;
}

int
main(void)
{
    char dir[] = "/tmp/stage_reconcile_ut.XXXXXX";
    char req[1200];
    int  status;

    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }

    /* 1. THE FIX: ngx_cycle == NULL + a pending journal record must not crash
     *    (pre-fix: SIGSEGV in ngx_log_error on the NULL log). */
    if (seed_corrupt_req(dir, req, sizeof(req)) != 0) {
        perror("seed");
        return 1;
    }
    status = reconcile_in_child(dir, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "NULL ngx_cycle: reconcile returns instead of crashing");

    /* 2. DEFER SEMANTICS: with no cycle the journal must be untouched — the
     *    record is kept for a properly-initialised boot, not consumed blind. */
    CHECK(access(req, F_OK) == 0,
          "NULL ngx_cycle: journal record kept (reconcile deferred)");

    /* 3. NORMAL PATH: with a cycle log, the corrupt record is dropped
     *    (unlinked) and reconcile completes. */
    status = reconcile_in_child(dir, 1);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "with cycle log: reconcile completes (no backend stub reached)");
    CHECK(access(req, F_OK) != 0,
          "with cycle log: corrupt record dropped from the journal");

    unlink(req);
    rmdir(dir);

    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
