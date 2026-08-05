/*
 * test_stage_bearer_thread.c — token write-back bearer-threading unit test.
 *
 * WHAT: Drives the REAL stage_engine_run (via brix_stage_run_inline_cred, the
 *       sync inline FLUSH the WebDAV/https whole-object gateway uses) over a mock
 *       source + destination SD driver and asserts three things:
 *         success  — a brix_stage_cred_t carrying a live WLCG bearer causes the
 *                    destination's staged_open_cred to receive a brix_sd_cred_t
 *                    whose ->bearer is that exact token (and ->x509_proxy NULL):
 *                    the deferred commit authenticates to the origin AS the end
 *                    user, closing the token+https write-back gap;
 *         error    — an empty credential (no key, no bearer) flushes under the
 *                    SERVICE identity: the cred-scoped open slot is never taken,
 *                    so no token is presented (no accidental promotion);
 *         sec-neg  — a key-only (x509-store) credential with NO bearer never
 *                    presents a bearer — the x509 and token paths stay disjoint.
 *
 * WHY:  The gap was that brix_stage_cred_t (the staged-commit flush identity) had
 *       no bearer slot, so the out-of-request commit went anonymous. This pins the
 *       fix at the seam that actually carries the token to the backend driver.
 *
 * HOW:  Mock drivers implement only the ops the mover touches (src open/pread/
 *       close; dst staged_open/_cred/write/commit/abort). The dst staged_open_cred
 *       records the cred it is handed into file-scoped globals the test inspects.
 *       The four externals stage_engine.o pulls in are stubbed (never exercised on
 *       the bearer path). Built and run by the `stage_bearer_thread` C-regression
 *       runner.
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/xfer/stage_engine.h"
#include "fs/xfer/xfer.h"            /* brix_xfer_finish prototype (stubbed) */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- externals stage_engine.o references but the bearer path never calls ---- */
ngx_int_t brix_sd_ucred_resolve(const char *dir, const char *key, void *out)
{ (void) dir; (void) key; (void) out; return NGX_ERROR; }
void brix_sd_ucred_wipe(void *cred) { (void) cred; }
void brix_xfer_finish(brix_xfer_kind_t kind, const char *direction,
    const char *path, const char *principal, size_t bytes,
    brix_xfer_result_t result, int sys_errno, ngx_log_t *log)
{ (void) kind; (void) direction; (void) path; (void) principal; (void) bytes;
  (void) result; (void) sys_errno; (void) log; }
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...) { (void) level; (void) log; (void) err; (void) fmt; }

/* ---- what the destination's cred-scoped open observed --------------------- */
static int   g_cred_open_calls;     /* staged_open_cred invocations            */
static int   g_plain_open_calls;    /* plain staged_open invocations           */
static char  g_seen_bearer[4096];   /* bearer the backend was handed ("" none) */
static int   g_seen_x509_null;      /* 1 iff ->x509_proxy was NULL             */

static void
capture_reset(void)
{
    g_cred_open_calls  = 0;
    g_plain_open_calls = 0;
    g_seen_bearer[0]   = '\0';
    g_seen_x509_null   = 0;
}

/* ---- mock SOURCE driver (stage store) ------------------------------------- */
static ssize_t
mock_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    (void) obj;
    if (off == 0 && len >= 5) {          /* one 5-byte granule, then EOF */
        memcpy(buf, "hello", 5);
        return 5;
    }
    return 0;
}
static ngx_int_t mock_src_close(brix_sd_obj_t *obj) { (void) obj; return NGX_OK; }
static brix_sd_obj_t *
mock_src_open(brix_sd_instance_t *inst, const char *path, int flags, mode_t mode,
    int *err)
{
    brix_sd_obj_t *o = calloc(1, sizeof(*o));
    (void) path; (void) flags; (void) mode;
    o->driver     = inst->driver;
    o->inst       = inst;
    o->snap.mode  = 0644;
    o->heap_shell = 1;                   /* release() frees it */
    if (err != NULL) { *err = 0; }
    return o;
}

/* ---- mock DEST driver (backend) ------------------------------------------- */
static ssize_t
mock_staged_write(brix_sd_staged_t *st, const void *buf, size_t len, off_t off)
{ (void) st; (void) buf; (void) off; return (ssize_t) len; }
static ngx_int_t
mock_staged_commit(brix_sd_staged_t *st, int noreplace)
{ (void) noreplace; free(st); return NGX_OK; }
static void mock_staged_abort(brix_sd_staged_t *st) { free(st); }

static brix_sd_staged_t *
mock_staged_open(brix_sd_instance_t *inst, const char *final_path, mode_t mode,
    int *err)
{
    brix_sd_staged_t *h = calloc(1, sizeof(*h));
    (void) final_path; (void) mode;
    g_plain_open_calls++;
    h->inst = inst;
    if (err != NULL) { *err = 0; }
    return h;
}
static brix_sd_staged_t *
mock_staged_open_cred(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, const brix_sd_cred_t *cred, int *err)
{
    brix_sd_staged_t *h = calloc(1, sizeof(*h));
    (void) final_path; (void) mode;
    g_cred_open_calls++;
    if (cred != NULL && cred->bearer != NULL) {
        snprintf(g_seen_bearer, sizeof(g_seen_bearer), "%s", cred->bearer);
    }
    g_seen_x509_null = (cred == NULL || cred->x509_proxy == NULL);
    h->inst = inst;
    if (err != NULL) { *err = 0; }
    return h;
}

static brix_sd_driver_t g_src_driver;
static brix_sd_driver_t g_dst_driver;

static void
drivers_init(void)
{
    memset(&g_src_driver, 0, sizeof(g_src_driver));
    g_src_driver.name  = "mock-src";
    g_src_driver.open  = mock_src_open;
    g_src_driver.pread = mock_pread;
    g_src_driver.close = mock_src_close;

    memset(&g_dst_driver, 0, sizeof(g_dst_driver));
    g_dst_driver.name             = "mock-dst";
    g_dst_driver.staged_open      = mock_staged_open;
    g_dst_driver.staged_open_cred = mock_staged_open_cred;
    g_dst_driver.staged_write     = mock_staged_write;
    g_dst_driver.staged_commit    = mock_staged_commit;
    g_dst_driver.staged_abort     = mock_staged_abort;
}

static ngx_log_t g_log;             /* log_level 0 → ngx_log_error suppresses */

static ngx_int_t
run_flush(const brix_stage_cred_t *cred)
{
    brix_sd_instance_t src, dst;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    src.driver = &g_src_driver;
    dst.driver = &g_dst_driver;
    src.log = &g_log;               /* real callers always pass a valid log */
    dst.log = &g_log;
    return brix_stage_run_inline_cred(BRIX_STAGE_FLUSH, &src, "obj", &dst, "obj",
                                      cred);
}

int
main(void)
{
    static const char TOKEN[] = "eyJhbGciOi.ALICE-BEARER.sig";

    drivers_init();

    /* SUCCESS: a bearer cred → backend cred-open sees the exact token, x509 NULL */
    {
        brix_stage_cred_t cred;
        memset(&cred, 0, sizeof(cred));
        snprintf(cred.key, sizeof(cred.key), "tok-alice");
        snprintf(cred.principal, sizeof(cred.principal), "alice");
        snprintf(cred.bearer, sizeof(cred.bearer), "%s", TOKEN);

        capture_reset();
        assert(run_flush(&cred) == NGX_OK);
        assert(g_cred_open_calls == 1);
        assert(g_plain_open_calls == 0);
        assert(strcmp(g_seen_bearer, TOKEN) == 0);
        assert(g_seen_x509_null == 1);
        printf("ok bearer_threaded_to_backend\n");
    }

    /* ERROR/service: empty cred → plain (service) open, no token presented */
    {
        brix_stage_cred_t cred;
        memset(&cred, 0, sizeof(cred));      /* no key, no bearer */

        capture_reset();
        assert(run_flush(&cred) == NGX_OK);
        assert(g_cred_open_calls == 0);      /* cred-scoped slot NOT taken */
        assert(g_plain_open_calls == 1);
        assert(g_seen_bearer[0] == '\0');
        printf("ok empty_cred_uses_service\n");
    }

    /* SEC-NEG: x509-store cred (key set, NO bearer) presents no bearer — the
     * token and proxy paths stay disjoint. brix_sd_ucred_resolve is stubbed to
     * fail and deny=0, so the mover falls back to the service credential (plain
     * open) — critically WITHOUT a bearer. */
    {
        brix_stage_cred_t cred;
        memset(&cred, 0, sizeof(cred));
        snprintf(cred.key, sizeof(cred.key), "x5h-alice");   /* x509, no bearer */
        snprintf(cred.dir, sizeof(cred.dir), "/nonexistent");

        capture_reset();
        assert(run_flush(&cred) == NGX_OK);
        assert(g_seen_bearer[0] == '\0');    /* never a bearer on the x509 path */
        printf("ok x509_path_presents_no_bearer\n");
    }

    printf("PASS test_stage_bearer_thread\n");
    return 0;
}
