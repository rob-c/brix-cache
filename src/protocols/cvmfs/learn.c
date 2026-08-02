/* learn.c — phase-87 G11: workload-learned predictive prewarm.
 *
 * WHAT: a passive per-worker Markov model of CAS access sequences ("a GET of
 *       X on this connection is followed by Y"), and an advisory prewarm
 *       that fills the predicted successors through the cache-fill seam
 *       before they are requested.
 * WHY:  batch workloads open the same working set in the same order on every
 *       job (loader → catalog → the same .so chain); after one warm pass the
 *       proxy can hide the origin RTT of the NEXT job's cold misses entirely.
 *       This is the *policy* layer over the fill machinery's *mechanism* —
 *       it never invents a transfer path of its own.
 * HOW:  registration mirrors the G17 scrub (config-time per-process statics,
 *       per-worker context at init_process — but EVERY worker, the model is
 *       request-stream-local and workers see disjoint connections). The
 *       request path calls brix_cvmfs_learn_note() on each classified CAS
 *       GET: it records the connection's previous-key → this-key transition
 *       into a fixed-size successor table, then looks this key up and posts
 *       one bounded batch of confident (count >= 2), non-resident successors
 *       to the thread pool, where brix_sd_cache_fill_key() runs the ordinary
 *       verified fill (source → store + cinfo). One task in flight per
 *       export, a per-second rate cap, and a full-table overwrite policy
 *       keep it O(1) memory and immune to mispredict storms: an
 *       unrecognized access matches no node and prewarms nothing.
 *
 *       PRIVACY / CARDINALITY (INVARIANT #8): the model holds CAS keys,
 *       connection numbers and small counts — never an Authorization value,
 *       token, DN or any per-user content. Predictions learned from one
 *       client's connection fire for every later client; the profile is a
 *       property of the WORKLOAD, not the user. No metrics are emitted —
 *       observability is two log lines (DEBUG on post, INFO on completion).
 */
#include "cvmfs.h"
#include "classify.h"
#include "core/aio/aio.h"                  /* brix_task_bind */
#include "core/fnv.h"
#include "fs/backend/cache/sd_cache.h"     /* fill seam + cstore accessor */
#include "fs/cache/cstore.h"
#include "fs/cache/cinfo.h"

#include <string.h>

#define CVMFS_LEARN_MAX_EXPORTS 8
#define CVMFS_LEARN_KEY_MAX     192        /* CAS keys are ~60 bytes        */
#define CVMFS_LEARN_CONN_SLOTS  64         /* connection → last-key table   */
#define CVMFS_LEARN_NODES       256        /* predecessor hash → successors */
#define CVMFS_LEARN_SUCC        3          /* successors kept per node      */
#define CVMFS_LEARN_MIN_COUNT   2          /* observations before a prewarm */
#define CVMFS_LEARN_BATCH       4          /* keys per posted fill task     */
#define CVMFS_LEARN_RATE        8          /* prewarm fills per second      */

/* Config-time registration (per-process statics; written by the master's
 * config parse, read at worker init — the RTT-probe/scrub lifecycle). */
typedef struct {
    char  root[256];
    char  pool[64];
} cvmfs_learn_reg_t;

static cvmfs_learn_reg_t  cvmfs_learn_regs[CVMFS_LEARN_MAX_EXPORTS];
static ngx_uint_t         cvmfs_learn_regs_n;

void
brix_cvmfs_learn_register(const char *root_canon, const ngx_str_t *pool_name)
{
    ngx_uint_t         i;
    cvmfs_learn_reg_t *reg = NULL;

    for (i = 0; i < cvmfs_learn_regs_n; i++) {
        if (ngx_strcmp(cvmfs_learn_regs[i].root, root_canon) == 0) {
            reg = &cvmfs_learn_regs[i];        /* reload: update in place */
            break;
        }
    }
    if (reg == NULL) {
        if (cvmfs_learn_regs_n >= CVMFS_LEARN_MAX_EXPORTS
            || ngx_strlen(root_canon) >= sizeof(reg->root))
        {
            return;
        }
        reg = &cvmfs_learn_regs[cvmfs_learn_regs_n++];
    }
    ngx_cpystrn((u_char *) reg->root, (u_char *) root_canon,
                sizeof(reg->root));
    reg->pool[0] = '\0';
    if (pool_name != NULL && pool_name->len > 0
        && pool_name->len < sizeof(reg->pool))
    {
        ngx_memcpy(reg->pool, pool_name->data, pool_name->len);
        reg->pool[pool_name->len] = '\0';
    }
}

/* ---- per-worker model + prewarm task ------------------------------------ */

typedef struct {
    uint64_t  conn;                        /* connection number (0 = free)  */
    char      key[CVMFS_LEARN_KEY_MAX];    /* last CAS key seen on it       */
} cvmfs_learn_conn_t;

typedef struct {
    char      key[CVMFS_LEARN_KEY_MAX];
    uint16_t  count;
} cvmfs_learn_succ_t;

typedef struct {
    uint64_t            hash;              /* FNV-1a64 of the predecessor   */
    unsigned            used:1;
    cvmfs_learn_succ_t  succ[CVMFS_LEARN_SUCC];
} cvmfs_learn_node_t;

/* One context per registered export, embedded as its task's ctx. The busy
 * flag is set on the event loop before the post and cleared in the (event
 * loop) completion — strictly sequential, no atomics needed. */
typedef struct {
    ngx_thread_task_t        *task;
    const cvmfs_learn_reg_t  *reg;
    unsigned                  busy:1;

    /* task payload (owned by the thread while busy) */
    brix_sd_instance_t       *inst;
    ngx_uint_t                n_keys;
    ngx_uint_t                filled;
    char                      keys[CVMFS_LEARN_BATCH][CVMFS_LEARN_KEY_MAX];

    /* model (event loop only) */
    cvmfs_learn_conn_t        conns[CVMFS_LEARN_CONN_SLOTS];
    cvmfs_learn_node_t        nodes[CVMFS_LEARN_NODES];
    time_t                    rate_sec;
    ngx_uint_t                rate_n;
} cvmfs_learn_ctx_t;

static cvmfs_learn_ctx_t  *cvmfs_learn_ctxs[CVMFS_LEARN_MAX_EXPORTS];

static uint64_t
cvmfs_learn_hash(const char *s)
{
    uint64_t h = BRIX_FNV1A64_OFFSET_BASIS;

    for (; *s != '\0'; s++) {
        h = (h ^ (u_char) *s) * BRIX_FNV1A64_PRIME;
    }
    return h;
}

/* Thread-pool side: run the ordinary verified whole-file fill for each
 * predicted key (source → cache store + cinfo). A DECLINED/ERROR fill is
 * simply not counted — the prewarm is advisory and the on-demand path
 * remains the correctness authority. */
static void
cvmfs_learn_thread(void *data, ngx_log_t *log)
{
    cvmfs_learn_ctx_t *lc = data;
    ngx_uint_t         i;

    (void) log;
    for (i = 0; i < lc->n_keys; i++) {
        /* Background prewarm: service credential only (no per-user cred). */
        if (brix_sd_cache_fill_key(lc->inst, lc->keys[i], NULL) == NGX_OK) {
            lc->filled++;
        }
    }
}

static void
cvmfs_learn_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task = ev->data;
    cvmfs_learn_ctx_t *lc = task->ctx;

    lc->busy = 0;
    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
        "cvmfs-learn (export %s): prewarmed %ui/%ui predicted object(s)",
        lc->reg->root, lc->filled, lc->n_keys);
}

/* Record one observed prev → cur transition. A hash-slot collision with a
 * DIFFERENT predecessor overwrites the node (fixed memory beats a perfect
 * model — the demoted pattern just re-learns); a full successor row evicts
 * its weakest entry. */
static void
cvmfs_learn_record(cvmfs_learn_ctx_t *lc, const char *prev, const char *cur)
{
    uint64_t             h = cvmfs_learn_hash(prev);
    cvmfs_learn_node_t  *node = &lc->nodes[h % CVMFS_LEARN_NODES];
    cvmfs_learn_succ_t  *weakest;
    ngx_uint_t           i;

    if (!node->used || node->hash != h) {
        ngx_memzero(node, sizeof(*node));
        node->used = 1;
        node->hash = h;
    }
    weakest = &node->succ[0];
    for (i = 0; i < CVMFS_LEARN_SUCC; i++) {
        cvmfs_learn_succ_t *s = &node->succ[i];

        if (s->key[0] != '\0' && strcmp(s->key, cur) == 0) {
            if (s->count < 0xffff) {
                s->count++;
            }
            return;
        }
        if (s->key[0] == '\0') {           /* free slot: install fresh */
            ngx_cpystrn((u_char *) s->key, (u_char *) cur,
                        CVMFS_LEARN_KEY_MAX);
            s->count = 1;
            return;
        }
        if (s->count < weakest->count) {
            weakest = s;
        }
    }
    ngx_cpystrn((u_char *) weakest->key, (u_char *) cur,
                CVMFS_LEARN_KEY_MAX);
    weakest->count = 1;
}

/* Collect up to one batch of confident, non-resident successor keys into
 * lc->keys, honoring the per-second rate cap. Returns the batch size. */
static ngx_uint_t
cvmfs_learn_collect(cvmfs_learn_ctx_t *lc, cvmfs_learn_node_t *node,
    brix_cstore_t *cs)
{
    brix_cache_cinfo_t  ci;
    ngx_uint_t          i, n = 0;

    for (i = 0; i < CVMFS_LEARN_SUCC && n < CVMFS_LEARN_BATCH; i++) {
        cvmfs_learn_succ_t *s = &node->succ[i];

        if (s->key[0] == '\0' || s->count < CVMFS_LEARN_MIN_COUNT) {
            continue;
        }
        if (brix_cstore_cinfo_load(cs, s->key, &ci) == NGX_OK
            && (ci.flags & BRIX_CINFO_F_COMPLETE))
        {
            continue;                      /* already resident */
        }
        if (lc->rate_n >= CVMFS_LEARN_RATE) {
            break;
        }
        lc->rate_n++;
        ngx_cpystrn((u_char *) lc->keys[n], (u_char *) s->key,
                    CVMFS_LEARN_KEY_MAX);
        n++;
    }
    return n;
}

/* Resolve the prewarm thread pool (configured name or "default"). */
static ngx_thread_pool_t *
cvmfs_learn_pool(cvmfs_learn_ctx_t *lc)
{
    ngx_str_t pname;

    if (lc->reg->pool[0] != '\0') {
        pname.data = (u_char *) lc->reg->pool;
        pname.len  = ngx_strlen(lc->reg->pool);
    } else {
        ngx_str_set(&pname, "default");
    }
    return ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &pname);
}

/* Predict successors of `key` and post one bounded prewarm batch: confident
 * (count >= 2), not already cache-resident, inside the per-second rate cap,
 * one task in flight. Every miss condition is a silent no-op — this path
 * must never affect the serve that triggered it. */
static void
cvmfs_learn_predict(cvmfs_learn_ctx_t *lc, ngx_http_request_t *r,
    brix_sd_instance_t *sd, const char *key)
{
    uint64_t             h = cvmfs_learn_hash(key);
    cvmfs_learn_node_t  *node = &lc->nodes[h % CVMFS_LEARN_NODES];
    brix_cstore_t       *cs;
    ngx_thread_pool_t   *pool;
    time_t               now;
    ngx_uint_t           n;

    if (lc->busy || !node->used || node->hash != h) {
        return;
    }
    cs = brix_sd_cache_cstore(sd);
    if (cs == NULL) {
        return;
    }
    now = ngx_time();
    if (lc->rate_sec != now) {
        lc->rate_sec = now;
        lc->rate_n = 0;
    }
    n = cvmfs_learn_collect(lc, node, cs);
    if (n == 0) {
        return;
    }

    pool = cvmfs_learn_pool(lc);
    if (pool == NULL) {
        return;
    }

    lc->inst   = sd;                       /* registry-owned, worker-lifetime */
    lc->n_keys = n;
    lc->filled = 0;
    lc->busy   = 1;
    if (ngx_thread_task_post(pool, lc->task) != NGX_OK) {
        lc->busy = 0;
        return;
    }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "cvmfs-learn: %ui predicted successor(s) of \"%s\" posted "
        "for prewarm", n, key);
}

/* Request-path hook (event loop, classified CAS tier entry): learn this
 * connection's transition, then prewarm what usually follows `key`. */
void
brix_cvmfs_learn_note(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    brix_sd_instance_t *sd, const char *key)
{
    cvmfs_learn_ctx_t  *lc = NULL;
    cvmfs_learn_conn_t *cslot;
    uint64_t            conn;
    ngx_uint_t          i;

    if (lcf->cvmfs.learn != 1
        || r->method != NGX_HTTP_GET
        || ctx == NULL
        || ctx->url.cls != CVMFS_URL_CAS
        || sd == NULL
        || key == NULL
        || strlen(key) >= CVMFS_LEARN_KEY_MAX)
    {
        return;
    }
    for (i = 0; i < cvmfs_learn_regs_n; i++) {
        if (ngx_strcmp(cvmfs_learn_regs[i].root,
                       lcf->common.root_canon) == 0)
        {
            lc = cvmfs_learn_ctxs[i];
            break;
        }
    }
    if (lc == NULL) {
        return;
    }

    conn = (uint64_t) r->connection->number;
    cslot = &lc->conns[conn % CVMFS_LEARN_CONN_SLOTS];
    if (cslot->conn == conn && cslot->key[0] != '\0'
        && strcmp(cslot->key, key) != 0)
    {
        cvmfs_learn_record(lc, cslot->key, key);
    }
    cslot->conn = conn;
    ngx_cpystrn((u_char *) cslot->key, (u_char *) key,
                CVMFS_LEARN_KEY_MAX);

    cvmfs_learn_predict(lc, r, sd, key);
}

ngx_int_t
brix_cvmfs_learn_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t i;

    /* EVERY worker builds its own model (unlike the worker-0 scrub): the
     * table learns from the connections THIS worker accepts, and a fill the
     * siblings race on is serialized by the fill spine itself. */
    for (i = 0; i < cvmfs_learn_regs_n; i++) {
        ngx_thread_task_t *task;
        cvmfs_learn_ctx_t *lc;

        task = ngx_thread_task_alloc(cycle->pool, sizeof(cvmfs_learn_ctx_t));
        if (task == NULL) {
            return NGX_ERROR;
        }
        lc = task->ctx;
        lc->task = task;
        lc->reg  = &cvmfs_learn_regs[i];

        brix_task_bind(task, cvmfs_learn_thread, cvmfs_learn_done);
        task->event.log = cycle->log;

        cvmfs_learn_ctxs[i] = lc;
    }
    return NGX_OK;
}
