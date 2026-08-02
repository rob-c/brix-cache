/* scrub.c — phase-87 G17: background CAS integrity scrubbing (self-healing).
 *
 * WHAT: a repeating worker-0 timer walks the cvmfs cache store in bounded
 *       windows and re-runs the cvmfs-cas verify (name-hash == byte-hash) on
 *       resident CAS objects; a mismatch is evicted so the next access
 *       re-fills verified from the origin.
 * WHY:  the fill-time verify proves the bytes ONCE; disk bitrot after commit
 *       would then be served forever (the CAS client rejects it, but every
 *       reader pays the corrupt transfer and the object never heals). The
 *       scrub is the F1 verify path run proactively, off the hot path.
 * HOW:  registration mirrors the T19 RTT probe (config-time per-process
 *       statics, per-worker timer at init_process — worker 0 only, the store
 *       is shared and duplicate hashing is pure waste). Each pass the event
 *       loop collects one cursor-bounded window of CAS keys via
 *       brix_cstore_scan, a thread-pool task hashes them (the expensive
 *       part), and the completion evicts mismatches on the event loop — the
 *       same loop the watermark reaper mutates the store from.
 *
 *       A mismatch here is LOCAL corruption (this host's disk): the origin
 *       proved these bytes at fill time. It is logged as such and NEVER
 *       raises signal=cvmfs_tamper — that signal names a lying origin and
 *       feeds an instant-ban jail (the cold_tier lesson). If the origin's
 *       copy is ALSO bad, the re-fill's own verify gate rejects, quarantines
 *       and raises the tamper signal — the scrub needs no second gate.
 */
#include "cvmfs.h"
#include "classify.h"
#include "core/aio/aio.h"                  /* brix_task_bind */
#include "fs/backend/cache/sd_cache.h"     /* brix_sd_cache_cstore */
#include "fs/cache/cstore.h"
#include "fs/cache/verify.h"               /* brix_cache_verify_cvmfs_cas */
#include "fs/vfs/vfs_backend_registry.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define CVMFS_SCRUB_MAX_EXPORTS 8
#define CVMFS_SCRUB_KEY_MAX     512
#define CVMFS_SCRUB_RATE_DEF    20
#define CVMFS_SCRUB_RATE_MAX    256

/* Config-time registration (per-process statics; written by the master's
 * config parse, read at worker init — the RTT probe's exact lifecycle). */
typedef struct {
    char        root[256];
    char        pool[64];
    time_t      interval;
    ngx_uint_t  rate;
} cvmfs_scrub_reg_t;

static cvmfs_scrub_reg_t  cvmfs_scrub_regs[CVMFS_SCRUB_MAX_EXPORTS];
static ngx_uint_t         cvmfs_scrub_regs_n;

void
brix_cvmfs_scrub_register(const char *root_canon, time_t interval,
    ngx_uint_t rate, const ngx_str_t *pool_name)
{
    ngx_uint_t         i;
    cvmfs_scrub_reg_t *reg = NULL;

    for (i = 0; i < cvmfs_scrub_regs_n; i++) {
        if (ngx_strcmp(cvmfs_scrub_regs[i].root, root_canon) == 0) {
            reg = &cvmfs_scrub_regs[i];        /* reload: update in place */
            break;
        }
    }
    if (reg == NULL) {
        if (cvmfs_scrub_regs_n >= CVMFS_SCRUB_MAX_EXPORTS
            || ngx_strlen(root_canon) >= sizeof(reg->root))
        {
            return;
        }
        reg = &cvmfs_scrub_regs[cvmfs_scrub_regs_n++];
    }
    ngx_cpystrn((u_char *) reg->root, (u_char *) root_canon,
                sizeof(reg->root));
    reg->interval = (interval > 0) ? interval : 60;
    reg->rate = (rate == 0) ? CVMFS_SCRUB_RATE_DEF
              : (rate > CVMFS_SCRUB_RATE_MAX) ? CVMFS_SCRUB_RATE_MAX : rate;
    reg->pool[0] = '\0';
    if (pool_name != NULL && pool_name->len > 0
        && pool_name->len < sizeof(reg->pool))
    {
        ngx_memcpy(reg->pool, pool_name->data, pool_name->len);
        reg->pool[pool_name->len] = '\0';
    }
}

/* One window entry: the store key and its re-verify verdict (thread → done). */
typedef struct {
    char                        key[CVMFS_SCRUB_KEY_MAX];
    brix_cache_verify_result_e  verdict;
} cvmfs_scrub_item_t;

/* Per-worker scrub context (one per export; the task is allocated once and
 * re-posted — timer → collect → post → done → re-arm is strictly sequential). */
typedef struct {
    ngx_event_t               timer;
    ngx_thread_task_t        *task;
    const cvmfs_scrub_reg_t  *reg;
    brix_cstore_t            *cs;          /* resolved on each fire        */
    char                      root_abs[PATH_MAX]; /* store local root, trimmed */
    size_t                    root_len;
    ngx_uint_t                cursor;      /* CAS objects to skip this pass */
    ngx_uint_t                seen_cas;    /* CAS objects seen by the walk  */
    ngx_uint_t                n;           /* window entries collected      */
    unsigned                  wrapped:1;   /* walk reached end-of-store     */
    cvmfs_scrub_item_t       *items;       /* reg->rate entries             */
} cvmfs_scrub_ctx_t;

/* Scan visitor (event loop): collect the pass's window of CAS keys.
 * Non-CAS entries (manifests, whitelists, /.gcas canonical names) are
 * skipped — they are either mutable or reachable through a CAS key. */
static ngx_int_t
cvmfs_scrub_collect(const char *key, const brix_cache_cinfo_t *ci,
    const brix_sd_stat_t *stx, void *ctx)
{
    cvmfs_scrub_ctx_t *sc = ctx;
    cvmfs_url_info_t   info;

    (void) ci;
    (void) stx;

    if (cvmfs_classify_url(key, strlen(key), &info) != 0
        || info.cls != CVMFS_URL_CAS)
    {
        return NGX_OK;
    }
    if (sc->seen_cas++ < sc->cursor) {
        return NGX_OK;                     /* before this pass's window */
    }
    if (sc->n >= sc->reg->rate) {
        return NGX_DONE;                   /* window full — stop the walk */
    }
    if (strlen(key) < CVMFS_SCRUB_KEY_MAX) {
        ngx_cpystrn((u_char *) sc->items[sc->n].key, (u_char *) key,
                    CVMFS_SCRUB_KEY_MAX);
        sc->items[sc->n].verdict = BRIX_CACHE_VERIFY_UNVERIFIED;
        sc->n++;
    }
    return NGX_OK;
}

/* Thread-pool side: hash every window entry against its CAS name. The log is
 * deliberately NOT passed down — the fill-path mismatch wording blames the
 * origin transfer, which is the wrong actor here; the completion handler
 * emits the accurate local-corruption line instead. */
static void
cvmfs_scrub_thread(void *data, ngx_log_t *log)
{
    cvmfs_scrub_ctx_t *sc = data;
    char               path[PATH_MAX];
    ngx_uint_t         i;
    int                n;

    (void) log;
    for (i = 0; i < sc->n; i++) {
        n = snprintf(path, sizeof(path), "%.*s%s",
                     (int) sc->root_len, sc->root_abs, sc->items[i].key);
        if (n < 0 || (size_t) n >= sizeof(path)) {
            sc->items[i].verdict = BRIX_CACHE_VERIFY_ERROR;
            continue;
        }
        sc->items[i].verdict =
            brix_cache_verify_cvmfs_cas(path, sc->items[i].key, NULL,
                                          NULL, NULL);
    }
}

/* Event-loop side: evict mismatches, advance the cursor, re-arm. An ERROR
 * verdict (object evicted/raced away mid-pass) is a silent skip. */
static void
cvmfs_scrub_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task = ev->data;
    cvmfs_scrub_ctx_t *sc = task->ctx;
    ngx_uint_t         i, corrupt = 0;

    for (i = 0; i < sc->n; i++) {
        if (sc->items[i].verdict != BRIX_CACHE_VERIFY_MISMATCH) {
            continue;
        }
        corrupt++;
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
            "cvmfs scrub: LOCAL corruption in cached object \"%s\" "
            "(stored bytes no longer match their CAS name — disk bitrot "
            "or on-host modification, NOT an origin event); evicting so "
            "the next access re-fills verified from the origin",
            sc->items[i].key);
        brix_cstore_evict(sc->cs, sc->items[i].key);
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
        "cvmfs scrub pass (export %s): checked %ui CAS object(s) "
        "at cursor %ui, corrupt=%ui",
        sc->reg->root, sc->n, sc->cursor, corrupt);

    sc->cursor = sc->wrapped ? 0 : sc->cursor + sc->n;

    if (!ngx_exiting) {
        ngx_add_timer(&sc->timer, (ngx_msec_t) sc->reg->interval * 1000
                                  + (ngx_msec_t) (ngx_random() % 500));
    }
}

/* Timer side (event loop): resolve the store, collect one window, post the
 * hashing task. Any miss (non-cache backend, non-local store, empty window,
 * no pool) just re-arms — the scrub is best-effort by design. */
static void
cvmfs_scrub_fire(ngx_event_t *ev)
{
    cvmfs_scrub_ctx_t   *sc = ev->data;
    brix_sd_instance_t  *inst;
    ngx_thread_pool_t   *pool;
    ngx_str_t            pname;
    const char          *root;
    ngx_int_t            rc;

    inst = brix_vfs_backend_resolve(sc->reg->root, ev->log);
    sc->cs = (inst != NULL) ? brix_sd_cache_cstore(inst) : NULL;
    root = (sc->cs != NULL) ? brix_cstore_local_root(sc->cs) : NULL;

    if (root != NULL) {
        sc->root_len = strlen(root);
        while (sc->root_len > 0 && root[sc->root_len - 1] == '/') {
            sc->root_len--;
        }
        if (sc->root_len < sizeof(sc->root_abs)) {
            ngx_memcpy(sc->root_abs, root, sc->root_len);
        } else {
            root = NULL;
        }
    }

    sc->n = 0;
    sc->seen_cas = 0;
    sc->wrapped = 0;

    if (root != NULL) {
        rc = brix_cstore_scan(sc->cs, cvmfs_scrub_collect, sc);
        sc->wrapped = (rc == NGX_OK);      /* full walk: window hit the end */
    }

    if (sc->n > 0) {
        if (sc->reg->pool[0] != '\0') {
            pname.data = (u_char *) sc->reg->pool;
            pname.len  = ngx_strlen(sc->reg->pool);
        } else {
            ngx_str_set(&pname, "default");
        }
        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &pname);
        if (pool != NULL && ngx_thread_task_post(pool, sc->task) == NGX_OK) {
            return;                        /* re-armed by cvmfs_scrub_done */
        }
    }

    sc->cursor = 0;                        /* empty/failed pass: restart */
    if (!ngx_exiting) {
        ngx_add_timer(ev, (ngx_msec_t) sc->reg->interval * 1000);
    }
}

ngx_int_t
brix_cvmfs_scrub_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t i;

    /* The store is shared across workers: one scrubber is enough, N of them
     * is N× the hashing I/O for the same coverage. Worker 0 always exists
     * (and IS the process in single-process mode). */
    if (ngx_worker > 0) {
        return NGX_OK;
    }

    for (i = 0; i < cvmfs_scrub_regs_n; i++) {
        const cvmfs_scrub_reg_t *reg = &cvmfs_scrub_regs[i];
        ngx_thread_task_t       *task;
        cvmfs_scrub_ctx_t       *sc;

        task = ngx_thread_task_alloc(cycle->pool, sizeof(cvmfs_scrub_ctx_t));
        if (task == NULL) {
            return NGX_ERROR;
        }
        sc = task->ctx;
        sc->task = task;
        sc->reg  = reg;
        sc->items = ngx_pcalloc(cycle->pool,
                                reg->rate * sizeof(cvmfs_scrub_item_t));
        if (sc->items == NULL) {
            return NGX_ERROR;
        }

        brix_task_bind(task, cvmfs_scrub_thread, cvmfs_scrub_done);
        task->event.log = cycle->log;

        sc->timer.handler = cvmfs_scrub_fire;
        sc->timer.data    = sc;
        sc->timer.log     = cycle->log;
        ngx_add_timer(&sc->timer, (ngx_msec_t) reg->interval * 1000);
    }
    return NGX_OK;
}
