/*
 * stage_engine.c - the one async-staging engine (phase-64 section 11). See header.
 *
 * SP1 lands the seam: the generic promote-loop mover (open src for read,
 * staged_open dst, pread -> staged_write -> staged_commit) plus the inline submit
 * front door and the unified audit line. The durable queue + waiter + restart
 * reconcile are extracted from src/frm/ in SP4 (section 13b) and attach behind
 * xrootd_stage_submit() without touching a caller; until then async degrades to an
 * honest inline move and the scheduler/reconcile hooks are no-ops.
 */
#include "stage_engine.h"
#include "xfer.h"   /* xrootd_xfer_finish + the kind/result vocabulary (ledger) */
#include "../../aio/aio.h"                /* xrootd_task_bind (mover thread-offload) */
#include "../vfs_backend_registry.h"      /* xrootd_vfs_backend_resolve (reconcile) */
#include "../backend/cache/sd_cache.h"    /* cache instance_is / source_instance    */
#include "../backend/stage/sd_stage.h"    /* stage instance_is / reflush            */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Move granule: one 1 MiB driver-mediated pread/staged_write per turn (the same
 * window the legacy sd_stage promote and the xfer pump use). */
#define STAGE_ENGINE_CHUNK (1u << 20)

/* ---- SP4: the durable async queue -----------------------------------------
 * An async submit is DEFERRED rather than run inline: the request is appended to
 * a per-worker in-memory pending list (holding the live src/dst instances, which
 * are the memoised per-worker tier instances - they outlive the request) and,
 * when a journal dir is configured, persisted as a small record for crash
 * visibility/recovery. xrootd_stage_scheduler_tick() (a per-worker timer) drains
 * the list, runs each mover, and drops the stage copy of a completed FLUSH. This
 * generalises the FRM queue model to SD instances (section 11); the full physical
 * extraction of src/frm/ is the remaining SP4/SP5 migration. */

typedef struct stage_pending_s {
    char                     reqid[40];
    xrootd_stage_kind_t      kind;
    xrootd_sd_instance_t    *src;
    char                     src_key[1024];
    xrootd_sd_instance_t    *dst;
    char                     dst_key[1024];
    char                     export_root[1024]; /* anchor for restart reconcile     */
    struct stage_pending_s  *next;
} stage_pending_t;

static stage_pending_t *stage_pending_head;          /* per-worker FIFO tail-append */
static stage_pending_t *stage_pending_tail;
static char             stage_journal_dir[1024];     /* "" = in-memory only */
static uint64_t         stage_reqid_seq;

void
xrootd_stage_engine_init(const char *journal_dir)
{
    if (journal_dir != NULL && journal_dir[0] != '\0') {
        snprintf(stage_journal_dir, sizeof(stage_journal_dir), "%s", journal_dir);
    } else {
        stage_journal_dir[0] = '\0';
    }
}

/* Mint a per-worker-unique request id: pid-seconds-counter. */
static void
stage_reqid_mint(char out[40])
{
    snprintf(out, 40, "%ld-%lld-%llu", (long) getpid(),
             (long long) time(NULL), (unsigned long long) ++stage_reqid_seq);
}

/* Persist (best-effort) a QUEUED request record so a crash leaves a recoverable
 * row; removed on completion. Skipped when no journal dir is configured. */
static void
stage_journal_write(const stage_pending_t *p)
{
    xrootd_sreq_t rec;
    char          path[1200];
    int           fd;

    if (stage_journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                          stage_journal_dir, p->reqid) >= sizeof(path))
    {
        return;
    }
    ngx_memzero(&rec, sizeof(rec));
    snprintf(rec.reqid, sizeof(rec.reqid), "%s", p->reqid);
    rec.kind  = p->kind;
    rec.state = XROOTD_SREQ_QUEUED;
    snprintf(rec.src_driver, sizeof(rec.src_driver), "%s",
             (p->src->driver && p->src->driver->name) ? p->src->driver->name : "");
    snprintf(rec.src_key, sizeof(rec.src_key), "%s", p->src_key);
    snprintf(rec.dst_driver, sizeof(rec.dst_driver), "%s",
             (p->dst->driver && p->dst->driver->name) ? p->dst->driver->name : "");
    snprintf(rec.dst_key, sizeof(rec.dst_key), "%s", p->dst_key);
    snprintf(rec.export_root, sizeof(rec.export_root), "%s", p->export_root);
    rec.enqueued_at = (int64_t) time(NULL);

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    if (write(fd, &rec, sizeof(rec)) == (ssize_t) sizeof(rec)) {
        (void) fsync(fd);
    }
    (void) close(fd);
}

static void
stage_journal_remove(const char *reqid)
{
    char path[1200];

    if (stage_journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                          stage_journal_dir, reqid) < sizeof(path))
    {
        (void) unlink(path);
    }
}

/* ---- kind -> ledger vocabulary -------------------------------------------- */

/* Map an async-staging kind onto the existing unified-ledger transfer kind, so
 * one audit schema covers recall/flush/upload/multipart (section 19). */
static xrootd_xfer_kind_t
stage_kind_to_xfer(xrootd_stage_kind_t kind)
{
    switch (kind) {
    case XROOTD_STAGE_RECALL:    return XROOTD_XFER_TAPE;   /* tape -> cache store  */
    case XROOTD_STAGE_FLUSH:     return XROOTD_XFER_WT;     /* stage -> backend     */
    case XROOTD_STAGE_UPLOAD:    return XROOTD_XFER_STAGE;  /* body -> stage store  */
    case XROOTD_STAGE_MULTIPART: return XROOTD_XFER_STAGE;  /* part -> stage store  */
    }
    return XROOTD_XFER_STAGE;
}

/* "in" = bytes land in our storage; "out" = bytes leave to the backend. */
static const char *
stage_kind_dir(xrootd_stage_kind_t kind)
{
    return (kind == XROOTD_STAGE_FLUSH) ? "out" : "in";
}

const char *
xrootd_stage_kind_str(xrootd_stage_kind_t kind)
{
    switch (kind) {
    case XROOTD_STAGE_RECALL:    return "recall";
    case XROOTD_STAGE_FLUSH:     return "flush";
    case XROOTD_STAGE_UPLOAD:    return "upload";
    case XROOTD_STAGE_MULTIPART: return "multipart";
    }
    return "stage";
}

/* ---- the generic promote-loop mover --------------------------------------- */

/* Copy the whole object `src_key` on `src` into `dst_key` on `dst` by reading
 * through the source driver and writing through the destination's staged sink,
 * then committing it atomically. Both endpoints are SD instances, so this same
 * loop moves bytes between ANY two tiers (posix stage -> remote backend, tape
 * buffer -> posix cache, ...). On success *bytes_out carries the moved size and
 * the staged handle is consumed by commit; on failure the staged temp is aborted
 * and *err_out carries errno. Returns an xrootd_xfer_result_t terminal code. */
static xrootd_xfer_result_t
stage_engine_move(xrootd_sd_instance_t *src, const char *src_key,
    xrootd_sd_instance_t *dst, const char *dst_key, off_t *bytes_out,
    int *err_out)
{
    xrootd_sd_obj_t    *so;
    xrootd_sd_staged_t *ds;
    u_char             *buf;
    off_t               off = 0;
    int                 oerr = 0;
    mode_t              mode;

    if (src->driver->open == NULL || src->driver->pread == NULL) {
        *err_out = ENOSYS;
        return XROOTD_XFER_SRC_ERR;
    }
    if (dst->driver->staged_open == NULL || dst->driver->staged_write == NULL
        || dst->driver->staged_commit == NULL || dst->driver->staged_abort == NULL)
    {
        *err_out = ENOSYS;
        return XROOTD_XFER_DST_ERR;
    }

    so = src->driver->open(src, src_key, XROOTD_SD_O_READ, 0, &oerr);
    if (so == NULL) {
        *err_out = oerr ? oerr : EIO;
        ngx_log_error(NGX_LOG_ERR, src->log, *err_out,
            "stage move: source open failed (%s key=\"%s\")",
            src->driver->name, src_key);
        return XROOTD_XFER_SRC_ERR;
    }

    /* open() may not populate snap (the posix driver fstats lazily); fstat for an
     * accurate mode so a flush preserves the source's permission bits. */
    {
        xrootd_sd_stat_t snap = so->snap;

        if (src->driver->fstat != NULL) {
            (void) src->driver->fstat(so, &snap);
        }
        mode = (mode_t) (snap.mode & 0777);
    }
    if (mode == 0) {
        mode = 0644;
    }

    ds = dst->driver->staged_open(dst, dst_key, mode, &oerr);
    if (ds == NULL) {
        src->driver->close(so);
        *err_out = oerr ? oerr : EIO;
        ngx_log_error(NGX_LOG_ERR, dst->log, *err_out,
            "stage move: dest staged_open failed (%s key=\"%s\")",
            dst->driver->name, dst_key);
        return XROOTD_XFER_DST_ERR;
    }

    buf = malloc(STAGE_ENGINE_CHUNK);
    if (buf == NULL) {
        dst->driver->staged_abort(ds);
        src->driver->close(so);
        *err_out = ENOMEM;
        return XROOTD_XFER_DST_ERR;
    }

    for ( ;; ) {
        ssize_t r = src->driver->pread(so, buf, STAGE_ENGINE_CHUNK, off);

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            oerr = errno ? errno : EIO;
            ngx_log_error(NGX_LOG_ERR, src->log, oerr,
                "stage move: source read failed at off=%O (%s key=\"%s\")",
                off, src->driver->name, src_key);
            free(buf);
            dst->driver->staged_abort(ds);
            src->driver->close(so);
            *err_out = oerr;
            return XROOTD_XFER_SRC_ERR;
        }
        if (r == 0) {
            break;                      /* EOF - the whole object is moved */
        }
        if (dst->driver->staged_write(ds, buf, (size_t) r, off) < 0) {
            oerr = errno ? errno : EIO;
            ngx_log_error(NGX_LOG_ERR, dst->log, oerr,
                "stage move: dest write failed at off=%O (%s key=\"%s\")",
                off, dst->driver->name, dst_key);
            free(buf);
            dst->driver->staged_abort(ds);
            src->driver->close(so);
            *err_out = oerr;
            return XROOTD_XFER_DST_ERR;
        }
        off += r;
    }

    free(buf);
    src->driver->close(so);

    if (dst->driver->staged_commit(ds, 0) != NGX_OK) {
        oerr = errno ? errno : EIO;
        ngx_log_error(NGX_LOG_ERR, dst->log, oerr,
            "stage move: dest commit failed (%s key=\"%s\")",
            dst->driver->name, dst_key);
        dst->driver->staged_abort(ds);     /* commit failed - drop the temp */
        *err_out = oerr;
        return XROOTD_XFER_COMMIT_ERR;
    }

    *bytes_out = off;
    return XROOTD_XFER_OK;
}

/* Move the object inline and book one unified audit line. Shared by the async
 * front door (xrootd_stage_submit) and the sync path (xrootd_stage_run_inline). */
static xrootd_xfer_result_t
stage_engine_run(xrootd_stage_kind_t kind, xrootd_sd_instance_t *src,
    const char *src_key, xrootd_sd_instance_t *dst, const char *dst_key)
{
    xrootd_xfer_result_t res;
    off_t                bytes = 0;
    int                  oerr = 0;
    ngx_log_t           *log = (dst->log != NULL) ? dst->log : src->log;

    res = stage_engine_move(src, src_key, dst, dst_key, &bytes, &oerr);

    /* One unified audit line per terminal transfer (transport-agnostic). */
    xrootd_xfer_finish(stage_kind_to_xfer(kind), stage_kind_dir(kind), dst_key,
        NULL, (size_t) bytes, res, (res == XROOTD_XFER_OK) ? 0 : oerr, log);

    if (res != XROOTD_XFER_OK && oerr != 0) {
        errno = oerr;
    }
    return res;
}

/* ---- the public front doors ----------------------------------------------- */

const char *
xrootd_stage_submit(xrootd_stage_kind_t kind, xrootd_sd_instance_t *src,
    const char *src_key, xrootd_sd_instance_t *dst, const char *dst_key,
    const xrootd_stage_opts_t *opts)
{
    static const char ran_inline[] = "";
    static char       last_reqid[40];   /* event-loop single-threaded: stable enough */
    stage_pending_t  *p;

    if (src == NULL || src_key == NULL || dst == NULL || dst_key == NULL
        || src->driver == NULL || dst->driver == NULL)
    {
        return NULL;
    }

    /* Synchronous (the default): move now and return "" = done inline. */
    if (opts == NULL || !opts->async) {
        (void) stage_engine_run(kind, src, src_key, dst, dst_key);
        return ran_inline;
    }

    /* Asynchronous: defer to the scheduler (durable). The src/dst instances are
     * the memoised per-worker tier instances, so holding them is safe. */
    p = calloc(1, sizeof(*p));
    if (p == NULL) {
        (void) stage_engine_run(kind, src, src_key, dst, dst_key);  /* never lose it */
        return ran_inline;
    }
    stage_reqid_mint(p->reqid);
    p->kind = kind;
    p->src  = src;
    p->dst  = dst;
    snprintf(p->src_key, sizeof(p->src_key), "%s", src_key);
    snprintf(p->dst_key, sizeof(p->dst_key), "%s", dst_key);
    if (opts->export_root != NULL) {
        snprintf(p->export_root, sizeof(p->export_root), "%s", opts->export_root);
    }

    if (stage_pending_tail != NULL) {
        stage_pending_tail->next = p;
    } else {
        stage_pending_head = p;
    }
    stage_pending_tail = p;

    stage_journal_write(p);
    snprintf(last_reqid, sizeof(last_reqid), "%s", p->reqid);
    return last_reqid;          /* non-empty = deferred; the caller may park on it */
}

ngx_int_t
xrootd_stage_run_inline(xrootd_stage_kind_t kind, xrootd_sd_instance_t *src,
    const char *src_key, xrootd_sd_instance_t *dst, const char *dst_key)
{
    if (src == NULL || src_key == NULL || dst == NULL || dst_key == NULL
        || src->driver == NULL || dst->driver == NULL)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }
    return (stage_engine_run(kind, src, src_key, dst, dst_key) == XROOTD_XFER_OK)
         ? NGX_OK : NGX_ERROR;
}

/* Max transfers a single tick STARTS, so a backlog never monopolises the worker.
 * The next tick continues the queue. */
#define STAGE_TICK_BUDGET 32

/* Terminal post-processing for a completed mover (inline or thread): on success a
 * FLUSH drops the now-redundant stage copy (the migrate semantic, §9.5) and the
 * journal record is removed; on failure the record is KEPT (the reconcile retries
 * it on restart, or a later tick re-drives it). Shared by both paths. */
static void
stage_complete(xrootd_stage_kind_t kind, xrootd_sd_instance_t *src,
    const char *src_key, const char *dst_key, const char *reqid,
    xrootd_xfer_result_t res, ngx_log_t *log)
{
    if (res == XROOTD_XFER_OK) {
        if (kind == XROOTD_STAGE_FLUSH && src->driver->unlink != NULL) {
            (void) src->driver->unlink(src, src_key, 0);
        }
        stage_journal_remove(reqid);
    } else {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "xrootd stage: deferred %s of \"%s\" failed (reqid %s) - record kept",
            xrootd_stage_kind_str(kind), dst_key, reqid);
    }
}

#if (NGX_THREADS)

/* In-flight offloaded movers (per-worker), bounded so a burst never floods the
 * thread pool nor unbounds memory. The tick stops starting new ones at the cap and
 * resumes next tick as they drain. */
static ngx_uint_t stage_inflight;
#define STAGE_MAX_INFLIGHT 8

/* The off-loop mover task (lives on its own small pool, freed in the done event). */
typedef struct {
    ngx_pool_t           *pool;
    xrootd_stage_kind_t   kind;
    xrootd_sd_instance_t *src;
    xrootd_sd_instance_t *dst;
    xrootd_xfer_result_t  res;
    ngx_log_t            *log;
    char                  reqid[40];
    char                  src_key[1024];
    char                  dst_key[1024];
} stage_flush_task_t;

static void
stage_flush_thread(void *data, ngx_log_t *log)
{
    stage_flush_task_t *t = data;

    (void) log;
    t->res = stage_engine_run(t->kind, t->src, t->src_key, t->dst, t->dst_key);
}

static void
stage_flush_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    stage_flush_task_t *t = task->ctx;
    ngx_pool_t         *pool = t->pool;

    if (stage_inflight > 0) {
        stage_inflight--;
    }
    stage_complete(t->kind, t->src, t->src_key, t->dst_key, t->reqid, t->res,
                   t->log);
    ngx_destroy_pool(pool);              /* frees the task + ctx */
}

/* Post `p`'s mover to `pool`. NGX_OK = posted (caller drops the pending item; the
 * journal record persists until the thread completes); NGX_DECLINED = setup failed
 * (caller runs it inline). */
static ngx_int_t
stage_flush_offload(const stage_pending_t *p, ngx_thread_pool_t *pool)
{
    ngx_log_t          *log = (p->dst->log != NULL) ? p->dst->log : p->src->log;
    ngx_pool_t         *tp;
    ngx_thread_task_t  *task;
    stage_flush_task_t *t;

    if (log == NULL) {
        log = ngx_cycle->log;
    }
    tp = ngx_create_pool(4096, log);
    if (tp == NULL) {
        return NGX_DECLINED;
    }
    task = ngx_thread_task_alloc(tp, sizeof(stage_flush_task_t));
    if (task == NULL) {
        ngx_destroy_pool(tp);
        return NGX_DECLINED;
    }
    t = task->ctx;
    t->pool = tp;
    t->kind = p->kind;
    t->src  = p->src;
    t->dst  = p->dst;
    t->res  = XROOTD_XFER_DST_ERR;
    t->log  = log;
    snprintf(t->reqid, sizeof(t->reqid), "%s", p->reqid);
    snprintf(t->src_key, sizeof(t->src_key), "%s", p->src_key);
    snprintf(t->dst_key, sizeof(t->dst_key), "%s", p->dst_key);

    xrootd_task_bind(task, stage_flush_thread, stage_flush_done);
    task->event.log = log;
    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        ngx_destroy_pool(tp);
        return NGX_DECLINED;
    }
    stage_inflight++;
    return NGX_OK;
}

/* The export's async thread pool (the common "default" pool). NULL = serve inline. */
static ngx_thread_pool_t *
stage_thread_pool(void)
{
    static ngx_str_t name = ngx_string("default");

    return (ngx_cycle != NULL)
         ? ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name) : NULL;
}

#endif /* NGX_THREADS */

void
xrootd_stage_scheduler_tick(void)
{
    int budget = STAGE_TICK_BUDGET;
#if (NGX_THREADS)
    ngx_thread_pool_t *pool = stage_thread_pool();
#endif

    while (stage_pending_head != NULL && budget-- > 0) {
        stage_pending_t     *p = stage_pending_head;
        xrootd_xfer_result_t res;
        ngx_log_t           *log = (p->dst->log != NULL) ? p->dst->log
                                                         : p->src->log;

#if (NGX_THREADS)
        /* Run the mover OFF the event loop so a flush to a REMOTE backend (or from a
         * remote stage store) never blocks/fails on the un-pumped loop. Bounded
         * in-flight; the durable journal record is what survives a crash mid-flush
         * (recovered by reconcile), so the on-disk record is dropped only in the
         * completion. */
        if (pool != NULL) {
            if (stage_inflight >= STAGE_MAX_INFLIGHT) {
                break;                      /* let in-flight drain; resume next tick */
            }
            if (stage_flush_offload(p, pool) == NGX_OK) {
                stage_pending_head = p->next;
                if (stage_pending_head == NULL) {
                    stage_pending_tail = NULL;
                }
                free(p);
                continue;
            }
            /* offload setup failed - fall through to the inline path */
        }
#endif

        stage_pending_head = p->next;
        if (stage_pending_head == NULL) {
            stage_pending_tail = NULL;
        }
        res = stage_engine_run(p->kind, p->src, p->src_key, p->dst, p->dst_key);
        stage_complete(p->kind, p->src, p->src_key, p->dst_key, p->reqid, res,
                       log);
        free(p);
    }
}

/* Re-flush ONE persisted record. Only a staged-write FLUSH is replayable: its
 * bytes are durable on the stage store and the export anchor lets us rebuild both
 * tiers. An UPLOAD/MULTIPART (client body -> stage) cannot be replayed - the body
 * is gone after a crash, so the client retries; such records are dropped, never
 * silently re-driven wrong. Returns 1 replayed / 0 kept (retry) / -1 dropped. */
static int
stage_reconcile_one(const char *path, ngx_log_t *log)
{
    xrootd_sreq_t         rec;
    xrootd_sd_instance_t *inst;
    int                   fd;
    ssize_t               n;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    n = read(fd, &rec, sizeof(rec));
    (void) close(fd);
    if (n != (ssize_t) sizeof(rec)) {
        (void) unlink(path);                 /* corrupt/short record - drop */
        return -1;
    }
    if (rec.kind != XROOTD_STAGE_FLUSH || rec.export_root[0] == '\0') {
        (void) unlink(path);                 /* not a recoverable staged write */
        return -1;
    }

    /* Rebuild the export's composed stack and unwrap to its stage decorator. */
    inst = xrootd_vfs_backend_resolve(rec.export_root, log);
    if (xrootd_sd_cache_instance_is(inst)) {
        inst = xrootd_sd_cache_source_instance(inst);
    }
    if (xrootd_sd_stage_instance_is(inst)
        && xrootd_sd_stage_reflush(inst, rec.dst_key) == NGX_OK)
    {
        (void) unlink(path);                 /* re-flushed + stage copy dropped */
        return 1;
    }
    /* Backend unreachable / no stage tier now: keep the record for a later retry. */
    ngx_log_error(NGX_LOG_WARN, log, 0,
        "xrootd stage: reconcile could not re-flush \"%s\" (export \"%s\") - "
        "record kept for retry", rec.dst_key, rec.export_root);
    return 0;
}

void
xrootd_stage_reconcile(xrootd_stage_queue_t *queue)
{
    DIR           *d;
    struct dirent *de;
    char           names[1024][256];
    ngx_uint_t     ncount = 0, i, replayed = 0, kept = 0, dropped = 0;
    ngx_log_t     *log = (ngx_cycle != NULL) ? ngx_cycle->log : NULL;

    (void) queue;
    if (stage_journal_dir[0] == '\0') {
        return;                              /* no durable journal configured */
    }
    d = opendir(stage_journal_dir);
    if (d == NULL) {
        return;
    }
    /* Snapshot the *.req names first (we unlink while driving). */
    while ((de = readdir(d)) != NULL && ncount < 1024) {
        size_t nlen = strlen(de->d_name);

        if (nlen > 4 && nlen < sizeof(names[0])
            && strcmp(de->d_name + nlen - 4, ".req") == 0)
        {
            memcpy(names[ncount], de->d_name, nlen + 1);
            ncount++;
        }
    }
    closedir(d);

    for (i = 0; i < ncount; i++) {
        char path[1300];
        int  r;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s",
                              stage_journal_dir, names[i]) >= sizeof(path))
        {
            continue;
        }
        r = stage_reconcile_one(path, log);
        if (r > 0)      { replayed++; }
        else if (r < 0) { dropped++;  }
        else            { kept++;     }
    }

    if (replayed > 0 || kept > 0 || dropped > 0) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "xrootd stage: restart reconcile - %ui staged flush(es) replayed, "
            "%ui kept for retry, %ui dropped", replayed, kept, dropped);
    }
}
