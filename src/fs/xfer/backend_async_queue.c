/*
 * backend_async_queue.c — durable write-behind queue for backend namespace
 * mutations (brix_backend_async). See backend_async_queue.h for the contract.
 *
 * WHAT: Per-worker coalescing + durable journalling of unlink/rmdir/rename/mkdir,
 *       with in-bulk drain against the backend and a protocol-supplied waker.
 *
 * WHY:  Trade per-op latency for bulk backend efficiency without ever losing an
 *       acknowledged mutation across a crash. Split from the stage engine on
 *       purpose: a namespace mutation is not a byte transfer.
 *
 * HOW:  A fixed-size pending array (per worker), each row carrying the durable
 *       record + the adapter's completion callback + coalescing thresholds. The
 *       size trigger fires inline in enqueue; the time trigger fires on the worker
 *       timer tick. Durability reuses the stage engine's journal DIRECTORY root
 *       (stage_journal_dir) but a private "backend/" subdir and a private record
 *       type + reconcile, so the two subsystems never scan each other's records.
 */

#include "backend_async_queue.h"
#include <ngx_event.h>               /* ngx_post_event / ngx_posted_events (drain) */
#include "stage_engine.h"            /* stage_engine.h pulls the journal dir seam */
#include "stage_engine_internal.h"   /* stage_journal_dir (the durable root)      */
#include "fs/vfs/vfs.h"              /* brix_vfs_*_path drain primitives          */
#include "fs/vfs/vfs_backend_registry.h" /* brix_vfs_backend_resolve (rename)     */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* The worker's pending batch. Bounded: at capacity, enqueue drains first so a
 * burst never grows unboundedly (and never silently drops). 4096 rows is far
 * above any sane coalescing batch while staying a small fixed footprint. */
#define BRIX_BAQ_MAX_PENDING 4096

typedef struct {
    brix_baq_rec_t    rec;         /* the durable record (also what we journal)   */
    brix_baq_done_pt  done;        /* adapter waker (NULL = replayed, no client)  */
    void             *client;      /* opaque conn/request token for `done`        */
    ngx_uint_t        batch;       /* this op's size trigger                      */
    ngx_msec_t        wait_ms;     /* this op's time trigger                      */
    ngx_msec_t        enqueued_ms; /* monotonic enqueue stamp (time trigger)      */
} brix_baq_pending_t;

static brix_baq_pending_t  baq_pending[BRIX_BAQ_MAX_PENDING];
static ngx_uint_t           baq_count;
static char                 baq_journal_dir[1100];   /* "" = in-memory only */
static uint64_t             baq_reqid_seq;
static ngx_event_t          baq_drain_ev;            /* deferred size-trigger drain */

/* ---- durable journal ------------------------------------------------------- */

void
brix_baq_init(void)
{
    /* Derive the private subdir from the stage engine's journal root (set by
     * brix_stage_engine_init just before this call). Empty root = no durability. */
    if (stage_journal_dir[0] == '\0') {
        baq_journal_dir[0] = '\0';
        return;
    }
    if ((size_t) snprintf(baq_journal_dir, sizeof(baq_journal_dir), "%s/backend",
                          stage_journal_dir) >= sizeof(baq_journal_dir))
    {
        baq_journal_dir[0] = '\0';           /* path too long — degrade to memory */
        return;
    }
    if (mkdir(baq_journal_dir, 0700) != 0 && errno != EEXIST) {
        baq_journal_dir[0] = '\0';           /* cannot create — degrade to memory */
    }
}

/* Mint a per-worker-unique request id: pid-seconds-counter (namespace-disjoint
 * from the stage engine's, which lives in a different directory anyway). */
static void
baq_reqid_mint(char out[40])
{
    snprintf(out, 40, "b%ld-%lld-%llu", (long) getpid(),
             (long long) time(NULL), (unsigned long long) ++baq_reqid_seq);
}

/* fsync a QUEUED record to <baq_journal_dir>/<reqid>.req. Best-effort: a failure
 * costs durability for that one op, never correctness of the in-memory drain. */
static void
baq_journal_write(const brix_baq_rec_t *rec)
{
    char path[1300];
    int  fd;

    if (baq_journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                          baq_journal_dir, rec->reqid) >= sizeof(path))
    {
        return;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    if (write(fd, rec, sizeof(*rec)) == (ssize_t) sizeof(*rec)) {
        (void) fsync(fd);
    }
    (void) close(fd);
}

static void
baq_journal_remove(const char *reqid)
{
    char path[1300];

    if (baq_journal_dir[0] == '\0') {
        return;
    }
    if ((size_t) snprintf(path, sizeof(path), "%s/%s.req",
                          baq_journal_dir, reqid) < sizeof(path))
    {
        (void) unlink(path);
    }
}

/* ---- backend apply --------------------------------------------------------- */

/*
 * Drive ONE record against its backend. Returns the raw POSIX errno (0 == ok).
 *
 * WHAT: Dispatches on rec->op to the matching pool-less VFS path primitive, all
 *       of which confine to root_canon and are safe to call inline on the event
 *       loop (no pool alloc, no metric).
 *
 * WHY:  Shared by the live drain (which delivers the raw errno to the client as
 *       the true result) and reconcile (which additionally squashes idempotent-
 *       benign errnos — see baq_apply_idempotent).
 *
 * HOW:  RENAME needs the resolved backend instance (brix_vfs_rename_path takes an
 *       sd); the others take root_canon directly.
 */
static int
baq_apply(const brix_baq_rec_t *rec, ngx_log_t *log)
{
    switch ((brix_baq_op_t) rec->op) {

    case BRIX_BAQ_UNLINK:
        if (brix_vfs_unlink_path(log, rec->root_canon, rec->src_key) == 0) {
            return 0;
        }
        /* kXR_rm parity: "unlink a file, rmdir a directory" non-recursively. The
         * file-unlink primitive returns EISDIR on a directory target, so fall back
         * to the empty-dir removal (which itself returns ENOTEMPTY on a non-empty
         * dir) — matching brix_vfs_unlink's file-or-empty-dir behaviour exactly. */
        if (errno == EISDIR
            && brix_vfs_rmdir_path(log, rec->root_canon, rec->src_key) == 0)
        {
            return 0;
        }
        return errno ? errno : EIO;

    case BRIX_BAQ_RMDIR:
        return brix_vfs_rmdir_path(log, rec->root_canon, rec->src_key) == 0
               ? 0 : (errno ? errno : EIO);

    case BRIX_BAQ_MKDIR:
        return brix_vfs_mkdir_path(log, rec->root_canon, rec->src_key,
                                   (mode_t) rec->mode) == 0
               ? 0 : (errno ? errno : EIO);

    case BRIX_BAQ_RENAME: {
        brix_sd_instance_t *sd = brix_vfs_backend_resolve(rec->root_canon, log);

        errno = 0;
        if (brix_vfs_rename_path(sd, log, rec->root_canon,
                                 rec->src_key, rec->dst_key,
                                 0 /* no overwrite */, NULL) == NGX_OK)
        {
            return 0;
        }
        return errno ? errno : EIO;
    }

    default:
        return EINVAL;                       /* unknown op = corrupt record */
    }
}

/* Reconcile-time idempotency: a mutation the client was told to wait for has
 * already taken effect if the target is now in the desired end-state. Squash the
 * benign "already done" errnos to success so the replay removes the record; any
 * other errno is a real transient failure and the record is kept for a later try. */
static int
baq_apply_idempotent(const brix_baq_rec_t *rec, ngx_log_t *log)
{
    int e = baq_apply(rec, log);

    switch ((brix_baq_op_t) rec->op) {
    case BRIX_BAQ_UNLINK:
    case BRIX_BAQ_RMDIR:
        return (e == ENOENT) ? 0 : e;        /* already gone = done */
    case BRIX_BAQ_MKDIR:
        return (e == EEXIST) ? 0 : e;        /* already present = done */
    case BRIX_BAQ_RENAME:
        return (e == ENOENT) ? 0 : e;        /* source already moved = done */
    default:
        return e;
    }
}

/* ---- drain ----------------------------------------------------------------- */

/* Drain the WHOLE batch: apply each op, deliver its real errno to its client, drop
 * its durable record. Clears the pending list. Live path (has clients to wake). */
static void
baq_drain_all(void)
{
    ngx_log_t *log = (ngx_cycle != NULL) ? ngx_cycle->log : NULL;
    ngx_uint_t i;

    for (i = 0; i < baq_count; i++) {
        brix_baq_pending_t *p = &baq_pending[i];
        int e = baq_apply(&p->rec, log);

        baq_journal_remove(p->rec.reqid);
        if (p->done != NULL) {
            p->done(p->client, e);           /* wake the parked client (real result) */
        }
    }
    baq_count = 0;
}

/*
 * Deferred-drain event: the size trigger posts this instead of draining inline.
 *
 * WHAT: An nginx posted event whose handler runs baq_drain_all() after the current
 *       stack unwinds (processed from ngx_posted_events by the event loop).
 *
 * WHY:  A batch of 1 (or any op that completes the batch) would otherwise drain
 *       INSIDE brix_baq_enqueue, firing the done() callback for the very client the
 *       caller is still in the middle of parking — the reply would race the caller's
 *       own state transition. Deferring guarantees every parked connection has fully
 *       reached its wait state before its waker fires.
 *
 * HOW:  ngx_post_event is idempotent via ev->posted, so multiple enqueues in one
 *       loop iteration coalesce into a single drain.
 */
static void
baq_drain_event_handler(ngx_event_t *ev)
{
    (void) ev;
    baq_drain_all();
}

static void
baq_post_drain(void)
{
    if (baq_drain_ev.handler == NULL) {
        baq_drain_ev.handler = baq_drain_event_handler;
        baq_drain_ev.data    = NULL;
        baq_drain_ev.log     = (ngx_cycle != NULL) ? ngx_cycle->log : NULL;
    }
    ngx_post_event((&baq_drain_ev), (&ngx_posted_events));
}

/* Would the batch flush on the SIZE trigger? True once the queue depth reaches the
 * smallest per-op batch threshold currently parked (a shared worker may hold ops
 * from servers configured with different batch sizes). */
static ngx_uint_t
baq_size_triggered(void)
{
    ngx_uint_t i, min_batch = 0;

    if (baq_count == 0) {
        return 0;
    }
    for (i = 0; i < baq_count; i++) {
        if (min_batch == 0 || baq_pending[i].batch < min_batch) {
            min_batch = baq_pending[i].batch;
        }
    }
    return (min_batch != 0 && baq_count >= min_batch);
}

/* Would the batch flush on the TIME trigger? True once any parked op has waited at
 * least its own wait_ms (ngx_current_msec is the worker's monotonic clock). */
static ngx_uint_t
baq_time_triggered(void)
{
    ngx_uint_t i;

    for (i = 0; i < baq_count; i++) {
        if (baq_pending[i].wait_ms == 0) {
            return 1;                        /* 0ms wait = flush at the next tick */
        }
        if (ngx_current_msec - baq_pending[i].enqueued_ms
            >= baq_pending[i].wait_ms)
        {
            return 1;
        }
    }
    return 0;
}

/* ---- public API ------------------------------------------------------------ */

ngx_int_t
brix_baq_enqueue(brix_baq_op_t op, const char *root_canon,
    const char *src_key, const char *dst_key, uint32_t mode,
    ngx_uint_t batch, ngx_msec_t wait_ms,
    brix_baq_done_pt done, void *client)
{
    brix_baq_pending_t *p;

    if (root_canon == NULL || src_key == NULL || done == NULL) {
        return NGX_ERROR;
    }

    /* Reject any path that would not fit the fixed record fields rather than
     * silently truncating it — a truncated path at drain would target the WRONG
     * object. The caller falls back to running the op inline. */
    if (strlen(root_canon) >= sizeof(baq_pending[0].rec.root_canon)
        || strlen(src_key) >= sizeof(baq_pending[0].rec.src_key)
        || (dst_key != NULL
            && strlen(dst_key) >= sizeof(baq_pending[0].rec.dst_key)))
    {
        return NGX_ERROR;
    }

    /* At capacity: drain now to make room. If a full-queue drain still leaves us
     * at capacity (should not happen — drain empties it), fail so the caller runs
     * the op inline rather than overwrite a parked row. */
    if (baq_count >= BRIX_BAQ_MAX_PENDING) {
        baq_drain_all();
    }
    if (baq_count >= BRIX_BAQ_MAX_PENDING) {
        return NGX_ERROR;
    }

    p = &baq_pending[baq_count];
    ngx_memzero(&p->rec, sizeof(p->rec));
    baq_reqid_mint(p->rec.reqid);
    p->rec.op = (uint32_t) op;
    snprintf(p->rec.root_canon, sizeof(p->rec.root_canon), "%s", root_canon);
    snprintf(p->rec.src_key, sizeof(p->rec.src_key), "%s", src_key);
    if (dst_key != NULL) {
        snprintf(p->rec.dst_key, sizeof(p->rec.dst_key), "%s", dst_key);
    }
    p->rec.mode        = mode;
    p->rec.enqueued_at = (int64_t) time(NULL);
    p->done            = done;
    p->client          = client;
    p->batch           = (batch == 0) ? 1 : batch;
    p->wait_ms         = wait_ms;
    p->enqueued_ms     = ngx_current_msec;

    baq_journal_write(&p->rec);              /* durable BEFORE the client parks */
    baq_count++;

    /* Size trigger: post a deferred drain rather than draining inline, so this op's
     * waker never fires before the caller has finished parking its client (a batch
     * of 1 still behaves like a synchronous mutation with a durable record, just one
     * event-loop hop later). */
    if (baq_size_triggered()) {
        baq_post_drain();
    }
    return NGX_OK;
}

void
brix_baq_tick(void)
{
    if (baq_count > 0 && baq_time_triggered()) {
        baq_drain_all();
    }
}

void
brix_baq_drop_client(void *client)
{
    ngx_uint_t i = 0;

    /* Compact the array, dropping rows for `client`. Their durable records are
     * intentionally LEFT on disk so an un-drained mutation is replayed at boot. */
    while (i < baq_count) {
        if (baq_pending[i].client == client) {
            baq_pending[i] = baq_pending[baq_count - 1];
            baq_count--;                     /* re-test the swapped-in row */
            continue;
        }
        i++;
    }
}

/* ---- restart replay -------------------------------------------------------- */

/* Re-apply ONE persisted record idempotently; remove it on success. Returns
 * 1 replayed / 0 kept (transient failure) / -1 dropped (corrupt). */
static int
baq_reconcile_one(const char *path, ngx_log_t *log)
{
    brix_baq_rec_t rec;
    char           rbuf[sizeof(brix_baq_rec_t)];
    int            fd, e;
    ssize_t        n;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    n = read(fd, rbuf, sizeof(rbuf));
    (void) close(fd);

    if (n != (ssize_t) sizeof(rec)) {
        (void) unlink(path);                 /* short/corrupt/oversized — drop */
        return -1;
    }
    ngx_memcpy(&rec, rbuf, sizeof(rec));
    if (rec.op > BRIX_BAQ_MKDIR) {
        (void) unlink(path);                 /* unknown op — drop */
        return -1;
    }

    e = baq_apply_idempotent(&rec, log);
    if (e == 0) {
        (void) unlink(path);
        return 1;
    }
    ngx_log_error(NGX_LOG_WARN, log, e,
        "xrootd backend-async: reconcile of \"%s\" (op %uD root \"%s\") kept "
        "for retry", rec.src_key, rec.op, rec.root_canon);
    return 0;
}

void
brix_baq_reconcile(void)
{
    char           names[1024][256];
    DIR           *d;
    struct dirent *de;
    ngx_uint_t     ncount = 0, i, replayed = 0, kept = 0, dropped = 0;
    ngx_log_t     *log;

    if (baq_journal_dir[0] == '\0' || ngx_cycle == NULL) {
        return;
    }
    log = ngx_cycle->log;

    /* Snapshot the *.req names first (we unlink while driving). */
    d = opendir(baq_journal_dir);
    if (d == NULL) {
        return;
    }
    while ((de = readdir(d)) != NULL && ncount < 1024) {
        size_t nlen = strlen(de->d_name);

        if (nlen > 4 && nlen < 256
            && strcmp(de->d_name + nlen - 4, ".req") == 0)
        {
            memcpy(names[ncount], de->d_name, nlen + 1);
            ncount++;
        }
    }
    closedir(d);

    for (i = 0; i < ncount; i++) {
        char path[1400];
        int  r;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s",
                              baq_journal_dir, names[i]) >= sizeof(path))
        {
            continue;
        }
        r = baq_reconcile_one(path, log);
        if (r > 0)      { replayed++; }
        else if (r < 0) { dropped++;  }
        else            { kept++;     }
    }

    if (replayed > 0 || kept > 0 || dropped > 0) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "xrootd backend-async: restart reconcile — %ui mutation(s) replayed, "
            "%ui kept for retry, %ui dropped", replayed, kept, dropped);
    }
}
