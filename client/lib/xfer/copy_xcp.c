/*
 * copy_xcp.c — extreme copy: multi-source block-stealing download (phase-100).
 *
 * WHAT: copy_download_xcp() downloads one known-size file from up to
 *       --sources N replicas concurrently: the file is cut into blocks, each
 *       worker owns one connection to one replica and claims blocks from a
 *       shared table; when no unclaimed block remains, idle workers STEAL
 *       blocks still in flight on slower sources (bounded duplicate fetch,
 *       first-writer-wins on identical bytes), so the tail finishes at the
 *       speed of the fastest replicas.
 * WHY:  The upstream XrdCl XCpCtx behavior (xrdcp --sources): aggregate
 *       bandwidth across replicas and survive a dead/slow mirror mid-transfer.
 *       The phase-94 striped --parallel path fans one server across bound
 *       streams; this engine fans DISTINCT servers, with dynamic instead of
 *       static range assignment.
 * HOW:  Replica URLs come from copy_xcp_sources.c (metalink mirrors → locate
 *       → duplication). Per-block atomic state bytes coordinate claim/steal;
 *       disjoint pwrites into the shared VFS temp reassemble by offset
 *       (io_uring OFF, the phase-94 thread-safety pattern). Fail-closed:
 *       losing every worker aborts the temp; losing some is survived by
 *       claim-return + stealing.
 */
#include "copy_internal.h"
#include "copy_xcp_internal.h"

#include <pthread.h>


/* ---- Record the first worker failure (for the final verdict) ----
 *
 * WHAT: First caller stores its status into sh->first_err; later callers are
 *       ignored.
 *
 * WHY: The transfer's failure message should name the FIRST fault, not
 *       whichever worker lost the shutdown race.
 *
 * HOW: CAS latch on have_err.
 */
static void
xcp_note_error(xcp_shared_t *sh, const brix_status *st)
{
    int expected = 0;

    if (atomic_compare_exchange_strong(&sh->have_err, &expected, 1)) {
        sh->first_err = *st;
    }
}


/* ---- Claim the next block for a worker ----
 *
 * WHAT: Return a block index to fetch and set *stole (0 = fresh claim,
 *       1 = stealing a BUSY block), or -1 when nothing is claimable right now
 *       (all DONE, or every BUSY block already has its one stealer).
 *
 * WHY: Dynamic assignment IS the extreme-copy scheduler: fast sources come
 *      back sooner and naturally take more blocks; the steal arm keeps the
 *      transfer from ending at the slowest source's pace.
 *
 * HOW: 1. One rotating-scan pass CASing XCP_TODO→XCP_BUSY (the per-worker
 *         start hint spreads workers across the table so they do not contend
 *         block 0).
 *         2. A second pass latches the first un-stolen XCP_BUSY block. At most
 *         one stealer per block bounds duplicate fetches to 2x.
 */
static ssize_t
xcp_claim(xcp_shared_t *sh, unsigned hint, int *stole)
{
    size_t i;

    for (i = 0; i < sh->nblocks; i++) {
        size_t idx = (hint + i) % sh->nblocks;
        unsigned char expected = XCP_TODO;
        if (atomic_compare_exchange_strong(&sh->state[idx], &expected,
                                           XCP_BUSY)) {
            *stole = 0;
            return (ssize_t) idx;
        }
    }
    for (i = 0; i < sh->nblocks; i++) {
        unsigned char expected = 0;
        if (atomic_load(&sh->state[i]) == XCP_BUSY
            && atomic_compare_exchange_strong(&sh->stealer[i], &expected, 1)) {
            /* Re-check: the owner may have finished between the two loads. */
            if (atomic_load(&sh->state[i]) == XCP_BUSY) {
                atomic_fetch_add(&sh->steals, 1);
                *stole = 1;
                return (ssize_t) i;
            }
            atomic_store(&sh->stealer[i], 0);
        }
    }
    return -1;
}


/* ---- Are all blocks DONE? ---- */
static int
xcp_all_done(const xcp_shared_t *sh)
{
    size_t i;

    for (i = 0; i < sh->nblocks; i++) {
        if (atomic_load(&sh->state[i]) != XCP_DONE) {
            return 0;
        }
    }
    return 1;
}


/* ---- Fetch one block from this worker's replica into the dest temp ----
 *
 * WHAT: Read [idx*block, min(size, (idx+1)*block)) from the open handle and
 *       pwrite it at its absolute offset; mark the block DONE (counting its
 *       bytes exactly once, whichever racer gets there first). 0 / -1.
 *
 * WHY: The per-block unit of work both the claim and steal arms share.
 *
 * HOW: Short-read loop; between reads, bail out early on operator cancel or
 *      when the racing fetcher already finished the block (a stolen block's
 *      owner, or a stealer racing this owner).
 */
static int
xcp_fetch_block(xcp_worker_t *w, brix_conn *c, brix_file *f, size_t idx,
                uint8_t *buf)
{
    xcp_shared_t *sh = w->sh;
    int64_t start = (int64_t) idx * (int64_t) sh->block;
    int64_t end = start + (int64_t) sh->block;
    int64_t off = start;

    if (end > sh->size) {
        end = sh->size;
    }
    while (off < end) {
        ssize_t n;

        if (brix_copy_quit_requested()) {
            brix_status_set(&w->st, XRDC_ESOCK, EINTR, "cancelled (signal)");
            return -1;
        }
        if (atomic_load(&sh->state[idx]) == XCP_DONE) {
            return 0;   /* the racing fetcher finished this block first */
        }
        n = brix_file_read(c, f, off, buf + (off - start),
                           (size_t) (end - off), &w->st);
        if (n <= 0) {
            if (n == 0) {
                brix_status_set(&w->st, XRDC_EPROTO, 0,
                                "short read at %lld from %s",
                                (long long) off, w->url);
            }
            return -1;
        }
        off += n;
    }
    if (brix_vfs_pwrite(sh->vf, start, buf, (size_t) (end - start),
                        &w->st) != 0) {
        return -1;
    }
    if (atomic_exchange(&sh->state[idx], XCP_DONE) != XCP_DONE) {
        atomic_fetch_add(&sh->done_bytes,
                         (unsigned long long) (end - start));
        w->blocks_done++;
    }
    return 0;
}


/* ---- Undo a claim this worker cannot finish ----
 *
 * WHAT: Return a fresh-claimed block to XCP_TODO, or release the stealer latch
 *       of a stolen one (unless the block completed meanwhile).
 *
 * WHY: A dying worker must never strand a block in XCP_BUSY — the survivors'
 *      claim scan only picks up XCP_TODO entries.
 *
 * HOW: CAS XCP_BUSY→XCP_TODO for claims (an XCP_DONE result means the stealer
 *      won — leave it); plain latch clear for steals.
 */
static void
xcp_release_block(xcp_shared_t *sh, size_t idx, int stole)
{
    if (stole) {
        atomic_store(&sh->stealer[idx], 0);
        return;
    }
    {
        unsigned char expected = XCP_BUSY;
        atomic_compare_exchange_strong(&sh->state[idx], &expected, XCP_TODO);
    }
}


/* ---- Release an unstarted worker's reserved block ----
 *
 * WHAT: Return a startup reservation to the normal claim pool.
 *
 * WHY: A replica can fail before it reaches the block loop; its reserved
 *      block must not remain invisible to the surviving workers.
 *
 * HOW: Atomically change only XCP_RESERVED to XCP_TODO. A worker that has
 *      already claimed the reservation owns the ordinary release path.
 */
static void
xcp_release_reserved_block(xcp_shared_t *sh, size_t idx)
{
    unsigned char expected = XCP_RESERVED;
    atomic_compare_exchange_strong(&sh->state[idx], &expected, XCP_TODO);
}


/* ---- Drive one worker's claim/fetch loop ----
 *
 * WHAT: Fetch the startup reservation and then claim or steal blocks until the
 *       destination is complete, cancellation is requested, or a fetch fails.
 *       Returns 0 for a worker that can leave normally and -1 for its failure.
 *
 * WHY: The thread entry point owns connection/buffer lifetime; keeping the
 *      scheduler in this helper makes those resource edges independent of the
 *      block-stealing state machine and keeps both paths below the complexity
 *      gate.
 *
 * HOW: 1. Convert the startup reservation into a normal busy claim and fetch it.
 *      2. Repeatedly claim/steal, fetch, and release the stealer latch.
 *      3. Wait briefly when a straggler owns the remaining work; stop on DONE or
 *         cancellation and return the worker verdict.
 */
static int
xcp_worker_blocks(xcp_worker_t *w, brix_conn *c, brix_file *f, uint8_t *buf)
{
    xcp_shared_t *sh = w->sh;
    int rc = 0;

    if (w->initial_reserved) {
        unsigned char expected = XCP_RESERVED;

        if (atomic_compare_exchange_strong(&sh->state[w->initial_idx],
                                           &expected, XCP_BUSY)) {
            w->initial_reserved = 0;
            if (xcp_fetch_block(w, c, f, w->initial_idx, buf) != 0) {
                xcp_release_block(sh, w->initial_idx, 0);
                rc = -1;
            }
        } else {
            w->initial_reserved = 0;
        }
    }

    while (rc == 0) {
        int stole = 0;
        ssize_t idx = xcp_claim(sh, w->claim_hint, &stole);

        if (idx < 0) {
            if (xcp_all_done(sh)) {
                break;
            }
            if (brix_copy_quit_requested()) {
                brix_status_set(&w->st, XRDC_ESOCK, EINTR,
                                "cancelled (signal)");
                rc = -1;
                break;
            }
            /* Blocks remain but none claimable: idle-wait for a straggler
             * to finish, die, or free its steal slot. Bounded tail spin. */
            {
                struct timespec ts = { 0, 20 * 1000 * 1000 };
                nanosleep(&ts, NULL);
            }
            continue;
        }

        w->claim_hint = (unsigned) idx + 1;
        if (xcp_fetch_block(w, c, f, (size_t) idx, buf) != 0) {
            xcp_release_block(sh, (size_t) idx, stole);
            rc = -1;
            break;
        }
        if (stole) {
            atomic_store(&sh->stealer[(size_t) idx], 0);
        }
    }

    return rc;
}


/* ---- Worker thread: one replica connection driving the block loop ----
 *
 * WHAT: Connect + open this worker's replica URL, then claim/steal/fetch until
 *       every block is DONE, an unrecoverable local fault hits, or the replica
 *       dies (w->rc = -1, block returned, engine survives on the others).
 *
 * WHY: One thread per replica keeps each connection's request pipeline full —
 *      the whole point of multi-source — while the atomics above make worker
 *      death safe at any instant.
 *
 * HOW: 1. Parse/connect/open (any failure kills only this worker). 2. Loop:
 *         claim else steal else (blocks remain? 20 ms idle wait : exit).
 *         3. Fetch errors release the block and kill the worker. 4. Teardown
 *         always closes handle + connection and drops the live count.
 */
static void *
xcp_worker_main(void *arg)
{
    xcp_worker_t *w = (xcp_worker_t *) arg;
    xcp_shared_t *sh = w->sh;
    brix_url      u;
    brix_conn     c;
    brix_file     f;
    uint8_t      *buf = NULL;
    int           opened = 0, connected = 0;

    w->rc = -1;
    if (brix_url_parse(w->url, &u, &w->st) == 0
        && brix_connect(&c, &u, sh->co, &w->st) == 0) {
        connected = 1;
        if (brix_file_open_read(&c, u.path, &f, &w->st) == 0) {
            opened = 1;
            buf = (uint8_t *) malloc(sh->block);
            if (buf == NULL) {
                brix_status_set(&w->st, XRDC_EPROTO, 0, "out of memory");
            }
        }
    }

    if (buf != NULL) {
        w->rc = xcp_worker_blocks(w, &c, &f, buf);
    }

    if (w->initial_reserved) {
        xcp_release_reserved_block(sh, w->initial_idx);
        w->initial_reserved = 0;
    }

    if (w->rc != 0) {
        xcp_note_error(sh, &w->st);
    }
    free(buf);
    if (opened) {
        brix_status throwaway;
        brix_status_clear(&throwaway);
        brix_file_close(&c, &f, &throwaway);
    }
    if (connected) {
        brix_close(&c);
    }
    atomic_fetch_sub(&sh->live, 1);
    return NULL;
}


/* ---- Spawn the workers, report progress, join, and give the verdict ----
 *
 * WHAT: Run n workers to completion. 0 when every block is DONE, else -1 with
 *       *st carrying the first worker failure.
 *
 * WHY: Keeping the thread lifecycle + the single-threaded progress feed in one
 *      helper leaves the orchestrator a flat setup/commit sequence. The
 *      coordinator (not the workers) invokes o->progress, preserving the
 *      serial pump's "progress callback runs on one thread" contract.
 *
 * HOW: 1. Spawn each worker (a spawn failure just burns that slot's live
 *         count — the engine needs only >= 1 running). 2. Poll live/donebytes
 *         at 100 ms, feeding progress. 3. Join, final progress tick, verdict.
 */
static int
xcp_run_workers(xcp_shared_t *sh, xcp_worker_t *w, pthread_t *th, size_t n,
                const brix_copy_opts *o)
{
    size_t k;

    atomic_store(&sh->live, (unsigned) n);
    for (k = 0; k < n; k++) {
        if (k < sh->nblocks) {
            w[k].initial_idx = k;
            w[k].initial_reserved = 1;
            atomic_store(&sh->state[k], XCP_RESERVED);
        }
        if (pthread_create(&th[k], NULL, xcp_worker_main, &w[k]) != 0) {
            th[k] = 0;
            if (w[k].initial_reserved) {
                xcp_release_reserved_block(sh, w[k].initial_idx);
                w[k].initial_reserved = 0;
            }
            atomic_fetch_sub(&sh->live, 1);
        }
    }
    while (atomic_load(&sh->live) > 0) {
        struct timespec ts = { 0, 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        if (o->progress != NULL) {
            o->progress(o->progress_arg,
                        (long long) atomic_load(&sh->done_bytes),
                        (long long) sh->size);
        }
    }
    for (k = 0; k < n; k++) {
        if (th[k] != 0) {
            pthread_join(th[k], NULL);
        }
    }
    if (o->progress != NULL) {
        o->progress(o->progress_arg,
                    (long long) atomic_load(&sh->done_bytes),
                    (long long) sh->size);
    }
    return xcp_all_done(sh) ? 0 : -1;
}


/* ---- Eligibility: may this download run the extreme-copy engine? ----
 *
 * WHAT: 1 only for an explicit --sources >= 2 download to a real local file of
 *       known size >= 2 blocks, with no per-request payload transforms.
 *
 * WHY: pgread framing and inline decompression are per-connection negotiated
 *      states the block engine does not carry; tiny/unknown sizes cannot be
 *      cut into blocks worth two connections.
 *
 * HOW: Cheap predicate over the job; the caller falls back to the serial (or
 *      --parallel) path on 0.
 */
static int
xcp_eligible(const download_job_t *job, size_t block)
{
    const brix_copy_opts *o = job->o;

    return o->sources >= 2
        && job->du->scheme != XRDC_SCHEME_STDIO
        && !o->pgrw
        && !(o->compress != NULL && o->compress[0] != '\0')
        && job->si->size >= 2 * (int64_t) block;
}


/* ---- Print the observability line the dedicated tests assert on ---- */
static void
xcp_debug_line(const xcp_shared_t *sh, const xcp_worker_t *w, size_t n)
{
    size_t k;

    if (getenv("BRIX_XCP_DEBUG") == NULL) {
        return;
    }
    fprintf(stderr, "brix: xcp sources=%zu blocks=%zu per-source=[", n,
            sh->nblocks);
    for (k = 0; k < n; k++) {
        fprintf(stderr, "%s%u", k ? "," : "", w[k].blocks_done);
    }
    fprintf(stderr, "] steals=%u\n", atomic_load(&sh->steals));
}


/* ---- Run the multi-source block-stealing download end-to-end ----
 *
 * WHAT: Returns 1 when it handled the transfer (verdict in *out_rc), or 0 when
 *       the request is not eligible and the caller should fall through to the
 *       --parallel / serial paths. Same contract as copy_download_parallel.
 *
 * WHY: The audit's §7.2 extreme-copy gap: replica-parallel downloads with
 *      block stealing, fed by metalink mirrors or locate discovery.
 *
 * HOW: 1. Eligibility gate. 2. Build the replica list (>= 2 workers). 3. Open
 *         the dest via the VFS (atomic temp+rename, io_uring OFF so pwrite(2)
 *         is thread-safe for the disjoint blocks). 4. Allocate block tables +
 *         run the workers. 5. Debug line, then the shared commit/abort +
 *         checksum-reconcile helper gives the final verdict.
 */
int
copy_download_xcp(const download_job_t *job, int *out_rc, brix_status *st)
{
    const brix_copy_opts *o = job->o;
    size_t             block = xcp_block_size();
    size_t             want, n, k;
    xcp_shared_t       sh;
    xcp_worker_t      *w;
    pthread_t         *th;
    brix_vfs_open_opts vopts = {0};
    int                rc = -1;

    if (!xcp_eligible(job, block)) {
        return 0;
    }
    want = (size_t) o->sources;
    if (want > XRDC_XCP_MAX_SRCS) {
        want = XRDC_XCP_MAX_SRCS;
    }

    memset(&sh, 0, sizeof(sh));
    sh.size = job->si->size;
    sh.block = block;
    sh.nblocks = (size_t) ((sh.size + (int64_t) block - 1) / (int64_t) block);
    sh.co = job->co;

    w  = (xcp_worker_t *) calloc(want, sizeof(*w));
    th = (pthread_t *)  calloc(want, sizeof(*th));
    sh.state   = (atomic_uchar *) calloc(sh.nblocks, sizeof(atomic_uchar));
    sh.stealer = (atomic_uchar *) calloc(sh.nblocks, sizeof(atomic_uchar));
    if (w == NULL || th == NULL || sh.state == NULL || sh.stealer == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        free(w); free(th); free(sh.state); free(sh.stealer);
        *out_rc = -1;
        return 1;
    }

    for (k = 0; k < want; k++) {
        w[k].sh = &sh;
        /* Spread the initial claim scans across the table. */
        w[k].claim_hint = (unsigned) ((sh.nblocks / want) * k);
        brix_status_clear(&w[k].st);
    }
    n = xcp_build_sources(job, w, want);
    if (n < 2) {
        free(w); free(th); free(sh.state); free(sh.stealer);
        return 0;   /* could not even duplicate: serial path handles it */
    }

    vopts.io_uring      = XRDC_IO_URING_OFF;
    vopts.expected_size = sh.size;
    if (brix_vfs_open(job->du->path,
                      XRDC_VFS_WRITE | (o->force ? XRDC_VFS_FORCE : 0),
                      &vopts, &sh.vf, st) != 0) {
        free(w); free(th); free(sh.state); free(sh.stealer);
        *out_rc = -1;
        return 1;
    }

    rc = xcp_run_workers(&sh, w, th, n, o);
    if (rc != 0) {
        if (atomic_load(&sh.have_err)) {
            *st = sh.first_err;
        } else {
            brix_status_set(st, XRDC_ESOCK, 0, "xcp: no worker completed");
        }
    }
    xcp_debug_line(&sh, w, n);

    rc = download_commit_or_abort(job, sh.vf, rc, st);

    free(w); free(th); free(sh.state); free(sh.stealer);
    *out_rc = rc;
    return 1;
}
