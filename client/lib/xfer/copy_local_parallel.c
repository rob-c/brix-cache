/*
 * copy_local_parallel.c - the TRUE concurrent striped download (phase 94,
 * opt-in via --parallel). Split from copy_local.c (600-line ratchet); the
 * serial download paths and the shared temp/commit helpers stay there.
 */
#include "copy_internal.h"

#include <pthread.h>   /* Phase 94: concurrent striped download workers */

/*
 * Phase 94 — TRUE concurrent striped download (opt-in, --parallel).
 *
 * WHAT: one thread per bound connection (primary + secondaries), each streaming a
 *       DISJOINT contiguous byte range of the source and pwrite()-ing it into the
 *       destination at its absolute offset.  Reassembly is by offset, so the
 *       stripes are order-independent and need no coordination — the real
 *       multi-stream throughput the serial round-robin fan-out cannot give (the
 *       serial pump has one in-flight request at a time).
 *
 * WHY:  on a high-latency link N connections reading in parallel hide N× the RTT.
 *       kXR_read carries no pathid, so a read on a bound secondary is served on
 *       that connection against the primary-published handle — the same handle the
 *       server publishes to its SHM table for cross-worker bound reads.
 *
 * SAFETY: `brix_file` is a POD (fhandle + codec bytes) and the read path only
 *       READS it (streamid comes from each connection's own brix_send), so the
 *       single handle is shared read-only across the workers with no lock; each
 *       worker owns its connection and its own brix_status, and the pwrite ranges
 *       are disjoint.  The path is FAIL-CLOSED: any worker error drops the temp and
 *       fails the copy (no single-link resilient ride-out — that is why --parallel
 *       is opt-in and the resilient serial fan-out stays the default).
 */
typedef struct {
    brix_conn     *c;    /* this worker's connection (never shared)            */
    brix_file     *f;    /* SHARED read-only handle (POD; read never mutates)  */
    brix_vfs_file *vf;   /* SHARED dest VFS handle — disjoint pwrite ranges,
                          * io_uring OFF so posix_pwrite is a plain thread-safe
                          * pwrite(2) at an explicit offset (no shared cursor)  */
    int64_t        start;/* inclusive                                          */
    int64_t        end;  /* exclusive                                          */
    int            rc;   /* 0 ok / -1 fail                                     */
    brix_status    st;   /* per-worker status (never shared)                   */
} dl_stripe_t;


static void *
dl_stripe_worker(void *arg)
{
    dl_stripe_t *w   = (dl_stripe_t *) arg;
    uint8_t     *buf = (uint8_t *) malloc(XRDC_COPY_CHUNK);
    int64_t      off = w->start;

    if (buf == NULL) {
        brix_status_set(&w->st, XRDC_EPROTO, 0, "out of memory");
        w->rc = -1;
        return NULL;
    }
    while (off < w->end) {
        int64_t remain = w->end - off;
        size_t  want   = (remain < (int64_t) XRDC_COPY_CHUNK)
                         ? (size_t) remain : XRDC_COPY_CHUNK;
        ssize_t n;

        if (brix_copy_quit_requested()) {
            brix_status_set(&w->st, XRDC_ESOCK, EINTR, "cancelled (signal)");
            w->rc = -1;
            free(buf);
            return NULL;
        }
        n = brix_file_read(w->c, w->f, off, buf, want, &w->st);
        if (n <= 0) {
            if (n == 0) {
                brix_status_set(&w->st, XRDC_EPROTO, 0,
                                "short read at %lld", (long long) off);
            }
            w->rc = -1;
            free(buf);
            return NULL;
        }
        if (brix_vfs_pwrite(w->vf, off, buf, (size_t) n, &w->st) != 0) {
            w->rc = -1;
            free(buf);
            return NULL;
        }
        off += n;
    }
    w->rc = 0;
    free(buf);
    return NULL;
}


/* Eligible for the concurrent striped path?  Explicit opt-in, a real local
 * destination, and a plain known-size object big enough to be worth ≥2 stripes;
 * everything else (stdout, --compress, --pgrw, tiny/unknown size) uses the serial
 * pump.  All cheap, no I/O. */
static int
dl_parallel_eligible(const download_job_t *job)
{
    const brix_copy_opts *o = job->o;

    return o->parallel
        && job->du->scheme != XRDC_SCHEME_STDIO
        && !o->pgrw
        && !(o->compress != NULL && o->compress[0] != '\0')
        && job->si->size >= 2 * (int64_t) XRDC_COPY_CHUNK;
}


/* Partition [0,size) into `nconns` contiguous stripes; the last absorbs the
 * remainder.  Worker 0 uses the primary connection, worker k the (k-1)-th
 * secondary.  All workers share the read-only handle `f` and dest handle `vf`. */
static void
dl_plan_stripes(dl_stripe_t *w, int nconns, brix_streamset *ss, brix_conn *primary,
                brix_file *f, brix_vfs_file *vf, int64_t size)
{
    int64_t stride = (size + nconns - 1) / nconns;
    int     k;

    for (k = 0; k < nconns; k++) {
        w[k].c     = (k == 0) ? primary : &ss->sec[k - 1];
        w[k].f     = f;
        w[k].vf    = vf;
        w[k].start = (int64_t) k * stride;
        w[k].end   = w[k].start + stride;
        if (w[k].end > size) {
            w[k].end = size;
        }
        if (w[k].start > size) {
            w[k].start = size;   /* empty tail stripe (size < nconns*stride) */
        }
        brix_status_clear(&w[k].st);
        w[k].rc = 0;
    }
}


/* Spawn workers 1..n-1 on their own threads (a spawn failure runs that stripe
 * inline so none is dropped), run worker 0 inline, join, then fold the verdicts:
 * fail-closed — any stripe error returns -1 with that stripe's status in *st. */
static int
dl_run_stripes(dl_stripe_t *w, pthread_t *th, int nconns, brix_status *st)
{
    int k, rc = 0;

    for (k = 1; k < nconns; k++) {
        if (pthread_create(&th[k], NULL, dl_stripe_worker, &w[k]) != 0) {
            dl_stripe_worker(&w[k]);
            th[k] = 0;
        }
    }
    dl_stripe_worker(&w[0]);
    for (k = 1; k < nconns; k++) {
        if (th[k] != 0) {
            pthread_join(th[k], NULL);
        }
    }
    for (k = 0; k < nconns; k++) {
        if (w[k].rc != 0) {
            *st = w[k].st;   /* surface the first failing stripe's status */
            rc = -1;
            break;
        }
    }
    return rc;
}


/* Commit (fsync+rename) a fully-successful concurrent download and verify its
 * checksum, or abort the temp so the destination is never partial — mirroring
 * download_to_local_file.  Always closes `vf`.  Returns the final verdict.
 * Shared (copy_internal.h) with the phase-100 extreme-copy engine, whose
 * commit/abort/cksum-drop semantics are identical. */
int
download_commit_or_abort(const download_job_t *job, brix_vfs_file *vf, int rc,
                         brix_status *st)
{
    int committed = 0;

    if (rc == 0) {
        rc = brix_vfs_commit(vf, st);
        if (rc == 0) {
            committed = 1;
            if (job->o->cksum != NULL) {
                rc = download_reconcile_cksum(job, job->du->path, st);
                if (rc != 0) {
                    unlink(job->du->path);   /* drop committed-but-bad file */
                }
            }
        }
    }
    if (rc != 0 && !committed) {
        brix_vfs_abort(vf);
    }
    brix_vfs_close(vf);
    return rc;
}


/* Run the concurrent striped download end-to-end.  Returns 1 when it handled the
 * transfer (verdict in *out_rc), or 0 when the request is not eligible for the
 * parallel path and the caller should run the serial pump.  On the handled path
 * it opens its own read handle + binds the secondaries into job->ss (the caller
 * still owns the streamset teardown). */
int
copy_download_parallel(const download_job_t *job, int *out_rc, brix_status *st)
{
    const brix_copy_opts *o  = job->o;
    int64_t   size = job->si->size;
    brix_file f;
    brix_vfs_file     *vf = NULL;
    brix_vfs_open_opts vopts = {0};
    int          nconns, rc;
    dl_stripe_t *w;
    pthread_t   *th;

    if (!dl_parallel_eligible(job)) {
        return 0;
    }
    if (brix_file_open_read(job->c, job->su->path, &f, st) != 0) {
        *out_rc = -1;
        return 1;
    }
    brix_streams_open(job->ss, job->c, o->streams, st);   /* best-effort; n may be 0 */
    nconns = 1 + job->ss->n;
    if (getenv("BRIX_STREAMS_DEBUG") != NULL) {
        fprintf(stderr, "brix: parallel-download stripes=%d\n", nconns);
    }

    /* Atomic temp+rename via the VFS (INV-12), io_uring OFF so posix_pwrite is a
     * plain pwrite(2) at an explicit offset — thread-safe for the disjoint stripe
     * ranges (no shared ring / cursor). */
    vopts.io_uring      = XRDC_IO_URING_OFF;
    vopts.expected_size = size;
    if (brix_vfs_open(job->du->path,
                      XRDC_VFS_WRITE | (o->force ? XRDC_VFS_FORCE : 0),
                      &vopts, &vf, st) != 0) {
        brix_file_close(job->c, &f, st);
        *out_rc = -1;
        return 1;
    }

    w  = (dl_stripe_t *) calloc((size_t) nconns, sizeof(*w));
    th = (pthread_t *)  calloc((size_t) nconns, sizeof(*th));
    if (w == NULL || th == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        rc = -1;
    } else {
        dl_plan_stripes(w, nconns, job->ss, job->c, &f, vf, size);
        rc = dl_run_stripes(w, th, nconns, st);
    }

    rc = download_commit_or_abort(job, vf, rc, st);
    brix_file_close(job->c, &f, st);
    free(w);
    free(th);
    *out_rc = rc;
    return 1;
}
