/*
 * copy_continue.c — xrdcp --continue: byte-offset download resume (§7.6).
 *
 * WHAT: copy_download_continue() handles a --continue download: the
 *       destination file is written DIRECTLY (no atomic temp+rename), and
 *       when it already exists the transfer resumes at its current size —
 *       stock xrdcp's --continue semantics.
 * WHY:  The normal download path deliberately never leaves a partial
 *       destination (temp+rename, abort unlinks).  That fail-closed posture
 *       makes interrupted multi-gigabyte transfers start over from byte 0;
 *       --continue is the operator's explicit opt-OUT: keep what arrived,
 *       finish the rest.  The audit (§7.6) lists it as the one missing
 *       resume mode (the journal --resume is whole-file only).
 * HOW:  Gate first in copy_download (before the destination-exists check —
 *       an existing partial is the POINT).  stat the local file, bound-check
 *       against the remote size, then a plain offset read loop appending at
 *       the partial's tail.  fsync before the verdict.  --cksum, when given,
 *       verifies the COMPLETED file exactly like the normal path (and drops
 *       it on a genuine mismatch — a finished-but-corrupt file is never kept;
 *       only IN-PROGRESS partials are preserved).
 */
#include "copy_internal.h"

#include <fcntl.h>
#include <sys/stat.h>

/* Resume-mode read granularity: a chunk lost mid-flight to a sever is
 * progress the NEXT attempt must refetch, so --continue trades a little
 * pipeline depth for durability — 1 MiB bounds the refetch per fault while
 * the normal (non-resume) paths keep the full 8 MiB chunk. */
#define XRDC_CONTINUE_CHUNK  (1024u * 1024u)


/* ---- Pull [start, size) from the open source into fd at the same offset ----
 *
 * WHAT: Chunked offset read loop: brix_rfile reads from `start` to the known
 *       remote size, pwrite'ing each chunk at its absolute offset. Feeds
 *       o->progress with absolute completion. 0 / -1 (st set).
 *
 * WHY: download_stream_body always pumps from byte 0; resume needs an
 *      arbitrary starting offset, and the plain pread/pwrite pair keeps the
 *      resumed region byte-addressed (no rename dance to preserve the head).
 *
 * HOW: 1. Open the remote for read (resilient handle, same as stream_file).
 *      2. Loop XRDC_COPY_CHUNK reads; short reads advance by what arrived;
 *         EOF before `size` is a protocol error (size was authoritative).
 *      3. Progress callback per chunk with (start + done, size).
 */
static int
continue_pull_tail(const download_job_t *job, int fd, int64_t start,
                   brix_status *st)
{
    const brix_copy_opts *o = job->o;
    brix_rfile            rf;
    uint8_t              *buf;
    int64_t               off = start;
    uint64_t              t0 = brix_mono_ns();
    int                   rc = 0;

    if (brix_rfile_open_read(job->c, job->su->path, NULL, 0, -1, &rf,
                             st) != 0) {
        return -1;
    }
    buf = (uint8_t *) malloc(XRDC_COPY_CHUNK);
    if (buf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        brix_rfile_close(&rf, st);
        return -1;
    }
    while (off < job->si->size) {
        size_t  cap = brix_pump_pace_cap(o, XRDC_CONTINUE_CHUNK);
        size_t  want = (size_t) ((job->si->size - off < (int64_t) cap)
                                 ? (size_t) (job->si->size - off)
                                 : cap);
        ssize_t n = brix_rfile_pread(&rf, off, buf, want, st);

        if (n < 0) {
            rc = -1;
            break;
        }
        if (n == 0) {
            brix_status_set(st, XRDC_EPROTO, 0,
                            "source ended early at %lld (size said %lld)",
                            (long long) off, (long long) job->si->size);
            rc = -1;
            break;
        }
        if (pwrite(fd, buf, (size_t) n, (off_t) off) != n) {
            brix_status_set(st, XRDC_ESOCK, errno, "local write failed: %s",
                            strerror(errno));
            rc = -1;
            break;
        }
        off += n;
        if (o->progress != NULL) {
            o->progress(o->progress_arg, (long long) off,
                        (long long) job->si->size);
        }
        /* --xrate pacing counts only the RESUMED bytes (off - start). */
        if (brix_pump_pace(o, t0, off - start, st) != 0) {
            rc = -1;
            break;
        }
        if (brix_copy_quit_requested()) {
            brix_status_set(st, XRDC_ESOCK, EINTR, "cancelled (signal)");
            rc = -1;
            break;
        }
    }
    free(buf);
    {
        brix_status tw;
        brix_status_clear(&tw);
        brix_rfile_close(&rf, rc == 0 ? st : &tw);
    }
    return rc;
}


/* ---- Run a --continue download end-to-end ----
 *
 * WHAT: Returns 1 when it handled the transfer (verdict in *out_rc), 0 when
 *       --continue was not requested (caller proceeds normally). Same
 *       handled? contract as the xcp/parallel gates.
 *
 * WHY: §7.6 — resume an interrupted download at the partial's size instead
 *      of restarting; see the file header for the fail-open-partial /
 *      fail-closed-complete split.
 *
 * HOW: 1. stat the destination: absent → start 0; a non-regular file or one
 *         LARGER than the source are usage errors; equal size skips straight
 *         to the (optional) checksum verdict.
 *      2. Open O_WRONLY|O_CREAT (never O_TRUNC), pull the tail, fsync.
 *      3. Transfer failure keeps the partial (the mode's contract); a
 *         completed file failing --cksum is unlinked like the normal path.
 */
int
copy_download_continue(const download_job_t *job, int *out_rc, brix_status *st)
{
    const brix_copy_opts *o = job->o;
    struct stat           sb;
    int64_t               start = 0;
    int                   fd, rc = 0;

    if (!o->cont) {
        return 0;
    }

    if (stat(job->du->path, &sb) == 0) {
        if (!S_ISREG(sb.st_mode)) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "--continue: destination is not a regular file: %s",
                            job->du->path);
            *out_rc = -1;
            return 1;
        }
        start = (int64_t) sb.st_size;
    }
    if (start > job->si->size) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "--continue: local file (%lld bytes) is larger than "
                        "the source (%lld) — refusing to guess",
                        (long long) start, (long long) job->si->size);
        *out_rc = -1;
        return 1;
    }

    if (start < job->si->size) {
        fd = open(job->du->path, O_WRONLY | O_CREAT, 0644);
        if (fd < 0) {
            brix_status_set(st, XRDC_ESOCK, errno, "open %s failed: %s",
                            job->du->path, strerror(errno));
            *out_rc = -1;
            return 1;
        }
        rc = continue_pull_tail(job, fd, start, st);
        if (rc == 0 && fsync(fd) != 0) {
            brix_status_set(st, XRDC_ESOCK, errno, "fsync failed: %s",
                            strerror(errno));
            rc = -1;
        }
        close(fd);
        if (rc != 0) {
            *out_rc = -1;   /* the partial stays — that is the mode's point */
            return 1;
        }
    }

    if (o->cksum != NULL) {
        rc = download_reconcile_cksum(job, job->du->path, st);
        if (rc != 0) {
            unlink(job->du->path);   /* completed-but-corrupt: never kept */
        }
    }
    *out_rc = rc;
    return 1;
}
