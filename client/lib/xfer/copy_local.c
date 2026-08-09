/*
 * copy_local.c - extracted concern
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"



/*
 * Phase 40 (a): build a per-transfer-UNIQUE temp path
 * "<dst>.xrdcp-tmp.<pid>.<seq>". The pid alone is NOT unique under `-j`, whose
 * batch workers are threads sharing one pid — two same-basename sources copied
 * into one directory would otherwise collide on an identical temp name and
 * interleave-corrupt it (then rename a garbage file into place, reported as
 * success). A process-wide atomic sequence makes every concurrent transfer's
 * temp distinct; pids already differ across separate processes. Returns 0, or -1
 * if the composed path would not fit.
 */
int
make_temp_path(const char *dst, char *out, size_t outsz)
{
    static atomic_ulong seq;
    unsigned long s = atomic_fetch_add(&seq, 1ul);
    if ((size_t) snprintf(out, outsz, "%s.xrdcp-tmp.%ld.%lu",
                          dst, (long) getpid(), s) >= outsz) {
        return -1;
    }
    return 0;
}


/*
 * open_download_temp — create a fresh private temp next to `dst` for the
 * download+atomic-rename, and hand back its fd and name.
 *
 * WHY: the temp name is predictable (pid + counter), so an attacker with write
 *      access to the destination directory could pre-create it as a symlink and
 *      redirect our O_TRUNC onto a victim-owned file. O_EXCL refuses a
 *      pre-existing name and O_NOFOLLOW refuses a symlink, closing that race; we
 *      regenerate the name and retry on a stale collision so a leftover temp from
 *      a killed run doesn't wedge the transfer. Returns an fd (caller closes) and
 *      fills tmp[], or -1 with *st set.
 */
int
open_download_temp(const char *dst, char *tmp, size_t tmpsz, brix_status *st)
{
    int attempt;

    for (attempt = 0; attempt < 64; attempt++) {
        int fd;
        if (make_temp_path(dst, tmp, tmpsz) != 0) {
            brix_status_set(st, XRDC_EUSAGE, 0, "destination path too long: %s", dst);
            return -1;
        }
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
        if (fd >= 0) {
            return fd;
        }
        if (errno != EEXIST) {
            brix_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
                            tmp, strerror(errno));
            return -1;
        }
    }
    brix_status_set(st, XRDC_EUSAGE, EEXIST,
                    "could not create a unique temp for %s", dst);
    return -1;
}


/*
 * Commit (or discard) a temp destination: on rc==0 rename `tmp`→`dest`
 * atomically (downgrading rc to -1 with st set if the rename fails); on rc!=0
 * drop the temp. Returns the final rc. Shared by every local-dest writer so the
 * "atomic dest" guarantee lives in one place.
 */
int
atomic_dest_finish(const char *tmp, const char *dest, int rc, brix_status *st)
{
    if (rc == 0) {
        if (rename(tmp, dest) != 0) {
            brix_status_set(st, XRDC_ESOCK, errno, "rename %s -> %s: %s",
                            tmp, dest, strerror(errno));
            unlink(tmp);
            return -1;
        }
        return 0;
    }
    unlink(tmp);   /* drop the partial/cancelled/mismatched temp */
    return rc;
}


/*
 * WHAT: Reconnect a control connection to its home (redirector) endpoint,
 *       falling back to the currently-connected host/port when no home is set.
 * WHY:  Every resilient open/close retry re-establishes the session against the
 *       redirector (home_host/home_port) so a reopen re-runs the full locate,
 *       not a stale data-server address.  Confining that host/port selection to
 *       one helper removes the duplicated `home ?: current` picking from both
 *       the download and upload retry loops.
 * HOW:  Prefer c->home_host / c->home_port when populated; otherwise use the
 *       live c->host / c->port.  The reconnect result is intentionally ignored
 *       (the caller re-attempts the open and re-checks the deadline).
 */
void
csctx_reopen_home(brix_conn *c, brix_status *st)
{
    const char *h = (c->home_host[0] != '\0') ? c->home_host : c->host;
    int         p = (c->home_port != 0) ? c->home_port : c->port;
    (void) brix_reconnect(c, h, p, st);
}


/*
 * WHAT: Decide whether a failed resilient attempt may be retried, sleeping a
 *       backoff step when it can.
 * WHY:  The download open, upload open, and upload close-commit loops share one
 *       give-up rule — stop on a non-retryable status, an operator cancel, or a
 *       blown stall deadline — and otherwise back off before the next attempt.
 *       One predicate keeps that rule identical across all three callers.
 * HOW:  Returns 1 (retry, after brix_backoff_sleep_fast) when the status is
 *       retryable, no cancel is pending, and the deadline is still in the future;
 *       returns 0 (give up) otherwise.  `*attempt` is advanced on a retry so the
 *       backoff grows.
 */
int
csctx_retry_gate(const brix_status *st, uint64_t deadline_ns, unsigned *attempt)
{
    if (!brix_status_retryable(st) || brix_copy_quit_requested()
        || brix_mono_ns() >= deadline_ns) {
        return 0;
    }
    brix_backoff_sleep_fast((*attempt)++);
    return 1;
}


/*
 * WHAT: Open the download source read handle, retrying reconnect+reopen within
 *       the stall deadline on a transport fault.
 * WHY:  The open is the last single-RTT step of setup and is just as sever-prone
 *       as connect/stat on a lossy link, so it rides the same resilient loop.
 *       Split out so download_stream_body stays a flat sequence.
 * HOW:  Issues brix_file_open_opaque when a compress opaque is set (ctx->opaque),
 *       else brix_file_open_read; on failure applies csctx_retry_gate and, if it
 *       permits, reconnects to home and retries.  Returns 0 with *f open, or -1
 *       (st set) once the retry gate gives up.
 */
static int
download_open_resilient(const copy_stream_ctx_t *ctx, brix_file *f,
                        brix_status *st)
{
    unsigned attempt = 0;
    for (;;) {
        int orc = (ctx->opaque != NULL)
                  ? brix_file_open_opaque(ctx->c, ctx->path,
                                          ctx->opaque, 0, 0, 0, f, st)
                  : brix_file_open_read(ctx->c, ctx->path, f, st);
        if (orc == 0) {
            return 0;
        }
        if (!csctx_retry_gate(st, ctx->deadline_ns, &attempt)) {
            return -1;
        }
        csctx_reopen_home(ctx->c, st);   /* re-establish, then reopen */
    }
}


/*
 * WHAT: Open the source for read, stream the known-size body to the local sink,
 *       then close the remote handle — the whole "remote file is open" lifetime.
 * WHY:  Confining the open-read handle (and its secondary streams + scratch buf)
 *       to one helper lets the caller stay a flat early-return sequence: the file
 *       is always closed here, on every path, without a shared cleanup jump.
 * HOW:  open_read → streams_open(&ss) → pump(src, sink/sinkctx, si->size) →
 *       file_close.  The caller supplies (sink, sinkctx): either a VFS file via
 *       pump_sink_local_vfs + pump_local_t, or the stdout fd via pump_sink_local.
 *       Returns 0 on a complete transfer, -1 (st set) otherwise.  On open_read
 *       failure the streams are left untouched (ss.n stays 0, so the caller's
 *       streams_close is a no-op) — mirroring the original NULL-init.  The
 *       connection is owned by the caller so it can run the post-transfer checksum
 *       before tearing down.  NOTE: the invariant inputs (c/su/si/o/ss) ride in
 *       a download_body_ctx so the extern stays under the 5-parameter gate; the
 *       (sink, sinkctx) pump pair and st stay free (per-callsite / out-param).
 */
int
download_stream_body(const download_body_ctx *j, pump_sink_fn sink,
                     void *sinkctx, brix_status *st)
{
    brix_conn            *c  = j->c;
    const brix_url       *su = j->su;
    const brix_statinfo  *si = j->si;
    const brix_copy_opts *o  = j->o;
    brix_streamset       *ss = j->ss;
    brix_file        f;
    pump_remote_t    src = {0};
    int              rc;
    int              stall = copy_stall_ms(o, 60000);
    char             opq[80];
    copy_stream_ctx_t ctx = {0};

    ctx.c = c;
    ctx.path = su->path;
    ctx.deadline_ns = brix_mono_ns() + (uint64_t) stall * 1000000ULL;

    /* phase-42 W4: request inline read compression when --compress was given.
     * Rides the open opaque; the server confirms via the open reply and
     * brix_file_read transparently inflates.  A server that doesn't support it
     * just returns plaintext (f.read_codec stays 0), so this is always safe. */
    if (o->compress != NULL && o->compress[0] != '\0') {
        snprintf(opq, sizeof(opq), "xrootd.compress=%s", o->compress);
        ctx.opaque = opq;
    }
    /* Open the remote handle, retried within max_stall on a transport fault
     * (reconnecting between attempts). */
    if (download_open_resilient(&ctx, &f, st) != 0) {
        return -1;
    }

    /* M8: attach N-1 bound secondary streams to the (post-redirect) session. */
    brix_streams_open(ss, c, o->streams, st);

    /* remote (known si->size) → caller-supplied sink, with progress.  Resilient:
     * a sever mid-read reconnects + reopens at offset and adapts the request size,
     * so a one-shot download rides out a flaky/lossy link. */
    src.c = c;
    src.f = &f;
    src.pgrw = o->pgrw;
    src.resilient = 1;
    src.path = su->path;
    src.opaque = ctx.opaque;
    src.max_stall_ms = copy_stall_ms(o, 60000);
    src.cur_chunk = XRDC_COPY_CHUNK;
    /* Phase 94 parallel download: spread reads across the bound secondaries.
     * Reads self-address by offset and any secondary miss falls back to the
     * primary read, so this is safe against a server that won't serve bound
     * reads.  Inline read-compression stays single-stream (the server confirms
     * the codec on the primary open; keep the decode path on that one conn). */
    src.ss = (o->compress != NULL && o->compress[0] != '\0') ? NULL : ss;
    src.rr_next = 0;
    src.sec_reads = 0;
    rc = transfer_pump(pump_src_remote, &src, sink, sinkctx,
                       si->size, o, si->size, st);

    if (getenv("BRIX_STREAMS_DEBUG") != NULL) {
        fprintf(stderr, "brix: download substreams=%d chunks-on-secondaries=%u\n",
                ss->n, src.sec_reads);
    }

    {
        brix_status throwaway;
        brix_status_clear(&throwaway);
        brix_file_close(c, &f, rc == 0 ? st : &throwaway);
    }
    return rc;
}

/*
 * WHAT: Reconcile a completed download's checksum verdict into the transfer rc,
 *       emitting the "downloaded but NOT verified" note on an unverified query.
 * WHY:  Both the stdout and local-file download paths apply the identical
 *       MISMATCH→fail / UNVERIFIED→warn-and-clear rule after a good transfer;
 *       one helper keeps that policy in a single place and off copy_download's
 *       two branches.
 * HOW:  Runs cksum_verify(local_path may be NULL for stdout); a MISMATCH returns
 *       -1 (caller drops any committed file), an UNVERIFIED prints the note
 *       (unless silent) and clears st (a query hiccup is not a transfer failure),
 *       and an OK returns 0.  `local_path` NULL ≡ stdout; the note names du->path.
 */
int
download_reconcile_cksum(const download_job_t *job, const char *local_path,
                         brix_status *st)
{
    const brix_copy_opts *o = job->o;
    int ck = cksum_verify(job->c, job->su->path, local_path, o->cksum,
                          o->silent, st);
    if (ck == XRDC_CK_MISMATCH) {
        return -1;
    }
    if (ck == XRDC_CK_UNVERIFIED) {
        if (!o->silent) {
            fprintf(stderr, "xrdcp: %s downloaded but checksum NOT verified: "
                            "%s\n", job->du->path, st->msg);
        }
        brix_status_clear(st);
    }
    return 0;
}


/*
 * WHAT: Download the source body straight to stdout (no temp, no VFS, no commit),
 *       then verify its checksum.
 * WHY:  The stdio destination has no on-disk file to commit or unlink, so it is
 *       the simple half of copy_download; splitting it out keeps each branch a
 *       flat sequence.
 * HOW:  Pumps to STDOUT_FILENO via pump_sink_local; on success, when --cksum was
 *       given, reconciles the verdict with a NULL local path (cksum_verify skips
 *       gracefully, since stdout has no file).  Connection is caller-owned.
 */
static int
download_to_stdout(const download_job_t *job, brix_status *st)
{
    int stdoutfd = STDOUT_FILENO;
    download_body_ctx dj = { job->c, job->su, job->si, job->o, job->ss };
    int rc = download_stream_body(&dj, pump_sink_local, &stdoutfd, st);
    if (rc == 0 && job->o->cksum != NULL) {
        rc = download_reconcile_cksum(job, NULL, st);
    }
    return rc;
}


/*
 * WHAT: Download the source body into a VFS-backed temp at du->path, then commit
 *       (fsync+rename) and verify the checksum, dropping the file on any failure.
 * WHY:  The local-file path adds the atomic temp+rename lifecycle and integrity
 *       drop-on-mismatch that the stdout path lacks; confining the VFS handle to
 *       this helper keeps its acquire/commit/abort/close linear (no shared jump).
 * HOW:  Opens du->path WRITE (+FORCE when -f) via brix_vfs_open, streams into it,
 *       and on success commits.  A committed transfer with --cksum is reconciled;
 *       a genuine MISMATCH unlinks the committed-but-bad file and fails.  On any
 *       failure before commit the temp is aborted (unlinked).  Connection is
 *       caller-owned.
 */
static int
download_to_local_file(const download_job_t *job, brix_status *st)
{
    const brix_copy_opts *o = job->o;
    brix_vfs_file     *vf = NULL;
    brix_vfs_open_opts vopts = {0};
    pump_local_t       lc;
    int                committed = 0;
    int                rc;

    vopts.io_uring      = o->io_uring;
    vopts.io_uring_direct = o->io_uring_direct;
    vopts.expected_size = job->si->size;
    vopts.cred          = NULL;

    if (brix_vfs_open(job->du->path,
                      XRDC_VFS_WRITE | (o->force ? XRDC_VFS_FORCE : 0),
                      &vopts, &vf, st) != 0) {
        return -1;
    }

    lc.vf = vf;
    {
    download_body_ctx dj = { job->c, job->su, job->si, o, job->ss };
    rc = download_stream_body(&dj, pump_sink_local_vfs, &lc, st);
    }

    /* Commit on success (fsync + rename temp→final); only then verify the
     * checksum against the committed file.  A genuine MISMATCH drops the
     * committed file and returns error — it is an integrity failure, not a
     * transient fault.  A query hiccup (UNVERIFIED) keeps the good bytes. */
    if (rc == 0) {
        rc = brix_vfs_commit(vf, st);
        if (rc == 0) {
            committed = 1;
            if (o->cksum != NULL) {
                rc = download_reconcile_cksum(job, job->du->path, st);
                if (rc != 0) {
                    unlink(job->du->path);   /* drop committed-but-bad file */
                }
            }
        }
    }
    if (rc != 0 && !committed) {
        brix_vfs_abort(vf);   /* discard the partial temp */
    }
    brix_vfs_close(vf);
    return rc;
}



int
copy_download(const brix_url *su, const brix_url *du, const brix_copy_opts *o,
              const brix_opts *co, brix_status *st)
{
    brix_conn      c;
    brix_statinfo  si;
    brix_streamset ss;
    download_job_t job = {0};
    int            to_stdout = (du->scheme == XRDC_SCHEME_STDIO);
    int            stall = copy_stall_ms(o, 60000);
    int            rc;

    ss.n = 0;   /* so the streams teardown is a no-op if we never bind */
    if (resilient_setup(&c, su, co, &si, stall, st) != 0) {
        return -1;
    }
    if (si.flags & kXR_isDir) {
        brix_status_set(st, XRDC_EUSAGE, 0, "source is a directory (use -r, M5)");
        brix_close(&c);
        return -1;
    }

    job.c = &c;
    job.su = su;
    job.du = du;
    job.si = &si;
    job.o = o;
    job.ss = &ss;
    job.co = co;

    if (to_stdout) {
        rc = download_to_stdout(&job, st);
        brix_streams_close(&ss);
        brix_close(&c);
        return rc;
    }

    /* Local file path: existence-check preserving the original error message,
     * then open via VFS (atomic temp+rename and optional io_uring inside the
     * backend).  commit() does fsync+rename; abort() unlinks the temp on any
     * failure or checksum mismatch so the final destination is never partial. */
    if (!o->force && access(du->path, F_OK) == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "destination exists (use -f to overwrite): %s",
                        du->path);
        brix_close(&c);
        return -1;
    }

    /* Phase-100 extreme copy (--sources N): multi-source block-stealing
     * download over metalink mirrors / locate replicas.  Returns 1 when it
     * handled the transfer; 0 falls through to --parallel, then serial. */
    if (copy_download_xcp(&job, &rc, st)) {
        brix_streams_close(&ss);
        brix_close(&c);
        return rc;
    }

    /* Opt-in TRUE concurrent striped download (--parallel): one thread per bound
     * connection, disjoint pwrite ranges.  Returns 1 when it handled the transfer;
     * 0 (not eligible) falls through to the serial resilient pump below. */
    if (copy_download_parallel(&job, &rc, st)) {
        brix_streams_close(&ss);
        brix_close(&c);
        return rc;
    }

    rc = download_to_local_file(&job, st);

    brix_streams_close(&ss);
    brix_close(&c);
    return rc;
}


