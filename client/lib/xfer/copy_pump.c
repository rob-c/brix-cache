/*
 * copy_pump.c - extracted concern
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"


int
write_all(int fd, const uint8_t *buf, size_t n, brix_status *st)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            brix_status_set(st, XRDC_ESOCK, errno, "local write: %s", strerror(errno));
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}


/* Remote source/sink over an open handle; ->pgrw selects paged I/O + per-page
 * CRC32c (kXR_pgread/pgwrite) vs the plain kXR_read/write path.
 *
 * Resilience (download source, when ->resilient): on a transport fault the read
 * is retried within a max_stall deadline — reconnecting the session and REOPENING
 * the file at the same absolute offset (idempotent), with fast backoff. The read
 * size adapts: it starts large (full throughput on a clean link) and HALVES on
 * each sever down to XRDC_RESILIENT_FLOOR, so a lossy link converges on a request
 * small enough to get through. This is what lets a one-shot xrdcp ride out loss
 * the way the FUSE driver's mfile layer does. */

/* Reconnect the session (to the original endpoint, re-selecting a data server)
 * and reopen the source file — replacing the dead handle. 0 / -1 (st set). */
int
pump_remote_reopen(pump_remote_t *r, brix_status *st)
{
    const char *host = (r->c->home_host[0] != '\0') ? r->c->home_host : r->c->host;
    int         port = (r->c->home_port != 0) ? r->c->home_port : r->c->port;
    if (brix_reconnect(r->c, host, port, st) != 0) {
        return -1;
    }
    brix_file nf;
    int rc = (r->opaque != NULL && r->opaque[0] != '\0')
             ? brix_file_open_opaque(r->c, r->path, r->opaque, 0, 0, 0, &nf, st)
             : brix_file_open_read(r->c, r->path, &nf, st);
    if (rc != 0) {
        return -1;
    }
    *r->f = nf;
    return 0;
}


/* Phase 94 parallel download: issue this chunk's read on a bound secondary,
 * round-robin over primary+secondaries.  kXR_read carries no pathid, so the
 * server routes a read purely by WHICH connection it arrives on — a read on a
 * bound secondary is served there against the primary-published handle (the same
 * cross-worker SHM path the read tests exercise).  Best-effort: slot 0 (primary)
 * and any secondary read that fails return -1 so the caller runs its normal
 * (resilient) primary read, so an old/gateway server that won't serve bound reads
 * never breaks the download.  Returns the byte count on a served secondary read,
 * or -1 to mean "not carried by a secondary — do the primary read". */
static ssize_t
pump_src_secondary(pump_remote_t *r, uint8_t *buf, int64_t off, size_t want,
                   brix_status *st)
{
    unsigned   slot;
    brix_conn *sec;
    ssize_t    n;

    if (r->ss == NULL || r->ss->n == 0) {
        return -1;
    }
    slot = r->rr_next % (unsigned) (r->ss->n + 1);
    r->rr_next++;
    if (slot == 0) {
        return -1;                                  /* primary's turn */
    }
    sec = &r->ss->sec[slot - 1];
    n = r->pgrw ? brix_file_pgread(sec, r->f, off, buf, want, st)
                : brix_file_read(sec, r->f, off, buf, want, st);
    if (n < 0) {
        brix_status_clear(st);                      /* fall back to the primary */
        return -1;
    }
    r->sec_reads++;
    return n;
}


ssize_t
pump_src_remote(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st)
{
    pump_remote_t *r = (pump_remote_t *) ctx;

    if (!r->resilient) {
        return r->pgrw ? brix_file_pgread(r->c, r->f, off, buf, cap, st)
                       : brix_file_read(r->c, r->f, off, buf, cap, st);
    }

    uint64_t deadline = brix_mono_ns() + (uint64_t) r->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        size_t  want = (cap < r->cur_chunk) ? cap : r->cur_chunk;
        ssize_t n = pump_src_secondary(r, buf, off, want, st);
        if (n < 0) {
            n = r->pgrw ? brix_file_pgread(r->c, r->f, off, buf, want, st)
                        : brix_file_read(r->c, r->f, off, buf, want, st);
        }
        if (n >= 0) {
            return n;
        }
        if (!brix_status_retryable(st) || brix_copy_quit_requested()
            || brix_mono_ns() >= deadline) {
            return -1;
        }
        /* Transport fault: shrink the request so it is likelier to get through,
         * then reconnect+reopen and retry at the same offset. */
        if (r->cur_chunk > XRDC_RESILIENT_FLOOR) {
            r->cur_chunk /= 2;
        }
        brix_backoff_sleep_fast(attempt++);
        (void) pump_remote_reopen(r, st);   /* best-effort; loop re-tries */
    }
}


/* Reconnect + reopen the destination IN PLACE (kXR_open_updt, no truncate) so a
 * resilient upload resumes onto the same (server-preserved) partial. 0 / -1. */
int
pump_sink_reopen(pump_remote_t *r, brix_status *st)
{
    const char *host = (r->c->home_host[0] != '\0') ? r->c->home_host : r->c->host;
    int         port = (r->c->home_port != 0) ? r->c->home_port : r->c->port;
    if (brix_reconnect(r->c, host, port, st) != 0) {
        return -1;
    }
    brix_file nf;
    if (brix_file_open_update(r->c, r->path, r->posc, &nf, st) != 0) {
        return -1;
    }
    *r->f = nf;
    return 0;
}


int
pump_sink_remote(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                 brix_status *st)
{
    pump_remote_t *r = (pump_remote_t *) ctx;

    if (!r->resilient) {
        return r->pgrw ? brix_file_pgwrite(r->c, r->f, off, buf, n, st)
                       : brix_file_write(r->c, r->f, off, buf, n, st);
    }

    /* Phase 94 parallel upload: spread this chunk across the bound secondaries
     * round-robin.  Each kXR_write self-addresses (offset + fhandle), so any
     * connection can serve it; the server reopens the writable handle on that
     * connection's worker and pwrites.  Best-effort: a chunk a secondary won't take
     * (old server / gateway that refuses bound writes) falls through to the
     * resilient primary loop below, which re-writes it authoritatively at the same
     * offset (idempotent pwrite) — a secondary hiccup never fails the copy.  slot 0
     * (the primary) also falls through to that loop, so the primary keeps its full
     * resilient reopen/retry semantics. */
    if (r->ss != NULL && r->ss->n > 0) {
        unsigned slot = r->rr_next % (unsigned) (r->ss->n + 1);
        r->rr_next++;
        if (slot != 0) {
            brix_conn *sec = &r->ss->sec[slot - 1];
            if (brix_file_write(sec, r->f, off, buf, n, st) == 0) {
                r->sec_writes++;
                return 0;
            }
            brix_status_clear(st);   /* fall back to the resilient primary write */
        }
    }

    /* Resilient upload (server has brix_upload_resume on): on a transport
     * fault, reconnect + reopen-in-place and re-issue THIS buffer at the same
     * absolute offset.  The bytes below `off` were already acked, so the server
     * has them on the preserved partial — re-writing the current span is either
     * filling the gap or an idempotent overwrite, so there is never a hole. */
    uint64_t deadline = brix_mono_ns() + (uint64_t) r->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        int rc = r->pgrw ? brix_file_pgwrite(r->c, r->f, off, buf, n, st)
                         : brix_file_write(r->c, r->f, off, buf, n, st);
        if (rc == 0) {
            return 0;
        }
        if (!brix_status_retryable(st) || brix_copy_quit_requested()
            || brix_mono_ns() >= deadline) {
            return -1;
        }
        brix_backoff_sleep_fast(attempt++);
        (void) pump_sink_reopen(r, st);   /* best-effort; loop re-tries */
    }
}


/* Local source/sink over a plain fd (ctx is &fd). The read EINTR-retries; the
 * write is write_all(). off is ignored — a local fd is positioned by the kernel. */
ssize_t
pump_src_local(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st)
{
    int fd = *(int *) ctx;
    (void) off;
    for (;;) {
        ssize_t r = read(fd, buf, cap);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r < 0) {
            brix_status_set(st, XRDC_ESOCK, errno, "local read: %s",
                            strerror(errno));
        }
        return r;
    }
}


int
pump_sink_local(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                brix_status *st)
{
    (void) off;
    return write_all(*(int *) ctx, buf, n, st);
}


/* VFS-backed local pump context and adapters *
 * pump_local_t holds the VFS handle for a local file endpoint.  The VFS layer
 * (vfs_posix.c) owns the fd, optional io_uring ring, and temp+rename commit
 * internally — copy.c just calls brix_vfs_pread / brix_vfs_pwrite through it.
 * Ring selection (AUTO/ON/OFF from opts.io_uring) happens inside vfs_posix.c's
 * open, eliminating the old local_ring_select helper from this file. */


ssize_t
pump_src_local_vfs(void *ctx, uint8_t *buf, int64_t off, size_t cap,
                   brix_status *st)
{
    pump_local_t *lc = ctx;
    return brix_vfs_pread(lc->vf, off, buf, cap, st);
}


int
pump_sink_local_vfs(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                    brix_status *st)
{
    pump_local_t *lc = ctx;
    return brix_vfs_pwrite(lc->vf, off, buf, n, st);
}


/* ---- Fire the optional progress callback for one tick ----
 *
 * WHAT: If a progress sink is configured (o non-NULL AND o->progress set), calls
 * it once with (cur, total); otherwise a no-op. No return value.
 *
 * WHY: transfer_pump reports progress from two sites — after each drained chunk
 * (cur=off, total=progress_total) and once at clean EOF (cur=off, total=off to
 * mirror the historical "100%" tick). Both share the identical NULL-guard; hoisting
 * it here keeps that guard in one place and keeps the pump loop under its
 * complexity cap without changing when or with what arguments progress fires.
 *
 * HOW:
 *   1. Return immediately when o is NULL or o->progress is unset.
 *   2. Otherwise invoke o->progress with o->progress_arg and the two counters,
 *      widened to long long exactly as the original inline call sites did.
 */
static void
pump_emit_progress(const brix_copy_opts *o, int64_t cur, int64_t total)
{
    if (o != NULL && o->progress != NULL) {
        o->progress(o->progress_arg, (long long) cur, (long long) total);
    }
}


/*
 * The loop. expected >= 0 = known length (stop at expected; a 0-read before it
 * is a short-read error); expected < 0 = EOF-driven (a 0-read is the clean end).
 * When o->progress is set it fires after each drained chunk with (off,
 * progress_total), plus one final (off, off) at EOF to mirror the historical
 * "100%" upload tick; pass o == NULL to suppress progress entirely. Cancel
 * (g_brix_copy_quit) aborts with EINTR. Owns its CHUNK buffer. Returns 0 / -1.
 */
/* ---- §7.13 --xrate / --xrate-threshold: pace or floor the pump ----
 *
 * WHAT: brix_pump_pace() sleeps just long enough that `moved` bytes since
 *       `t0_ns` never exceed o->xrate_bps, and fails (st set, -1) when the
 *       average rate has fallen below o->xrate_min_bps after a 3 s grace.
 *       Returns 0 to continue. brix_pump_pace_cap() shrinks a read size so a
 *       paced transfer moves in ~quarter-second steps instead of 8 MiB lumps.
 *
 * WHY: Stock xrdcp -X/--xrate caps a copy's bandwidth (shared-link hygiene);
 *      --xrate-threshold aborts a transfer that has degraded below a floor
 *      instead of letting it crawl forever. Both act on the serial pump, the
 *      one place every byte of a non-engine copy passes.
 *
 * HOW: Cap: elapsed vs the time `moved` bytes SHOULD have taken; sleep the
 *      difference in ≤250 ms slices so a signal still cancels promptly.
 *      Floor: moved/elapsed compared after the grace so bring-up never trips.
 */
int
brix_pump_pace(const brix_copy_opts *o, uint64_t t0_ns, int64_t moved,
               brix_status *st)
{
    uint64_t elapsed = brix_mono_ns() - t0_ns;

    if (o == NULL || moved <= 0) {
        return 0;
    }
    if (o->xrate_bps > 0) {
        uint64_t due_ns = (uint64_t) ((double) moved * 1e9
                                      / (double) o->xrate_bps);
        while (elapsed < due_ns) {
            uint64_t        gap = due_ns - elapsed;
            struct timespec ts;

            if (brix_copy_quit_requested()) {
                brix_status_set(st, XRDC_ESOCK, EINTR,
                                "transfer cancelled (signal)");
                return -1;
            }
            if (gap > 250ULL * 1000 * 1000) {
                gap = 250ULL * 1000 * 1000;
            }
            ts.tv_sec  = 0;
            ts.tv_nsec = (long) gap;
            nanosleep(&ts, NULL);
            elapsed = brix_mono_ns() - t0_ns;
        }
    }
    if (o->xrate_min_bps > 0 && elapsed > 3ULL * 1000 * 1000 * 1000) {
        double rate = (double) moved * 1e9 / (double) elapsed;

        if (rate < (double) o->xrate_min_bps) {
            brix_status_set(st, XRDC_ESOCK, 0,
                            "transfer rate %.0f B/s fell below the "
                            "--xrate-threshold floor (%lld B/s)",
                            rate, (long long) o->xrate_min_bps);
            return -1;
        }
    }
    return 0;
}

size_t
brix_pump_pace_cap(const brix_copy_opts *o, size_t cap)
{
    if (o != NULL && o->xrate_bps > 0) {
        size_t step = (size_t) (o->xrate_bps / 4);

        if (step < 64 * 1024) {
            step = 64 * 1024;
        }
        if (cap > step) {
            cap = step;
        }
    }
    return cap;
}

int
transfer_pump(pump_src_fn src, void *sctx, pump_sink_fn sink, void *kctx,
              int64_t expected, const brix_copy_opts *o, int64_t progress_total,
              brix_status *st)
{
    uint8_t *buf;
    int64_t  off = 0;
    uint64_t t0 = brix_mono_ns();
    int      rc = -1;

    buf = (uint8_t *) malloc(XRDC_COPY_CHUNK);
    if (buf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }

    for (;;) {
        size_t  cap = brix_pump_pace_cap(o, XRDC_COPY_CHUNK);
        ssize_t n;

        /* Completion is tested BEFORE the cancel flag: a byte-complete known-size
         * transfer must report success even if the sticky g_brix_copy_quit was
         * set on the final chunk. This mirrors the original head-controlled
         * `while (off < si->size)` loops (download/r2r), where completion was the
         * loop condition and the cancel check lived inside the body — so a SIGINT
         * landing at the finish line never discarded a perfect file. For an
         * EOF-driven pump (expected < 0) this is skipped and cancel is checked
         * first, exactly as the original `for (;;)` upload/recursive loops did. */
        if (expected >= 0 && off >= expected) {
            rc = 0;
            break;
        }
        if (g_brix_copy_quit) {
            brix_status_set(st, XRDC_ESOCK, EINTR, "transfer cancelled (signal)");
            break;   /* rc stays -1 → caller drops the partial/temp */
        }
        if (expected >= 0 && (int64_t) cap > expected - off) {
            cap = (size_t) (expected - off);
        }

        n = src(sctx, buf, off, cap, st);
        if (n < 0) {
            break;
        }
        if (n == 0) {
            if (expected >= 0) {
                brix_status_set(st, XRDC_EPROTO, 0,
                                "short read: got %lld of %lld bytes",
                                (long long) off, (long long) expected);
                break;
            }
            rc = 0;   /* EOF — full body streamed */
            pump_emit_progress(o, off, off);
            break;
        }
        if (sink(kctx, buf, off, (size_t) n, st) != 0) {
            break;
        }
        off += n;
        pump_emit_progress(o, off, progress_total);
        if (brix_pump_pace(o, t0, off, st) != 0) {
            break;   /* rate floor tripped or cancelled during the pace sleep */
        }
    }

    free(buf);
    return rc;
}
