/*
 * copy.c — the xrdcp copy engine (download this pass; upload in M3).
 *
 * WHAT: xrdc_copy() infers direction from the two endpoints' schemes and drives a
 *       chunked transfer: remote↔local (download/upload), local↔"-" (stdio), or
 *       remote→remote (client-mediated, bytes transit this process).
 * WHY:  This is the reusable core behind the xrdcp CLI (and, later, libxrdc's
 *       xrdc_copy() public call).
 * HOW:  Download = stat (authoritative size) → open-read → read/write loop to the
 *       known length → close. Reading to the stat size (rather than trusting a
 *       short read to mean EOF) is robust against partial read frames. Remote→remote
 *       chains a source open-read and a destination open-write over two sessions;
 *       each open follows its own cluster redirect. Server-side TPC is out of scope.
 */
#include "xrdc.h"
#include "uring.h"                /* phase-44: optional local-disk overlap ring */
#include "zip.h"                  /* phase-42 W3: ?xrdcl.unzip= member extraction */
#include "compat/host_format.h"  /* xrootd_format_host_port (IPv6-bracketed Host) */
#include "compat/hex.h"          /* shared hex encoder (libxrdproto) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp for hex-digest compare */
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>     /* ECONNREFUSED — fail fast on a never-established refusal */
#include <errno.h>
#include <dirent.h>    /* recursive upload: walk the local tree */
#include <sys/stat.h>  /* mkdir / stat for recursive copy */
#include <signal.h>    /* Phase 40 (a): cooperative SIGINT/SIGTERM cancellation */
#include <stdatomic.h> /* Phase 40 (a): per-transfer unique temp-name sequence */

#define XRDC_COPY_CHUNK  (8u * 1024u * 1024u)

/*
 * cksum_verify() outcome — a three-way verdict so a transient control-plane
 * hiccup can NEVER be mistaken for a genuine mismatch (which would delete a
 * byte-perfect file). XRDC_CK_OK==0 / XRDC_CK_MISMATCH==-1 keep the historical
 * 0/-1 sense; XRDC_CK_UNVERIFIED is the new "could not determine" middle ground.
 */
#define XRDC_CK_OK          0    /* digest matched / printed / nothing to do */
#define XRDC_CK_MISMATCH  (-1)   /* digest KNOWN and WRONG → drop the destination */
#define XRDC_CK_UNVERIFIED  1    /* query/transport/usage error → keep file, warn */

static int cksum_verify(xrdc_conn *c, const char *remote_path,
                        const char *local_path, const char *spec, int silent,
                        xrdc_status *st);

/*
 * Phase 40 (a): cooperative cancellation. A SIGINT/SIGTERM handler sets this
 * flag — the ONLY async-signal-safe action it takes. The synchronous transfer
 * loops poll it and abort with an error status, so the normal teardown unlinks
 * the temp destination; the actual unlink/rename always runs in normal context,
 * never inside the handler (unlink IS async-signal-safe, but knowing WHICH path
 * to remove is not, hence the mark-then-reclaim discipline).
 */
static volatile sig_atomic_t g_xrdc_copy_quit;

static void
copy_signal_handler(int sig)
{
    (void) sig;
    g_xrdc_copy_quit = 1;
}

int
xrdc_copy_quit_requested(void)
{
    return g_xrdc_copy_quit != 0;
}

void
xrdc_copy_install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = copy_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;   /* NO SA_RESTART: let blocked I/O return EINTR promptly */
    (void) sigaction(SIGINT, &sa, NULL);
    (void) sigaction(SIGTERM, &sa, NULL);

    /* A write to a peer severed mid-transfer (flaky link / firewall) must surface
     * as EPIPE, never kill the process with SIGPIPE. The cleartext path already
     * uses MSG_NOSIGNAL; this also covers the TLS write path (OpenSSL's internal
     * write()) and any other send site. */
    signal(SIGPIPE, SIG_IGN);
}

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
static int
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
 * Commit (or discard) a temp destination: on rc==0 rename `tmp`→`dest`
 * atomically (downgrading rc to -1 with st set if the rename fails); on rc!=0
 * drop the temp. Returns the final rc. Shared by every local-dest writer so the
 * "atomic dest" guarantee lives in one place.
 */
static int
atomic_dest_finish(const char *tmp, const char *dest, int rc, xrdc_status *st)
{
    if (rc == 0) {
        if (rename(tmp, dest) != 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "rename %s -> %s: %s",
                            tmp, dest, strerror(errno));
            unlink(tmp);
            return -1;
        }
        return 0;
    }
    unlink(tmp);   /* drop the partial/cancelled/mismatched temp */
    return rc;
}

static int
write_all(int fd, const uint8_t *buf, size_t n, xrdc_status *st)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            xrdc_status_set(st, XRDC_ESOCK, errno, "local write: %s", strerror(errno));
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Shared chunked-transfer core (B5).
 *
 * Every byte-pump in this file is the same loop — fill a CHUNK-sized buffer from
 * a source, drain it to a sink, honour cooperative cancel + optional progress —
 * differing only in (a) where bytes come from (remote pgread/read vs a local
 * fd), (b) where they go (a local fd vs remote pgwrite/write), and (c) whether
 * the length is known up front (download/r2r: stop at si->size, where a 0-read
 * is a short-read ERROR) or EOF-driven (upload/recursive: a 0-read is the clean
 * end). transfer_pump() owns the loop once; the source/sink are supplied as
 * small read/write adapters, so each caller keeps its own open/close/teardown
 * verbatim — only the malloc+loop+free block collapses here.
 * ------------------------------------------------------------------------- */

/* Fill up to cap bytes at file offset off. Returns bytes read (>0), 0 for "no
 * more" (EOF for an EOF-driven pump; a short read for a sized pump), or -1 (st
 * set). */
typedef ssize_t (*pump_src_fn)(void *ctx, uint8_t *buf, int64_t off, size_t cap,
                               xrdc_status *st);
/* Drain exactly n bytes at offset off. Returns 0 or -1 (st set). */
typedef int (*pump_sink_fn)(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                            xrdc_status *st);

/* Smallest adaptive read request on a high packet-loss link. Balances two costs:
 * smaller = each read likelier to get through, but more reads ⇒ more (expensive,
 * multi-RTT) reconnects after the severs that do happen. 256 KiB is the sweet
 * spot measured against a fault proxy up to 15% per-segment loss. */
#define XRDC_RESILIENT_FLOOR (256u * 1024u)

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
typedef struct {
    xrdc_conn  *c;
    xrdc_file  *f;
    int         pgrw;
    /* resilient download source only (zero for upload sink / non-resilient): */
    int         resilient;
    const char *path;        /* source/dest path, for reopen */
    const char *opaque;      /* compress opaque or NULL */
    int         max_stall_ms;
    size_t      cur_chunk;   /* adaptive read size (shrinks on loss) */
    int         posc;        /* resilient upload sink only: posc flag for reopen */
} pump_remote_t;

/* Reconnect the session (to the original endpoint, re-selecting a data server)
 * and reopen the source file — replacing the dead handle. 0 / -1 (st set). */
static int
pump_remote_reopen(pump_remote_t *r, xrdc_status *st)
{
    const char *host = (r->c->home_host[0] != '\0') ? r->c->home_host : r->c->host;
    int         port = (r->c->home_port != 0) ? r->c->home_port : r->c->port;
    if (xrdc_reconnect(r->c, host, port, st) != 0) {
        return -1;
    }
    xrdc_file nf;
    int rc = (r->opaque != NULL && r->opaque[0] != '\0')
             ? xrdc_file_open_opaque(r->c, r->path, r->opaque, 0, 0, 0, &nf, st)
             : xrdc_file_open_read(r->c, r->path, &nf, st);
    if (rc != 0) {
        return -1;
    }
    *r->f = nf;
    return 0;
}

static ssize_t
pump_src_remote(void *ctx, uint8_t *buf, int64_t off, size_t cap, xrdc_status *st)
{
    pump_remote_t *r = (pump_remote_t *) ctx;

    if (!r->resilient) {
        return r->pgrw ? xrdc_file_pgread(r->c, r->f, off, buf, cap, st)
                       : xrdc_file_read(r->c, r->f, off, buf, cap, st);
    }

    uint64_t deadline = xrdc_mono_ns() + (uint64_t) r->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        size_t  want = (cap < r->cur_chunk) ? cap : r->cur_chunk;
        ssize_t n = r->pgrw ? xrdc_file_pgread(r->c, r->f, off, buf, want, st)
                            : xrdc_file_read(r->c, r->f, off, buf, want, st);
        if (n >= 0) {
            return n;
        }
        if (!xrdc_status_retryable(st) || xrdc_copy_quit_requested()
            || xrdc_mono_ns() >= deadline) {
            return -1;
        }
        /* Transport fault: shrink the request so it is likelier to get through,
         * then reconnect+reopen and retry at the same offset. */
        if (r->cur_chunk > XRDC_RESILIENT_FLOOR) {
            r->cur_chunk /= 2;
        }
        xrdc_backoff_sleep_fast(attempt++);
        (void) pump_remote_reopen(r, st);   /* best-effort; loop re-tries */
    }
}

/* Reconnect + reopen the destination IN PLACE (kXR_open_updt, no truncate) so a
 * resilient upload resumes onto the same (server-preserved) partial. 0 / -1. */
static int
pump_sink_reopen(pump_remote_t *r, xrdc_status *st)
{
    const char *host = (r->c->home_host[0] != '\0') ? r->c->home_host : r->c->host;
    int         port = (r->c->home_port != 0) ? r->c->home_port : r->c->port;
    if (xrdc_reconnect(r->c, host, port, st) != 0) {
        return -1;
    }
    xrdc_file nf;
    if (xrdc_file_open_update(r->c, r->path, r->posc, &nf, st) != 0) {
        return -1;
    }
    *r->f = nf;
    return 0;
}

static int
pump_sink_remote(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                 xrdc_status *st)
{
    pump_remote_t *r = (pump_remote_t *) ctx;

    if (!r->resilient) {
        return r->pgrw ? xrdc_file_pgwrite(r->c, r->f, off, buf, n, st)
                       : xrdc_file_write(r->c, r->f, off, buf, n, st);
    }

    /* Resilient upload (server has xrootd_upload_resume on): on a transport
     * fault, reconnect + reopen-in-place and re-issue THIS buffer at the same
     * absolute offset.  The bytes below `off` were already acked, so the server
     * has them on the preserved partial — re-writing the current span is either
     * filling the gap or an idempotent overwrite, so there is never a hole. */
    uint64_t deadline = xrdc_mono_ns() + (uint64_t) r->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        int rc = r->pgrw ? xrdc_file_pgwrite(r->c, r->f, off, buf, n, st)
                         : xrdc_file_write(r->c, r->f, off, buf, n, st);
        if (rc == 0) {
            return 0;
        }
        if (!xrdc_status_retryable(st) || xrdc_copy_quit_requested()
            || xrdc_mono_ns() >= deadline) {
            return -1;
        }
        xrdc_backoff_sleep_fast(attempt++);
        (void) pump_sink_reopen(r, st);   /* best-effort; loop re-tries */
    }
}

/* Local source/sink over a plain fd (ctx is &fd). The read EINTR-retries; the
 * write is write_all(). off is ignored — a local fd is positioned by the kernel. */
static ssize_t
pump_src_local(void *ctx, uint8_t *buf, int64_t off, size_t cap, xrdc_status *st)
{
    int fd = *(int *) ctx;
    (void) off;
    for (;;) {
        ssize_t r = read(fd, buf, cap);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r < 0) {
            xrdc_status_set(st, XRDC_ESOCK, errno, "local read: %s",
                            strerror(errno));
        }
        return r;
    }
}

static int
pump_sink_local(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                xrdc_status *st)
{
    (void) off;
    return write_all(*(int *) ctx, buf, n, st);
}

/* ---- Phase 44: optional io_uring local-disk overlap (Option A) ----
 *
 * The uring adapters present the same synchronous one-chunk face as the local
 * adapters above, but route through xrdc_disk_ring so disk I/O overlaps the
 * network side.  transfer_pump and the remote adapters are untouched; the only
 * change is which (fn, ctx) pair a local fd is driven by, chosen per
 * xrdc_copy_opts.io_uring.  See copy_run_download / copy_run_upload below. */

typedef struct {
    int             fd;
    xrdc_disk_ring *ring;
} pump_local_t;

static ssize_t
pump_src_local_uring(void *ctx, uint8_t *buf, int64_t off, size_t cap,
                     xrdc_status *st)
{
    pump_local_t *lc = ctx;
    return xrdc_disk_ring_pread(lc->ring, off, buf, cap, st);
}

static int
pump_sink_local_uring(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                      xrdc_status *st)
{
    pump_local_t *lc = ctx;
    return xrdc_disk_ring_pwrite(lc->ring, off, buf, n, st);
}

/*
 * local_ring_select — decide whether to engage the overlap ring for a local fd.
 * Sets *ring (NULL = use the classic adapter).  off  -> never; on  -> required,
 * a clean error if io_uring is unavailable (client fail-fast); auto -> use it
 * iff available, silently falling back otherwise.  o == NULL (recursive helper
 * sub-transfers) is treated as auto.  Returns 0, or -1 (with *st) for on+absent.
 */
static int
local_ring_select(int fd, const xrdc_copy_opts *o, xrdc_disk_ring **ring,
                  xrdc_status *st)
{
    int mode = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;

    *ring = NULL;
    if (mode == XRDC_IO_URING_OFF) {
        return 0;
    }
    if (!xrdc_uring_available()) {
        if (mode == XRDC_IO_URING_ON) {
            xrdc_status_set(st, XRDC_EUNSUPPORTED, 0,
                "--io-uring=on but io_uring is unavailable on this host "
                "(kernel/seccomp) or this build lacks liburing");
            return -1;
        }
        return 0;   /* auto: classic path */
    }
    {
        xrdc_status tmp;
        xrdc_status_clear(&tmp);
        /* A 4-deep window of pump-sized buffers overlaps disk and network. */
        *ring = xrdc_disk_ring_create(fd, 4, XRDC_COPY_CHUNK, 0, &tmp);
        if (*ring == NULL && mode == XRDC_IO_URING_ON) {
            if (st != NULL) { *st = tmp; }
            return -1;
        }
        /* auto: a create failure just leaves *ring NULL -> classic path */
    }
    return 0;
}

/*
 * The loop. expected >= 0 = known length (stop at expected; a 0-read before it
 * is a short-read error); expected < 0 = EOF-driven (a 0-read is the clean end).
 * When o->progress is set it fires after each drained chunk with (off,
 * progress_total), plus one final (off, off) at EOF to mirror the historical
 * "100%" upload tick; pass o == NULL to suppress progress entirely. Cancel
 * (g_xrdc_copy_quit) aborts with EINTR. Owns its CHUNK buffer. Returns 0 / -1.
 */
static int
transfer_pump(pump_src_fn src, void *sctx, pump_sink_fn sink, void *kctx,
              int64_t expected, const xrdc_copy_opts *o, int64_t progress_total,
              xrdc_status *st)
{
    uint8_t *buf;
    int64_t  off = 0;
    int      rc = -1;

    buf = (uint8_t *) malloc(XRDC_COPY_CHUNK);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }

    for (;;) {
        size_t  cap = XRDC_COPY_CHUNK;
        ssize_t n;

        /* Completion is tested BEFORE the cancel flag: a byte-complete known-size
         * transfer must report success even if the sticky g_xrdc_copy_quit was
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
        if (g_xrdc_copy_quit) {
            xrdc_status_set(st, XRDC_ESOCK, EINTR, "transfer cancelled (signal)");
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
                xrdc_status_set(st, XRDC_EPROTO, 0,
                                "short read: got %lld of %lld bytes",
                                (long long) off, (long long) expected);
                break;
            }
            rc = 0;   /* EOF — full body streamed */
            if (o != NULL && o->progress != NULL) {
                o->progress(o->progress_arg, (long long) off, (long long) off);
            }
            break;
        }
        if (sink(kctx, buf, off, (size_t) n, st) != 0) {
            break;
        }
        off += n;
        if (o != NULL && o->progress != NULL) {
            o->progress(o->progress_arg, (long long) off,
                        (long long) progress_total);
        }
    }

    free(buf);
    return rc;
}

/*
 * copy_run_download — run the pump for a remote source into a local fd, routing
 * the local writes through the io_uring overlap ring when selected.  On the
 * ring path the pump's write-behind leaves writes in flight, so the ring is
 * flushed (committing every queued pwrite) before it is destroyed; a flush
 * error fails the transfer.  The classic path is byte-identical to before.
 */
static int
copy_run_download(pump_src_fn rsrc, void *rsctx, int outfd, int64_t expected,
                  const xrdc_copy_opts *o, int64_t ptotal, xrdc_status *st)
{
    xrdc_disk_ring *ring = NULL;
    int             rc;

    if (local_ring_select(outfd, o, &ring, st) != 0) {
        return -1;
    }
    if (ring == NULL) {
        return transfer_pump(rsrc, rsctx, pump_sink_local, &outfd,
                             expected, o, ptotal, st);
    }

    {
        pump_local_t lc;
        lc.fd   = outfd;
        lc.ring = ring;
        rc = transfer_pump(rsrc, rsctx, pump_sink_local_uring, &lc,
                           expected, o, ptotal, st);
        if (rc == 0) {
            rc = xrdc_disk_ring_flush(ring, st);
        }
        xrdc_disk_ring_destroy(ring);
    }
    return rc;
}

/*
 * copy_run_upload — run the pump for a local fd into a remote sink, routing the
 * local reads through the io_uring read-ahead ring when selected.  Reads need
 * no flush (destroy drains any speculative reads).
 */
static int
copy_run_upload(int infd, pump_sink_fn rsink, void *rsctx, int64_t expected,
                const xrdc_copy_opts *o, int64_t ptotal, xrdc_status *st)
{
    xrdc_disk_ring *ring = NULL;
    int             rc;

    if (local_ring_select(infd, o, &ring, st) != 0) {
        return -1;
    }
    if (ring == NULL) {
        return transfer_pump(pump_src_local, &infd, rsink, rsctx,
                             expected, o, ptotal, st);
    }

    {
        pump_local_t lc;
        lc.fd   = infd;
        lc.ring = ring;
        rc = transfer_pump(pump_src_local_uring, &lc, rsink, rsctx,
                           expected, o, ptotal, st);
        xrdc_disk_ring_destroy(ring);
    }
    return rc;
}

/*
 * WHAT: Open the source for read, stream the known-size body to `outfd`, then
 *       close the remote handle — the whole "remote file is open" lifetime.
 * WHY:  Confining the open-read handle (and its secondary streams + scratch buf)
 *       to one helper lets the caller stay a flat early-return sequence: the file
 *       is always closed here, on every path, without a shared cleanup jump.
 * HOW:  open_read → streams_open(&ss) → malloc buf → read/write loop to si.size →
 *       file_close. Returns 0 on a complete transfer, -1 (st set) otherwise. On
 *       open_read failure the streams are left untouched (ss.n stays 0, so the
 *       caller's streams_close is a no-op) — mirroring the original NULL-init.
 *       buf is freed here; the connection and outfd are owned by the caller so it
 *       can run the post-transfer checksum before tearing them down.
 */
static int
download_stream_body(xrdc_conn *c, const xrdc_url *su, const xrdc_statinfo *si,
                     int outfd, const xrdc_copy_opts *o, xrdc_streamset *ss,
                     xrdc_status *st)
{
    xrdc_file     f;
    pump_remote_t src = {0};
    int           rc;
    char          opq[80];
    const char   *opaque = NULL;

    /* phase-42 W4: request inline read compression when --compress was given.
     * Rides the open opaque; the server confirms via the open reply and
     * xrdc_file_read transparently inflates.  A server that doesn't support it
     * just returns plaintext (f.read_codec stays 0), so this is always safe. */
    if (o->compress != NULL && o->compress[0] != '\0') {
        snprintf(opq, sizeof(opq), "xrootd.compress=%s", o->compress);
        opaque = opq;
    }
    /* Open the remote handle, retried within max_stall on a transport fault
     * (reconnecting between attempts): the open is the last single-RTT step of
     * setup and is just as sever-prone as connect/stat on a lossy link. */
    {
        int      stall = (o->max_stall_ms > 0) ? o->max_stall_ms : 60000;
        uint64_t deadline = xrdc_mono_ns() + (uint64_t) stall * 1000000ULL;
        unsigned attempt = 0;
        for (;;) {
            int orc = (opaque != NULL)
                      ? xrdc_file_open_opaque(c, su->path, opq, 0, 0, 0, &f, st)
                      : xrdc_file_open_read(c, su->path, &f, st);
            if (orc == 0) {
                break;
            }
            if (!xrdc_status_retryable(st) || xrdc_copy_quit_requested()
                || xrdc_mono_ns() >= deadline) {
                return -1;
            }
            xrdc_backoff_sleep_fast(attempt++);
            const char *h = (c->home_host[0] != '\0') ? c->home_host : c->host;
            int         p = (c->home_port != 0) ? c->home_port : c->port;
            (void) xrdc_reconnect(c, h, p, st);   /* re-establish, then reopen */
        }
    }

    /* M8: attach N-1 bound secondary streams to the (post-redirect) session. */
    xrdc_streams_open(ss, c, o->streams, st);

    /* remote (known si->size) → local outfd, with progress. Resilient: a sever
     * mid-read reconnects + reopens at offset and adapts the request size, so a
     * one-shot download rides out a flaky/lossy link (off by default-clean: it
     * only engages on a transport fault). */
    src.c = c;
    src.f = &f;
    src.pgrw = o->pgrw;
    src.resilient = 1;
    src.path = su->path;
    src.opaque = opaque;
    src.max_stall_ms = (o->max_stall_ms > 0) ? o->max_stall_ms : 60000;
    src.cur_chunk = XRDC_COPY_CHUNK;
    rc = copy_run_download(pump_src_remote, &src, outfd,
                           si->size, o, si->size, st);

    {
        xrdc_status throwaway;
        xrdc_status_clear(&throwaway);
        xrdc_file_close(c, &f, rc == 0 ? st : &throwaway);
    }
    return rc;
}

/*
 * Resilient session bring-up for a download: connect + stat, retried within a
 * max_stall window on a transport fault (with fast backoff), so the MULTI-RTT
 * setup phase (handshake + login + stat) survives a flaky/lossy link instead of
 * failing the whole copy on the first sever — the same patience the read pump
 * gets. On success `c` is connected and `*si` is filled. 0 / -1 (st set).
 */
static int
resilient_setup(xrdc_conn *c, const xrdc_url *su, const xrdc_opts *co,
                xrdc_statinfo *si, int max_stall_ms, xrdc_status *st)
{
    uint64_t deadline = xrdc_mono_ns() + (uint64_t) max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    int      up = 0;
    for (;;) {
        if (!up && xrdc_connect(c, su, co, st) == 0) {
            up = 1;
        }
        if (up && xrdc_stat(c, su->path, si, st) == 0) {
            return 0;
        }
        /* A connection that has NEVER established and is actively REFUSED is a
         * definitive failure (nothing is listening), not a transient stall — fail
         * fast instead of burning the whole max_stall window retrying it. Re-attempts
         * for a momentarily-down/restarting endpoint are the OUTER --retry's job
         * (it backs off with jitter between whole-copy attempts). A connect TIMEOUT
         * / unreachable (lossy link) or any fault AFTER we were up stays retryable. */
        if (!up && st->kxr == XRDC_ESOCK && st->sys_errno == ECONNREFUSED) {
            return -1;
        }
        if (!xrdc_status_retryable(st) || xrdc_copy_quit_requested()
            || xrdc_mono_ns() >= deadline) {
            if (up) {
                xrdc_close(c);
            }
            return -1;
        }
        if (up) {            /* drop the suspect session before reconnecting */
            xrdc_close(c);
            up = 0;
        }
        xrdc_backoff_sleep_fast(attempt++);
    }
}

static int
copy_download(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o,
              const xrdc_opts *co, xrdc_status *st)
{
    xrdc_conn      c;
    xrdc_statinfo  si;
    xrdc_streamset ss;
    int            outfd = -1;
    int            to_stdout = (du->scheme == XRDC_SCHEME_STDIO);
    int            use_tmp = 0;
    int            rc;
    char           tmp[XRDC_PATH_MAX];
    int            stall = (o->max_stall_ms > 0) ? o->max_stall_ms : 60000;

    ss.n = 0;   /* so the streams teardown is a no-op if we never bind */
    if (resilient_setup(&c, su, co, &si, stall, st) != 0) {
        return -1;
    }
    if (si.flags & kXR_isDir) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "source is a directory (use -r, M5)");
        xrdc_close(&c);
        return -1;
    }

    /*
     * Phase 40 (a): download to a `<dst>.xrdcp-tmp.<pid>` sibling and rename(2)
     * onto the final path only after a complete, checksum-verified transfer —
     * the same atomicity copy_web_download already has. An interrupt (SIGINT) or
     * error then leaves at most an orphan temp; the real destination is never a
     * truncated/partial file, and a pre-existing file is never clobbered until
     * the new copy is known-good.
     */
    if (to_stdout) {
        outfd = STDOUT_FILENO;
    } else {
        if (!o->force && access(du->path, F_OK) == 0) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "destination exists (use -f to overwrite): %s",
                            du->path);
            xrdc_close(&c);
            return -1;
        }
        if (make_temp_path(du->path, tmp, sizeof(tmp)) != 0) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "destination path too long: %s",
                            du->path);
            xrdc_close(&c);
            return -1;
        }
        outfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (outfd < 0) {
            xrdc_status_set(st, XRDC_EUSAGE, errno,
                            "open %s: %s", tmp, strerror(errno));
            xrdc_close(&c);
            return -1;
        }
        use_tmp = 1;
    }

    rc = download_stream_body(&c, su, &si, outfd, o, &ss, st);

    if (outfd >= 0 && !to_stdout) {
        close(outfd);   /* flush before any checksum read */
    }
    /* Verify the checksum (against the TEMP file) while the post-redirect
     * connection is still open. A genuine MISMATCH drops the temp; a transient
     * query failure keeps the good bytes and only warns — never delete a
     * byte-perfect download because the control-plane query hiccupped. */
    if (rc == 0 && o->cksum != NULL) {
        int ck = cksum_verify(&c, su->path, to_stdout ? NULL : tmp,
                              o->cksum, o->silent, st);
        if (ck == XRDC_CK_MISMATCH) {
            rc = -1;
        } else if (ck == XRDC_CK_UNVERIFIED) {
            if (!o->silent) {
                fprintf(stderr, "xrdcp: %s downloaded but checksum NOT verified: "
                                "%s\n", du->path, st->msg);
            }
            xrdc_status_clear(st);   /* could-not-verify is not a transfer failure */
        }
    }

    if (use_tmp) {
        rc = atomic_dest_finish(tmp, du->path, rc, st);
    }
    xrdc_streams_close(&ss);
    xrdc_close(&c);
    return rc;
}

/*
 * WHAT: Connect the destination, open it for write, stream `infd` into it, then
 *       tear the whole remote side down (file close on success, checksum, bound
 *       streams, connection) — the entire "destination session is up" lifetime.
 * WHY:  Confining the connection / write handle / secondary streams / scratch buf
 *       to one helper keeps copy_upload() a flat early-return sequence whose only
 *       lingering resource is the local infd. Both pre-open failure paths
 *       (connect, open_write) return early without entering the finish teardown,
 *       exactly as the original early exits skipped the finish label.
 * HOW:  connect (fail → return -1) → open_write (fail → xrdc_close, return -1) →
 *       streams_open → malloc buf → read(infd)/remote-write loop. The finish step
 *       runs unconditionally once opened: close the remote file cleanly only on
 *       success (POSC discards a partial upload when the handle is abandoned on
 *       error), verify the checksum on the still-open connection, close streams,
 *       close the connection. buf is freed here; infd is owned by the caller.
 */
static int
upload_stream_body(const xrdc_url *su, const xrdc_url *du,
                   const xrdc_copy_opts *o, const xrdc_opts *co, int infd,
                   int from_stdin, xrdc_status *st)
{
    xrdc_conn      c;
    xrdc_file      f;
    xrdc_streamset ss;
    pump_remote_t  sink = {0};
    int64_t        total = -1;   /* progress total: file size, or -1 for stdin */
    int            rc;

    ss.n = 0;
    {
        struct stat usb;
        if (!from_stdin && fstat(infd, &usb) == 0 && S_ISREG(usb.st_mode)) {
            total = (int64_t) usb.st_size;
        }
    }
    if (xrdc_connect_resilient(&c, du, co, st) != 0) {
        return -1;
    }
    /* phase-42 W5: request inline write compression when --compress was given —
     * the server decompresses each payload on ingest (xrdc_file_write compresses
     * transparently once the handle's write_codec is learned).  A server that
     * doesn't support it returns plaintext (write_codec stays 0), so this is safe.
     * Streams are disabled under write compression (the secondaries would carry
     * raw payloads the server can't frame). */
    {
        char        opq[80];
        const char *copq = NULL;
        if (o->compress != NULL && o->compress[0] != '\0') {
            snprintf(opq, sizeof(opq), "xrootd.compress=%s", o->compress);
            copq = opq;
        }
        /* Resilient INITIAL open: a restart can hit during connect/open, before
         * the write loop's resilient sink is reached.  Retry the open with
         * reconnect within the stall window — nothing is written yet, so a fresh
         * create/truncate retry is safe (matches download_stream_body and
         * xrdc_rfile_open_write).  Subsequent reopens (pump_sink_reopen) switch
         * to in-place update so resumed bytes are never re-truncated. */
        int      stall = (o->max_stall_ms > 0) ? o->max_stall_ms : 60000;
        uint64_t deadline = xrdc_mono_ns() + (uint64_t) stall * 1000000ULL;
        unsigned attempt = 0;
        for (;;) {
            int orc = (copq != NULL)
                      ? xrdc_file_open_opaque(&c, du->path, opq, 1, o->force,
                                              o->posc, &f, st)
                      : xrdc_file_open_write(&c, du->path, o->force, o->posc,
                                             &f, st);
            if (orc == 0) {
                break;
            }
            if (!xrdc_status_retryable(st) || xrdc_copy_quit_requested()
                || xrdc_mono_ns() >= deadline) {
                xrdc_close(&c);
                return -1;
            }
            xrdc_backoff_sleep_fast(attempt++);
            const char *h = (c.home_host[0] != '\0') ? c.home_host : c.host;
            int         p = (c.home_port != 0) ? c.home_port : c.port;
            (void) xrdc_reconnect(&c, h, p, st);
        }
    }

    /* M8: attach N-1 bound secondary streams to the (post-redirect) session.
     * Skip them when write compression is active (see above). */
    if (f.write_codec == 0) {
        xrdc_streams_open(&ss, &c, o->streams, st);
    }

    /* local infd → remote (EOF-driven), with progress (total = file size or -1).
     * The sink is resilient: a transport sever mid-upload reconnects, reopens the
     * destination IN PLACE (no truncate) and re-issues from the same offset, so an
     * upload survives an nginx restart and resumes from where it left off.  This
     * needs the bytes below the offset to still be on the server: true for a
     * direct-to-final write (default, posc off) and for a server with
     * xrootd_upload_resume on (deterministic preserved partial).  Re-issuing the
     * same buffer at the same offset is idempotent. */
    sink.c = &c;
    sink.f = &f;
    sink.pgrw = o->pgrw;
    sink.resilient = 1;
    sink.path = du->path;
    sink.posc = o->posc;
    sink.max_stall_ms = (o->max_stall_ms > 0) ? o->max_stall_ms : 60000;
    rc = copy_run_upload(infd, pump_sink_remote, &sink, -1, o, total, st);

    /* Only close the remote file cleanly on success: with POSC, abandoning the
     * handle (connection teardown without close) makes the server discard the
     * partial upload, which is exactly the atomicity we want on error.
     *
     * The close is the COMMIT (it renames the staged partial to the destination),
     * so it must be resilient too: a restart landing on the final close would
     * otherwise leave a fully-written-but-uncommitted partial.  Retry the close
     * within the stall window, reconnecting + reopening IN PLACE between attempts
     * — the bytes are all there, so reopen+close simply commits. */
    if (rc == 0) {
        uint64_t deadline = xrdc_mono_ns()
                          + (uint64_t) sink.max_stall_ms * 1000000ULL;
        unsigned attempt = 0;
        for (;;) {
            if (xrdc_file_close(&c, &f, st) == 0) {
                break;
            }
            if (xrdc_copy_quit_requested() || xrdc_mono_ns() >= deadline) {
                rc = -1;
                break;
            }
            xrdc_backoff_sleep_fast(attempt++);
            if (pump_sink_reopen(&sink, st) == 0) {
                continue;   /* reopened the partial in place — loop re-commits */
            }
            /*
             * Reopen-in-place failed.  A PRIOR close may have already committed
             * (renamed the staged partial onto the destination) with its ack lost
             * to the sever — so the partial is gone and reopen-update NotFounds.
             * Confirm the commit by the destination's size and treat as success.
             * (total < 0 = stdin: no known size, so fall back to retryability.)
             */
            if (total >= 0) {
                xrdc_statinfo si;
                if (xrdc_stat(&c, du->path, &si, st) == 0 && si.size == total) {
                    xrdc_status_clear(st);
                    rc = 0;
                    break;
                }
            }
            if (!xrdc_status_retryable(st) || xrdc_mono_ns() >= deadline) {
                rc = -1;
                break;
            }
        }
    }
    /* The file is persisted after close — verify its checksum now (connection
     * still open), comparing our local source digest against the server's. */
    if (rc == 0 && o->cksum != NULL) {
        int ck = cksum_verify(&c, du->path, from_stdin ? NULL : su->path,
                              o->cksum, o->silent, st);
        if (ck == XRDC_CK_MISMATCH) {
            rc = -1;
        } else if (ck == XRDC_CK_UNVERIFIED) {
            if (!o->silent) {
                fprintf(stderr, "xrdcp: uploaded but checksum NOT verified: %s\n",
                        st->msg);
            }
            xrdc_status_clear(st);   /* could-not-verify is not a transfer failure */
        }
    }
    xrdc_streams_close(&ss);
    xrdc_close(&c);
    return rc;
}

static int
copy_upload(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o,
            const xrdc_opts *co, xrdc_status *st)
{
    int infd;
    int from_stdin = (su->scheme == XRDC_SCHEME_STDIO);
    int rc;

    if (from_stdin) {
        infd = STDIN_FILENO;
    } else {
        infd = open(su->path, O_RDONLY);
        if (infd < 0) {
            xrdc_status_set(st, XRDC_EUSAGE, errno,
                            "open %s: %s", su->path, strerror(errno));
            return -1;
        }
    }

    rc = upload_stream_body(su, du, o, co, infd, from_stdin, st);

    if (infd >= 0 && !from_stdin) {
        close(infd);
    }
    return rc;
}

/*
 * Client-mediated remote → remote copy: read from the source server and write to
 * the destination server through this process (two independent sessions). This is
 * NOT server-side third-party copy (kXR_tpc / M8); the bytes transit the client.
 * Both opens go through xrdc_roundtrip, so each side independently follows any
 * cluster redirect to its data server.
 */
/*
 * WHAT: Tear down whatever the remote→remote copy actually acquired, in reverse
 *       order, and return the final rc.
 * WHY:  Both sessions/handles are released the same way from every exit point;
 *       extracting it lets the orchestrator return r2r_teardown(...) directly at
 *       each decision site instead of jumping to a shared label.
 * HOW:  Each `*_up` / `*open` flag gates the matching close so a partially
 *       initialised attempt frees only what it acquired. The destination handle
 *       is closed cleanly only on success (POSC discards a partial upload when the
 *       handle is abandoned on error); the source handle always closes silently.
 */
static int
r2r_teardown(xrdc_conn *sc, xrdc_conn *dc, xrdc_file *sf, xrdc_file *df,
             int src_up, int dst_up, int sopen, int dopen, int rc,
             xrdc_status *st)
{
    if (dopen && rc == 0) {
        if (xrdc_file_close(dc, df, st) != 0) {
            rc = -1;
        }
    }
    if (sopen) {
        xrdc_status throwaway;
        xrdc_status_clear(&throwaway);
        xrdc_file_close(sc, sf, &throwaway);
    }
    if (dst_up) {
        xrdc_close(dc);
    }
    if (src_up) {
        xrdc_close(sc);
    }
    return rc;
}

/*
 * WHAT: Stream the source's `si->size` bytes through this process into the open
 *       destination handle. Returns 0 on a complete transfer, -1 (st set) otherwise.
 * WHY:  Isolating the read/write loop (and its scratch buffer) keeps the loop body
 *       free of cleanup jumps — it just reports success/failure to the orchestrator,
 *       which owns the connections and runs the staged teardown.
 * HOW:  malloc one chunk buffer, read from the source and write to the destination
 *       until si->size is reached, then free the buffer on every path.
 */
static int
r2r_stream_body(xrdc_conn *sc, xrdc_conn *dc, xrdc_file *sf, xrdc_file *df,
                const xrdc_statinfo *si, const xrdc_copy_opts *o, xrdc_status *st)
{
    pump_remote_t src  = { .c = sc, .f = sf, .pgrw = o->pgrw };
    pump_remote_t sink = { .c = dc, .f = df, .pgrw = o->pgrw };

    /* remote (known si->size) → remote; no progress here (historical). */
    return transfer_pump(pump_src_remote, &src, pump_sink_remote, &sink,
                         si->size, NULL, si->size, st);
}

static int
copy_remote_to_remote(const xrdc_url *su, const xrdc_url *du,
                      const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st)
{
    xrdc_conn     sc, dc;
    xrdc_file     sf, df;
    xrdc_statinfo si;
    int           rc;

    if (xrdc_connect(&sc, su, co, st) != 0) {
        return -1;
    }
    if (xrdc_stat(&sc, su->path, &si, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 0, 0, 0, -1, st);
    }
    if (si.flags & kXR_isDir) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "source is a directory (recursive copy unsupported)");
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 0, 0, 0, -1, st);
    }

    if (xrdc_connect(&dc, du, co, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 0, 0, 0, -1, st);
    }

    if (xrdc_file_open_read(&sc, su->path, &sf, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 1, 0, 0, -1, st);
    }
    if (xrdc_file_open_write(&dc, du->path, o->force, o->posc, &df, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 1, 1, 0, -1, st);
    }

    rc = r2r_stream_body(&sc, &dc, &sf, &df, &si, o, st);

    return r2r_teardown(&sc, &dc, &sf, &df, 1, 1, 1, 1, rc, st);
}

/*
 * --cksum handling. `spec` is "<type>[:source|:print|:<value>]". Computes the
 * named checksum over the local file `local_path` (the bytes we actually moved)
 * and then, by mode:
 *   :source / :end2end → query the server (kXR_Qcksum) for `remote_path` on the
 *                        already-open connection `c` and require they match;
 *   :<value>           → require the local digest equals the given hex;
 *   :print / (none)    → print "<type> <digest>" (unless silent).
 * Returns XRDC_CK_OK (matched/printed), XRDC_CK_MISMATCH (digest known and WRONG
 * — caller drops the destination), or XRDC_CK_UNVERIFIED (query/transport/usage
 * error — the digest is UNKNOWN, so the caller keeps the file and only warns;
 * deleting a byte-perfect download because a control-plane query hiccupped would
 * be the inverse footgun).
 */
static int
cksum_verify(xrdc_conn *c, const char *remote_path, const char *local_path,
             const char *spec, int silent, xrdc_status *st)
{
    char            algo_name[32];
    char            local_hex[129];
    const char     *colon = strchr(spec, ':');
    const char     *mode = NULL;
    size_t          alen;
    xrdc_cksum_algo algo;
    int             lfd;

    alen = colon ? (size_t) (colon - spec) : strlen(spec);
    if (alen == 0 || alen >= sizeof(algo_name)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "bad --cksum type");
        return XRDC_CK_UNVERIFIED;
    }
    memcpy(algo_name, spec, alen);
    algo_name[alen] = '\0';
    mode = colon ? colon + 1 : NULL;

    if (xrdc_cksum_algo_parse(algo_name, &algo) != 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "unsupported --cksum type \"%s\"", algo_name);
        return XRDC_CK_UNVERIFIED;
    }

    if (local_path == NULL) {
        /* stdio endpoint — nothing on disk to digest; skip rather than lie. */
        if (!silent) {
            fprintf(stderr, "xrdcp: --cksum skipped for stdin/stdout\n");
        }
        return XRDC_CK_OK;
    }

    lfd = open(local_path, O_RDONLY);
    if (lfd < 0) {
        xrdc_status_set(st, XRDC_EUSAGE, errno,
                        "open %s for checksum: %s", local_path, strerror(errno));
        return XRDC_CK_UNVERIFIED;
    }
    if (xrdc_cksum_fd(lfd, algo, local_hex, sizeof(local_hex), st) != 0) {
        close(lfd);
        return XRDC_CK_UNVERIFIED;
    }
    close(lfd);

    if (mode != NULL
        && (strcmp(mode, "source") == 0 || strcmp(mode, "end2end") == 0)) {
        char server_hex[129];
        if (remote_path == NULL) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "--cksum:source has no remote");
            return XRDC_CK_UNVERIFIED;
        }
        if (xrdc_query_cksum(c, remote_path, algo_name,
                             server_hex, sizeof(server_hex), st) != 0) {
            return XRDC_CK_UNVERIFIED;   /* server digest UNKNOWN, not WRONG */
        }
        if (strcasecmp(local_hex, server_hex) != 0) {
            /* A checksum mismatch is a data-integrity failure, not a transient
             * framing fault — classify it non-retryable so no resilient loop
             * spins re-verifying the same bytes. */
            xrdc_status_set(st, XRDC_EINTEGRITY, 0,
                            "%s mismatch: local %s != server %s",
                            algo_name, local_hex, server_hex);
            return XRDC_CK_MISMATCH;
        }
        if (!silent) {
            printf("%s %s OK (matches server)\n", algo_name, local_hex);
        }
        return XRDC_CK_OK;
    }

    if (mode != NULL && strcmp(mode, "print") != 0) {
        /* literal expected value */
        if (strcasecmp(local_hex, mode) != 0) {
            xrdc_status_set(st, XRDC_EINTEGRITY, 0,
                            "%s mismatch: got %s expected %s",
                            algo_name, local_hex, mode);
            return XRDC_CK_MISMATCH;
        }
        if (!silent) {
            printf("%s %s OK\n", algo_name, local_hex);
        }
        return XRDC_CK_OK;
    }

    /* print / no mode */
    if (!silent) {
        printf("%s %s\n", algo_name, local_hex);
    }
    return XRDC_CK_OK;
}

/* Mint a random TPC rendezvous key (hex of 16 /dev/urandom bytes). */
static int
gen_tpc_key(char *out, size_t outsz)
{
    uint8_t raw[16];
    int     fd;

    if (outsz < sizeof(raw) * 2 + 1) {
        return -1;
    }
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    if (read(fd, raw, sizeof(raw)) != (ssize_t) sizeof(raw)) {
        close(fd);
        return -1;
    }
    close(fd);
    xrootd_hex_encode(raw, sizeof(raw), out);   /* shared lowercase hex */
    return 0;
}

/*
 * Server-side third-party copy (root://), source-first rendezvous:
 *   1. open SRC read with tpc.key=K & tpc.dst=root://dest//dpath  → registers K
 *   2. open DST write with tpc.src=root://src//spath & tpc.key=K  → dest = puller
 *   3. kXR_sync DST (arm "tpc-arm"), then kXR_sync DST again (trigger the pull;
 *      its reply is deferred until the transfer completes).
 * The destination server connects to the source itself and pulls the bytes — no
 * data transits this client (unlike copy_remote_to_remote).
 */
/*
 * WHAT: Tear down whatever the TPC rendezvous acquired — the two opaque request
 *       strings, the source/destination handles, and their connections — and
 *       return the final rc.
 * WHY:  Every exit point releases the same resources the same way; extracting it
 *       lets the orchestrator return tpc_teardown(...) directly at each decision
 *       site instead of jumping to a shared label.
 * HOW:  Each `*open` / `*_up` flag gates the matching close so a partially set-up
 *       rendezvous frees only what it acquired. The destination handle reports its
 *       close error into `st` only on success (so a failed sync's status survives);
 *       the source handle always closes silently. The opaque strings are freed
 *       unconditionally (they are allocated before any session is opened).
 */
static int
tpc_teardown(xrdc_conn *sc, xrdc_conn *dc, xrdc_file *sf, xrdc_file *df,
             char *src_opaque, char *dst_opaque,
             int su_up, int du_up, int sopen, int dopen, int rc, xrdc_status *st)
{
    if (dopen) {
        xrdc_status tw; xrdc_status_clear(&tw);
        xrdc_file_close(dc, df, rc == 0 ? st : &tw);
    }
    if (sopen) {
        xrdc_status tw; xrdc_status_clear(&tw);
        xrdc_file_close(sc, sf, &tw);
    }
    if (du_up) { xrdc_close(dc); }
    if (su_up) { xrdc_close(sc); }
    free(src_opaque);
    free(dst_opaque);
    return rc;
}

static int
copy_tpc(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o,
         const xrdc_opts *co, xrdc_status *st)
{
    xrdc_conn   sc, dc;
    xrdc_file   sf, df;
    char        key[40];
    char       *src_opaque = NULL, *dst_opaque = NULL;
    size_t      need;
    const char *tok = (o->tpc_token_mode && o->tpc_token_mode[0])
                      ? o->tpc_token_mode : NULL;

    if (gen_tpc_key(key, sizeof(key)) != 0) {
        xrdc_status_set(st, XRDC_ESOCK, 0, "cannot generate TPC key");
        return -1;
    }
    /* Heap-size the opaque strings to the actual host/path/key/token lengths. */
    need = strlen(su->host) + strlen(su->path) + strlen(du->host)
           + strlen(du->path) + sizeof(key) + (tok ? strlen(tok) : 0) + 128;
    src_opaque = (char *) malloc(need);
    dst_opaque = (char *) malloc(need);
    if (src_opaque == NULL || dst_opaque == NULL) {
        free(src_opaque); free(dst_opaque);
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    snprintf(src_opaque, need,
             "tpc.key=%s&tpc.dst=root://%s:%d/%s%s%s", key,
             du->host, du->port, du->path,
             tok ? "&tpc.token_mode=" : "", tok ? tok : "");
    snprintf(dst_opaque, need,
             "tpc.src=root://%s:%d/%s&tpc.key=%s%s%s",
             su->host, su->port, su->path, key,
             tok ? "&tpc.token_mode=" : "", tok ? tok : "");

    if (xrdc_connect(&sc, su, co, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            0, 0, 0, 0, -1, st);
    }
    if (xrdc_file_open_opaque(&sc, su->path, src_opaque, 0, 0, 0, &sf, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 0, 0, 0, -1, st);
    }

    if (xrdc_connect(&dc, du, co, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 0, 1, 0, -1, st);
    }
    if (xrdc_file_open_opaque(&dc, du->path, dst_opaque, 1, o->force, o->posc,
                              &df, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 1, 1, 0, -1, st);
    }

    if (xrdc_file_sync(&dc, &df, st) != 0) {     /* arm → "tpc-arm" */
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 1, 1, 1, -1, st);
    }
    if (dc.io.timeout_ms < 300000) {
        dc.io.timeout_ms = 300000;               /* 5 min for the deferred pull */
    }
    if (xrdc_file_sync(&dc, &df, st) != 0) {     /* trigger + await completion */
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 1, 1, 1, -1, st);
    }

    return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                        1, 1, 1, 1, 0, st);
}

/* ------------------------------------------------------------------ */
/* recursive copy (-r): one connection per tree, dirlist/local walk     */
/* ------------------------------------------------------------------ */

/* Copy one remote file (open under conn c) to a fresh local file. */
static int
copy_one_r2l(xrdc_conn *c, const char *rpath, const char *lpath,
             int64_t expected_size, xrdc_status *st)
{
    xrdc_file     f;
    int           fd;
    char          tmp[XRDC_PATH_MAX];
    pump_remote_t src = {0};
    int           rc;

    if (xrdc_file_open_read(c, rpath, &f, st) != 0) {
        return -1;
    }
    /* Phase 40 (a): atomic per-file temp+rename + signal-abort, mirroring
     * copy_download — so a failed or interrupted recursive transfer leaves no
     * partial/truncated tree entry (the old direct O_TRUNC write left a partial
     * on every error path and on Ctrl-C). */
    if (make_temp_path(lpath, tmp, sizeof(tmp)) != 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "destination path too long: %s", lpath);
        xrdc_file_close(c, &f, st);
        return -1;
    }
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "open %s: %s", tmp, strerror(errno));
        xrdc_file_close(c, &f, st);
        return -1;
    }

    /* remote (dirlist-sized when available, plain read — recursive path
     * historically never paged) → local temp fd. atomic_dest_finish() drops the
     * temp on any failure (rc != 0). */
    src.c = c;
    src.f = &f;
    src.pgrw = 0;
    rc = copy_run_download(pump_src_remote, &src, fd,
                           expected_size, NULL, expected_size, st);

    close(fd);
    xrdc_file_close(c, &f, st);
    return atomic_dest_finish(tmp, lpath, rc, st);
}

/* Copy one local file to a fresh remote file (open under conn c). */
static int
copy_one_l2r(xrdc_conn *c, const char *lpath, const char *rpath,
             const xrdc_copy_opts *o, xrdc_status *st)
{
    xrdc_file     f;
    int           fd;
    pump_remote_t sink = {0};
    int           rc;

    fd = open(lpath, O_RDONLY);
    if (fd < 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "open %s: %s", lpath, strerror(errno));
        return -1;
    }
    if (xrdc_file_open_write(c, rpath, 1 /*force*/, o ? o->posc : 0, &f, st) != 0) {
        close(fd);
        return -1;
    }

    /* local fd (EOF-driven) → remote, plain write (recursive path). On failure
     * the file is still closed (preserving the historical recursive teardown,
     * which never relied on POSC-discard the way single-file upload does). */
    sink.c = c;
    sink.f = &f;
    sink.pgrw = 0;
    rc = copy_run_upload(fd, pump_sink_remote, &sink, -1, NULL, 0, st);

    close(fd);
    if (rc != 0) {
        xrdc_file_close(c, &f, st);
        return -1;
    }
    return xrdc_file_close(c, &f, st);
}

/* Recurse a remote tree (rpath) under conn c into local lpath. */
static int
copy_tree_download(xrdc_conn *c, const char *rpath, const char *lpath,
                   const xrdc_copy_opts *o, xrdc_status *st)
{
    xrdc_dirent *ents = NULL;
    size_t       n = 0, i;

    if (mkdir(lpath, 0755) != 0 && errno != EEXIST) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "mkdir %s: %s", lpath, strerror(errno));
        return -1;
    }
    if (xrdc_dirlist(c, rpath, 1, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        char rc[XRDC_PATH_MAX], lc[XRDC_PATH_MAX];
        if (ents[i].name[0] == '.'
            && (ents[i].name[1] == '\0'
                || (ents[i].name[1] == '.' && ents[i].name[2] == '\0'))) {
            continue;
        }
        if ((size_t) snprintf(rc, sizeof(rc), "%s/%s", rpath, ents[i].name)
                >= sizeof(rc)
            || (size_t) snprintf(lc, sizeof(lc), "%s/%s", lpath, ents[i].name)
                >= sizeof(lc)) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "recursive copy: path too long under %s", rpath);
            free(ents);
            return -1;
        }
        if (ents[i].have_stat && (ents[i].st.flags & kXR_isDir)) {
            if (copy_tree_download(c, rc, lc, o, st) != 0) { free(ents); return -1; }
        } else {
            int64_t expected = ents[i].have_stat ? ents[i].st.size : -1;
            if (copy_one_r2l(c, rc, lc, expected, st) != 0) {
                free(ents);
                return -1;
            }
        }
    }
    free(ents);
    return 0;
}

/* Recurse a local tree (lpath) into a remote tree (rpath) under conn c. */
static int
copy_tree_upload(xrdc_conn *c, const char *lpath, const char *rpath,
                 const xrdc_copy_opts *o, xrdc_status *st)
{
    DIR           *d;
    struct dirent *de;
    xrdc_status    mst;

    xrdc_status_clear(&mst);
    (void) xrdc_mkdir(c, rpath, 0755, 1 /*parents*/, &mst);  /* may already exist */
    d = opendir(lpath);
    if (d == NULL) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "opendir %s: %s", lpath, strerror(errno));
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        char        lc[XRDC_PATH_MAX], rc[XRDC_PATH_MAX];
        struct stat sb;
        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
            continue;
        }
        if ((size_t) snprintf(lc, sizeof(lc), "%s/%s", lpath, de->d_name)
                >= sizeof(lc)
            || (size_t) snprintf(rc, sizeof(rc), "%s/%s", rpath, de->d_name)
                >= sizeof(rc)) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "recursive copy: path too long under %s", lpath);
            closedir(d);
            return -1;
        }
        /* lstat (not stat) so symlinks are detected, not followed — a link to a
         * parent directory would otherwise drive unbounded recursion. */
        if (lstat(lc, &sb) != 0) {
            continue;   /* vanished between readdir and stat — skip */
        }
        if (S_ISLNK(sb.st_mode)) {
            continue;   /* skip symlinks (loop-safe; mirrors official -r default) */
        }
        if (S_ISDIR(sb.st_mode)) {
            if (copy_tree_upload(c, lc, rc, o, st) != 0) { closedir(d); return -1; }
        } else if (S_ISREG(sb.st_mode)) {
            if (copy_one_l2r(c, lc, rc, o, st) != 0) { closedir(d); return -1; }
        }
    }
    closedir(d);
    return 0;
}

/* Recursive copy entry: connect once, walk the source tree. Direction-aware. */
static int
copy_recursive(const xrdc_url *su, const xrdc_url *du, int download,
               const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st)
{
    xrdc_conn c;
    int       rc;

    if (download) {
        if (xrdc_connect(&c, su, co, st) != 0) { return -1; }
        rc = copy_tree_download(&c, su->path, du->path, o, st);
    } else {
        if (xrdc_connect(&c, du, co, st) != 0) { return -1; }
        rc = copy_tree_upload(&c, su->path, du->path, o, st);
    }
    xrdc_close(&c);
    return rc;
}

/* ------------------------------------------------------------------ */
/* web transfer (davs:// / http(s):// / s3://) — production GET/PUT over  */
/* the streaming HTTP client. Auth: WebDAV bearer token or S3 SigV4.      */
/* ------------------------------------------------------------------ */

#define XRDC_WEB_TIMEOUT_MS 300000   /* 5 min per-read ceiling for big files */

/* Build the auth header block for a web request into hdrs[] (may be empty for an
 * anonymous endpoint). S3 → SigV4 (host signed as "host:port" to match the Host
 * header we send); WebDAV/HTTP → Authorization: Bearer if a token is available. */
static int
web_auth_headers(const xrdc_weburl *u, const char *method,
                 const xrdc_copy_opts *o, char *hdrs, size_t hdrsz, xrdc_status *st)
{
    hdrs[0] = '\0';
    if (u->is_s3) {
        const char *ak = (o && o->s3_access) ? o->s3_access : getenv("AWS_ACCESS_KEY_ID");
        const char *sk = (o && o->s3_secret) ? o->s3_secret : getenv("AWS_SECRET_ACCESS_KEY");
        const char *rg = (o && o->s3_region) ? o->s3_region : getenv("AWS_DEFAULT_REGION");
        char host[300], payhash[65];
        if (ak == NULL || sk == NULL) {
            return 0;   /* anonymous — server may permit unsigned access */
        }
        if (rg == NULL) { rg = "us-east-1"; }
        /* A '?' would split path vs query in the server's canonical request but
         * we sign the whole path as CanonicalURI — reject rather than mis-sign. */
        if (strchr(u->path, '?') != NULL) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "s3: query strings in the URL are not supported");
            return -1;
        }
        /* The SigV4 signed host MUST match the wire Host header byte-for-byte; that
         * header brackets IPv6 literals ([::1]:9000), so sign the same form. */
        xrootd_format_host_port(u->host, (uint16_t) u->port, host, sizeof(host));
        /* UNSIGNED-PAYLOAD for every method: the body isn't folded into the
         * signature (it streams), which both nginx-xrootd's S3 and real AWS accept. */
        snprintf(payhash, sizeof(payhash), "UNSIGNED-PAYLOAD");
        if (xrdc_s3_sign_v4(method, host, u->path, ak, sk, rg, payhash,
                            hdrs, hdrsz) != 0) {
            xrdc_status_set(st, XRDC_EAUTH, 0, "s3: failed to build SigV4 signature");
            return -1;
        }
        return 0;
    }
    {
        const char *tok = (o && o->bearer) ? o->bearer : getenv("BEARER_TOKEN");
        if (tok != NULL && tok[0] != '\0') {
            int n = snprintf(hdrs, hdrsz, "Authorization: Bearer %s\r\n", tok);
            if (n < 0 || (size_t) n >= hdrsz) {
                xrdc_status_set(st, XRDC_EUSAGE, 0, "bearer token too long");
                return -1;
            }
        }
    }
    return 0;
}

static int
copy_web_download(const xrdc_weburl *su, const xrdc_url *du, int to_stdout,
                  const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st)
{
    char      hdrs[8192];
    char      tmp[XRDC_PATH_MAX];
    int       outfd, status = 0, rc;
    long long blen = 0;

    if (web_auth_headers(su, "GET", o, hdrs, sizeof(hdrs), st) != 0) {
        return -1;
    }
    if (to_stdout) {
        rc = xrdc_http_download(su->host, su->port, su->tls, su->path,
                                hdrs[0] ? hdrs : NULL, co ? co->verify_host : 1,
                                co ? co->ca_dir : NULL, STDOUT_FILENO,
                                XRDC_WEB_TIMEOUT_MS, &status, &blen, st);
        return rc;
    }
    /* Refuse to overwrite an existing destination unless -f. */
    if (!(o && o->force) && access(du->path, F_OK) == 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "destination exists (use -f to overwrite): %s", du->path);
        return -1;
    }
    /* Download to a temp sibling and atomically rename on success: a failed
     * transfer must never truncate or delete a pre-existing destination. */
    if (make_temp_path(du->path, tmp, sizeof(tmp)) != 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "destination path too long");
        return -1;
    }
    outfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (outfd < 0) {
        xrdc_status_set(st, XRDC_EUSAGE, errno, "open %s: %s", tmp, strerror(errno));
        return -1;
    }
    rc = xrdc_http_download(su->host, su->port, su->tls, su->path,
                            hdrs[0] ? hdrs : NULL, co ? co->verify_host : 1,
                            co ? co->ca_dir : NULL, outfd, XRDC_WEB_TIMEOUT_MS,
                            &status, &blen, st);
    close(outfd);
    rc = atomic_dest_finish(tmp, du->path, rc, st);
    if (rc != 0) {
        return rc;
    }
    if (o && !o->silent) {
        fprintf(stderr, "xrdcp: downloaded %lld bytes (HTTP %d)\n", blen, status);
    }
    return 0;
}

static int
copy_web_upload(const xrdc_url *su, const xrdc_weburl *du, const xrdc_copy_opts *o,
                const xrdc_opts *co, xrdc_status *st)
{
    char        hdrs[8192];
    struct stat sb;
    int         infd, status = 0, rc;

    if (su->scheme == XRDC_SCHEME_STDIO) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "web upload needs a regular local file (Content-Length); "
                        "stdin not supported");
        return -1;
    }
    infd = open(su->path, O_RDONLY);
    if (infd < 0) {
        xrdc_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
                        su->path, strerror(errno));
        return -1;
    }
    if (fstat(infd, &sb) != 0) {
        close(infd);
        xrdc_status_set(st, XRDC_ESOCK, errno, "fstat %s: %s",
                        su->path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(sb.st_mode)) {
        /* st_size is only a reliable Content-Length for a regular file. */
        close(infd);
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "web upload source must be a regular file: %s", su->path);
        return -1;
    }
    if (web_auth_headers(du, "PUT", o, hdrs, sizeof(hdrs), st) != 0) {
        close(infd);
        return -1;
    }
    {
        /* Resilient by default: Content-Range PUT chunks that reconnect + resume
         * from the server's durable offset, so the upload survives an nginx
         * restart (server xrootd_webdav_upload_resume).  A plain server commits on
         * the first whole-range chunk, so a single-shot upload still works. */
        int stall = (o && o->max_stall_ms > 0) ? o->max_stall_ms
                                               : XRDC_DEFAULT_MAX_STALL_MS;
        rc = xrdc_http_upload_resumable(du->host, du->port, du->tls, du->path,
                          hdrs[0] ? hdrs : NULL, infd, (long long) sb.st_size,
                          co ? co->verify_host : 1, co ? co->ca_dir : NULL,
                          XRDC_WEB_TIMEOUT_MS, stall, &status, st);
    }
    close(infd);
    if (rc == 0 && o && !o->silent) {
        fprintf(stderr, "xrdcp: uploaded %lld bytes (HTTP %d)\n",
                (long long) sb.st_size, status);
    }
    return rc;
}

/* Dispatch a copy where at least one endpoint is a web URL. */
static int
copy_web(const char *src, const char *dst, const xrdc_copy_opts *o,
         const xrdc_opts *co, xrdc_status *st)
{
    int src_web = xrdc_is_web_url(src);
    int dst_web = xrdc_is_web_url(dst);

    if (o && o->recursive) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "recursive copy is not supported for web (davs/s3) endpoints");
        return -1;
    }
    if (src_web && !dst_web) {                 /* download: web → local/stdout */
        xrdc_weburl su;
        xrdc_url    du;
        if (xrdc_weburl_parse(src, &su) != 0) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "bad web source URL");
            return -1;
        }
        if (xrdc_url_parse(dst, &du, st) != 0) {
            return -1;
        }
        if (du.scheme != XRDC_SCHEME_LOCAL && du.scheme != XRDC_SCHEME_STDIO) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "web download destination must be local or '-'");
            return -1;
        }
        return copy_web_download(&su, &du, du.scheme == XRDC_SCHEME_STDIO, o, co, st);
    }
    if (!src_web && dst_web) {                 /* upload: local → web */
        xrdc_url    su;
        xrdc_weburl du;
        if (xrdc_url_parse(src, &su, st) != 0) {
            return -1;
        }
        if (xrdc_weburl_parse(dst, &du) != 0) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "bad web destination URL");
            return -1;
        }
        if (su.scheme != XRDC_SCHEME_LOCAL && su.scheme != XRDC_SCHEME_STDIO) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "web upload source must be a local file");
            return -1;
        }
        return copy_web_upload(&su, &du, o, co, st);
    }
    xrdc_status_set(st, XRDC_EUSAGE, 0,
                    "web→web copy is not supported (stage via a local file)");
    return -1;
}

/* ---- phase-42 W3: ?xrdcl.unzip=<member> ZIP-archive member extraction ---- */

typedef struct { xrdc_conn *c; xrdc_file *f; xrdc_status *st; } zip_remote_ctx;

static ssize_t
zip_remote_pread(void *vctx, uint64_t off, void *buf, size_t len)
{
    zip_remote_ctx *z = vctx;
    return xrdc_file_read(z->c, z->f, (int64_t) off, buf, len, z->st);
}

typedef struct { int fd; } unzip_sink_ctx;

static int
unzip_sink_write(void *sc, const uint8_t *d, size_t l)
{
    unzip_sink_ctx *s = sc;
    size_t          off = 0;
    while (off < l) {
        ssize_t n = write(s->fd, d + off, l - off);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            return -1;
        }
        off += (size_t) n;
    }
    return 0;
}

/* Extract `member` from the remote ZIP archive at `archive_path` into the local
 * destination du. The server is untouched (serves raw archive bytes); the client
 * parses the directory and inflates the member locally (zlib-only). */
static int
copy_unzip(const xrdc_url *su, const char *archive_path, const char *member,
           const xrdc_url *du, const xrdc_copy_opts *o, const xrdc_opts *co,
           xrdc_status *st)
{
    xrdc_conn      c;
    xrdc_statinfo  si;
    xrdc_file      f;
    xrdc_zip_dir   dir;
    zip_remote_ctx zc;
    const xrdc_zip_entry *e;
    int            outfd = -1, to_stdout = (du->scheme == XRDC_SCHEME_STDIO);
    int            use_tmp = 0, rc = -1, zr;
    char           tmp[XRDC_PATH_MAX];

    if (xrdc_connect(&c, su, co, st) != 0) {
        return -1;
    }
    if (xrdc_stat(&c, archive_path, &si, st) != 0) {
        xrdc_close(&c);
        return -1;
    }
    if (xrdc_file_open_read(&c, archive_path, &f, st) != 0) {
        xrdc_close(&c);
        return -1;
    }

    if (to_stdout) {
        outfd = STDOUT_FILENO;
    } else {
        if (!o->force && access(du->path, F_OK) == 0) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "destination exists (use -f): %s", du->path);
            xrdc_file_close(&c, &f, st); xrdc_close(&c); return -1;
        }
        if (make_temp_path(du->path, tmp, sizeof(tmp)) != 0) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "destination path too long");
            xrdc_file_close(&c, &f, st); xrdc_close(&c); return -1;
        }
        outfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (outfd < 0) {
            xrdc_status_set(st, XRDC_EUSAGE, errno, "open %s: %s", tmp,
                            strerror(errno));
            xrdc_file_close(&c, &f, st); xrdc_close(&c); return -1;
        }
        use_tmp = 1;
    }

    zc.c = &c; zc.f = &f; zc.st = st;
    zr = xrdc_zip_open(zip_remote_pread, &zc, (uint64_t) si.size, &dir);
    if (zr != XRDC_ZIP_OK) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "ZIP open failed (%d) for %s", zr, archive_path);
    } else {
        e = xrdc_zip_find(&dir, member);
        if (e == NULL) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "ZIP member not found: %s", member);
        } else {
            unzip_sink_ctx sink = { outfd };
            zr = xrdc_zip_member_extract(zip_remote_pread, &zc, e,
                                         unzip_sink_write, &sink);
            if (zr == XRDC_ZIP_OK) {
                rc = 0;
            } else {
                xrdc_status_set(st, XRDC_EUSAGE, 0,
                                "ZIP member extract failed (%d): %s", zr, member);
            }
        }
        xrdc_zip_dir_free(&dir);
    }

    xrdc_file_close(&c, &f, st);
    if (outfd >= 0 && !to_stdout) {
        close(outfd);
    }
    if (use_tmp) {
        if (rc == 0) {
            if (rename(tmp, du->path) != 0) {
                xrdc_status_set(st, XRDC_EUSAGE, errno, "rename to %s", du->path);
                unlink(tmp);
                rc = -1;
            }
        } else {
            unlink(tmp);
        }
    }
    xrdc_close(&c);
    return rc;
}

/* If `src` carries the opaque key xrdcl.unzip=<member>, copy `member` into out
 * (caller buffer) and the archive path (opaque stripped) into arch; return 1.
 * Otherwise return 0. */
static int
unzip_member_from_src(const char *src, const xrdc_url *su,
                      char *member, size_t member_sz, char *arch, size_t arch_sz)
{
    const char *q = strstr(src, "xrdcl.unzip=");
    const char *v, *end;
    size_t      n, an;

    if (q == NULL) {
        return 0;
    }
    v   = q + (sizeof("xrdcl.unzip=") - 1);
    end = v;
    while (*end != '\0' && *end != '&') { end++; }
    n = (size_t) (end - v);
    if (n == 0 || n >= member_sz) {
        return 0;
    }
    memcpy(member, v, n);
    member[n] = '\0';

    /* archive path = su->path with any trailing "?opaque" removed. */
    an = strlen(su->path);
    {
        const char *qm = strchr(su->path, '?');
        if (qm != NULL) {
            an = (size_t) (qm - su->path);
        }
    }
    if (an >= arch_sz) {
        return 0;
    }
    memcpy(arch, su->path, an);
    arch[an] = '\0';
    return 1;
}

/* ---- phase-42 W3 write: xrdcp --zip / --zip-append (STORE-only) ----------- */

typedef struct { int fd; uint64_t off; } zipw_local_sink;
static int
zipw_local_write(void *cx, const void *d, size_t n)
{
    zipw_local_sink *s = cx;
    ssize_t          w = pwrite(s->fd, d, n, (off_t) s->off);
    if (w < 0 || (size_t) w != n) {
        return -1;
    }
    s->off += n;
    return 0;
}

typedef struct { xrdc_conn *c; xrdc_file *f; uint64_t off; xrdc_status *st; } zipw_remote_sink;
static int
zipw_remote_write(void *cx, const void *d, size_t n)
{
    zipw_remote_sink *s = cx;
    if (xrdc_file_write(s->c, s->f, (int64_t) s->off, d, n, s->st) != 0) {
        return -1;
    }
    s->off += n;
    return 0;
}

static ssize_t
zipw_local_pread(void *cx, uint64_t off, void *buf, size_t len)
{
    return pread(*(int *) cx, buf, len, (off_t) off);
}

static const char *
zip_member_basename(const char *p)
{
    const char *s = strrchr(p, '/');
    return (s != NULL) ? s + 1 : p;
}

/* Read the existing archive's EOCD + raw central directory for append. Refuses a
 * ZIP64 archive (append-in-place would need 64-bit CD rewrite). Returns 0 with a
 * malloc'd *seed_cd (caller frees), or -1 on error. */
static int
zip_read_seed(xrdc_zip_pread_fn pr, void *ctx, uint64_t size, uint64_t *base,
              uint8_t **seed_cd, size_t *seed_len, size_t *seed_n, xrdc_status *st)
{
    uint64_t cd_off, cd_size, n;
    int      z64;
    uint8_t *buf;

    if (xrdc_zip_read_eocd(pr, ctx, size, &cd_off, &cd_size, &n, &z64)
        != XRDC_ZIP_OK)
    {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "--zip-append: destination is not a valid ZIP archive");
        return -1;
    }
    if (z64) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "--zip-append: ZIP64 archives are not supported for append");
        return -1;
    }
    buf = malloc(cd_size ? (size_t) cd_size : 1);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    if (pr(ctx, cd_off, buf, (size_t) cd_size) != (ssize_t) cd_size) {
        free(buf);
        xrdc_status_set(st, XRDC_ESOCK, 0, "--zip-append: cannot read central directory");
        return -1;
    }
    *base = cd_off;
    *seed_cd = buf;
    *seed_len = (size_t) cd_size;
    *seed_n = (size_t) n;
    return 0;
}

/* Drive a writer (already created) to add the source member then finish. */
static int
zip_emit_member(xrdc_zip_writer *w, const char *member, int srcfd, xrdc_status *st)
{
    if (w == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory (zip writer)");
        return -1;
    }
    if (xrdc_zip_writer_add_fd(w, member, srcfd) != XRDC_ZIP_OK
        || xrdc_zip_writer_finish(w) != XRDC_ZIP_OK)
    {
        xrdc_status_set(st, XRDC_ESOCK, 0, "zip write failed");
        return -1;
    }
    return 0;
}

static int
copy_zip_store_local(const char *member, int srcfd, const xrdc_url *du,
                     int append, xrdc_status *st)
{
    int             flags = append ? (O_RDWR | O_CREAT) : (O_WRONLY | O_CREAT | O_TRUNC);
    int             dfd = open(du->path, flags, 0644);
    uint64_t        base = 0;
    uint8_t        *seed = NULL;
    size_t          seed_len = 0, seed_n = 0;
    zipw_local_sink sink;
    xrdc_zip_writer *w;
    int             rc;

    if (dfd < 0) {
        xrdc_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
                        du->path, strerror(errno));
        return -1;
    }
    if (append) {
        struct stat sb;
        if (fstat(dfd, &sb) == 0 && sb.st_size > 0) {
            if (zip_read_seed(zipw_local_pread, &dfd, (uint64_t) sb.st_size,
                              &base, &seed, &seed_len, &seed_n, st) != 0) {
                close(dfd);
                return -1;
            }
        }
    }
    sink.fd = dfd;
    sink.off = base;
    w = seed ? xrdc_zip_writer_new_append(zipw_local_write, &sink, base,
                                          seed, seed_len, seed_n)
             : xrdc_zip_writer_new(zipw_local_write, &sink);
    rc = zip_emit_member(w, member, srcfd, st);
    xrdc_zip_writer_free(w);
    free(seed);
    /* Append always grows the archive (new member + larger CD), and create uses
     * O_TRUNC, so the written length is authoritative — no tail to trim. */
    close(dfd);
    return rc;
}

static int
copy_zip_store_remote(const char *member, int srcfd, const xrdc_url *du,
                      int append, const xrdc_opts *co, xrdc_status *st)
{
    xrdc_conn         c;
    xrdc_file         f;
    xrdc_statinfo     si;
    uint64_t          base = 0;
    uint8_t          *seed = NULL;
    size_t            seed_len = 0, seed_n = 0;
    int               existed = 0, rc;
    zipw_remote_sink  sink;
    xrdc_zip_writer  *w;

    if (xrdc_connect(&c, du, co, st) != 0) {
        return -1;
    }
    if (append && xrdc_stat(&c, du->path, &si, st) == 0 && si.size > 0) {
        existed = 1;
    }
    if (existed) {
        if (xrdc_file_open_update(&c, du->path, 0, &f, st) != 0) {
            xrdc_close(&c);
            return -1;
        }
        zip_remote_ctx zc = { &c, &f, st };
        if (zip_read_seed(zip_remote_pread, &zc, (uint64_t) si.size,
                          &base, &seed, &seed_len, &seed_n, st) != 0) {
            xrdc_file_close(&c, &f, st);
            xrdc_close(&c);
            return -1;
        }
    } else if (xrdc_file_open_write(&c, du->path, 1 /*truncate*/, 0, &f, st) != 0) {
        xrdc_close(&c);
        return -1;
    }

    sink.c = &c;
    sink.f = &f;
    sink.off = base;
    sink.st = st;
    w = seed ? xrdc_zip_writer_new_append(zipw_remote_write, &sink, base,
                                          seed, seed_len, seed_n)
             : xrdc_zip_writer_new(zipw_remote_write, &sink);
    rc = zip_emit_member(w, member, srcfd, st);
    xrdc_zip_writer_free(w);
    free(seed);

    {
        xrdc_status tw;
        xrdc_status_clear(&tw);
        if (xrdc_file_close(&c, &f, rc == 0 ? st : &tw) != 0 && rc == 0) {
            rc = -1;
        }
    }
    xrdc_close(&c);
    return rc;
}

/* xrdcp --zip / --zip-append: store the local source as a STORE member of the
 * destination ZIP archive (create, or append to an existing non-ZIP64 archive). */
static int
copy_zip_store(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o,
               const xrdc_opts *co, xrdc_status *st)
{
    const char *member;
    int         srcfd, append, dst_remote, rc;

    if (su->scheme == XRDC_SCHEME_STDIO) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "--zip requires a regular-file source");
        return -1;
    }
    member = zip_member_basename(su->path);
    srcfd = open(su->path, O_RDONLY);
    if (srcfd < 0) {
        xrdc_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
                        su->path, strerror(errno));
        return -1;
    }
    append = (o != NULL && o->zip_append);
    dst_remote = (du->scheme == XRDC_SCHEME_ROOT || du->scheme == XRDC_SCHEME_ROOTS);

    rc = dst_remote
       ? copy_zip_store_remote(member, srcfd, du, append, co, st)
       : copy_zip_store_local(member, srcfd, du, append, st);

    close(srcfd);
    return rc;
}

int
xrdc_copy(const char *src, const char *dst, const xrdc_copy_opts *o,
          const xrdc_opts *co_in, xrdc_status *st)
{
    xrdc_url su, du;
    int      src_remote, dst_remote, src_local, dst_local;

    /* copy.c manages its OWN reconnect/retry — resilient_setup() for the multi-RTT
     * bring-up and the read pump (pump_src_remote) for mid-transfer severs. Disable
     * the library's op-level baked resilience on the connections this path owns, so
     * stat/dirlist/mkdir don't double-retry inside copy's already-bounded loops. */
    xrdc_opts co_local;
    if (co_in != NULL) {
        co_local = *co_in;
    } else {
        memset(&co_local, 0, sizeof(co_local));
        co_local.verify_host = 1;
    }
    co_local.no_retry = 1;
    const xrdc_opts *co = &co_local;

    /* Web schemes (davs/http(s)/s3) take the HTTP transfer path, never the root://
     * session machinery. Check before xrdc_url_parse (which is root-only). */
    if (xrdc_is_web_url(src) || xrdc_is_web_url(dst)) {
        return copy_web(src, dst, o, co, st);
    }

    if (xrdc_url_parse(src, &su, st) != 0) {
        return -1;
    }
    if (xrdc_url_parse(dst, &du, st) != 0) {
        return -1;
    }

    src_remote = (su.scheme == XRDC_SCHEME_ROOT || su.scheme == XRDC_SCHEME_ROOTS);
    dst_remote = (du.scheme == XRDC_SCHEME_ROOT || du.scheme == XRDC_SCHEME_ROOTS);
    src_local  = (su.scheme == XRDC_SCHEME_LOCAL || su.scheme == XRDC_SCHEME_STDIO);
    dst_local  = (du.scheme == XRDC_SCHEME_LOCAL || du.scheme == XRDC_SCHEME_STDIO);

    if (o != NULL && o->recursive) {
        if (src_remote && dst_local) {
            return copy_recursive(&su, &du, 1, o, co, st);   /* remote tree → local */
        }
        if (src_local && dst_remote) {
            return copy_recursive(&su, &du, 0, o, co, st);   /* local tree → remote */
        }
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "recursive copy requires one remote and one local endpoint");
        return -1;
    }

    /* phase-42 W3 write: --zip / --zip-append stores a LOCAL source as a STORE
     * member of the destination ZIP archive (local or remote dst). */
    if (o != NULL && (o->zip || o->zip_append)) {
        if (!src_local) {
            xrdc_status_set(st, XRDC_EUSAGE, 0,
                            "--zip requires a local-file source");
            return -1;
        }
        return copy_zip_store(&su, &du, o, co, st);
    }

    if (src_remote && dst_local) {
        char member[XRDC_PATH_MAX], arch[XRDC_PATH_MAX];
        if (unzip_member_from_src(src, &su, member, sizeof(member),
                                  arch, sizeof(arch))) {
            return copy_unzip(&su, arch, member, &du, o, co, st);  /* ?xrdcl.unzip= */
        }
        return copy_download(&su, &du, o, co, st);   /* remote → local */
    }
    if (src_local && dst_remote) {
        return copy_upload(&su, &du, o, co, st);      /* local → remote */
    }
    if (src_remote && dst_remote) {
        if (o->tpc_mode == XRDC_TPC_ONLY) {
            return copy_tpc(&su, &du, o, co, st);            /* TPC or hard fail */
        }
        if (o->tpc_mode == XRDC_TPC_FIRST
            || o->tpc_mode == XRDC_TPC_DELEGATE) {
            if (copy_tpc(&su, &du, o, co, st) == 0) {
                return 0;
            }
            if (!o->silent) {
                fprintf(stderr, "xrdcp: TPC failed (%s); falling back to "
                        "client-mediated copy\n", st->msg);
            }
            return copy_remote_to_remote(&su, &du, o, co, st);
        }
        return copy_remote_to_remote(&su, &du, o, co, st);   /* default: client-mediated */
    }

    xrdc_status_set(st, XRDC_EUSAGE, 0,
                    "unsupported copy direction (local→local not supported)");
    return -1;
}
