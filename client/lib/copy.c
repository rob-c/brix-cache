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
#include "cred.h"                 /* xrdc_cred_acquire/available for web auth store path */
#include "vfs.h"                  /* xrdc_vfs — pluggable local storage backend */

/*
 * POSIX backend link anchor — prevents the static linker from omitting
 * vfs_posix.o when xrdcp / other tools link against libxrdc.a.
 *
 * WHY:  vfs.c declares xrdc_vfs_posix_backend __attribute__((weak)) so the
 *       library compiles before the backends land.  A weak undefined reference
 *       is NOT sufficient to pull an object file from a static archive; only a
 *       STRONG (non-weak) undefined reference triggers the scan.  By declaring
 *       xrdc_vfs_posix_backend here without the weak attribute, copy.o carries
 *       a strong U entry that forces the linker to include vfs_posix.o from
 *       libxrdc.a whenever copy.o is linked — no Makefile changes needed.
 * HOW:  declare the function (non-weak extern) and store its address in a
 *       const, __attribute__((used)) variable so neither the compiler nor the
 *       linker's dead-code pass removes the reference before the archive scan.
 */
extern const xrdc_vfs_backend *xrdc_vfs_posix_backend(void);
__attribute__((used))
static const xrdc_vfs_backend *(*const s_vfs_posix_anchor)(void) =
    xrdc_vfs_posix_backend;

/*
 * Block backend link anchor — mirrors the POSIX anchor above.
 * WHY:  vfs.c declares xrdc_vfs_block_backend __attribute__((weak)); a weak
 *       symbol does NOT pull vfs_block.o from libxrdc.a.  Declaring it here
 *       as a plain extern (strong U) forces the linker to include vfs_block.o
 *       whenever copy.o is linked, so copy_block / copy_vfs_to_vfs work.
 */
extern const xrdc_vfs_backend *xrdc_vfs_block_backend(void);
__attribute__((used))
static const xrdc_vfs_backend *(*const s_vfs_block_anchor)(void) =
    xrdc_vfs_block_backend;

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
static int
open_download_temp(const char *dst, char *tmp, size_t tmpsz, xrdc_status *st)
{
    int attempt;

    for (attempt = 0; attempt < 64; attempt++) {
        int fd;
        if (make_temp_path(dst, tmp, tmpsz) != 0) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "destination path too long: %s", dst);
            return -1;
        }
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
        if (fd >= 0) {
            return fd;
        }
        if (errno != EEXIST) {
            xrdc_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
                            tmp, strerror(errno));
            return -1;
        }
    }
    xrdc_status_set(st, XRDC_EUSAGE, EEXIST,
                    "could not create a unique temp for %s", dst);
    return -1;
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

/* Effective resilience (max-stall) window in ms for a copy, honouring the
 * fail-fast knob: `no_retry` (set by --no-retry / --retry 0 / --max-stall 0)
 * yields 0 — every bounded copy loop then has a zero-length deadline and fails
 * on the first transport fault instead of spinning the default window against a
 * dead endpoint. Otherwise an explicit positive max_stall_ms wins, else `dflt`.
 * Centralises the choice the bounded loops below all make so `no_retry` can
 * never again be silently dropped (the raw `max_stall_ms > 0 ? : DEFAULT`
 * ternary could not distinguish "fail fast" from "use the default"). */
static int
copy_stall_ms(const xrdc_copy_opts *o, int dflt)
{
    if (o != NULL && o->no_retry) {
        return 0;
    }
    if (o != NULL && o->max_stall_ms > 0) {
        return o->max_stall_ms;
    }
    return dflt;
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

/* ---- VFS-backed local pump context and adapters ---------------------------
 *
 * pump_local_t holds the VFS handle for a local file endpoint.  The VFS layer
 * (vfs_posix.c) owns the fd, optional io_uring ring, and temp+rename commit
 * internally — copy.c just calls xrdc_vfs_pread / xrdc_vfs_pwrite through it.
 * Ring selection (AUTO/ON/OFF from opts.io_uring) happens inside vfs_posix.c's
 * open, eliminating the old local_ring_select helper from this file. */

typedef struct {
    xrdc_vfs_file *vf;
} pump_local_t;

static ssize_t
pump_src_local_vfs(void *ctx, uint8_t *buf, int64_t off, size_t cap,
                   xrdc_status *st)
{
    pump_local_t *lc = ctx;
    return xrdc_vfs_pread(lc->vf, off, buf, cap, st);
}

static int
pump_sink_local_vfs(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                    xrdc_status *st)
{
    pump_local_t *lc = ctx;
    return xrdc_vfs_pwrite(lc->vf, off, buf, n, st);
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
 *       before tearing down.
 */
static int
download_stream_body(xrdc_conn *c, const xrdc_url *su, const xrdc_statinfo *si,
                     pump_sink_fn sink, void *sinkctx,
                     const xrdc_copy_opts *o, xrdc_streamset *ss,
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
        int      stall = copy_stall_ms(o, 60000);
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

    /* remote (known si->size) → caller-supplied sink, with progress.  Resilient:
     * a sever mid-read reconnects + reopens at offset and adapts the request size,
     * so a one-shot download rides out a flaky/lossy link. */
    src.c = c;
    src.f = &f;
    src.pgrw = o->pgrw;
    src.resilient = 1;
    src.path = su->path;
    src.opaque = opaque;
    src.max_stall_ms = copy_stall_ms(o, 60000);
    src.cur_chunk = XRDC_COPY_CHUNK;
    rc = transfer_pump(pump_src_remote, &src, sink, sinkctx,
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
    xrdc_conn     c;
    xrdc_statinfo si;
    xrdc_streamset ss;
    int            to_stdout = (du->scheme == XRDC_SCHEME_STDIO);
    int            stall = copy_stall_ms(o, 60000);
    int            rc;

    ss.n = 0;   /* so the streams teardown is a no-op if we never bind */
    if (resilient_setup(&c, su, co, &si, stall, st) != 0) {
        return -1;
    }
    if (si.flags & kXR_isDir) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "source is a directory (use -r, M5)");
        xrdc_close(&c);
        return -1;
    }

    if (to_stdout) {
        /* stdio path: pump directly to STDOUT_FILENO — no temp, no VFS, no commit */
        int stdoutfd = STDOUT_FILENO;
        rc = download_stream_body(&c, su, &si, pump_sink_local, &stdoutfd,
                                  o, &ss, st);
        if (rc == 0 && o->cksum != NULL) {
            /* stdout has no on-disk file; cksum_verify skips gracefully on NULL */
            int ck = cksum_verify(&c, su->path, NULL, o->cksum, o->silent, st);
            if (ck == XRDC_CK_MISMATCH) {
                rc = -1;
            } else if (ck == XRDC_CK_UNVERIFIED) {
                if (!o->silent) {
                    fprintf(stderr, "xrdcp: %s downloaded but checksum NOT verified: "
                                    "%s\n", du->path, st->msg);
                }
                xrdc_status_clear(st);
            }
        }
        xrdc_streams_close(&ss);
        xrdc_close(&c);
        return rc;
    }

    /* Local file path: existence-check preserving the original error message,
     * then open via VFS (atomic temp+rename and optional io_uring inside the backend).
     * commit() does fsync+rename; abort() unlinks the temp on any failure or
     * checksum mismatch so the final destination is never a partial/corrupt file. */
    if (!o->force && access(du->path, F_OK) == 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "destination exists (use -f to overwrite): %s",
                        du->path);
        xrdc_close(&c);
        return -1;
    }

    {
        xrdc_vfs_file     *vf = NULL;
        xrdc_vfs_open_opts vopts;
        pump_local_t       lc;
        int                committed = 0;

        vopts.io_uring      = o->io_uring;
        vopts.expected_size = si.size;
        vopts.cred          = NULL;

        if (xrdc_vfs_open(du->path,
                          XRDC_VFS_WRITE | (o->force ? XRDC_VFS_FORCE : 0),
                          &vopts, &vf, st) != 0) {
            xrdc_close(&c);
            return -1;
        }

        lc.vf = vf;
        rc = download_stream_body(&c, su, &si, pump_sink_local_vfs, &lc,
                                  o, &ss, st);

        /* Commit on success (fsync + rename temp→final); only then verify the
         * checksum against the committed file.  A genuine MISMATCH drops the
         * committed file and returns error — it is an integrity failure, not a
         * transient fault.  A query hiccup (UNVERIFIED) keeps the good bytes. */
        if (rc == 0) {
            rc = xrdc_vfs_commit(vf, st);
            if (rc == 0) {
                committed = 1;
                if (o->cksum != NULL) {
                    int ck = cksum_verify(&c, su->path, du->path,
                                         o->cksum, o->silent, st);
                    if (ck == XRDC_CK_MISMATCH) {
                        unlink(du->path);   /* drop committed-but-bad file */
                        rc = -1;
                    } else if (ck == XRDC_CK_UNVERIFIED) {
                        if (!o->silent) {
                            fprintf(stderr, "xrdcp: %s downloaded but checksum "
                                            "NOT verified: %s\n",
                                    du->path, st->msg);
                        }
                        xrdc_status_clear(st);
                    }
                }
            }
        }
        if (rc != 0 && !committed) {
            xrdc_vfs_abort(vf);   /* discard the partial temp */
        }
        xrdc_vfs_close(vf);
    }

    xrdc_streams_close(&ss);
    xrdc_close(&c);
    return rc;
}

/*
 * WHAT: Connect the destination, open it for write, stream bytes from the
 *       caller-supplied (src, srcctx) into it, then tear the whole remote side
 *       down (file close on success, checksum, bound streams, connection) — the
 *       entire "destination session is up" lifetime.
 * WHY:  Confining the connection / write handle / secondary streams to one helper
 *       keeps copy_upload() a flat early-return sequence whose only lingering
 *       resource is the caller-owned VFS handle.  Both pre-open failure paths
 *       (connect, open_write) return early without entering the finish teardown.
 * HOW:  connect → open_write → streams_open → transfer_pump(src→remote) → finish.
 *       `total` is the known source size for progress and resilient-close checks
 *       (-1 for stdin / unknown).  src is either pump_src_local (stdin) or
 *       pump_src_local_vfs (local file via xrdc_vfs).  su->path is used as the
 *       local checksum source path (NULL ≡ stdin → cksum_verify skips gracefully).
 */
static int
upload_stream_body(const xrdc_url *su, const xrdc_url *du,
                   const xrdc_copy_opts *o, const xrdc_opts *co,
                   pump_src_fn src, void *srcctx, int64_t total,
                   xrdc_status *st)
{
    xrdc_conn      c;
    xrdc_file      f;
    xrdc_streamset ss;
    pump_remote_t  sink = {0};
    int            rc;

    ss.n = 0;
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
        int      stall = copy_stall_ms(o, 60000);
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

    /* local src → remote (EOF-driven), with progress (total = file size or -1).
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
    sink.max_stall_ms = copy_stall_ms(o, 60000);
    rc = transfer_pump(src, srcctx, pump_sink_remote, &sink, -1, o, total, st);

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
     * still open), comparing our local source digest against the server's.
     * For stdin (XRDC_SCHEME_STDIO) there is no on-disk file; pass NULL so
     * cksum_verify skips gracefully instead of trying to open the path. */
    if (rc == 0 && o->cksum != NULL) {
        const char *ck_local = (su->scheme == XRDC_SCHEME_STDIO) ? NULL : su->path;
        int ck = cksum_verify(&c, du->path, ck_local,
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
    if (su->scheme == XRDC_SCHEME_STDIO) {
        /* stdio path: pump from raw STDIN_FILENO; no VFS open */
        int stdinfd = STDIN_FILENO;
        return upload_stream_body(su, du, o, co, pump_src_local, &stdinfd,
                                  -1 /* size unknown */, st);
    }

    /* Local file path: open via VFS (io_uring selection inside the backend) */
    {
        xrdc_vfs_file     *vf = NULL;
        xrdc_vfs_open_opts vopts;
        xrdc_vfs_stat      vst;
        xrdc_status        tmp_st;
        pump_local_t       lc;
        int64_t            total = -1;
        int                rc;

        vopts.io_uring      = o->io_uring;
        vopts.expected_size = -1;   /* read-only open; hint unused */
        vopts.cred          = NULL;

        if (xrdc_vfs_open(su->path, XRDC_VFS_READ, &vopts, &vf, st) != 0) {
            return -1;
        }
        xrdc_status_clear(&tmp_st);
        if (xrdc_vfs_fstat(vf, &vst, &tmp_st) == 0) {
            total = vst.size;
        }

        lc.vf = vf;
        rc = upload_stream_body(su, du, o, co, pump_src_local_vfs, &lc,
                                total, st);
        xrdc_vfs_close(vf);
        return rc;
    }
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
    xrdc_file         f;
    xrdc_vfs_file    *vf = NULL;
    xrdc_vfs_open_opts vopts;
    pump_local_t       lc;
    pump_remote_t      src = {0};
    int                rc;

    if (xrdc_file_open_read(c, rpath, &f, st) != 0) {
        return -1;
    }

    /* Atomic temp+rename + signal-abort via VFS, mirroring copy_download — so a
     * failed or interrupted recursive transfer leaves no partial/truncated tree
     * entry.  FORCE is always set: recursive copies overwrite existing files. */
    vopts.io_uring      = XRDC_IO_URING_AUTO;
    vopts.expected_size = expected_size;
    vopts.cred          = NULL;
    if (xrdc_vfs_open(lpath, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                      &vopts, &vf, st) != 0) {
        xrdc_file_close(c, &f, st);
        return -1;
    }

    /* remote → local VFS (plain read, recursive path; not paged). */
    src.c    = c;
    src.f    = &f;
    src.pgrw = 0;
    lc.vf    = vf;
    rc = transfer_pump(pump_src_remote, &src, pump_sink_local_vfs, &lc,
                       expected_size, NULL, expected_size, st);

    if (rc == 0) {
        rc = xrdc_vfs_commit(vf, st);
    } else {
        xrdc_vfs_abort(vf);
    }
    xrdc_vfs_close(vf);
    xrdc_file_close(c, &f, st);
    return rc;
}

/* Copy one local file to a fresh remote file (open under conn c). */
static int
copy_one_l2r(xrdc_conn *c, const char *lpath, const char *rpath,
             const xrdc_copy_opts *o, xrdc_status *st)
{
    xrdc_file         f;
    xrdc_vfs_file    *vf = NULL;
    xrdc_vfs_open_opts vopts;
    pump_local_t       lc;
    pump_remote_t      sink = {0};
    int                rc;

    vopts.io_uring      = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;
    vopts.expected_size = -1;
    vopts.cred          = NULL;
    if (xrdc_vfs_open(lpath, XRDC_VFS_READ, &vopts, &vf, st) != 0) {
        return -1;
    }
    if (xrdc_file_open_write(c, rpath, 1 /*force*/, o ? o->posc : 0, &f, st) != 0) {
        xrdc_vfs_close(vf);
        return -1;
    }

    /* local VFS (EOF-driven) → remote, plain write (recursive path). On failure
     * the file is still closed (preserving the historical recursive teardown,
     * which never relied on POSC-discard the way single-file upload does). */
    sink.c    = c;
    sink.f    = &f;
    sink.pgrw = 0;
    lc.vf     = vf;
    rc = transfer_pump(pump_src_local_vfs, &lc, pump_sink_remote, &sink,
                       -1, NULL, 0, st);

    xrdc_vfs_close(vf);
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
            /* For a symlink (kXR_other) the dirlist size is the lstat size — the
             * LENGTH OF THE LINK TARGET PATH, not the bytes the server serves
             * when it follows the link on open.  Trusting it truncates the copy
             * (a link to a 10-byte file named "two.txt" would copy 7 bytes), so
             * read to EOF (expected = -1) for those; regular files keep their
             * real size, whose short-read guard still catches truncation. */
            int64_t expected = (ents[i].have_stat
                                && !(ents[i].st.flags & kXR_other))
                               ? ents[i].st.size : -1;
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

/* Build the recursive copy's destination root: the source tree's basename
 * appended to the destination directory.  This matches stock `xrdcp -r`, which
 * NESTS the copied tree under the source's last path component (`xrdcp -r <dir>
 * <dst>` populates `<dst>/<basename(dir)>/...`).  Copying the children straight
 * into <dst> instead would FLATTEN — silently merging two differently-named
 * source trees and diverging from every other xrootd client.
 *
 * A degenerate basename ('.', '/', or empty — e.g. the whole-export `//.` form)
 * has no meaningful name to nest under, so the destination is used verbatim.
 * Returns 0 on success, -1 if the composed path would overflow `out`. */
static int
recursive_dest_root(const char *dstdir, const char *srcpath,
                    char *out, size_t outsz)
{
    size_t      len = strlen(srcpath);
    const char *base;
    size_t      blen, dl, i;
    const char *sep;

    while (len > 1 && srcpath[len - 1] == '/') { len--; }   /* ignore trailing / */
    base = srcpath;
    for (i = len; i > 0; i--) {
        if (srcpath[i - 1] == '/') { base = srcpath + i; break; }
    }
    blen = (size_t) (srcpath + len - base);

    if (blen == 0 || (blen == 1 && base[0] == '.')) {       /* nothing to nest */
        return ((size_t) snprintf(out, outsz, "%s", dstdir) >= outsz) ? -1 : 0;
    }
    dl  = strlen(dstdir);
    sep = (dl > 0 && dstdir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, outsz, "%s%s%.*s", dstdir, sep,
                              (int) blen, base) >= outsz) ? -1 : 0;
}

/* Recursive copy entry: connect once, walk the source tree. Direction-aware. */
static int
copy_recursive(const xrdc_url *su, const xrdc_url *du, int download,
               const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st)
{
    xrdc_conn c;
    int       rc;
    char      destroot[XRDC_PATH_MAX];

    /* Nest under the source basename (stock parity); see recursive_dest_root. */
    if (recursive_dest_root(du->path, su->path, destroot, sizeof(destroot)) != 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "recursive copy: destination path too long");
        return -1;
    }

    if (download) {
        if (xrdc_connect(&c, su, co, st) != 0) { return -1; }
        rc = copy_tree_download(&c, su->path, destroot, o, st);
    } else {
        if (xrdc_connect(&c, du, co, st) != 0) { return -1; }
        rc = copy_tree_upload(&c, su->path, destroot, o, st);
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
 * header we send); WebDAV/HTTP → Authorization: Bearer if a token is available.
 *
 * co carries the credential store (co->cred); when set the store is tried first
 * for both the bearer token and S3 keys, falling back to opts/env on failure so
 * env-sourced credentials behave identically to today. */
static int
web_auth_headers(const xrdc_weburl *u, const char *method,
                 const xrdc_copy_opts *o, const xrdc_opts *co,
                 char *hdrs, size_t hdrsz, xrdc_status *st)
{
    hdrs[0] = '\0';
    if (u->is_s3) {
        const char *ak = (o && o->s3_access) ? o->s3_access : NULL;
        const char *sk = (o && o->s3_secret) ? o->s3_secret : NULL;
        const char *rg = (o && o->s3_region) ? o->s3_region : getenv("AWS_DEFAULT_REGION");
        xrdc_cred_view sv;
        char host[300], payhash[65];

        /* Prefer the cred store for S3 keys when no explicit opts override. */
        if ((ak == NULL || sk == NULL) && co != NULL && co->cred != NULL) {
            if (xrdc_cred_acquire(co->cred, XRDC_CRED_S3KEYS, 0, &sv, st) == 0) {
                if (ak == NULL) { ak = sv.s3_access; }
                if (sk == NULL) { sk = sv.s3_secret; }
            } else {
                xrdc_status_clear(st);
            }
        }
        /* Fall through to env when store not set or acquire failed. */
        if (ak == NULL) { ak = getenv("AWS_ACCESS_KEY_ID"); }
        if (sk == NULL) { sk = getenv("AWS_SECRET_ACCESS_KEY"); }

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
        const char *tok = (o && o->bearer) ? o->bearer : NULL;
        xrdc_cred_view bv;

        /* Prefer the cred store for the bearer token when no explicit opt override. */
        if (tok == NULL && co != NULL && co->cred != NULL) {
            if (xrdc_cred_acquire(co->cred, XRDC_CRED_BEARER, 0, &bv, st) == 0
                && bv.token != NULL) {
                tok = bv.token;
            } else {
                xrdc_status_clear(st);
            }
        }
        /* Fall through to env when store not set or acquire failed. */
        if (tok == NULL) { tok = getenv("BEARER_TOKEN"); }

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

    if (web_auth_headers(su, "GET", o, co, hdrs, sizeof(hdrs), st) != 0) {
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
    outfd = open_download_temp(du->path, tmp, sizeof(tmp), st);
    if (outfd < 0) {
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
    if (web_auth_headers(du, "PUT", o, co, hdrs, sizeof(hdrs), st) != 0) {
        close(infd);
        return -1;
    }
    {
        /* Resilient by default: Content-Range PUT chunks that reconnect + resume
         * from the server's durable offset, so the upload survives an nginx
         * restart (server xrootd_webdav_upload_resume).  A plain server commits on
         * the first whole-range chunk, so a single-shot upload still works. */
        int stall = copy_stall_ms(o, XRDC_DEFAULT_MAX_STALL_MS);
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
        outfd = open_download_temp(du->path, tmp, sizeof(tmp), st);
        if (outfd < 0) {
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

/* ---- block:// endpoint copy helpers --------------------------------------- */

/*
 * copy_remote_to_block — root:// → block:// single-file transfer.
 *
 * WHAT: connects to the remote XRootD source, opens the block:// destination
 *       directly through the VFS block backend (in-place write, no temp+rename),
 *       and streams all bytes via the existing download pump machinery.
 * WHY:  copy_download routes its destination through xrdc_url du->path (a stripped
 *       bare POSIX path), which selects the POSIX backend.  A block:// URL must be
 *       passed as-is so vfs_url_to_scheme routes it to the block backend instead.
 * HOW:  parse src → resilient_setup → xrdc_vfs_open(dst_url, WRITE|FORCE) →
 *       download_stream_body → commit (fsync) on success, abort (no-op) on failure.
 *       FORCE is always set: block/device targets pre-exist by design.
 */
static int
copy_remote_to_block(const char *src_url, const char *dst_url,
                     const xrdc_copy_opts *o, const xrdc_opts *co,
                     xrdc_status *st)
{
    xrdc_url            su;
    xrdc_conn           c;
    xrdc_statinfo       si;
    xrdc_streamset      ss;
    xrdc_vfs_file      *vf = NULL;
    xrdc_vfs_open_opts  vopts;
    pump_local_t        lc;
    int                 stall;
    int                 rc;

    if (xrdc_url_parse(src_url, &su, st) != 0) {
        return -1;
    }

    stall = copy_stall_ms(o, 60000);
    ss.n = 0;
    if (resilient_setup(&c, &su, co, &si, stall, st) != 0) {
        return -1;
    }
    if (si.flags & kXR_isDir) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "block copy: remote source is a directory (use -r)");
        xrdc_close(&c);
        return -1;
    }

    vopts.io_uring      = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;
    vopts.expected_size = si.size;
    vopts.cred          = NULL;

    if (xrdc_vfs_open(dst_url, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                      &vopts, &vf, st) != 0) {
        xrdc_close(&c);
        return -1;
    }

    lc.vf = vf;
    rc = download_stream_body(&c, &su, &si, pump_sink_local_vfs, &lc,
                              o, &ss, st);

    if (rc == 0) {
        rc = xrdc_vfs_commit(vf, st);
    } else {
        xrdc_vfs_abort(vf);
    }
    xrdc_vfs_close(vf);
    xrdc_streams_close(&ss);
    xrdc_close(&c);
    return rc;
}

/*
 * copy_block_to_remote — block:// → root:// single-file transfer.
 *
 * WHAT: opens the block:// source through the VFS block backend (READ) and
 *       uploads all bytes into the remote (root://) destination.
 * WHY:  copy_upload reads su->path as a bare path (POSIX backend).  A block://
 *       source URL must be passed to xrdc_vfs_open so vfs_url_to_scheme routes
 *       it to the block backend; the stripped path alone selects the POSIX backend.
 * HOW:  xrdc_vfs_open(src_url, READ) → fstat for size →
 *       parse dst URL → upload_stream_body(pump_src_local_vfs) → close.
 *       Checksum verification on block sources is best-effort: cksum_verify
 *       opens the file by POSIX path; for a pure block:// URL it returns
 *       XRDC_CK_UNVERIFIED (a non-fatal warn), keeping the good upload intact.
 */
static int
copy_block_to_remote(const char *src_url, const char *dst_url,
                     const xrdc_copy_opts *o, const xrdc_opts *co,
                     xrdc_status *st)
{
    xrdc_url            du;
    xrdc_url            fake_su;
    xrdc_vfs_file      *vf = NULL;
    xrdc_vfs_open_opts  vopts;
    xrdc_vfs_stat       vst;
    xrdc_status         tmp_st;
    pump_local_t        lc;
    int64_t             total = -1;
    int                 rc;

    if (xrdc_url_parse(dst_url, &du, st) != 0) {
        return -1;
    }

    vopts.io_uring      = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;
    vopts.expected_size = -1;
    vopts.cred          = NULL;

    if (xrdc_vfs_open(src_url, XRDC_VFS_READ, &vopts, &vf, st) != 0) {
        return -1;
    }

    xrdc_status_clear(&tmp_st);
    if (xrdc_vfs_fstat(vf, &vst, &tmp_st) == 0) {
        total = vst.size;
    }

    /* Synthesise a source descriptor for upload_stream_body diagnostics.
     * scheme=LOCAL tells it to use fake_su.path for optional cksum_verify;
     * for a block:// URL that open() cannot resolve, cksum_verify returns
     * XRDC_CK_UNVERIFIED (non-fatal warn) rather than a hard failure. */
    memset(&fake_su, 0, sizeof(fake_su));
    fake_su.scheme = XRDC_SCHEME_LOCAL;
    snprintf(fake_su.path, sizeof(fake_su.path), "%s", src_url);

    lc.vf = vf;
    rc = upload_stream_body(&fake_su, &du, o, co, pump_src_local_vfs, &lc,
                            total, st);
    xrdc_vfs_close(vf);
    return rc;
}

/*
 * copy_vfs_to_vfs — VFS-source → VFS-destination transfer (local↔block).
 *
 * WHAT: opens both src and dst through xrdc_vfs_open (which routes block://
 *       and /dev/ to the block backend; bare paths to the POSIX backend) and
 *       pumps bytes via transfer_pump.  Covers local→block://, block://→local,
 *       and block://→block:// directions.
 * WHY:  when neither side is a root:// remote the generic copy machinery
 *       (copy_download / copy_upload) is unnecessary; two VFS opens + a pump
 *       are enough.
 * HOW:  open src READ → fstat → open dst WRITE|FORCE → pump → commit dst →
 *       close both.  FORCE is always set on the destination: block targets
 *       pre-exist by design; POSIX destinations use atomic temp+rename whose
 *       overwrite semantics are controlled by the FORCE flag.
 */
static int
copy_vfs_to_vfs(const char *src_url, const char *dst_url,
                const xrdc_copy_opts *o, xrdc_status *st)
{
    xrdc_vfs_file      *src_vf = NULL;
    xrdc_vfs_file      *dst_vf = NULL;
    xrdc_vfs_open_opts  vopts;
    xrdc_vfs_stat       vst;
    xrdc_status         tmp_st;
    pump_local_t        src_lc, dst_lc;
    int64_t             total = -1;
    int                 rc;

    vopts.io_uring      = (o != NULL) ? o->io_uring : XRDC_IO_URING_AUTO;
    vopts.expected_size = -1;
    vopts.cred          = NULL;

    if (xrdc_vfs_open(src_url, XRDC_VFS_READ, &vopts, &src_vf, st) != 0) {
        return -1;
    }

    xrdc_status_clear(&tmp_st);
    if (xrdc_vfs_fstat(src_vf, &vst, &tmp_st) == 0) {
        total = vst.size;
    }

    vopts.expected_size = total;
    if (xrdc_vfs_open(dst_url, XRDC_VFS_WRITE | XRDC_VFS_FORCE,
                      &vopts, &dst_vf, st) != 0) {
        xrdc_vfs_close(src_vf);
        return -1;
    }

    src_lc.vf = src_vf;
    dst_lc.vf = dst_vf;
    rc = transfer_pump(pump_src_local_vfs, &src_lc,
                       pump_sink_local_vfs, &dst_lc,
                       total, o, total, st);

    if (rc == 0) {
        rc = xrdc_vfs_commit(dst_vf, st);
    } else {
        xrdc_vfs_abort(dst_vf);
    }
    xrdc_vfs_close(dst_vf);
    xrdc_vfs_close(src_vf);
    return rc;
}

/*
 * copy_block — dispatch for copies involving at least one block:// endpoint.
 *
 * WHAT: classifies the (src, dst) pair and routes to the right helper:
 *   root://→block://  → copy_remote_to_block
 *   block://→root://  → copy_block_to_remote
 *   local→block://    → copy_vfs_to_vfs  (POSIX src + block dst)
 *   block://→local    → copy_vfs_to_vfs  (block src + POSIX dst)
 *   block://→block:// → copy_vfs_to_vfs  (block src + block dst)
 * WHY:  xrdc_copy() intercepts block:// before xrdc_url_parse (which does not
 *       know the block:// scheme) and delegates here.
 * HOW:  classify src/dst by xrdc_is_block_url and xrdc_is_web_url; for the
 *       root:// directions use xrdc_url_parse to distinguish remote/local;
 *       recursion and zip are explicitly rejected (not supported for block).
 */
static int
copy_block(const char *src, const char *dst, const xrdc_copy_opts *o,
           const xrdc_opts *co, xrdc_status *st)
{
    int src_block  = xrdc_is_block_url(src);
    int dst_block  = xrdc_is_block_url(dst);
    int src_remote = 0;
    int dst_remote = 0;

    if (o != NULL && o->recursive) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "recursive copy not supported for block:// endpoints");
        return -1;
    }

    /* Classify non-block sides: parse with xrdc_url_parse to detect root://. */
    if (!src_block) {
        xrdc_url su;
        xrdc_status tmp;
        xrdc_status_clear(&tmp);
        if (xrdc_url_parse(src, &su, &tmp) == 0) {
            src_remote = (su.scheme == XRDC_SCHEME_ROOT
                          || su.scheme == XRDC_SCHEME_ROOTS);
        }
    }
    if (!dst_block) {
        xrdc_url du;
        xrdc_status tmp;
        xrdc_status_clear(&tmp);
        if (xrdc_url_parse(dst, &du, &tmp) == 0) {
            dst_remote = (du.scheme == XRDC_SCHEME_ROOT
                          || du.scheme == XRDC_SCHEME_ROOTS);
        }
    }

    if (src_remote && dst_block) {
        return copy_remote_to_block(src, dst, o, co, st);
    }
    if (src_block && dst_remote) {
        return copy_block_to_remote(src, dst, o, co, st);
    }
    if (!src_remote && !dst_remote) {
        /* both sides are local/block: pure VFS-to-VFS */
        return copy_vfs_to_vfs(src, dst, o, st);
    }

    xrdc_status_set(st, XRDC_EUSAGE, 0,
                    "unsupported block:// copy direction "
                    "(src=%s dst=%s)", src, dst);
    return -1;
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

    /* block:// (and /dev/) endpoints route through the VFS block backend.
     * xrdc_url_parse does not know the block:// scheme and would reject it,
     * so intercept here before the parse. */
    if (xrdc_is_block_url(src) || xrdc_is_block_url(dst)) {
        return copy_block(src, dst, o, co, st);
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
