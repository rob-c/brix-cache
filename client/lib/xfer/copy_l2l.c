/*
 * copy_l2l.c — local→local copy (§7.17: file:// / bare-path both sides).
 *
 * WHAT: brix_copy_local_to_local() moves bytes between two LOCAL endpoints —
 *       a file (or file:// URL) or the '-' stdio stream on either side.
 * WHY:  Stock xrdcp copies local→local; BriX rejected the direction outright
 *       ("local→local not supported"), so `xrdcp file:///a file:///b`, a
 *       plain `xrdcp /a /b`, and the `cat | xrdcp - out` / `xrdcp in -`
 *       stdio idioms all failed. file:// already parses to the local scheme
 *       (net/url.c); the only missing piece was the copy direction itself.
 * HOW:  Reuse the transfer pump. A file source opens through the VFS
 *       (size known → bounded pump); stdin is an EOF-driven fd read. A file
 *       destination opens through the VFS (atomic temp+rename on commit,
 *       --force honored); stdout is a raw fd write with no commit. --xrate
 *       pacing rides the shared pump; --cksum runs post-commit against the
 *       committed file (literal/print modes — :source is meaningless with no
 *       server and is reported skipped). A mismatch drops the destination,
 *       matching every other download path.
 */
#include "copy_internal.h"

#include <fcntl.h>
#include <unistd.h>

/* ---- Sequential fd source/sink for the stdio ('-') endpoints ---- */
typedef struct { int fd; } l2l_fd_io;

static ssize_t
l2l_src_fd(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st)
{
    l2l_fd_io *s = ctx;
    ssize_t    n;

    (void) off;   /* stdin is a stream: sequential, offset ignored */
    do {
        n = read(s->fd, buf, cap);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        brix_status_set(st, XRDC_ESOCK, errno, "read stdin: %s",
                        strerror(errno));
    }
    return n;
}

static int
l2l_sink_fd(void *ctx, const uint8_t *buf, int64_t off, size_t n,
            brix_status *st)
{
    l2l_fd_io *s = ctx;
    size_t     done = 0;

    (void) off;   /* stdout is a stream: sequential, offset ignored */
    while (done < n) {
        ssize_t w = write(s->fd, buf + done, n - done);

        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            brix_status_set(st, XRDC_ESOCK, errno, "write stdout: %s",
                            strerror(errno));
            return -1;
        }
        done += (size_t) w;
    }
    return 0;
}

/* ---- Open the local source: stdin fd or a VFS file handle ----
 *
 * WHAT: Populates the pump src function + ctx and *expected (byte count, or
 *       -1 for the EOF-driven stdin stream). Returns 0 / -1 (st set).
 *
 * WHY: The two source shapes differ only in "how many bytes and by what
 *      reader" — isolating the open keeps the orchestrator flat.
 *
 * HOW: STDIO → fd 0, expected -1. A file → brix_vfs_open READ + fstat for the
 *      size so the pump terminates on the byte count (not an EOF probe).
 */
static int
l2l_open_src(const brix_url *su, brix_vfs_file **vf_out, l2l_fd_io *fdio,
             pump_src_fn *src, void **sctx, int64_t *expected, brix_status *st)
{
    if (su->scheme == XRDC_SCHEME_STDIO) {
        fdio->fd  = STDIN_FILENO;
        *src      = l2l_src_fd;
        *sctx     = fdio;
        *expected = -1;
        return 0;
    }
    {
        brix_vfs_open_opts opts = {0};
        brix_vfs_stat      vst;

        if (brix_vfs_open(su->path, XRDC_VFS_READ, &opts, vf_out, st) != 0) {
            return -1;
        }
        if (brix_vfs_fstat(*vf_out, &vst, st) != 0) {
            brix_vfs_close(*vf_out);
            *vf_out = NULL;
            return -1;
        }
        *expected = vst.size;
        return 0;
    }
}

/* ---- Run one local→local transfer end to end ----
 *
 * WHAT: Returns 0 on a byte-complete copy (committed, and --cksum-verified
 *       when asked), -1 (st set) otherwise. Handles every local/stdio pair.
 *
 * WHY: §7.17 — the missing copy direction. Kept a peer of the download/upload
 *      routers rather than folded into brix_copy_route so each direction is
 *      one function.
 *
 * HOW: 1. Open src (stdin | VFS). 2. Open dst (stdout | VFS temp, --force).
 *      3. transfer_pump with the chosen src/sink (pacing + cancel inside).
 *      4. File dst: commit on success, then --cksum against the committed
 *         file (drop on a genuine mismatch); abort the temp on any failure.
 */
int
brix_copy_local_to_local(const brix_url *su, const brix_url *du,
                         const brix_copy_opts *o, brix_status *st)
{
    brix_vfs_file *src_vf = NULL, *dst_vf = NULL;
    l2l_fd_io      src_fd = {0}, dst_fd = {0};
    pump_local_t   src_lc, dst_lc;
    pump_src_fn    src_fn = NULL;
    pump_sink_fn   sink_fn = NULL;
    void          *sctx = NULL, *kctx = NULL;
    int64_t        expected = -1;
    int            dst_stdout = (du->scheme == XRDC_SCHEME_STDIO);
    int            rc, committed = 0;

    /* Friendly destination-exists refusal (matches the download path's
     * message) BEFORE opening the source, so the user sees "-f", not the
     * VFS layer's internal flag name. stdout and --force skip it. */
    if (!dst_stdout && !o->force && access(du->path, F_OK) == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "destination exists (use -f to overwrite): %s",
                        du->path);
        return -1;
    }

    if (l2l_open_src(su, &src_vf, &src_fd, &src_fn, &sctx, &expected,
                     st) != 0) {
        return -1;
    }
    if (src_vf != NULL) {
        src_lc.vf = src_vf;
        src_fn = pump_src_local_vfs;
        sctx = &src_lc;
    }

    if (dst_stdout) {
        dst_fd.fd = STDOUT_FILENO;
        sink_fn = l2l_sink_fd;
        kctx = &dst_fd;
    } else {
        brix_vfs_open_opts vopts = {0};

        vopts.expected_size = expected;
        if (brix_vfs_open(du->path,
                          XRDC_VFS_WRITE | (o->force ? XRDC_VFS_FORCE : 0),
                          &vopts, &dst_vf, st) != 0) {
            if (src_vf != NULL) {
                brix_vfs_close(src_vf);
            }
            return -1;
        }
        dst_lc.vf = dst_vf;
        sink_fn = pump_sink_local_vfs;
        kctx = &dst_lc;
    }

    rc = transfer_pump(src_fn, sctx, sink_fn, kctx, expected, o,
                       expected, st);

    if (rc == 0 && dst_vf != NULL) {
        rc = brix_vfs_commit(dst_vf, st);
        if (rc == 0) {
            committed = 1;
            if (o->cksum != NULL
                && cksum_verify(NULL, NULL, du->path, o->cksum, o->silent, st)
                   == XRDC_CK_MISMATCH) {
                unlink(du->path);   /* committed-but-bad: drop it */
                rc = -1;
            }
        }
    }
    if (rc != 0 && dst_vf != NULL && !committed) {
        brix_vfs_abort(dst_vf);
    }
    if (dst_vf != NULL) {
        brix_vfs_close(dst_vf);
    }
    if (src_vf != NULL) {
        brix_vfs_close(src_vf);
    }
    return rc;
}
