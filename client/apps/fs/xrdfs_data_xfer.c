/*
 * xrdfs_data_xfer.c — xrdfs bulk-transfer + vector data ops (Phase-38 split).
 *
 * WHAT: the bulk/vector I/O busybox ops — upload and download (local<->remote,
 *       optionally io_uring-accelerated through the VFS), plus readv/writev
 *       (scatter/gather segment transfers).
 * WHY:  split from xrdfs_data.c to hold each TU within the Phase-38 size
 *       budget; these are the only data ops that touch the local VFS driver and
 *       the io_uring knob, so they form one cohesive concern. Every do_* entry
 *       point is declared in xrdfs_internal.h.
 * HOW:  named local endpoints are opened through brix_vfs_* (shared SD driver),
 *       so --io-uring reaches vfs_posix via vopts; stdin/stdout stay raw pipes.
 *       Each do_* parses operands into a file-local xfer bundle. No goto.
 */
#include "xrdfs_internal.h"
#include "brix_ops.h"              /* brix_cli_parse_io_uring */
#include "fs/vfs.h"   /* local endpoint I/O routes through the shared SD driver */

/* Shared upload/download operand set: the bs=/rate=/-f/--io-uring flags plus the
 * two positional operands (pos1/pos2 order is per-command: upload = local,remote;
 * download = remote,local). */
typedef struct {
    const char *pos1;           /* first positional (NULL if missing) */
    const char *pos2;           /* second positional (NULL if missing) */
    int64_t     bs;             /* block size in bytes */
    double      rate;           /* bytes/s throttle (0 = unlimited) */
    int         force;          /* -f overwrite */
    int         io_uring_mode;  /* --io-uring mode (XRDC_IO_URING_*) */
} xfer_args_t;

/* upload [bs=BYTES] [rate=BYTES/s] [-f] [--io-uring on|off|auto] <localfile|-> <remote>
 * WHAT: write a local file (or stdin "-") to a remote path, optionally rate-limited.
 * WHY:  named local sources are opened through the VFS (shared SD driver), so --io-uring
 *       controls the kernel io_uring read path for the local source file; stdin is a raw
 *       pipe and does not benefit from io_uring (the flag is accepted but silently ignored
 *       for stdin to keep the interface uniform).
 * HOW:  parse --io-uring before the vfs open; pass the mode in vopts so vfs_posix can
 *       engage or suppress the uring ring accordingly.  Without -f the remote must not
 *       already exist (kXR_new); -f truncates/overwrites.  bs defaults to 1 MiB. */
/* Recognise a bs=/rate=/-f/--io-uring operand shared by upload and download; `who` is
 * the command name for diagnostics.  Returns 1 if consumed (advancing *i past a spaced
 * --io-uring value), 0 if the token is not a common flag, and -1 on a bad value (a
 * diagnostic is printed).  Updates *bs, *rate, *force, *io_uring_mode as applicable. */
static int
xfer_common_arg(const char *who, char **argv, int argc, int *i, xfer_args_t *x)
{
    const char *a = argv[*i];

    if (strncmp(a, "bs=", 3) == 0) {
        x->bs = parse_bytes(a + 3);
        if (x->bs <= 0 || x->bs > XRDFS_DD_MAXBS) {
            fprintf(stderr, "xrdfs: %s: bad bs (max 256M)\n", who); return -1;
        }
        return 1;
    }
    if (strncmp(a, "rate=", 5) == 0) {
        int64_t r = parse_bytes(a + 5);
        if (r < 0) { fprintf(stderr, "xrdfs: %s: bad rate\n", who); return -1; }
        x->rate = (double) r;
        return 1;
    }
    if (strcmp(a, "-f") == 0) { x->force = 1; return 1; }
    if (strncmp(a, "--io-uring=", 11) == 0) {
        int v = brix_cli_parse_io_uring(a + 11);
        if (v < 0) {
            fprintf(stderr, "xrdfs: %s: --io-uring: invalid mode '%s' "
                    "(use on|off|auto)\n", who, a + 11);
            return -1;
        }
        x->io_uring_mode = v;
        return 1;
    }
    if (strcmp(a, "--io-uring") == 0 && *i + 1 < argc) {
        const char *m = argv[++(*i)];
        int v = brix_cli_parse_io_uring(m);
        if (v < 0) {
            fprintf(stderr, "xrdfs: %s: --io-uring: invalid mode '%s' "
                    "(use on|off|auto)\n", who, m);
            return -1;
        }
        x->io_uring_mode = v;
        return 1;
    }
    return 0;
}


/*
 * Copy-loop endpoint bundle shared by upload and download.
 *
 * WHAT: the fixed-for-the-transfer state of one xrdfs copy loop — the remote
 *       handle, the local VFS handle, the raw pipe fd (stdin for upload / stdout
 *       for download) and whether that pipe is the active local end, the reusable
 *       buffer and its size, the rate throttle + pacing clock, and the two endpoint
 *       names used only for diagnostics.
 * WHY:  the two copy loops each carried a dozen positional parameters; grouping the
 *       invariant-per-transfer state into one value keeps them under the parameter
 *       budget while the running offset stays an explicit in/out pointer.
 * HOW:  the caller fills the struct once before the loop; the loop reads it and
 *       advances the caller's `off` through a pointer argument. No behavior change:
 *       every field maps one-for-one onto a former parameter.
 */
typedef struct {
    brix_rfile      *f;       /* remote handle */
    brix_vfs_file   *vf;      /* local VFS handle (source for upload, dest for download) */
    int              fd;      /* raw pipe fd (stdin=0 upload, stdout=1 download) */
    int              is_pipe; /* 1 iff the local end is the raw pipe (fd), else VFS */
    uint8_t         *buf;     /* reusable transfer buffer */
    int64_t          bs;      /* buffer / chunk size */
    double           rate;    /* bytes/s throttle (0 = unlimited) */
    struct timespec *start;   /* pacing clock origin */
    const char      *local;   /* local endpoint name (diagnostics) */
    const char      *rpath;   /* remote endpoint name (diagnostics) */
} xfer_io_t;


/* Copy the local source (stdin fd or VFS handle) to the open remote handle, reading
 * `io->bs`-byte chunks and rate-pacing off *off. Advances *off; returns 0, -1 (read
 * error) or a shell exit code. */
static int
upload_copy_loop(const xfer_io_t *io, int64_t *off, brix_status *st)
{
    for (;;) {
        ssize_t r = io->is_pipe ? read(io->fd, io->buf, (size_t) io->bs)
                                : brix_vfs_pread(io->vf, *off, io->buf,
                                                 (size_t) io->bs, st);
        if (r < 0) {
            if (io->is_pipe && errno == EINTR) { continue; }
            fprintf(stderr, "xrdfs: upload: read %s: %s\n", io->local,
                    io->is_pipe ? strerror(errno) : st->msg);
            return -1;
        }
        if (r == 0) { break; }
        if (brix_rfile_pwrite(io->f, *off, io->buf, (size_t) r, st) != 0) {
            return brix_report_err(stderr, "xrdfs", "upload", io->rpath, st,
                                   1, NULL);
        }
        *off += r;
        rate_pace(io->start, *off, io->rate);
    }
    return 0;
}


/* Parse a transfer verb's operands: the shared bs=/rate=/-f/--io-uring flags plus
 * up to two positionals into x->pos1/x->pos2 (NULL if missing). `verb` selects the
 * bad-flag error prefix. upload takes <localfile|-> <remote>; download takes
 * <remote> [localfile|-]. Returns 0 on success or 50 on a bad flag value. */
static int
xfer_parse_operands(const char *verb, int argc, char **argv, xfer_args_t *x)
{
    int i;

    for (i = 1; i < argc; i++) {
        int r = xfer_common_arg(verb, argv, argc, &i, x);
        if (r < 0) { return 50; }
        if (r > 0) { continue; }
        if (x->pos1 == NULL)      { x->pos1 = argv[i]; }
        else if (x->pos2 == NULL) { x->pos2 = argv[i]; }
    }
    return 0;
}


int
do_upload(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status     st;
    char            rpath[XRDC_PATH_MAX];
    xfer_args_t     a = {0};
    const char     *local, *remote;
    int64_t         off = 0;
    int             rc = 0, is_stdin;
    brix_vfs_file  *svf = NULL;                     /* local-file source through the VFS */
    brix_rfile      f;
    uint8_t        *buf;
    struct timespec start;
    xfer_io_t       io;

    a.bs = 1 << 20; a.io_uring_mode = XRDC_IO_URING_AUTO;

    rc = xfer_parse_operands("upload", argc, argv, &a);
    if (rc != 0) { return rc; }
    rc = 0;
    local = a.pos1; remote = a.pos2;
    if (local == NULL || remote == NULL) {
        fprintf(stderr,
                "usage: upload [bs=N] [rate=R] [-f] [--io-uring on|off|auto]"
                " <localfile|-> <remote>\n");
        return 50;
    }

    /* stdin "-" is a pipe (raw fd 0); a named local file is opened through the
     * VFS so its bytes route through the shared SD driver, read by offset.
     * --io-uring is forwarded through vopts; for stdin it is parsed but unused
     * because the raw-pipe path never calls brix_vfs_open. */
    is_stdin = (strcmp(local, "-") == 0);
    if (!is_stdin) {
        brix_vfs_open_opts vopts;
        vopts.io_uring = a.io_uring_mode; vopts.expected_size = -1; vopts.cred = NULL;
        brix_status_clear(&st);
        if (brix_vfs_open(local, XRDC_VFS_READ, &vopts, &svf, &st) != 0) {
            fprintf(stderr, "xrdfs: upload: %s: %s\n", local, st.msg);
            return 50;
        }
    }
    build_path(cwd, remote, rpath, sizeof(rpath));
    brix_status_clear(&st);
    if (brix_rfile_open_write(c, rpath, a.force ? 1 : 0, 0, 0, -1, &f, &st) != 0) {
        if (svf != NULL) { brix_vfs_close(svf); }
        return xrdfs_report_err("upload", rpath, &st, 1, c);
    }
    buf = (uint8_t *) malloc((size_t) a.bs);
    if (buf == NULL) {
        brix_rfile_close(&f, &st);
        if (svf != NULL) { brix_vfs_close(svf); }
        fprintf(stderr, "xrdfs: upload: out of memory\n");
        return 51;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    io.f = &f; io.vf = svf; io.fd = 0; io.is_pipe = is_stdin;
    io.buf = buf; io.bs = a.bs; io.rate = a.rate; io.start = &start;
    io.local = local; io.rpath = rpath;
    rc = upload_copy_loop(&io, &off, &st);
    free(buf);
    brix_rfile_close(&f, &st);   /* commit */
    if (svf != NULL) { brix_vfs_close(svf); }
    if (rc != 0) { return rc < 0 ? 1 : rc; }
    fprintf(stderr, "%lld bytes uploaded to %s\n", (long long) off, rpath);
    return 0;
}


/* download [bs=BYTES] [rate=BYTES/s] [-f] [--io-uring on|off|auto] <remote> [localfile|-]
 * WHAT: read a remote file to a local file (or stdout "-"), optionally rate-limited.
 * WHY:  named local destinations are written through the VFS (shared SD driver), so
 *       --io-uring controls the kernel io_uring write path for the local destination file;
 *       stdout is a raw pipe and does not benefit from io_uring (flag accepted, ignored).
 * HOW:  parse --io-uring before the vfs open; pass the mode in vopts.  The local
 *       destination defaults to the remote basename in the current directory (like `get`).
 *       Without -f an existing local file is not overwritten (O_EXCL).  The rate-limit
 *       counterpart to `upload`; for windowed/stdout reads use `dd`. */

/* Write all `n` bytes of `buf` to the raw stdout fd, retrying short writes and EINTR.
 * `local` names the destination for diagnostics. Returns 0 on success, 1 on error. */
static int
download_write_stdout(int fd, const uint8_t *buf, ssize_t n, const char *local)
{
    ssize_t w = 0;
    while (w < n) {
        ssize_t k = write(fd, buf + w, (size_t) (n - w));
        if (k < 0) {
            if (errno == EINTR) { continue; }
            fprintf(stderr, "xrdfs: download: write %s: %s\n", local, strerror(errno));
            return 1;
        }
        if (k == 0) { return 1; }
        w += k;
    }
    return 0;
}


/* Finalize the VFS destination `dvf` (NULL = stdout, no-op): on a clean transfer
 * (`rc`==0) commit it (a commit failure yields rc 1), otherwise abort; then close.
 * Returns the resulting exit code. */
static int
download_finalize_local(brix_vfs_file *dvf, int rc, const char *local, brix_status *st)
{
    if (dvf != NULL) {
        if (rc == 0 && brix_vfs_commit(dvf, st) != 0) {
            fprintf(stderr, "xrdfs: download: commit %s: %s\n", local, st->msg);
            rc = 1;
        } else if (rc != 0) {
            brix_vfs_abort(dvf);
        }
        brix_vfs_close(dvf);
    }
    return rc;
}


/* Open the named local destination `local` through the VFS for writing (FORCE when
 * `force`), forwarding `io_uring_mode` in vopts. On success sets *dvf; on failure
 * prints the diagnostic and returns -1. */
static int
download_open_local(const char *local, int force, int io_uring_mode,
                    brix_vfs_file **dvf, brix_status *st)
{
    brix_vfs_open_opts vopts;
    vopts.io_uring = io_uring_mode; vopts.expected_size = -1; vopts.cred = NULL;
    brix_status_clear(st);
    if (brix_vfs_open(local, XRDC_VFS_WRITE | (force ? XRDC_VFS_FORCE : 0),
                      &vopts, dvf, st) != 0) {
        fprintf(stderr, "xrdfs: download: %s: %s\n", local, st->msg);
        return -1;
    }
    return 0;
}


/* Derive the default local destination (the remote basename in the cwd, like `get`)
 * from `rpath` into `namebuf`, pointing *local at it. Returns 0, or 50 if the remote
 * has no basename. */
static int
download_default_local(const char *rpath, char *namebuf, size_t namebuf_sz,
                       const char **local)
{
    const char *base = strrchr(rpath, '/');
    base = (base != NULL) ? base + 1 : rpath;
    if (base[0] == '\0') {
        fprintf(stderr, "xrdfs: download: no local dest and remote has no basename\n");
        return 50;
    }
    snprintf(namebuf, namebuf_sz, "%s", base);
    *local = namebuf;
    return 0;
}


/* Read the open remote handle in `io->bs`-byte chunks, writing each to the raw stdout
 * fd (is_pipe) or the VFS destination, rate-pacing off *off. Advances *off; returns 0
 * or a shell exit code. */
static int
download_copy_loop(const xfer_io_t *io, int64_t *off, brix_status *st)
{
    for (;;) {
        ssize_t n = brix_rfile_pread(io->f, *off, io->buf, (size_t) io->bs, st);
        int     rc = 0;
        if (n < 0) {
            return brix_report_err(stderr, "xrdfs", "download", io->rpath, st,
                                   0, NULL);
        }
        if (n == 0) { break; }
        if (io->is_pipe) {
            rc = download_write_stdout(io->fd, io->buf, n, io->local);
        } else if (brix_vfs_pwrite(io->vf, *off, io->buf, (size_t) n, st) != 0) {
            fprintf(stderr, "xrdfs: download: write %s: %s\n", io->local, st->msg);
            rc = 1;
        }
        if (rc != 0) { return rc; }
        *off += n;
        rate_pace(io->start, *off, io->rate);
    }
    return 0;
}


int
do_download(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status     st;
    char            rpath[XRDC_PATH_MAX], namebuf[XRDC_PATH_MAX];
    xfer_args_t     a = {0};
    const char     *remote, *local;
    int64_t         off = 0;
    int             rc = 0, is_stdout;
    brix_vfs_file  *dvf = NULL;                     /* local-file destination through the VFS */
    brix_rfile      f;
    uint8_t        *buf;
    struct timespec start;
    xfer_io_t       io;

    a.bs = 1 << 20; a.io_uring_mode = XRDC_IO_URING_AUTO;

    rc = xfer_parse_operands("download", argc, argv, &a);
    if (rc != 0) { return rc; }
    rc = 0;
    remote = a.pos1; local = a.pos2;
    if (remote == NULL) {
        fprintf(stderr,
                "usage: download [bs=N] [rate=R] [-f] [--io-uring on|off|auto]"
                " <remote> [localfile|-]\n");
        return 50;
    }
    build_path(cwd, remote, rpath, sizeof(rpath));
    if (local == NULL) {   /* default: remote basename in the cwd (like get) */
        rc = download_default_local(rpath, namebuf, sizeof(namebuf), &local);
        if (rc != 0) { return rc; }
    }

    /* stdout "-" is a pipe (raw fd 1); a named local file is written through the
     * VFS — atomic temp+rename commit, FORCE (-f) overwrites, else the existing
     * destination is refused (the same no-overwrite guard as the old O_EXCL).
     * --io-uring is forwarded through vopts; for stdout it is parsed but unused
     * because the raw-pipe path never calls brix_vfs_open. */
    is_stdout = (strcmp(local, "-") == 0);
    if (!is_stdout
        && download_open_local(local, a.force, a.io_uring_mode, &dvf, &st) != 0) {
        return 50;
    }
    brix_status_clear(&st);
    if (brix_rfile_open_read(c, rpath, NULL, 0, -1, &f, &st) != 0) {
        if (dvf != NULL) { brix_vfs_abort(dvf); brix_vfs_close(dvf); }
        return xrdfs_report_err("download", rpath, &st, 0, c);
    }
    buf = (uint8_t *) malloc((size_t) a.bs);
    if (buf == NULL) {
        brix_rfile_close(&f, &st);
        if (dvf != NULL) { brix_vfs_abort(dvf); brix_vfs_close(dvf); }
        fprintf(stderr, "xrdfs: download: out of memory\n");
        return 51;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    io.f = &f; io.vf = dvf; io.fd = 1; io.is_pipe = is_stdout;
    io.buf = buf; io.bs = a.bs; io.rate = a.rate; io.start = &start;
    io.local = local; io.rpath = rpath;
    rc = download_copy_loop(&io, &off, &st);
    free(buf);
    brix_rfile_close(&f, &st);
    rc = download_finalize_local(dvf, rc, local, &st);
    if (rc != 0) { return rc; }
    if (!is_stdout) {   /* don't pollute a piped stdout with the summary */
        fprintf(stderr, "%lld bytes downloaded to %s\n", (long long) off, local);
    }
    return 0;
}
