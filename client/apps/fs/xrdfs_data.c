/*
 * xrdfs_data.c — xrdfs text/inspection data ops (Phase-38 keep-file).
 *
 * WHAT: the streaming text viewers of the xrdfs busybox — cat, head, tail
 *       (incl. -f follow), and wc — plus their shared open-read/stream core.
 * WHY:  the busybox data ops were split by concern to hold each TU within the
 *       Phase-38 size budget; this file owns the "read bytes and render text"
 *       commands. The content-inspection ops (cmp/grep/hexdump/dd) live in
 *       xrdfs_data_content.c and the bulk-transfer ops (upload/download/
 *       readv/writev) in xrdfs_data_xfer.c. Every do_* entry point is declared
 *       in xrdfs_internal.h and dispatched from xrdfs.c.
 * HOW:  each do_* parses its operands into a file-local arg bundle (kept under
 *       the 5-parameter gate), then streams over an open brix_rfile. tail -f
 *       exits cleanly on the SIGINT flag tail_stop (owned by xrdfs.c). No goto.
 */
#include "xrdfs_internal.h"

/* tail operand set: the target path plus the -c/-n/-f/--interval modes. */
typedef struct {
    const char *arg;       /* target path, NULL if none given */
    long long   nbytes;    /* -c byte count (< 0 = not set) */
    long        nlines;    /* -n line count */
    int         follow;    /* -f follow mode */
    double      interval;  /* --interval poll seconds */
} tail_args_t;

/* cat / tail / head share an open-read + stream-to-stdout core. tail seeks the tail
 * window via stat size. `limit` caps the number of bytes streamed from `start`
 * (< 0 = stream to EOF); head passes a positive cap, cat/tail pass -1.
 * `opaque` is forwarded verbatim to brix_rfile_open_read (NULL = plain open). */
int
stream_file(brix_conn *c, const char *path, const char *opaque,
            int64_t start, int64_t limit, brix_status *st)
{
    brix_rfile rf;
    uint8_t  *buf;
    int64_t   off = start;
    int64_t   remaining = limit;   /* meaningful only when limit >= 0 */
    int       rc = 0;

    /* Resilient read: rides out a mid-stream sever (reconnect + reopen + resume
     * at offset) within the connection's stall window — xrootdfs parity. */
    if (brix_rfile_open_read(c, path, opaque, 0, -1, &rf, st) != 0) {
        return -1;
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        brix_rfile_close(&rf, st);
        return -1;
    }
    for (;;) {
        size_t  want = 1 << 20;
        ssize_t n;
        if (limit >= 0) {
            if (remaining <= 0) { break; }
            if ((int64_t) want > remaining) { want = (size_t) remaining; }
        }
        n = brix_rfile_pread(&rf, off, buf, want, st);
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        if (fwrite(buf, 1, (size_t) n, stdout) != (size_t) n) {
            brix_status_set(st, XRDC_ESOCK, 0, "stdout write failed");
            rc = -1;
            break;
        }
        off += n;
        if (limit >= 0) { remaining -= n; }
    }
    free(buf);
    {
        brix_status tw;
        brix_status_clear(&tw);
        brix_rfile_close(&rf, rc == 0 ? st : &tw);
    }
    return rc;
}


/* cat [-z codec] <path> [path ...] — stream remote files to stdout with
 * optional compression.
 *
 * WHAT: Stream every named remote file's contents to stdout, concatenated in
 * operand order (POSIX cat semantics). Returns 0 when all paths stream
 * cleanly, else the first failure's exit code. With -z, requests server-side
 * inline compression; output is identical whether compression was negotiated
 * or ignored.
 *
 * WHY: Transparency contract with the server — the -z flag is an opt-in request that
 * the server may decline. Clients must handle both compressed and plaintext responses
 * interchangeably, ensuring the output is byte-identical after decompression.
 * Multiple operands used to silently stream the LAST path only (feature-parity
 * audit §9.2); like cat(1), a failing operand is reported on stderr and the
 * remaining operands still stream.
 *
 * HOW: (1) Parse arguments for the -z <codec> flag. (2) Validate codec
 * (reject empty, >16 chars, or injection chars &?=). (3) Encode codec as opaque
 * "xrootd.compress=<codec>". (4) Forward every non-flag operand to
 * stream_file() with the opaque key, remembering the first failing exit code;
 * decompression is transparent in brix_file_read().
 */
int
do_cat(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    const char *codec  = NULL;
    const char *opaque = NULL;
    char        opq[80];
    int         worst = 0, npaths = 0, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-z") == 0 && i + 1 < argc) {
            codec = argv[++i];
        }
    }

    /* -z <codec>: ask the server for inline read compression (gzip|deflate|
     * zstd|br|xz|bzip2). Transparent: brix_file_read inflates each frame; a
     * server without support ignores the request and streams plaintext.
     * Guard: reject codec strings that could inject opaque key=value pairs. */
    if (codec != NULL) {
        if (codec[0] == '\0' || strlen(codec) > 16 || strpbrk(codec, "&?=") != NULL) {
            fprintf(stderr, "xrdfs: cat: invalid codec '%s'\n", codec);
            return 50;
        }
        snprintf(opq, sizeof(opq), "xrootd.compress=%s", codec);
        opaque = opq;
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-z") == 0 && i + 1 < argc) {
            i++;                      /* skip the codec value operand */
            continue;
        }
        npaths++;
        build_path(cwd, argv[i], path, sizeof(path));
        brix_status_clear(&st);
        if (stream_file(c, path, opaque, 0, -1, &st) != 0) {
            int path_rc = xrdfs_report_err("cat", path, &st, 0, c);

            if (worst == 0) { worst = path_rc; }
        }
    }
    if (npaths == 0) {
        fprintf(stderr, "usage: cat [-z codec] <path> [path ...]\n");
        return 50;
    }
    return worst;
}


/* Stream the first `nlines` newline-delimited lines of `path` to stdout, reading
 * forward in 1 MiB chunks and stopping at the Nth newline (emitting any trailing
 * partial line if EOF arrives first). 0 / -1. */
int
head_lines(brix_conn *c, const char *path, long nlines, brix_status *st)
{
    brix_rfile f;
    uint8_t  *buf;
    int64_t   off = 0;
    long      seen = 0;
    int       rc = 0;

    if (brix_rfile_open_read(c, path, NULL, 0, -1, &f, st) != 0) {
        return -1;
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        brix_rfile_close(&f, st);
        return -1;
    }
    while (seen < nlines) {
        ssize_t n = brix_rfile_pread(&f, off, buf, 1 << 20, st);
        size_t  emit;
        ssize_t i;
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        emit = (size_t) n;
        for (i = 0; i < n; i++) {
            if (buf[i] == '\n' && ++seen == nlines) {
                emit = (size_t) (i + 1);
                break;
            }
        }
        if (fwrite(buf, 1, emit, stdout) != emit) {
            brix_status_set(st, XRDC_ESOCK, 0, "stdout write failed");
            rc = -1;
            break;
        }
        off += n;
    }
    free(buf);
    {
        brix_status tw;
        brix_status_clear(&tw);
        brix_rfile_close(&f, rc == 0 ? st : &tw);
    }
    return rc;
}


/* head [-c BYTES] [-n LINES] <path> — print the start of a file. -c (byte count) wins
 * over -n (line count, default 10); both modes stream forward only. */
int
do_head(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    long long   nbytes = -1;   /* -c; < 0 = not set */
    long        nlines = 10;   /* -n default */
    const char *arg = NULL;
    int         i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            nbytes = strtoll(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            nlines = strtol(argv[++i], NULL, 10);
        } else { arg = argv[i]; }
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: head [-c BYTES] [-n LINES] <path>\n");
        return 50;
    }
    build_path(cwd, arg, path, sizeof(path));
    brix_status_clear(&st);

    if (nbytes >= 0) {
        if (stream_file(c, path, NULL, 0, (int64_t) nbytes, &st) != 0) {
            return xrdfs_report_err("head", path, &st, 0, c);
        }
        return 0;
    }
    if (nlines <= 0) { return 0; }   /* head -n 0 → nothing */
    if (head_lines(c, path, nlines, &st) != 0) {
        return xrdfs_report_err("head", path, &st, 0, c);
    }
    return 0;
}


/* tail -f sets this from a SIGINT handler so the follow loop exits cleanly. */

void
tail_sigint(int sig)
{
    (void) sig;
    tail_stop = 1;
}


/* Backward line-scan progress for tail's start-offset search: the file size and the
 * target line count are fixed inputs; `newlines` accumulates across windows and
 * `start` receives the answer once the target is reached. */
typedef struct {
    int64_t size;       /* total file size (a trailing newline at size-1 is ignored) */
    long    nlines;     /* target number of lines */
    long    newlines;   /* line-starting newlines seen so far */
    int64_t start;      /* byte offset where the last nlines lines begin */
} tail_scan_t;


/* Scan the `n` bytes at buf[] (which cover file offsets base..base+n-1) backward,
 * counting line-starting newlines toward the running total s->newlines. A newline at
 * the very end of the file (abs offset == s->size-1) terminates the last line and is
 * not counted. When the count reaches s->nlines, sets s->start to the byte after that
 * newline and returns 1 (found); otherwise returns 0. */
static int
tail_scan_window(const uint8_t *buf, ssize_t n, int64_t base, tail_scan_t *s)
{
    ssize_t i;

    for (i = n - 1; i >= 0; i--) {
        int64_t abs_off = base + i;
        if (buf[i] == '\n' && abs_off != s->size - 1) {
            if (++(s->newlines) == s->nlines) {
                s->start = abs_off + 1;
                return 1;
            }
        }
    }
    return 0;
}


/* Compute the byte offset at which the last `nlines` lines of a `size`-byte file
 * begin, scanning backward in 64 KiB windows. A single trailing newline at EOF is
 * not counted (it terminates the last line; it does not start an extra one). Sets
 * *start (0 if the whole file is within the window). 0 / -1. */
int
tail_start_for_lines(brix_conn *c, const char *path, int64_t size, long nlines,
                     int64_t *start, brix_status *st)
{
    brix_rfile    f;
    uint8_t      *buf;
    const int64_t WIN = 1 << 16;
    int64_t       pos = size;
    tail_scan_t   scan = { size, nlines, 0, 0 };
    int           rc = 0, found = 0;

    *start = 0;
    if (size <= 0 || nlines <= 0) { return 0; }
    if (brix_rfile_open_read(c, path, NULL, 0, -1, &f, st) != 0) { return -1; }
    buf = (uint8_t *) malloc((size_t) WIN);
    if (buf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        brix_rfile_close(&f, st);
        return -1;
    }
    while (pos > 0 && !found) {
        int64_t chunk = (pos > WIN) ? WIN : pos;
        int64_t base  = pos - chunk;
        ssize_t n = brix_rfile_pread(&f, base, buf, (size_t) chunk, st);
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        found = tail_scan_window(buf, n, base, &scan);
        if (found) { *start = scan.start; }
        pos = base;
    }
    free(buf);
    {
        brix_status tw;
        brix_status_clear(&tw);
        brix_rfile_close(&f, rc == 0 ? st : &tw);
    }
    return rc;
}


/* WHAT: follow mode for tail (-f): after the initial dump, poll the file size every
 *       `interval` seconds and stream appended bytes until SIGINT.
 * WHY:  one long-lived brix_rfile rides out connection severs (reconnect+reopen+resume)
 *       transparently — the resilient-handle showcase.  Re-opening per poll would add
 *       per-round open/close RTT and forfeit the automatic reconnect benefit.
 * HOW:  open brix_rfile once; brix_stat once per poll; new bytes brix_rfile_pread
 *       through the handle; a shrink (truncate/rotate) emits a stderr notice and resets
 *       to the new EOF; a soft EOF (pread returns 0) means the file was replaced
 *       (delete+create) — close the stale handle and reopen to bind the new inode.
 *       A retryable per-poll brix_stat failure (transient sever) does NOT end
 *       follow mode: it best-effort reconnects and keeps polling within the
 *       resilience window (brix_resilient_window_ms), giving up only once the
 *       window is exhausted; a hard failure (e.g. ENOENT after deletion) exits.
 *       SIGINT handler sets tail_stop for a clean exit.
 * Returns 0 (clean / interrupted) / -1 (stat or read error, st set). */
/* State threaded through tail's follow (-f) loop: the connection + path being
 * followed, the one long-lived resilient handle (`rf`, open iff `rf_open`), the
 * reusable read buffer, and the running read offset. Bundling these keeps the
 * drain helper and the poll loop under the parameter budget. */
typedef struct {
    brix_conn *c;
    const char *path;
    brix_rfile *rf;
    int         rf_open;   /* 1 iff rf holds an open, unclosed handle */
    uint8_t    *buf;
    int64_t     off;       /* next byte to read */
} tail_follow_t;


/* Drain the bytes in (fl->off .. size) of the followed file to stdout through the
 * open handle `fl->rf`.  A soft EOF (pread returns 0) means the inode was replaced:
 * close the stale handle and reopen to bind the new inode (updating fl->rf_open),
 * then stop so the caller re-polls the size.  Advances fl->off past written bytes.
 * Returns 0 normally, -1 on a read or reopen error (st set). */
static int
tail_follow_drain(tail_follow_t *fl, int64_t size, brix_status *st)
{
    while (fl->off < size) {
        size_t  want = (size_t) ((size - fl->off) < (1 << 20)
                                 ? (size - fl->off) : (1 << 20));
        ssize_t n = brix_rfile_pread(fl->rf, fl->off, fl->buf, want, st);
        if (n < 0)  { return -1; }
        if (n == 0) {
            /* Soft EOF: the underlying file was replaced (server unlinked the
             * inode our handle tracks).  Close the stale handle, reopen to bind
             * to the new inode, then break to re-poll the size before reading. */
            brix_status tw;
            brix_status_clear(&tw);
            brix_rfile_close(fl->rf, &tw);
            fl->rf_open = 0;
            brix_status_clear(st);
            if (brix_rfile_open_read(fl->c, fl->path, NULL, 0, -1, fl->rf, st) != 0) {
                return -1;
            }
            fl->rf_open = 1;
            return 0;
        }
        fwrite(fl->buf, 1, (size_t) n, stdout);
        fl->off += n;
    }
    return 0;
}


int
tail_follow(brix_conn *c, const char *path, int64_t from, double interval,
            brix_status *st)
{
    brix_rfile       rf;
    tail_follow_t    fl = {0};
    struct sigaction sa, old;
    int              rc = 0;
    int              window_ms = brix_resilient_window_ms(c);   /* stat-retry patience */
    uint64_t         stall_deadline = 0;   /* armed on the first retryable stat failure */

    fl.c = c; fl.path = path; fl.rf = &rf; fl.off = from;

    if (brix_rfile_open_read(c, path, NULL, 0, -1, &rf, st) != 0) {
        return -1;
    }
    fl.rf_open = 1;

    fl.buf = (uint8_t *) malloc(1 << 20);
    if (fl.buf == NULL) {
        /* Use a throwaway status for the close so the OOM message in st is
         * not clobbered by close's own error path (tail -f OOM clobber fix). */
        brix_status tw;
        brix_status_clear(&tw);
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        brix_rfile_close(&rf, &tw);
        fl.rf_open = 0;
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = tail_sigint;
    sigaction(SIGINT, &sa, &old);

    while (!tail_stop) {
        brix_statinfo   si;
        struct timespec ts;
        ts.tv_sec  = (time_t) interval;
        ts.tv_nsec = (long) ((interval - (double) ts.tv_sec) * 1e9);
        brix_status_clear(st);
        if (brix_stat(c, path, &si, st) != 0) {
            /* A transient sever (retryable) during follow must NOT end the
             * session: ride it out within the resilience window, mirroring
             * brix_rfile_pread.  A hard failure (e.g. the file was deleted →
             * ENOENT, not retryable) is definitive and exits follow mode. */
            if (window_ms > 0 && brix_status_retryable(st)) {
                uint64_t now = brix_mono_ns();
                if (stall_deadline == 0) {
                    stall_deadline = now + (uint64_t) window_ms * 1000000ULL;
                }
                if (now < stall_deadline) {
                    brix_status rc_st;   /* best-effort reconnect; keep st = the stat error */
                    brix_status_clear(&rc_st);
                    (void) brix_reconnect_home(c, &rc_st);
                    nanosleep(&ts, NULL);
                    continue;
                }
            }
            rc = -1;
            break;
        }
        stall_deadline = 0;   /* a healthy poll resets the patience window */
        if ((int64_t) si.size < fl.off) {
            fprintf(stderr, "xrdfs: tail: %s truncated, following new end\n", path);
            fl.off = (int64_t) si.size;
        }
        rc = tail_follow_drain(&fl, si.size, st);
        fflush(stdout);
        if (rc != 0) { break; }
        if (tail_stop) { break; }
        nanosleep(&ts, NULL);
    }

    sigaction(SIGINT, &old, NULL);
    free(fl.buf);
    if (fl.rf_open) {
        brix_status tw;
        brix_status_clear(&tw);
        brix_rfile_close(&rf, &tw);
    }
    return rc;
}


/* Parse tail's [-c BYTES] [-n LINES] [-f] [--interval S] flags plus the <path> operand
 * into `a` (pre-seeded with the command defaults); never fails. */
static void
tail_parse_args(int argc, char **argv, tail_args_t *a)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            a->nbytes = strtoll(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            a->nlines = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-f") == 0) {
            a->follow = 1;
        } else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            a->interval = atof(argv[++i]);
            if (a->interval <= 0.0) { a->interval = 1.0; }
        } else { a->arg = argv[i]; }
    }
}


int
do_tail(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status   st;
    brix_statinfo si;
    char          path[XRDC_PATH_MAX];
    tail_args_t   a = {0};
    int64_t       start;

    a.nbytes = -1;     /* -c; < 0 = not set */
    a.nlines = 10;     /* -n default */
    a.interval = 1.0;  /* --interval seconds */

    tail_parse_args(argc, argv, &a);
    if (a.arg == NULL) {
        fprintf(stderr, "usage: tail [-c BYTES] [-n LINES] [-f] [--interval S] <path>\n");
        return 50;
    }
    build_path(cwd, a.arg, path, sizeof(path));

    brix_status_clear(&st);
    if (brix_stat(c, path, &si, &st) != 0) {
        return xrdfs_report_err("tail", path, &st, 0, c);
    }
    if (a.nbytes >= 0) {
        start = (si.size > a.nbytes) ? si.size - a.nbytes : 0;
    } else if (tail_start_for_lines(c, path, si.size, a.nlines, &start, &st) != 0) {
        return xrdfs_report_err("tail", path, &st, 0, c);
    }
    if (stream_file(c, path, NULL, start, -1, &st) != 0) {
        return xrdfs_report_err("tail", path, &st, 0, c);
    }
    if (a.follow) {
        fflush(stdout);
        if (tail_follow(c, path, si.size, a.interval, &st) != 0) {
            return xrdfs_report_err("tail -f", path, &st, 0, c);
        }
    }
    return 0;
}
