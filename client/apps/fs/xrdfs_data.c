/*
 * xrdfs_data.c - extracted concern
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"
#include "brix_ops.h"              /* brix_cli_parse_io_uring */
#include "fs/vfs.h"   /* local endpoint I/O routes through the shared SD driver */


/*
 * Per-subcommand argument bundles.
 *
 * WHAT: file-local structs that collect the parsed operands of a single xrdfs
 *       data subcommand into one value passed by pointer.
 * WHY:  the busybox parsers grew one out-param per operand (7-8 each); bundling
 *       them keeps every parser and its callers under the 5-parameter budget and
 *       makes the operand set for a command self-documenting at its call site.
 * HOW:  the caller zero-initialises the struct to the command's defaults, hands
 *       its address to the parser, then reads the populated fields. No behavior
 *       change: the fields mirror the former out-params one-for-one.
 */

/* dd operand set: source path plus the windowing / rate knobs. */
typedef struct {
    const char *arg;     /* source path (if= or bare), NULL if none given */
    int64_t     bs;      /* block size in bytes */
    int64_t     skip;    /* leading blocks to skip */
    int64_t     count;   /* blocks to copy (-1 = to EOF) */
    double      rate;    /* bytes/s throttle (0 = unlimited) */
} dd_args_t;


/* tail operand set: the target path plus the -c/-n/-f/--interval modes. */
typedef struct {
    const char *arg;       /* target path, NULL if none given */
    long long   nbytes;    /* -c byte count (< 0 = not set) */
    long        nlines;    /* -n line count */
    int         follow;    /* -f follow mode */
    double      interval;  /* --interval poll seconds */
} tail_args_t;


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


/* cat [-z codec] <path> — stream a remote file to stdout with optional compression.
 *
 * WHAT: Stream remote file contents to stdout. Returns 0 on success, nonzero exit code
 * on error (e.g. missing file, invalid codec). With -z, requests server-side inline
 * compression; output is identical whether compression was negotiated or ignored.
 *
 * WHY: Transparency contract with the server — the -z flag is an opt-in request that
 * the server may decline. Clients must handle both compressed and plaintext responses
 * interchangeably, ensuring the output is byte-identical after decompression.
 *
 * HOW: (1) Parse arguments for -z <codec> flag and target path. (2) Validate codec
 * (reject empty, >16 chars, or injection chars &?=). (3) Encode codec as opaque
 * "xrootd.compress=<codec>". (4) Forward to stream_file() with the opaque key;
 * decompression is transparent in brix_file_read().
 */
int
do_cat(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    const char *codec  = NULL;
    const char *arg    = NULL;
    const char *opaque = NULL;
    char        opq[80];
    int         i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-z") == 0 && i + 1 < argc) {
            codec = argv[++i];
        } else {
            arg = argv[i];
        }
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: cat [-z codec] <path>\n");
        return 50;
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

    build_path(cwd, arg, path, sizeof(path));
    brix_status_clear(&st);
    if (stream_file(c, path, opaque, 0, -1, &st) != 0) {
        fprintf(stderr, "xrdfs: cat %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    return 0;
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
            fprintf(stderr, "xrdfs: head %s: %s\n", path, st.msg);
            return brix_shellcode(&st);
        }
        return 0;
    }
    if (nlines <= 0) { return 0; }   /* head -n 0 → nothing */
    if (head_lines(c, path, nlines, &st) != 0) {
        fprintf(stderr, "xrdfs: head %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
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
        fprintf(stderr, "xrdfs: tail %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    if (a.nbytes >= 0) {
        start = (si.size > a.nbytes) ? si.size - a.nbytes : 0;
    } else if (tail_start_for_lines(c, path, si.size, a.nlines, &start, &st) != 0) {
        fprintf(stderr, "xrdfs: tail %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    if (stream_file(c, path, NULL, start, -1, &st) != 0) {
        fprintf(stderr, "xrdfs: tail %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    if (a.follow) {
        fflush(stdout);
        if (tail_follow(c, path, si.size, a.interval, &st) != 0) {
            fprintf(stderr, "xrdfs: tail -f %s: %s\n", path, st.msg);
            return brix_shellcode(&st);
        }
    }
    return 0;
}


/* Stream `path` once, accumulating line (newline) and word counts into *lines and *words.
 * On error prints the wc diagnostic and returns the shell exit code (>0); 0 on success. */
static int
wc_count_stream(brix_conn *c, const char *path, long long *lines, long long *words,
                brix_status *st)
{
    brix_rfile f;
    uint8_t   *buf;
    int64_t    off = 0;
    int        in_word = 0, rc = 0;

    if (brix_rfile_open_read(c, path, NULL, 0, -1, &f, st) != 0) {
        fprintf(stderr, "xrdfs: wc %s: %s\n", path, st->msg);
        return brix_shellcode(st);
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) {
        brix_rfile_close(&f, st);
        fprintf(stderr, "xrdfs: wc: out of memory\n");
        return 51;
    }
    for (;;) {
        ssize_t got = brix_rfile_pread(&f, off, buf, 1 << 20, st);
        ssize_t k;
        if (got < 0) { rc = -1; break; }
        if (got == 0) { break; }
        for (k = 0; k < got; k++) {
            if (buf[k] == '\n') { (*lines)++; }
            if (isspace(buf[k])) { in_word = 0; }
            else if (!in_word) { in_word = 1; (*words)++; }
        }
        off += got;
    }
    free(buf);
    brix_rfile_close(&f, st);
    if (rc != 0) {
        fprintf(stderr, "xrdfs: wc %s: %s\n", path, st->msg);
        return brix_shellcode(st);
    }
    return 0;
}


/* wc operand set: which counters were requested plus the target path. */
typedef struct {
    const char *arg;      /* target path, NULL if none given */
    int         want_c;   /* -c bytes */
    int         want_l;   /* -l lines */
    int         want_w;   /* -w words */
} wc_args_t;


/* Parse wc's [-c] [-l] [-w] flags plus the <path> operand into `a` (each want_* set
 * when its flag is present, a->arg = the bare path or NULL). Never fails. */
static void
wc_parse_args(int argc, char **argv, wc_args_t *a)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0)      { a->want_c = 1; }
        else if (strcmp(argv[i], "-l") == 0) { a->want_l = 1; }
        else if (strcmp(argv[i], "-w") == 0) { a->want_w = 1; }
        else { a->arg = argv[i]; }
    }
}


/* wc [-c] [-l] [-w] <path> — count bytes/lines/words. With no flag, prints all three
 * (lines words bytes), like wc(1). -c alone is answered from stat (no read); -l/-w
 * stream the file once. Output columns match the selected counters, then the path. */
int
do_wc(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status   st;
    brix_statinfo si;
    char          path[XRDC_PATH_MAX];
    wc_args_t     a = {0};
    long long     lines = 0, words = 0, bytes = 0;

    wc_parse_args(argc, argv, &a);
    if (a.arg == NULL) { fprintf(stderr, "usage: wc [-c] [-l] [-w] <path>\n"); return 50; }
    if (!a.want_c && !a.want_l && !a.want_w) { a.want_l = a.want_w = a.want_c = 1; }
    build_path(cwd, a.arg, path, sizeof(path));

    brix_status_clear(&st);
    if (brix_stat(c, path, &si, &st) != 0) {
        fprintf(stderr, "xrdfs: wc %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    bytes = (long long) si.size;

    if (a.want_l || a.want_w) {   /* a single streaming pass counts lines + words */
        int wrc = wc_count_stream(c, path, &lines, &words, &st);
        if (wrc != 0) { return wrc; }
    }

    if (a.want_l) { printf(" %lld", lines); }
    if (a.want_w) { printf(" %lld", words); }
    if (a.want_c) { printf(" %lld", bytes); }
    printf(" %s\n", path);
    return 0;
}


/* Read a whole remote file into a malloc'd buffer (*out, *len). Caller frees. 0/-1. */
int
slurp_file(brix_conn *c, const char *path, uint8_t **out, int64_t *len, brix_status *st)
{
    brix_rfile    f;
    brix_statinfo si;
    uint8_t      *buf;
    int64_t       off = 0;

    if (brix_stat(c, path, &si, st) != 0) { return -1; }
    if (brix_rfile_open_read(c, path, NULL, 0, -1, &f, st) != 0) { return -1; }
    buf = (uint8_t *) malloc(si.size > 0 ? (size_t) si.size : 1);
    if (buf == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        brix_rfile_close(&f, st);
        return -1;
    }
    while (off < si.size) {
        ssize_t got = brix_rfile_pread(&f, off, buf + off, (size_t) (si.size - off), st);
        if (got < 0) { free(buf); brix_rfile_close(&f, st); return -1; }
        if (got == 0) { break; }
        off += got;
    }
    brix_rfile_close(&f, st);
    *out = buf;
    *len = off;
    return 0;
}


/* cmp <path1> <path2> — compare two files on this endpoint. Fast path: same-algo
 * server checksums (adler32); if they match the files are identical (exit 0), if they
 * differ exit 1. Falls back to a byte-exact compare when checksums are unavailable.
 * Quiet on a match (cmp(1) convention); reports the first differing offset otherwise. */
int
do_cmp(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        p1[XRDC_PATH_MAX], p2[XRDC_PATH_MAX];
    char        h1[160], h2[160];

    if (argc < 3) { fprintf(stderr, "usage: cmp <path1> <path2>\n"); return 50; }
    build_path(cwd, argv[1], p1, sizeof(p1));
    build_path(cwd, argv[2], p2, sizeof(p2));

    /* Fast path: compare server checksums (cheap, no bulk transfer). */
    brix_status_clear(&st);
    if (brix_query_cksum(c, p1, "adler32", h1, sizeof(h1), &st) == 0) {
        brix_status s2;
        brix_status_clear(&s2);
        if (brix_query_cksum(c, p2, "adler32", h2, sizeof(h2), &s2) == 0) {
            if (strcmp(h1, h2) == 0) { return 0; }
            printf("%s %s differ: checksum adler32 (%s vs %s)\n", p1, p2, h1, h2);
            return 1;
        }
    }

    /* Fallback: byte-exact compare. */
    {
        uint8_t *b1 = NULL, *b2 = NULL;
        int64_t  l1 = 0, l2 = 0, i, rc;
        brix_status_clear(&st);
        if (slurp_file(c, p1, &b1, &l1, &st) != 0) {
            fprintf(stderr, "xrdfs: cmp %s: %s\n", p1, st.msg);
            return brix_shellcode(&st);
        }
        if (slurp_file(c, p2, &b2, &l2, &st) != 0) {
            fprintf(stderr, "xrdfs: cmp %s: %s\n", p2, st.msg);
            free(b1);
            return brix_shellcode(&st);
        }
        rc = 0;
        for (i = 0; i < l1 && i < l2; i++) {
            if (b1[i] != b2[i]) {
                printf("%s %s differ: byte %lld\n", p1, p2, (long long) (i + 1));
                rc = 1;
                break;
            }
        }
        if (rc == 0 && l1 != l2) {
            printf("%s %s differ: EOF (sizes %lld vs %lld)\n", p1, p2,
                   (long long) l1, (long long) l2);
            rc = 1;
        }
        free(b1);
        free(b2);
        return (int) rc;
    }
}


/* State threaded through the grep chunk scanner: the reassembly line buffer plus the
 * running line number and match flag. */
typedef struct {
    char  *line;
    size_t lcap;
    size_t llen;
    long   lineno;
    int    matched;
} grep_scan_t;


/* Scan one read chunk of `got` bytes, reassembling complete lines and matching each
 * against `re` (numbered = prefix line numbers). Returns 0 normally, 2 on OOM growing
 * the line buffer. */
static int
grep_scan_chunk(const uint8_t *buf, ssize_t got, const regex_t *re, int numbered,
                grep_scan_t *g)
{
    ssize_t k;

    for (k = 0; k < got; k++) {
        if (buf[k] == '\n') {
            if (g->llen + 1 > g->lcap) {
                char *nl = (char *) realloc(g->line, g->llen + 1);
                if (nl == NULL) { return 2; }
                g->line = nl; g->lcap = g->llen + 1;
            }
            g->line[g->llen] = '\0';
            g->lineno++;
            if (regexec(re, g->line, 0, NULL, 0) == 0) {
                g->matched = 1;
                if (numbered) { printf("%ld:", g->lineno); }
                printf("%s\n", g->line);
            }
            g->llen = 0;
        } else {
            if (g->llen + 1 > g->lcap) {
                size_t ncap = g->lcap ? g->lcap * 2 : 256;
                char  *nl = (char *) realloc(g->line, ncap);
                if (nl == NULL) { return 2; }
                g->line = nl; g->lcap = ncap;
            }
            g->line[g->llen++] = (char) buf[k];
        }
    }
    return 0;
}


/* grep operand set: the regex source, target path, and case/number flags. */
typedef struct {
    const char *pattern;    /* PATTERN operand, NULL if none given */
    const char *arg;        /* target path, NULL if none given */
    int         icase;      /* -i case-insensitive */
    int         numbered;   /* -n prefix line numbers */
} grep_args_t;


/* Parse grep's [-i] [-n] flags plus the PATTERN and <path> operands into `a`. On a
 * usage error prints the diagnostic and returns 2; otherwise returns 0. */
static int
grep_parse_args(int argc, char **argv, grep_args_t *a)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0)      { a->icase = 1; }
        else if (strcmp(argv[i], "-n") == 0) { a->numbered = 1; }
        else if (a->pattern == NULL)         { a->pattern = argv[i]; }
        else                                 { a->arg = argv[i]; }
    }
    if (a->pattern == NULL || a->arg == NULL) {
        fprintf(stderr, "usage: grep [-i] [-n] PATTERN <path>\n");
        return 2;
    }
    return 0;
}


/* grep [-i] [-n] PATTERN <path> — POSIX-regex line match over a streamed file. Lines
 * are reassembled across read chunks. -i case-insensitive, -n prefix line numbers.
 * Exit 0 if any line matched, 1 if none, >1 on error (grep(1) convention). */
int
do_grep(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    grep_args_t a = {0};
    int         cflags = REG_NEWLINE;
    regex_t     re;
    brix_rfile  f;
    uint8_t    *buf;
    grep_scan_t g = { NULL, 0, 0, 0, 0 };
    int64_t     off = 0;
    int         rc = 0;

    rc = grep_parse_args(argc, argv, &a);
    if (rc != 0) { return rc; }
    rc = 0;
    if (a.icase) { cflags |= REG_ICASE; }
    if (regcomp(&re, a.pattern, cflags) != 0) {
        fprintf(stderr, "xrdfs: grep: bad pattern '%s'\n", a.pattern);
        return 2;
    }
    build_path(cwd, a.arg, path, sizeof(path));

    brix_status_clear(&st);
    if (brix_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: grep %s: %s\n", path, st.msg);
        regfree(&re);
        return brix_shellcode(&st) > 1 ? brix_shellcode(&st) : 2;
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) { brix_rfile_close(&f, &st); regfree(&re); return 2; }

    for (;;) {
        ssize_t got = brix_rfile_pread(&f, off, buf, 1 << 20, &st);
        if (got < 0) { rc = 2; break; }
        if (got == 0) { break; }
        rc = grep_scan_chunk(buf, got, &re, a.numbered, &g);
        if (rc != 0) { break; }
        off += got;
    }
    free(buf);
    free(g.line);
    brix_rfile_close(&f, &st);
    regfree(&re);
    if (rc != 0) {
        fprintf(stderr, "xrdfs: grep %s: %s\n", path, st.msg);
        return rc;
    }
    return g.matched ? 0 : 1;
}


/* Print one xxd-style row for the `row` bytes at buf[base..], labelled with the
 * absolute file offset `abs_off`: 8-hex-digit offset, 16 hex columns (padded), then
 * the printable-ASCII gutter. */
static void
hexdump_row(const uint8_t *buf, ssize_t base, ssize_t row, int64_t abs_off)
{
    ssize_t j;
    printf("%08llx ", (unsigned long long) abs_off);
    for (j = 0; j < 16; j++) {
        if (j < row) { printf("%02x ", buf[base + j]); }
        else         { printf("   "); }
    }
    printf(" |");
    for (j = 0; j < row; j++) {
        int ch = buf[base + j];
        putchar((ch >= 32 && ch < 127) ? ch : '.');
    }
    printf("|\n");
}


/* Read the open handle `*f` in 64 KiB chunks from *off, emitting an xxd-style row per
 * 16 bytes; `limit` (>=0) caps the total bytes shown. Advances *off; 0 / -1 (st set). */
static int
hexdump_stream(brix_rfile *f, uint8_t *buf, long long limit, int64_t *off,
               brix_status *st)
{
    for (;;) {
        size_t  want = 1 << 16;
        ssize_t got, base;
        if (limit >= 0) {
            int64_t rem = limit - *off;
            if (rem <= 0) { break; }
            if ((int64_t) want > rem) { want = (size_t) rem; }
        }
        got = brix_rfile_pread(f, *off, buf, want, st);
        if (got < 0) { return -1; }
        if (got == 0) { break; }
        for (base = 0; base < got; base += 16) {
            ssize_t row = (got - base < 16) ? got - base : 16;
            hexdump_row(buf, base, row, *off + base);
        }
        *off += got;
    }
    return 0;
}


/* hexdump [-n BYTES] <path> — xxd-style dump: 8-hex-digit offset, 16 hex bytes, then
 * the printable-ASCII gutter. -n caps the number of bytes shown. */
int
do_hexdump(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    const char *arg = NULL;
    long long   limit = -1;        /* -n; < 0 = whole file */
    int         i;
    brix_rfile  f;
    uint8_t    *buf;
    int64_t     off = 0;
    int         rc = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) { limit = strtoll(argv[++i], NULL, 10); }
        else { arg = argv[i]; }
    }
    if (arg == NULL) { fprintf(stderr, "usage: hexdump [-n BYTES] <path>\n"); return 50; }
    build_path(cwd, arg, path, sizeof(path));

    brix_status_clear(&st);
    if (brix_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: hexdump %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    buf = (uint8_t *) malloc(1 << 16);
    if (buf == NULL) { brix_rfile_close(&f, &st); return 51; }

    rc = hexdump_stream(&f, buf, limit, &off, &st);
    free(buf);
    brix_rfile_close(&f, &st);
    if (rc != 0) {
        fprintf(stderr, "xrdfs: hexdump %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    return 0;
}


/* dd [if=]<path> [bs=BYTES] [skip=BLOCKS] [count=BLOCKS] [rate=BYTES/s] — read a
 * windowed, optionally rate-limited slice of a remote file to stdout. bs defaults to
 * 1 MiB; the window starts at skip*bs and is count*bs bytes (count omitted = to EOF).
 * rate accepts a K/M/G suffix; 0 = unlimited. A one-line byte summary goes to stderr. */
/* Parse the dd operand list (bs=/skip=/count=/rate=/if=/bare path) into `a` (pre-seeded
 * with the command defaults). On a bad operand prints the diagnostic and returns 50;
 * otherwise returns 0 (a->arg = source path, NULL if none was given). */
static int
dd_parse_args(int argc, char **argv, dd_args_t *a)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "bs=", 3) == 0) {
            a->bs = parse_bytes(argv[i] + 3);
            if (a->bs <= 0 || a->bs > XRDFS_DD_MAXBS) {
                fprintf(stderr, "xrdfs: dd: bad bs (max 256M)\n"); return 50;
            }
        } else if (strncmp(argv[i], "skip=", 5) == 0) {
            a->skip = strtoll(argv[i] + 5, NULL, 10);
            if (a->skip < 0) { fprintf(stderr, "xrdfs: dd: bad skip\n"); return 50; }
        } else if (strncmp(argv[i], "count=", 6) == 0) {
            a->count = strtoll(argv[i] + 6, NULL, 10);
            if (a->count < 0) { fprintf(stderr, "xrdfs: dd: bad count\n"); return 50; }
        } else if (strncmp(argv[i], "rate=", 5) == 0) {
            int64_t r = parse_bytes(argv[i] + 5);
            if (r < 0) { fprintf(stderr, "xrdfs: dd: bad rate\n"); return 50; }
            a->rate = (double) r;
        } else if (strncmp(argv[i], "if=", 3) == 0) {
            a->arg = argv[i] + 3;
        } else if (argv[i][0] != '-') {
            a->arg = argv[i];
        }
    }
    return 0;
}


int
do_dd(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status     st;
    char            path[XRDC_PATH_MAX];
    dd_args_t       a = {0};
    int64_t         want_total, off, produced = 0;
    int             rc = 0;
    brix_rfile      f;
    uint8_t        *buf;
    struct timespec start;

    a.bs = 1 << 20; a.count = -1;   /* skip/rate default to 0 via zero-init */

    rc = dd_parse_args(argc, argv, &a);
    if (rc != 0) { return rc; }
    if (a.arg == NULL) {
        fprintf(stderr, "usage: dd [if=]<path> [bs=N] [skip=N] [count=N] [rate=R]\n");
        return 50;
    }
    build_path(cwd, a.arg, path, sizeof(path));
    off        = a.skip * a.bs;
    want_total = (a.count >= 0) ? a.count * a.bs : -1;

    brix_status_clear(&st);
    if (brix_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: dd %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    buf = (uint8_t *) malloc((size_t) a.bs);
    if (buf == NULL) {
        brix_rfile_close(&f, &st);
        fprintf(stderr, "xrdfs: dd: out of memory\n");
        return 51;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        size_t  want = (size_t) a.bs;
        ssize_t n;
        if (want_total >= 0) {
            int64_t rem = want_total - produced;
            if (rem <= 0) { break; }
            if ((int64_t) want > rem) { want = (size_t) rem; }
        }
        n = brix_rfile_pread(&f, off, buf, want, &st);
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        if (fwrite(buf, 1, (size_t) n, stdout) != (size_t) n) {
            brix_status_set(&st, XRDC_ESOCK, 0, "stdout write failed");
            rc = -1; break;
        }
        off += n; produced += n;
        rate_pace(&start, produced, a.rate);
    }
    free(buf);
    brix_rfile_close(&f, &st);
    if (rc != 0) {
        fprintf(stderr, "xrdfs: dd %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    fprintf(stderr, "%lld bytes copied\n", (long long) produced);
    return 0;
}


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
            fprintf(stderr, "xrdfs: upload %s: %s\n", io->rpath, st->msg);
            return brix_shellcode(st);
        }
        *off += r;
        rate_pace(io->start, *off, io->rate);
    }
    return 0;
}


/* Parse upload's operands: the shared bs=/rate=/-f/--io-uring flags plus the two
 * positionals <localfile|-> <remote> (x->pos1 = local, x->pos2 = remote; NULL if
 * missing).  Returns 0 on success or 50 on a bad flag value. */
static int
upload_parse_args(int argc, char **argv, xfer_args_t *x)
{
    int i;

    for (i = 1; i < argc; i++) {
        int r = xfer_common_arg("upload", argv, argc, &i, x);
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

    rc = upload_parse_args(argc, argv, &a);
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
        fprintf(stderr, "xrdfs: upload %s: %s\n", rpath, st.msg);
        xrdfs_op_hints(&st, 1, c);   /* WS-3/WS-7 */
        if (svf != NULL) { brix_vfs_close(svf); }
        return brix_shellcode(&st);
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
            fprintf(stderr, "xrdfs: download %s: %s\n", io->rpath, st->msg);
            return brix_shellcode(st);
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


/* Parse download's operands: the shared bs=/rate=/-f/--io-uring flags plus the two
 * positionals <remote> [localfile|-] (x->pos1 = remote, x->pos2 = local; NULL if
 * missing).  Returns 0 on success or 50 on a bad flag value. */
static int
download_parse_args(int argc, char **argv, xfer_args_t *x)
{
    int i;

    for (i = 1; i < argc; i++) {
        int r = xfer_common_arg("download", argv, argc, &i, x);
        if (r < 0) { return 50; }
        if (r > 0) { continue; }
        if (x->pos1 == NULL)      { x->pos1 = argv[i]; }
        else if (x->pos2 == NULL) { x->pos2 = argv[i]; }
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

    rc = download_parse_args(argc, argv, &a);
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
        fprintf(stderr, "xrdfs: download %s: %s\n", rpath, st.msg);
        if (dvf != NULL) { brix_vfs_abort(dvf); brix_vfs_close(dvf); }
        return brix_shellcode(&st);
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


/* Parse the <off len>... argument pairs of readv into `segs`, allocating a receive
 * buffer per segment. On error frees any partial allocations, prints the diagnostic,
 * and returns the shell exit code (>0); on success returns 0 and sets *nseg_out. */
static int
readv_parse_segs(int argc, char **argv, brix_readv_seg *segs, size_t *nseg_out)
{
    size_t nseg = 0, i;
    int    a;

    for (a = 2; a + 1 < argc && nseg < XRDC_VEC_MAXSEGS; a += 2) {
        unsigned long long off, len;
        if (parse_u64_strict(argv[a], &off) != 0
            || parse_u64_strict(argv[a + 1], &len) != 0) {
            for (i = 0; i < nseg; i++) { free(segs[i].buf); }
            fprintf(stderr, "xrdfs: readv: bad offset/length '%s %s'\n",
                    argv[a], argv[a + 1]);
            return 50;
        }
        segs[nseg].offset = (int64_t) off;
        segs[nseg].len    = (size_t) len;
        segs[nseg].got    = 0;
        segs[nseg].buf    = malloc(segs[nseg].len ? segs[nseg].len : 1);
        if (segs[nseg].buf == NULL) {
            for (i = 0; i < nseg; i++) { free(segs[i].buf); }
            fprintf(stderr, "xrdfs: readv: out of memory\n");
            return 51;
        }
        nseg++;
    }
    *nseg_out = nseg;
    return 0;
}


/* readv <path> <off1> <len1> [<off2> <len2> ...] — scatter-gather read (kXR_readv);
 * the requested segments are read in one round-trip and written, concatenated, to
 * stdout (so the bytes can be verified against the file). */
int
do_readv(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status    st;
    char           path[XRDC_PATH_MAX];
    brix_file      f;
    brix_readv_seg segs[XRDC_VEC_MAXSEGS];
    size_t         nseg = 0, i;
    ssize_t        got;
    int            rc = 0;

    if (argc < 4 || ((argc - 2) % 2) != 0) {
        fprintf(stderr, "usage: readv <path> <off len>...\n");
        return 50;
    }
    build_path(cwd, argv[1], path, sizeof(path));
    rc = readv_parse_segs(argc, argv, segs, &nseg);
    if (rc != 0) { return rc; }
    rc = 0;
    brix_status_clear(&st);
    if (brix_file_open_read(c, path, &f, &st) != 0) {
        for (i = 0; i < nseg; i++) { free(segs[i].buf); }
        fprintf(stderr, "xrdfs: readv open %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    got = brix_file_readv(c, &f, segs, nseg, &st);
    if (got < 0) {
        fprintf(stderr, "xrdfs: readv %s: %s\n", path, st.msg);
        rc = brix_shellcode(&st);
    } else {
        for (i = 0; i < nseg; i++) {
            fwrite(segs[i].buf, 1, segs[i].got, stdout);   /* actual bytes read */
        }
    }
    brix_file_close(c, &f, &st);
    for (i = 0; i < nseg; i++) { free(segs[i].buf); }
    return rc;
}


/* Decode one <off hexdata> writev pair into segs[nseg]. Frees the segment's own
 * scratch on failure (the caller frees earlier segments). 0 on success, else the
 * shell exit code (>0). */
static int
writev_parse_seg(char **argv, int a, brix_writev_seg *segs, size_t nseg)
{
    const char *hex = argv[a + 1];
    size_t      hl = strlen(hex), n = hl / 2, j;
    uint8_t    *d;
    unsigned long long off;

    if (hl == 0 || (hl % 2) != 0) {
        fprintf(stderr, "xrdfs: writev: bad hex data\n");
        return 50;
    }
    d = malloc(n);
    if (d == NULL) {
        fprintf(stderr, "xrdfs: writev: out of memory\n");
        return 51;
    }
    for (j = 0; j < n; j++) {
        unsigned v;
        if (sscanf(hex + 2 * j, "%2x", &v) != 1) {
            free(d);
            fprintf(stderr, "xrdfs: writev: bad hex data\n");
            return 50;
        }
        d[j] = (uint8_t) v;
    }
    if (parse_u64_strict(argv[a], &off) != 0) {
        free(d);
        fprintf(stderr, "xrdfs: writev: bad offset '%s'\n", argv[a]);
        return 50;
    }
    segs[nseg].offset = (int64_t) off;
    segs[nseg].len    = n;
    segs[nseg].data   = d;
    return 0;
}


/* Parse all <off hexdata>... writev pairs into `segs`. On error frees any decoded
 * segments, prints the diagnostic, and returns the shell exit code (>0); on success
 * returns 0 and sets *nseg_out. */
static int
writev_parse_segs(int argc, char **argv, brix_writev_seg *segs, size_t *nseg_out)
{
    size_t nseg = 0, i;
    int    a, rc;

    for (a = 2; a + 1 < argc && nseg < XRDC_VEC_MAXSEGS; a += 2) {
        rc = writev_parse_seg(argv, a, segs, nseg);
        if (rc != 0) {
            for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
            return rc;
        }
        nseg++;
    }
    *nseg_out = nseg;
    return 0;
}


/* writev <path> <off1> <hexdata1> [<off2> <hexdata2> ...] — scatter-gather write
 * (kXR_writev): each segment's hex-encoded bytes are written at its offset in one
 * round-trip (the file is created/truncated first). */
int
do_writev(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status     st;
    char            path[XRDC_PATH_MAX];
    brix_file       f;
    brix_writev_seg segs[XRDC_VEC_MAXSEGS];
    size_t          nseg = 0, i;
    int             rc = 0;

    if (argc < 4 || ((argc - 2) % 2) != 0) {
        fprintf(stderr, "usage: writev <path> <off hexdata>...\n");
        return 50;
    }
    build_path(cwd, argv[1], path, sizeof(path));
    rc = writev_parse_segs(argc, argv, segs, &nseg);
    if (rc != 0) { return rc; }
    rc = 0;
    brix_status_clear(&st);
    if (brix_file_open_write(c, path, 1 /*force*/, 0 /*posc*/, &f, &st) != 0) {
        for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
        fprintf(stderr, "xrdfs: writev open %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    if (brix_file_writev(c, &f, segs, nseg, 1 /*sync*/, &st) != 0) {
        fprintf(stderr, "xrdfs: writev %s: %s\n", path, st.msg);
        rc = brix_shellcode(&st);
    }
    brix_file_close(c, &f, &st);
    for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
    return rc;
}
