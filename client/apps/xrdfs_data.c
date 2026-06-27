/*
 * xrdfs_data.c - extracted concern
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"


/* cat / tail / head share an open-read + stream-to-stdout core. tail seeks the tail
 * window via stat size. `limit` caps the number of bytes streamed from `start`
 * (< 0 = stream to EOF); head passes a positive cap, cat/tail pass -1. */
int
stream_file(xrdc_conn *c, const char *path, int64_t start, int64_t limit,
            xrdc_status *st)
{
    xrdc_rfile rf;
    uint8_t  *buf;
    int64_t   off = start;
    int64_t   remaining = limit;   /* meaningful only when limit >= 0 */
    int       rc = 0;

    /* Resilient read: rides out a mid-stream sever (reconnect + reopen + resume
     * at offset) within the connection's stall window — xrootdfs parity. */
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &rf, st) != 0) {
        return -1;
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        xrdc_rfile_close(&rf, st);
        return -1;
    }
    for (;;) {
        size_t  want = 1 << 20;
        ssize_t n;
        if (limit >= 0) {
            if (remaining <= 0) { break; }
            if ((int64_t) want > remaining) { want = (size_t) remaining; }
        }
        n = xrdc_rfile_pread(&rf, off, buf, want, st);
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        if (fwrite(buf, 1, (size_t) n, stdout) != (size_t) n) {
            xrdc_status_set(st, XRDC_ESOCK, 0, "stdout write failed");
            rc = -1;
            break;
        }
        off += n;
        if (limit >= 0) { remaining -= n; }
    }
    free(buf);
    {
        xrdc_status tw;
        xrdc_status_clear(&tw);
        xrdc_rfile_close(&rf, rc == 0 ? st : &tw);
    }
    return rc;
}


int
do_cat(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];

    if (argc < 2) { fprintf(stderr, "usage: cat <path>\n"); return 50; }
    build_path(cwd, argv[1], path, sizeof(path));
    xrdc_status_clear(&st);
    if (stream_file(c, path, 0, -1, &st) != 0) {
        fprintf(stderr, "xrdfs: cat %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    return 0;
}


/* Stream the first `nlines` newline-delimited lines of `path` to stdout, reading
 * forward in 1 MiB chunks and stopping at the Nth newline (emitting any trailing
 * partial line if EOF arrives first). 0 / -1. */
int
head_lines(xrdc_conn *c, const char *path, long nlines, xrdc_status *st)
{
    xrdc_rfile f;
    uint8_t  *buf;
    int64_t   off = 0;
    long      seen = 0;
    int       rc = 0;

    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, st) != 0) {
        return -1;
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        xrdc_rfile_close(&f, st);
        return -1;
    }
    while (seen < nlines) {
        ssize_t n = xrdc_rfile_pread(&f, off, buf, 1 << 20, st);
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
            xrdc_status_set(st, XRDC_ESOCK, 0, "stdout write failed");
            rc = -1;
            break;
        }
        off += n;
    }
    free(buf);
    {
        xrdc_status tw;
        xrdc_status_clear(&tw);
        xrdc_rfile_close(&f, rc == 0 ? st : &tw);
    }
    return rc;
}


/* head [-c BYTES] [-n LINES] <path> — print the start of a file. -c (byte count) wins
 * over -n (line count, default 10); both modes stream forward only. */
int
do_head(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
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
    xrdc_status_clear(&st);

    if (nbytes >= 0) {
        if (stream_file(c, path, 0, (int64_t) nbytes, &st) != 0) {
            fprintf(stderr, "xrdfs: head %s: %s\n", path, st.msg);
            return xrdc_shellcode(&st);
        }
        return 0;
    }
    if (nlines <= 0) { return 0; }   /* head -n 0 → nothing */
    if (head_lines(c, path, nlines, &st) != 0) {
        fprintf(stderr, "xrdfs: head %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
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


/* Compute the byte offset at which the last `nlines` lines of a `size`-byte file
 * begin, scanning backward in 64 KiB windows. A single trailing newline at EOF is
 * not counted (it terminates the last line; it does not start an extra one). Sets
 * *start (0 if the whole file is within the window). 0 / -1. */
int
tail_start_for_lines(xrdc_conn *c, const char *path, int64_t size, long nlines,
                     int64_t *start, xrdc_status *st)
{
    xrdc_rfile    f;
    uint8_t      *buf;
    const int64_t WIN = 1 << 16;
    int64_t       pos = size;
    long          newlines = 0;
    int           rc = 0, found = 0;

    *start = 0;
    if (size <= 0 || nlines <= 0) { return 0; }
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, st) != 0) { return -1; }
    buf = (uint8_t *) malloc((size_t) WIN);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        xrdc_rfile_close(&f, st);
        return -1;
    }
    while (pos > 0 && !found) {
        int64_t chunk = (pos > WIN) ? WIN : pos;
        int64_t base  = pos - chunk;
        ssize_t n = xrdc_rfile_pread(&f, base, buf, (size_t) chunk, st);
        ssize_t i;
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        for (i = n - 1; i >= 0; i--) {
            int64_t abs_off = base + i;
            if (buf[i] == '\n' && abs_off != size - 1) {
                if (++newlines == nlines) {
                    *start = abs_off + 1;
                    found = 1;
                    break;
                }
            }
        }
        pos = base;
    }
    free(buf);
    {
        xrdc_status tw;
        xrdc_status_clear(&tw);
        xrdc_rfile_close(&f, rc == 0 ? st : &tw);
    }
    return rc;
}


/* tail -f follow loop: after the initial dump, poll the file size every `interval`
 * seconds and stream any growth, until SIGINT. On truncation, resync to the new EOF.
 * 0 (clean / interrupted) / -1 (stat or read error, st set). */
int
tail_follow(xrdc_conn *c, const char *path, int64_t from, double interval,
            xrdc_status *st)
{
    int64_t          off = from;
    struct sigaction sa, old;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = tail_sigint;
    sigaction(SIGINT, &sa, &old);

    while (!tail_stop) {
        xrdc_statinfo   si;
        struct timespec ts;
        xrdc_status_clear(st);
        if (xrdc_stat(c, path, &si, st) != 0) {
            sigaction(SIGINT, &old, NULL);
            return -1;
        }
        if (si.size > off) {
            if (stream_file(c, path, off, si.size - off, st) != 0) {
                sigaction(SIGINT, &old, NULL);
                return -1;
            }
            fflush(stdout);
            off = si.size;
        } else if (si.size < off) {
            off = si.size;   /* truncated → resync */
        }
        if (tail_stop) { break; }
        ts.tv_sec  = (time_t) interval;
        ts.tv_nsec = (long) ((interval - (double) ts.tv_sec) * 1e9);
        nanosleep(&ts, NULL);
    }
    sigaction(SIGINT, &old, NULL);
    return 0;
}


int
do_tail(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status   st;
    xrdc_statinfo si;
    char          path[XRDC_PATH_MAX];
    long long     nbytes = -1;     /* -c; < 0 = not set */
    long          nlines = 10;     /* -n default */
    int           follow = 0, i;
    double        interval = 1.0;  /* --interval seconds */
    int64_t       start;
    const char   *arg = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            nbytes = strtoll(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            nlines = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-f") == 0) {
            follow = 1;
        } else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            interval = atof(argv[++i]);
            if (interval <= 0.0) { interval = 1.0; }
        } else { arg = argv[i]; }
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: tail [-c BYTES] [-n LINES] [-f] [--interval S] <path>\n");
        return 50;
    }
    build_path(cwd, arg, path, sizeof(path));

    xrdc_status_clear(&st);
    if (xrdc_stat(c, path, &si, &st) != 0) {
        fprintf(stderr, "xrdfs: tail %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    if (nbytes >= 0) {
        start = (si.size > nbytes) ? si.size - nbytes : 0;
    } else if (tail_start_for_lines(c, path, si.size, nlines, &start, &st) != 0) {
        fprintf(stderr, "xrdfs: tail %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    if (stream_file(c, path, start, -1, &st) != 0) {
        fprintf(stderr, "xrdfs: tail %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    if (follow) {
        fflush(stdout);
        if (tail_follow(c, path, si.size, interval, &st) != 0) {
            fprintf(stderr, "xrdfs: tail -f %s: %s\n", path, st.msg);
            return xrdc_shellcode(&st);
        }
    }
    return 0;
}


/* wc [-c] [-l] [-w] <path> — count bytes/lines/words. With no flag, prints all three
 * (lines words bytes), like wc(1). -c alone is answered from stat (no read); -l/-w
 * stream the file once. Output columns match the selected counters, then the path. */
int
do_wc(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status   st;
    xrdc_statinfo si;
    char          path[XRDC_PATH_MAX];
    const char   *arg = NULL;
    int           want_c = 0, want_l = 0, want_w = 0, i;
    long long     lines = 0, words = 0, bytes = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0)      { want_c = 1; }
        else if (strcmp(argv[i], "-l") == 0) { want_l = 1; }
        else if (strcmp(argv[i], "-w") == 0) { want_w = 1; }
        else { arg = argv[i]; }
    }
    if (arg == NULL) { fprintf(stderr, "usage: wc [-c] [-l] [-w] <path>\n"); return 50; }
    if (!want_c && !want_l && !want_w) { want_l = want_w = want_c = 1; }
    build_path(cwd, arg, path, sizeof(path));

    xrdc_status_clear(&st);
    if (xrdc_stat(c, path, &si, &st) != 0) {
        fprintf(stderr, "xrdfs: wc %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    bytes = (long long) si.size;

    if (want_l || want_w) {   /* a single streaming pass counts lines + words */
        xrdc_rfile f;
        uint8_t  *buf;
        int64_t   off = 0;
        int       in_word = 0, rc = 0;

        if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
            fprintf(stderr, "xrdfs: wc %s: %s\n", path, st.msg);
            return xrdc_shellcode(&st);
        }
        buf = (uint8_t *) malloc(1 << 20);
        if (buf == NULL) {
            xrdc_rfile_close(&f, &st);
            fprintf(stderr, "xrdfs: wc: out of memory\n");
            return 51;
        }
        for (;;) {
            ssize_t got = xrdc_rfile_pread(&f, off, buf, 1 << 20, &st);
            ssize_t k;
            if (got < 0) { rc = -1; break; }
            if (got == 0) { break; }
            for (k = 0; k < got; k++) {
                if (buf[k] == '\n') { lines++; }
                if (isspace(buf[k])) { in_word = 0; }
                else if (!in_word) { in_word = 1; words++; }
            }
            off += got;
        }
        free(buf);
        xrdc_rfile_close(&f, &st);
        if (rc != 0) {
            fprintf(stderr, "xrdfs: wc %s: %s\n", path, st.msg);
            return xrdc_shellcode(&st);
        }
    }

    if (want_l) { printf(" %lld", lines); }
    if (want_w) { printf(" %lld", words); }
    if (want_c) { printf(" %lld", bytes); }
    printf(" %s\n", path);
    return 0;
}


/* Read a whole remote file into a malloc'd buffer (*out, *len). Caller frees. 0/-1. */
int
slurp_file(xrdc_conn *c, const char *path, uint8_t **out, int64_t *len, xrdc_status *st)
{
    xrdc_rfile    f;
    xrdc_statinfo si;
    uint8_t      *buf;
    int64_t       off = 0;

    if (xrdc_stat(c, path, &si, st) != 0) { return -1; }
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, st) != 0) { return -1; }
    buf = (uint8_t *) malloc(si.size > 0 ? (size_t) si.size : 1);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        xrdc_rfile_close(&f, st);
        return -1;
    }
    while (off < si.size) {
        ssize_t got = xrdc_rfile_pread(&f, off, buf + off, (size_t) (si.size - off), st);
        if (got < 0) { free(buf); xrdc_rfile_close(&f, st); return -1; }
        if (got == 0) { break; }
        off += got;
    }
    xrdc_rfile_close(&f, st);
    *out = buf;
    *len = off;
    return 0;
}


/* cmp <path1> <path2> — compare two files on this endpoint. Fast path: same-algo
 * server checksums (adler32); if they match the files are identical (exit 0), if they
 * differ exit 1. Falls back to a byte-exact compare when checksums are unavailable.
 * Quiet on a match (cmp(1) convention); reports the first differing offset otherwise. */
int
do_cmp(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        p1[XRDC_PATH_MAX], p2[XRDC_PATH_MAX];
    char        h1[160], h2[160];

    if (argc < 3) { fprintf(stderr, "usage: cmp <path1> <path2>\n"); return 50; }
    build_path(cwd, argv[1], p1, sizeof(p1));
    build_path(cwd, argv[2], p2, sizeof(p2));

    /* Fast path: compare server checksums (cheap, no bulk transfer). */
    xrdc_status_clear(&st);
    if (xrdc_query_cksum(c, p1, "adler32", h1, sizeof(h1), &st) == 0) {
        xrdc_status s2;
        xrdc_status_clear(&s2);
        if (xrdc_query_cksum(c, p2, "adler32", h2, sizeof(h2), &s2) == 0) {
            if (strcmp(h1, h2) == 0) { return 0; }
            printf("%s %s differ: checksum adler32 (%s vs %s)\n", p1, p2, h1, h2);
            return 1;
        }
    }

    /* Fallback: byte-exact compare. */
    {
        uint8_t *b1 = NULL, *b2 = NULL;
        int64_t  l1 = 0, l2 = 0, i, rc;
        xrdc_status_clear(&st);
        if (slurp_file(c, p1, &b1, &l1, &st) != 0) {
            fprintf(stderr, "xrdfs: cmp %s: %s\n", p1, st.msg);
            return xrdc_shellcode(&st);
        }
        if (slurp_file(c, p2, &b2, &l2, &st) != 0) {
            fprintf(stderr, "xrdfs: cmp %s: %s\n", p2, st.msg);
            free(b1);
            return xrdc_shellcode(&st);
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


/* grep [-i] [-n] PATTERN <path> — POSIX-regex line match over a streamed file. Lines
 * are reassembled across read chunks. -i case-insensitive, -n prefix line numbers.
 * Exit 0 if any line matched, 1 if none, >1 on error (grep(1) convention). */
int
do_grep(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];
    const char *pattern = NULL, *arg = NULL;
    int         icase = 0, numbered = 0, i, cflags = REG_NEWLINE;
    regex_t     re;
    xrdc_rfile  f;
    uint8_t    *buf;
    char       *line = NULL;
    size_t      lcap = 0, llen = 0;
    int64_t     off = 0;
    long        lineno = 0;
    int         matched = 0, rc = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0)      { icase = 1; }
        else if (strcmp(argv[i], "-n") == 0) { numbered = 1; }
        else if (pattern == NULL)            { pattern = argv[i]; }
        else                                 { arg = argv[i]; }
    }
    if (pattern == NULL || arg == NULL) {
        fprintf(stderr, "usage: grep [-i] [-n] PATTERN <path>\n");
        return 2;
    }
    if (icase) { cflags |= REG_ICASE; }
    if (regcomp(&re, pattern, cflags) != 0) {
        fprintf(stderr, "xrdfs: grep: bad pattern '%s'\n", pattern);
        return 2;
    }
    build_path(cwd, arg, path, sizeof(path));

    xrdc_status_clear(&st);
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: grep %s: %s\n", path, st.msg);
        regfree(&re);
        return xrdc_shellcode(&st) > 1 ? xrdc_shellcode(&st) : 2;
    }
    buf = (uint8_t *) malloc(1 << 20);
    if (buf == NULL) { xrdc_rfile_close(&f, &st); regfree(&re); return 2; }

    for (;;) {
        ssize_t got = xrdc_rfile_pread(&f, off, buf, 1 << 20, &st);
        ssize_t k;
        if (got < 0) { rc = 2; break; }
        if (got == 0) { break; }
        for (k = 0; k < got; k++) {
            if (buf[k] == '\n') {
                if (llen + 1 > lcap) {
                    char *nl = (char *) realloc(line, llen + 1);
                    if (nl == NULL) { rc = 2; break; }
                    line = nl; lcap = llen + 1;
                }
                line[llen] = '\0';
                lineno++;
                if (regexec(&re, line, 0, NULL, 0) == 0) {
                    matched = 1;
                    if (numbered) { printf("%ld:", lineno); }
                    printf("%s\n", line);
                }
                llen = 0;
            } else {
                if (llen + 1 > lcap) {
                    size_t ncap = lcap ? lcap * 2 : 256;
                    char  *nl = (char *) realloc(line, ncap);
                    if (nl == NULL) { rc = 2; break; }
                    line = nl; lcap = ncap;
                }
                line[llen++] = (char) buf[k];
            }
        }
        if (rc != 0) { break; }
        off += got;
    }
    free(buf);
    free(line);
    xrdc_rfile_close(&f, &st);
    regfree(&re);
    if (rc != 0) {
        fprintf(stderr, "xrdfs: grep %s: %s\n", path, st.msg);
        return rc;
    }
    return matched ? 0 : 1;
}


/* hexdump [-n BYTES] <path> — xxd-style dump: 8-hex-digit offset, 16 hex bytes, then
 * the printable-ASCII gutter. -n caps the number of bytes shown. */
int
do_hexdump(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status st;
    char        path[XRDC_PATH_MAX];
    const char *arg = NULL;
    long long   limit = -1;        /* -n; < 0 = whole file */
    int         i;
    xrdc_rfile  f;
    uint8_t    *buf;
    int64_t     off = 0;
    int         rc = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) { limit = strtoll(argv[++i], NULL, 10); }
        else { arg = argv[i]; }
    }
    if (arg == NULL) { fprintf(stderr, "usage: hexdump [-n BYTES] <path>\n"); return 50; }
    build_path(cwd, arg, path, sizeof(path));

    xrdc_status_clear(&st);
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: hexdump %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    buf = (uint8_t *) malloc(1 << 16);
    if (buf == NULL) { xrdc_rfile_close(&f, &st); return 51; }

    for (;;) {
        size_t  want = 1 << 16;
        ssize_t got, base;
        if (limit >= 0) {
            int64_t rem = limit - off;
            if (rem <= 0) { break; }
            if ((int64_t) want > rem) { want = (size_t) rem; }
        }
        got = xrdc_rfile_pread(&f, off, buf, want, &st);
        if (got < 0) { rc = -1; break; }
        if (got == 0) { break; }
        for (base = 0; base < got; base += 16) {
            ssize_t j, row = (got - base < 16) ? got - base : 16;
            printf("%08llx ", (unsigned long long) (off + base));
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
        off += got;
    }
    free(buf);
    xrdc_rfile_close(&f, &st);
    if (rc != 0) {
        fprintf(stderr, "xrdfs: hexdump %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    return 0;
}


/* dd [if=]<path> [bs=BYTES] [skip=BLOCKS] [count=BLOCKS] [rate=BYTES/s] — read a
 * windowed, optionally rate-limited slice of a remote file to stdout. bs defaults to
 * 1 MiB; the window starts at skip*bs and is count*bs bytes (count omitted = to EOF).
 * rate accepts a K/M/G suffix; 0 = unlimited. A one-line byte summary goes to stderr. */
int
do_dd(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status     st;
    char            path[XRDC_PATH_MAX];
    const char     *arg = NULL;
    int64_t         bs = 1 << 20, skip = 0, count = -1, want_total, off, produced = 0;
    double          rate = 0.0;
    int             i, rc = 0;
    xrdc_rfile      f;
    uint8_t        *buf;
    struct timespec start;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "bs=", 3) == 0) {
            bs = parse_bytes(argv[i] + 3);
            if (bs <= 0 || bs > XRDFS_DD_MAXBS) {
                fprintf(stderr, "xrdfs: dd: bad bs (max 256M)\n"); return 50;
            }
        } else if (strncmp(argv[i], "skip=", 5) == 0) {
            skip = strtoll(argv[i] + 5, NULL, 10);
            if (skip < 0) { fprintf(stderr, "xrdfs: dd: bad skip\n"); return 50; }
        } else if (strncmp(argv[i], "count=", 6) == 0) {
            count = strtoll(argv[i] + 6, NULL, 10);
            if (count < 0) { fprintf(stderr, "xrdfs: dd: bad count\n"); return 50; }
        } else if (strncmp(argv[i], "rate=", 5) == 0) {
            int64_t r = parse_bytes(argv[i] + 5);
            if (r < 0) { fprintf(stderr, "xrdfs: dd: bad rate\n"); return 50; }
            rate = (double) r;
        } else if (strncmp(argv[i], "if=", 3) == 0) {
            arg = argv[i] + 3;
        } else if (argv[i][0] != '-') {
            arg = argv[i];
        }
    }
    if (arg == NULL) {
        fprintf(stderr, "usage: dd [if=]<path> [bs=N] [skip=N] [count=N] [rate=R]\n");
        return 50;
    }
    build_path(cwd, arg, path, sizeof(path));
    off        = skip * bs;
    want_total = (count >= 0) ? count * bs : -1;

    xrdc_status_clear(&st);
    if (xrdc_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: dd %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    buf = (uint8_t *) malloc((size_t) bs);
    if (buf == NULL) {
        xrdc_rfile_close(&f, &st);
        fprintf(stderr, "xrdfs: dd: out of memory\n");
        return 51;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        size_t  want = (size_t) bs;
        ssize_t n;
        if (want_total >= 0) {
            int64_t rem = want_total - produced;
            if (rem <= 0) { break; }
            if ((int64_t) want > rem) { want = (size_t) rem; }
        }
        n = xrdc_rfile_pread(&f, off, buf, want, &st);
        if (n < 0) { rc = -1; break; }
        if (n == 0) { break; }
        if (fwrite(buf, 1, (size_t) n, stdout) != (size_t) n) {
            xrdc_status_set(&st, XRDC_ESOCK, 0, "stdout write failed");
            rc = -1; break;
        }
        off += n; produced += n;
        rate_pace(&start, produced, rate);
    }
    free(buf);
    xrdc_rfile_close(&f, &st);
    if (rc != 0) {
        fprintf(stderr, "xrdfs: dd %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    fprintf(stderr, "%lld bytes copied\n", (long long) produced);
    return 0;
}


/* upload [bs=BYTES] [rate=BYTES/s] [-f] <localfile|-> <remote-path> — write a local
 * file (or stdin "-") to a remote path, optionally rate-limited. Without -f the remote
 * must not already exist (kXR_new); -f truncates/overwrites. bs defaults to 1 MiB. */
int
do_upload(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status     st;
    char            rpath[XRDC_PATH_MAX];
    const char     *local = NULL, *remote = NULL;
    int64_t         bs = 1 << 20, off = 0;
    double          rate = 0.0;
    int             force = 0, i, fd, rc = 0;
    xrdc_rfile      f;
    uint8_t        *buf;
    struct timespec start;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "bs=", 3) == 0) {
            bs = parse_bytes(argv[i] + 3);
            if (bs <= 0 || bs > XRDFS_DD_MAXBS) {
                fprintf(stderr, "xrdfs: upload: bad bs (max 256M)\n"); return 50;
            }
        } else if (strncmp(argv[i], "rate=", 5) == 0) {
            int64_t r = parse_bytes(argv[i] + 5);
            if (r < 0) { fprintf(stderr, "xrdfs: upload: bad rate\n"); return 50; }
            rate = (double) r;
        } else if (strcmp(argv[i], "-f") == 0) {
            force = 1;
        } else if (local == NULL)  { local = argv[i]; }
        else if (remote == NULL)   { remote = argv[i]; }
    }
    if (local == NULL || remote == NULL) {
        fprintf(stderr, "usage: upload [bs=N] [rate=R] [-f] <localfile|-> <remote>\n");
        return 50;
    }

    fd = (strcmp(local, "-") == 0) ? 0 : open(local, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "xrdfs: upload: %s: %s\n", local, strerror(errno));
        return 50;
    }
    build_path(cwd, remote, rpath, sizeof(rpath));
    xrdc_status_clear(&st);
    if (xrdc_rfile_open_write(c, rpath, force ? 1 : 0, 0, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: upload %s: %s\n", rpath, st.msg);
        xrdc_cred_hint_for_status(&st, 1, stderr);
        if (fd > 0) { close(fd); }
        return xrdc_shellcode(&st);
    }
    buf = (uint8_t *) malloc((size_t) bs);
    if (buf == NULL) {
        xrdc_rfile_close(&f, &st);
        if (fd > 0) { close(fd); }
        fprintf(stderr, "xrdfs: upload: out of memory\n");
        return 51;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        ssize_t r = read(fd, buf, (size_t) bs);
        if (r < 0) {
            if (errno == EINTR) { continue; }
            fprintf(stderr, "xrdfs: upload: read %s: %s\n", local, strerror(errno));
            rc = -1; break;
        }
        if (r == 0) { break; }
        if (xrdc_rfile_pwrite(&f, off, buf, (size_t) r, &st) != 0) {
            fprintf(stderr, "xrdfs: upload %s: %s\n", rpath, st.msg);
            rc = xrdc_shellcode(&st); break;
        }
        off += r;
        rate_pace(&start, off, rate);
    }
    free(buf);
    xrdc_rfile_close(&f, &st);   /* commit */
    if (fd > 0) { close(fd); }
    if (rc != 0) { return rc < 0 ? 1 : rc; }
    fprintf(stderr, "%lld bytes uploaded to %s\n", (long long) off, rpath);
    return 0;
}


/* download [bs=BYTES] [rate=BYTES/s] [-f] <remote> [localfile|-] — read a remote file
 * to a local file (or stdout "-"), optionally rate-limited. The local destination
 * defaults to the remote basename in the current directory (like `get`). Without -f an
 * existing local file is not overwritten (O_EXCL). The rate-limit counterpart to
 * `upload`; for windowed/stdout reads use `dd`. */
int
do_download(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status     st;
    char            rpath[XRDC_PATH_MAX], namebuf[XRDC_PATH_MAX];
    const char     *remote = NULL, *local = NULL;
    int64_t         bs = 1 << 20, off = 0;
    double          rate = 0.0;
    int             force = 0, i, fd, rc = 0;
    xrdc_rfile      f;
    uint8_t        *buf;
    struct timespec start;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "bs=", 3) == 0) {
            bs = parse_bytes(argv[i] + 3);
            if (bs <= 0 || bs > XRDFS_DD_MAXBS) {
                fprintf(stderr, "xrdfs: download: bad bs (max 256M)\n"); return 50;
            }
        } else if (strncmp(argv[i], "rate=", 5) == 0) {
            int64_t r = parse_bytes(argv[i] + 5);
            if (r < 0) { fprintf(stderr, "xrdfs: download: bad rate\n"); return 50; }
            rate = (double) r;
        } else if (strcmp(argv[i], "-f") == 0) {
            force = 1;
        } else if (remote == NULL) { remote = argv[i]; }
        else if (local == NULL)    { local = argv[i]; }
    }
    if (remote == NULL) {
        fprintf(stderr, "usage: download [bs=N] [rate=R] [-f] <remote> [localfile|-]\n");
        return 50;
    }
    build_path(cwd, remote, rpath, sizeof(rpath));
    if (local == NULL) {   /* default: remote basename in the cwd (like get) */
        const char *base = strrchr(rpath, '/');
        base = (base != NULL) ? base + 1 : rpath;
        if (base[0] == '\0') {
            fprintf(stderr, "xrdfs: download: no local dest and remote has no basename\n");
            return 50;
        }
        snprintf(namebuf, sizeof(namebuf), "%s", base);
        local = namebuf;
    }

    if (strcmp(local, "-") == 0) {
        fd = 1;   /* stdout */
    } else {
        int flags = O_WRONLY | O_CREAT | (force ? O_TRUNC : O_EXCL);
        fd = open(local, flags, 0644);
        if (fd < 0) {
            fprintf(stderr, "xrdfs: download: %s: %s\n", local, strerror(errno));
            return 50;
        }
    }
    xrdc_status_clear(&st);
    if (xrdc_rfile_open_read(c, rpath, NULL, 0, -1, &f, &st) != 0) {
        fprintf(stderr, "xrdfs: download %s: %s\n", rpath, st.msg);
        if (fd > 1) { close(fd); }
        return xrdc_shellcode(&st);
    }
    buf = (uint8_t *) malloc((size_t) bs);
    if (buf == NULL) {
        xrdc_rfile_close(&f, &st);
        if (fd > 1) { close(fd); }
        fprintf(stderr, "xrdfs: download: out of memory\n");
        return 51;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        ssize_t n = xrdc_rfile_pread(&f, off, buf, (size_t) bs, &st);
        ssize_t w = 0;
        if (n < 0) {
            fprintf(stderr, "xrdfs: download %s: %s\n", rpath, st.msg);
            rc = xrdc_shellcode(&st); break;
        }
        if (n == 0) { break; }
        while (w < n) {
            ssize_t k = write(fd, buf + w, (size_t) (n - w));
            if (k < 0) {
                if (errno == EINTR) { continue; }
                fprintf(stderr, "xrdfs: download: write %s: %s\n", local, strerror(errno));
                rc = 1; break;
            }
            if (k == 0) { rc = 1; break; }
            w += k;
        }
        if (rc != 0) { break; }
        off += n;
        rate_pace(&start, off, rate);
    }
    free(buf);
    xrdc_rfile_close(&f, &st);
    if (fd > 1) { close(fd); }
    if (rc != 0) { return rc; }
    if (fd != 1) {   /* don't pollute a piped stdout with the summary */
        fprintf(stderr, "%lld bytes downloaded to %s\n", (long long) off, local);
    }
    return 0;
}


/* readv <path> <off1> <len1> [<off2> <len2> ...] — scatter-gather read (kXR_readv);
 * the requested segments are read in one round-trip and written, concatenated, to
 * stdout (so the bytes can be verified against the file). */
int
do_readv(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status    st;
    char           path[XRDC_PATH_MAX];
    xrdc_file      f;
    xrdc_readv_seg segs[XRDC_VEC_MAXSEGS];
    size_t         nseg = 0, i;
    int            a;
    ssize_t        got;
    int            rc = 0;

    if (argc < 4 || ((argc - 2) % 2) != 0) {
        fprintf(stderr, "usage: readv <path> <off len>...\n");
        return 50;
    }
    build_path(cwd, argv[1], path, sizeof(path));
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
    xrdc_status_clear(&st);
    if (xrdc_file_open_read(c, path, &f, &st) != 0) {
        for (i = 0; i < nseg; i++) { free(segs[i].buf); }
        fprintf(stderr, "xrdfs: readv open %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    got = xrdc_file_readv(c, &f, segs, nseg, &st);
    if (got < 0) {
        fprintf(stderr, "xrdfs: readv %s: %s\n", path, st.msg);
        rc = xrdc_shellcode(&st);
    } else {
        for (i = 0; i < nseg; i++) {
            fwrite(segs[i].buf, 1, segs[i].got, stdout);   /* actual bytes read */
        }
    }
    xrdc_file_close(c, &f, &st);
    for (i = 0; i < nseg; i++) { free(segs[i].buf); }
    return rc;
}


/* writev <path> <off1> <hexdata1> [<off2> <hexdata2> ...] — scatter-gather write
 * (kXR_writev): each segment's hex-encoded bytes are written at its offset in one
 * round-trip (the file is created/truncated first). */
int
do_writev(xrdc_conn *c, const char *cwd, int argc, char **argv)
{
    xrdc_status     st;
    char            path[XRDC_PATH_MAX];
    xrdc_file       f;
    xrdc_writev_seg segs[XRDC_VEC_MAXSEGS];
    size_t          nseg = 0, i;
    int             a, rc = 0;

    if (argc < 4 || ((argc - 2) % 2) != 0) {
        fprintf(stderr, "usage: writev <path> <off hexdata>...\n");
        return 50;
    }
    build_path(cwd, argv[1], path, sizeof(path));
    for (a = 2; a + 1 < argc && nseg < XRDC_VEC_MAXSEGS; a += 2) {
        const char *hex = argv[a + 1];
        size_t      hl = strlen(hex), n = hl / 2, j;
        uint8_t    *d;
        if (hl == 0 || (hl % 2) != 0) {
            for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
            fprintf(stderr, "xrdfs: writev: bad hex data\n");
            return 50;
        }
        d = malloc(n);
        if (d == NULL) {
            for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
            fprintf(stderr, "xrdfs: writev: out of memory\n");
            return 51;
        }
        for (j = 0; j < n; j++) {
            unsigned v;
            if (sscanf(hex + 2 * j, "%2x", &v) != 1) {
                free(d);
                for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
                fprintf(stderr, "xrdfs: writev: bad hex data\n");
                return 50;
            }
            d[j] = (uint8_t) v;
        }
        {
            unsigned long long off;
            if (parse_u64_strict(argv[a], &off) != 0) {
                free(d);
                for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
                fprintf(stderr, "xrdfs: writev: bad offset '%s'\n", argv[a]);
                return 50;
            }
            segs[nseg].offset = (int64_t) off;
        }
        segs[nseg].len    = n;
        segs[nseg].data   = d;
        nseg++;
    }
    xrdc_status_clear(&st);
    if (xrdc_file_open_write(c, path, 1 /*force*/, 0 /*posc*/, &f, &st) != 0) {
        for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
        fprintf(stderr, "xrdfs: writev open %s: %s\n", path, st.msg);
        return xrdc_shellcode(&st);
    }
    if (xrdc_file_writev(c, &f, segs, nseg, 1 /*sync*/, &st) != 0) {
        fprintf(stderr, "xrdfs: writev %s: %s\n", path, st.msg);
        rc = xrdc_shellcode(&st);
    }
    xrdc_file_close(c, &f, &st);
    for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
    return rc;
}
