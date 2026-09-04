/*
 * xrdfs_data_content.c — xrdfs content-inspection data ops (Phase-38 split).
 *
 * WHAT: the content-examining busybox ops — cmp (byte compare two files),
 *       grep (regex scan), hexdump (canonical hex+ASCII), and dd (windowed,
 *       rate-limited block copy to stdout).
 * WHY:  split from xrdfs_data.c to hold each TU within the Phase-38 size
 *       budget; these ops share the "pull bytes and analyse/transform them"
 *       shape, distinct from the plain text viewers and the bulk-transfer ops.
 *       Every do_* entry point is declared in xrdfs_internal.h.
 * HOW:  each do_* parses its operands into a file-local arg bundle (kept under
 *       the 5-parameter gate), then scans/dumps over an open brix_rfile. No goto.
 */
#include "xrdfs_internal.h"

/* dd operand set: source path plus the windowing / rate knobs. */
typedef struct {
    const char *arg;     /* source path (if= or bare), NULL if none given */
    int64_t     bs;      /* block size in bytes */
    int64_t     skip;    /* leading blocks to skip */
    int64_t     count;   /* blocks to copy (-1 = to EOF) */
    double      rate;    /* bytes/s throttle (0 = unlimited) */
} dd_args_t;

/* Read a whole remote file into a malloc'd buffer (*out, *len). Caller frees. 0/-1. */
int
slurp_file(brix_conn *c, const char *path, uint8_t **out, int64_t *len, brix_status *st)
{
    return brix_rfile_slurp(c, path, NULL, -1, out, len, st);
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
            return xrdfs_report_err("cmp", p1, &st, 0, c);
        }
        if (slurp_file(c, p2, &b2, &l2, &st) != 0) {
            free(b1);
            return xrdfs_report_err("cmp", p2, &st, 0, c);
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

typedef struct {
    const regex_t *regex;
    int            numbered;
    grep_scan_t   *scan;
} grep_sink_t;

static int
grep_sink(const uint8_t *data, size_t len, int64_t offset, void *arg,
          brix_status *st)
{
    grep_sink_t *sink = arg;

    (void) offset;
    if (grep_scan_chunk(data, (ssize_t) len, sink->regex,
                        sink->numbered, sink->scan) == 0) {
        return 0;
    }
    brix_status_set(st, XRDC_EIO, ENOMEM, "grep: out of memory");
    return -1;
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
    grep_scan_t g = { NULL, 0, 0, 0, 0 };
    grep_sink_t sink;
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
        rc = xrdfs_report_err("grep", path, &st, 0, c);
        regfree(&re);
        return rc > 1 ? rc : 2;
    }
    sink.regex = &re;
    sink.numbered = a.numbered;
    sink.scan = &g;
    rc = brix_rfile_pump(&f, 0, -1, 0, grep_sink, &sink, NULL, &st);
    free(g.line);
    brix_rfile_close(&f, &st);
    regfree(&re);
    if (rc != 0) {
        (void) xrdfs_report_err("grep", path, &st, 0, c);
        return 2;
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


static int
hexdump_sink(const uint8_t *data, size_t len, int64_t offset, void *arg,
             brix_status *st)
{
    size_t base;

    (void) arg;
    (void) st;
    for (base = 0; base < len; base += 16) {
        size_t row = len - base < 16 ? len - base : 16;
        hexdump_row(data, (ssize_t) base, (ssize_t) row,
                    offset + (int64_t) base);
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
    int         rc = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) { limit = strtoll(argv[++i], NULL, 10); }
        else { arg = argv[i]; }
    }
    if (arg == NULL) { fprintf(stderr, "usage: hexdump [-n BYTES] <path>\n"); return 50; }
    build_path(cwd, arg, path, sizeof(path));

    brix_status_clear(&st);
    if (brix_rfile_open_read(c, path, NULL, 0, -1, &f, &st) != 0) {
        return xrdfs_report_err("hexdump", path, &st, 0, c);
    }
    rc = brix_rfile_pump(&f, 0, limit, 1 << 16,
                         hexdump_sink, NULL, NULL, &st);
    brix_rfile_close(&f, &st);
    if (rc != 0) {
        return xrdfs_report_err("hexdump", path, &st, 0, c);
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

typedef struct {
    const struct timespec *start;
    double                 rate;
    int64_t                produced;
} dd_sink_t;

static int
dd_sink(const uint8_t *data, size_t len, int64_t offset, void *arg,
        brix_status *st)
{
    dd_sink_t *sink = arg;

    (void) offset;
    if (fwrite(data, 1, len, stdout) != len) {
        brix_status_set(st, XRDC_EIO, errno, "stdout write failed");
        return -1;
    }
    sink->produced += (int64_t) len;
    rate_pace(sink->start, sink->produced, sink->rate);
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
    struct timespec start;
    dd_sink_t       sink;

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
        return xrdfs_report_err("dd", path, &st, 0, c);
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    sink.start = &start;
    sink.rate = a.rate;
    sink.produced = 0;
    rc = brix_rfile_pump(&f, off, want_total, (size_t) a.bs,
                         dd_sink, &sink, &produced, &st);
    produced = sink.produced;
    brix_rfile_close(&f, &st);
    if (rc != 0) {
        return xrdfs_report_err("dd", path, &st, 0, c);
    }
    fprintf(stderr, "%lld bytes copied\n", (long long) produced);
    return 0;
}
