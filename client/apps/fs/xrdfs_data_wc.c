/*
 * xrdfs_data_wc.c — xrdfs `wc` word/line/byte-count command.
 *
 * WHAT: the wc subcommand — stream a remote object once and count lines, words
 *       and bytes, rendering the standard wc columns.
 * WHY:  Phase-38 split of xrdfs_data.c to keep each TU under the 600-line cap,
 *       one concept per file (coding-standards.md §1).
 * HOW:  behavior-identical extraction; do_wc is declared in xrdfs_internal.h and
 *       dispatched from xrdfs.c exactly as before.
 */
#include "xrdfs_internal.h"

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
        return xrdfs_report_err("wc", path, st, 0, c);
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
        return xrdfs_report_err("wc", path, st, 0, c);
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
        return xrdfs_report_err("wc", path, &st, 0, c);
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
