/*
 * xrdfs_data_xfer_vec.c — xrdfs scatter/gather vector ops: readv / writev.
 *
 * Phase-38 split of xrdfs_data_xfer.c; behaviour-identical. The bulk upload/
 * download half stays in xrdfs_data_xfer.c; the vectored segment ops move here
 * to hold each TU within the size budget. Both share apps/fs/xrdfs_internal.h,
 * where every do_* entry point is declared. No goto.
 */
#include "xrdfs_internal.h"
#include "brix_ops.h"              /* brix_cli_parse_io_uring, brix_readv_seg */
#include "fs/vfs.h"

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
        return xrdfs_report_err("readv open", path, &st, 0, c);
    }
    got = brix_file_readv(c, &f, segs, nseg, &st);
    if (got < 0) {
        rc = xrdfs_report_err("readv", path, &st, 0, c);
    } else {
        for (i = 0; i < nseg; i++) {
            fwrite(segs[i].buf, 1, segs[i].got, stdout);   /* actual bytes read */
        }
    }
    brix_file_close(c, &f, &st);
    for (i = 0; i < nseg; i++) { free(segs[i].buf); }
    return rc;
}


/* ---- Parse readvm triples + open each segment's file (dedup) ----
 *
 * WHAT: Fills segs[] (allocating a receive buffer each) and segfile[] (the
 *       open handle for each segment, reusing one when a path repeats) from
 *       the `<path> <off> <len>` argv triples. Sets *nseg / *nopen to what was
 *       actually allocated/opened so the caller's single cleanup path frees
 *       exactly those on any outcome. Returns 0 / shell code.
 *
 * WHY:  Extracting setup keeps do_readvm a flat setup→run→cleanup sequence
 *       with ONE cleanup site (no goto; coding-standards §4).
 *
 * HOW:  Parse loop allocates per segment; open loop dedups by path string.
 */
static int
readvm_setup(brix_conn *c, const char *cwd, int argc, char **argv,
             brix_readv_seg *segs, size_t *nseg, brix_file *files,
             brix_file **segfile, size_t *nopen)
{
    char       paths[XRDC_VEC_MAXSEGS][XRDC_PATH_MAX];
    brix_status st;
    int         a;

    for (a = 1; a + 2 < argc && *nseg < XRDC_VEC_MAXSEGS; a += 3) {
        unsigned long long off, len;
        size_t             s = *nseg;

        if (parse_u64_strict(argv[a + 1], &off) != 0
            || parse_u64_strict(argv[a + 2], &len) != 0) {
            fprintf(stderr, "xrdfs: readvm: bad offset/length '%s %s'\n",
                    argv[a + 1], argv[a + 2]);
            return 50;
        }
        build_path(cwd, argv[a], paths[s], sizeof(paths[s]));
        segs[s].offset = (int64_t) off;
        segs[s].len    = (size_t) len;
        segs[s].got    = 0;
        segs[s].buf    = malloc(len ? (size_t) len : 1);
        if (segs[s].buf == NULL) {
            fprintf(stderr, "xrdfs: readvm: out of memory\n");
            return 51;
        }
        (*nseg)++;
    }

    for (size_t i = 0; i < *nseg; i++) {
        size_t j;

        segfile[i] = NULL;
        for (j = 0; j < i; j++) {
            if (strcmp(paths[i], paths[j]) == 0) {
                segfile[i] = segfile[j];
                break;
            }
        }
        if (segfile[i] != NULL) {
            continue;
        }
        brix_status_clear(&st);
        if (brix_file_open_read(c, paths[i], &files[*nopen], &st) != 0) {
            return xrdfs_report_err("readvm open", paths[i], &st, 0, c);
        }
        segfile[i] = &files[(*nopen)++];
    }
    return 0;
}


/* ---- readvm: per-segment-fhandle scatter-gather across MULTIPLE files ----
 *
 * WHAT: `readvm <path> <off> <len> [<path> <off> <len> ...]` reads one segment
 *       from each named file — all in ONE kXR_readv — and writes the segments,
 *       concatenated in request order, to stdout. Returns 0 / shell code.
 *
 * WHY:  §7.15 — stock's readahead_list carries a per-segment fhandle so a
 *       single readv can gather from many open files; BriX's single-handle
 *       readv could not express it. Exercises brix_file_readv_multi.
 *
 * HOW:  readvm_setup opens the files + builds the segments; one
 *       brix_file_readv_multi; emit; ONE cleanup path closes every opened
 *       handle and frees every segment buffer regardless of where we stopped.
 */
int
do_readvm(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_readv_seg segs[XRDC_VEC_MAXSEGS];
    brix_file      files[XRDC_VEC_MAXSEGS];
    brix_file     *segfile[XRDC_VEC_MAXSEGS];
    size_t         nseg = 0, nopen = 0, i;
    int            rc;

    if (argc < 4 || ((argc - 1) % 3) != 0) {
        fprintf(stderr, "usage: readvm <path> <off> <len> "
                        "[<path> <off> <len> ...]\n");
        return 50;
    }

    rc = readvm_setup(c, cwd, argc, argv, segs, &nseg, files, segfile, &nopen);
    if (rc == 0) {
        brix_status st;
        ssize_t     got;

        brix_status_clear(&st);
        got = brix_file_readv_multi(c, segfile, segs, nseg, &st);
        if (got < 0) {
            rc = xrdfs_report_err("readvm", argv[1], &st, 0, c);
        } else {
            for (i = 0; i < nseg; i++) {
                fwrite(segs[i].buf, 1, segs[i].got, stdout);
            }
        }
    }

    for (i = 0; i < nopen; i++) {
        brix_status tw;
        brix_status_clear(&tw);
        brix_file_close(c, &files[i], &tw);
    }
    for (i = 0; i < nseg; i++) {
        free(segs[i].buf);
    }
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
        return xrdfs_report_err("writev open", path, &st, 1, c);
    }
    if (brix_file_writev(c, &f, segs, nseg, 1 /*sync*/, &st) != 0) {
        rc = xrdfs_report_err("writev", path, &st, 1, c);
    }
    brix_file_close(c, &f, &st);
    for (i = 0; i < nseg; i++) { free((void *) segs[i].data); }
    return rc;
}


