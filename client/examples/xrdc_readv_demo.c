/*
 * xrdc_readv_demo.c — exercise libxrdc's scatter-gather read (kXR_readv) with
 *                     caller-chosen, variably-sized segments.
 *
 * Issues ONE xrdc_file_readv() for every "<off>:<len>" segment given on the
 * command line, writes each segment's actually-delivered bytes (in request
 * order, concatenated) to <outfile>, and prints one line per segment:
 *     seg <i> <off> <req_len> <got>
 * plus a trailing "total <bytes>".  `got` may be < req_len when the server caps
 * the element (xrootd_readv_segment_size) or the read runs short of EOF — which
 * is exactly the variable-block behaviour a test wants to verify.
 *
 *   cc xrdc_readv_demo.c $(pkg-config --cflags --libs libxrdc) -o demo
 */
#include "xrdc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
    xrdc_url        u;
    xrdc_conn       c;
    xrdc_status     st;
    xrdc_file       f;
    xrdc_readv_seg *segs;
    size_t          nseg, i;
    FILE           *out;
    ssize_t         total;

    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <url> <path> <outfile> <off:len> [off:len ...]\n",
                argv[0]);
        return 2;
    }
    nseg = (size_t) (argc - 4);
    if (nseg > XRDC_VEC_MAXSEGS) {
        fprintf(stderr, "too many segments (%zu > %d)\n", nseg, XRDC_VEC_MAXSEGS);
        return 2;
    }

    segs = calloc(nseg, sizeof(*segs));
    if (segs == NULL) { fprintf(stderr, "oom\n"); return 1; }

    for (i = 0; i < nseg; i++) {
        long long     off;
        unsigned long len;
        if (sscanf(argv[4 + i], "%lld:%lu", &off, &len) != 2) {
            fprintf(stderr, "bad segment '%s' (want off:len)\n", argv[4 + i]);
            return 2;
        }
        segs[i].offset = (int64_t) off;
        segs[i].len    = (size_t) len;
        segs[i].buf    = malloc(len ? len : 1);   /* caller-owned, >= len */
        if (segs[i].buf == NULL) { fprintf(stderr, "oom\n"); return 1; }
    }

    xrdc_status_clear(&st);
    if (xrdc_url_parse(argv[1], &u, &st) != 0) {
        fprintf(stderr, "url: %s\n", st.msg); return 1;
    }
    if (xrdc_connect(&c, &u, NULL, &st) != 0) {
        fprintf(stderr, "connect: %s\n", st.msg); return 1;
    }
    if (xrdc_file_open_read(&c, argv[2], &f, &st) != 0) {
        fprintf(stderr, "open: %s\n", st.msg); xrdc_close(&c); return 1;
    }

    total = xrdc_file_readv(&c, &f, segs, nseg, &st);
    if (total < 0) {
        fprintf(stderr, "readv: %s\n", st.msg);
        xrdc_file_close(&c, &f, &st); xrdc_close(&c); return 1;
    }

    out = fopen(argv[3], "wb");
    if (out == NULL) { fprintf(stderr, "cannot open outfile\n"); return 1; }
    for (i = 0; i < nseg; i++) {
        printf("seg %zu %lld %zu %zu\n", i, (long long) segs[i].offset,
               segs[i].len, segs[i].got);
        if (segs[i].got > 0) {
            fwrite(segs[i].buf, 1, segs[i].got, out);
        }
        free(segs[i].buf);
    }
    fclose(out);
    printf("total %zd\n", total);
    free(segs);

    xrdc_file_close(&c, &f, &st);
    xrdc_close(&c);
    return 0;
}
