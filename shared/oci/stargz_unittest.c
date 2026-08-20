/*
 * stargz_unittest.c — CLI driver for the eStargz writer (phase-104 D15.8).
 *
 *   stargz_unittest convert <in_layer> <out_blob>
 *
 * Converts one layer blob (gzip/zstd/plain tar) into an eStargz blob and
 * prints one stats line:
 *
 *   stats blob=<digest> diffid=<digest> toc=<digest> size=N entries=N
 *         dropped=N
 *
 * or "ERROR: <msg>" with exit 1 on refusal. Deliberately a driver, not a
 * suite: the pytest lane builds the fixtures with Python's tarfile and then
 * checks the OUTPUT against the format spec — footer arithmetic, member
 * boundaries, TOC digests — which is work Python's zlib does far better
 * than a C harness would.
 *
 * Compiles without nginx (catalog_write.c carries the xattr wire helpers and
 * drags catalog.c + hash.c):
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/stargz_ut \
 *       shared/oci/stargz_unittest.c shared/oci/stargz.c \
 *       shared/oci/stargz_toc.c shared/oci/tar.c shared/oci/tar_pax.c \
 *       shared/oci/tar_digest.c shared/oci/digest.c \
 *       shared/cvmfs/catalog/catalog_write.c shared/cvmfs/catalog/catalog.c \
 *       shared/cvmfs/grammar/hash.c -lsqlite3 -lcrypto -lz
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "oci/stargz.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int usage(void) {
    fprintf(stderr, "usage: stargz_unittest convert <in_layer> <out_blob>\n");
    return 2;
}

int main(int argc, char **argv) {
    brix_stargz_stats_t st;
    char                err[512];
    int                 in, out, rc;

    if (argc != 4 || strcmp(argv[1], "convert") != 0)
        return usage();

    in = open(argv[2], O_RDONLY);
    if (in < 0) {
        printf("ERROR: cannot open source %s\n", argv[2]);
        return 1;
    }
    out = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        printf("ERROR: cannot create destination %s\n", argv[3]);
        close(in);
        return 1;
    }

    rc = brix_stargz_convert(in, out, &st, err, sizeof(err));
    close(in);
    close(out);
    if (rc != 0) {
        printf("ERROR: %s\n", err);
        return 1;
    }

    printf("stats blob=%s diffid=%s toc=%s size=%lld entries=%lld "
           "dropped=%lld\n",
           st.blob_digest, st.diffid, st.toc_digest, st.blob_size,
           (long long) st.entries, (long long) st.dropped);
    return 0;
}
