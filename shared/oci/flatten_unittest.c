/*
 * flatten_unittest.c — CLI driver for the layer flattener (phase-104 D7.4).
 *
 *   flatten_unittest apply [--strict] [--max-bytes N] [--max-entries N]
 *                          [--squash UID:GID] <upper_dir> <layer>...
 *
 * Applies the layers in order (base first) into <upper_dir> and prints one
 * accumulated stats line:
 *
 *   stats files=N dirs=N links=N wh=N opq=N skip=N bytes=N
 *
 * or "ERROR: <msg>" with exit 1 on refusal. Deliberately a driver, not a
 * suite: the pytest lane builds every fixture — including the hostile ones
 * (`..` members, absolute paths, marker smuggling, symlink-escape layer
 * pairs) — with Python's tarfile, where an entry name is just a string.
 *
 * Compiles without nginx (catalog_write.c carries the xattr wire helpers and
 * drags catalog.c + hash.c):
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/flatten_ut \
 *       shared/oci/flatten_unittest.c shared/oci/flatten.c shared/oci/tar.c \
 *       shared/oci/tar_pax.c shared/cvmfs/catalog/catalog_write.c \
 *       shared/cvmfs/catalog/catalog.c shared/cvmfs/grammar/hash.c \
 *       -lsqlite3 -lcrypto -lz
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "oci/flatten.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int usage(void) {
    fprintf(stderr,
            "usage: flatten_unittest apply [--strict] [--max-bytes N]\n"
            "       [--max-entries N] [--squash UID:GID] <upper> <layer>...\n");
    return 2;
}

int main(int argc, char **argv) {
    brix_flatten_opts_t  o = { 0 };
    brix_flatten_stats_t st = { 0 };
    char                 err[512];
    int                  i = 2;

    if (argc < 2 || strcmp(argv[1], "apply") != 0)
        return usage();

    for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++) {
        if (strcmp(argv[i], "--strict") == 0) {
            o.strict = 1;
        } else if (strcmp(argv[i], "--max-bytes") == 0 && i + 1 < argc) {
            o.max_total_bytes = strtoll(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--max-entries") == 0 && i + 1 < argc) {
            o.max_entries = strtoll(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--squash") == 0 && i + 1 < argc) {
            unsigned long u, g;

            if (sscanf(argv[++i], "%lu:%lu", &u, &g) != 2)
                return usage();
            o.squash_uid = (uid_t) u;
            o.squash_gid = (gid_t) g;
            o.squash     = 1;
        } else {
            return usage();
        }
    }
    if (argc - i < 2)
        return usage();
    o.upper_dir = argv[i++];

    for (; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        int rc;

        if (fd < 0) {
            printf("ERROR: cannot open layer %s\n", argv[i]);
            return 1;
        }
        rc = brix_flatten_layer(&o, fd, &st, err, sizeof(err));
        close(fd);
        if (rc != 0) {
            printf("ERROR: %s\n", err);
            return 1;
        }
    }

    printf("stats files=%lld dirs=%lld links=%lld wh=%lld opq=%lld "
           "skip=%lld toc=%lld bytes=%lld\n",
           (long long) st.files, (long long) st.dirs, (long long) st.links,
           (long long) st.whiteouts, (long long) st.opaques,
           (long long) st.skipped_special, (long long) st.skipped_toc,
           (long long) st.bytes);
    return 0;
}
