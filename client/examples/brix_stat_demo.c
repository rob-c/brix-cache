/*
 * brix_stat_demo.c — minimal public-API consumer of libbrix.
 *
 * Proves the promoted library is usable by an external C program: it links only
 * libbrix (+ libxrdproto + OpenSSL/zlib via pkg-config), not libXrdCl. Builds via
 *   cc brix_stat_demo.c $(pkg-config --cflags --libs libbrix) -o demo
 * and stats a path over an anonymous root:// connection.
 */
#include "brix.h"

#include <stdio.h>

int
main(int argc, char **argv)
{
    brix_url      u;
    brix_conn     c;
    brix_status   st;
    brix_statinfo si;

    if (argc != 3) {
        fprintf(stderr, "usage: %s root://host[:port] /path\n", argv[0]);
        return 2;
    }
    brix_status_clear(&st);
    if (brix_url_parse(argv[1], &u, &st) != 0) {
        fprintf(stderr, "url: %s\n", st.msg);
        return 1;
    }
    if (brix_connect(&c, &u, NULL, &st) != 0) {
        fprintf(stderr, "connect: %s\n", st.msg);
        return 1;
    }
    if (brix_stat(&c, argv[2], &si, &st) != 0) {
        fprintf(stderr, "stat: %s\n", st.msg);
        brix_close(&c);
        return 1;
    }
    printf("Size: %lld\n", (long long) si.size);
    brix_close(&c);
    return 0;
}
