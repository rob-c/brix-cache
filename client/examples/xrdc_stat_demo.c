/*
 * xrdc_stat_demo.c — minimal public-API consumer of libxrdc.
 *
 * Proves the promoted library is usable by an external C program: it links only
 * libxrdc (+ libxrdproto + OpenSSL/zlib via pkg-config), not libXrdCl. Builds via
 *   cc xrdc_stat_demo.c $(pkg-config --cflags --libs libxrdc) -o demo
 * and stats a path over an anonymous root:// connection.
 */
#include "xrdc.h"

#include <stdio.h>

int
main(int argc, char **argv)
{
    xrdc_url      u;
    xrdc_conn     c;
    xrdc_status   st;
    xrdc_statinfo si;

    if (argc != 3) {
        fprintf(stderr, "usage: %s root://host[:port] /path\n", argv[0]);
        return 2;
    }
    xrdc_status_clear(&st);
    if (xrdc_url_parse(argv[1], &u, &st) != 0) {
        fprintf(stderr, "url: %s\n", st.msg);
        return 1;
    }
    if (xrdc_connect(&c, &u, NULL, &st) != 0) {
        fprintf(stderr, "connect: %s\n", st.msg);
        return 1;
    }
    if (xrdc_stat(&c, argv[2], &si, &st) != 0) {
        fprintf(stderr, "stat: %s\n", st.msg);
        xrdc_close(&c);
        return 1;
    }
    printf("Size: %lld\n", (long long) si.size);
    xrdc_close(&c);
    return 0;
}
