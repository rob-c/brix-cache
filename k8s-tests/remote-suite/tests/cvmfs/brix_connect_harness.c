/*
 * brix_connect_harness.c — call the REAL brix_tcp_connect (from libbrix) so both
 * its paths are exercised: direct (no proxy env) and CONNECT-tunnelled (proxy env
 * set). Prints the fd; exit 0 iff a socket was returned.
 *
 * usage: harness <host> <port>
 */
#include "brix.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: harness host port\n"); return 2; }
    brix_status st;
    brix_status_clear(&st);
    int fd = brix_tcp_connect(argv[1], atoi(argv[2]), 5000, &st);
    if (fd < 0) {
        fprintf(stderr, "connect failed: %s\n", st.msg);
        return 1;
    }
    printf("connected fd=%d\n", fd);
    close(fd);
    return 0;
}
