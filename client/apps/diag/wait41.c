/*
 * wait41.c — block until an XRootD server accepts connections.
 *
 * WHAT: `wait41 [--timeout S] [--full] host[:port]` — poll until the server is
 *       reachable (TCP connect; with --full, a complete handshake+login). Exits 0
 *       when ready, non-zero on timeout. The readiness helper the harness wants.
 * WHY:  A tiny front-end over the client transport/session layer. libXrdCl-free.
 * HOW:  Loop brix_tcp_connect (or brix_connect with --full) until a deadline,
 *       sleeping 1s between attempts.
 */
#include "brix.h"
#include "core/compat/crypto.h"
#include "core/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Real main; dispatched from xrddiag (multi-call, see xrddiag.c). */
int
brix_wait41_main(int argc, char **argv)
{
    brix_url    u;
    brix_status st;
    const char *endpoint = NULL;
    int         timeout_s = 60, full = 0, i;
    time_t      deadline;

    /* --help / --version before main loop. */
    if (argc >= 2) {
        if (strcmp(argv[1], "--version") == 0) {
            printf("%s (BriX-Cache client) %s\n", argv[0], brix_client_version());
            return 0;
        }
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("usage: %s [--timeout S] [--full] host[:port]\n"
                   BRIX_USAGE_FOOTER("wait41"),
                   argv[0]);
            return 0;
        }
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            timeout_s = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--full") == 0) {
            full = 1;
        } else {
            endpoint = argv[i];
        }
    }
    if (endpoint == NULL) {
        fprintf(stderr, "usage: %s [--timeout S] [--full] host[:port]\n", argv[0]);
        return 50;
    }

    brix_crypto_init();
    brix_status_clear(&st);
    if (brix_endpoint_parse(endpoint, &u, &st) != 0) {
        fprintf(stderr, "%s: %s\n", argv[0], st.msg);
        return 50;
    }

    deadline = time(NULL) + timeout_s;
    for (;;) {
        brix_status_clear(&st);
        if (full) {
            brix_conn c;
            if (brix_connect(&c, &u, NULL, &st) == 0) {
                brix_close(&c);
                printf("%s:%d ready\n", u.host, u.port);
                return 0;
            }
        } else {
            int fd = brix_tcp_connect(u.host, u.port, 1000, &st);
            if (fd >= 0) {
                close(fd);
                printf("%s:%d ready\n", u.host, u.port);
                return 0;
            }
        }
        if (time(NULL) >= deadline) {
            fprintf(stderr, "%s: %s:%d not ready after %ds\n",
                    argv[0], u.host, u.port, timeout_s);
            return 1;
        }
        sleep(1);
    }
}
