/*
 * wait41.c — block until an XRootD server accepts connections.
 *
 * WHAT: `wait41-brix [--timeout S] [--full] host[:port]` — poll until the server is
 *       reachable (TCP connect; with --full, a complete handshake+login). Exits 0
 *       when ready, non-zero on timeout. The readiness helper the harness wants.
 * WHY:  A tiny front-end over the client transport/session layer. libXrdCl-free.
 * HOW:  Loop brix_tcp_connect (or brix_connect with --full) until a deadline,
 *       sleeping 1s between attempts.
 */
#include "brix.h"
#include "core/compat/crypto.h"
#include "core/version.h"
#include "core/progname.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* WHAT: Print wait41 command usage.
 * WHY: Keep all help paths identical.
 * HOW: Emit the synopsis and shared client footer to stdout. */
static int
wait41_usage(const char *prog)
{
    printf("usage: %s [--timeout S] [--full] host[:port]\n",
           brix_prog_base(prog));
    brix_usage_footer(stdout, prog);
    return 0;
}


/* WHAT: Parse wait41 options and positional endpoint.
 * WHY: Separate command-line policy from readiness polling.
 * HOW: Update timeout/full/endpoint and signal immediate help or version exit. */
static int
wait41_options(int argc, char **argv, const char **endpoint, int *timeout_s,
    int *full, int *exit_now)
{
    int i;

    *exit_now = 0;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("%s (BriX-Cache client) %s\n", brix_prog_base(argv[0]),
                   brix_client_version());
            *exit_now = 1;
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            *exit_now = 1;
            return wait41_usage(argv[0]);
        }
        if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            *timeout_s = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--full") == 0) {
            *full = 1;
        } else {
            *endpoint = argv[i];
        }
    }
    return 0;
}


/* WHAT: Attempt one readiness probe.
 * WHY: Keep full-session and TCP-only resource handling out of the retry loop.
 * HOW: Connect using the selected mode, close successful resources, and report
 *      a boolean ready result.
 */
static int
wait41_probe(const brix_url *url, int full, brix_status *status)
{
    if (full) {
        brix_conn connection;

        if (brix_connect(&connection, url, NULL, status) != 0) {
            return 0;
        }
        brix_close(&connection);
        return 1;
    }
    {
        int fd = brix_tcp_connect(url->host, url->port, 1000, status);

        if (fd < 0) {
            return 0;
        }
        close(fd);
        return 1;
    }
}


/* Real main; dispatched from xrddiag (multi-call, see xrddiag.c). */
int
brix_wait41_main(int argc, char **argv)
{
    brix_url    u;
    brix_status st;
    const char *endpoint = NULL;
    int         timeout_s = 60, full = 0;
    int         exit_now;
    time_t      deadline;

    wait41_options(argc, argv, &endpoint, &timeout_s, &full, &exit_now);
    if (exit_now) {
        return 0;
    }
    if (endpoint == NULL) {
        fprintf(stderr, "usage: %s [--timeout S] [--full] host[:port]\n", brix_prog_base(argv[0]));
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
        if (wait41_probe(&u, full, &st)) {
            printf("%s:%d ready\n", u.host, u.port);
            return 0;
        }
        if (time(NULL) >= deadline) {
            fprintf(stderr, "%s: %s:%d not ready after %ds\n",
                    argv[0], u.host, u.port, timeout_s);
            return 1;
        }
        sleep(1);
    }
}
