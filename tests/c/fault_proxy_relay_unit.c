/*
 * Finite driver for one production fault-proxy relay connection.
 *
 * WHAT: Relay a passed client socket to a loopback test upstream, then report
 *       the production counters and exit when that connection finishes.
 * WHY:  Byte transformations and teardown can be asserted without killing an
 *       endless daemon; normal exit retains the actual relay's gcov counters.
 * HOW:  Link the full shipped tool, initialize its real route/control state,
 *       and run relay_thread synchronously with the normal connection context.
 */
#include "brix_fault_proxy_state.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#undef main

/* ---- Apply the requested fault configuration ----
 * WHAT: Return zero for accepted commands, two for a rejected command.
 * WHY:  A test must never claim a fault was exercised when its setup failed.
 * HOW:  1. Dispatch each command. 2. Refuse any error reply before relaying.
 */
static int
configure_faults(int argc, char **argv)
{
    for (int index = 4; index < argc; index++) {
        char reply[16384] = "";
        apply_command(argv[index], reply, sizeof(reply));
        if (strncmp(reply, "err", 3) == 0) {
            fputs(reply, stderr);
            return 2;
        }
    }
    return 0;
}

/* ---- Relay one connection and return its observed counters ----
 * WHAT: Return zero after the real relay closes, two for invalid driver setup.
 * WHY:  The test supplies the accepted socket; every data-path operation stays
 *       in production code, including dial, fault application and teardown.
 * HOW:  1. Initialize defaults and the route. 2. Transfer the heap context to
 *       relay_thread. 3. Emit its counters after it returns and exit normally.
 */
int
main(int argc, char **argv)
{
    if (argc < 4) {
        return 2;
    }
    clear_all();
    signal(SIGPIPE, SIG_IGN);
    clock_gettime(CLOCK_MONOTONIC, &g_t0);
    if (configure_faults(argc, argv) != 0) {
        return 2;
    }
    fp_route *route = fp_route_register_default(0);
    if (fp_route_add_target(route, argv[2], atoi(argv[3])) != 0) {
        return 2;
    }
    relay_arg *connection = calloc(1, sizeof(*connection));
    if (connection == NULL) {
        return 2;
    }
    connection->client_fd = atoi(argv[1]);
    connection->epoch = g_drop_epoch;
    connection->conn_id = CBUMP(conns, 1);
    connection->route = route;
    CBUMP(active, 1);
    fp_route_inc_conns(route);
    relay_thread(connection);
    char report[4096];
    cmd_status_json(report, sizeof(report));
    fputs(report, stdout);
    return ferror(stdout) ? 1 : 0;
}
