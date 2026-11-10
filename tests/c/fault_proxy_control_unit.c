/*
 * Finite driver for the shipped fault-proxy control dispatcher.
 *
 * WHAT: Apply an argv sequence to real production state and emit each reply,
 *       separated by NUL bytes, for observable contract assertions in pytest.
 * WHY:  Control grammar and reset contracts need deterministic tests independent
 *       of socket scheduling. Normal exit also preserves standalone gcov data.
 * HOW:  Link every fault-proxy source, rename its daemon entry point, initialize
 *       the same lever defaults, and call the real dispatcher without stubs.
 */
#include "brix_fault_proxy_state.h"
#include "brix_fault_oracle.h"
#include "brix_fault_priv.h"
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#undef main

/* WHAT: Wait for a finite oracle job, refusing to hide a stalled worker.
 * WHY: Result assertions must observe completed jobs and their reset state.
 * HOW: Poll the production busy flag with a five-second monotonic bound. */
static int
wait_for_oracle(void)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (g_oracle_busy) {
        if (now_ms_since(start) > 5000) { return -1; }
        usleep(1000);
    }
    return 0;
}

/* WHAT: Dispatch one command with a flushed NUL-delimited response.
 * WHY: Interactive tests inspect kernel state before sending the next command.
 * HOW: Use the production dispatcher and wait for any asynchronous oracle. */
static int
emit_reply(char *command, int wait)
{
    char reply[16384] = "";
    apply_command(command, reply, sizeof(reply));
    if (wait && wait_for_oracle() != 0) { return 2; }
    fwrite(reply, 1, strlen(reply), stdout);
    fputc('\0', stdout);
    return fflush(stdout) == 0 ? 0 : 1;
}

/* WHAT: Arm real privileged levers and restore their state on normal exit.
 * WHY: Tests need the kernel effects and counters from the same finite process.
 * HOW: Use the public opt-in API with ports private to an isolated namespace. */
static int
arm_privileged(const char *iface)
{
    const int ports[] = { 24002, 24003 };
    const char *error = NULL;
    if (fp_priv_enable(iface, 24001, ports, 2, &error) != 0) {
        fprintf(stderr, "%s\n", error);
        return 3;
    }
    return atexit(fp_priv_teardown) == 0 ? 0 : 4;
}

/* WHAT: Process a bounded command per input line until EOF.
 * WHY: EOF permits normal cleanup and profile flush without daemon signals.
 * HOW: Reject oversized input before handing a mutable buffer to production. */
static int
read_commands(void)
{
    char command[4096];
    while (fgets(command, sizeof(command), stdin) != NULL) {
        size_t length = strlen(command);
        if (length == 0 || command[length - 1] != '\n') { return 5; }
        command[length - 1] = '\0';
        int rc = emit_reply(command, 0);
        if (rc != 0) { return rc; }
    }
    if (wait_for_oracle() != 0) { return 2; }
    return ferror(stdin) ? 1 : 0;
}

/* Register the real listener/relay callbacks on the normal loopback gate.
 * Tests delete every dynamic route before EOF and wait for relays to finish. */
static int
arm_network(void)
{
    fp_route_ops operations = { fp_core_bind_listen, fp_accept_loop };
    const char *host = getenv("BRIX_FAULT_TEST_BIND");
    if (host == NULL) { host = "127.0.0.1"; }
    if (fp_setup_bind(host, 0, &g_bind_ss, &g_bind_len) != FP_CONTINUE) {
        return 6;
    }
    signal(SIGPIPE, SIG_IGN);
    fp_route_init(&operations);
    fp_route_register_default(24001);
    return 0;
}

/* Exercise the real UDP pump until stdin EOF, then join it before profile
 * flush. poll/usleep are cancellation points; process exit closes its fds. */
static int
run_udp(int listen_port, const char *host, int target_port)
{
    fp_udp_cfg *config = calloc(1, sizeof(*config));
    pthread_t worker;
    void *result = NULL;
    int status;

    if (config == NULL) { return 7; }
    if (arm_network() != 0) { free(config); return 8; }
    config->listen_port = listen_port;
    config->port = target_port;
    snprintf(config->host, sizeof(config->host), "%s", host);
    if (pthread_create(&worker, NULL, fp_udp_thread, config) != 0) {
        free(config);
        return 9;
    }
    status = read_commands();
    pthread_cancel(worker);
    if (pthread_join(worker, &result) != 0) { return 10; }
    if (result == PTHREAD_CANCELED) { free(config); }
    return status;
}

/* Run the real persistent socket-control parser until the fixture's stdin
 * reaches EOF. Join the owned thread before normal exit flushes its counters. */
static int
run_control(int port)
{
    pthread_t worker;
    if (arm_network() != 0) { return 11; }
    int listener = listen_sa(&g_bind_ss, g_bind_len, port);
    if (listener < 0) { return 12; }
    int *argument = malloc(sizeof(*argument));
    if (argument == NULL) { close(listener); return 13; }
    *argument = listener;
    if (pthread_create(&worker, NULL, control_thread, argument) != 0) {
        free(argument); close(listener); return 14;
    }
    puts("ready"); fflush(stdout);
    int status = read_commands();
    shutdown(listener, SHUT_RDWR);
    close(listener);
    pthread_cancel(worker);
    if (pthread_join(worker, NULL) != 0) { return 15; }
    return status;
}

static int
run_special_fixture(int argc, char **argv)
{
    if (argc == 5 && strcmp(argv[1], "--udp-fixture") == 0) {
        return run_udp(atoi(argv[2]), argv[3], atoi(argv[4]));
    }
    if (argc == 3 && strcmp(argv[1], "--control-fixture") == 0) {
        return run_control(atoi(argv[2]));
    }
    if (argc == 3 && strcmp(argv[1], "--script-fixture") == 0) {
        script_thread(argv[2]);
        return emit_reply((char[]){"{\"cmd\":\"status\"}"}, 1);
    }
    return FP_CONTINUE;
}

/* ---- Execute a finite command transcript ----
 * WHAT: Return zero after emitting all replies, or one on an output failure.
 * WHY:  The Python tests inspect actual replies and subsequent state snapshots.
 * HOW:  1. Initialize production defaults. 2. Dispatch each mutable argv string.
 *       3. Frame replies without interpreting their contents and exit normally.
 */
int
main(int argc, char **argv)
{
    int first = 1;

    clear_all();
    clock_gettime(CLOCK_MONOTONIC, &g_t0);
    int special = run_special_fixture(argc, argv);
    if (special != FP_CONTINUE) { return special; }
    if (argc > 1 && strcmp(argv[1], "--enable-exec") == 0) {
        fp_oracle_enable();
        first = 2;
    }
    if (argc > 2 && strcmp(argv[1], "--privileged-fixture") == 0) {
        int rc = arm_privileged(argv[2]);
        if (rc != 0) { return rc; }
        first = 3;
    }
    if (argc > 1 && strcmp(argv[1], "--network-fixture") == 0) {
        int rc = arm_network();
        if (rc != 0) { return rc; }
        first = 2;
        if (argc > 2 && strcmp(argv[2], "--enable-exec") == 0) {
            fp_oracle_enable();
            first = 3;
        }
    }
    if (first < argc && strcmp(argv[first], "--stdin") == 0) {
        return read_commands();
    }
    for (int index = first; index < argc; index++) {
        int rc = emit_reply(argv[index], 1);
        if (rc != 0) { return rc; }
    }
    return ferror(stdout) ? 1 : 0;
}
