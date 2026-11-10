/* Finite event consumer for the real double-fork transfer-agent API. */
#include "fs/xfer/xfer.h"
#include <ngx_event.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    uint32_t operation, sequence, value, reserved;
} request_t;

typedef struct {
    uint32_t sequence, value;
    pid_t child, parent;
} reply_t;

typedef struct {
    unsigned replies, drains;
    reply_t last;
} result_t;

void *__real_malloc(size_t size);
pid_t __real_fork(void);
int __real_socketpair(int domain, int type, int protocol, int sockets[2]);

static int
failing(const char *mode)
{
    const char *fault = getenv("BRIX_AGENT_TEST_FAIL");
    return fault != NULL && !strcmp(fault, mode);
}

void *__wrap_malloc(size_t size)
{
    if (failing("alloc")) { errno = ENOMEM; return NULL; }
    return __real_malloc(size);
}

pid_t __wrap_fork(void)
{
    if (failing("fork")) { errno = EAGAIN; return -1; }
    return __real_fork();
}

int __wrap_socketpair(int domain, int type, int protocol, int sockets[2])
{
    if (failing("socketpair")) { errno = EMFILE; return -1; }
    return __real_socketpair(domain, type, protocol, sockets);
}

/* The payload callback is the public API's extension point. Process isolation
 * is observable through PIDs and writes that never reach parent data. */
static void
process_request(const void *request, void *reply, void *opaque)
{
    const request_t *input = request;
    reply_t *output = reply;
    result_t *result = opaque;
    if (input->operation == 1) { raise(SIGTERM); return; }
    if (input->operation == 2) { exit(27); }
    if (input->operation == 3) { usleep(250000); }
    output->sequence = input->sequence;
    output->value = input->value ^ UINT32_C(0xa5c37e19);
    output->child = getpid(); output->parent = getppid();
    result->replies = 1000000;
}

static void
accept_reply(const void *reply, void *opaque)
{
    result_t *result = opaque;
    result->last = *(const reply_t *) reply;
    result->replies++;
}

static void
after_drain(void *opaque)
{
    ((result_t *) opaque)->drains++;
}

/* A finite poll loop invokes the registered production nginx callback only
 * when its real socket is readable. No socket, connection, or agent is faked. */
static void
drain(brix_xfer_agent_t *agent)
{
    struct pollfd ready = {.fd = agent->fd, .events = POLLIN};
    assert(poll(&ready, 1, 5000) == 1);
    agent->conn->read->handler(agent->conn->read);
}

static void
roundtrip(brix_xfer_agent_t *agent, result_t *result, unsigned sequence)
{
    request_t request = {.sequence = sequence, .value = sequence * 119};
    unsigned previous = result->replies;
    assert(brix_xfer_agent_dispatch(agent, &request) == NGX_OK);
    drain(agent);
    assert(result->replies == previous + 1);
    assert(result->last.sequence == sequence);
    assert(result->last.value == (request.value ^ UINT32_C(0xa5c37e19)));
    assert(result->last.child != getpid() && result->last.parent != getpid());
}

static void
failure_case(brix_xfer_agent_t *agent, const brix_xfer_agent_ops_t *ops,
             ngx_cycle_t *cycle, const char *mode)
{
    if (!strcmp(mode, "connections")) {
        cycle->free_connections = NULL; cycle->free_connection_n = 0;
    } else {
        assert(setenv("BRIX_AGENT_TEST_FAIL", mode, 1) == 0);
    }
    assert(brix_xfer_agent_attach(agent, ops, cycle->log) == NGX_ERROR);
    assert(unsetenv("BRIX_AGENT_TEST_FAIL") == 0);
    request_t request = {0};
    assert(agent->fd == -1 && agent->conn == NULL);
    assert(brix_xfer_agent_dispatch(agent, &request) == NGX_ERROR);
}

static void
backpressure(brix_xfer_agent_t *agent, result_t *result)
{
    request_t request = {.operation = 3};
    unsigned accepted = 0;
    ngx_int_t rc = NGX_OK;
    while (accepted < 65536 && rc == NGX_OK) {
        request.sequence = accepted;
        rc = brix_xfer_agent_dispatch(agent, &request);
        if (rc == NGX_OK) { accepted++; }
        request.operation = 0;
    }
    assert(accepted > 0 && rc == NGX_AGAIN);
    while (result->replies < accepted) { drain(agent); }
    assert(result->replies == accepted && result->last.sequence == accepted - 1);
    roundtrip(agent, result, accepted);
}

static void
live_case(brix_xfer_agent_t *agent, const brix_xfer_agent_ops_t *ops,
          ngx_log_t *log, result_t *result, const char *mode)
{
    assert(brix_xfer_agent_attach(agent, ops, log) == NGX_OK);
    if (!strcmp(mode, "backpressure")) {
        backpressure(agent, result);
        return;
    }
    for (unsigned i = 1; i <= 20; i++) { roundtrip(agent, result, i); }
    if (!strcmp(mode, "respawn") || !strcmp(mode, "callback-exit")) {
        pid_t previous = result->last.child;
        request_t die = {.operation = 1};
        if (!strcmp(mode, "callback-exit")) { die.operation = 2; }
        assert(brix_xfer_agent_dispatch(agent, &die) == NGX_OK);
        drain(agent);
        assert(agent->fd >= 0 && agent->conn != NULL);
        roundtrip(agent, result, 21);
        assert(result->last.child != previous);
    }
    if (ops->after_drain != NULL) { assert(result->drains == result->replies); }
    else { assert(result->drains == 0); }
    brix_xfer_agent_teardown(agent);
    assert(agent->fd == -1 && agent->conn == NULL);
    request_t request = {0};
    assert(brix_xfer_agent_dispatch(agent, &request) == NGX_ERROR);
}

int
main(int argc, char **argv)
{
    ngx_log_t log = {0};
    ngx_cycle_t cycle = {.log = &log};
    ngx_connection_t connections[16] = {0};
    ngx_event_t reads[16] = {0}, writes[16] = {0};
    result_t result = {0};
    brix_xfer_agent_ops_t ops = {sizeof(request_t), sizeof(reply_t),
        process_request, accept_reply, after_drain, &result, "native-contract"};
    brix_xfer_agent_t agent = {.fd = -1, .ops = &ops};
    assert(argc == 2);
    ngx_cycle = &cycle; ngx_time_init(); ngx_pid = getpid();
    signal(SIGPIPE, SIG_IGN);
    ngx_queue_init(&cycle.reusable_connections_queue);
    cycle.connections = connections; cycle.connection_n = 16;
    cycle.free_connections = connections; cycle.free_connection_n = 16;
    for (unsigned i = 0; i < 16; i++) {
        connections[i].read = &reads[i]; connections[i].write = &writes[i];
        connections[i].data = i < 15 ? &connections[i + 1] : NULL;
    }
    if (!strcmp(argv[1], "no-drain")) { ops.after_drain = NULL; }
    if (!strcmp(argv[1], "alloc") || !strcmp(argv[1], "fork")
        || !strcmp(argv[1], "socketpair") || !strcmp(argv[1], "connections"))
    {
        failure_case(&agent, &ops, &cycle, argv[1]);
    } else {
        live_case(&agent, &ops, &log, &result, argv[1]);
    }
    brix_xfer_agent_teardown(&agent);
    free(agent.rep_buf);
    return 0;
}
