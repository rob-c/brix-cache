/* Exercise the real flow-label implementation through local syscall hooks.
 * No socket, label lease, connection, or metric shared memory is created. */
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include "observability/pmark/pmark.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"

typedef struct {
    uint32_t expected_label;
    unsigned sockets, closes, leases, sends, notices, marked, failed;
    int deny;
} pmark_test_state_t;

static int pmark_test_socket(int domain, int type, int protocol, ngx_log_t *log);
static int pmark_test_close(int fd, ngx_log_t *log);
static int pmark_test_setsockopt(int fd, int level, int option,
    const void *value, socklen_t length, ngx_log_t *log);
static void pmark_test_metric(ngx_log_t *log, const char *name);

#undef ngx_socket
#define ngx_socket(domain, type, protocol) pmark_test_socket(domain, type, protocol, log)
#undef ngx_close_socket
#define ngx_close_socket(fd) pmark_test_close(fd, log)
#define setsockopt(fd, level, option, value, length) \
    pmark_test_setsockopt(fd, level, option, value, length, log)
#undef ngx_random
#define ngx_random() BRIX_IPV6_FL_ENTROPY_MASK
#undef BRIX_PMARK_METRIC_INC
#define BRIX_PMARK_METRIC_INC(field) pmark_test_metric(log, #field)

#include "observability/pmark/flowlabel.c"

static int
pmark_test_socket(int domain, int type, int protocol, ngx_log_t *log)
{
    pmark_test_state_t *state = log->data;

    assert(domain == AF_INET6 && type == SOCK_DGRAM && protocol == 0);
    state->sockets++;
    return 42;
}

static int
pmark_test_close(int fd, ngx_log_t *log)
{
    pmark_test_state_t *state = log->data;

    assert(fd == 42);
    state->closes++;
    return 0;
}

static int
pmark_test_setsockopt(int fd, int level, int option,
    const void *value, socklen_t length, ngx_log_t *log)
{
    pmark_test_state_t *state = log->data;
    const struct pmark_flowlabel_req *request = value;

    assert(fd == 42 && level == IPPROTO_IPV6);
    if (option == BRIX_IPV6_FLOWINFO_SEND) {
        assert(length == sizeof(int) && *(const int *) value == 1);
        state->sends++;
        return 0;
    }
    assert(option == BRIX_IPV6_FLOWLABEL_MGR && length == sizeof(*request));
    assert(IN6_IS_ADDR_LOOPBACK(&request->flr_dst));
    assert(ntohl(request->flr_label) == state->expected_label);
    assert(request->flr_action == BRIX_IPV6_FL_A_GET);
    assert(request->flr_flags == BRIX_IPV6_FL_F_CREATE);
    assert(request->flr_share == BRIX_IPV6_FL_S_EXCL);
    state->leases++;
    if (state->deny) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static void
pmark_test_metric(ngx_log_t *log, const char *name)
{
    pmark_test_state_t *state = log->data;

    if (strcmp(name, "pmark_flowlabel_set_total") == 0) {
        state->marked++;
    } else {
        assert(strcmp(name, "pmark_flowlabel_failed_total") == 0);
        state->failed++;
    }
}

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
    const char *format, ...)
{
    pmark_test_state_t *state = log->data;

    (void) error;
    (void) format;
    if (level == NGX_LOG_NOTICE) {
        state->notices++;
    }
}

static void
pmark_test_probe(ngx_log_t *log, int denied)
{
    pmark_test_state_t *state = log->data;
    struct sockaddr_in6 destination = {.sin6_family = AF_INET6};
    ngx_int_t expected = denied ? NGX_DECLINED : NGX_OK;

    state->expected_label = 0x20004;
    state->deny = denied;
    assert(brix_pmark_flowlabel_usable(log) == expected);
    assert(brix_pmark_flowlabel_usable(log) == expected);
    assert(state->sockets == 1 && state->closes == 1 && state->leases == 1);
    assert(state->notices == (unsigned) denied);
    if (denied) {
        destination.sin6_addr = in6addr_loopback;
        assert(brix_pmark_flowlabel_apply_addr(42,
            (const struct sockaddr *) &destination, sizeof(destination), 3, 14, log)
            == NGX_DECLINED);
        assert(state->leases == 1 && state->marked == 0 && state->failed == 0);
    }
}

static void
pmark_test_lease(ngx_log_t *log)
{
    pmark_test_state_t *state = log->data;

    state->expected_label = 196664 | BRIX_IPV6_FL_ENTROPY_MASK;
    assert(pmark_flowlabel_lease(42, &in6addr_loopback, 3, 14, log) == NGX_OK);
    assert(state->leases == 1 && state->sends == 1);
    assert(state->marked == 1 && state->failed == 0);
    state->deny = 1;
    assert(pmark_flowlabel_lease(42, &in6addr_loopback, 3, 14, log) == NGX_DECLINED);
    assert(state->leases == 2 && state->sends == 1);
    assert(state->marked == 1 && state->failed == 1);
}

static void
pmark_test_encoding(char **arguments)
{
    ngx_uint_t experiment = strtoul(arguments[2], NULL, 0);
    ngx_uint_t activity = strtoul(arguments[3], NULL, 0);
    uint32_t expected = strtoul(arguments[4], NULL, 0);
    uint32_t label = brix_pmark_flowlabel_encode(experiment, activity);

    assert(label == expected);
    assert((label & BRIX_IPV6_FL_ENTROPY_MASK) == 0);
    assert((label & ~BRIX_IPV6_FL_MASK) == 0);
}

int
main(int argc, char **argv)
{
    pmark_test_state_t state = {0};
    ngx_log_t log = {.log_level = NGX_LOG_INFO, .data = &state};

    assert(argc >= 2);
    if (strcmp(argv[1], "encode") == 0) {
        assert(argc == 5);
        pmark_test_encoding(argv);
    } else if (strcmp(argv[1], "lease") == 0) {
        pmark_test_lease(&log);
    } else {
        assert(strcmp(argv[1], "probe-success") == 0
               || strcmp(argv[1], "probe-denied") == 0);
        pmark_test_probe(&log, strcmp(argv[1], "probe-denied") == 0);
    }
    return 0;
}
