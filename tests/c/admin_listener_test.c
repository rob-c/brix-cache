/* Admin-listener boundaries: no socket is opened and no path is modified.
 * The Python fixture appends the real production listener function bodies. */
#include <assert.h>
#include <sys/un.h>
#include "net/admin/admin_unix.h"

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_connection_t connection;
    ngx_event_t read_event;
    ngx_event_t write_event;
    unsigned socket_calls;
    unsigned registrations;
    unsigned closed;
    unsigned logs;
    mode_t mode;
    ngx_int_t registration_result;
} admin_test_t;

/* The nginx worker index is a core ABI symbol read by path construction. */
ngx_uint_t ngx_worker;

/* WHAT: Return process-local fixture state. WHY: Keep injected state together.
 * HOW: 1. Use a zeroed private static. 2. Return its address. */
static admin_test_t *
admin_test_state(void)
{
    static admin_test_t state;
    return &state;
}

/* WHAT: Supply a bare nginx connection. WHY: Event logs start unset in nginx.
 * HOW: 1. Populate connection metadata. 2. Attach zeroed event records. */
ngx_connection_t *
ngx_get_connection(ngx_socket_t fd, ngx_log_t *log)
{
    admin_test_t *state = admin_test_state();
    ngx_connection_t *connection = &state->connection;

    connection->fd = fd;
    connection->log = log;
    connection->read = &state->read_event;
    connection->write = &state->write_event;
    state->read_event.data = connection;
    state->write_event.data = connection;
    assert(state->read_event.log == NULL && state->write_event.log == NULL);
    return connection;
}

/* WHAT: Validate event registration. WHY: Debug nginx reads both event logs.
 * HOW: 1. Assert log/handler identity. 2. Return the requested backend result. */
ngx_int_t
ngx_handle_read_event(ngx_event_t *event, ngx_uint_t flags)
{
    admin_test_t *state = admin_test_state();
    ngx_connection_t *connection = event->data;

    assert(flags == 0 && event == connection->read);
    assert(event->log == &state->log && event->handler != NULL);
    assert(connection->write->log == &state->log);
    state->registrations++;
    return state->registration_result;
}

/* WHAT: Observe connection cleanup. WHY: Failed registration must release it.
 * HOW: 1. Verify the fixture connection. 2. Count its one allowed release. */
void
ngx_close_connection(ngx_connection_t *connection)
{
    admin_test_t *state = admin_test_state();
    assert(connection == &state->connection);
    assert(++state->closed == 1);
}

/* WHAT: Observe diagnostics. WHY: Invalid paths must report a real refusal.
 * HOW: 1. Check the cycle log. 2. Record the error or success diagnostic. */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
    const char *format, ...)
{
    assert(log == &admin_test_state()->log && format != NULL);
    admin_test_state()->logs++;
    (void) level;
    (void) error;
}

/* WHAT: Stop unexpected accepts. WHY: This fixture never processes traffic.
 * HOW: 1. Fail if the registered handler is invoked. */
static void
admin_unix_accept_handler(ngx_event_t *event)
{
    (void) event;
    assert(0);
}

/* WHAT: Simulate descriptor creation. WHY: No listener may reach the host.
 * HOW: 1. Verify socket type. 2. Return a fixed synthetic descriptor. */
static int
admin_test_socket(int domain, int type, int protocol)
{
    assert(domain == AF_UNIX && type == SOCK_STREAM && protocol == 0);
    admin_test_state()->socket_calls++;
    return 71;
}

/* WHAT: Check binding arguments. WHY: A truncated path could select a peer.
 * HOW: 1. Verify the synthetic fd/address. 2. Require the exact owned path. */
static int
admin_test_bind(int fd, const struct sockaddr *address, socklen_t length)
{
    const struct sockaddr_un *unix_address = (const struct sockaddr_un *) address;
    assert(fd == 71 && length == sizeof(*unix_address));
    assert(unix_address->sun_family == AF_UNIX);
    assert(strcmp(unix_address->sun_path, "owned-admin.sock") == 0);
    return 0;
}

/* WHAT: Record permission application. WHY: Admin access requires mode 0600.
 * HOW: 1. Check the path. 2. Save the exact requested mode. */
static int
admin_test_chmod(const char *path, mode_t mode)
{
    assert(strcmp(path, "owned-admin.sock") == 0);
    admin_test_state()->mode = mode;
    return 0;
}

/* WHAT: Simulate listen. WHY: Preserve ordering without a real endpoint.
 * HOW: 1. Require 0600 already applied. 2. Validate the existing backlog. */
static int
admin_test_listen(int fd, int backlog)
{
    assert(fd == 71 && backlog == 8 && admin_test_state()->mode == 0600);
    return 0;
}

/* WHAT: Simulate nonblocking setup. WHY: A synthetic fd must stay private.
 * HOW: 1. Validate its identity. 2. Return success. */
static int
admin_test_nonblocking(int fd)
{
    assert(fd == 71);
    return 0;
}

/* WHAT: Intercept stale-path cleanup. WHY: Never unlink a host pathname.
 * HOW: 1. Require the exact fixture-owned name. 2. Return success. */
static int
admin_test_unlink(const char *path)
{
    assert(strcmp(path, "owned-admin.sock") == 0);
    return 0;
}

/* WHAT: Intercept descriptor failure cleanup. WHY: Never close a host fd.
 * HOW: 1. Validate its synthetic identity. 2. Return success. */
static int
admin_test_close(int fd)
{
    assert(fd == 71);
    return 0;
}

/* WHAT: Exercise success, failure, and path refusal. WHY: Pin lifecycle rules.
 * HOW: 1. Select a case. 2. Call the real listener. 3. Assert its boundary effects. */
int
main(int argc, char **argv)
{
    admin_test_t *state = admin_test_state();
    brix_admin_unix_t server = {.label = "test-admin"};
    char oversized[sizeof(((struct sockaddr_un *) 0)->sun_path) + 1];
    const char *path = "owned-admin.sock";
    int rejected;

    assert(argc == 2);
    rejected = strcmp(argv[1], "path-too-long") == 0;
    state->cycle.log = &state->log;
    state->log.log_level = NGX_LOG_INFO;
    state->registration_result = strcmp(argv[1], "registration-failure") == 0
                                 ? NGX_ERROR : NGX_OK;
    if (rejected) {
        memset(oversized, 'x', sizeof(oversized) - 1);
        oversized[sizeof(oversized) - 1] = '\0';
        path = oversized;
    }
    brix_admin_unix_listen(&state->cycle, path, &server);
    if (rejected) {
        assert(state->socket_calls == 0 && state->registrations == 0);
        assert(state->closed == 0 && state->logs == 1);
        return 0;
    }
    assert(state->socket_calls == 1 && state->registrations == 1);
    assert(state->connection.data == &server && state->mode == 0600);
    assert(state->closed == (state->registration_result == NGX_ERROR));
    return 0;
}

/* The appended production functions use only these syscall boundaries. */
#define socket admin_test_socket
#define bind admin_test_bind
#define chmod admin_test_chmod
#define listen admin_test_listen
#undef ngx_nonblocking
#define ngx_nonblocking admin_test_nonblocking
#define unlink admin_test_unlink
#define close admin_test_close
