/* WHAT: Exercise shipped socket I/O under finite syscall failures and cancellation.
 * WHY: A failed or over-budget transfer must not publish success or consume data.
 * HOW: Own a real socketpair; interpose only its poll/read/send and finite clock. */
#define _POSIX_C_SOURCE 200809L
#include "brix.h"
/* Keep the test assertions active with release-mode client build flags. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* WHAT: Select one immutable process scenario. WHY: No shared fixture globals.
 * HOW: Read the process-local selector supplied by main before any I/O. */
static int selected(const char *name)
{
    const char *value = getenv("BRIX_SOCKET_BOUNDARY_CASE");
    return value != NULL && !strcmp(value, name);
}

/* WHAT: Recognize the owned descriptor. WHY: Profile and runtime I/O stay real.
 * HOW: Match only the socketpair endpoint published by this process. */
static int owned(int fd)
{
    const char *value = getenv("BRIX_SOCKET_BOUNDARY_FD");
    return value != NULL && fd == atoi(value);
}

int __real_poll(struct pollfd *, nfds_t, int);
ssize_t __real_read(int, void *, size_t);
ssize_t __real_send(int, const void *, size_t, int);
uint64_t __real_brix_mono_ns(void);
int __real_socket(int, int, int);
int __real_connect(int, const struct sockaddr *, socklen_t);
int __real_getsockopt(int, int, int, void *, socklen_t *);

/* WHAT: Publish the descriptor created by the production dialer. WHY: Only owned
 * sockets may receive faults. HOW: Preserve real allocation except EMFILE. */
int __wrap_socket(int family, int type, int protocol)
{
    if (getenv("BRIX_SOCKET_BOUNDARY_CONNECT") == NULL) {
        return __real_socket(family, type, protocol);
    }
    if (selected("connect-socket-error")) { errno = EMFILE; return -1; }
    int fd = __real_socket(family, type, protocol);
    if (getenv("BRIX_SOCKET_BOUNDARY_CONNECT") != NULL && fd >= 0) {
        char text[32]; snprintf(text, sizeof(text), "%d", fd);
        assert(setenv("BRIX_SOCKET_BOUNDARY_FD", text, 1) == 0);
    }
    return fd;
}

/* WHAT: Select direct refusal or in-progress completion. WHY: Error errno must
 * survive closing the owned socket. HOW: Successful mode uses real loopback TCP. */
int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    if (!owned(fd) || selected("connect-success")) {
        return __real_connect(fd, address, length);
    }
    assert(address->sa_family == AF_INET && length == sizeof(struct sockaddr_in));
    errno = selected("connect-direct-error") ? EACCES : EINPROGRESS;
    return -1;
}

/* WHAT: Supply an inspection error or completed refusal. WHY: Readiness alone
 * is not connected success. HOW: Fault only SO_ERROR on the owned descriptor. */
int __wrap_getsockopt(int fd, int level, int option, void *value, socklen_t *length)
{
    if (owned(fd) && selected("connect-inspect-error")) { errno = EIO; return -1; }
    if (owned(fd) && selected("connect-refused")) {
        assert(level == SOL_SOCKET && option == SO_ERROR && *length == sizeof(int));
        *(int *) value = ECONNREFUSED; return 0;
    }
    return __real_getsockopt(fd, level, option, value, length);
}

/* WHAT: Inject one interrupt. WHY: EINTR/EAGAIN must retry without losing bytes.
 * HOW: Keep the one-shot marker in this disposable process's environment. */
static int interrupt_once(const char *key, int code)
{
    if (getenv(key) != NULL) { return 0; }
    assert(setenv(key, "1", 1) == 0);
    errno = code;
    return 1;
}

/* WHAT: Bound readiness failures. WHY: A live peer cannot mask poll errors.
 * HOW: Interpose only this pair; all unrelated descriptors retain libc semantics. */
int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    if (count != 1 || !owned(fds[0].fd)) { return __real_poll(fds, count, timeout); }
    if (selected("read-poll-error") || selected("write-poll-error")) {
        errno = EIO; return -1;
    }
    if (selected("read-timeout") || selected("write-timeout")) { return 0; }
    if (selected("connect-poll-error")) { errno = EIO; return -1; }
    if (selected("connect-timeout")) { return 0; }
    if (selected("connect-inspect-error") || selected("connect-refused")) { return 1; }
    if (selected("read-drip")) {
        assert(setenv("BRIX_SOCKET_BOUNDARY_POLLED", "1", 1) == 0); return 0;
    }
    if (selected("poll-interrupt") && interrupt_once("BRIX_SOCKET_BOUNDARY_POLLED", EINTR)) {
        return -1;
    }
    return __real_poll(fds, count, timeout);
}

/* WHAT: Refuse or partially satisfy a real read. WHY: No error can become EOF/success.
 * HOW: Inject the selected finite fault; delegate actual byte ownership to libc. */
ssize_t __wrap_read(int fd, void *buffer, size_t size)
{
    if (!owned(fd)) { return __real_read(fd, buffer, size); }
    if (selected("read-error")) { errno = EIO; return -1; }
    if (selected("read-again") && interrupt_once("BRIX_SOCKET_BOUNDARY_INTERRUPTED", EAGAIN)) {
        return -1;
    }
    return __real_read(fd, buffer, selected("read-partial") && size > 1 ? 1 : size);
}

/* WHAT: Refuse or partially send real bytes. WHY: Retry must preserve exact payloads.
 * HOW: Interpose this pair's sender without altering flags or unrelated writes. */
ssize_t __wrap_send(int fd, const void *buffer, size_t size, int flags)
{
    if (!owned(fd)) { return __real_send(fd, buffer, size, flags); }
    if (selected("write-error")) { errno = EIO; return -1; }
    if (selected("write-interrupt") && interrupt_once("BRIX_SOCKET_BOUNDARY_INTERRUPTED", EINTR)) {
        return -1;
    }
    return __real_send(fd, buffer, selected("write-partial") && size > 1 ? 1 : size, flags);
}

/* WHAT: Cross a deterministic whole-operation cutoff. WHY: No clock races in the guard.
 * HOW: Advance only the drip scenario after its owned poll, never host wall time. */
uint64_t __wrap_brix_mono_ns(void)
{
    if (selected("read-expired") || selected("read-submillisecond")) { return 1000000000ULL; }
    if (selected("read-drip")) {
        return getenv("BRIX_SOCKET_BOUNDARY_POLLED") ? 3000000000ULL : 1000000000ULL;
    }
    return __real_brix_mono_ns();
}

/* WHAT: Arm the selected limit or cooperative cancel. WHY: Boundaries precede bytes.
 * HOW: Use the real public signal setup and the actual I/O deadline fields. */
static void prepare(brix_io *io)
{
    if (selected("read-expired")) { io->stall_deadline_ns = 1; }
    if (selected("read-submillisecond")) { io->stall_deadline_ns = 1000500000ULL; }
    if (selected("read-drip")) { io->stall_deadline_ns = 2000000000ULL; }
    if (selected("read-cancel") || selected("write-cancel")) {
        brix_copy_install_signal_handlers(); assert(raise(SIGINT) == 0);
    }
}

/* WHAT: Require byte-exact successful transfers. WHY: Retry cannot duplicate/drop data.
 * HOW: Read the actual socketpair peer or inspect the guarded receive buffer. */
static void successful(int reading, int peer, const unsigned char *buffer)
{
    if (reading) { assert(memcmp(buffer, "data", 4) == 0); return; }
    unsigned char received[4]; assert(__real_read(peer, received, 4) == 4);
    assert(memcmp(received, "data", 4) == 0);
}

/* WHAT: Require stable transport error identity. WHY: Cancel/deadline/errors differ.
 * HOW: Check native status, errno and that a failed read publishes no bytes. */
static void failed(const brix_status *status, const unsigned char *buffer)
{
    assert(status->kxr == XRDC_ESOCK);
    int expected = ETIMEDOUT;
    if (selected("read-error") || selected("write-error") ||
        selected("read-poll-error") || selected("write-poll-error")) { expected = EIO; }
    if (selected("read-cancel") || selected("write-cancel")) { expected = EINTR; }
    if (selected("read-eof")) { expected = 0; }
    assert(status->sys_errno == expected);
    for (size_t i = 0; i < 6; i++) { assert(buffer[i] == 0xa5); }
}

/* WHAT: Prove failed work transferred no bytes. WHY: Cancel/deadline cannot leak data.
 * HOW: Inspect the real pair without the injected failure after checking status. */
static void untouched_pair(int reading, int *pair)
{
    if (reading && !selected("read-eof")) {
        unsigned char pending[4]; assert(__real_read(pair[0], pending, 4) == 4);
        assert(memcmp(pending, "data", 4) == 0); return;
    }
    if (!reading) {
        struct pollfd peer = {.fd = pair[1], .events = POLLIN};
        assert(__real_poll(&peer, 1, 0) == 0);
    }
}

/* WHAT: Own one byte-I/O scenario. WHY: No fixture state crosses processes.
 * HOW: Seed the peer, invoke shipped read/write entry points, and verify canaries. */
static void byte_io(const char *name)
{
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    char descriptor[32]; snprintf(descriptor, sizeof(descriptor), "%d", pair[0]);
    assert(setenv("BRIX_SOCKET_BOUNDARY_FD", descriptor, 1) == 0);
    int reading = strncmp(name, "write-", 6) != 0;
    brix_io io = {.fd = pair[0], .timeout_ms = 50, .stall_deadline_ms = 1};
    brix_status status = {0}; unsigned char buffer[6]; memset(buffer, 0xa5, sizeof(buffer));
    if (reading && !selected("read-eof")) { assert(write(pair[1], "data", 4) == 4); }
    if (selected("read-eof")) { assert(close(pair[1]) == 0); pair[1] = -1; }
    prepare(&io);
    int result = reading ? brix_read_full(&io, buffer, 4, &status)
                         : brix_write_full(&io, "data", 4, &status);
    int success = selected("read-partial") || selected("write-partial") ||
                  selected("read-again") || selected("write-interrupt") || selected("poll-interrupt");
    assert(result == (success ? 0 : -1));
    if (success) { successful(reading, pair[1], buffer); }
    else { failed(&status, buffer); untouched_pair(reading, pair); }
    assert(buffer[4] == 0xa5 && buffer[5] == 0xa5);
    assert(close(pair[0]) == 0); if (pair[1] >= 0) { assert(close(pair[1]) == 0); }
}

/* WHAT: Allocate an actual loopback listener. WHY: Connect success is not mocked.
 * HOW: Bind an ephemeral port using the platform's normal TCP implementation. */
static int listener(int *port)
{
    int fd = __real_socket(AF_INET, SOCK_STREAM, 0); assert(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(bind(fd, (struct sockaddr *) &address, sizeof(address)) == 0);
    assert(listen(fd, 1) == 0); socklen_t length = sizeof(address);
    assert(getsockname(fd, (struct sockaddr *) &address, &length) == 0);
    *port = ntohs(address.sin_port); return fd;
}

/* WHAT: Require failed dials to close their descriptor and preserve errno.
 * WHY: A failed status cannot leak handles or be treated as a connected socket.
 * HOW: Drive the public connector with real numeric resolution and finite faults. */
static void connection(void)
{
    int port = 1, server = -1;
    if (selected("connect-success")) { server = listener(&port); }
    assert(setenv("no_proxy", "*", 1) == 0); assert(setenv("NO_PROXY", "*", 1) == 0);
    assert(setenv("BRIX_SOCKET_BOUNDARY_CONNECT", "1", 1) == 0);
    brix_status status = {0}; int fd = brix_tcp_connect("127.0.0.1", port, 50, &status);
    if (server >= 0) {
        assert(fd >= 0 && !(fcntl(fd, F_GETFL) & O_NONBLOCK));
        int peer = accept(server, NULL, NULL); assert(peer >= 0);
        assert(close(peer) == 0 && close(server) == 0 && close(fd) == 0); return;
    }
    assert(fd == -1 && status.kxr == XRDC_ESOCK); int expected = EIO;
    if (selected("connect-socket-error")) { expected = EMFILE; }
    if (selected("connect-timeout")) { expected = ETIMEDOUT; }
    if (selected("connect-refused")) { expected = ECONNREFUSED; }
    if (selected("connect-direct-error")) { expected = EACCES; }
    assert(status.sys_errno == expected);
    const char *descriptor = getenv("BRIX_SOCKET_BOUNDARY_FD");
    if (descriptor) { errno = 0; assert(fcntl(atoi(descriptor), F_GETFL) == -1 && errno == EBADF); }
}

/* WHAT: Select one hermetic native contract. WHY: Fault controls never outlive it.
 * HOW: Execute byte I/O or connect, then unpublish descriptor interception. */
int main(int argc, char **argv)
{
    assert(argc == 2); assert(setenv("BRIX_SOCKET_BOUNDARY_CASE", argv[1], 1) == 0);
    if (!strncmp(argv[1], "connect-", 8)) { connection(); }
    else { byte_io(argv[1]); }
    assert(unsetenv("BRIX_SOCKET_BOUNDARY_CONNECT") == 0);
    assert(unsetenv("BRIX_SOCKET_BOUNDARY_FD") == 0);
    assert(unsetenv("BRIX_SOCKET_BOUNDARY_CASE") == 0);
    puts("Socket boundary contract verified"); return 0;
}
