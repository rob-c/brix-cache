/* Finite TLS record results exercise the real retry/deadline policy.
 * No network peer or TLS parser is substituted into production code. */
#include "brix.h"
#include "net/tls_internal.h"
#include <openssl/ssl.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *operation, *mode;
    brix_io io;
    int error, call_errno;
    unsigned calls, polls, clock, copied;
} fixture;
static fixture *state(void)
{
    return (fixture *)(uintptr_t) strtoull(getenv("BRIX_TLS_IO_STATE"), NULL, 16);
}
static int mode(const char *name) { return strcmp(state()->mode, name) == 0; }

static int record_result(size_t capacity, size_t *count)
{
    fixture *f = state(); f->calls++;
    assert(f->calls < 20);
    if (f->error && f->calls == 1) {
        *count = 0; errno = f->call_errno; return 0;
    }
    *count = capacity < 3 ? capacity : 3;
    return 1;
}
int __wrap_SSL_read_ex(SSL *ssl, void *buffer, size_t capacity, size_t *count)
{
    fixture *f = state(); assert(ssl == (SSL *) f);
    int rc = record_result(capacity, count);
    if (rc == 1) {
        assert(f->copied + *count <= 8);
        memcpy(buffer, "abcdefgh" + f->copied, *count); f->copied += (unsigned) *count;
    }
    return rc;
}
int __wrap_SSL_write_ex(SSL *ssl, const void *buffer, size_t capacity, size_t *count)
{
    fixture *f = state(); assert(ssl == (SSL *) f);
    int rc = record_result(capacity, count);
    if (rc == 1) {
        assert(f->copied + *count <= 8 && memcmp(buffer, "abcdefgh" + f->copied, *count) == 0);
        f->copied += (unsigned) *count;
    }
    return rc;
}
int __wrap_SSL_get_error(const SSL *ssl, int result)
{
    assert(ssl == (SSL *) state() && result == 0); return state()->error;
}
int __wrap_brix_copy_quit_requested(void) { return mode("cancel"); }
uint64_t __wrap_brix_mono_ns(void)
{
    fixture *f = state(); unsigned index = f->clock++;
    if (mode("submillisecond")) { return 999500000ULL; }
    if (mode("deadline")) { return 1000000000ULL; }
    if (mode("deadline-after-poll") && index > 0) { return 1000000000ULL; }
    return 900000000ULL;
}
int __wrap_poll(struct pollfd *descriptors, nfds_t count, int timeout)
{
    fixture *f = state(); unsigned index = f->polls++;
    assert(count == 1 && descriptors[0].fd == 57);
    assert(descriptors[0].events == (f->error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN));
    if (mode("clamp")) { assert(timeout == 100); }
    else { assert(timeout == f->io.timeout_ms); }
    if (mode("poll-intr") && index == 0) { errno = EINTR; return -1; }
    if (mode("poll-error")) { errno = EBADF; return -1; }
    if (mode("timeout") || mode("deadline-after-poll")) { return 0; }
    return 1;
}

int main(int argc, char **argv)
{
    fixture f = {0}; brix_status status = {0};
    char pointer[32], buffer[8] = {0}; size_t got = 99;
    int result;
    assert(argc == 8); f.operation = argv[1]; f.mode = argv[2];
    f.error = atoi(argv[3]); f.call_errno = atoi(argv[4]);
    f.io.fd = 57; f.io.ssl = (struct ssl_st *) &f; f.io.timeout_ms = atoi(argv[7]);
    f.io.stall_deadline_ms = 100;
    if (atoi(argv[6])) { f.io.stall_deadline_ns = 1000000000ULL; }
    snprintf(pointer, sizeof(pointer), "%llx", (unsigned long long) (uintptr_t) &f);
    assert(setenv("BRIX_TLS_IO_STATE", pointer, 1) == 0);
    if (!strcmp(f.operation, "read")) {
        result = brix_tls_read(&f.io, buffer, sizeof(buffer), &status);
        if (!result) { assert(memcmp(buffer, "abcdefgh", 8) == 0 && f.copied == 8); }
    } else if (!strcmp(f.operation, "write")) {
        result = brix_tls_write(&f.io, "abcdefgh", 8, &status);
        if (!result) { assert(f.copied == 8); }
    } else {
        assert(!strcmp(f.operation, "some"));
        result = brix_tls_read_some(&f.io, buffer, sizeof(buffer), &got, &status);
        if (!result && got) { assert(got == 3 && memcmp(buffer, "abc", 3) == 0); }
        if (result) { assert(got == 0); }
    }
    assert(result == atoi(argv[5]));
    printf("calls=%u polls=%u copied=%u got=%zu errno=%d\n%s\n",
        f.calls, f.polls, f.copied, got, status.sys_errno, status.msg);
    return 0;
}
