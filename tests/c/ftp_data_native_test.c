/* Real FTP control parsing, passive policy and transfer lifecycle over socketpairs. */
#include "protocols/ftp/ftp_client.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    const char *payload;
    size_t offset;
    unsigned progress;
} transfer_fixture;

static int
fault(const char *name)
{
    const char *value = getenv("BRIX_FTP_FAULT");
    return value != NULL && strcmp(value, name) == 0;
}

static int
fixture_fd(void)
{
    return atoi(getenv("BRIX_FTP_DATA_FD"));
}

static int
refused(brix_status *st, const char *message)
{
    brix_status_set(st, XRDC_ESOCK, EIO, "%s", message);
    return -1;
}

int
__wrap_brix_tcp_connect(const char *host, int port, int timeout, brix_status *st)
{
    assert(timeout == 20);
    printf("DIAL %s %d\n", host, port);
    if (fault("connect")) { return refused(st, "connect refused"); }
    assert(setenv("BRIX_FTP_CONNECTED", "1", 1) == 0);
    return fixture_fd();
}

ssize_t __real_brix_ftp_io_read(int, void *, size_t, int, brix_status *);
ssize_t
__wrap_brix_ftp_io_read(int fd, void *buf, size_t n, int timeout, brix_status *st)
{
    if (fd == fixture_fd() && fault("read")) { return refused(st, "data read failed"); }
    return __real_brix_ftp_io_read(fd, buf, n, timeout, st);
}

int __real_brix_ftp_io_write_all(int, const void *, size_t, int, brix_status *);
int
__wrap_brix_ftp_io_write_all(int fd, const void *buf, size_t n, int timeout, brix_status *st)
{
    if (fd == fixture_fd() && fault("write")) { return refused(st, "data write failed"); }
    return __real_brix_ftp_io_write_all(fd, buf, n, timeout, st);
}

int __wrap_brix_copy_quit_requested(void) { return fault("cancel"); }

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void *__wrap_malloc(size_t n) {
    return n == BRIX_FTP_DATA_CHUNK && fault("malloc") ? NULL : __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t size) {
    return n == 1 && size == 1 && fault("calloc") ? NULL : __real_calloc(n, size);
}
void *__wrap_realloc(void *pointer, size_t n) {
    return fault("realloc") ? NULL : __real_realloc(pointer, n);
}

static int
consume(void *arg, const uint8_t *buf, size_t n, brix_status *st)
{
    transfer_fixture *f = arg;
    if (fault("sink")) { return refused(st, "sink failed"); }
    assert(f->offset + n <= strlen(f->payload));
    assert(memcmp(f->payload + f->offset, buf, n) == 0);
    f->offset += n;
    return 0;
}

static ssize_t
produce(void *arg, uint8_t *buf, size_t cap, brix_status *st)
{
    transfer_fixture *f = arg;
    size_t length = strlen(f->payload) - f->offset;
    if (fault("source")) { return refused(st, "source failed"); }
    if (length > cap) { length = cap; }
    memcpy(buf, f->payload + f->offset, length);
    f->offset += length;
    return (ssize_t) length;
}

static void
progress(void *arg, long long done, long long total)
{
    transfer_fixture *f = arg;
    assert(done == (long long) f->offset && total == (long long) strlen(f->payload));
    f->progress++;
}

static void
feed_script(int fd, const char *path)
{
    char buf[4096];
    size_t length;
    FILE *input = fopen(path, "r");
    assert(input != NULL);
    while ((length = fread(buf, 1, sizeof(buf), input)) != 0) {
        assert(write(fd, buf, length) == (ssize_t) length);
    }
    assert(!ferror(input));
    fclose(input);
    assert(shutdown(fd, SHUT_WR) == 0);
}

static int
slurp(brix_ftp_sess *s, transfer_fixture *f, brix_status *st)
{
    char *body = (char *) 1;
    size_t length = 99;
    int rc = brix_ftp_data_slurp(s, "MLSD /tree", &body, &length, st);
    if (rc == 0) {
        assert(body != NULL && length == strlen(f->payload));
        assert(strcmp(body, f->payload) == 0);
        free(body);
    } else {
        assert(body == NULL && length == 0);
    }
    return rc;
}

static int
transfer(brix_ftp_sess *s, const char *operation, transfer_fixture *f, brix_status *st)
{
    brix_copy_opts options = {0};
    options.progress = progress;
    options.progress_arg = f;
    if (strcmp(operation, "slurp") == 0) { return slurp(s, f, st); }
    if (strcmp(operation, "retr") == 0) {
        return brix_ftp_retr(s, "/file", consume, f, &options, strlen(f->payload), st);
    }
    assert(strcmp(operation, "stor") == 0);
    return brix_ftp_stor(s, "/file", produce, f, &options, strlen(f->payload), st);
}

static void
check_output(const char *operation, int peer, const transfer_fixture *f)
{
    char buf[4096];
    ssize_t n;
    if (strcmp(operation, "slurp") == 0) { return; }
    assert(f->offset == strlen(f->payload));
    assert(f->progress == (f->offset ? 1u : 0u));
    if (strcmp(operation, "stor") != 0) { return; }
    n = read(peer, buf, sizeof(buf));
    assert(n == (ssize_t) strlen(f->payload));
    assert(memcmp(buf, f->payload, (size_t) n) == 0);
    assert(read(peer, buf, sizeof(buf)) == 0);
}

int
main(int argc, char **argv)
{
    int control[2], data[2], rc;
    char fdstr[32], commands[4096];
    ssize_t n;
    brix_ftp_sess *s = calloc(1, sizeof(*s));
    brix_status st;
    transfer_fixture fixture = {0};
    assert(argc == 6 && s != NULL);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, control) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, data) == 0);
    s->fd = control[0]; s->timeout_ms = 20;
    snprintf(s->peer_ip, sizeof(s->peer_ip), "192.0.2.1");
    snprintf(fdstr, sizeof(fdstr), "%d", data[0]);
    assert(setenv("BRIX_FTP_DATA_FD", fdstr, 1) == 0);
    assert(unsetenv("BRIX_FTP_CONNECTED") == 0);
    feed_script(control[1], argv[2]);
    fixture.payload = argv[3];
    if (strcmp(argv[1], "stor") != 0) {
        assert(write(data[1], argv[3], strlen(argv[3])) == (ssize_t) strlen(argv[3]));
    }
    assert(shutdown(data[1], SHUT_WR) == 0);
    assert(setenv("BRIX_FTP_FAULT", argv[4], 1) == 0);
    brix_status_clear(&st);
    rc = transfer(s, argv[1], &fixture, &st);
    printf("RESULT %d %d %d %s\n", rc, st.kxr, st.sys_errno, st.msg);
    assert(rc == atoi(argv[5]));
    if (getenv("BRIX_FTP_CONNECTED") != NULL) {
        assert(fcntl(data[0], F_GETFD) == -1 && errno == EBADF);
    } else { close(data[0]); }
    if (rc == 0) { check_output(argv[1], data[1], &fixture); }
    close(control[0]);
    n = read(control[1], commands, sizeof(commands) - 1);
    assert(n >= 0);
    commands[n] = 0;
    printf("COMMANDS %s", commands);
    close(control[1]); close(data[1]); free(s);
    return 0;
}
