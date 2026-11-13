/* FTP framing and bounded-I/O failures over real, private socketpairs. */
#include "protocols/ftp/ftp_client.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int
selected(const char *name)
{
    const char *value = getenv("BRIX_CTL_FAULT");
    return value != NULL && strcmp(value, name) == 0;
}

static int
once(const char *name)
{
    if (!selected(name)) { return 0; }
    assert(unsetenv("BRIX_CTL_FAULT") == 0);
    return 1;
}

int __real_poll(struct pollfd *, nfds_t, int);
int
__wrap_poll(struct pollfd *p, nfds_t count, int timeout)
{
    if (once("poll-eintr")) { errno = EINTR; return -1; }
    if (once("poll-error")) { errno = EIO; return -1; }
    if (once("poll-timeout")) { return 0; }
    return __real_poll(p, count, timeout);
}

ssize_t __real_recv(int, void *, size_t, int);
ssize_t
__wrap_recv(int fd, void *buffer, size_t capacity, int flags)
{
    if (once("recv-eintr")) { errno = EINTR; return -1; }
    if (once("recv-eagain")) { errno = EAGAIN; return -1; }
    if (once("recv-error")) { errno = EIO; return -1; }
    if (selected("fragment") && capacity > 3) { capacity = 3; }
    return __real_recv(fd, buffer, capacity, flags);
}

ssize_t __real_send(int, const void *, size_t, int);
ssize_t
__wrap_send(int fd, const void *buffer, size_t length, int flags)
{
    if (once("send-eintr")) { errno = EINTR; return -1; }
    if (once("send-eagain")) { errno = EAGAIN; return -1; }
    if (once("send-error")) { errno = EPIPE; return -1; }
    if (once("send-zero")) { errno = EIO; return 0; }
    if (selected("short-send") && length > 2) { length = 2; }
    return __real_send(fd, buffer, length, flags);
}

void *__real_malloc(size_t);
void *
__wrap_malloc(size_t length)
{
    if (selected("malloc-first")) { errno = ENOMEM; return NULL; }
    if (selected("malloc-second")) {
        assert(setenv("BRIX_CTL_FAULT", "malloc-first", 1) == 0);
    }
    return __real_malloc(length);
}

static int
identity_frame(const void *in, size_t length, uint8_t **out, size_t *out_length,
               brix_status *st)
{
    *out = NULL;
    *out_length = 0;
    if (selected("gss-error")) {
        brix_status_set(st, XRDC_EAUTH, 0, "protection refused");
        return -1;
    }
    *out = __real_malloc(length + 1);
    assert(*out != NULL);
    memcpy(*out, in, length);
    (*out)[length] = 0;
    *out_length = length;
    return 0;
}

int
__wrap_brix_ftp_gss_wrap(struct brix_ftp_gss *g, const void *in, size_t length,
                        uint8_t **out, size_t *out_length, brix_status *st)
{
    (void) g;
    return identity_frame(in, length, out, out_length, st);
}

int
__wrap_brix_ftp_gss_unwrap(struct brix_ftp_gss *g, const void *in, size_t length,
                          uint8_t **out, size_t *out_length, brix_status *st)
{
    (void) g;
    return identity_frame(in, length, out, out_length, st);
}

int
__wrap_brix_tcp_connect(const char *host, int port, int timeout, brix_status *st)
{
    assert(strcmp(host, "fixture.invalid") == 0 && port == 2121 && timeout == 10);
    if (selected("connect-error")) {
        brix_status_set(st, XRDC_ESOCK, ECONNREFUSED, "connect refused");
        return -1;
    }
    return atoi(getenv("BRIX_CTL_FD"));
}

static void
feed(int fd, const char *path)
{
    char bytes[4096];
    size_t length;
    FILE *input = fopen(path, "rb");
    assert(input != NULL);
    while ((length = fread(bytes, 1, sizeof(bytes), input)) != 0) {
        assert(write(fd, bytes, length) == (ssize_t) length);
    }
    assert(!ferror(input));
    fclose(input);
    assert(shutdown(fd, SHUT_WR) == 0);
}

static int
operation(brix_ftp_sess *s, const char *verb, const char *argument, brix_status *st)
{
    if (strcmp(verb, "read") == 0) { return brix_ftp_read_reply(s, st); }
    if (strcmp(verb, "command") == 0) { return brix_ftp_cmd(s, st, "%s", argument); }
    if (strcmp(verb, "connect") == 0) {
        return brix_ftp_connect(s, "fixture.invalid", 2121, 10, st);
    }
    assert(strcmp(verb, "expect") == 0);
    return brix_ftp_cmd_expect(s, 200, 299, st, "%s", argument);
}

static void
drain_and_close(int fd)
{
    char unused[4096];
    ssize_t n;
    /* An early refusal leaves scripted inbound bytes unread. Drain only after
     * recording the result so fixture teardown does not reset the peer socket. */
    do { n = read(fd, unused, sizeof(unused)); } while (n > 0);
    assert(n == 0);
    close(fd);
}

int
main(int argc, char **argv)
{
    brix_ftp_sess *s = calloc(1, sizeof(*s));
    brix_status st;
    int pair[2], rc;
    char fdstr[32], output[8192];
    ssize_t length;
    assert(argc == 8 && s != NULL);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    s->fd = pair[0]; s->timeout_ms = 10; s->secure = atoi(argv[4]);
    snprintf(fdstr, sizeof(fdstr), "%d", pair[0]);
    assert(setenv("BRIX_CTL_FD", fdstr, 1) == 0);
    feed(pair[1], argv[2]);
    assert(setenv("BRIX_CTL_FAULT", argv[5], 1) == 0);
    brix_status_clear(&st);
    rc = operation(s, argv[1], argv[3], &st);
    printf("RESULT %d %d %d code=%d\nMESSAGE %s\nTEXT %s\n", rc, st.kxr,
           st.sys_errno, s->code, st.msg, s->text);
    assert(rc == atoi(argv[6]));
    if (rc == 0) { assert(s->code == atoi(argv[7])); }
    if (s->fd >= 0) { drain_and_close(s->fd); }
    if (selected("connect-error")) { drain_and_close(pair[0]); }
    assert(unsetenv("BRIX_CTL_FAULT") == 0);
    length = read(pair[1], output, sizeof(output) - 1);
    assert(length >= 0);
    output[length] = 0;
    printf("SENT %s", output);
    close(pair[1]); free(s);
    brix_ftp_close(NULL);
    return 0;
}
