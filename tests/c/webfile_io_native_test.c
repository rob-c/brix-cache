/* Ranged HTTP response handling with real socket reads and observed requests. */
#include "protocols/http/webfile_internal.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>

static int
fault(const char *name)
{
    const char *value = getenv("BRIX_WEB_FAULT");
    return value != NULL && strcmp(value, name) == 0;
}

static int
once(const char *name)
{
    if (!fault(name)) { return 0; }
    assert(unsetenv("BRIX_WEB_FAULT") == 0);
    return 1;
}

int __real_poll(struct pollfd *, nfds_t, int);
int
__wrap_poll(struct pollfd *p, nfds_t count, int timeout)
{
    if (once("poll-eintr")) { errno = EINTR; return -1; }
    if (once("poll-error")) { errno = EIO; return -1; }
    if (once("timeout")) { return 0; }
    return __real_poll(p, count, timeout);
}

ssize_t __real_read(int, void *, size_t);
ssize_t
__wrap_read(int fd, void *buf, size_t n)
{
    const char *value = getenv("BRIX_WEB_FRAGMENT");
    size_t limit = value ? (size_t) atoi(value) : 0;
    if (once("read-eintr")) { errno = EINTR; return -1; }
    if (once("read-error")) { errno = EIO; return -1; }
    if (limit > 0 && n > limit) { n = limit; }
    return __real_read(fd, buf, n);
}

int
__wrap_brix_write_full(brix_io *io, const void *data, size_t length, brix_status *st)
{
    (void) io;
    printf("REQUEST %.*s\n", (int) length, (const char *) data);
    if (fault("write")) {
        brix_status_set(st, XRDC_ESOCK, EPIPE, "write failed");
        return -1;
    }
    return 0;
}

int
__wrap_brix_tcp_connect(const char *host, int port, int timeout, brix_status *st)
{
    assert(strcmp(host, "fixture.invalid") == 0 && port == 443 && timeout == 20);
    if (fault("connect")) {
        brix_status_set(st, XRDC_ESOCK, ECONNREFUSED, "connect failed");
        return -1;
    }
    assert(setenv("BRIX_WEB_DIALED", "1", 1) == 0);
    return atoi(getenv("BRIX_WEB_FD"));
}

int
__wrap_brix_tls_client(brix_io *io, const char *host, int peer, int verify,
                      const char *ca, const char *cert, void **ctx, brix_status *st)
{
    assert(strcmp(host, "fixture.invalid") == 0 && peer == 1 && verify == 1);
    assert(strcmp(ca, "/fixture/ca") == 0 && strcmp(cert, "/fixture/proxy") == 0);
    if (fault("tls-connect")) {
        brix_status_set(st, XRDC_EAUTH, 0, "TLS refused");
        return -1;
    }
    io->ssl = io; *ctx = io;
    return 0;
}

void
__wrap_brix_tls_client_free(brix_io *io, void *ctx)
{
    assert(ctx == io && io->ssl == io);
    io->ssl = NULL;
    puts("TLS-FREE");
}

int
__wrap_brix_tls_read_some(brix_io *io, void *buf, size_t n, size_t *got, brix_status *st)
{
    ssize_t count;
    if (fault("tls-read")) {
        brix_status_set(st, XRDC_ESOCK, EIO, "TLS read failed");
        return -1;
    }
    count = __wrap_read(io->fd, buf, n);
    assert(count >= 0);
    *got = (size_t) count;
    return 0;
}

static void
feed(int fd, const char *path)
{
    char buf[8192];
    FILE *input = fopen(path, "rb");
    size_t n;
    assert(input != NULL);
    while ((n = fread(buf, 1, sizeof(buf), input)) != 0) {
        assert(write(fd, buf, n) == (ssize_t) n);
    }
    assert(!ferror(input)); fclose(input);
    assert(shutdown(fd, SHUT_WR) == 0);
}

static void
setup(brix_webfile *wf, int fd, int tls)
{
    memset(wf, 0, sizeof(*wf));
    snprintf(wf->host, sizeof(wf->host), "fixture.invalid");
    snprintf(wf->hostport, sizeof(wf->hostport), "fixture.invalid:443");
    snprintf(wf->path, sizeof(wf->path), "/nested/file");
    snprintf(wf->ca_dir, sizeof(wf->ca_dir), "/fixture/ca");
    snprintf(wf->client_cert, sizeof(wf->client_cert), "/fixture/proxy");
    wf->port = 443; wf->tls = tls; wf->verify = 1; wf->timeout_ms = 20;
    wf->io.fd = fd; wf->io.timeout_ms = 20;
    wf->connected = !tls;
}

int
main(int argc, char **argv)
{
    brix_webfile wf;
    brix_status st;
    int pair[2];
    char fdstr[32], output[512];
    ssize_t result;
    assert(argc == 8);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    feed(pair[1], argv[1]);
    setup(&wf, pair[0], atoi(argv[6]));
    snprintf(fdstr, sizeof(fdstr), "%d", pair[0]);
    assert(setenv("BRIX_WEB_FD", fdstr, 1) == 0);
    assert(setenv("BRIX_WEB_FAULT", argv[4], 1) == 0);
    assert(unsetenv("BRIX_WEB_DIALED") == 0);
    if (fault("long-request")) {
        memset(wf.path, 'a', sizeof(wf.path) - 1);
        memset(wf.auth, 'b', sizeof(wf.auth) - 1);
    }
    if (fault("empty-path")) { wf.path[0] = 0; }
    brix_status_clear(&st);
    result = wf.tls ? web_connect(&wf, &st) : 0;
    if (result == 0) {
        result = web_get_range(&wf, atoll(argv[2]), output, (size_t) atoi(argv[3]), &st);
    }
    printf("RESULT %zd %d connected=%d\nMESSAGE %s\n", result, st.kxr, wf.connected, st.msg);
    assert(result == atoi(argv[5]));
    if (result >= 0) {
        assert((size_t) result == strlen(argv[7]));
        assert(memcmp(output, argv[7], (size_t) result) == 0);
    }
    if (fault("connect")) { close(pair[0]); }
    web_disconnect(&wf);
    web_disconnect(&wf);
    assert(wf.connected == 0);
    assert(fcntl(pair[0], F_GETFD) == -1 && errno == EBADF);
    close(pair[1]);
    return 0;
}
