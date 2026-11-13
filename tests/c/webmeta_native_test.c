/* Real keep-alive PROPFIND exchanges against a finite local HTTP peer. */
#include "protocols/http/web_ka.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* WHAT: Select a fault. WHY: Keep transport failures scoped. HOW: Environment. */
static int mode(const char *name) { return !strcmp(getenv("BRIX_KA_MODE"), name); }

/* WHAT: Consume an armed fault. WHY: Interrupted calls must recover. HOW: Unset. */
static int armed(const char *name)
{
    if (!mode(name) || !getenv("BRIX_KA_ARM")) { return 0; }
    assert(unsetenv("BRIX_KA_ARM") == 0); return 1;
}

int __real_poll(struct pollfd *, nfds_t, int);
/* WHAT: Interrupt or fail readiness. WHY: Distinguish timeout/EINTR/errors.
 * HOW: Inject only after the request has been sent, then use real poll. */
int __wrap_poll(struct pollfd *fds, nfds_t n, int timeout)
{
    if (armed("poll-eintr")) { errno = EINTR; return -1; }
    if (armed("poll-error")) { errno = EIO; return -1; }
    if (armed("poll-timeout")) { return 0; }
    return __real_poll(fds, n, timeout);
}

ssize_t __real_read(int, void *, size_t);
/* WHAT: Fragment or fail reads. WHY: Headers must tolerate arbitrary boundaries.
 * HOW: Limit actual socket reads, or inject one selected errno. */
ssize_t __wrap_read(int fd, void *buf, size_t n)
{
    size_t limit = (size_t) atoi(getenv("BRIX_KA_CHUNK"));
    if (armed("read-eintr")) { errno = EINTR; return -1; }
    if (armed("read-error")) { errno = EIO; return -1; }
    if (limit && n > limit) { n = limit; }
    return __real_read(fd, buf, n);
}

void *__real_malloc(size_t);
/* WHAT: Fail the response allocation. WHY: No partial body may escape.
 * HOW: Arm only after sending and reject the next production malloc. */
void *__wrap_malloc(size_t n)
{
    if (armed("allocation")) { errno = ENOMEM; return NULL; }
    return __real_malloc(n);
}

int __real_brix_write_full(brix_io *, const void *, size_t, brix_status *);
/* WHAT: Observe request transmission. WHY: Scope later faults to response I/O.
 * HOW: Real write except for one explicit EPIPE case. */
int __wrap_brix_write_full(brix_io *io, const void *data, size_t n, brix_status *st)
{
    int rc;
    if (mode("write-error")) {
        brix_status_set(st, XRDC_ESOCK, EPIPE, "finite write failure"); return -1;
    }
    rc = __real_brix_write_full(io, data, n, st);
    assert(setenv("BRIX_KA_ARM", "1", 1) == 0); return rc;
}

/* WHAT: Verify connection defaults. WHY: Null optional fields must initialize.
 * HOW: Call the real initializer and compare its public state. */
static void defaults(void)
{
    brix_kaconn k;
    brix_kaconn_init(&k, NULL, 80, 0, 1, NULL, NULL, 0);
    assert(k.host[0] == 0 && k.ca_dir[0] == 0 && k.client_cert[0] == 0);
    assert(k.io.fd == -1 && k.timeout_ms == 30000 && !k.connected);
    brix_kaconn_disconnect(&k);
}

/* WHAT: Execute a bounded exchange. WHY: Verify body ownership and disconnects.
 * HOW: Compare exact returned bytes/status and require the socket closes. */
int main(int argc, char **argv)
{
    brix_webmeta m; brix_status st = {0}; char *body = NULL, long_path[4000];
    size_t length = 0; int rc = 0, fd = -1;
    const char *path;
    assert(argc == 8); defaults();
    assert(setenv("BRIX_KA_MODE", argv[1], 1) == 0);
    brix_webmeta_init(&m, "127.0.0.1", atoi(argv[2]), 0, 1, "/ca", "/cert",
        mode("anonymous") ? NULL : "fixture-token", 100);
    assert(!strcmp(m.ka.ca_dir, "/ca") && !strcmp(m.ka.client_cert, "/cert"));
    memset(long_path, 'x', sizeof(long_path)); long_path[sizeof(long_path) - 1] = 0;
    path = mode("long-path") ? long_path : (mode("root-path") ? "" : "/tree");
    for (int i = 0; i < atoi(argv[7]); i++) {
        rc = brix_webmeta_propfind(&m, path, atoi(argv[3]), &body, &length, &st);
        assert(rc == atoi(argv[4]));
        if (rc == 0) {
            assert(length == strlen(argv[6]) && !memcmp(body, argv[6], length));
            assert(body[length] == 0 && m.ka.connected);
        } else { assert(body == NULL && length == 0 && st.kxr == atoi(argv[5])); }
        free(body); body = NULL;
    }
    fd = m.ka.io.fd;
    printf("result=%d status=%d connected=%d %s\n", rc, st.kxr, m.ka.connected, st.msg);
    brix_kaconn_disconnect(&m.ka); brix_kaconn_disconnect(&m.ka);
    assert(!m.ka.connected && m.ka.io.fd == -1);
    if (fd >= 0) { assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF); }
    return 0;
}
