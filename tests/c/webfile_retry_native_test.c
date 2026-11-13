/* Exercise real persistent HTTP file reads with finite socket peers.
 * Only stat, dialing, and time are controlled; response parsing stays real. */
#include "protocols/http/webfile_internal.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>

/* WHAT: Read scenario state. WHY: Keep cases process-local. HOW: Environment. */
static int mode(const char *value)
{
    return strcmp(getenv("BRIX_WEB_CASE"), value) == 0;
}

/* WHAT: Advance an observer. WHY: Assert attempts precisely. HOW: Decimal env. */
static unsigned step(const char *key)
{
    const char *old = getenv(key);
    unsigned count = old ? (unsigned) atoi(old) : 0;
    char value[32];
    snprintf(value, sizeof(value), "%u", count + 1);
    assert(setenv(key, value, 1) == 0);
    return count;
}

/* WHAT: Supply stat metadata. WHY: Isolate HTTP read behavior. HOW: Exact inputs. */
int __wrap_brix_web_stat(const brix_weburl *u, const char *path, const char *bearer,
    int verify, const char *ca, const char *cert, brix_statinfo *si, brix_status *st)
{
    assert(strcmp(u->host, "fixture.invalid") == 0);
    assert(strcmp(path, "/data") == 0 && verify == 1);
    assert(bearer == NULL || strcmp(bearer, "test-token") == 0);
    assert(ca == NULL || strcmp(ca, "/ca") == 0);
    assert(cert == NULL || strcmp(cert, "/cert") == 0);
    step("BRIX_WEB_STAT");
    if (mode("stat-error")) {
        brix_status_set(st, kXR_NotAuthorized, EACCES, "stat denied");
        return -1;
    }
    memset(si, 0, sizeof(*si));
    si->size = 10; si->flags = mode("directory") ? kXR_isDir : 0;
    return 0;
}

void *__real_calloc(size_t, size_t);
/* WHAT: Fail file allocation. WHY: Verify clean refusal. HOW: Selected calloc. */
void *__wrap_calloc(size_t count, size_t size)
{
    if (mode("allocation") && size == sizeof(brix_webfile)) { return NULL; }
    return __real_calloc(count, size);
}

/* WHAT: Supply config fallback. WHY: Test precedence. HOW: Explicit env value. */
int __wrap_brix_xrdrc_default_ms(const char *key, int *out)
{
    const char *value = getenv("BRIX_WEB_CONFIG_WINDOW");
    assert(strcmp(key, "max_stall_ms") == 0);
    if (value == NULL) { return 0; }
    *out = atoi(value);
    return 1;
}

/* WHAT: Advance monotonic time. WHY: Bound retry tests. HOW: Two ms per read. */
uint64_t __wrap_brix_mono_ns(void)
{
    return (uint64_t) step("BRIX_WEB_CLOCK") * 2000000ULL;
}

/* WHAT: Observe backoff. WHY: Check reset after progress. HOW: Print attempt. */
void __wrap_brix_backoff_sleep_fast(unsigned attempt)
{
    printf("BACKOFF %u\n", attempt);
    step("BRIX_WEB_BACKOFF");
}

/* WHAT: Supply finite peers. WHY: Exercise reconnect ownership. HOW: Socketpair. */
int __wrap_brix_tcp_connect(const char *host, int port, int timeout, brix_status *st)
{
    unsigned call = step("BRIX_WEB_CONNECT");
    int pair[2];
    char descriptor[32];
    assert(strcmp(host, "fixture.invalid") == 0 && port == 80);
    assert(timeout == 20 || timeout == WEB_TIMEOUT_MS);
    if (mode("connect-error") || mode("deadline") || (mode("retry-once") && !call)) {
        brix_status_set(st, XRDC_ESOCK, ECONNREFUSED, "connection refused");
        return -1;
    }
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    snprintf(descriptor, sizeof(descriptor), "%d", pair[1]);
    assert(setenv("BRIX_WEB_PEER", descriptor, 1) == 0);
    return pair[0];
}

/* WHAT: Choose response fragments. WHY: Prove progress survives reconnects.
 * HOW: Keep Content-Length complete while closing after the selected prefix. */
static size_t fragment(size_t length)
{
    if (mode("progress")) { return length > 1 ? 1 : length; }
    if (mode("short") || mode("partial-auth") || mode("partial-eof")
        || mode("partial-error")) { return length > 2 ? 2 : length; }
    return length;
}

/* WHAT: Respond to a real Range request. WHY: Verify resume offsets and bytes.
 * HOW: A finite socket response, never a replacement for the parser/read loop. */
int __wrap_brix_write_full(brix_io *io, const void *data, size_t size, brix_status *st)
{
    const char *request = data, *range = strstr(request, "Range: bytes=");
    long long first, last;
    char response[256];
    unsigned call = step("BRIX_WEB_REQUEST");
    int peer = atoi(getenv("BRIX_WEB_PEER")), status = 206, count;
    size_t length, send;
    (void) io; (void) st;
    assert(size > 0 && range != NULL);
    assert(sscanf(range, "Range: bytes=%lld-%lld", &first, &last) == 2);
    assert(first >= 0 && last < 10 && first <= last);
    length = (size_t) (last - first + 1); send = fragment(length);
    if (call && mode("partial-auth")) { status = 403; send = 0; }
    if (call && mode("partial-eof")) { status = 416; send = 0; }
    if (call && mode("partial-error")) { send = 0; }
    count = snprintf(response, sizeof(response),
        "HTTP/1.1 %d reply\r\nContent-Length: %zu\r\n\r\n%.*s",
        status, length, (int) send, "abcdefghij" + first);
    assert(count > 0 && (size_t) count < sizeof(response));
    assert(write(peer, response, (size_t) count) == count);
    assert(close(peer) == 0);
    printf("RANGE %lld %lld\n", first, last);
    return 0;
}

/* WHAT: Check construction and teardown. WHY: Preserve options and ownership.
 * HOW: Inspect the real file handle and observe close through EBADF. */
static brix_webfile *open_file(int optional, int timeout, brix_status *st)
{
    brix_weburl url = {0};
    brix_statinfo si = {0};
    brix_webfile *wf;
    snprintf(url.host, sizeof(url.host), "fixture.invalid"); url.port = 80;
    wf = brix_webfile_open(&url, "/data", optional ? NULL : "test-token", 1,
        optional ? NULL : "/ca", optional ? NULL : "/cert", timeout,
        optional ? NULL : &si, st);
    if (mode("stat-error") || mode("directory") || mode("allocation")) {
        assert(wf == NULL); return NULL;
    }
    assert(wf != NULL && brix_webfile_size(wf) == 10);
    assert(optional || si.size == 10);
    assert(wf->io.fd == -1 && !wf->connected);
    assert(strcmp(wf->hostport, "fixture.invalid:80") == 0);
    assert(strcmp(wf->ca_dir, optional ? "" : "/ca") == 0);
    assert(strcmp(wf->client_cert, optional ? "" : "/cert") == 0);
    assert(strcmp(wf->auth, optional ? "" : "Authorization: Bearer test-token\r\n") == 0);
    assert(wf->timeout_ms == (timeout > 0 ? timeout : WEB_TIMEOUT_MS));
    return wf;
}

/* WHAT: Run one bounded contract. WHY: Expose all failures to pytest.
 * HOW: Compare returned bytes, attempts, metadata, and descriptor cleanup. */
int main(int argc, char **argv)
{
    brix_status st = {0};
    brix_webfile *wf;
    char data[32] = {0};
    ssize_t result;
    int fd, off, len;
    assert(argc == 8 && setenv("BRIX_WEB_CASE", argv[1], 1) == 0);
    brix_webfile_close(NULL, &st);
    if (mode("window")) {
        printf("WINDOW %d\n", webfile_window_ms()); return 0;
    }
    wf = open_file(atoi(argv[5]), atoi(argv[6]), &st);
    if (wf == NULL) { printf("OPEN-ERROR %s\n", st.msg); return 0; }
    off = atoi(argv[2]); len = atoi(argv[3]);
    result = brix_webfile_pread(wf, off, data, (size_t) len, &st);
    printf("RESULT %zd\n", result);
    assert(result == atoi(argv[4]));
    if (result > 0) { assert(memcmp(data, "abcdefghij" + off, (size_t) result) == 0); }
    fd = wf->io.fd;
    brix_webfile_close(wf, &st);
    if (fd >= 0) { assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF); }
    assert(atoi(argv[7]) == (getenv("BRIX_WEB_REQUEST") ? atoi(getenv("BRIX_WEB_REQUEST")) : 0));
    return 0;
}
