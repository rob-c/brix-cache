/* Real nonblocking sockets and pipes exercise splice accounting and fallback.
 * Only terminal/event callbacks are observed; every byte transfer uses the
 * kernel. No fixture needs a running nginx worker or an external listener.
 */
#include "net/proxy/proxy_internal.h"
#include "protocols/root/connection/handler.h"
#include "protocols/root/connection/write_helpers.h"
#include "platform/platform_api.h"
#include <assert.h>
#include <signal.h>

typedef struct {
    brix_ctx_t ctx;
    brix_proxy_ctx_t proxy;
    ngx_stream_brix_srv_conf_t conf;
    ngx_connection_t client, upstream;
    ngx_event_t cr, cw, ur, uw;
    ngx_log_t log;
    ngx_cycle_t cycle;
    int upstream_pair[2], client_pair[2];
    int aborts, resumes, sends, arms, arm_error, alloc_error, relay_error;
    int header_mode, header_calls;
    char reason[128], queued[256];
    size_t queued_length;
} fixture_t;

/* WHAT: Observe aborts. WHY: Refusal must stop the pump. HOW: Save the reason. */
void __wrap_brix_proxy_abort(brix_proxy_ctx_t *proxy, const char *reason)
{
    fixture_t *f = (fixture_t *)proxy->client_ctx;
    f->aborts++;
    snprintf(f->reason, sizeof(f->reason), "%s", reason);
}

/* WHAT: Observe read resumption. WHY: Final bodies return to the request loop.
 * HOW: Count the callback without running another protocol request. */
ngx_int_t __wrap_brix_schedule_read_resume(ngx_connection_t *connection)
{
    fixture_t *f = connection->data;
    f->resumes++;
    return NGX_OK;
}

/* WHAT: Observe restoration of the normal writer. WHY: Deferred splice ends.
 * HOW: Count the restored event callback. */
void __wrap_ngx_stream_brix_send(ngx_event_t *event)
{
    ngx_connection_t *connection = event->data;
    fixture_t *f = connection->data;
    f->sends++;
}

/* WHAT: Record raw fallback ownership. WHY: A second response header corrupts
 * the stream. HOW: Copy exactly the tail bytes and release the passed owner. */
ngx_int_t __wrap_brix_queue_response_base(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *data, size_t length, u_char *owner)
{
    fixture_t *f = (fixture_t *)ctx;
    assert(c == &f->client && data == owner && length <= sizeof(f->queued));
    memcpy(f->queued, data, length);
    f->queued_length = length;
    ngx_free(owner);
    return f->relay_error ? NGX_ERROR : NGX_OK;
}

/* WHAT: Observe event registration. WHY: Backpressure must wait on the correct
 * side. HOW: Record the arm and optionally return a terminal registration error. */
static ngx_int_t arm_event(ngx_event_t *event)
{
    ngx_connection_t *connection = event->data;
    fixture_t *f = connection->data;
    f->arms++;
    return f->arm_error ? NGX_ERROR : NGX_OK;
}

/* WHAT: Register reads. WHY: Isolate event-loop scheduling. HOW: Observe seam. */
ngx_int_t __wrap_ngx_handle_read_event(ngx_event_t *event, ngx_uint_t flags)
{
    (void)flags;
    return arm_event(event);
}

/* WHAT: Register writes. WHY: Isolate event-loop scheduling. HOW: Observe seam. */
ngx_int_t __wrap_ngx_handle_write_event(ngx_event_t *event, size_t lowat)
{
    (void)lowat;
    return arm_event(event);
}

void *__real_ngx_alloc(size_t size, ngx_log_t *log);

/* WHAT: Refuse a fallback allocation on demand. WHY: Memory pressure must abort
 * without leaking a partial frame. HOW: Otherwise retain the real allocator. */
void *__wrap_ngx_alloc(size_t size, ngx_log_t *log)
{
    fixture_t *f = log->data;
    if (f != NULL && f->alloc_error) { return NULL; }
    return __real_ngx_alloc(size, log);
}

/* WHAT: Send headers using real sockets with bounded short-send outcomes.
 * WHY: A partially transmitted header must never be sent a second time.
 * HOW: Inject only the selected boundary and send all other bytes normally. */
static ssize_t send_header(ngx_connection_t *connection, u_char *data, size_t n)
{
    fixture_t *f = connection->data;
    f->header_calls++;
    if (f->header_mode == 1) { return NGX_AGAIN; }
    if (f->header_mode == 2 && f->header_calls > 1) { return NGX_AGAIN; }
    if (f->header_mode == 3) { return NGX_ERROR; }
    if (f->header_mode != 0 && n > 3) { n = 3; }
    return send(connection->fd, data, n, MSG_NOSIGNAL);
}

/* WHAT: Construct the complete transport pair. WHY: Exercise actual kernel
 * splice behavior. HOW: Initialize events, two socketpairs, and one pipe. */
static void setup(fixture_t *f, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    ngx_time_init(); ngx_pid = getpid(); ngx_os_argv = argv;
    ngx_cycle = &f->cycle; f->cycle.log = &f->log; f->log.data = f;
    assert(ngx_os_init(&f->log) == NGX_OK);
    ngx_queue_init(&ngx_posted_events);
    assert(ngx_event_timer_init(&f->log) == NGX_OK);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, f->upstream_pair) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, f->client_pair) == 0);
    assert(brix_plat_pipe2(f->proxy.splice_pipe, BRIX_PIPE_NONBLOCK) == 0);
    f->client.fd = f->client_pair[0]; f->upstream.fd = f->upstream_pair[0];
    f->client.log = f->upstream.log = &f->log;
    f->client.data = f->upstream.data = f;
    f->client.read = &f->cr; f->client.write = &f->cw;
    f->upstream.read = &f->ur; f->upstream.write = &f->uw;
    f->cr.data = f->cw.data = &f->client;
    f->ur.data = f->uw.data = &f->upstream;
    f->client.send = send_header;
    f->proxy.client_ctx = &f->ctx; f->proxy.client_conn = &f->client;
    f->proxy.conn = &f->upstream; f->proxy.conf = &f->conf;
    f->ctx.proxy = &f->proxy;
    f->proxy.splice_total = 9; f->proxy.splice_active = 1;
    f->proxy.resp_dlen = 9; f->proxy.resp_status = kXR_ok;
    f->proxy.fwd_local_fh = 2; f->proxy.fwd_reqid = kXR_read;
    f->proxy.state = XRD_PX_FORWARDING;
}

/* WHAT: Release only fixture-owned resources. WHY: Each case is independent.
 * HOW: Remove posted events/timers, free fallback bytes, then close descriptors. */
static void teardown(fixture_t *f)
{
    if (f->ur.posted) { ngx_delete_posted_event(&f->ur); }
    if (f->ur.timer_set) { ngx_del_timer(&f->ur); }
    ngx_free(f->proxy.resp_body);
    close(f->proxy.splice_pipe[0]); close(f->proxy.splice_pipe[1]);
    close(f->client_pair[0]); close(f->client_pair[1]);
    close(f->upstream_pair[0]); close(f->upstream_pair[1]);
}

/* WHAT: Saturate the downstream send queue. WHY: Trigger real EAGAIN instead
 * of replacing splice. HOW: Fill a deliberately small nonblocking socket. */
static void block_client(fixture_t *f)
{
    int size = 4096;
    char bytes[4096] = {0};
    assert(setsockopt(f->client.fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
    while (send(f->client.fd, bytes, sizeof(bytes), MSG_NOSIGNAL) > 0) { }
    assert(errno == EAGAIN);
}

/* WHAT: Verify completed transfer accounting. WHY: Both relay paths must count
 * the entire body once. HOW: Check state, handle bytes, and released accumulator. */
static void completed(fixture_t *f)
{
    assert(!f->proxy.splice_active && !f->proxy.splice_fallback);
    assert(f->proxy.splice_total == 0 && f->proxy.resp_body == NULL);
    assert(f->proxy.fh_map[2].bytes_read == 9);
    assert(f->resumes == 1 && f->ctx.state == XRD_ST_REQ_HEADER);
    assert(f->proxy.state == XRD_PX_IDLE);
}

/* WHAT: Exercise both under-draining fallbacks. WHY: A raw tail must preserve
 * bytes already sent. HOW: Fill only the selected side, pump, inspect, finish. */
static void fallback(fixture_t *f, int drain)
{
    if (drain) {
        block_client(f);
        f->cw.ready = 1;
        assert(write(f->upstream_pair[1], "body-tail", 9) == 9);
    }
    brix_proxy_splice_pump(&f->proxy);
    if (f->alloc_error || f->arm_error) { assert(f->aborts == 1); return; }
    assert(f->proxy.splice_fallback && !f->proxy.splice_active);
    assert(f->proxy.resp_dlen == 9 && f->ur.posted);
    assert(f->proxy.resp_body[9] == 0);
    if (drain) {
        assert(f->proxy.resp_body_pos == 9);
        assert(memcmp(f->proxy.resp_body, "body-tail", 9) == 0);
    } else {
        assert(f->proxy.resp_body_pos == 0);
        memcpy(f->proxy.resp_body, "body-tail", 9);
        f->proxy.resp_body_pos = 9;
    }
    brix_proxy_splice_fallback_finish(&f->proxy);
    assert(f->queued_length == 9 && memcmp(f->queued, "body-tail", 9) == 0);
    if (f->relay_error) { assert(f->aborts == 1 && f->resumes == 0); return; }
    completed(f);
}

/* WHAT: Resume a genuinely blocked writer. WHY: Backpressure must retain its
 * pipe bytes until writable. HOW: Drain the client, invoke the saved event. */
static void deferred(fixture_t *f, const char *mode)
{
    char data[65536];
    block_client(f);
    assert(write(f->upstream_pair[1], "body-tail", 9) == 9);
    brix_proxy_splice_pump(&f->proxy);
    assert(f->proxy.splice_active && f->cw.handler != NULL);
    if (f->arm_error) { assert(f->aborts == 1); return; }
    if (strcmp(mode, "destroyed") == 0) { f->ctx.destroyed = 1; }
    if (strcmp(mode, "missing-context") == 0) { f->client.data = NULL; }
    if (strcmp(mode, "missing-proxy") == 0) { f->ctx.proxy = NULL; }
    if (strcmp(mode, "inactive") == 0) { f->proxy.splice_active = 0; }
    while (read(f->client_pair[1], data, sizeof(data)) > 0) { }
    f->cw.handler(&f->cw);
    if (strcmp(mode, "deferred") == 0) {
        assert(read(f->client_pair[1], data, sizeof(data)) == 9);
        assert(memcmp(data, "body-tail", 9) == 0);
        completed(f);
    }
    if (strcmp(mode, "missing-proxy") == 0 || strcmp(mode, "inactive") == 0) {
        assert(f->sends == 1);
    }
    f->client.data = f;
}

/* WHAT: Exercise stream continuation and syscall failure boundaries.
 * WHY: A dropped peer must abort; oksofar must re-post buffered follow-up data.
 * HOW: Configure one boundary, pump the real descriptors, inspect the result. */
static void pump_case(fixture_t *f, const char *mode)
{
    if (strcmp(mode, "no-upstream") == 0) { f->proxy.conn = NULL; }
    if (strcmp(mode, "no-client") == 0) { f->proxy.client_conn = NULL; }
    if (strcmp(mode, "closed") == 0) { shutdown(f->upstream_pair[1], SHUT_WR); }
    if (strcmp(mode, "bad-upstream") == 0) { f->upstream.fd = -1; }
    if (strcmp(mode, "bad-client") == 0) { f->client.fd = -1; }
    if (strncmp(mode, "stream", 6) == 0) {
        f->proxy.resp_status = kXR_oksofar; f->conf.proxy.read_timeout = 250;
        assert(write(f->upstream_pair[1], "body-tail", 9) == 9);
    }
    if (strcmp(mode, "bad-client") == 0) {
        assert(write(f->upstream_pair[1], "body-tail", 9) == 9);
    }
    brix_proxy_splice_pump(&f->proxy);
    if (strncmp(mode, "no-", 3) == 0) { assert(f->resumes == 0); return; }
    if (strcmp(mode, "stream") == 0) {
        assert(f->proxy.fwd_streaming && f->ur.posted && f->ur.timer_set);
        assert(f->resumes == 0 && f->proxy.fh_map[2].bytes_read == 9);
        return;
    }
    assert(f->aborts == 1);
}

/* WHAT: Verify one-shot header framing with real bytes on the wire.
 * WHY: Partial header errors cannot safely fall back to another full header.
 * HOW: Configure a send boundary and check splice admission and actual length. */
static void header_case(fixture_t *f, int mode)
{
    char bytes[32];
    f->header_mode = mode;
    assert(write(f->upstream_pair[1], "body-tail", 9) == 9);
    ngx_int_t result = brix_proxy_try_splice(&f->proxy);
    if (mode == 1) { assert(result == NGX_DECLINED && f->aborts == 0); return; }
    if (mode == 2 || mode == 3) {
        assert(result == NGX_ERROR && f->aborts == 1 && f->resumes == 0);
        return;
    }
    assert(result == NGX_OK);
    assert(read(f->client_pair[1], bytes, sizeof(bytes)) == 17);
    assert(memcmp(bytes + 8, "body-tail", 9) == 0);
    completed(f);
}

/* WHAT: Run one finite transport contract. WHY: Bound all failure injections.
 * HOW: Initialize, select the isolated case, then release fixture ownership. */
int main(int argc, char **argv)
{
    assert(argc == 2);
    fixture_t *f = calloc(1, sizeof(*f)); assert(f != NULL);
    setup(f, argv);
    const char *mode = argv[1];
    f->arm_error = strstr(mode, "arm-error") != NULL;
    f->alloc_error = strstr(mode, "alloc-error") != NULL;
    f->relay_error = strstr(mode, "relay-error") != NULL;
    if (strncmp(mode, "fill", 4) == 0) { fallback(f, 0); }
    else if (strncmp(mode, "drain", 5) == 0) { fallback(f, 1); }
    else if (strncmp(mode, "header", 6) == 0) { header_case(f, atoi(mode + 6)); }
    else if (strncmp(mode, "deferred", 8) == 0 || strcmp(mode, "destroyed") == 0
             || strcmp(mode, "missing-context") == 0
             || strcmp(mode, "missing-proxy") == 0 || strcmp(mode, "inactive") == 0) {
        deferred(f, mode);
    } else { pump_case(f, mode); }
    teardown(f); free(f);
    return 0;
}
