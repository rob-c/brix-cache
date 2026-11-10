/* Real shared session records and socket transport; only terminal callbacks
 * and selected event/send failures are observed at their external seams. */
#include "net/proxy/forward_relay_response_internal.h"
#include "protocols/root/session/registry.h"
#include "core/compat/shm_slots.h"
#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    ngx_log_t log;
    ngx_cycle_t cycle;
    ngx_conf_t cf;
    ngx_connection_t upstream, client;
    ngx_event_t upstream_read, upstream_write, client_read;
    brix_proxy_ctx_t proxy;
    brix_ctx_t ctx;
    ngx_shm_zone_t *zone;
    int pair[2], aborts, cleanups, error, arm_error, send_error, send_again;
} fixture_t;

ngx_int_t
__wrap_brix_send_error(brix_ctx_t *ctx, ngx_connection_t *connection,
    uint16_t code, const char *message)
{
    fixture_t *f = connection->data;
    assert(ctx == &f->ctx && message != NULL);
    f->error = code;
    return NGX_OK;
}

void
__wrap_brix_proxy_abort(brix_proxy_ctx_t *proxy, const char *reason)
{
    fixture_t *f = proxy->client_conn->data;
    assert(reason != NULL);
    f->aborts++;
}

void
__wrap_brix_proxy_cleanup(brix_proxy_ctx_t *proxy)
{
    fixture_t *f = proxy->client_conn->data;
    f->cleanups++;
}

ngx_int_t __real_ngx_handle_read_event(ngx_event_t *, ngx_uint_t);

ngx_int_t
__wrap_ngx_handle_read_event(ngx_event_t *event, ngx_uint_t flags)
{
    ngx_connection_t *connection = event->data;
    fixture_t *f = connection->data;
    return f->arm_error ? NGX_ERROR : __real_ngx_handle_read_event(event, flags);
}

/* Inject a bounded send outcome; normal cases still transmit real bytes. */
static ssize_t
send_upstream(ngx_connection_t *connection, u_char *data, size_t length)
{
    fixture_t *f = connection->data;
    if (f->send_error) { return NGX_ERROR; }
    if (f->send_again) { return NGX_AGAIN; }
    return ngx_unix_send(connection, data, length);
}

/* Allocate the real handle table with the same canonical slab-lock helper
 * used by the server. Only the handle zone is needed by these finite units. */
static void
configure_registry(fixture_t *f)
{
    assert(ngx_list_init(&f->cycle.shared_memory, f->cf.pool, 4,
                        sizeof(ngx_shm_zone_t)) == NGX_OK);
    assert(brix_configure_session_registry(&f->cf, 4) == NGX_OK);
    ngx_shm_zone_t *zones = f->cycle.shared_memory.part.elts;
    assert(f->cycle.shared_memory.part.nelts == 2);
    f->zone = &zones[1];
    assert(ngx_shm_alloc(&f->zone->shm) == NGX_OK);
    ngx_slab_pool_t *slab = (ngx_slab_pool_t *) f->zone->shm.addr;
    slab->end = f->zone->shm.addr + f->zone->shm.size;
    slab->min_shift = 3;
    slab->addr = f->zone->shm.addr;
    ngx_slab_init(slab);
    int bootstrap = 0;
    assert(brix_shm_table_alloc(f->zone, &bootstrap, 0,
                                &slab->mutex, NULL) == &bootstrap);
    assert(f->zone->init(f->zone, NULL) == NGX_OK);
}

static void
setup(fixture_t *f, char **argv)
{
    ngx_time_init(); ngx_pid = getpid(); ngx_os_argv = argv;
    ngx_cycle = &f->cycle;
    f->cycle.log = &f->log;
    assert(ngx_os_init(&f->log) == NGX_OK);
    ngx_event_flags = 0;
    ngx_queue_init(&ngx_posted_events);
    f->cf.cycle = &f->cycle; f->cf.log = &f->log;
    f->cf.pool = f->cycle.pool = ngx_create_pool(16384, &f->log);
    assert(f->cf.pool != NULL);
    configure_registry(f);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, f->pair) == 0);
    f->upstream.fd = f->pair[0]; f->upstream.log = &f->log;
    f->upstream.data = f; f->upstream.send = send_upstream;
    f->upstream.read = &f->upstream_read;
    f->upstream.write = &f->upstream_write;
    f->upstream_read.data = f->upstream_write.data = &f->upstream;
    f->upstream_write.ready = 1;
    f->client.data = f; f->client.log = &f->log;
    f->client.read = &f->client_read;
    f->client_read.data = &f->client; f->client_read.ready = 1;
    f->proxy.client_conn = &f->client; f->proxy.client_ctx = &f->ctx;
    f->proxy.conn = &f->upstream;
    memset(f->ctx.bound_sessid, 0x71, sizeof(f->ctx.bound_sessid));
}

static void
teardown(fixture_t *f)
{
    if (f->proxy.wbuf != NULL) { ngx_free(f->proxy.wbuf); }
    if (f->proxy.saved_req != NULL) { ngx_free(f->proxy.saved_req); }
    if (f->proxy.wait_retry_req != NULL) { ngx_free(f->proxy.wait_retry_req); }
    if (f->proxy.resp_body != NULL) { ngx_free(f->proxy.resp_body); }
    close(f->pair[0]); close(f->pair[1]);
    ngx_shm_free(&f->zone->shm);
    ngx_destroy_pool(f->cf.pool);
}

static void
publish(fixture_t *f, int index)
{
    brix_file_t file = {0};
    file.fd = f->pair[0]; file.readable = 1;
    file.path = "/bound/data";
    brix_session_handle_publish(f->ctx.bound_sessid, index, &file);
    brix_shared_handle_entry_t entry;
    assert(brix_session_handle_lookup(f->ctx.bound_sessid, index, &entry));
    assert(!strcmp(entry.path, "/bound/data"));
}

static u_char *
request(fixture_t *f, uint16_t opcode, size_t payload)
{
    u_char *bytes = ngx_alloc(XRD_REQUEST_HDR_LEN + payload, &f->log);
    assert(bytes != NULL);
    memset(bytes, 0, XRD_REQUEST_HDR_LEN + payload);
    ClientRequestHdr *header = (ClientRequestHdr *) (void *) bytes;
    header->streamid[0] = 0xa1; header->streamid[1] = 0xb2;
    header->requestid = htons(opcode); header->dlen = htonl(payload);
    bytes[4] = 3;
    return bytes;
}

static void
receive_exact(fixture_t *f, void *output, size_t length)
{
    assert(recv(f->pair[1], output, length, MSG_WAITALL) == (ssize_t) length);
}

static void
expect_open(fixture_t *f)
{
    u_char bytes[XRD_REQUEST_HDR_LEN + sizeof("/bound/data") - 1];
    receive_exact(f, bytes, sizeof(bytes));
    ClientOpenRequest *header = (ClientOpenRequest *) (void *) bytes;
    assert(header->streamid[0] == 0 && header->streamid[1] == 0xfe);
    assert(ntohs(header->requestid) == kXR_open);
    assert(ntohl(header->dlen) == sizeof("/bound/data") - 1);
    assert(!memcmp(bytes + XRD_REQUEST_HDR_LEN, "/bound/data", sizeof("/bound/data") - 1));
    xrdw_open_req_t body;
    assert(xrdw_open_req_unpack(((ClientRequestHdr *) (void *) bytes)->body,
                                &body) == 0);
    assert(body.options == kXR_open_read && body.mode == 0);
}

static void
open_response(fixture_t *f, const u_char handle[4])
{
    f->proxy.resp_status = kXR_ok; f->proxy.resp_dlen = 4;
    f->proxy.resp_body = ngx_alloc(4, &f->log);
    assert(f->proxy.resp_body != NULL);
    memcpy(f->proxy.resp_body, handle, 4);
}

static void
fault_mode(fixture_t *f, const char *mode)
{
    f->send_error = strstr(mode, "send-error") != NULL;
    f->send_again = strstr(mode, "send-again") != NULL;
    f->arm_error = strstr(mode, "arm-error") != NULL;
}

static void
check_forwarded(fixture_t *f, uint16_t opcode, size_t length,
    const u_char handle[4])
{
    u_char bytes[XRD_REQUEST_HDR_LEN + 48];
    assert(length <= sizeof(bytes));
    receive_exact(f, bytes, length);
    assert(bytes[0] == 0xa1 && bytes[1] == 0xb2);
    assert(f->proxy.fwd_reqid == opcode && f->proxy.state == XRD_PX_FORWARDING);
    assert(!memcmp(bytes + (opcode == kXR_readv ? XRD_REQUEST_HDR_LEN : 4), handle, 4));
    if (opcode == kXR_readv) {
        assert(!memcmp(bytes + XRD_REQUEST_HDR_LEN + 16, "\x80\x90\xa0\xb0", 4));
        assert(bytes[XRD_REQUEST_HDR_LEN + 32] == BRIX_MAX_FILES);
        assert(f->proxy.fwd_local_fh == -1);
    }
    assert(f->proxy.wait_retry_req_len == length);
    assert(!memcmp(f->proxy.wait_retry_req, bytes, length));
    assert(f->proxy.saved_req == NULL && f->proxy.resp_body == NULL);
}

/* Requests are published by one session, opened on its bound secondary, and
 * forwarded using all four bytes of each independently allocated handle. */
static void
lazy_success(fixture_t *f, const char *mode)
{
    const u_char handle[] = {0xff, 0x23, 0x45, 0x67};
    uint16_t opcode = !strcmp(mode, "pgread") ? kXR_pgread : kXR_read;
    if (!strcmp(mode, "readv") || !strcmp(mode, "chain")) { opcode = kXR_readv; }
    size_t payload = opcode == kXR_readv ? 48 : 0;
    u_char *bytes = request(f, opcode, payload);
    publish(f, 3); publish(f, 4);
    if (payload) {
        bytes[XRD_REQUEST_HDR_LEN] = 3; bytes[XRD_REQUEST_HDR_LEN + 16] = 4;
        bytes[XRD_REQUEST_HDR_LEN + 32] = BRIX_MAX_FILES;
        brix_proxy_fh_bind(&f->proxy.fh_map[4], (u_char *) "\x80\x90\xa0\xb0", 4);
    }
    assert(brix_proxy_lazy_open(&f->proxy, &f->ctx, &f->client, 3,
                              bytes, XRD_REQUEST_HDR_LEN + payload) == NGX_OK);
    assert(f->proxy.fh_map[3].fh_state == BRIX_PROXY_FH_PENDING);
    assert(f->proxy.saved_req == bytes && f->proxy.wbuf == NULL);
    expect_open(f);
    if (!strcmp(mode, "chain")) {
        f->proxy.lazy_open_pending_fhs[0] = 4; f->proxy.lazy_open_pending_count = 1;
        open_response(f, handle);
        assert(brix_proxy_relay_lazy_open(&f->proxy) == 1);
        expect_open(f);
        assert(f->proxy.lazy_open_pending_count == 0);
        open_response(f, (u_char *) "\x80\x90\xa0\xb0");
    } else { open_response(f, handle); }
    fault_mode(f, mode);
    assert(brix_proxy_relay_lazy_open(&f->proxy) == 1);
    if (f->send_error || f->arm_error) { assert(f->aborts == 1); return; }
    if (f->send_again) { assert(f->proxy.wbuf_pos == 0); return; }
    check_forwarded(f, opcode, XRD_REQUEST_HDR_LEN + payload, handle);
}

static void
lazy_refusal(fixture_t *f, const char *mode)
{
    publish(f, 3);
    int index = !strcmp(mode, "invalid-handle") ? BRIX_MAX_FILES : 3;
    if (!strcmp(mode, "missing-handle")) { index = 2; }
    if (!strcmp(mode, "foreign-session")) { f->ctx.bound_sessid[0] ^= 1; }
    fault_mode(f, mode);
    ngx_int_t result = brix_proxy_lazy_open(&f->proxy, &f->ctx, &f->client,
                          index, request(f, kXR_read, 0), XRD_REQUEST_HDR_LEN);
    if (f->send_error || f->arm_error) {
        assert(result == NGX_ERROR && f->aborts == 1);
        return;
    }
    assert(result == NGX_OK);
    if (f->send_again) {
        assert(f->proxy.wbuf_pos == 0 && f->proxy.saved_req != NULL);
        return;
    }
    assert(f->error == kXR_InvalidRequest && f->proxy.saved_req == NULL);
}

static void
lazy_empty(fixture_t *f, const char *mode)
{
    if (!strcmp(mode, "not-lazy")) {
        assert(brix_proxy_relay_lazy_open(&f->proxy) == 0);
        return;
    }
    f->proxy.fwd_is_lazy_open = 1; f->proxy.fwd_local_fh = 3;
    f->proxy.fh_map[3].fh_state = BRIX_PROXY_FH_PENDING;
    open_response(f, (u_char *) "1234");
    if (!strcmp(mode, "upstream-denied")) {
        f->proxy.resp_status = kXR_error;
        f->proxy.saved_req = request(f, kXR_read, 0);
    }
    assert(brix_proxy_relay_lazy_open(&f->proxy) == 1);
    assert(f->proxy.state == XRD_PX_IDLE && f->ctx.state == XRD_ST_REQ_HEADER);
    assert(f->client_read.posted && f->proxy.saved_req == NULL);
    assert(f->proxy.resp_body == NULL);
    if (!strcmp(mode, "upstream-denied")) {
        assert(f->error == kXR_IOError);
        assert(f->proxy.fh_map[3].fh_state == BRIX_PROXY_FH_FREE);
    }
}

static void
wait_case(fixture_t *f, const char *mode)
{
    ngx_event_t event = {.data = &f->proxy};
    if (!strcmp(mode, "wait-null")) { event.data = NULL; }
    if (!strcmp(mode, "wait-no-context")) { f->proxy.client_ctx = NULL; }
    if (!strcmp(mode, "wait-destroyed")) { f->ctx.destroyed = 1; }
    if (!strcmp(mode, "wait-no-upstream")) { f->proxy.conn = NULL; }
    size_t payload = !strcmp(mode, "wait-payload") ? 12 : 0;
    f->proxy.wait_retry_req_len = XRD_REQUEST_HDR_LEN + payload;
    f->proxy.wait_retry_local_fh = 3;
    if (strcmp(mode, "wait-no-request")) {
        f->proxy.wait_retry_req = request(f, kXR_read, payload);
    }
    fault_mode(f, mode);
    brix_proxy_wait_handler(&event);
    if (f->proxy.client_ctx == NULL || f->ctx.destroyed) {
        assert(f->cleanups == 1); return;
    }
    if (event.data == NULL || f->proxy.conn == NULL || !strcmp(mode, "wait-no-request")) { return; }
    assert(f->proxy.wait_retry_req == NULL);
    assert(f->proxy.fwd_reqid == kXR_read && f->proxy.fwd_local_fh == 3);
    assert(f->proxy.fwd_streamid[0] == 0xa1 && f->proxy.fwd_streamid[1] == 0xb2);
    assert(f->proxy.fwd_payload_len == payload);
    if (f->send_error || f->arm_error) { assert(f->aborts == 1); return; }
    if (f->send_again) { assert(f->proxy.wbuf_pos == 0); return; }
    u_char bytes[XRD_REQUEST_HDR_LEN + 12];
    receive_exact(f, bytes, XRD_REQUEST_HDR_LEN + payload);
    assert(bytes[4] == 3 && f->proxy.wbuf == NULL);
}

static void
slots(fixture_t *f)
{
    for (int i = 0; i < BRIX_MAX_FILES; i++) {
        assert(brix_proxy_alloc_local_fh(&f->proxy) == i);
        f->proxy.fh_map[i].fh_state = i % 2 ? BRIX_PROXY_FH_BOUND : BRIX_PROXY_FH_PENDING;
    }
    assert(brix_proxy_alloc_local_fh(&f->proxy) == -1);
    f->proxy.fh_map[5].fh_state = BRIX_PROXY_FH_FREE;
    assert(brix_proxy_alloc_local_fh(&f->proxy) == 5);
}

int
main(int argc, char **argv)
{
    assert(argc == 2);
    fixture_t *f = calloc(1, sizeof(*f));
    assert(f != NULL);
    signal(SIGPIPE, SIG_IGN);
    setup(f, argv);
    const char *mode = argv[1];
    if (!strncmp(mode, "wait", 4)) { wait_case(f, mode); }
    else if (!strcmp(mode, "slots")) { slots(f); }
    else if (!strcmp(mode, "no-saved") || !strcmp(mode, "not-lazy") || !strcmp(mode, "upstream-denied")) { lazy_empty(f, mode); }
    else if (!strncmp(mode, "deferred-", 9) || !strcmp(mode, "read") || !strcmp(mode, "pgread") || !strcmp(mode, "readv") || !strcmp(mode, "chain")) { lazy_success(f, mode); }
    else { lazy_refusal(f, mode); }
    teardown(f); free(f);
    return 0;
}
