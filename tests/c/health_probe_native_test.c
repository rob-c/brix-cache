/* Finite readiness and TLS completions drive the real health-probe state machine. */
#include "net/manager/health_check.h"
#include "observability/metrics/metrics_macros.h"
#include "net/manager/health_check_internal.h"
#include <assert.h>
#include <openssl/ssl.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_connection_t connection;
    ngx_event_t read, write;
    ngx_ssl_connection_t ssl;
    ngx_stream_brix_srv_conf_t config;
    brix_hc_ctx_t probe;
    const char *mode;
    unsigned char input[32], output[128];
    size_t length, offset, sent;
    unsigned finishes, passed, read_events, write_events, receives;
    int fail_alloc;
} fixture;

static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

void __wrap_brix_hc_finish(brix_hc_ctx_t *probe, int passed)
{
    assert(probe == &state()->probe && state()->finishes++ == 0);
    state()->passed = passed;
}

ngx_int_t __wrap_ngx_handle_read_event(ngx_event_t *event, ngx_uint_t flags)
{
    assert(event == &state()->read && flags == 0);
    state()->read_events++;
    return mode("read-event-error") ? NGX_ERROR : NGX_OK;
}

ngx_int_t __wrap_ngx_handle_write_event(ngx_event_t *event, size_t lowat)
{
    assert(event == &state()->write && lowat == 0);
    state()->write_events++;
    return mode("write-event-error") ? NGX_ERROR : NGX_OK;
}

void *__real_ngx_palloc(ngx_pool_t *pool, size_t size);
void *__wrap_ngx_palloc(ngx_pool_t *pool, size_t size)
{
    return state()->fail_alloc ? NULL : __real_ngx_palloc(pool, size);
}

static ssize_t send_bytes(ngx_connection_t *connection, u_char *data, size_t length)
{
    fixture *f = state(); assert(connection == &f->connection);
    if (mode("send-error") || mode("tls-send-error")) { return NGX_ERROR; }
    if (mode("send-again") || mode("write-event-error")) { return NGX_AGAIN; }
    if (mode("partial") && length > 1) { length = 1; }
    assert(f->sent + length <= sizeof(f->output));
    memcpy(f->output + f->sent, data, length); f->sent += length;
    return (ssize_t) length;
}

static ssize_t receive_bytes(ngx_connection_t *connection, u_char *data, size_t length)
{
    fixture *f = state(); assert(connection == &f->connection); f->receives++;
    if (mode("read-eof")) { return 0; }
    if (f->offset >= 8 && mode("body-eof")) { return 0; }
    if (f->offset >= 8 && mode("body-again") && f->receives == 2) { return NGX_AGAIN; }
    if (mode("read-again") || f->offset == f->length) { return NGX_AGAIN; }
    if (length > f->length - f->offset) { length = f->length - f->offset; }
    if (mode("partial") && length > 1) { length = 1; }
    memcpy(data, f->input + f->offset, length); f->offset += length;
    return (ssize_t) length;
}

ngx_int_t __wrap_brix_outbound_start_tls(ngx_ssl_t *ctx, ngx_connection_t *connection,
                                        const char *sni, void (*done)(ngx_connection_t *))
{
    fixture *f = state();
    assert(ctx == f->config.upstream_tls_ctx && connection == &f->connection);
    assert(!strcmp(sni, "source.example"));
    if (mode("tls-start-error")) { return NGX_ERROR; }
    f->ssl.handshaked = !mode("tls-handshake-error");
    SSL_set_verify_result(f->ssl.connection, mode("tls-untrusted") ? X509_V_ERR_CERT_REVOKED : X509_V_OK);
    f->fail_alloc = mode("tls-alloc-error");
    done(connection);
    return NGX_OK;
}

int main(int argc, char **argv)
{
    assert(argc == 7);
    fixture f = {0}; f.mode = argv[1]; ngx_cycle = &f.cycle; f.cycle.log = &f.log;
    ngx_queue_init(&ngx_posted_events);
    ngx_pool_t *pool = ngx_create_pool(4096, &f.log); assert(pool);
    f.connection.pool = pool; f.connection.log = &f.log; f.connection.data = &f.probe;
    f.connection.read = &f.read; f.connection.write = &f.write;
    f.connection.send = send_bytes; f.connection.recv = receive_bytes;
    f.read.data = &f.connection; f.write.data = &f.connection;
    f.probe.pool = pool; f.probe.conn = &f.connection; f.probe.log = &f.log;
    f.probe.conf = &f.config; strcpy(f.probe.host, "source.example");
    f.probe.phase = atoi(argv[2]); f.probe.probe_type = mode("stat") ? BRIX_HC_TYPE_STAT : BRIX_HC_TYPE_PING;
    f.probe.tls_capable = mode("deferred") || mode("deferred-alloc-error");
    ServerResponseHdr response = {0}; response.status = htons(atoi(argv[3]));
    unsigned body = (unsigned) atoi(argv[4]); response.dlen = htonl(body);
    memcpy(f.input, &response, sizeof(response)); f.length = sizeof(response) + (body > 8 ? 0 : body);
    SSL_CTX *context = SSL_CTX_new(TLS_client_method()); assert(context);
    f.ssl.connection = SSL_new(context); assert(f.ssl.connection); f.connection.ssl = &f.ssl;
    if (!strncmp(f.mode, "tls-", 4)) {
        uint32_t flags = htonl(kXR_gotoTLS); memcpy(f.input + 12, &flags, 4);
        f.config.upstream_tls = !mode("tls-disabled");
        f.config.upstream_tls_ctx = (ngx_ssl_t *) &f;
    }
    f.fail_alloc = mode("alloc-error") || mode("deferred-alloc-error");
    f.read.timedout = mode("timeout");
    for (unsigned i = 0; i < 100; i++) {
        brix_hc_read_handler(&f.read);
        if (f.finishes || f.probe.phase != (brix_hc_phase_t) atoi(argv[2]) || f.read.posted
            || mode("read-again")) { break; }
    }
    assert(f.finishes == (unsigned) atoi(argv[5]));
    assert(f.passed == (unsigned) atoi(argv[6]));
    if (mode("stat") && !f.finishes) {
        ClientStatRequest *request = (ClientStatRequest *) f.output;
        assert(f.sent == sizeof(*request) + 1 && ntohs(request->requestid) == kXR_stat);
        assert(ntohl(request->dlen) == 1 && f.output[sizeof(*request)] == '/');
    }
    if (f.read.posted) { ngx_delete_posted_event(&f.read); }
    SSL_free(f.ssl.connection); SSL_CTX_free(context); ngx_destroy_pool(pool);
    return 0;
}
