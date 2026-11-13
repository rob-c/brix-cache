/* Real TLS completion callback: trust decision, lifecycle and event ownership. */
#include "net/proxy/proxy_internal.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_connection_t upstream;
    ngx_ssl_connection_t ssl;
    ngx_event_t read, write;
    brix_ctx_t client;
    brix_proxy_ctx_t proxy;
    const char *mode;
    int cleanup, aborts, flushes, reads, writes;
} fixture;

static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

void __wrap_brix_proxy_cleanup(brix_proxy_ctx_t *proxy)
{
    assert(proxy == &state()->proxy);
    state()->cleanup++;
}

void __wrap_brix_proxy_abort(brix_proxy_ctx_t *proxy, const char *reason)
{
    assert(proxy == &state()->proxy && strstr(reason, "proxy:"));
    if (mode("untrusted")) { assert(strstr(reason, "peer verification failed")); }
    if (mode("handshake")) { assert(strstr(reason, "handshake failed")); }
    state()->aborts++;
}

ngx_int_t __wrap_brix_proxy_flush(brix_proxy_ctx_t *proxy)
{
    assert(proxy == &state()->proxy && proxy->state == XRD_PX_BOOTSTRAP);
    assert(proxy->bs_phase == XRD_PX_BS_HANDSHAKE && proxy->rhdr_pos == 0);
    state()->flushes++;
    if (!mode("partial") && !mode("write-error")) { proxy->wbuf_pos = proxy->wbuf_len; }
    return mode("flush-error") ? NGX_ERROR : NGX_OK;
}

ngx_int_t __wrap_ngx_handle_read_event(ngx_event_t *event, ngx_uint_t flags)
{
    assert(event == &state()->read && flags == 0);
    state()->reads++;
    return mode("read-error") ? NGX_ERROR : NGX_OK;
}

ngx_int_t __wrap_ngx_handle_write_event(ngx_event_t *event, size_t lowat)
{
    assert(event == &state()->write && lowat == 0);
    state()->writes++;
    return mode("write-error") ? NGX_ERROR : NGX_OK;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    fixture f = {0};
    f.mode = argv[1]; ngx_cycle = &f.cycle; f.cycle.log = &f.log;
    f.upstream.data = &f.proxy; f.upstream.read = &f.read; f.upstream.write = &f.write;
    f.upstream.ssl = &f.ssl; f.proxy.client_ctx = &f.client;
    f.proxy.wbuf_len = 68; f.proxy.rhdr_pos = 9;
    SSL_CTX *tls = SSL_CTX_new(TLS_client_method()); assert(tls);
    f.ssl.connection = SSL_new(tls); assert(f.ssl.connection);
    f.ssl.handshaked = !mode("handshake");
    SSL_set_verify_result(f.ssl.connection,
                          mode("untrusted") ? X509_V_ERR_CERT_HAS_EXPIRED : X509_V_OK);
    if (mode("destroyed")) { f.client.destroyed = 1; }
    if (mode("no-client")) { f.proxy.client_ctx = NULL; }
    brix_proxy_tls_handshake_done(&f.upstream);
    int gone = mode("destroyed") || mode("no-client");
    int trust_error = mode("handshake") || mode("untrusted");
    int event_error = mode("write-error") || mode("read-error");
    assert(f.cleanup == gone);
    assert(f.aborts == (trust_error || event_error || mode("flush-error")));
    assert(f.flushes == (!gone && !trust_error));
    assert(f.reads == (mode("normal") || mode("read-error")));
    assert(f.writes == (mode("partial") || mode("write-error")));
    if (f.flushes) {
        assert(f.read.handler == brix_proxy_read_handler);
        assert(f.write.handler == brix_proxy_write_handler);
    } else {
        assert(!f.read.handler && !f.write.handler && f.proxy.rhdr_pos == 9);
    }
    SSL_free(f.ssl.connection); SSL_CTX_free(tls);
    return 0;
}
