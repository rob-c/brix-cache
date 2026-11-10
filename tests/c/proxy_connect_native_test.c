/* Real proxy connect/bootstrap state machine with finite resolver/event seams. */
#include "net/proxy/proxy_internal.h"
#include "net/dns/dns.h"
#include <assert.h>
#include <fcntl.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_connection_t client, upstream;
    ngx_event_t read, write;
    ngx_stream_brix_srv_conf_t conf;
    brix_ctx_t client_ctx;
    brix_proxy_ctx_t proxy;
    ngx_ssl_t tls;
    ngx_ssl_connection_t ssl;
    const char *mode;
    int deferred, dns, aborts, cleanups, freed, flushes, tls_done, armed, fd;
} fixture;

/* WHAT: Recover the observer. WHY: No production hook. HOW: Enclosing cycle. */
static fixture *state(void) { return (fixture *) ngx_cycle; }

/* WHAT: Select a failure. WHY: Keep transitions independent. HOW: Mode string. */
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Supply an endpoint decision. WHY: Isolate socket/resolve phases.
 * HOW: Preserve configured host/port and exercise early return decisions. */
ngx_int_t __wrap_brix_proxy_select_endpoint(brix_proxy_ctx_t *proxy, ngx_connection_t *client,
    ngx_stream_brix_srv_conf_t *conf, brix_proxy_target_t *target)
{
    assert(proxy == &state()->proxy && client == &state()->client && conf == &state()->conf);
    if (mode("pooled")) { return NGX_OK; }
    if (mode("select-error")) { return NGX_ERROR; }
    target->host = &conf->proxy.host; target->port = 12345; return NGX_DECLINED;
}

/* WHAT: Observe the delegated GSI route. WHY: It must bypass ordinary DNS/socket.
 * HOW: Validate endpoint and return the selected terminal status. */
ngx_int_t __wrap_brix_proxy_gsi_connect_async(brix_proxy_ctx_t *proxy,
    ngx_stream_brix_srv_conf_t *conf, ngx_str_t *host, uint16_t port)
{
    assert(proxy == &state()->proxy && conf == &state()->conf);
    assert(host == &conf->proxy.host && port == 12345);
    return mode("gsi-error") ? NGX_ERROR : NGX_OK;
}

/* WHAT: Supply concrete resolver results. WHY: Connect must honor answer order.
 * HOW: Inline/deferred callbacks and optional unusable first address. */
ngx_int_t __wrap_brix_dns_resolve(brix_dns_req_t *req)
{
    fixture *f = state(); struct sockaddr_in *address;
    f->dns++; assert(req->port == 12345 && req->socktype == SOCK_STREAM && req->af == BRIX_AF_AUTO);
    assert(req->name.len == 15 && !memcmp(req->name.data, "fixture.invalid", 15));
    if (mode("dns-start")) { return NGX_ERROR; }
    req->rc = mode("dns-error") ? NGX_ERROR : NGX_OK;
    req->error = mode("dns-error") ? "finite NXDOMAIN" : NULL;
    req->naddrs = mode("dns-empty") ? 0 : 1;
    address = (struct sockaddr_in *) &req->addrs[0].ss;
    address->sin_family = AF_INET; address->sin_port = htons(req->port);
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK); req->addrs[0].len = sizeof(*address);
    if (mode("second-family")) {
        req->addrs[1] = req->addrs[0]; req->naddrs = 2; address->sin_family = AF_UNSPEC;
    }
    if (mode("no-family")) { address->sin_family = AF_UNSPEC; }
    if (!f->deferred) { req->handler(req); }
    return NGX_OK;
}

int __real_ngx_nonblocking(ngx_socket_t);
/* WHAT: Inject nonblocking setup failure. WHY: The socket must not leak.
 * HOW: Observe the real fd and preserve the normal host implementation. */
int __wrap_ngx_nonblocking(ngx_socket_t fd)
{
    state()->fd = fd;
    return mode("nonblocking") ? NGX_ERROR : __real_ngx_nonblocking(fd);
}

/* WHAT: Supply nginx's connection allocation boundary. WHY: Own real socket state.
 * HOW: Stack events plus the real pool and bootstrap allocation below. */
ngx_connection_t *__wrap_ngx_get_connection(ngx_socket_t fd, ngx_log_t *log)
{
    fixture *f = state(); f->fd = fd; assert(log == &f->log);
    if (mode("connection")) { return NULL; }
    f->upstream.fd = fd; return &f->upstream;
}

/* WHAT: Count connection release. WHY: Failed pool/bootstrap must free the slot.
 * HOW: Observe the allocator's matching release boundary. */
void __wrap_ngx_free_connection(ngx_connection_t *connection)
{
    assert(connection == &state()->upstream); state()->freed++;
}

ngx_pool_t *__real_ngx_create_pool(size_t, ngx_log_t *);
/* WHAT: Fail pool creation. WHY: Exercise partially acquired connection cleanup.
 * HOW: Use the actual nginx pool for every other case. */
ngx_pool_t *__wrap_ngx_create_pool(size_t size, ngx_log_t *log)
{
    return mode("pool") ? NULL : __real_ngx_create_pool(size, log);
}

void *__real_ngx_palloc(ngx_pool_t *, size_t);
/* WHAT: Fail bootstrap allocation. WHY: No incomplete bootstrap may be sent.
 * HOW: Override only this fixture's production allocation boundary. */
void *__wrap_ngx_palloc(ngx_pool_t *pool, size_t size)
{
    return mode("bootstrap") ? NULL : __real_ngx_palloc(pool, size);
}

/* WHAT: Supply synchronous/asynchronous connect outcomes. WHY: Events differ.
 * HOW: Check the pinned sockaddr and real O_NONBLOCK fd before returning. */
int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    const struct sockaddr_in *in = (const struct sockaddr_in *) address;
    assert(fd == state()->fd && length == sizeof(*in) && in->sin_family == AF_INET);
    assert(in->sin_port == htons(12345) && in->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(fcntl(fd, F_GETFL) & O_NONBLOCK);
    if (mode("connect-error")) { errno = ECONNREFUSED; return -1; }
    if (mode("connecting") || mode("no-timeout")) { errno = EINPROGRESS; return -1; }
    return 0;
}

/* WHAT: Observe event registration. WHY: A failed write event cannot progress.
 * HOW: Match the upstream event and return a finite result. */
ngx_int_t __wrap_ngx_handle_write_event(ngx_event_t *event, size_t lowat)
{
    assert(event == &state()->write && lowat == 0); state()->armed++;
    return mode("event-error") ? NGX_ERROR : NGX_OK;
}

/* WHAT: Release an incomplete upstream. WHY: Cleanup must run on each terminal fault.
 * HOW: Close the real fd/pool and remove any real nginx connect timer. */
void __wrap_brix_proxy_cleanup(brix_proxy_ctx_t *proxy)
{
    fixture *f = state(); assert(proxy == &f->proxy); f->cleanups++;
    if (f->write.timer_set) { ngx_del_timer(&f->write); }
    if (f->ssl.connection) { SSL_free(f->ssl.connection); f->ssl.connection = NULL; }
    if (proxy->conn) {
        close(proxy->conn->fd); ngx_destroy_pool(proxy->conn->pool); proxy->conn = NULL;
    }
}

/* WHAT: Observe delayed failure. WHY: A returned caller cannot receive DNS errors.
 * HOW: Assert resolve completion precedes abort, then release any acquired state. */
void __wrap_brix_proxy_abort(brix_proxy_ctx_t *proxy, const char *reason)
{
    assert(!proxy->dns_inflight && reason != NULL); state()->aborts++;
    __wrap_brix_proxy_cleanup(proxy);
}

/* WHAT: Check bootstrap framing and username. WHY: Policy must survive connect.
 * HOW: Decode the real login request and verify every expected username byte. */
ngx_int_t __wrap_brix_proxy_flush(brix_proxy_ctx_t *proxy)
{
    xrdw_login_req_t login; const char *name = getenv("BRIX_PROXY_USER");
    assert(proxy->wbuf_len == 68 && !proxy->wbuf_owned);
    ClientRequestHdr *header = (ClientRequestHdr *) (proxy->wbuf + 44);
    assert(ntohs(header->requestid) == kXR_login);
    xrdw_login_req_unpack(header->body, &login);
    assert(!memcmp(login.username, name, strlen(name)));
    state()->flushes++; return mode("flush-error") ? NGX_ERROR : NGX_OK;
}

/* WHAT: Attach real SSL state. WHY: SNI setup must run on a valid object.
 * HOW: Only handshake scheduling is synthetic; context and SNI remain OpenSSL. */
ngx_int_t __wrap_ngx_ssl_create_connection(ngx_ssl_t *tls, ngx_connection_t *connection, ngx_uint_t flags)
{
    fixture *f = state(); assert(tls == &f->tls && connection == &f->upstream);
    assert(flags == (NGX_SSL_BUFFER | NGX_SSL_CLIENT));
    if (mode("tls-create")) { return NGX_ERROR; }
    f->ssl.connection = SSL_new(tls->ctx); assert(f->ssl.connection);
    connection->ssl = &f->ssl; return NGX_OK;
}

/* WHAT: Observe SNI and async handshake selection. WHY: Explicit names take precedence.
 * HOW: Inspect real SSL metadata and return AGAIN only for the deferred case. */
ngx_int_t __wrap_ngx_ssl_handshake(ngx_connection_t *connection)
{
    const char *name = SSL_get_servername(connection->ssl->connection, TLSEXT_NAMETYPE_host_name);
    assert(!strcmp(name, mode("tls-name") ? "explicit.invalid" : "fixture.invalid"));
    return mode("tls-again") ? NGX_AGAIN : NGX_OK;
}

/* WHAT: Observe completed TLS. WHY: It must use the installed upstream callback.
 * HOW: Count completion without starting an unrelated bootstrap receive loop. */
void __wrap_brix_proxy_tls_handshake_done(ngx_connection_t *connection)
{
    assert(connection == &state()->upstream); state()->tls_done++;
}

/* WHAT: Construct the public connect inputs. WHY: Exercise actual buffer/events.
 * HOW: Stack contexts, real clock/timer tree, explicit login and TLS policies. */
static void setup(fixture *f, const char *user)
{
    ngx_cycle = &f->cycle; f->cycle.log = &f->log; ngx_time_init();
    assert(ngx_event_timer_init(&f->log) == NGX_OK); f->fd = -1;
    f->client.log = &f->log; f->upstream.read = &f->read; f->upstream.write = &f->write;
    f->read.data = f->write.data = &f->upstream;
    f->proxy.client_conn = &f->client; f->proxy.client_ctx = &f->client_ctx; f->proxy.conf = &f->conf;
    ngx_str_set(&f->conf.proxy.host, "fixture.invalid");
    f->conf.proxy.connect_timeout = mode("no-timeout") ? 0 : 2000;
    f->conf.proxy.login_user = atoi(user);
    memcpy(f->conf.proxy.login_user_name, "fixed-us", 9);
    snprintf(f->client_ctx.login.user, sizeof(f->client_ctx.login.user), "client");
    if (mode("empty-user")) { f->client_ctx.login.user[0] = 0; }
    if (mode("no-client")) { f->proxy.client_ctx = NULL; }
    if (!strncmp(f->mode, "gsi-", 4)) { f->conf.proxy.auth = BRIX_PROXY_AUTH_GSI; }
    if (!strncmp(f->mode, "tls-", 4)) {
        f->conf.proxy.upstream_tls = 1; f->tls.ctx = SSL_CTX_new(TLS_client_method()); assert(f->tls.ctx);
        f->conf.proxy.tls_ctx = &f->tls;
        if (mode("tls-name")) { ngx_str_set(&f->conf.proxy.upstream_tls_name, "explicit.invalid"); }
    }
}

/* WHAT: Run one connect transition. WHY: Check inline/deferred error ownership.
 * HOW: Explicit outcomes, real fd closure and event/timer state assertions. */
int main(int argc, char **argv)
{
    fixture f = {0}; ngx_int_t rc; int expected;
    assert(argc == 6); f.mode = argv[1]; f.deferred = atoi(argv[2]); expected = atoi(argv[4]);
    assert(setenv("BRIX_PROXY_USER", argv[5], 1) == 0); setup(&f, argv[3]);
    rc = brix_proxy_connect(&f.proxy, &f.client, &f.conf);
    if (f.deferred && f.proxy.dns_inflight) {
        assert(rc == NGX_OK); f.proxy.dns_req.handler(&f.proxy.dns_req);
        assert(f.aborts == (expected == NGX_ERROR));
    } else { assert(rc == expected); }
    assert(!f.proxy.dns_inflight);
    if (mode("connecting")) { assert(f.write.timer_set && f.proxy.state == XRD_PX_CONNECTING); }
    if (mode("no-timeout")) { assert(!f.write.timer_set && f.proxy.state == XRD_PX_CONNECTING); }
    printf("dns=%d aborts=%d cleanups=%d freed=%d flushes=%d tls=%d\n",
        f.dns, f.aborts, f.cleanups, f.freed, f.flushes, f.tls_done);
    __wrap_brix_proxy_cleanup(&f.proxy); SSL_CTX_free(f.tls.ctx);
    if (f.fd >= 0) { assert(fcntl(f.fd, F_GETFD) == -1 && errno == EBADF); }
    return 0;
}
