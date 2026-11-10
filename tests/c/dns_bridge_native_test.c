/* Exercise the real thread/eventfd bridge with a controlled async DNS peer.
 * Worker threads, queues, wake descriptors and shutdown ownership stay real. */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <pthread.h>
#include <poll.h>
#include "net/dns/dns.h"
#include "native_alloc_fail.h"

typedef struct {
    const char *mode;
    ngx_connection_t conn;
    ngx_event_t read, write;
    brix_dns_policy_t policy;
    brix_dns_req_t *pending;
    brix_dns_rev_req_t *reverse_pending;
    int dispatched, freed, reverse, max;
} fixture;
typedef struct {
    fixture *f;
    ngx_int_t rc, answer;
    ngx_uint_t count;
    brix_dns_addr_t addresses[2];
    char text[256];
} worker;

static fixture *state(void) { return (fixture *) ngx_cycle->conf_ctx; }
static int mode(const char *value) { return strcmp(state()->mode, value) == 0; }

ngx_connection_t *__wrap_ngx_get_connection(ngx_socket_t fd, ngx_log_t *log) {
    fixture *f = state();
    f->conn.fd = fd; f->conn.log = log;
    f->conn.read = &f->read; f->conn.write = &f->write;
    f->read.data = &f->conn;
    return mode("connection-fail") ? NULL : &f->conn;
}
void __wrap_ngx_free_connection(ngx_connection_t *conn) {
    assert(conn == &state()->conn); state()->freed++;
}
static ngx_int_t add_event(ngx_event_t *event, ngx_int_t type, ngx_uint_t flags) {
    (void) flags;
    assert(event == &state()->read && type == NGX_READ_EVENT);
    return mode("event-fail") ? NGX_ERROR : NGX_OK;
}

static void finish_forward(brix_dns_req_t *req) {
    req->rc = mode("answer-error") ? NGX_ERROR : NGX_OK;
    req->naddrs = mode("empty") ? 0 : 2;
    req->error = mode("answer-error") ? "controlled NXDOMAIN" : NULL;
    for (unsigned i = 0; i < 2; i++) {
        struct sockaddr_in *sa = (struct sockaddr_in *) &req->addrs[i].ss;
        sa->sin_family = AF_INET; sa->sin_port = htons(req->port);
        sa->sin_addr.s_addr = htonl(0x7f000001 + i);
        req->addrs[i].len = sizeof(*sa);
    }
    req->handler(req);
}
ngx_int_t __wrap_brix_dns_resolve(brix_dns_req_t *req) {
    fixture *f = state(); f->dispatched++;
    assert(req->policy == &f->policy && req->port == 1094);
    assert(req->name.len == 12 && memcmp(req->name.data, "bridge.test.", 12) == 0);
    assert(req->socktype == SOCK_STREAM);
    if (mode("dispatch-error")) { return NGX_ERROR; }
    if (mode("inflight-exit")) { f->pending = req; return NGX_OK; }
    finish_forward(req); return NGX_OK;
}
static void finish_reverse(brix_dns_rev_req_t *req) {
    req->rc = mode("answer-error") ? NGX_DECLINED : NGX_OK;
    strcpy(req->name, "verified.example"); req->handler(req);
}
ngx_int_t __wrap_brix_dns_reverse(brix_dns_rev_req_t *req) {
    fixture *f = state(); f->dispatched++;
    assert(req->policy == &f->policy && req->ss.ss_family == AF_INET);
    if (mode("dispatch-error")) { return NGX_ERROR; }
    if (mode("inflight-exit")) { f->reverse_pending = req; return NGX_OK; }
    finish_reverse(req); return NGX_OK;
}

static void *lookup(void *argument) {
    worker *w = argument;
    fixture *f = w->f;
    const brix_dns_policy_t *policy = mode("no-policy") ? NULL : &f->policy;
    if (f->reverse) {
        struct sockaddr_in address = {.sin_family = AF_INET};
        address.sin_addr.s_addr = htonl(0x7f000001);
        socklen_t length = mode("oversize") ? sizeof(struct sockaddr_storage) + 1 : sizeof(address);
        w->rc = brix_dns_bridge_reverse(policy, (struct sockaddr *) &address,
            length, w->text, f->max ? (size_t) f->max : sizeof(w->text), &w->answer);
    } else {
        w->rc = brix_dns_bridge_resolve(policy, "bridge.test.", 1094, 0,
            SOCK_STREAM, w->addresses, (ngx_uint_t) f->max, &w->count,
            mode("no-error-buffer") ? NULL : w->text, sizeof(w->text));
    }
    return NULL;
}

static int declined(void) {
    return mode("not-ready") || mode("no-policy") || mode("off")
        || mode("empty-resolver") || mode("main") || mode("oversize")
        || mode("connection-fail") || mode("event-fail");
}
static void drive(worker *w) {
    fixture *f = w->f;
    if (mode("main")) { lookup(w); return; }
    pthread_t thread;
    if (mode("pending-exit")) { ngx_exiting = 1; }
    assert(pthread_create(&thread, NULL, lookup, w) == 0);
    if (!declined() && !mode("alloc-fail") && !mode("pending-exit")) {
        struct pollfd poller = {.fd = f->conn.fd, .events = POLLIN};
        assert(poll(&poller, 1, 3000) == 1);
        f->read.handler(&f->read);
        if (mode("inflight-exit")) { ngx_exiting = 1; }
    }
    assert(pthread_join(thread, NULL) == 0);
    if (f->pending) { finish_forward(f->pending); }
    if (f->reverse_pending) { finish_reverse(f->reverse_pending); }
    /* A timed-out pending item must have been removed before the next drain. */
    if (mode("pending-exit")) { f->read.handler(&f->read); }
}

static void verify_reverse(worker *w) {
    ngx_int_t expected = mode("dispatch-error") ? NGX_ERROR
        : (mode("answer-error") ? NGX_DECLINED : NGX_OK);
    assert(w->answer == expected);
    if (expected == NGX_OK) { assert(strncmp(w->text, "verified.example", strlen(w->text)) == 0); }
}
static void verify(worker *w) {
    fixture *f = w->f;
    if (declined()) { assert(w->rc == NGX_DECLINED && !f->dispatched); return; }
    if (mode("alloc-fail")) {
        assert(w->rc == (f->reverse ? NGX_DECLINED : NGX_ERROR)); return;
    }
    assert(w->rc == NGX_OK);
    if (mode("pending-exit") || mode("inflight-exit")) {
        assert(f->reverse ? w->answer == NGX_ERROR : w->count == 0); return;
    }
    if (f->reverse) { verify_reverse(w); return; }
    if (mode("dispatch-error") || mode("answer-error") || mode("empty")) {
        assert(w->count == 0 && w->text[0]); return;
    }
    assert(w->count == (ngx_uint_t) f->max);
    for (unsigned i = 0; i < w->count; i++) {
        struct sockaddr_in *sa = (struct sockaddr_in *) &w->addresses[i].ss;
        assert(sa->sin_port == htons(1094) && sa->sin_addr.s_addr == htonl(0x7f000001 + i));
    }
}

int main(int argc, char **argv) {
    assert(argc == 4);
    fixture f = {.mode = argv[1], .reverse = atoi(argv[2]), .max = atoi(argv[3])};
    ngx_log_t log = {0}; ngx_cycle_t cycle = {.log = &log, .conf_ctx = (void ****) &f};
    ngx_resolver_t resolver = {0}; resolver.connections.nelts = 1;
    ngx_cycle = &cycle; ngx_event_actions.add = add_event;
    ngx_time_init();
    f.policy.mode = BRIX_DNS_MODE_AUTO; f.policy.resolver = &resolver;
    f.policy.search = 1; f.policy.rc.nsearch = 2;
    if (mode("large-deadline")) { f.policy.rc.timeout = 10000; f.policy.rc.attempts = 10; }
    if (mode("off")) { f.policy.mode = BRIX_DNS_MODE_OFF; }
    if (mode("empty-resolver")) { resolver.connections.nelts = 0; }
    if (!mode("not-ready")) { assert(brix_dns_bridge_init_worker(&cycle) == NGX_OK); }
    if (mode("normal")) { assert(brix_dns_bridge_init_worker(&cycle) == NGX_OK); }
    if (mode("alloc-fail")) { native_alloc_arm("ngx_calloc", 0); }
    worker w = {.f = &f}; drive(&w); native_alloc_disarm(); verify(&w);
    if (mode("connection-fail") || mode("event-fail")) {
        assert(fcntl(f.conn.fd, F_GETFD) == -1 && errno == EBADF);
        assert(f.freed == mode("event-fail"));
    }
    ngx_uint_t requests, timeouts;
    brix_dns_bridge_stats(&requests, &timeouts);
    assert(requests == (ngx_uint_t) (!declined() && !mode("alloc-fail")));
    assert(timeouts == (ngx_uint_t) mode("inflight-exit"));
    printf("rc=%ld answer=%ld count=%lu requests=%lu timeouts=%lu dispatched=%d text=%s\n",
        (long) w.rc, (long) w.answer, (unsigned long) w.count, (unsigned long) requests,
        (unsigned long) timeouts, f.dispatched, w.text);
    return 0;
}
