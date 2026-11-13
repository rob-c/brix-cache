/* HTTP preaccess reverse-DNS waits retain request ownership through completion/cancel. */
#include "core/http/http_peer_name.h"
#include "core/config/http_common.h"
#include "observability/metrics/io_monitor.h"
#include "net/dns/dns.h"
#include <assert.h>

typedef struct {
    const char *mode;
    ngx_http_request_t request;
    brix_io_monitor_t monitor;
    brix_dns_rev_req_t *pending;
    unsigned dispatches, resumes, cancelled;
    int armed;
} fixture;

/* WHAT: Recover a request fixture. WHY: Faults must remain local to this process.
 * HOW: Use the test cycle's existing opaque context. */
static fixture *state(void) { return (fixture *) ngx_cycle->conf_ctx; }

/* WHAT: Compare the selected scenario. WHY: Setup must remain real before arming failures.
 * HOW: Read the process-owned mode without changing production state. */
static int mode(const char *name) { return !strcmp(state()->mode, name); }

void *__real_ngx_pcalloc(ngx_pool_t *, size_t);
ngx_pool_cleanup_t *__real_ngx_pool_cleanup_add(ngx_pool_t *, size_t);
void *__real_ngx_array_push(ngx_array_t *);

/* WHAT: Refuse the wait object. WHY: Resource pressure must fall through without a dangling callback.
 * HOW: Fail only after fixture setup, at the request allocation boundary. */
void *__wrap_ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    if (state()->armed && mode("wait-allocation")) { return NULL; }
    return __real_ngx_pcalloc(pool, size);
}

/* WHAT: Refuse cancellation registration. WHY: An unowned async request cannot be started.
 * HOW: Leave the real pool intact while returning a finite cleanup failure. */
ngx_pool_cleanup_t *__wrap_ngx_pool_cleanup_add(ngx_pool_t *pool, size_t size)
{
    if (state()->armed && mode("cleanup-allocation")) { return NULL; }
    return __real_ngx_pool_cleanup_add(pool, size);
}

/* WHAT: Refuse phase registration. WHY: Configuration must report a missing handler slot.
 * HOW: Fault only the explicit postconfiguration case. */
void *__wrap_ngx_array_push(ngx_array_t *array)
{
    if (mode("phase-allocation")) { return NULL; }
    return __real_ngx_array_push(array);
}

/* WHAT: Supply the real request's monitor. WHY: The wait-once latch belongs to that request.
 * HOW: Return its owned monitor or the selected allocation refusal. */
brix_io_monitor_t *__wrap_brix_http_monitor_get(ngx_http_request_t *request)
{
    assert(request == &state()->request); return mode("no-monitor") ? NULL : &state()->monitor;
}

/* WHAT: Model a cached PTR result. WHY: A known result needs no asynchronous wait.
 * HOW: Validate address bounds and return only the requested cache outcome. */
ngx_int_t __wrap_brix_dns_reverse_cached(const struct sockaddr *address, socklen_t length,
                                        char *name, size_t capacity)
{
    assert(address && address->sa_family == AF_INET && length == sizeof(struct sockaddr_in));
    assert(capacity >= sizeof("peer.example")); strcpy(name, "peer.example");
    if (mode("cached")) { return NGX_OK; }
    return mode("negative") ? NGX_DECLINED : NGX_AGAIN;
}

/* WHAT: Complete inline, defer or refuse reverse lookup. WHY: The callback may run before dispatch returns.
 * HOW: Retain the actual request pointer until completion or cancellation. */
ngx_int_t __wrap_brix_dns_reverse(brix_dns_rev_req_t *request)
{
    fixture *f = state(); assert(++f->dispatches == 1);
    assert(request->len == sizeof(struct sockaddr_in) && request->ss.ss_family == AF_INET);
    if (mode("dispatch-refusal")) { return NGX_ERROR; }
    if (mode("inline")) { request->rc = NGX_OK; request->handler(request); }
    else { f->pending = request; }
    return NGX_OK;
}

/* WHAT: Observe abort cleanup. WHY: A client disconnect must cancel exactly one pending lookup.
 * HOW: Clear ownership before the request pool releases its memory. */
void __wrap_brix_dns_reverse_cancel(brix_dns_rev_req_t *request)
{
    fixture *f = state(); assert(request == f->pending && ++f->cancelled == 1);
    f->pending = NULL;
}

/* WHAT: Observe phase resumption. WHY: Inline completion must not recurse into the phase engine.
 * HOW: Require restored request handlers and one deferred resume. */
void __wrap_ngx_http_core_run_phases(ngx_http_request_t *request)
{
    assert(request == &state()->request && ++state()->resumes == 1);
    assert(request->read_event_handler == ngx_http_block_reading);
    assert(request->write_event_handler == ngx_http_core_run_phases);
}

/* WHAT: Set up the real preaccess phase array. WHY: The private handler must be reached by its public hook.
 * HOW: Install finite module contexts and retrieve the registered function pointer. */
static ngx_http_handler_pt register_handler(ngx_pool_t *pool)
{
    ngx_http_core_main_conf_t main = {0};
    assert(ngx_array_init(&main.phases[NGX_HTTP_PREACCESS_PHASE].handlers,
                          pool, 1, sizeof(ngx_http_handler_pt)) == NGX_OK);
    ngx_http_core_module.ctx_index = 0; void *main_conf[] = {&main};
    ngx_http_conf_ctx_t context = {.main_conf = main_conf}; ngx_conf_t conf = {.ctx = &context};
    ngx_int_t rc = brix_http_peer_name_postconfiguration(&conf);
    if (mode("phase-allocation")) { assert(rc == NGX_ERROR); return NULL; }
    assert(rc == NGX_OK && main.phases[NGX_HTTP_PREACCESS_PHASE].handlers.nelts == 1);
    return *(ngx_http_handler_pt *) main.phases[NGX_HTTP_PREACCESS_PHASE].handlers.elts;
}

/* WHAT: Configure early refusal conditions. WHY: Invalid addresses and unnecessary policy must not dispatch.
 * HOW: Vary one prerequisite without changing the production handler. */
static void configure_request(fixture *f, ngx_http_brix_common_conf_t *common,
                              ngx_connection_t *connection, void **locations)
{
    common->common.acc.resolve_hosts = !mode("unneeded");
    if (mode("no-config")) { locations[0] = NULL; }
    if (mode("no-address")) { connection->sockaddr = NULL; }
    if (mode("oversize-address")) { connection->socklen = sizeof(struct sockaddr_storage) + 1; }
    if (mode("already-waited")) { f->monitor.peer_name_waited = 1; }
}

/* WHAT: Exercise completion and cancellation ownership. WHY: Every async wait must resume or cancel once.
 * HOW: Invoke the real registered phase, complete the finite resolver and destroy the pool. */
static void check_request(fixture *f, ngx_http_handler_pt handler, ngx_pool_t *pool)
{
    ngx_http_brix_common_conf_t common = {0}; void *locations[] = {&common};
    ngx_http_brix_common_module.ctx_index = 0;
    struct sockaddr_in address = {.sin_family = AF_INET};
    address.sin_addr.s_addr = htonl(0xc0000201);
    ngx_connection_t connection = {.sockaddr = (struct sockaddr *) &address,
        .socklen = sizeof(address), .log = ngx_cycle->log};
    f->request.pool = pool; f->request.connection = &connection; f->request.loc_conf = locations;
    configure_request(f, &common, &connection, locations); f->armed = 1;
    ngx_int_t rc = handler(&f->request);
    if (f->pending) {
        assert(rc == NGX_AGAIN && f->monitor.peer_name_waited && f->resumes == 0);
        assert(f->request.read_event_handler == ngx_http_test_reading);
        assert(f->request.write_event_handler == ngx_http_request_empty_handler);
        if (mode("cancel")) { ngx_destroy_pool(pool); assert(f->cancelled == 1); return; }
        brix_dns_rev_req_t *pending = f->pending; f->pending = NULL;
        pending->rc = mode("answer-refusal") ? NGX_DECLINED : NGX_OK;
        pending->handler(pending); assert(f->resumes == 1);
        assert(handler(&f->request) == NGX_DECLINED && f->dispatches == 1);
    } else { assert(rc == NGX_DECLINED && f->resumes == 0); }
    ngx_destroy_pool(pool); assert(f->cancelled == 0);
}

/* WHAT: Run one preaccess contract. WHY: Module indices and fault state are process-local.
 * HOW: Allocate a real nginx pool, register the phase and release all ownership. */
int main(int argc, char **argv)
{
    assert(argc == 2); fixture f = {.mode = argv[1]}; ngx_log_t log = {0};
    ngx_cycle_t cycle = {.log = &log, .conf_ctx = (void ****) &f}; ngx_cycle = &cycle;
    ngx_pagesize = 4096; ngx_cacheline_size = 64;
    ngx_pool_t *pool = ngx_create_pool(4096, &log); assert(pool);
    ngx_http_handler_pt handler = register_handler(pool);
    if (handler) { check_request(&f, handler, pool); }
    else { ngx_destroy_pool(pool); }
    assert(!f.pending); puts("HTTP peer-name ownership verified"); return 0;
}
