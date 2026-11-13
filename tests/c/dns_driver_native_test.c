/* WHAT: Drive the shipped asynchronous DNS and thread completion state machines.
 * WHY: Retry, cancellation and malformed replies must preserve request ownership.
 * HOW: 1. Keep real nginx pools/events and control only resolver and task dispatch. */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_thread_pool.h>
#include <netdb.h>
#include <assert.h>
#include "net/dns/dns.h"

typedef struct {
    const char *mode;
    brix_dns_req_t req;
    brix_dns_policy_t policy;
    ngx_resolver_t resolver;
    ngx_resolver_ctx_t ctx;
    ngx_resolver_addr_t answer;
    struct sockaddr_in address;
    struct sockaddr_in6 address6;
    struct addrinfo libc_answer;
    ngx_thread_task_t *task;
    ngx_pool_t *pool;
    unsigned queries, released, callbacks, stored, destroyed, detached_answers;
    char names[8][BRIX_RESOLV_DOMAIN_LEN * 2];
} fixture;

/* WHAT: Recover this process's fixture. WHY: Production globals stay unchanged.
 * HOW: 1. Use the fixture cycle's opaque configuration pointer. */
static fixture *state(void) { return (fixture *) ngx_cycle->conf_ctx; }
/* WHAT: Select the finite case. WHY: Each process owns one fault setting.
 * HOW: 1. Compare the current fixture's immutable case name. */
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Retain completion evidence. WHY: The handler can release its request.
 * HOW: 1. Count callbacks and require all backend ownership to be cleared first. */
static void completed(brix_dns_req_t *req)
{
    assert(req == &state()->req && !req->rctx && !req->task);
    state()->callbacks++;
}
/* WHAT: Report an uncached name. WHY: The resolver driver is the subject.
 * HOW: 1. Leave the request untouched. 2. Return the normal cache-miss status. */
ngx_int_t __wrap_brix_dns_cache_lookup(brix_dns_req_t *req)
{ (void) req; return NGX_DECLINED; }
/* WHAT: Observe cache publication. WHY: Terminal TTLs must remain valid.
 * HOW: 1. Validate the TTL. 2. Count the publication without retaining the request. */
void __wrap_brix_dns_cache_store(brix_dns_req_t *req)
{ assert(req->ttl >= 0); state()->stored++; }

/* WHAT: Supply one owned resolver context. WHY: Startup failures cannot leak it.
 * HOW: 1. Record candidate names and provide explicit null/sentinel failures. */
ngx_resolver_ctx_t *__wrap_ngx_resolve_start(ngx_resolver_t *resolver,
                                           ngx_resolver_ctx_t *temp)
{
    fixture *fixture_data = state(); assert(resolver == &fixture_data->resolver && fixture_data->queries < 8);
    assert(temp->name.len < sizeof(fixture_data->names[0]));
    memcpy(fixture_data->names[fixture_data->queries], temp->name.data, temp->name.len);
    fixture_data->names[fixture_data->queries++][temp->name.len] = 0;
    if (mode("no-resolver")) { return NGX_NO_RESOLVER; }
    if (mode("start-fail")) { return NULL; }
    memset(&fixture_data->ctx, 0, sizeof(fixture_data->ctx)); return &fixture_data->ctx;
}

/* WHAT: Publish a finite answer or failure. WHY: Retries must be posted, not recursive.
 * HOW: 1. Complete inline except for explicit in-flight cancellation. */
ngx_int_t __wrap_ngx_resolve_name(ngx_resolver_ctx_t *ctx)
{
    fixture *fixture_data = state(); assert(ctx == &fixture_data->ctx);
    if (mode("dispatch-fail")) { return NGX_ERROR; }
    if (mode("cancel")) { return NGX_OK; }
    ctx->state = NGX_OK; ctx->naddrs = 1; ctx->addrs = &fixture_data->answer;
    ctx->valid = 1015;
    if (mode("min-ttl") || mode("default-ttl")) { ctx->valid = 999; }
    if (mode("max-ttl")) { ctx->valid = 1100; }
    if ((mode("retry") || mode("policy-removed") || mode("cancel-posted")) && fixture_data->queries == 1) {
        ctx->state = NGX_RESOLVE_TIMEDOUT;
    }
    if ((mode("search") || mode("absolute-search")) && fixture_data->queries < 3) {
        ctx->state = NGX_RESOLVE_NXDOMAIN;
    }
    ctx->handler(ctx); return NGX_OK;
}
/* WHAT: Observe resolver release. WHY: Retries must relinquish the old context.
 * HOW: 1. Verify ownership. 2. Count the completed release. */
void __wrap_ngx_resolve_name_done(ngx_resolver_ctx_t *ctx)
{ assert(ctx == &state()->ctx); state()->released++; }

/* WHAT: Retain real pools and task allocations. WHY: Failed setup must release ownership.
 * HOW: 1. Inject individual allocation failures and count actual pool destruction. */
ngx_pool_t *__real_ngx_create_pool(size_t, ngx_log_t *);
void __real_ngx_destroy_pool(ngx_pool_t *);
ngx_thread_task_t *__real_ngx_thread_task_alloc(ngx_pool_t *, size_t);
ngx_pool_t *__wrap_ngx_create_pool(size_t size, ngx_log_t *log)
{
    if (mode("pool-fail")) { return NULL; }
    state()->pool = __real_ngx_create_pool(size, log); return state()->pool;
}
/* WHAT: Release the actual task pool. WHY: Cancellation still owns eventual cleanup.
 * HOW: 1. Verify pool identity. 2. Count release. 3. Free using nginx's implementation. */
void __wrap_ngx_destroy_pool(ngx_pool_t *pool)
{ assert(pool == state()->pool); state()->destroyed++; __real_ngx_destroy_pool(pool); }
/* WHAT: Allocate a real task or fail it. WHY: A missing task must not strand its pool.
 * HOW: 1. Apply the selected failure. 2. Delegate ordinary allocation to nginx. */
ngx_thread_task_t *__wrap_ngx_thread_task_alloc(ngx_pool_t *pool, size_t size)
{ return mode("task-fail") ? NULL : __real_ngx_thread_task_alloc(pool, size); }
/* WHAT: Select a finite worker pool. WHY: The no-pool fallback is a distinct API outcome.
 * HOW: 1. Validate lookup arguments. 2. Return a fixture token or no pool. */
ngx_thread_pool_t *__wrap_ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name)
{
    assert(cycle == ngx_cycle && name->len == 7);
    return mode("no-pool") ? NULL : (ngx_thread_pool_t *) state();
}
/* WHAT: Accept or refuse task ownership. WHY: Failed dispatch must preserve caller cleanup.
 * HOW: 1. Verify the single pending slot. 2. Refuse or retain the real task. */
ngx_int_t __wrap_ngx_thread_task_post(ngx_thread_pool_t *pool, ngx_thread_task_t *task)
{
    assert(pool == (ngx_thread_pool_t *) state() && !state()->task);
    if (mode("post-fail")) { return NGX_ERROR; }
    state()->task = task; return NGX_OK;
}

/* WHAT: Control the libc seam's reply. WHY: Host DNS cannot make failures deterministic.
 * HOW: 1. Supply a bounded address, oversized record or a precise NSS error. */
int __wrap_getaddrinfo(const char *host, const char *service,
                       const struct addrinfo *hints, struct addrinfo **out)
{
    fixture *fixture_data = state(); assert(host && !strcmp(service, "4321"));
    assert(hints->ai_socktype == SOCK_STREAM);
    if (mode("system") || mode("bounded")) { errno = EACCES; return EAI_SYSTEM; }
    if (mode("negative")) { return EAI_NONAME; }
    fixture_data->libc_answer.ai_addr = (struct sockaddr *) &fixture_data->address;
    fixture_data->libc_answer.ai_addrlen = mode("oversize") ? sizeof(struct sockaddr_storage) + 1 : sizeof(fixture_data->address);
    *out = &fixture_data->libc_answer; return 0;
}
/* WHAT: Observe NSS reply release. WHY: Even unusable answers require cleanup.
 * HOW: 1. Verify the fixture-owned reply. 2. Count its release. */
void __wrap_freeaddrinfo(struct addrinfo *answer)
{ assert(answer == &state()->libc_answer); state()->detached_answers++; }

/* WHAT: Initialize one request. WHY: Defaults and policy must be production-owned.
 * HOW: 1. Leave socket/log defaults unset and provide documentation-only addresses. */
static void initialize(fixture *fixture_data)
{
    fixture_data->policy.mode = BRIX_DNS_MODE_AUTO; fixture_data->policy.resolver = &fixture_data->resolver;
    fixture_data->policy.min_ttl = 10; fixture_data->policy.max_ttl = 20; fixture_data->policy.negative_ttl = 7;
    fixture_data->policy.rc.attempts = 2; fixture_data->policy.rc.ndots = 1;
    fixture_data->resolver.connections.nelts = 1;
    fixture_data->req.name = (ngx_str_t) ngx_string("node.test"); fixture_data->req.port = 4321;
    fixture_data->req.policy = &fixture_data->policy; fixture_data->req.handler = completed;
    fixture_data->address.sin_family = AF_INET; fixture_data->address.sin_port = htons(4321);
    fixture_data->address.sin_addr.s_addr = htonl(0xc0000201u);
    fixture_data->answer.sockaddr = (struct sockaddr *) &fixture_data->address;
    fixture_data->answer.socklen = sizeof(fixture_data->address);
}

/* WHAT: Exercise literal validation. WHY: Invalid or excluded inputs cannot dispatch DNS.
 * HOW: 1. Verify exactly one failed/successful completion with untouched resolver state. */
static void literals(fixture *fixture_data)
{
    char oversized[BRIX_RESOLV_DOMAIN_LEN + 1]; memset(oversized, 'a', sizeof(oversized));
    fixture_data->req.name = (ngx_str_t) ngx_string("[2001:db8::1]");
    if (mode("excluded")) { fixture_data->req.af = BRIX_AF_INET; }
    if (mode("empty")) { fixture_data->req.name.len = 0; }
    if (mode("long")) { fixture_data->req.name.data = (u_char *) oversized; fixture_data->req.name.len = sizeof(oversized); }
    assert(brix_dns_resolve(&fixture_data->req) == NGX_OK && fixture_data->callbacks == 1 && !fixture_data->queries);
    assert(fixture_data->req.socktype == SOCK_STREAM && fixture_data->req.log == ngx_cycle->log);
    assert((fixture_data->req.rc == NGX_OK) == mode("bracket"));
    if (mode("bracket")) { assert(fixture_data->req.naddrs == 1 && fixture_data->req.literal); }
    else { assert(fixture_data->req.naddrs == 0 && fixture_data->req.error); }
}

/* WHAT: Configure search and address constraints. WHY: Family and candidate order are contracts.
 * HOW: 1. Keep query outcomes finite while changing only the supplied resolver policy. */
static void nginx_options(fixture *fixture_data)
{
    if (mode("family")) {
        fixture_data->req.af = BRIX_AF_INET; fixture_data->address6.sin6_family = AF_INET6;
        fixture_data->answer.sockaddr = (struct sockaddr *) &fixture_data->address6; fixture_data->answer.socklen = sizeof(fixture_data->address6);
    }
    if (mode("oversize")) { fixture_data->answer.socklen = sizeof(struct sockaddr_storage) + 1; }
    if (mode("default-ttl")) { fixture_data->req.policy = NULL; fixture_data->req.resolver = &fixture_data->resolver; }
    if (mode("trailing-dot")) { fixture_data->req.name = (ngx_str_t) ngx_string("node.test."); }
    if (mode("search") || mode("absolute-search")) {
        fixture_data->policy.search = 1; fixture_data->policy.rc.nsearch = 2;
        strcpy(fixture_data->policy.rc.search[0], "first.test"); strcpy(fixture_data->policy.rc.search[1], "second.test");
        if (mode("search")) { fixture_data->req.name = (ngx_str_t) ngx_string("node"); }
    }
}

/* WHAT: Check normal and cancelled nginx-resolver requests. WHY: Completion must be exactly once.
 * HOW: 1. Drain the real posted-event queue and inspect resulting addresses and candidate names. */
static void nginx_request(fixture *fixture_data)
{
    nginx_options(fixture_data); assert(brix_dns_resolve(&fixture_data->req) == NGX_OK);
    if (mode("cancel") || mode("cancel-posted")) {
        brix_dns_resolve_cancel(&fixture_data->req);
        assert(!fixture_data->callbacks && !fixture_data->req.rctx && !fixture_data->req.ev.posted); return;
    }
    if (mode("policy-removed")) { fixture_data->policy.mode = BRIX_DNS_MODE_OFF; }
    ngx_event_process_posted((ngx_cycle_t *) ngx_cycle, &ngx_posted_events);
    assert(fixture_data->callbacks == 1 && !fixture_data->req.ev.posted);
    const char *failures[] = {"family", "oversize", "no-resolver", "start-fail", "dispatch-fail", "policy-removed"};
    unsigned failed = 0;
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) { failed += mode(failures[i]); }
    assert((fixture_data->req.rc == NGX_ERROR) == (int) failed);
    if (fixture_data->req.rc != NGX_OK) { assert(!fixture_data->req.naddrs && fixture_data->req.error); return; }
    assert(fixture_data->req.naddrs == 1 && ngx_inet_get_port((struct sockaddr *) &fixture_data->req.addrs[0].ss) == 4321);
    if (mode("min-ttl")) { assert(fixture_data->req.ttl == 10); }
    if (mode("max-ttl")) { assert(fixture_data->req.ttl == 20); }
    if (mode("default-ttl")) { assert(fixture_data->req.ttl > 0); }
    if (mode("retry")) { assert(fixture_data->queries == 2 && !strcmp(fixture_data->names[0], fixture_data->names[1])); }
    if (mode("search")) { assert(!strcmp(fixture_data->names[0], "node.first.test") && !strcmp(fixture_data->names[2], "node")); }
    if (mode("absolute-search")) { assert(!strcmp(fixture_data->names[0], "node.test") && !strcmp(fixture_data->names[2], "node.test.second.test")); }
    if (mode("trailing-dot")) { assert(!strcmp(fixture_data->names[0], "node.test")); }
}

/* WHAT: Complete genuine thread task state. WHY: Detaching a caller must leave pool cleanup owned.
 * HOW: 1. Run the real worker and completion handlers after an explicit finite dispatch. */
static void thread_request(fixture *fixture_data)
{
    fixture_data->policy.mode = BRIX_DNS_MODE_OFF;
    if (mode("max-ttl")) { fixture_data->policy.max_ttl = 1; }
    ngx_int_t rc = brix_dns_resolve(&fixture_data->req);
    if (mode("pool-fail") || mode("task-fail") || mode("post-fail")) {
        assert(rc == NGX_ERROR && !fixture_data->callbacks && !fixture_data->req.task);
        assert(fixture_data->destroyed == (unsigned) !mode("pool-fail")); return;
    }
    assert(rc == NGX_OK);
    if (mode("no-pool")) { assert(fixture_data->callbacks == 1 && fixture_data->req.rc == NGX_ERROR); return; }
    assert(fixture_data->task && fixture_data->req.task);
    if (mode("cancel")) { brix_dns_resolve_cancel(&fixture_data->req); }
    fixture_data->task->handler(fixture_data->task->ctx, fixture_data->req.log);
    fixture_data->task->event.handler(&fixture_data->task->event);
    assert(fixture_data->destroyed == 1 && !fixture_data->req.task);
    assert(fixture_data->callbacks == (unsigned) !mode("cancel"));
    if (mode("success") || mode("max-ttl")) { assert(fixture_data->req.rc == NGX_OK && fixture_data->req.naddrs == 1); }
    if (mode("max-ttl")) { assert(fixture_data->req.ttl == 1); }
    if (mode("negative")) { assert(fixture_data->req.rc == NGX_ERROR && fixture_data->req.ttl == 7); }
    if (mode("system") || mode("oversize")) { assert(fixture_data->req.rc == NGX_ERROR && fixture_data->req.ttl == 0); }
}

/* WHAT: Verify bounded synchronous failure outputs. WHY: Bad NSS replies must not corrupt callers.
 * HOW: 1. Surround the output/error capacity with canaries and assert exact successful addresses. */
static void sync_request(fixture *fixture_data)
{
    brix_dns_addr_t answers[2]; memset(answers, 0xa5, sizeof(answers)); char error[64] = {0};
    const char *host = mode("empty") ? "" : "finite.invalid";
    size_t capacity = mode("bounded") ? 2 : sizeof(error) - 1; error[capacity] = 'Z';
    fixture_data->policy.mode = BRIX_DNS_MODE_OFF; fixture_data->policy.max_ttl = 1;
    ngx_uint_t count = brix_dns_resolve_sync(&fixture_data->policy, host, 4321, BRIX_AF_INET,
                                            0, answers, 1, error, capacity);
    assert(error[capacity] == 'Z');
    assert(count == (ngx_uint_t) mode("success"));
    if (count) { assert(answers[0].len == sizeof(fixture_data->address)); assert(!memcmp(&answers[0].ss, &fixture_data->address, sizeof(fixture_data->address))); }
    else { assert(error[0] && error[capacity - 1] == 0); }
    const unsigned char *untouched = (const unsigned char *) &answers[1];
    for (size_t i = 0; i < sizeof(answers[1]); i++) { assert(untouched[i] == 0xa5); }
}

/* WHAT: Check every diagnostic-buffer boundary. WHY: Truncation must retain a safe C string.
 * HOW: 1. Select capacity. 2. Copy through the shared helper. 3. Check text and canaries. */
static void diagnostic(fixture *fixture_data)
{
    char text[64]; memset(text, 'X', sizeof(text));
    size_t capacity = sizeof(text) - 1;
    if (mode("one")) { capacity = 1; }
    if (mode("zero")) { capacity = 0; }
    if (mode("bounded")) { capacity = 2; }
    const char *message = mode("empty") ? "" : "finite DNS failure";
    brix_dns_set_err(mode("missing") ? NULL : text, capacity, message);
    assert(text[capacity] == 'X');
    if (mode("missing") || mode("zero")) { assert(text[0] == 'X'); return; }
    assert(memchr(text, 0, capacity));
    if (mode("complete") || mode("empty")) { assert(!strcmp(text, message)); }
    (void) fixture_data;
}

/* WHAT: Own each state machine in one process. WHY: Native singletons cannot cross test cases.
 * HOW: 1. Initialize genuine nginx time/log/event state and execute the requested lifecycle. */
int main(int argc, char **argv)
{
    assert(argc == 3); fixture fixture_data = {.mode = argv[2]};
    ngx_open_file_t output = {.fd = STDERR_FILENO}; ngx_log_t log = {.file = &output};
    ngx_cycle_t cycle = {.log = &log, .conf_ctx = (void ****) &fixture_data}; ngx_cycle = &cycle;
    ngx_time_init(); assert(ngx_strerror_init() == NGX_OK); ngx_cached_time->sec = 1000;
    ngx_queue_init(&ngx_posted_events); initialize(&fixture_data);
    if (!strcmp(argv[1], "literal")) { literals(&fixture_data); }
    else if (!strcmp(argv[1], "nginx")) { nginx_request(&fixture_data); }
    else if (!strcmp(argv[1], "thread")) { thread_request(&fixture_data); }
    else if (!strcmp(argv[1], "sync")) { sync_request(&fixture_data); }
    else { assert(!strcmp(argv[1], "diagnostic")); diagnostic(&fixture_data); }
    assert(ngx_queue_empty(&ngx_posted_events)); puts("DNS driver lifecycle verified"); return 0;
}
