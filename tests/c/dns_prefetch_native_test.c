/* Real DNS cache/prefetch contracts with a finite asynchronous resolver boundary. */
#include "net/dns/dns.h"
#include <assert.h>

typedef struct {
    const char *mode;
    brix_dns_policy_t policy;
    brix_dns_req_t *pending;
    unsigned dispatched, calloc_calls, fail_calloc, fail_name;
} fixture;

/* WHAT: Recover scoped state. WHY: Each test process owns its resolver and cache.
 * HOW: Use the fixture cycle's opaque configuration pointer. */
static fixture *state(void) { return (fixture *) ngx_cycle->conf_ctx; }

void *__real_ngx_calloc(size_t, ngx_log_t *);
void *__real_ngx_alloc(size_t, ngx_log_t *);

/* WHAT: Fail a chosen cache/request allocation. WHY: Failed fills must not dispatch or leak ownership.
 * HOW: Count only allocations after main has initialized nginx. */
void *__wrap_ngx_calloc(size_t size, ngx_log_t *log)
{
    fixture *f = state();
    if (++f->calloc_calls == f->fail_calloc) { return NULL; }
    return __real_ngx_calloc(size, log);
}

/* WHAT: Fail the copied key allocation. WHY: A cache shell alone is not a usable entry.
 * HOW: Scope failure to the explicit key-allocation case. */
void *__wrap_ngx_alloc(size_t size, ngx_log_t *log)
{
    if (state()->fail_name) { return NULL; }
    return __real_ngx_alloc(size, log);
}

/* WHAT: Create a finite DNS answer. WHY: Cached ports must be rebound for each caller.
 * HOW: Fill two documentation addresses with a short TTL and no network I/O. */
static void answer(brix_dns_req_t *req)
{
    req->rc = NGX_OK; req->ttl = 10; req->naddrs = 2;
    for (unsigned i = 0; i < 2; i++) {
        struct sockaddr_in *sa = (struct sockaddr_in *) &req->addrs[i].ss;
        sa->sin_family = AF_INET; sa->sin_addr.s_addr = htonl(0xc0000201u + i);
        sa->sin_port = htons(req->port); req->addrs[i].len = sizeof(*sa);
    }
}

/* WHAT: Complete a pending fill. WHY: Success and negative results must replace the pending marker.
 * HOW: Publish via the real cache and release through the actual prefetch callback. */
static void complete(brix_dns_req_t *req)
{
    const char *mode = state()->mode; answer(req);
    if (!strcmp(mode, "negative")) {
        req->rc = NGX_ERROR; req->negative = 1; req->naddrs = 0;
    }
    if (!strcmp(mode, "error") || !strcmp(mode, "unknown-error")) {
        req->rc = NGX_ERROR; req->naddrs = 0;
        req->error = !strcmp(mode, "error") ? "finite DNS failure" : NULL;
    }
    brix_dns_cache_store(req); req->handler(req);
}

/* WHAT: Own the async handoff. WHY: Prefetch must copy names and obey single-fill suppression.
 * HOW: Validate immutable request fields and choose inline, deferred or rejected completion. */
ngx_int_t __wrap_brix_dns_resolve(brix_dns_req_t *req)
{
    fixture *f = state(); f->dispatched++;
    assert(req->name.len == sizeof("prefetch.test") - 1);
    assert(!memcmp(req->name.data, "prefetch.test", req->name.len));
    assert(req->port == 1094 && req->socktype == SOCK_STREAM);
    if (!strcmp(f->mode, "dispatch-failure")) { return NGX_ERROR; }
    if (!strcmp(f->mode, "deferred") || !strcmp(f->mode, "long-budget")) {
        assert(!f->pending); f->pending = req; return NGX_OK;
    }
    complete(req); return NGX_OK;
}

/* WHAT: Probe one finite hostname. WHY: An unknown answer must remain distinguishable from refusal.
 * HOW: Preserve output canaries and compare port and address after a successful lookup. */
static ngx_int_t probe(const char *host, brix_af_policy_t af, ngx_uint_t max)
{
    brix_dns_addr_t addresses[2]; memset(addresses, 0xcc, sizeof(addresses));
    ngx_uint_t count = 99; char error[96];
    ngx_int_t rc = brix_dns_cache_probe(NULL, host, 4321, af, addresses, max,
                                      &count, error, sizeof(error));
    if (rc != NGX_OK) { assert(count == 0 && error[0]); return rc; }
    assert(count > 0 && count <= max && error[0] == '\0');
    assert(ngx_inet_get_port((struct sockaddr *) &addresses[0].ss) == 4321);
    if (max == 1) {
        const unsigned char *bytes = (const unsigned char *) &addresses[1];
        for (size_t i = 0; i < sizeof(addresses[1]); i++) { assert(bytes[i] == 0xcc); }
    }
    return rc;
}

/* WHAT: Exercise fill ownership. WHY: Repeated probes must not dispatch duplicate work.
 * HOW: Resolve one copied hostname and inspect pending, cached or negative outcomes. */
static void check_prefetch(fixture *f)
{
    char host[] = "prefetch.test"; brix_dns_addr_t addresses[2]; ngx_uint_t count; char error[96];
    if (!strcmp(f->mode, "request-alloc")) { f->fail_calloc = 2; }
    assert(brix_dns_lookup_cached(&f->policy, host, 1094, BRIX_AF_AUTO,
        addresses, 2, &count, error, sizeof(error)) == NGX_AGAIN);
    assert(count == 0 && !strcmp(error, "resolution in progress"));
    if (f->pending) {
        memset(host, 'x', sizeof(host) - 1);
        assert(!strcmp((char *) f->pending->name.data, "prefetch.test"));
        brix_dns_prefetch(&f->policy, "prefetch.test", 1094, BRIX_AF_AUTO);
        assert(f->dispatched == 1);
        if (!strcmp(f->mode, "long-budget")) {
            ngx_cached_time->sec += 10;
            ngx_str_t key = ngx_string("prefetch.test");
            assert(brix_dns_cache_mark_pending(&key, BRIX_AF_AUTO, 1) == 0);
        }
        complete(f->pending); f->pending = NULL;
    }
    if (!strcmp(f->mode, "dispatch-failure") || !strcmp(f->mode, "request-alloc")) {
        assert(probe("prefetch.test", BRIX_AF_AUTO, 1) == NGX_AGAIN);
        assert(f->dispatched == (unsigned) !strcmp(f->mode, "dispatch-failure")); return;
    }
    ngx_int_t expected = NGX_OK;
    if (!strcmp(f->mode, "negative") || !strcmp(f->mode, "error")
        || !strcmp(f->mode, "unknown-error")) { expected = NGX_DECLINED; }
    assert(probe("PREFETCH.TEST.", BRIX_AF_AUTO, 1) == expected);
    assert(f->dispatched == 1);
    brix_dns_prefetch(&f->policy, "prefetch.test", 1094, BRIX_AF_AUTO);
    assert(f->dispatched == 1);
}

/* WHAT: Exercise pending-marker replacement and expiry. WHY: Lost fills need bounded suppression.
 * HOW: Advance nginx's cached clock, publish an answer and compare entry counters. */
static void check_marker(fixture *f, const char *mode)
{
    ngx_str_t key = ngx_string("marker.test");
    if (!strcmp(mode, "entry-alloc")) { f->fail_calloc = 1; }
    if (!strcmp(mode, "name-alloc")) { f->fail_name = 1; }
    unsigned marked = brix_dns_cache_mark_pending(&key, BRIX_AF_AUTO, 0);
    if (f->fail_calloc || f->fail_name) {
        assert(!marked); ngx_uint_t entries, hits, misses, negative;
        brix_dns_cache_stats(&entries, &hits, &misses, &negative); assert(entries == 0); return;
    }
    assert(marked == 1 && brix_dns_cache_mark_pending(&key, BRIX_AF_AUTO, 1) == 0);
    assert(probe("marker.test", BRIX_AF_AUTO, 1) == NGX_AGAIN);
    ngx_cached_time->sec += BRIX_DNS_PENDING_HOLD;
    assert(brix_dns_cache_mark_pending(&key, BRIX_AF_AUTO, 2) == 1);
    brix_dns_req_t req = {0}; req.name = key; req.log = ngx_cycle->log; answer(&req);
    brix_dns_cache_store(&req); assert(probe("marker.test", BRIX_AF_AUTO, 1) == NGX_OK);
    ngx_cached_time->sec += 10; assert(probe("marker.test", BRIX_AF_AUTO, 1) == NGX_AGAIN);
}

/* WHAT: Keep address-family policies isolated through tree rotations.
 * WHY: Equal name hashes must not hide or replace a different policy's answer.
 * HOW: Store three policies for one name and look up each after every insertion. */
static void check_family_keys(unsigned permutation)
{
    brix_af_policy_t policies[] = {BRIX_AF_AUTO, BRIX_AF_INET, BRIX_AF_INET6};
    ngx_str_t name = ngx_string("family.test");
    for (unsigned i = 0; i < 3; i++) {
        unsigned index = (permutation + i * (permutation < 3 ? 1 : 2)) % 3;
        brix_dns_req_t req = {0}; req.name = name; req.af = policies[index]; req.log = ngx_cycle->log;
        answer(&req); req.ttl = 10 + i; brix_dns_cache_store(&req);
        for (unsigned j = 0; j <= i; j++) {
            index = (permutation + j * (permutation < 3 ? 1 : 2)) % 3;
            brix_dns_req_t lookup = {0}; lookup.name = name; lookup.af = policies[index];
            assert(brix_dns_cache_lookup(&lookup) == NGX_OK && lookup.ttl == (time_t) (10 + j));
        }
    }
}

/* WHAT: Distinguish different names sharing one hash. WHY: CRC identity is not hostname identity.
 * HOW: Store independently generated collision vectors and compare exact answer TTLs. */
static void check_name_collision(void)
{
    ngx_str_t names[] = {ngx_string("7f217f6b6dc8.invalid"), ngx_string("d7e77869948b.invalid")};
    brix_af_policy_t policies[] = {BRIX_AF_AUTO, BRIX_AF_INET, BRIX_AF_INET6};
    assert(ngx_crc32_short(names[0].data, names[0].len) == ngx_crc32_short(names[1].data, names[1].len));
    for (unsigned i = 0; i < 6; i++) {
        brix_dns_req_t req = {0}; req.name = names[i % 2]; req.af = policies[i / 2];
        req.log = ngx_cycle->log; answer(&req); req.ttl = 10 + i; brix_dns_cache_store(&req);
    }
    for (unsigned i = 0; i < 6; i++) {
        brix_dns_req_t req = {0}; req.name = names[i % 2]; req.af = policies[i / 2];
        assert(brix_dns_cache_lookup(&req) == NGX_OK && req.ttl == (time_t) (10 + i));
    }
}

/* WHAT: Preserve PTR identity for colliding address hashes. WHY: Ports and tree shape cannot change ownership.
 * HOW: Use three computed IPv6 CRC collisions, publishing distinct names after optional pending markers. */
static void check_reverse(const char *mode)
{
    const char *texts[] = {"2001:db8::d02c:3613", "2001:db8::1:461c:3164", "2001:db8::2:fc4d:38fd"};
    const char *names[] = {"first.example", "second.example", "third.example"};
    struct sockaddr_in6 addresses[3] = {0};
    for (unsigned i = 0; i < 3; i++) {
        addresses[i].sin6_family = AF_INET6; addresses[i].sin6_port = htons(1094);
        assert(inet_pton(AF_INET6, texts[i], &addresses[i].sin6_addr) == 1);
        assert(ngx_crc32_short(addresses[i].sin6_addr.s6_addr, 16) == 0x12345678);
        struct sockaddr *sa = (struct sockaddr *) &addresses[i];
        if (!strcmp(mode, "pending")) { assert(brix_dns_rcache_mark_pending(sa, sizeof(addresses[i]), 2)); }
        brix_dns_rcache_store(sa, sizeof(addresses[i]), names[i], 10 + i);
    }
    for (unsigned i = 0; i < 3; i++) {
        addresses[i].sin6_port = htons(4321); char name[256];
        struct sockaddr *sa = (struct sockaddr *) &addresses[i];
        assert(brix_dns_rcache_lookup(sa, sizeof(addresses[i]), name, sizeof(name)) == NGX_OK);
        assert(!strcmp(name, names[i]));
        assert(!brix_dns_rcache_mark_pending(sa, sizeof(addresses[i]), 2));
    }
    if (!strcmp(mode, "replace")) {
        struct sockaddr *sa = (struct sockaddr *) &addresses[0]; char name[256];
        brix_dns_rcache_store(sa, sizeof(addresses[0]), NULL, 1);
        assert(brix_dns_rcache_lookup(sa, sizeof(addresses[0]), name, sizeof(name)) == NGX_DECLINED);
        ngx_cached_time->sec += 1;
        assert(brix_dns_rcache_mark_pending(sa, sizeof(addresses[0]), 0) == 1);
        assert(brix_dns_rcache_lookup(sa, sizeof(addresses[0]), name, sizeof(name)) == NGX_AGAIN);
    }
}

/* WHAT: Check invalid inputs and literal-family refusal. WHY: Invalid names must not start work.
 * HOW: Probe bounded public APIs and verify the finite resolver was never called. */
static void check_invalid(fixture *f)
{
    char long_name[BRIX_RESOLV_DOMAIN_LEN + 1]; memset(long_name, 'a', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = 0;
    brix_dns_prefetch(NULL, NULL, 1094, BRIX_AF_AUTO);
    brix_dns_prefetch(NULL, "", 1094, BRIX_AF_AUTO);
    brix_dns_prefetch(NULL, long_name, 1094, BRIX_AF_AUTO);
    assert(probe(NULL, BRIX_AF_AUTO, 1) == NGX_DECLINED);
    assert(probe("", BRIX_AF_AUTO, 1) == NGX_DECLINED);
    assert(probe("prefetch.test", BRIX_AF_AUTO, 0) == NGX_DECLINED);
    assert(probe("192.0.2.1", BRIX_AF_INET6, 1) == NGX_DECLINED);
    assert(probe("2001:db8::1", BRIX_AF_INET, 1) == NGX_DECLINED);
    assert(probe("192.0.2.1", BRIX_AF_INET, 1) == NGX_OK);
    assert(f->dispatched == 0);
}

/* WHAT: Run a cache lifecycle contract. WHY: Fresh process state prevents singleton contamination.
 * HOW: Initialize nginx time/log state and invoke one finite family. */
int main(int argc, char **argv)
{
    assert(argc == 3); fixture f = {.mode = argv[2]};
    ngx_open_file_t output = {.fd = STDERR_FILENO}; ngx_log_t log = {.file = &output};
    ngx_cycle_t cycle = {.log = &log, .conf_ctx = (void ****) &f}; ngx_cycle = &cycle;
    ngx_time_init(); assert(ngx_strerror_init() == NGX_OK); ngx_cached_time->sec = 1000;
    f.policy.search = 1; f.policy.rc.timeout = 10; f.policy.rc.attempts = 2; f.policy.rc.nsearch = 2;
    if (!strcmp(argv[1], "prefetch")) { check_prefetch(&f); }
    else if (!strcmp(argv[1], "marker")) { check_marker(&f, argv[2]); }
    else if (!strcmp(argv[1], "family")) { check_family_keys((unsigned) atoi(argv[2])); }
    else if (!strcmp(argv[1], "collision")) { check_name_collision(); }
    else if (!strcmp(argv[1], "reverse")) { check_reverse(argv[2]); }
    else { assert(!strcmp(argv[1], "invalid")); check_invalid(&f); }
    puts("DNS cache ownership verified"); return 0;
}
