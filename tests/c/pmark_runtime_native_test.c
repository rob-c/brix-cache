/* Registry-backed mapping and asynchronous collector resolution contracts. */
#include "core/ngx_brix_module.h"
#include "observability/pmark/pmark.h"
#include "net/dns/dns.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    brix_pmark_conf_t conf;
    const char *fault;
    brix_dns_req_t *pending;
    brix_dns_addr_t address;
    unsigned calls;
    int armed;
} fixture;

/* WHAT: Recover the test observer. WHY: No production hooks or new globals.
 * HOW: The selected nginx cycle is the fixture's first member. */
static fixture *state(void) { return (fixture *) ngx_cycle; }
static ngx_str_t string(const char *s) { return (ngx_str_t){strlen(s), (u_char *)s}; }

ngx_array_t *__real_ngx_array_create(ngx_pool_t *, ngx_uint_t, size_t);
/* WHAT: Refuse one resolved-array allocation. WHY: Runtime init must fail open
 * and cache the refusal. HOW: Match the actual element type and selected fault. */
ngx_array_t *__wrap_ngx_array_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    fixture *f = state();
    if (f->armed && ((!strcmp(f->fault, "exp-create") && size == sizeof(brix_pmark_exp_rule_r_t))
        || (!strcmp(f->fault, "act-create") && size == sizeof(brix_pmark_act_rule_r_t))
        || (!strcmp(f->fault, "dest-create") && size == sizeof(brix_pmark_dest_t)))) { return NULL; }
    return __real_ngx_array_create(pool, n, size);
}

void *__real_ngx_array_push(ngx_array_t *);
/* WHAT: Refuse append at a selected ownership boundary. WHY: Partial runtime
 * state must not be reported ready. HOW: Select the resolved destination array. */
void *__wrap_ngx_array_push(ngx_array_t *array)
{
    fixture *f = state();
    if (f->armed && ((!strcmp(f->fault, "exp-push") && array == f->conf.exp_rules_r)
        || (!strcmp(f->fault, "act-push") && array == f->conf.act_rules_r)
        || (!strcmp(f->fault, "dest-push") && array == f->conf.dest_sa))) { return NULL; }
    return __real_ngx_array_push(array);
}

void *__real_ngx_pcalloc(ngx_pool_t *, size_t);
/* WHAT: Refuse the per-query lifetime allocation. WHY: DNS cannot borrow a
 * stack request. HOW: Fail pcalloc only after fixture construction. */
void *__wrap_ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    if (state()->armed && !strcmp(state()->fault, "dns-alloc")) { return NULL; }
    return __real_ngx_pcalloc(pool, size);
}

/* WHAT: Complete the real mapping callback. WHY: Inline/deferred answers use
 * one ownership path. HOW: Supply a bounded fixture address through the DNS API. */
static void resolve(brix_dns_req_t *request)
{
    fixture *f = state();
    request->rc = !strcmp(f->fault, "dns-error") ? NGX_ERROR : NGX_OK;
    request->error = "fixture lookup failure";
    request->naddrs = strcmp(f->fault, "dns-empty") ? 1 : 0;
    f->address.ss.ss_family = AF_INET6; f->address.len = sizeof(struct sockaddr_in6);
    request->addrs[0] = f->address;
    request->handler(request);
}

/* WHAT: Observe collector queries without external DNS. WHY: Parsing and
 * continuation behavior are the subject. HOW: Validate UDP and retain requests. */
ngx_int_t __wrap_brix_dns_resolve(brix_dns_req_t *request)
{
    fixture *f = state(); f->calls++;
    assert(request->socktype == SOCK_DGRAM && request->af == BRIX_AF_AUTO);
    printf("dns=%.*s port=%u\n", (int) request->name.len, request->name.data, request->port);
    if (!strcmp(f->fault, "dns-start")) { request->error = NULL; return NGX_ERROR; }
    if (!strcmp(f->fault, "deferred")) { f->pending = request; return NGX_OK; }
    resolve(request); return NGX_OK;
}

/* WHAT: Add named experiment/activity rules. WHY: Test the actual registry
 * resolution before precedence. HOW: Pool arrays match the production grammar. */
static void rules(fixture *f, ngx_pool_t *pool)
{
    brix_pmark_conf_t *pm = &f->conf;
    pm->exp_rules = ngx_array_create(pool, 4, sizeof(brix_pmark_exp_rule_t));
    pm->act_rules = ngx_array_create(pool, 5, sizeof(brix_pmark_act_rule_t));
    assert(pm->exp_rules && pm->act_rules);
    const char *names[] = {"alpha", "beta", "gamma", "missing"};
    const char *matches[] = {"", "/data/*", "atlas", ""};
    brix_pmark_exp_kind_t kinds[] = {BRIX_PMARK_EXP_DEFAULT, BRIX_PMARK_EXP_PATH,
                                   BRIX_PMARK_EXP_VO, BRIX_PMARK_EXP_DEFAULT};
    for (unsigned i = 0; i < 4; i++) {
        brix_pmark_exp_rule_t *r = ngx_array_push(pm->exp_rules); assert(r);
        *r = (brix_pmark_exp_rule_t){kinds[i], string(matches[i]), string(names[i])};
    }
    const char *acts[] = {"default", "role", "user", "missing", "default"};
    const char *who[] = {"", "production", "alice", "", ""};
    brix_pmark_act_kind_t akinds[] = {BRIX_PMARK_ACTR_DEFAULT, BRIX_PMARK_ACTR_ROLE,
        BRIX_PMARK_ACTR_USER, BRIX_PMARK_ACTR_DEFAULT, BRIX_PMARK_ACTR_DEFAULT};
    for (unsigned i = 0; i < 5; i++) {
        brix_pmark_act_rule_t *r = ngx_array_push(pm->act_rules); assert(r);
        *r = (brix_pmark_act_rule_t){string(i == 4 ? "missing" : "beta"),
                                   akinds[i], string(who[i]), string(acts[i])};
    }
}

/* WHAT: Build one real runtime and optionally map a flow. WHY: A broken
 * collector must not prevent a transfer or trigger repeated init attempts.
 * HOW: Assert cached init, deferred append and the numeric map outputs. */
int main(int argc, char **argv)
{
    assert(argc == 9); fixture f = {0}; ngx_cycle = &f.cycle;
    f.cycle.log = &f.log; ngx_time_init(); f.fault = argv[1];
    ngx_pool_t *pool = ngx_create_pool(8192, &f.log); assert(pool);
    f.conf.enable = strcmp(f.fault, "disabled") != 0;
    f.conf.firefly = 1; f.conf.scitag_cgi = 1; f.conf.defsfile = string(argv[2]);
    rules(&f, pool);
    f.conf.firefly_dest = ngx_array_create(pool, 1, sizeof(ngx_str_t));
    ngx_str_t *dest = ngx_array_push(f.conf.firefly_dest); assert(dest); *dest = string(argv[3]);
    f.armed = 1;
    ngx_int_t rc = brix_pmark_runtime_ensure(&f.conf, pool, &f.log);
    unsigned calls = f.calls;
    assert(brix_pmark_runtime_ensure(&f.conf, pool, &f.log) == rc && calls == f.calls);
    if (f.pending) { assert(f.conf.dest_sa->nelts == 0); resolve(f.pending); }
    brix_pmark_flow_id_t flow = {0}; flow.path = argv[4]; flow.vo_csv = argv[5];
    flow.user = argv[6]; flow.cgi = argv[7];
    ngx_uint_t exp = 99, act = 99;
    ngx_int_t mapped = brix_pmark_map_codes(&f.conf, &flow, &exp, &act);
    printf("runtime=%ld ready=%u ok=%u dest=%lu mapped=%ld exp=%lu act=%lu calls=%u\n",
        (long)rc, f.conf.rt_ready, f.conf.rt_ok,
        f.conf.dest_sa ? (unsigned long)f.conf.dest_sa->nelts : 0,
        (long)mapped, (unsigned long)exp, (unsigned long)act, f.calls);
    assert(rc == strtol(argv[8], NULL, 10)); ngx_destroy_pool(pool); return 0;
}
