/* WHAT: Drive admin proxy and io_uring control through their real handlers.
 * WHY: Rejected URLs/methods must not mutate shared state; failed mutations
 * must produce the documented response rather than a success envelope.
 * HOW: Replace only SHM pool operations and final HTTP output with finite
 * observations. URL validation, allowlisting, routing and JSON remain real. */
#include "observability/dashboard/dashboard_api_admin_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    unsigned calls, audits, json_calls, fail_json;
    int disabled;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }
json_t *__real_json_object(void);
json_t *__wrap_json_object(void)
{
    fixture *s = state(); s->json_calls++;
    return s->fail_json == s->json_calls ? NULL : __real_json_object();
}
json_t *__real_json_array(void);
json_t *__wrap_json_array(void) { return mode("array-oom") ? NULL : __real_json_array(); }
void __wrap_admin_audit(ngx_http_request_t *r, const char *action, const char *target, const char *result)
{ (void) r; (void) target; assert(action && result); state()->audits++; }
ngx_int_t __wrap_dashboard_json_send(ngx_http_request_t *r, ngx_int_t status, json_t *body)
{
    (void) r; char *text = json_dumps(body, JSON_COMPACT); assert(text);
    printf("json=%s\n", text); free(text); json_decref(body); return status;
}
ngx_int_t __wrap_brix_proxy_pool_add(const char *url, ngx_uint_t weight,
    ngx_pool_t *pool, ngx_log_t *log, uint32_t *id)
{
    (void) pool; (void) log; assert(url && id); state()->calls++;
    printf("weight=%lu\n", (unsigned long) weight); *id = 42;
    if (mode("disabled")) { return NGX_DECLINED; }
    return mode("failed") ? NGX_ERROR : NGX_OK;
}
int __wrap_brix_proxy_pool_drain(uint32_t id)
{ assert(id == 42); state()->calls++; return !mode("missing"); }
int __wrap_brix_proxy_pool_undrain(uint32_t id)
{ return __wrap_brix_proxy_pool_drain(id); }
brix_proxy_remove_result_e __wrap_brix_proxy_pool_remove(uint32_t id)
{
    assert(id == 42); state()->calls++;
    if (mode("missing")) { return BRIX_PROXY_REMOVE_NOT_FOUND; }
    return mode("busy") ? BRIX_PROXY_REMOVE_BUSY : BRIX_PROXY_REMOVE_REMOVED;
}
long __wrap_brix_proxy_pool_in_flight(uint32_t id)
{ assert(id == 42); state()->calls++; return mode("missing") ? -1 : 7; }
ngx_uint_t __wrap_brix_proxy_pool_snapshot(brix_proxy_be_snapshot_t *out, ngx_uint_t cap)
{
    assert(cap >= 4); state()->calls++;
    int states[] = {BRIX_PROXY_BE_ACTIVE, BRIX_PROXY_BE_DRAINING, BRIX_PROXY_BE_DEAD, BRIX_PROXY_BE_RESOLVING};
    unsigned n = mode("empty") ? 0 : 4;
    for (unsigned i = 0; i < n; i++) {
        memset(&out[i], 0, sizeof(out[i])); out[i].id = i + 1; out[i].state = states[i];
        strcpy(out[i].host, "backend.invalid"); out[i].port = 443; out[i].ssl = i % 2;
        out[i].weight = i + 10; out[i].in_flight = i;
    }
    return n;
}
ngx_int_t __wrap_brix_uring_killswitch_set(ngx_uint_t disabled)
{ state()->calls++; state()->disabled = (int) disabled; return mode("disabled") ? NGX_ERROR : NGX_OK; }
ngx_int_t __wrap_brix_uring_killswitch_get(void)
{ state()->calls++; return mode("disabled"); }

static ngx_uint_t method(const char *name)
{
    if (!strcmp(name, "POST")) { return NGX_HTTP_POST; }
    if (!strcmp(name, "DELETE")) { return NGX_HTTP_DELETE; }
    if (!strcmp(name, "GET")) { return NGX_HTTP_GET; }
    return NGX_HTTP_PUT;
}
static long dispatch(ngx_http_request_t *r, const char *operation, json_t *body, const char *argument)
{
    if (!strcmp(operation, "add")) { return admin_proxy_add(r, body); }
    if (!strcmp(operation, "list")) { return admin_proxy_list(r); }
    if (!strcmp(operation, "one")) { return admin_proxy_one(r, argument, 42); }
    if (!strcmp(operation, "uring-set")) { return admin_io_uring_set(r, body); }
    if (!strcmp(operation, "uring-get")) { return admin_io_uring_get(r); }
    assert(!strcmp(operation, "parse")); uint32_t id = 0; char action[16] = {0};
    r->uri = (ngx_str_t) {strlen(argument), (u_char *) argument};
    long rc = admin_parse_proxy_uri(r, &id, action, sizeof(action));
    printf("id=%u\naction=%s\n", id, action); return rc;
}
int main(int argc, char **argv)
{
    assert(argc == 7); fixture f = {0}; f.mode = argv[2]; ngx_cycle = &f.cycle;
    ngx_log_t log = {0}; f.cycle.log = &log; ngx_pool_t *pool = ngx_create_pool(4096, &log); assert(pool);
    ngx_http_brix_dashboard_loc_conf_t conf = {0}; void *configuration[] = {&conf};
    ngx_http_brix_dashboard_module.ctx_index = 0;
    ngx_str_t allowed = ngx_string("backend.invalid");
    ngx_array_t allow = {.elts = &allowed, .nelts = 1, .size = sizeof(allowed)};
    if (!mode("unrestricted")) { conf.admin_proxy_allow = &allow; }
    ngx_connection_t connection = {.log = &log};
    ngx_http_request_t request = {.pool = pool, .connection = &connection,
        .loc_conf = configuration, .method = method(argv[3])};
    json_error_t error; json_t *body = json_loads(argv[4], JSON_DECODE_ANY, &error); assert(body);
    f.json_calls = 0; f.fail_json = (unsigned) atoi(argv[6]);
    long rc = dispatch(&request, argv[1], body, argv[5]);
    printf("rc=%ld\ncalls=%u\naudits=%u\ndisabled=%d\n", rc, f.calls, f.audits, f.disabled);
    json_decref(body); ngx_destroy_pool(pool); ngx_cycle = NULL; return 0;
}
