/* Invoke the registered stream getters with real identities and value storage. */
#include "core/ngx_brix_module.h"
#include "protocols/root/stream/stream_variables.h"
#include "observability/metrics/unified.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    ngx_stream_variable_t variables[32];
    int count, allocations;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }
ngx_stream_variable_t *__wrap_ngx_stream_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
{
    fixture *f = state(); (void)cf;
    assert(f->count < 32);
    if (mode("register-error") && f->count == 3) { return NULL; }
    ngx_stream_variable_t *v = &f->variables[f->count++]; v->name = *name; v->flags = flags;
    return v;
}
void *__real_ngx_pnalloc(ngx_pool_t *, size_t);
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    state()->allocations++;
    if (mode("allocation") || (mode("first-allocation") && state()->allocations == 1)) { return NULL; }
    return __real_ngx_pnalloc(pool, size);
}
static void identity_setup(brix_identity_t *id, brix_ctx_t *ctx)
{
    ngx_str_set(&id->dn, "identity-dn"); ngx_str_set(&id->subject, "identity-subject");
    ngx_str_set(&id->issuer, "issuer"); ngx_str_set(&id->vo_csv, "/vo/Role=one,/vo/Role=two");
    snprintf(id->mapped_user, sizeof(id->mapped_user), "mapped"); id->mapped_resolved = 1;
    snprintf(ctx->login.dn, sizeof(ctx->login.dn), "login-dn");
    snprintf(ctx->login.user, sizeof(ctx->login.user), "user");
    snprintf(ctx->login.primary_vo, sizeof(ctx->login.primary_vo), "/fallback");
    ctx->identity = mode("legacy") ? NULL : id;
    if (mode("unmapped")) { id->mapped_resolved = 0; }
    if (mode("single-vo")) { ngx_str_set(&id->vo_csv, "/single"); }
    if (mode("empty-id")) { memset(id, 0, sizeof(*id)); }
}
static void monitor_setup(brix_ctx_t *ctx)
{
    ctx->totals.bytes = 12345; ctx->totals.bytes_written = 678;
    ctx->io_monitor.ops = 17; ctx->io_monitor.backend_usec = 1234567;
    ctx->io_monitor.cache = BRIX_CACHE_STATUS_HIT;
    snprintf(ctx->io_monitor.path, sizeof(ctx->io_monitor.path), "/data/file");
    ctx->io_monitor.path_len = strlen(ctx->io_monitor.path);
    if (mode("empty-monitor")) { memset(&ctx->io_monitor, 0, sizeof(ctx->io_monitor)); }
}
int main(int argc, char **argv)
{
    assert(argc == 3); fixture f = {0}; f.mode = argv[1]; ngx_cycle = &f.cycle;
    ngx_time_init(); ngx_stream_brix_module.ctx_index = 0;
    ngx_log_t log = {0}; ngx_pool_t *pool = ngx_create_pool(4096, &log); assert(pool);
    ngx_connection_t connection = {.pool=pool, .log=&log};
    if (mode("tls")) { connection.ssl = (void *)&connection; }
    brix_ctx_t *ctx = calloc(1, sizeof(*ctx)); assert(ctx);
    brix_identity_t id = {0}; identity_setup(&id, ctx); monitor_setup(ctx);
    ngx_stream_brix_srv_conf_t conf = {0}; ngx_str_set(&conf.common.storage_backend, "/origin");
    void *contexts[] = {mode("no-context") || mode("tls") ? NULL : ctx};
    void *configs[] = {mode("no-config") ? NULL : &conf};
    ngx_stream_session_t session = {.connection=&connection, .ctx=contexts, .srv_conf=configs};
    ngx_time_t *now = ngx_timeofday();
    session.start_sec = now->sec; session.start_msec = now->msec;
    ngx_conf_t configuration = {.pool=pool, .log=&log};
    int rc = brix_stream_add_variables(&configuration);
    if (mode("register-error")) { assert(rc == NGX_ERROR && f.count == 3); puts("refused"); }
    else {
        assert(rc == NGX_OK && f.count == 21); int found = 0;
        for (int i = 0; i < f.count; i++) {
            ngx_stream_variable_t *v = &f.variables[i];
            if (strlen(argv[2]) != v->name.len || memcmp(argv[2], v->name.data, v->name.len)) { continue; }
            ngx_stream_variable_value_t value = {0};
            assert(v->get_handler(&session, &value, v->data) == NGX_OK);
            assert(value.valid && !value.not_found && value.data && value.len);
            assert(fwrite(value.data, 1, value.len, stdout) == value.len); found++;
        }
        assert(found == 1);
    }
    ngx_destroy_pool(pool); free(ctx); ngx_cycle = NULL; return 0;
}
