/* Invoke real directive parsers with nginx pool/array storage; DNS preparation
 * is observed at its boundary, without performing a lookup during parsing. */
#include "net/proxy/proxy_internal.h"
#include <assert.h>

typedef struct { ngx_cycle_t cycle; const char *mode; int armed, allocations, dns; } fixture_t;
static fixture_t *state(void) { return (fixture_t *)ngx_cycle; }
static int mode(const char *s) { return state()->armed && !strcmp(state()->mode, s); }
void *__real_ngx_pnalloc(ngx_pool_t *, size_t);
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t n)
{
    if (state()->armed && ++state()->allocations == atoi(state()->mode)) { return NULL; }
    return __real_ngx_pnalloc(pool, n);
}
ngx_array_t *__real_ngx_array_create(ngx_pool_t *, ngx_uint_t, size_t);
ngx_array_t *__wrap_ngx_array_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{ return mode("array") ? NULL : __real_ngx_array_create(pool, n, size); }
void *__real_ngx_array_push(ngx_array_t *);
void *__wrap_ngx_array_push(ngx_array_t *a)
{ return mode("push") ? NULL : __real_ngx_array_push(a); }
char *__wrap_brix_dns_backend_prepare(ngx_conf_t *cf)
{ assert(cf->pool); state()->dns++; return mode("dns") ? NGX_CONF_ERROR : NGX_CONF_OK; }

int main(int argc, char **argv)
{
    assert(argc == 5); fixture_t f = {0}; f.mode = argv[4]; ngx_cycle = &f.cycle;
    ngx_time_init(); ngx_open_file_t file = {.fd = STDERR_FILENO};
    ngx_log_t log = {.log_level = NGX_LOG_ERR, .file = &file};
    ngx_pool_t *pool = ngx_create_pool(4096, &log); assert(pool);
    ngx_str_t args[3];
    for (unsigned i = 0; i < 3; i++) { args[i].data = (u_char *)argv[i + 1]; args[i].len = strlen(argv[i + 1]); }
    ngx_array_t array = {.elts = args, .nelts = *argv[3] ? 3 : 2};
    ngx_conf_t cf = {.pool = pool, .args = &array, .log = &log};
    ngx_stream_brix_srv_conf_t conf = {0};
    conf.proxy.auth = 99; conf.proxy.login_user = 99; conf.proxy.sss_identity = 99;
    f.armed = 1; char *rc;
    if (!strcmp(argv[1], "upstream")) { rc = brix_conf_set_proxy_upstream(&cf, NULL, &conf); }
    else if (!strcmp(argv[1], "auth")) { rc = brix_conf_set_proxy_auth(&cf, NULL, &conf); }
    else if (!strcmp(argv[1], "login")) { rc = brix_conf_set_proxy_login_user(&cf, NULL, &conf); }
    else if (!strcmp(argv[1], "identity")) { rc = brix_conf_set_proxy_sss_identity(&cf, NULL, &conf); }
    else { rc = brix_conf_set_proxy_path_rewrite(&cf, NULL, &conf); }
    printf("rc=%d\ndns=%d\nauth=%lu\nlogin=%lu\nidentity=%lu\nuser=%s\n",
        rc == NGX_CONF_OK ? 0 : -1, f.dns, (unsigned long)conf.proxy.auth,
        (unsigned long)conf.proxy.login_user, (unsigned long)conf.proxy.sss_identity,
        conf.proxy.login_user_name);
    if (rc == NGX_CONF_OK && !strcmp(argv[1], "upstream")) {
        assert(conf.proxy.upstreams->nelts == 1);
        brix_proxy_upstream_t *u = conf.proxy.upstreams->elts;
        printf("host=%.*s\nport=%u\npolicy=%ld\nkey=%s\n", (int)u->host.len,
            u->host.data, u->port, (long)u->auth, u->sss_keyname);
        assert(conf.proxy.host.len == u->host.len && conf.proxy.port == u->port);
        f.armed = 0; args[1] = (ngx_str_t)ngx_string("second.invalid:1000"); array.nelts = 2;
        assert(brix_conf_set_proxy_upstream(&cf, NULL, &conf) == NGX_CONF_OK);
        assert(conf.proxy.upstreams->nelts == 2 && conf.proxy.port == u->port);
    }
    if (!strcmp(argv[1], "rewrite")) {
        assert(conf.proxy.path_strip.data == args[1].data && conf.proxy.path_strip.len == args[1].len);
        assert(conf.proxy.path_add.data == args[2].data && conf.proxy.path_add.len == args[2].len);
    }
    f.armed = 0; ngx_destroy_pool(pool); ngx_cycle = NULL; return 0;
}
