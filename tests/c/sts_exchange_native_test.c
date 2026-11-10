/* Real STS signing, HTTP transport and XML parsing over a finite local endpoint. */
#include "auth/s3/sts_internal.h"
#include "core/compat/crypto.h"
#include <curl/curl.h>
#include <assert.h>

typedef struct { ngx_cycle_t cycle; const char *mode; int armed; } fixture;

/* WHAT: Read the active case. WHY: Faults must not affect fixture setup.
 * HOW: Keep all observer state attached to the selected nginx cycle. */
static int mode(const char *name)
{
    fixture *f = (fixture *) ngx_cycle;
    return f->armed && !strcmp(f->mode, name);
}

static ngx_str_t string(const char *s) { return (ngx_str_t) {strlen(s), (u_char *) s}; }

void *__real_ngx_pnalloc(ngx_pool_t *, size_t);
/* WHAT: Refuse host or response allocation. WHY: OOM must precede credentials.
 * HOW: Select either the first allocation or the transport buffer size. */
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    if (mode("host-allocation") || (mode("body-allocation") && size == BRIX_STS_RESP_MAX)) {
        return NULL;
    }
    return __real_ngx_pnalloc(pool, size);
}

CURL *__real_curl_easy_init(void);
/* WHAT: Refuse transport creation. WHY: Missing curl state cannot yield creds.
 * HOW: Use the genuine transport in every other case. */
CURL *__wrap_curl_easy_init(void)
{
    return mode("curl-init") ? NULL : __real_curl_easy_init();
}

struct tm *__real_gmtime_r(const time_t *, struct tm *);
/* WHAT: Refuse the signing timestamp. WHY: An invalid clock must fail closed.
 * HOW: Inject only after nginx and crypto initialization have completed. */
struct tm *__wrap_gmtime_r(const time_t *clock, struct tm *out)
{
    return mode("clock") ? NULL : __real_gmtime_r(clock, out);
}

/* WHAT: Apply invalid configuration cases. WHY: Validation precedes transport.
 * HOW: Clear individual required views or exceed the bounded credential buffer. */
static void configure(brix_s3_sts_conf_t *conf, const char *selected, char large[700])
{
    if (!strcmp(selected, "empty-endpoint")) { conf->endpoint.len = 0; }
    if (!strcmp(selected, "empty-region")) { conf->region.len = 0; }
    if (!strcmp(selected, "empty-ak")) { conf->svc_ak.len = 0; }
    if (!strcmp(selected, "empty-sk")) { conf->svc_sk.len = 0; }
    if (!strcmp(selected, "empty-host")) { conf->endpoint = string("http:///path"); }
    if (!strcmp(selected, "long-credential")) { conf->svc_ak = string(large); }
}

/* WHAT: Perform one exchange without synthetic transport responses.
 * WHY: Signing, response limits, parsing and output ownership form one contract.
 * HOW: Build explicit test credentials, invoke, then print only fixture results. */
int main(int argc, char **argv)
{
    assert(argc == 8); fixture f = {0}; ngx_log_t log = {0};
    f.mode = argv[2]; f.cycle.log = &log; ngx_cycle = &f.cycle; ngx_time_init();
    assert(brix_crypto_init()); assert(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
    ngx_pool_t *pool = ngx_create_pool(8192, &log); assert(pool);
    brix_s3_sts_conf_t conf = {0}; conf.endpoint = string(argv[1]);
    conf.region = string("test-region"); conf.svc_ak = string("FIXTURE_AK");
    conf.svc_sk = string("FIXTURE_SERVICE_SECRET"); conf.role_arn = string(argv[5]);
    conf.ttl_secs = atoi(argv[4]); conf.flavor = atoi(argv[3]);
    char large[700]; memset(large, 'A', sizeof(large) - 1); large[sizeof(large) - 1] = 0;
    configure(&conf, f.mode, large);
    brix_identity_t identity = {0}; identity.subject = string(argv[6]);
    if (!strcmp(f.mode, "dn")) { identity.dn = identity.subject; identity.subject.len = 0; }
    ngx_str_t ak = ngx_null_string, sk = ngx_null_string, session = ngx_null_string;
    brix_s3_sts_out_t output = {&ak, &sk, &session};
    f.armed = 1;
    ngx_int_t rc = brix_s3_sts_assume(mode("null-pool") ? NULL : pool,
        mode("null-id") ? NULL : &identity, mode("null-config") ? NULL : &conf, &output, &log);
    f.armed = 0; assert(rc == atoi(argv[7]));
    if (rc == NGX_OK) {
        printf("%.*s\n%.*s\n%.*s\n", (int) ak.len, ak.data,
               (int) sk.len, sk.data, (int) session.len, session.data);
    } else { assert(!ak.data && !sk.data && !session.data); }
    ngx_destroy_pool(pool); curl_global_cleanup(); brix_crypto_cleanup(); return 0;
}
