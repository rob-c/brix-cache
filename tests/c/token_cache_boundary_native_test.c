/* JWT cache boundaries: exact token identity, lifetime caps and safe zone binding. */
#include "core/ngx_brix_module.h"
#include "auth/token/token_cache.h"
#include "core/compat/crypto.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    brix_kv_t kv;
    brix_token_claims_t claims;
    const char *mode;
    unsigned char fingerprint[32];
    int reads, writes;
    ngx_msec_t ttl;
} fixture;

static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }
time_t __wrap_time(time_t *out)
{
    if (out) { *out = 1700000000; }
    return 1700000000;
}

int __real_brix_sha256(const u_char *, size_t, u_char *);
int __wrap_brix_sha256(const u_char *bytes, size_t size, u_char *output)
{
    return mode("digest-error") ? 0 : __real_brix_sha256(bytes, size, output);
}

static void check_key(brix_kv_t *kv, const void *key, size_t length)
{
    assert(kv == &state()->kv && length == 32);
    assert(!memcmp(key, state()->fingerprint, length));
}

int __wrap_brix_kv_get(brix_kv_t *kv, const void *key, size_t length,
                       void *out, size_t *out_length)
{
    check_key(kv, key, length); state()->reads++;
    assert(*out_length == sizeof(state()->claims));
    if (mode("miss")) { return 0; }
    memcpy(out, &state()->claims, *out_length);
    if (mode("short")) { (*out_length)--; }
    return 1;
}

ngx_int_t __wrap_brix_kv_set(brix_kv_t *kv, const void *key, size_t length,
    const void *value, size_t value_length, ngx_msec_t ttl)
{
    check_key(kv, key, length); state()->writes++;
    assert(value_length == sizeof(state()->claims));
    assert(!memcmp(value, &state()->claims, value_length));
    state()->ttl = ttl;
    return mode("full") ? NGX_ERROR : NGX_OK;
}

brix_kv_t *__wrap_brix_kv_find(const ngx_str_t *name)
{
    assert(name->len == 5 && !memcmp(name->data, "cache", 5));
    return mode("unknown") ? NULL : &state()->kv;
}

static void cache_case(fixture *f, int expiry)
{
    const char token[] = {'a', 0, 'b'};
    unsigned int size = 0;
    assert(EVP_Digest(token, sizeof(token), f->fingerprint, &size, EVP_sha256(), NULL));
    assert(size == 32);
    f->claims.exp = expiry == -999 ? 0 : 1700000000 + expiry;
    strcpy(f->claims.sub, "fixture-subject");
    brix_kv_t *kv = mode("null-zone") ? NULL : &f->kv;
    const char *input = mode("null-token") ? NULL : token;
    size_t length = mode("empty") ? 0 : sizeof(token);
    int unavailable = !kv || !input || !length || mode("digest-error");
    brix_token_cache_store(kv, input, length, &f->claims);
    int should_store = !unavailable && (expiry > 0 || expiry == -999);
    assert(f->writes == should_store);
    if (should_store) {
        assert(f->ttl == (expiry == -999 || expiry > 300 ? 300000 : (ngx_msec_t) expiry * 1000));
    }
    brix_token_claims_t got = {0};
    int hit = brix_token_cache_lookup(kv, input, length, &got);
    int expected = should_store && !mode("miss") && !mode("short");
    assert(hit == expected && f->reads == !unavailable);
    if (hit) { assert(!memcmp(&got, &f->claims, sizeof(got))); }
}

static void directive_case(fixture *f)
{
    ngx_str_t values[] = {ngx_string("brix_token_cache"), ngx_string("zone=cache")};
    ngx_array_t args = {.elts = values, .nelts = 2};
    ngx_conf_file_t file = {0}; ngx_str_set(&file.file.name, "fixture.conf");
    ngx_conf_t cf = {.args = &args, .log = &f->log, .cycle = &f->cycle, .conf_file = &file};
    struct { unsigned guard; brix_kv_t *slot; } target = {71, NULL};
    ngx_command_t command = {.offset = offsetof(__typeof__(target), slot)};
    f->kv.key_max = 32; f->kv.val_max = sizeof(f->claims);
    if (mode("missing")) { args.nelts = 1; }
    if (mode("empty")) { ngx_str_set(&values[1], "zone="); }
    if (mode("bad-option")) { ngx_str_set(&values[1], "unsafe=cache"); }
    if (mode("small-key")) { f->kv.key_max = 31; }
    if (mode("small-value")) { f->kv.val_max--; }
    char *rc = brix_token_cache_directive(&cf, &command, &target);
    assert((rc == NGX_CONF_OK) == mode("normal"));
    assert(target.guard == 71);
    assert(target.slot == (mode("normal") ? &f->kv : NULL));
}

int main(int argc, char **argv)
{
    assert(argc == 4);
    fixture f = {0}; f.mode = argv[2]; ngx_cycle = &f.cycle; f.cycle.log = &f.log;
    assert(brix_crypto_init() == 1);
    if (!strcmp(argv[1], "cache")) { cache_case(&f, atoi(argv[3])); }
    else { assert(!strcmp(argv[1], "directive")); directive_case(&f); }
    brix_crypto_cleanup();
    return 0;
}
