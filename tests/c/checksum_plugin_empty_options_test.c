/* Keep the real plugin registration path; replace only loader/log boundaries. */
#include "core/compat/checksum_plugin.h"
#include <assert.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/stat.h>

static void *checked_copy(void *destination, const void *source, size_t length);
static int fixture_stat(const char *path, struct stat *metadata);
static void *fixture_open(const char *path, int mode);
static void *fixture_symbol(void *handle, const char *name);
static int fixture_close(void *handle);

#undef ngx_memcpy
#define ngx_memcpy(dst, src, length) checked_copy(dst, src, length)
#define stat(path, metadata) fixture_stat(path, metadata)
#define dlopen(path, mode) fixture_open(path, mode)
#define dlsym(handle, name) fixture_symbol(handle, name)
#define dlclose(handle) fixture_close(handle)
#include "core/compat/checksum_plugin.c"

static void *
checked_copy(void *destination, const void *source, size_t length)
{
    assert(destination != NULL);
    assert(source != NULL);
    return memcpy(destination, source, length);
}

static int
fixture_stat(const char *path, struct stat *metadata)
{
    memset(metadata, 0, sizeof(*metadata));
    metadata->st_mode = S_IFREG | 0600;
    return 0;
}

static void *
fixture_open(const char *path, int mode)
{
    return (void *) (uintptr_t) 1;
}

static int
fixture_init(void *state, const char *options)
{
    assert(strcmp(options, getenv("BRIX_PLUGIN_OPTIONS")) == 0);
    *(unsigned char *) state = 1;
    return 0;
}

static int
fixture_update(void *state, const unsigned char *bytes, size_t length)
{
    assert(*(unsigned char *) state == 1);
    assert(bytes != NULL && length == 0);
    return 0;
}

static int
fixture_final(void *state, unsigned char *digest)
{
    digest[0] = *(unsigned char *) state;
    return 0;
}

static void *
fixture_symbol(void *handle, const char *name)
{
    static const brix_cks_plugin_t api = {
        .abi = BRIX_CKS_PLUGIN_ABI,
        .name = "fixture",
        .digest_len = 1,
        .state_size = 1,
        .init = fixture_init,
        .update = fixture_update,
        .final = fixture_final,
    };

    assert(handle == (void *) (uintptr_t) 1);
    assert(strcmp(name, BRIX_CKS_PLUGIN_SYMBOL) == 0);
    return (void *) &api;
}

static int
fixture_close(void *handle)
{
    assert(handle == (void *) (uintptr_t) 1);
    return 0;
}

ngx_int_t
brix_checksum_parse(const char *name, size_t length, brix_checksum_alg_t *algorithm,
    char *normalized, size_t capacity)
{
    return NGX_DECLINED;
}

void
ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *config, ngx_err_t error,
    const char *format, ...)
{
}

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
    const char *format, ...)
{
}

int
main(int argc, char **argv)
{
    ngx_cycle_t cycle = {0}, next_cycle = {0};
    ngx_log_t log = {0};
    ngx_conf_t config = {0};
    ngx_str_t name = ngx_string("fixture");
    ngx_str_t path = ngx_string("/fixture/plugin.so");
    ngx_str_t options = ngx_null_string;
    int oversized;

    assert(argc == 2);
    oversized = strcmp(argv[1], "oversized") == 0;
    if (strcmp(argv[1], "value") == 0) {
        ngx_str_set(&options, "mode=quick");
    }
    assert(setenv("BRIX_PLUGIN_OPTIONS",
                   options.len ? (char *) options.data : "", 1) == 0);
    if (oversized) {
        options.len = CKS_PLUGIN_PARMS_MAX + 1;
    }
    config.cycle = &cycle;
    config.log = &log;
    assert(brix_cks_plugin_register(&config, &name, &path, &options)
           == (oversized ? NGX_ERROR : NGX_OK));
    assert(cks_plugins.n == (oversized ? 0 : 1));
    if (!oversized) {
        assert(strcmp(cks_plugins.ent[0].parms, getenv("BRIX_PLUGIN_OPTIONS")) == 0);
    }
    brix_cks_plugins_init_worker(&next_cycle);
    return 0;
}
