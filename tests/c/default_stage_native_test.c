/* Default staging configuration uses private filesystem and identity seams. */
#include "core/config/config.h"
#include "core/config/runtime_server_backend_internal.h"
#include <assert.h>
#include <stdarg.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode, *root;
    char leaf[PATH_MAX], requested[PATH_MAX];
    unsigned chowns, warnings;
    int armed;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Supply config-time identity without changing process credentials.
 * WHY: Default staging must never adopt a foreign user-owned directory.
 * HOW: Pair observed identities with exact runtime-worker ownership requests. */
uid_t __real_geteuid(void);
uid_t __wrap_geteuid(void) { return state() ? (!strncmp(state()->mode, "root-", 5) ? 0 : 1000) : __real_geteuid(); }
ngx_int_t __wrap_brix_imp_worker_runtime_ids(ngx_uid_t configured, ngx_gid_t group,
    uid_t *uid, gid_t *gid)
{ (void) configured; (void) group; *uid = 5000; *gid = 5001; return NGX_OK; }
int __wrap_chown(const char *path, uid_t uid, gid_t gid)
{
    assert(!strcmp(path, state()->requested) && uid == 5000 && gid == 5001); state()->chowns++;
    if (mode("root-chown")) { errno = EPERM; return -1; } return 0;
}

/* WHAT: Confine config provisioning to a disposable fixture directory.
 * WHY: Tests must not create the host's shared default spool.
 * HOW: Validate the production path and forward its leaf operations locally. */
int __wrap_brix_mkdir_recursive(const char *path, mode_t permissions)
{
    assert(!strcmp(path, "/tmp/staging") && permissions == 0711);
    if (mode("base")) { errno = EACCES; return -1; } return 0;
}
int __real_mkdir(const char *, mode_t);
int __wrap_mkdir(const char *path, mode_t permissions)
{
    if (!state() || strcmp(path, state()->leaf) == 0) { return __real_mkdir(path, permissions); }
    assert(!strncmp(path, "/tmp/staging/", 13) && permissions == 0700);
    snprintf(state()->requested, sizeof(state()->requested), "%s", path);
    if (mode("mkdir")) { errno = ENOSPC; return -1; }
    return __real_mkdir(state()->leaf, permissions);
}
int __real_stat64(const char *, struct stat64 *);
int __wrap_stat64(const char *path, struct stat64 *out)
{
    if (!state()) { return __real_stat64(path, out); }
    assert(!strcmp(path, state()->requested));
    if (mode("stat")) { errno = EIO; return -1; }
    int rc = __real_stat64(state()->leaf, out); assert(rc == 0);
    out->st_uid = mode("foreign") ? 1001 : 1000;
    if (mode("root-owned")) { out->st_uid = 5000; }
    if (mode("not-directory")) { out->st_mode = S_IFREG | 0600; }
    return 0;
}
int __real_access(const char *, int);
int __wrap_access(const char *path, int permissions)
{
    if (!state()) { return __real_access(path, permissions); }
    assert(!strcmp(path, state()->requested) && permissions == (W_OK | X_OK));
    if (mode("access")) { errno = EACCES; return -1; }
    return __real_access(state()->leaf, permissions);
}
void *__real_ngx_pnalloc(ngx_pool_t *, size_t);
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    if (state()->armed && mode("allocation")) { state()->armed = 0; return NULL; }
    return __real_ngx_pnalloc(pool, size);
}

/* WHAT: Provide a finite mount-info document and capture real diagnostic bodies.
 * WHY: Stores under PrivateTmp must be explicitly identified to the operator.
 * HOW: Substitute only procfs input and nginx's final config diagnostic sink. */
FILE *__real_fopen64(const char *, const char *);
FILE *__wrap_fopen64(const char *path, const char *flags)
{
    if (!state() || strcmp(path, "/proc/self/mountinfo")) { return __real_fopen64(path, flags); }
    if (mode("mount-open")) { errno = EACCES; return NULL; }
    FILE *file = tmpfile(); assert(file);
    const char *root = mode("ordinary") ? "/tmp" : "/tmp/systemd-private-unit/tmp";
    fprintf(file, "malformed\n1 2 0:1 %s /tmp rw - tmpfs tmpfs rw\n", root);
    rewind(file); return file;
}
void __wrap_ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t error,
    const char *format, ...)
{
    (void) error; assert(cf->cycle == &state()->cycle && level == NGX_LOG_WARN);
    assert(!strcmp(format, "level=%s %s"));
    va_list args; va_start(args, format); (void) va_arg(args, const char *);
    const char *body = va_arg(args, const char *); printf("%s\n", body);
    va_end(args); state()->warnings++;
}

int main(int argc, char **argv)
{
    assert(argc == 6); fixture f = {0}; f.mode = argv[2]; f.root = argv[3]; ngx_cycle = &f.cycle;
    ngx_open_file_t file = {.fd = STDERR_FILENO}; ngx_log_t log = {.file = &file};
    f.cycle.log = &log; ngx_time_init();
    f.cycle.pool = ngx_create_pool(16384, &log); assert(f.cycle.pool);
    void *contexts[1] = {NULL}; ngx_core_module.index = 0; f.cycle.conf_ctx = (void ****) contexts;
    ngx_conf_t cf = {.cycle = &f.cycle, .pool = f.cycle.pool, .log = &log};
    ngx_http_brix_shared_conf_t common = {0};
    common.storage_backend = (ngx_str_t) {strlen(argv[4]), (u_char *) argv[4]};
    assert(snprintf(f.leaf, sizeof(f.leaf), "%s/leaf", f.root) < PATH_MAX);
    if (!strcmp(argv[1], "default")) {
        if (mode("exists")) { assert(!__real_mkdir(f.leaf, 0700)); }
        f.armed = 1; brix_tier_default_stage_store(&cf, &common);
        assert(common.stage_enable == atoi(argv[5]));
        if (common.stage_enable) { printf("store=%s\n", common.stage_store.data); }
        else { assert(common.stage_store.len == 0 && common.stage_store.data == NULL); }
        assert(f.chowns == (unsigned) (mode("root-new") || mode("root-chown")));
    } else {
        common.stage_store = (ngx_str_t) {strlen(argv[4]), (u_char *) argv[4]};
        common.cache_store = (ngx_str_t) {strlen(argv[5]), (u_char *) argv[5]};
        brix_tier_warn_private_tmp(&cf, &common);
    }
    printf("warnings=%u\n", f.warnings);
    ngx_destroy_pool(f.cycle.pool); ngx_cycle = NULL; return 0;
}
