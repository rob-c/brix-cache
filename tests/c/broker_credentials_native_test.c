/* Credential transitions observed at kernel boundaries; no host identity changes. */
#include "auth/impersonate/broker_internal.h"
#include "core/seccomp/seccomp_core.h"
#include <assert.h>
#include <stdarg.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    const char *mode;
    unsigned stage, bounding, capsets, filters;
    uid_t uid;
    gid_t gid;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return state() && !strcmp(state()->mode, name); }
static int failure(const char *name)
{ if (mode(name)) { errno = EPERM; return -1; } return 0; }

uid_t __wrap_getuid(void) { return mode("nonroot") ? 2000 : 0; }
uid_t __wrap_geteuid(void) { return state()->stage >= 4 ? state()->uid : 0; }
int __wrap_brix_plat_prctl(int option, unsigned long value)
{
    if (option == PR_SET_NO_NEW_PRIVS) { assert(value == 1); return failure("no-new-privs"); }
    if (option == PR_CAPBSET_DROP) {
        assert(value != CAP_SETUID && value != CAP_SETGID); state()->bounding++;
        if (mode("unknown-cap")) { errno = EINVAL; return -1; }
        return failure("bounding");
    }
    assert(option == PR_SET_KEEPCAPS);
    if (value == 0) { assert(state()->stage == 4); return 0; }
    assert(value == 1 && state()->stage == 0);
    if (failure("keepcaps")) { return -1; }
    state()->stage = 1; return 0;
}
long __wrap_syscall(long number, ...)
{
    assert(number == SYS_setgroups && state()->stage == 1);
    va_list args; va_start(args, number);
    size_t count = va_arg(args, size_t); const gid_t *groups = va_arg(args, const gid_t *);
    va_end(args); assert(count == 1 && groups[0] == state()->gid);
    if (failure("groups")) { return -1; }
    state()->stage = 2; return 0;
}
int __wrap_brix_plat_setresgid(gid_t real, gid_t effective, gid_t saved)
{
    assert(state()->stage == 2 && real == state()->gid && effective == real && saved == real);
    if (failure("setgid")) { return -1; }
    state()->stage = 3; return 0;
}
int __wrap_brix_plat_setresuid(uid_t real, uid_t effective, uid_t saved)
{
    assert(state()->stage == 3 && real == state()->uid && effective == real && saved == real);
    if (failure("setuid")) { return -1; }
    state()->stage = 4; return 0;
}
int __wrap_brix_plat_getresuid(uid_t *real, uid_t *effective, uid_t *saved)
{
    assert(state()->stage == 4);
    if (failure("getuid")) { return -1; }
    *real = mode("real-uid") ? 0 : state()->uid;
    *effective = mode("effective-uid") ? 0 : state()->uid;
    *saved = mode("saved-uid") ? 0 : state()->uid;
    return 0;
}
int __wrap_brix_plat_getresgid(gid_t *real, gid_t *effective, gid_t *saved)
{
    if (failure("getgid")) { return -1; }
    *real = mode("real-gid") ? 0 : state()->gid;
    *effective = mode("effective-gid") ? 0 : state()->gid;
    *saved = mode("saved-gid") ? 0 : state()->gid;
    return 0;
}
int __wrap_brix_plat_capset(struct __user_cap_header_struct *header,
    struct __user_cap_data_struct *data)
{
    assert(header->version == _LINUX_CAPABILITY_VERSION_3 && header->pid == 0);
    assert(data[0].permitted == ((1u << CAP_SETUID) | (1u << CAP_SETGID)));
    assert(data[0].effective == (mode("permitted-only") ? 0 : data[0].permitted));
    assert(!data[0].inheritable && !data[1].effective && !data[1].permitted && !data[1].inheritable);
    state()->capsets++;
    if (mode("capset") || (mode("reraise") && state()->stage == 4)) { errno = EPERM; return -1; }
    return 0;
}
int __wrap_brix_seccomp_broker_apply(brix_seccomp_err_fn error, void *context, unsigned *killed)
{
    assert(error == NULL && context == NULL); *killed = 5; state()->filters++;
    return mode("seccomp") ? BRIX_SECCOMP_CORE_ERR : BRIX_SECCOMP_CORE_OK;
}
int main(int argc, char **argv)
{
    assert(argc == 4); fixture f = {0}; f.mode = argv[2]; f.uid = 2001;
    f.cycle.log = &f.log; ngx_cycle = &f.cycle; f.gid = mode("default-gid") ? f.uid : 2002;
    ngx_time_init(); assert(ngx_strerror_init() == NGX_OK);
    brix_imp_set_broker_user(mode("unset") ? (uid_t) -1 : mode("root-user") ? 0 : f.uid,
        mode("default-gid") ? (gid_t) -1 : f.gid);
    ngx_log_t *log = atoi(argv[3]) ? &f.log : NULL;
    int rc;
    if (!strcmp(argv[1], "drop")) { rc = imp_drop_to_service_user(log); }
    else if (!strcmp(argv[1], "capset")) { rc = imp_capset_setuid_setgid(!mode("permitted-only"), log); }
    else { rc = brix_imp_broker_drop_caps(log); }
    printf("rc=%d\nstage=%u\nbounding=%u\ncapsets=%u\nfilters=%u\n", rc, f.stage, f.bounding, f.capsets, f.filters);
    ngx_cycle = NULL; return 0;
}
