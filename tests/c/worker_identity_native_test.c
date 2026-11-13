/* Exercise fail-closed worker identity transitions through finite PAL outcomes. */
#include "core/ngx_brix_module.h"
#include "auth/impersonate/lifecycle.h"
#include "platform/platform_api.h"
#include <assert.h>
#include <pwd.h>
#include <grp.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    uid_t uid, saved;
    gid_t gid, supplementary;
    struct passwd account;
    int capsets, group_sets, uid_sets, gid_sets, allocation;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }
uid_t __wrap_getuid(void) { return state()->uid; }
uid_t __wrap_geteuid(void) { return state()->uid; }
int __wrap_brix_plat_getresuid(uid_t *real, uid_t *effective, uid_t *saved)
{ *real = *effective = state()->uid; *saved = state()->saved; return mode("uid-read") ? -1 : 0; }
int __wrap_brix_plat_getresgid(gid_t *real, gid_t *effective, gid_t *saved)
{ *real = *effective = *saved = state()->gid; return mode("gid-read") ? -1 : 0; }
struct passwd *__wrap_getpwnam(const char *name)
{
    fixture *f = state(); if (mode("missing")) { return NULL; }
    f->account.pw_name = (char *)name; f->account.pw_uid = mode("root-target") ? 0 : 2000;
    f->account.pw_gid = 2001; return &f->account;
}
struct passwd *__wrap_getpwuid(uid_t uid)
{
    if (mode("default-missing")) { return NULL; }
    state()->account.pw_uid = uid; state()->account.pw_gid = 3001;
    state()->account.pw_name = "service"; return &state()->account;
}
int __wrap_getgroups(int count, gid_t *groups)
{
    if (mode("group-count")) { return -1; }
    if (!count) { state()->allocation = 1; return 1; }
    assert(count == 1 && groups); state()->allocation = 0;
    if (mode("group-read")) { return -1; }
    groups[0] = state()->supplementary; return 1;
}
int __wrap_brix_plat_getgrouplist(const char *name, gid_t primary, gid_t *groups, int *count)
{
    assert(name && *count >= 1); *count = 1; groups[0] = primary;
    return mode("group-resolve") ? -1 : 1;
}
int __wrap_setgroups(size_t count, const gid_t *groups)
{
    assert(count == 1 && *groups == 2001); state()->group_sets++;
    if (mode("group-write")) { errno = EPERM; return -1; }
    if (!mode("group-unstuck")) { state()->supplementary = *groups; } return 0;
}
int __wrap_setgid(gid_t gid)
{ assert(gid == 2001); state()->gid_sets++; if (mode("gid-write")) { return -1; } state()->gid = gid; return 0; }
int __wrap_setuid(uid_t uid)
{
    assert(uid == 2000); state()->uid_sets++; if (mode("uid-write")) { return -1; }
    if (!mode("uid-unstuck")) { state()->uid = state()->saved = uid; } return 0;
}
int __wrap_brix_plat_setresgid(gid_t real, gid_t effective, gid_t saved)
{ assert(real == effective && real == saved); return __wrap_setgid(real); }
int __wrap_brix_plat_setresuid(uid_t real, uid_t effective, uid_t saved)
{ assert(real == effective && real == saved); return __wrap_setuid(real); }
int __wrap_brix_imp_cap_held(int cap)
{ assert(cap == CAP_SETUID || cap == CAP_SETGID); return !mode("no-cap") && strncmp(state()->mode, "default", 7); }
int __wrap_brix_plat_prctl(int option, unsigned long argument)
{ assert(option == PR_SET_NO_NEW_PRIVS && argument == 1); return mode("no-new-privs") ? -1 : 0; }
ngx_int_t __wrap_brix_imp_worker_drop_bounds(ngx_log_t *log)
{ (void)log; return mode("bounds") ? NGX_ERROR : NGX_OK; }
int __wrap_brix_plat_capset(const void *header, const void *data)
{
    const struct __user_cap_header_struct *h = header;
    const struct __user_cap_data_struct *caps = data;
    assert(h->version == _LINUX_CAPABILITY_VERSION_3 && !h->pid);
    assert(!caps[0].inheritable && !caps[1].effective && !caps[1].permitted && !caps[1].inheritable);
    state()->capsets++; return mode("cap-write") ? -1 : 0;
}
int __wrap_brix_plat_capget(const void *header, void *data)
{
    (void)header; struct __user_cap_data_struct *caps = data; memset(caps, 0, 2 * sizeof(*caps));
    if (mode("cap-retained")) { caps[1].inheritable = 1; }
    return mode("cap-read") ? -1 : 0;
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size)
{ if (state() && state()->allocation && mode("allocation")) { state()->allocation = 0; return NULL; } return __real_malloc(size); }
int main(int argc, char **argv)
{
    assert(argc == 3); fixture f = {0}; f.mode = argv[2]; f.uid = f.saved = 2000; f.gid = f.supplementary = 2001;
    ngx_cycle = &f.cycle; ngx_process = NGX_PROCESS_WORKER;
    strcpy(brix_worker_user, "confined");
    if (!strcmp(argv[1], "transition")) { f.uid = f.saved = 0; f.gid = f.supplementary = 0; }
    if (!strcmp(argv[1], "normalize")) { f.gid = f.supplementary = 3001; f.saved = 0; }
    if (!strncmp(f.mode, "default", 7)) { brix_worker_user[0] = 0; f.uid = f.saved = 3000; f.gid = f.supplementary = 3001; }
    if (mode("default-unsafe")) { f.saved = 0; }
    if (mode("single")) { ngx_process = NGX_PROCESS_SINGLE; }
    ngx_log_t log = {0}; ngx_open_file_t file = {.fd=STDERR_FILENO}; log.file = &file; ngx_time_init();
    int rc = !strcmp(argv[1], "harden") ? brix_imp_worker_harden(&log) : brix_imp_worker_deescalate(&log);
    printf("%d %d %d %d %d\n", rc, f.capsets, f.group_sets, f.gid_sets, f.uid_sets);
    ngx_cycle = NULL; return 0;
}
