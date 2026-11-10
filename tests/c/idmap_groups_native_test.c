/* Resolve full supplementary group sets before admitting capped credentials. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "auth/impersonate/idmap_internal.h"
#include "platform/platform_api.h"
#include <assert.h>
#include <pwd.h>
#include <grp.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    struct passwd user;
    struct group group;
    int lookups, armed;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }
uid_t __wrap_brix_idmap_get_min_uid(void) { return 1000; }
int __wrap_brix_idmap_get_primary_only(void) { return mode("primary"); }
struct passwd *__wrap_getpwnam(const char *name)
{
    fixture *f = state();
    if (!strcmp(name, "absent") || mode("missing")) { return NULL; }
    f->user.pw_uid = !strcmp(name, "forbidden") ? 3000 : 2000;
    f->user.pw_gid = 2001;
    return &f->user;
}
struct group *__wrap_getgrnam(const char *name)
{
    if (strcmp(name, "forbidden")) { return NULL; }
    state()->group.gr_gid = 4000;
    return &state()->group;
}
int __wrap_brix_plat_getgrouplist(const char *name, gid_t primary, gid_t *groups, int *count)
{
    fixture *f = state(); f->lookups++;
    assert(!strcmp(name, "account") && primary == 2001);
    if (mode("empty")) { *count = 0; return 0; }
    int total = mode("normal") ? 3 : BRIX_IDMAP_MAXGROUPS + 8;
    if (*count < total || mode("grows-again")) { *count = total; f->armed = 1; return -1; }
    *count = total;
    for (int i = 0; i < total; i++) { groups[i] = (gid_t)(2001 + i); }
    if (mode("root-tail")) { groups[total - 1] = 0; }
    if (mode("reserved-tail")) { groups[total - 1] = 999; }
    if (mode("forbidden-tail")) { groups[total - 1] = 4000; }
    return total;
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size)
{
    if (state() && state()->armed && mode("allocation")) { state()->armed = 0; return NULL; }
    return __real_malloc(size);
}
static void configure(ngx_log_t *log)
{
    brix_idmap_conf_t conf = {0};
    ngx_str_set(&conf.forbidden_users, "forbidden, absent, forbidden, \t");
    ngx_str_set(&conf.forbidden_groups, "forbidden, absent, forbidden, \t");
    conf.worker_uid = 5000;
    idmap_init_denylists(&conf, log);
}
static void reserved_check(const char *kind)
{
    brix_idmap_creds_t cr = {.uid=2000, .gid=2001, .ngroups=1, .groups={2002}};
    if (!strcmp(kind, "uid")) { cr.uid = 0; }
    if (!strcmp(kind, "gid")) { cr.gid = 999; }
    if (!strcmp(kind, "supplementary")) { cr.groups[0] = 0; }
    if (!strcmp(kind, "negative")) { cr.ngroups = -1; }
    if (!strcmp(kind, "overflow")) { cr.ngroups = BRIX_IDMAP_MAXGROUPS + 1; }
    uint32_t id = 777; char category = '-';
    int denied = brix_imp_creds_privileged(!strcmp(kind, "null") ? NULL : &cr,
        1000, &id, &category);
    printf("%d %u %c\n", denied, id, category);
}
int main(int argc, char **argv)
{
    assert(argc == 3); fixture f = {0}; f.mode = argv[2]; ngx_cycle = &f.cycle;
    ngx_log_t log = {0}; ngx_open_file_t file = {0}; file.fd = STDERR_FILENO; log.file = &file;
    configure(&log);
    if (!strcmp(argv[1], "reserved")) { reserved_check(f.mode); ngx_cycle = NULL; return 0; }
    brix_idmap_creds_t credentials = {0};
    int rc = idmap_resolve_user("account", &credentials);
    f.armed = 0;
    int allowed = rc == 0 ? idmap_creds_allowed(&credentials) : 0;
    printf("%d %d %d %d\n", rc, f.lookups, credentials.ngroups, allowed);
    if (rc == 0) {
        assert(credentials.uid == 2000 && credentials.gid == 2001);
        for (int i = 0; i < credentials.ngroups; i++) {
            assert(credentials.groups[i] == (gid_t)(2001 + i));
        }
    }
    ngx_cycle = NULL;
    return 0;
}
