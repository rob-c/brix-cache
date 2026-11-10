/* WHAT: Exercise the real remote driver metadata and credential boundary.
 * WHY: A failed metadata read must neither erase unrelated fields nor fall
 * back from the caller's identity to the export's service keys.
 * HOW: Link configured server objects and inject finite S3 operation results.
 * Path construction, credential selection, merging and errno mapping stay real. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/remote/sd_remote_internal.h"
#include "fs/backend/meta_advisory.h"
#include "platform/platform_api.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *action, *fault, *identity;
    unsigned opens, closes, lists, gets, stores, heads, prefixes;
    unsigned writes, commits, aborts, copies, deletes;
    char key[768];
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int fault(const char *name) { return !strcmp(state()->fault, name); }
static int action(const char *name) { return !strcmp(state()->action, name); }

static void check_params(const sd_s3_open_params *p)
{
    assert(!strcmp(p->host, "origin.invalid") && p->port == 443 && p->tls == 1);
    assert(!strncmp(p->key, "/bucket/", 8));
    int user = !strcmp(state()->identity, "user");
    assert(!strcmp(p->ak, user ? "user-ak" : "service-ak"));
    assert(!strcmp(p->sk, user ? "user-sk" : "service-sk"));
    assert(!strcmp(p->region, user ? "user-region" : "service-region"));
    assert(user ? p->session_token && !strcmp(p->session_token, "user-session") : p->session_token == NULL);
}
sd_s3_file *__wrap_sd_s3_open_read(const sd_s3_open_params *p, char *error, size_t cap)
{
    (void) error; (void) cap; check_params(p); state()->opens++;
    snprintf(state()->key, sizeof(state()->key), "%s", p->key);
    if (fault("open") || fault("open-deny")) {
        errno = fault("open-deny") ? EACCES : 0; return NULL;
    }
    return (sd_s3_file *) state();
}
void __wrap_sd_s3_close(sd_s3_file *f)
{ assert(f == (sd_s3_file *) state()); state()->closes++; }

static ssize_t names(char *out, size_t cap)
{
    char list[4096] = {0}; size_t n = 0;
    unsigned count = fault("full") || fault("full-advisory") ? 32 : fault("overfull") ? 33 : 1;
    if (!fault("empty")) {
        for (unsigned i = 0; i < count; ++i) {
            int written = snprintf(list + n, sizeof(list) - n, "user.%s%u", count == 1 ? "color" : "key", i);
            assert(written > 0 && (size_t) written < sizeof(list) - n); n += (size_t) written + 1;
        }
    }
    if (fault("ignored-names")) {
        memcpy(list + n, "system.secret\0user.\0", 20); n += 20;
    }
    if (fault("long-existing")) {
        memcpy(list, "user.", 5); memset(list + 5, 'a', 170); list[175] = 0; n = 176;
    }
    if (!out || !cap) { return (ssize_t) n; }
    if (cap < n) { errno = ERANGE; return -1; }
    memcpy(out, list, n); return (ssize_t) n;
}
ssize_t __wrap_sd_s3_list_meta(sd_s3_file *f, char *out, size_t cap, char *error, size_t errcap)
{
    (void) error; (void) errcap; assert(f == (sd_s3_file *) state()); state()->lists++;
    if (fault("list") || fault("list-deny") || fault("list-unsupported")) {
        errno = fault("list-deny") ? EACCES : fault("list-unsupported") ? ENOTSUP : 0; return -1;
    }
    if (fault("missing") || (fault("marker") && state()->lists == 1)) { errno = ENOENT; return -1; }
    return names(out, cap);
}
ssize_t __wrap_sd_s3_get_meta(sd_s3_file *f, const char *name, const sd_s3_meta_buf *out,
    char *error, size_t cap)
{
    (void) error; (void) cap; assert(f == (sd_s3_file *) state()); state()->gets++;
    int advisory = !strcmp(name, BRIX_META_ADVISORY_S3META);
    if (fault("get") || fault("get-deny") || (fault("advisory-error") && advisory)) {
        errno = fault("get-deny") ? EACCES : 0; return -1;
    }
    if (fault("absent") || (advisory && !fault("advisory") && !fault("full-advisory"))) { return 0; }
    const char *value = advisory ? "v1 mode=0640 uid=123 gid=456" : "blue";
    size_t n = strlen(value); assert(n < out->cap); memcpy(out->buf, value, n + 1); return (ssize_t) n;
}
int __wrap_sd_s3_set_meta(const sd_s3_open_params *p, const sd_s3_meta_kv *pairs,
    size_t n, char *error, size_t cap)
{
    (void) error; (void) cap; check_params(p); state()->stores++;
    assert(n <= 32); printf("store-key=%s\n", p->key);
    for (size_t i = 0; i < n; ++i) { printf("pair=%s:%s\n", pairs[i].name, pairs[i].value); }
    if (fault("store") || fault("store-deny")) { errno = fault("store-deny") ? EACCES : 0; return -1; }
    return 0;
}
int __wrap_sd_s3_size(sd_s3_file *f, int64_t *size, char *error, size_t cap)
{
    (void) error; (void) cap; assert(f == (sd_s3_file *) state()); state()->heads++;
    if (fault("normal") || (fault("marker") && state()->heads == 2)
        || (action("rename") && (fault("copy") || fault("copy-deny") || fault("delete") || fault("delete-deny"))))
    { *size = 1234; return 0; }
    if (fault("head") || fault("head-deny")) { errno = fault("head-deny") ? EACCES : 0; return -1; }
    if (fault("marker-deny") && state()->heads == 2) { errno = EACCES; return -1; }
    errno = ENOENT; return -1;
}
int __wrap_sd_s3_prefix_exists(const sd_s3_open_params *p, const char *prefix, char *error, size_t cap)
{
    (void) error; (void) cap; check_params(p); assert(!strcmp(p->key, "/bucket/"));
    assert(!strcmp(prefix, "object/")); state()->prefixes++;
    if (fault("prefix") || fault("prefix-deny")) { errno = fault("prefix-deny") ? EACCES : 0; return -1; }
    return fault("implicit") ? 1 : 0;
}

sd_s3_file *__wrap_sd_s3_open_write(const sd_s3_open_params *p, int64_t size,
    int64_t part, char *error, size_t cap)
{
    (void) error; (void) cap; check_params(p); state()->writes++;
    assert(!strcmp(p->key, "/bucket/object/") && size == 0 && part > 0);
    return fault("write-open") ? NULL : (sd_s3_file *) state();
}
int __wrap_sd_s3_commit(sd_s3_file *f, char *error, size_t cap)
{
    (void) error; (void) cap; assert(f == (sd_s3_file *) state()); state()->commits++;
    return fault("commit") ? -1 : 0;
}
void __wrap_sd_s3_abort(sd_s3_file *f)
{ assert(f == (sd_s3_file *) state()); state()->aborts++; }
int __wrap_sd_s3_copy(const sd_s3_open_params *p, const char *source, char *error, size_t cap)
{
    (void) error; (void) cap; check_params(p); state()->copies++;
    assert(!strncmp(source, "/bucket/object", 14) && !strncmp(p->key, "/bucket/dest", 12));
    assert((source[strlen(source) - 1] == '/') == (p->key[strlen(p->key) - 1] == '/'));
    if (fault("copy") || fault("copy-deny")) { errno = fault("copy-deny") ? EACCES : 0; return -1; }
    return 0;
}
int __wrap_sd_s3_delete(const sd_s3_open_params *p, char *error, size_t cap)
{
    (void) error; (void) cap; check_params(p); state()->deletes++;
    assert(!strncmp(p->key, "/bucket/object", 14));
    if (fault("delete") || fault("delete-deny")) { errno = fault("delete-deny") ? EACCES : 0; return -1; }
    return 0;
}
int __wrap_sd_s3_list_page(const sd_s3_open_params *p, const char *prefix,
    const char *continuation, sd_s3_list_cb callback, void *context, int *truncated,
    char *next, size_t next_cap, char *error, size_t cap)
{
    (void) error; (void) cap; check_params(p); state()->lists++;
    assert(!strcmp(prefix, "object/") && !*continuation && next_cap > 0);
    *truncated = 0; next[0] = 0;
    if (fault("children-error") || fault("children-deny")) {
        errno = fault("children-deny") ? EACCES : 0; return -1;
    }
    if (fault("children")) { assert(callback(context, "child", 0) == 1); }
    return 0;
}

static long read_metadata(brix_sd_instance_t *inst, const brix_sd_cred_t *cred,
    const char *name, int capacity)
{
    char buf[4096] = {0}; assert(capacity <= (int) sizeof(buf));
    void *out = capacity < 0 ? NULL : buf; size_t cap = capacity < 0 ? sizeof(buf) : (size_t) capacity;
    long rc;
    if (action("get")) {
        rc = cred ? sd_remote_getxattr_cred(inst, "/object", name, out, cap, cred)
                  : sd_remote_getxattr(inst, "/object", name, out, cap);
    } else {
        rc = cred ? sd_remote_listxattr_cred(inst, "/object", out, cap, cred)
                  : sd_remote_listxattr(inst, "/object", out, cap);
    }
    if (rc > 0 && out && cap && (size_t) rc <= sizeof(buf)) {
        printf("hex="); for (long i = 0; i < rc; i++) { printf("%02x", (unsigned char) buf[i]); } putchar('\n');
    }
    return rc;
}
static long write_metadata(brix_sd_instance_t *inst, const brix_sd_cred_t *cred,
    const char *name, const char *value, int flags)
{
    if (action("remove")) {
        return cred ? sd_remote_removexattr_cred(inst, "/object", name, cred)
                    : sd_remote_removexattr(inst, "/object", name);
    }
    if (action("set")) {
        size_t len = strlen(value);
        if (fault("binary")) { value = "a\0b"; len = 3; }
        return cred ? sd_remote_setxattr_cred(inst, "/object", name, value, len, flags, cred)
                    : sd_remote_setxattr(inst, "/object", name, value, len, flags);
    }
    brix_sd_setattr_t attr = {.set_mode = !fault("noop"), .mode = 0600};
    return cred ? sd_remote_setattr_cred(inst, "/object", &attr, cred)
                : sd_remote_setattr(inst, "/object", &attr);
}
static long namespace_operation(brix_sd_instance_t *inst, const brix_sd_cred_t *cred, int flag)
{
    if (action("mkdir")) {
        return cred ? sd_remote_mkdir_cred(inst, "/object", 0700, cred) : sd_remote_mkdir(inst, "/object", 0700);
    }
    if (action("rename")) {
        return cred ? sd_remote_rename_cred(inst, "/object", "/dest", flag, cred)
                    : sd_remote_rename(inst, "/object", "/dest", flag);
    }
    if (action("unlink")) {
        return cred ? sd_remote_unlink_cred(inst, "/object", flag, cred) : sd_remote_unlink(inst, "/object", flag);
    }
    off_t bytes = -1;
    long rc = cred ? sd_remote_server_copy_cred(inst, "/object", "/dest", &bytes, cred)
                   : sd_remote_server_copy(inst, "/object", "/dest", &bytes);
    printf("bytes=%ld\n", (long) bytes); return rc;
}
int main(int argc, char **argv)
{
    assert(argc == 8); fixture f = {0}; f.action = argv[1]; f.fault = argv[2]; f.identity = argv[3];
    ngx_cycle = &f.cycle;
    brix_sd_remote_cfg_t cfg = {.host = "origin.invalid", .port = 443, .tls = 1,
        .bucket = "bucket", .access_key = "service-ak", .secret_key = "service-sk", .region = "service-region"};
    brix_sd_instance_t inst = {.state = &cfg}; brix_sd_cred_t cred = {0};
    if (!strcmp(f.identity, "user")) {
        cred.s3_ak = "user-ak"; cred.s3_sk = "user-sk"; cred.s3_region = "user-region"; cred.s3_session = "user-session";
    }
    cred.fallback_deny = !strcmp(f.identity, "deny");
    const brix_sd_cred_t *selected = !strcmp(f.identity, "plain") ? NULL : &cred;
    long rc; errno = 0;
    if (action("stat")) {
        const char *path = !strcmp(argv[4], "NULL") ? NULL : argv[4]; brix_sd_stat_t st = {0};
        rc = selected ? sd_remote_stat_cred(&inst, path, &st, selected) : sd_remote_stat(&inst, path, &st);
        printf("size=%ld\ndir=%d\nreg=%d\n", (long) st.size, st.is_dir, st.is_reg);
    } else if (action("get") || action("list")) {
        rc = read_metadata(&inst, selected, argv[4], atoi(argv[6]));
    } else if (action("mkdir") || action("rename") || action("unlink") || action("copy")) {
        rc = namespace_operation(&inst, selected, !strcmp(argv[7], "create"));
    } else {
        int flags = !strcmp(argv[7], "create") ? XATTR_CREATE : !strcmp(argv[7], "replace") ? XATTR_REPLACE : 0;
        rc = write_metadata(&inst, selected, argv[4], argv[5], flags);
    }
    printf("rc=%ld\nerrno=%d\nopens=%u\ncloses=%u\nlists=%u\ngets=%u\nstores=%u\nheads=%u\nprefixes=%u\n",
        rc, errno, f.opens, f.closes, f.lists, f.gets, f.stores, f.heads, f.prefixes);
    printf("writes=%u\ncommits=%u\naborts=%u\ncopies=%u\ndeletes=%u\n",
        f.writes, f.commits, f.aborts, f.copies, f.deletes);
    ngx_cycle = NULL; return 0;
}
