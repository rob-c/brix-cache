/* Client S3 adapter: real URL/credential/vtable logic over finite driver seams. */
#include "fs/backend/s3/vfs_s3_internal.h"
#include "auth/cred/cred.h"
#include <assert.h>

/* WHAT: Select one fault. WHY: Keep fixtures isolated. HOW: Read this subprocess's explicit environment. */
static int mode(const char *name) { return !strcmp(getenv("BRIX_S3_ADAPTER_MODE"), name); }
/* WHAT: Record boundary calls. WHY: Make cleanup/order independently observable. HOW: Emit synthetic event names. */
static void event(const char *name) { printf("event=%s\n", name); }
/* WHAT: Supply a finite driver failure. WHY: Pin errno preservation. HOW: Return the requested fault with fixed text. */
static int failure(const char *name, char *error, size_t capacity)
{
    event(name);
    if (!mode(name)) { return 0; }
    errno = atoi(getenv("BRIX_S3_ADAPTER_ERRNO"));
    snprintf(error, capacity, "adapter fixture refused"); return -1;
}
void *__real_calloc(size_t, size_t);
/* WHAT: Fail handle allocation. WHY: Verify no origin request before allocation succeeds. HOW: Match the adapter handle size. */
void *__wrap_calloc(size_t count, size_t size)
{
    if (mode("oom") && count == 1 && size == sizeof(vfs_s3_file)) { return NULL; }
    return __real_calloc(count, size);
}
/* WHAT: Supply a credential-store result. WHY: Check complete-pair selection. HOW: Return synthetic complete/partial views. */
int __wrap_brix_cred_acquire(brix_cred_store *store, brix_cred_kind kind,
    unsigned flags, brix_cred_view *view, brix_status *status)
{
    (void) status; assert(store && kind == XRDC_CRED_S3KEYS && flags == 0);
    event("credentials"); memset(view, 0, sizeof(*view));
    view->s3_access = "store-access";
    if (mode("store")) { view->s3_secret = "store-secret"; }
    return mode("credential-error") ? -1 : 0;
}
/* WHAT: Validate driver arguments. WHY: Avoid misrouted or mixed-key requests. HOW: Require exact synthetic endpoint and identity. */
static void endpoint(const sd_s3_open_params *params)
{
    assert(!strcmp(params->host, "origin.invalid") && params->port == 9443 && params->tls);
    assert(!strcmp(params->key, "/bucket/object") && params->timeout_ms == S3_REQ_TIMEOUT_MS);
    assert(params->transport == &brix_s3_http_transport);
    const char *access = mode("store") ? "store-access" : "env-access";
    const char *secret = mode("store") ? "store-secret" : "env-secret";
    assert(!strcmp(params->ak, access) && !strcmp(params->sk, secret));
    assert(!strcmp(params->region, "test-region"));
}
sd_s3_file *__wrap_sd_s3_open_read(const sd_s3_open_params *params, char *error, size_t cap)
{
    endpoint(params);
    if (failure("open-read", error, cap)) { return NULL; }
    return (sd_s3_file *) malloc(1);
}
sd_s3_file *__wrap_sd_s3_open_write(const sd_s3_open_params *params,
    int64_t expected, int64_t part, char *error, size_t cap)
{
    endpoint(params); assert(expected == 7 && part == 512);
    if (failure("open-write", error, cap)) { return NULL; }
    return (sd_s3_file *) malloc(1);
}
int __wrap_sd_s3_size(sd_s3_file *file, int64_t *size, char *error, size_t cap)
{
    assert(file);
    if (failure("size", error, cap)) { return -1; }
    *size = 7; return 0;
}
ssize_t __wrap_sd_s3_pread(sd_s3_file *file, void *out, size_t count,
    off_t offset, char *error, size_t cap)
{
    assert(file && count == 3 && offset == 2);
    if (failure("read", error, cap)) { return -1; }
    memcpy(out, "ylo", 3); return 3;
}
int __wrap_sd_s3_pwrite(sd_s3_file *file, const void *data, size_t count,
    off_t offset, char *error, size_t cap)
{
    assert(file && offset == 0 && count == 7 && !memcmp(data, "payload", 7));
    return failure("write", error, cap);
}
int64_t __wrap_sd_s3_write_size(sd_s3_file *file) { assert(file); event("write-size"); return 7; }
int __wrap_sd_s3_commit(sd_s3_file *file, char *error, size_t cap)
{ assert(file); return failure("commit", error, cap); }
void __wrap_sd_s3_abort(sd_s3_file *file) { assert(file); event("abort"); }
void __wrap_sd_s3_close(sd_s3_file *file) { assert(file); event("close"); free(file); }

/* WHAT: Exercise the actual handle vtable. WHY: Check lazy size and error cleanup. HOW: Invoke one operation with exact payload bounds. */
static int operate(brix_vfs_file *file, const char *action, brix_status *status)
{
    const brix_vfs_ops *ops = file->ops; assert(file->caps == 0);
    if (!strcmp(action, "write")) { return ops->pwrite(file, 0, "payload", 7, status); }
    if (!strcmp(action, "commit")) { return ops->commit(file, status); }
    if (!strcmp(action, "truncate")) { return ops->truncate(file, 0, status); }
    if (!strcmp(action, "sync")) { return ops->sync(file, status); }
    if (!strcmp(action, "abort")) { ops->abort(file); return 0; }
    if (!strcmp(action, "read")) {
        char data[5] = {0, 0, 0, 0x55, 0x66};
        ssize_t rc = ops->pread(file, 2, data, 3, status);
        assert(data[3] == 0x55 && data[4] == 0x66);
        if (rc >= 0) { assert(rc == 3 && !memcmp(data, "ylo", 3)); }
        return rc < 0 ? -1 : 0;
    }
    brix_vfs_stat out;
    int rc = ops->fstat(file, &out, status);
    if (rc) { return rc; }
    assert(out.exists && !out.is_dir && out.size == 7 && out.mtime == 0);
    return ops->fstat(file, &out, status);
}
/* WHAT: Run one isolated adapter case. WHY: Preserve real production routing. HOW: Use explicit synthetic credentials and finite I/O seams. */
int main(int argc, char **argv)
{
    assert(argc == 5); brix_status status; brix_status_clear(&status);
    assert(setenv("BRIX_S3_ADAPTER_MODE", argv[2], 1) == 0);
    assert(setenv("BRIX_S3_ADAPTER_ERRNO", argv[3], 1) == 0);
    assert(setenv("AWS_ACCESS_KEY_ID", "env-access", 1) == 0);
    assert(setenv("AWS_SECRET_ACCESS_KEY", "env-secret", 1) == 0);
    assert(setenv("AWS_DEFAULT_REGION", "test-region", 1) == 0);
    assert(setenv(S3_PART_MAX_ENV, "512", 1) == 0);
    brix_vfs_open_opts opts = {.expected_size = 7};
    unsigned char credential_marker = 0;
    if (mode("store") || mode("partial") || mode("credential-error")) {
        opts.cred = (brix_cred_store *) &credential_marker;
    }
    int rc;
    if (!strcmp(argv[1], "stat")) {
        brix_vfs_stat out = {0};
        rc = s3_be_stat(&s_s3_backend, argv[4], &out, &status);
        if (rc == 0) { assert(out.exists && out.size == 7 && !out.is_dir); }
    } else {
        brix_vfs_file *file = NULL;
        int flags = (!strcmp(argv[1], "write") || !strcmp(argv[1], "commit")
            || !strcmp(argv[1], "write-stat")) ? XRDC_VFS_WRITE : 0;
        rc = s3_be_open(&s_s3_backend, argv[4], flags, &opts, &file, &status);
        if (rc == 0) { rc = operate(file, argv[1], &status); file->ops->close(file); }
        else { assert(file == NULL); }
    }
    if (mode("open-write") || mode("write") || mode("commit")) {
        assert(status.kxr == s3_brix_from_errno(atoi(argv[3])));
    }
    printf("rc=%d\nerror=%d\n", rc, status.kxr); return 0;
}
