/* Real VFS xattrs with finite failures at allocation and physical publication. */
#include "protocols/root/fattr/storage_keys.h"
#include "core/compat/crypto.h"
#include "platform/platform_api.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    int armed;
    unsigned allocations;
} fixture;

/* WHAT: Select an armed test fault. WHY: Setup uses real production operations.
 * HOW: Store all case state on the selected nginx cycle. */
static int fault(const char *name)
{
    fixture *f = (fixture *) ngx_cycle;
    return f->armed && !strcmp(f->mode, name);
}

void *__real_ngx_palloc(ngx_pool_t *, size_t);
/* WHAT: Fail one requested allocation. WHY: No partial value may escape OOM.
 * HOW: Count only allocations made after the test arms its boundary. */
void *__wrap_ngx_palloc(ngx_pool_t *pool, size_t size)
{
    fixture *f = (fixture *) ngx_cycle;
    if (f->armed) {
        f->allocations++;
        if (fault("alloc-first") || (fault("alloc-second") && f->allocations == 2)) {
            return NULL;
        }
    }
    return __real_ngx_palloc(pool, size);
}

ngx_int_t __real_brix_vfs_fsetxattr(const brix_vfs_ctx_t *, int, const char *,
                                   const void *, size_t, int);
/* WHAT: Refuse chunk or manifest publication. WHY: Failed sets must clean up.
 * HOW: Match the physical namespace and delegate all other writes to real VFS. */
ngx_int_t __wrap_brix_vfs_fsetxattr(const brix_vfs_ctx_t *ctx, int fd,
    const char *key, const void *value, size_t size, int flags)
{
    int chunk = !strncmp(key, FATTR_CHUNK_PREFIX, sizeof(FATTR_CHUNK_PREFIX) - 1);
    if ((chunk && (fault("chunk-io") || fault("chunk-space")))
        || (!chunk && fault("manifest-io"))) {
        errno = fault("chunk-space") ? ENOSPC : EIO;
        return NGX_ERROR;
    }
    return __real_brix_vfs_fsetxattr(ctx, fd, key, value, size, flags);
}

int __real_brix_sha256(const uint8_t *, size_t, uint8_t[32]);
/* WHAT: Refuse a value digest. WHY: Unverified values must not be published.
 * HOW: Name hashing remains real; select the distinct payload length. */
int __wrap_brix_sha256(const uint8_t *data, size_t size, uint8_t out[32])
{
    if (fault("digest") && size > FATTR_CHUNK_VALUE_SIZE) { return 0; }
    return __real_brix_sha256(data, size, out);
}

/* WHAT: Check the exact logical value. WHY: Representation is private.
 * HOW: Compare complete returned bytes through the public storage adapter. */
static void expect(ngx_pool_t *pool, brix_vfs_ctx_t *ctx, int fd,
    const char *name, const u_char *bytes, size_t size)
{
    u_char *actual = NULL;
    assert(fattr_storage_get(pool, ctx, NULL, fd, name, strlen(name), &actual) == (ssize_t) size);
    assert(actual && !memcmp(bytes, actual, size));
}

/* WHAT: Corrupt one reserved envelope field. WHY: Private storage is untrusted.
 * HOW: Rewrite actual bytes and require both lookup and list to fail closed. */
static void corrupt(ngx_pool_t *pool, brix_vfs_ctx_t *ctx, int fd,
    const char *name, const char *mode)
{
    char key[256]; assert(fattr_storage_hashed_key(name, strlen(name), key, sizeof(key)) == 0);
    u_char raw[8192]; ssize_t count = brix_vfs_fgetxattr(ctx, fd, key, raw, sizeof(raw));
    assert(count > 10);
    size_t header = !memcmp(raw, FATTR_CHUNK_MAGIC, 8) ? FATTR_CHUNK_HEADER_LEN : FATTR_STORED_HEADER_LEN;
    if (!strcmp(mode, "magic")) { raw[0] ^= 1; }
    if (!strcmp(mode, "name")) { raw[header] ^= 1; }
    if (!strcmp(mode, "nul-name")) { raw[header] = 0; }
    if (!strcmp(mode, "name-size")) { raw[8] = 255; raw[9] = 255; }
    if (!strcmp(mode, "value-size")) { memset(raw + 10, 255, 4); }
    if (!strcmp(mode, "digest-byte")) { raw[14] ^= 1; }
    if (!strcmp(mode, "truncated")) { count = 5; }
    assert(brix_vfs_fsetxattr(ctx, fd, key, raw, (size_t) count, 0) == NGX_OK);
    u_char *value = (u_char *) "untouched";
    assert(fattr_storage_get(pool, ctx, NULL, fd, name, strlen(name), &value) == -1);
    assert(errno == EIO && !strcmp((const char *) value, "untouched"));
    brix_fattr_stored_t stored = {0};
    assert(fattr_storage_decode_list(pool, ctx, NULL, fd, key, &stored) == BRIX_FATTR_LIST_PRIVATE);
}

/* WHAT: Exercise normal publication and replacement. WHY: Old chunks must go.
 * HOW: Round-trip, enforce CREATE, replace bytes, then remove all physical keys. */
static void roundtrip(ngx_pool_t *pool, brix_vfs_ctx_t *ctx, int fd,
    const char *name, u_char *bytes, size_t size)
{
    expect(pool, ctx, fd, name, bytes, size);
    assert(fattr_storage_set(pool, ctx, NULL, fd, name, strlen(name), bytes, size, XATTR_CREATE) == NGX_ERROR);
    assert(errno == EEXIST);
    memset(bytes, 'b', size);
    assert(fattr_storage_set(pool, ctx, NULL, fd, name, strlen(name), bytes, size, 0) == NGX_OK);
    expect(pool, ctx, fd, name, bytes, size);
    assert(fattr_storage_remove(ctx, NULL, fd, name, strlen(name)) == NGX_OK);
    assert(brix_vfs_flistxattr(ctx, fd, NULL, 0) == 0);
}

/* WHAT: Dispatch the selected fault around a real stored value.
 * WHY: Read and write failures have different ownership contracts.
 * HOW: Arm only the selected operation, then assert errno and physical cleanup. */
static void exercise(fixture *f, brix_vfs_ctx_t *ctx, int fd,
    const char *operation, const char *name, u_char *bytes, size_t size, int expected)
{
    ngx_pool_t *pool = f->cycle.pool;
    if (!strcmp(operation, "write")) {
        f->armed = 1;
        ngx_int_t rc = fattr_storage_set(pool, ctx, NULL, fd, name, strlen(name), bytes, size, 0);
        int error = errno; f->armed = 0;
        assert(rc == (expected ? NGX_ERROR : NGX_OK));
        if (expected) {
            assert(error == expected);
            assert(brix_vfs_flistxattr(ctx, fd, NULL, 0) == 0);
        } else { roundtrip(pool, ctx, fd, name, bytes, size); }
        return;
    }
    assert(fattr_storage_set(pool, ctx, NULL, fd, name, strlen(name), bytes, size, 0) == NGX_OK);
    if (!strcmp(operation, "corrupt")) { corrupt(pool, ctx, fd, name, f->mode); return; }
    assert(!strcmp(operation, "read"));
    u_char *value = NULL; f->armed = 1;
    assert(fattr_storage_get(pool, ctx, NULL, fd, name, strlen(name), &value) == -1);
    int error = errno; f->armed = 0;
    assert(error == expected && value == NULL);
    expect(pool, ctx, fd, name, bytes, size);
}

/* WHAT: Bind a private writable export. WHY: Tests retain the real policy gate.
 * HOW: Use an inherited file descriptor and an initialized VFS context. */
int main(int argc, char **argv)
{
    assert(argc == 8); fixture f = {0}; ngx_log_t log = {0};
    f.mode = argv[3]; f.cycle.log = &log; ngx_cycle = &f.cycle; ngx_time_init();
    assert(brix_crypto_init());
    f.cycle.pool = ngx_create_pool(16384, &log); assert(f.cycle.pool);
    brix_vfs_ctx_t ctx;
    brix_vfs_ctx_init(&ctx, f.cycle.pool, &log, BRIX_PROTO_ROOT, "/", NULL,
        brix_vfs_policy_from_write_enable(1), 0, NULL, argv[1]);
    int fd = open(argv[1], O_CREAT | O_EXCL | O_RDWR, 0600); assert(fd >= 0);
    size_t size = strtoul(argv[5], NULL, 10); assert(size <= 8192);
    u_char bytes[8192]; memset(bytes, 'a', sizeof(bytes));
    if (atoi(argv[7])) { ctx.mutation_policy = BRIX_VFS_MUTATION_READ_ONLY; }
    exercise(&f, &ctx, fd, argv[2], argv[4], bytes, size, atoi(argv[6]));
    assert(close(fd) == 0); ngx_destroy_pool(f.cycle.pool); brix_crypto_cleanup(); return 0;
}
