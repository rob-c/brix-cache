/* Real block extents must isolate neighboring bytes and preserve fixed geometry. */
#include "fs/backend/block/sd_block_internal.h"
#include <assert.h>
#include <dirent.h>

typedef struct { ngx_cycle_t cycle; unsigned allocation, fail_at; } fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int fail_alloc(void)
{
    fixture *f = state(); return f->fail_at && ++f->allocation == f->fail_at;
}
void *__real_ngx_pcalloc(ngx_pool_t *, size_t);
void *__real_ngx_pnalloc(ngx_pool_t *, size_t);
void *__real_ngx_calloc(size_t, ngx_log_t *);
void *__wrap_ngx_pcalloc(ngx_pool_t *pool, size_t size)
{ return fail_alloc() ? NULL : __real_ngx_pcalloc(pool, size); }
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size)
{ return fail_alloc() ? NULL : __real_ngx_pnalloc(pool, size); }
void *__wrap_ngx_calloc(size_t size, ngx_log_t *log)
{ return fail_alloc() ? NULL : __real_ngx_calloc(size, log); }

/* WHAT: Enumerate only the fixed extent namespace.
 * WHY: A short final extent still has one name, while object paths are not dirs.
 * HOW: Read the actual driver cursor and report its complete finite listing. */
static void listing(brix_sd_instance_t *inst, const char *key, int expected)
{
    int error = 0; brix_sd_dir_t *dir = sd_block_opendir(inst, key, &error);
    if (expected) { assert(!dir && error == expected); return; }
    assert(dir); brix_sd_dirent_t entry; ngx_int_t rc;
    while ((rc = sd_block_readdir(dir, &entry)) == NGX_OK) {
        assert(entry.d_type == DT_REG); puts(entry.name);
    }
    assert(rc == NGX_DONE && sd_block_readdir(dir, &entry) == NGX_DONE);
    assert(sd_block_closedir(dir) == NGX_OK);
}

/* WHAT: Check logical and handle metadata agree for a successfully opened extent.
 * WHY: Device capacity cannot leak as an extent's logical size.
 * HOW: Compare actual stat slots and the window saved by production open. */
static off_t metadata(brix_sd_instance_t *inst, const char *key, brix_sd_obj_t *obj)
{
    brix_sd_stat_t path, handle;
    assert(sd_block_stat(inst, key, &path) == NGX_OK);
    assert(obj->driver->fstat(obj, &handle) == NGX_OK);
    assert(path.is_reg && handle.is_reg && !path.is_dir && path.size == handle.size);
    assert(path.size == ((sd_block_obj_t *) obj->state)->len);
    return path.size;
}

/* WHAT: Exercise scalar and vector I/O with independent byte-level verification.
 * WHY: A legal short read must never expose the next extent; an overrun write fails.
 * HOW: Output the read bytes and let the Python test compare the backing file too. */
static void io(brix_sd_obj_t *obj, const char *op, off_t offset, int expected)
{
    unsigned char bytes[80]; memset(bytes, 0xa5, sizeof(bytes));
    ssize_t rc;
    if (!strcmp(op, "read")) {
        rc = obj->driver->pread(obj, bytes, 16, offset);
    } else if (!strcmp(op, "write")) {
        rc = obj->driver->pwrite(obj, "0123456789abcdef", 16, offset);
    } else {
        struct iovec vectors[80];
        for (size_t i = 0; i < 80; i++) {
            vectors[i].iov_base = bytes + i; vectors[i].iov_len = 1;
        }
        int count = !strcmp(op, "vector-invalid") ? -1 : 80;
        rc = !strcmp(op, "vector2")
            ? obj->driver->preadv2(obj, vectors, count, offset, 0)
            : obj->driver->preadv(obj, vectors, count, offset);
    }
    if (expected) { assert(rc == -1 && errno == expected); return; }
    assert(rc >= 0 && rc <= (ssize_t) sizeof(bytes));
    if (strcmp(op, "write")) {
        assert(fwrite(bytes, 1, (size_t) rc, stdout) == (size_t) rc);
        for (size_t i = (size_t) rc; i < sizeof(bytes); i++) { assert(bytes[i] == 0xa5); }
    }
}

static void object_case(brix_sd_instance_t *inst, char **args)
{
    const char *op = args[0], *key = !strcmp(args[1], "<null>") ? NULL : args[1];
    off_t value = (off_t) atoll(args[2]); int expected = atoi(args[3]), error = 0;
    if (!strcmp(op, "open-alloc")) { state()->fail_at = (unsigned) value; }
    brix_sd_obj_t *obj = sd_block_open(inst, key,
        BRIX_SD_O_READ | BRIX_SD_O_WRITE | BRIX_SD_O_CREATE | BRIX_SD_O_TRUNC | BRIX_SD_O_EXCL,
        0600, &error);
    if (!strcmp(op, "open") || !strcmp(op, "open-alloc")) {
        assert(!obj && error == expected); return;
    }
    assert(obj); (void) metadata(inst, key, obj);
    if (!strcmp(op, "reserve")) {
        ngx_int_t rc = obj->driver->reserve(obj, value);
        assert(rc == (expected ? NGX_ERROR : NGX_OK));
        if (expected) { assert(errno == expected); }
    } else if (!strcmp(op, "bad-fd")) {
        assert(close(obj->fd) == 0); brix_sd_stat_t st;
        assert(obj->driver->fstat(obj, &st) == NGX_ERROR && errno == EBADF);
        assert(sd_block_close(obj) == NGX_ERROR && obj->fd == NGX_INVALID_FILE);
    } else {
        io(obj, op, value, expected);
        assert(obj->driver->fsync(obj) == NGX_OK);
    }
    assert(sd_block_close(obj) == NGX_OK && obj->state == NULL);
    assert(sd_block_close(obj) == NGX_OK); ngx_free(obj);
}

int main(int argc, char **argv)
{
    assert(argc == 8); fixture f = {0}; ngx_log_t log = {0};
    ngx_cycle = &f.cycle; f.cycle.log = &log;
    ngx_pool_t *pool = ngx_create_pool(4096, &log); assert(pool);
    brix_sd_instance_t inst = {.pool = pool, .log = &log, .driver = &brix_sd_block_driver};
    brix_sd_block_conf_t conf = {.device = argv[1], .extent_size = (size_t) atoll(argv[2])};
    const char *op = argv[3], *key = !strcmp(argv[4], "<null>") ? NULL : argv[4];
    int expected = atoi(argv[6]);
    if (!strcmp(op, "init-alloc")) { f.fail_at = (unsigned) atoi(argv[5]); }
    if (!strcmp(op, "init-empty-name")) { conf.device = ""; }
    ngx_int_t rc = sd_block_init(&inst, !strcmp(op, "init-null") ? NULL : &conf);
    if (!strncmp(op, "init-", 5)) {
        assert(rc == NGX_ERROR && errno == expected && inst.state == NULL);
        ngx_destroy_pool(pool); return 0;
    }
    assert(rc == NGX_OK);
    if (!strcmp(argv[7], "remove")) { assert(unlink(argv[1]) == 0); }
    if (!strcmp(op, "list-alloc")) { f.fail_at = (unsigned) atoi(argv[5]); }
    if (!strncmp(op, "list", 4)) { listing(&inst, key, expected); }
    else if (!strcmp(op, "stat")) {
        brix_sd_stat_t st; rc = sd_block_stat(&inst, key, &st);
        assert(rc == (expected ? NGX_ERROR : NGX_OK));
        if (expected) { assert(errno == expected); }
        else { printf("%d:%lld", (int) st.is_dir, (long long) st.size); }
    } else { object_case(&inst, argv + 3); }
    assert(sd_block_close(NULL) == NGX_OK);
    ngx_destroy_pool(pool); return 0;
}
