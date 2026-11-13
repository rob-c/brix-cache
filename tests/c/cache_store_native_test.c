/* Cache adapter dispatch and sparse-file ownership use real filesystem objects. */
#include "fs/cache/cstore.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    unsigned opens, closes, fills, writes, commits, aborts, parents;
    int armed, fd;
    brix_sd_staged_t staged;
} fixture_t;
static fixture_t *state(void) { return (fixture_t *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

brix_cinfo_l1_t *__real_brix_cinfo_l1_create(size_t, ngx_log_t *);
brix_cinfo_l1_t *__wrap_brix_cinfo_l1_create(size_t n, ngx_log_t *log)
{
    if (mode("allocation")) { errno = ENOMEM; return NULL; }
    return __real_brix_cinfo_l1_create(n, log);
}
int __real_ftruncate64(int, off_t);
int __wrap_ftruncate64(int fd, off_t n)
{
    if (state()->armed && mode("truncate")) {
        state()->fd = fd; errno = ENOSPC; return -1;
    }
    return __real_ftruncate64(fd, n);
}

static ngx_int_t parent(brix_sd_instance_t *inst, const char *key, mode_t permissions)
{
    (void)inst;
    assert(!strcmp(key, "/a") || !strcmp(key, "/a/b"));
    assert(permissions == 0700); state()->parents++; errno = EEXIST; return NGX_ERROR;
}
static brix_sd_staged_t *stage(brix_sd_instance_t *inst, const char *key,
    mode_t permissions, off_t size, int *err)
{
    assert(!strcmp(key, "/a/b/object") && permissions == 0600 && size == 6);
    state()->opens++;
    if (mode("stage-refused")) { *err = EDQUOT; return NULL; }
    state()->staged.inst = inst; return &state()->staged;
}
static ssize_t write_stage(brix_sd_staged_t *st, const void *p, size_t n, off_t off)
{
    assert(st == &state()->staged && n == 3 && off == 2 && !memcmp(p, "abc", 3));
    state()->writes++; return 3;
}
static ngx_int_t commit(brix_sd_staged_t *st, brix_sd_precond_t *pre)
{ assert(st == &state()->staged && pre == NULL); state()->commits++; return NGX_OK; }
static void abort_stage(brix_sd_staged_t *st)
{ assert(st == &state()->staged); state()->aborts++; }

/* WHAT: Supply a real readable object in a heap-owned driver shell.
 * WHY: Check checksum seeding closes the descriptor and consumes its shell.
 * HOW: Open the fixture file, preserve its fd and count the matching close. */
static brix_sd_obj_t *open_object(brix_sd_instance_t *inst, const char *key,
    int flags, mode_t permissions, int *err)
{
    (void)permissions; assert(flags == BRIX_SD_O_READ); state()->opens++;
    if (mode("open-refused")) { *err = EACCES; return NULL; }
    brix_sd_obj_t *o = calloc(1, sizeof(*o)); assert(o);
    o->fd = open(key, O_RDONLY); assert(o->fd >= 0); state()->fd = o->fd;
    o->driver = inst->driver; o->inst = inst; o->heap_shell = 1; return o;
}
static ngx_int_t close_object(brix_sd_obj_t *o)
{ state()->closes++; assert(close(o->fd) == 0); return NGX_OK; }

static int fill(void *ctx, uint64_t block)
{
    fixture_t *f = ctx; assert(block == 1 || block == 2); f->fills++;
    if (mode("fill-refused")) { errno = EIO; return -1; }
    return 0;
}

/* WHAT: Exercise absent-capability guards without creating a storage object.
 * WHY: Unsupported operations must not be reported as successful writes.
 * HOW: Pass empty adapters/handles and assert exact public errno contracts. */
static void missing(brix_cstore_t *cs)
{
    brix_sd_staged_t st = {.inst = cs->store}; int err = 0;
    assert(brix_cstore_fill_open(cs, "x", 0600, 1) == NULL && errno == ENOSYS);
    assert(brix_cstore_fill_write(&st, "x", 1, 0) == -1 && errno == ENOSYS);
    assert(brix_cstore_fill_commit(&st) == NGX_ERROR && errno == ENOSYS);
    brix_cstore_fill_abort(&st); brix_cstore_fill_abort(NULL);
    assert(brix_cstore_serve_open(cs, "x", &err) == NULL && err == ENOSYS);
    assert(brix_cstore_serve_open(cs, "x", NULL) == NULL);
    assert(brix_cstore_partial_open(NULL, "x", 0, 1, NULL, 0) == -1 && errno == ENOTSUP);
    assert(brix_cstore_freespace(NULL, NULL, NULL) == NGX_ERROR && errno == EINVAL);
    brix_cache_cinfo_t ci = {0};
    assert(brix_cstore_cinfo_load(cs, NULL, &ci) == NGX_ERROR && errno == EINVAL);
    assert(brix_cstore_cinfo_store(cs, "x", NULL) == NGX_ERROR && errno == EINVAL);
    assert(brix_cstore_evict(cs, NULL) == NGX_ERROR && errno == EINVAL);
    brix_cstore_seed_checksum(cs, "x", "", "1234");
}

static void partial(brix_cstore_t *cs, const char *root)
{
    strcpy(cs->local_root, root); cs->meta_mode = BRIX_CMETA_LOCAL;
    char key[PATH_MAX + 2] = "/object", output[PATH_MAX];
    if (mode("long-key")) { memset(key, 'a', PATH_MAX); key[PATH_MAX] = 0; }
    state()->armed = 1;
    int fd = brix_cstore_partial_open(cs, key, 0, 12, output, sizeof(output));
    state()->armed = 0;
    if (mode("long-key")) { assert(fd == -1 && errno == ENAMETOOLONG); return; }
    if (mode("truncate")) {
        assert(fd == -1 && errno == ENOSPC);
        assert(fcntl(state()->fd, F_GETFD) == -1 && errno == EBADF); return;
    }
    assert(fd >= 0); struct stat sb; assert(fstat(fd, &sb) == 0 && sb.st_size == 12);
    assert((sb.st_mode & 0777) == 0600);
    assert(pwrite(fd, "abcdefghijkl", 12, 0) == 12);
    uint8_t bitmap = 1; char bytes[16] = {0};
    assert(brix_cstore_serve_pread(fd, &bitmap, 3, 0, 12, bytes, 4, 2, fill, state()) == -1 && errno == EINVAL);
    ssize_t n = brix_cstore_serve_pread(fd, &bitmap, 3, 4, 12, bytes, 16, 2, fill, state());
    if (mode("fill-refused")) { assert(n == -1 && errno == EIO && state()->fills == 1); }
    else { assert(n == 10 && !memcmp(bytes, "cdefghijkl", 10) && state()->fills == 2); }
    assert(brix_cstore_serve_pread(fd, NULL, 3, 4, 12, bytes, 1, 12, fill, state()) == 0);
    close(fd);
    brix_cache_cinfo_t ci = {0};
    memset(key, 'a', PATH_MAX); key[PATH_MAX] = 0;
    assert(brix_cstore_cinfo_load(cs, key, &ci) == NGX_ERROR && errno == ENAMETOOLONG);
    assert(brix_cstore_cinfo_store(cs, key, &ci) == NGX_ERROR && errno == ENAMETOOLONG);
}

int main(int argc, char **argv)
{
    assert(argc == 4); fixture_t f = {0}; f.mode = argv[2]; ngx_cycle = &f.cycle;
    ngx_open_file_t file = {.fd = STDERR_FILENO};
    ngx_log_t log = {.log_level = NGX_LOG_WARN, .file = &file}; ngx_time_init();
    brix_sd_driver_t drv = {.name = "fixture"};
    brix_sd_instance_t inst = {.driver = &drv}; brix_cstore_t cs = {.store = &inst};
    if (!strcmp(argv[1], "partial")) { partial(&cs, argv[3]); }
    else if (!strcmp(argv[1], "missing")) { missing(&cs); }
    else if (!strcmp(argv[1], "seed")) {
        drv.open = open_object; drv.close = close_object;
        brix_cstore_seed_checksum(&cs, argv[3], "adler32", "1e3f04cf");
        assert(f.opens == 1 && f.closes == (unsigned)!mode("open-refused"));
        if (f.closes) { assert(fcntl(f.fd, F_GETFD) == -1 && errno == EBADF); }
    } else if (!strcmp(argv[1], "fill")) {
        drv.mkdir = parent; drv.staged_open = stage; drv.staged_write = write_stage;
        drv.staged_commit = commit; drv.staged_abort = abort_stage;
        brix_sd_staged_t *st = brix_cstore_fill_open(&cs, "/a/b/object", 0600, 6);
        assert(f.parents == 2 && f.opens == 1);
        if (mode("stage-refused")) { assert(st == NULL && errno == EDQUOT); }
        else {
            assert(brix_cstore_fill_write(st, "abc", 3, 2) == 3);
            assert(brix_cstore_fill_commit(st) == NGX_OK); brix_cstore_fill_abort(st);
            assert(f.writes == 1 && f.commits == 1 && f.aborts == 1);
        }
    } else {
        assert(brix_cstore_init(NULL, &inst, NULL, 0, 1, 0, &log) == NGX_ERROR && errno == EINVAL);
        if (mode("xattr")) { drv.caps = BRIX_SD_CAP_XATTR; inst.caps = BRIX_SD_CAP_XATTR; }
        int rc = brix_cstore_init(&cs, &inst, NULL, 0, 2, 0, &log);
        if (mode("allocation")) { assert(rc == NGX_ERROR && errno == ENOMEM); }
        else {
            assert(rc == NGX_OK && cs.meta_mode == (mode("xattr") ? BRIX_CMETA_XATTR : BRIX_CMETA_SIDECAR));
            brix_cstore_cleanup(&cs); assert(cs.l1 == NULL);
        }
    }
    ngx_cycle = NULL; return 0;
}
