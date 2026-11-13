/* Exercise cache admission, the actual POSIX storage driver, VFS adoption and
 * both metadata generations. Fault callbacks only inject named I/O failures. */
#include "fs/cache/open.h"
#include "fs/cache/meta.h"
#include "fs/cache/cache_storage.h"
#include "fs/meta/xmeta_path.h"
#include "fs/vfs/vfs.h"
#include "fs/backend/sd_registry.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    ngx_log_t log;
    ngx_cycle_t cycle;
    ngx_stream_brix_srv_conf_t conf;
    brix_vfs_ctx_t ctx;
    brix_sd_driver_t driver;
    brix_sd_instance_t *storage;
    brix_cache_meta_t meta;
    const char *mode;
    char file[PATH_MAX];
    int opened_fd;
} fixture_t;

ngx_int_t __real_brix_vfs_adopt_obj(brix_vfs_ctx_t *, const char *,
    brix_sd_obj_t *, unsigned, brix_vfs_file_t **);

ngx_int_t
__wrap_brix_vfs_adopt_obj(brix_vfs_ctx_t *ctx, const char *path,
    brix_sd_obj_t *object, unsigned writable, brix_vfs_file_t **out)
{
    fixture_t *f = ctx->log->data;
    if (!strncmp(f->mode, "adopt-", 6)) {
        assert(!strcmp(path, "/file") && writable == 0);
        f->opened_fd = object->fd;
        errno = ENOMEM;
        return NGX_ERROR;
    }
    return __real_brix_vfs_adopt_obj(ctx, path, object, writable, out);
}

static ngx_int_t
stat_error(brix_sd_instance_t *instance, const char *path, brix_sd_stat_t *out)
{
    (void) instance; (void) out;
    assert(!strcmp(path, "/file"));
    errno = EIO;
    return NGX_ERROR;
}

static brix_sd_obj_t *
open_fault(brix_sd_instance_t *instance, const char *path, int flags,
    mode_t mode, int *error)
{
    fixture_t *f = instance->log->data;
    assert(!strcmp(path, "/file") && flags == BRIX_SD_O_READ);
    if (strcmp(f->mode, "adopt-heap-error")) {
        *error = !strcmp(f->mode, "open-missing") ? ENOENT : EIO;
        return NULL;
    }
    brix_sd_obj_t *original = brix_sd_posix_driver.open(instance, path, flags, mode, error);
    assert(original != NULL);
    brix_sd_obj_t *heap = malloc(sizeof(*heap));
    assert(heap != NULL);
    *heap = *original; heap->heap_shell = 1;
    return heap;
}

static void
write_bytes(const char *path, const void *data, size_t length)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    assert(fd >= 0 && write(fd, data, length) == (ssize_t) length);
    assert(close(fd) == 0);
}

static void
setup(fixture_t *f, const char *root, char **argv)
{
    f->log.data = f; f->cycle.log = &f->log;
    ngx_cycle = &f->cycle; ngx_os_argv = argv;
    ngx_time_init();
    assert(ngx_os_init(&f->log) == NGX_OK);
    f->cycle.pool = ngx_create_pool(16384, &f->log);
    assert(f->cycle.pool != NULL);
    f->conf.cache_root.data = (u_char *) root;
    f->conf.cache_root.len = strlen(root);
    memcpy(f->conf.common.root_canon, "/export", sizeof("/export"));
    assert(brix_cache_storage_init(&f->conf, &f->cycle) == NGX_OK);
    f->storage = brix_cache_storage_by_root(root);
    assert(f->storage != NULL);
    f->driver = *f->storage->driver;
    f->storage->driver = &f->driver;
    brix_vfs_ctx_init(&f->ctx, f->cycle.pool, &f->log, BRIX_PROTO_ROOT,
        "/export", root, BRIX_VFS_MUTATION_READ_ONLY, 0, NULL, "/export/file");
    assert(snprintf(f->file, sizeof(f->file), "%s/file", root) < (int) sizeof(f->file));
    write_bytes(f->file, "cache-bytes", 11);
    struct stat st;
    assert(stat(f->file, &st) == 0);
    assert(brix_cache_meta_from_stat(&st, "origin-tag", &f->meta) == NGX_OK);
    assert(brix_cache_meta_write(&f->log, f->file, &f->meta) == NGX_OK);
}

static void
prepare_entry(fixture_t *f)
{
    if (!strcmp(f->mode, "stale-size")) { f->meta.size++; }
    if (!strcmp(f->mode, "stale-mtime")) { f->meta.mtime++; }
    /* A size mismatch must be present in the record's file_size as well as
     * the meta fields: a rewrite intentionally preserves the prior bitmap. */
    if (!strcmp(f->mode, "stale-size")) {
        assert(brix_xmeta_path_remove(f->file) == BRIX_XMETA_OK);
    }
    assert(brix_cache_meta_write(&f->log, f->file, &f->meta) == NGX_OK);
    if (!strcmp(f->mode, "no-meta")) { brix_xmeta_path_remove(f->file); }
    if (!strcmp(f->mode, "missing") || !strcmp(f->mode, "directory") || !strcmp(f->mode, "symlink")) {
        assert(unlink(f->file) == 0);
    }
    if (!strcmp(f->mode, "directory")) { assert(mkdir(f->file, 0700) == 0); }
    if (!strcmp(f->mode, "symlink")) { assert(symlink("/etc/passwd", f->file) == 0); }
    if (!strcmp(f->mode, "stat-error")) { f->driver.stat = stat_error; }
    if (!strncmp(f->mode, "open-", 5) || !strcmp(f->mode, "adopt-heap-error")) {
        f->driver.open = open_fault;
    }
}

static ngx_uint_t
open_flags(const char *mode)
{
    if (!strcmp(mode, "nocache")) { return BRIX_VFS_O_NOCACHE; }
    if (!strcmp(mode, "write")) { return BRIX_VFS_O_WRITE; }
    if (!strcmp(mode, "create")) { return BRIX_VFS_O_CREATE; }
    if (!strcmp(mode, "truncate")) { return BRIX_VFS_O_TRUNC; }
    if (!strcmp(mode, "append")) { return BRIX_VFS_O_APPEND; }
    return BRIX_VFS_O_READ;
}

static void
prepare_context(fixture_t *f)
{
    if (!strcmp(f->mode, "disabled")) { f->ctx.cache_enabled = 0; }
    if (!strcmp(f->mode, "no-cache-root")) { f->ctx.cache_root_canon = NULL; }
    if (!strcmp(f->mode, "empty-cache-root")) { f->ctx.cache_root_canon = ""; }
    if (!strcmp(f->mode, "wrong-root")) { f->ctx.root_canon = "/sibling"; }
    if (!strcmp(f->mode, "export-root")) { f->ctx.resolved.resolved.data = (u_char *) "/export"; }
    if (!strcmp(f->mode, "no-storage")) { f->ctx.cache_root_canon = "/nonexistent-brix-cache-fixture"; }
}

static void
open_case(fixture_t *f)
{
    prepare_entry(f); prepare_context(f);
    brix_vfs_file_t *handle = NULL;
    brix_vfs_ctx_t *ctx = !strcmp(f->mode, "null-context") ? NULL : &f->ctx;
    brix_vfs_file_t **out = !strcmp(f->mode, "null-output") ? NULL : &handle;
    ngx_int_t rc = brix_cache_open(ctx, open_flags(f->mode), out);
    if (!strcmp(f->mode, "hit")) {
        assert(rc == NGX_OK && handle != NULL);
        char bytes[16] = {0};
        assert(pread(brix_vfs_file_fd(handle), bytes, 11, 0) == 11);
        assert(!memcmp(bytes, "cache-bytes", 11));
        assert(brix_vfs_close(handle, &f->log) == NGX_OK);
        return;
    }
    assert(handle == NULL);
    if (!strncmp(f->mode, "adopt-", 6)) {
        assert(rc == NGX_ERROR && errno == ENOMEM);
        assert(fcntl(f->opened_fd, F_GETFD) == -1 && errno == EBADF);
    } else if (!strcmp(f->mode, "null-output")) {
        assert(rc == NGX_ERROR && errno == EINVAL);
    } else if (!strcmp(f->mode, "stat-error") || !strcmp(f->mode, "open-error")) {
        assert(rc == NGX_ERROR && errno == EIO);
    } else { assert(rc == NGX_DECLINED); }
}

static void
metadata_case(fixture_t *f)
{
    f->meta.access_count = 3; f->meta.last_access = 1234; f->meta.bytes_served = 17;
    memcpy(f->meta.cks_alg, "crc32c", 6); f->meta.cks_alg_len = 6;
    memcpy(f->meta.cks_hex, "12345678", 8); f->meta.cks_len = 8;
    if (!strcmp(f->mode, "metadata-limits")) {
        f->meta.etag_len = 255; f->meta.cks_alg_len = 255; f->meta.cks_len = 255;
    }
    if (!strcmp(f->mode, "metadata-zero")) {
        brix_xmeta_path_remove(f->file); f->meta.size = 0;
    }
    assert(brix_cache_meta_write(&f->log, f->file, &f->meta) == NGX_OK);
    brix_cache_meta_t readback;
    assert(brix_cache_meta_read(&f->log, f->file, &readback) == NGX_OK);
    assert(readback.mtime == f->meta.mtime && readback.size == f->meta.size);
    assert(readback.access_count == 3 && readback.bytes_served == 17);
    if (!strcmp(f->mode, "metadata-limits")) {
        assert(readback.etag_len == 0 && readback.cks_alg_len == 0 && readback.cks_len == 0);
    } else {
        assert(readback.cks_len == 8 && !strcmp(readback.cks_hex, "12345678"));
    }
    brix_xmeta_t record;
    assert(brix_xmeta_path_load(f->file, &record) == BRIX_XMETA_OK);
    if (record.nblocks) { record.bitmap[0] = 0; }
    assert(brix_xmeta_path_save(f->file, &record) == BRIX_XMETA_OK);
    brix_xmeta_free(&record);
    assert(brix_cache_meta_touch(&f->log, f->file, 20) == NGX_OK);
    assert(brix_cache_meta_read(&f->log, f->file, &readback) == NGX_OK);
    assert(readback.access_count == 4 && readback.bytes_served == 37);
    assert(readback.last_access > 1234);
    assert(brix_xmeta_path_load(f->file, &record) == BRIX_XMETA_OK);
    if (record.nblocks) { assert(record.bitmap[0] == 0); }
    brix_xmeta_free(&record);
}

static void
legacy_case(fixture_t *f)
{
    brix_xmeta_path_remove(f->file);
    char legacy[PATH_MAX];
    assert(brix_cache_meta_path(legacy, sizeof(legacy), f->file) == 0);
    if (!strcmp(f->mode, "legacy-corrupt")) { f->meta.etag_len = 255; }
    size_t length = !strcmp(f->mode, "legacy-short") ? 4 : BRIX_CACHE_META_BASE_SIZE;
    if (!strcmp(f->mode, "legacy-symlink")) { assert(symlink(f->file, legacy) == 0); }
    else { write_bytes(legacy, &f->meta, length); }
    brix_cache_meta_t readback;
    ngx_int_t rc = brix_cache_meta_read(&f->log, f->file, &readback);
    if (strcmp(f->mode, "legacy")) { assert(rc == NGX_DECLINED); return; }
    assert(rc == NGX_OK && readback.version == 0);
    assert(readback.size == 11 && readback.mtime == f->meta.mtime);
    assert(readback.etag_len == 10 && !memcmp(readback.etag, "origin-tag", 10));
}

static void
metadata_errors(fixture_t *f)
{
    brix_cache_meta_t meta;
    struct stat st = {.st_size = 1, .st_mtime = 2};
    char etag[128]; memset(etag, 'x', sizeof(etag) - 1); etag[127] = 0;
    assert(brix_cache_meta_from_stat(&st, etag, &meta) == NGX_OK);
    assert(meta.etag_len == BRIX_CACHE_META_ETAG_MAX);
    assert(brix_cache_meta_from_stat(NULL, NULL, &meta) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_meta_from_stat(&st, NULL, NULL) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_meta_read(&f->log, NULL, &meta) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_meta_read(&f->log, f->file, NULL) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_meta_write(&f->log, NULL, &meta) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_meta_write(&f->log, f->file, NULL) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_meta_touch(&f->log, NULL, 1) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_meta_write(&f->log, "/nonexistent-brix-cache-fixture/file", &meta) == NGX_ERROR);
    assert(brix_cache_meta_touch(&f->log, "/nonexistent-brix-cache-fixture/file", 1) == NGX_ERROR);
    brix_xmeta_path_remove(f->file);
    assert(brix_cache_meta_touch(&f->log, f->file, 1) == NGX_DECLINED);
    meta.size = UINT64_MAX;
    assert(brix_cache_meta_write(&f->log, f->file, &meta) == NGX_ERROR);
}

static void
access_case(fixture_t *f)
{
    struct stat before, after;
    struct timespec times[] = {{1, 0}, {2, 0}};
    assert(utimensat(AT_FDCWD, f->file, times, 0) == 0);
    assert(stat(f->file, &before) == 0);
    assert(brix_cache_record_access(f->file, 11, &f->log) == NGX_OK);
    assert(stat(f->file, &after) == 0 && after.st_atime > before.st_atime);
    assert(after.st_mtime == before.st_mtime);
    assert(brix_cache_record_access(NULL, 0, NULL) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_record_access("", 0, NULL) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_record_access("/nonexistent-brix-cache-fixture/file", 1, &f->log) == NGX_ERROR);
}

static void
path_mapping(void)
{
    const char *cases[][4] = {
        {"/cache", "/", "/leaf", "/cache/leaf"},
        {"/cache", "/", "/", "/cache"},
        {"/", "/export", "/export/leaf", "/leaf"},
        {"/cache", "/export", "/export", "/cache"},
    };
    char output[64];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert(brix_cache_path_for_resolved(cases[i][0], cases[i][1],
            cases[i][2], output, sizeof(output)) == NGX_OK);
        assert(!strcmp(output, cases[i][3]));
    }
    assert(brix_cache_path_for_resolved(NULL, "/", "/x", output, 64) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_path_for_resolved("", "/", "/x", output, 64) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_path_for_resolved("/cache", "/", "/x", NULL, 64) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_path_for_resolved("/cache", "/", "/x", output, 0) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_path_for_resolved("/cache", "/export", "/export-sibling/x", output, 64) == NGX_ERROR && errno == EINVAL);
    assert(brix_cache_path_for_resolved("/cache", "/export", "/export/leaf", output, 11) == NGX_ERROR && errno == ENAMETOOLONG);
}

static void
first_access(fixture_t *f)
{
    assert(brix_cache_meta_touch(&f->log, f->file, 23) == NGX_OK);
    brix_cache_meta_t meta;
    assert(brix_cache_meta_read(&f->log, f->file, &meta) == NGX_OK);
    assert(meta.access_count == 1 && meta.bytes_served == 23 && meta.last_access > 0);
}

int
main(int argc, char **argv)
{
    assert(argc == 3);
    fixture_t *f = calloc(1, sizeof(*f));
    assert(f != NULL); f->mode = argv[1];
    setup(f, argv[2], argv);
    if (!strcmp(f->mode, "metadata-errors")) { metadata_errors(f); }
    else if (!strncmp(f->mode, "metadata", 8)) { metadata_case(f); }
    else if (!strncmp(f->mode, "legacy", 6)) { legacy_case(f); }
    else if (!strcmp(f->mode, "access")) { access_case(f); }
    else if (!strcmp(f->mode, "path-map")) { path_mapping(); }
    else if (!strcmp(f->mode, "first-access")) { first_access(f); }
    else { open_case(f); }
    brix_cache_storage_cleanup(&f->conf);
    ngx_destroy_pool(f->cycle.pool); free(f);
    return 0;
}
