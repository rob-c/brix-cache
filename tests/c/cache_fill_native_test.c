/* Cache fills use real POSIX source, staged sink, digest and metadata code. */
#include "fs/cache/cache_internal.h"
#include "fs/cache/cache_storage.h"
#include "fs/cache/verify.h"
#include "fs/cache/meta.h"
#include "fs/backend/sd_registry.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_stream_brix_srv_conf_t conf;
    brix_sd_driver_t source_ops, sink_ops;
    brix_sd_instance_t *storage;
    const char *mode, *digest;
    unsigned opens, closes, stages, aborts, commits;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return state() && !strcmp(state()->mode, name); }
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size)
{
    if (mode("buffer") && size == BRIX_CACHE_FETCH_CHUNK) { errno = ENOMEM; return NULL; }
    return __real_malloc(size);
}

/* WHAT: Inject named source failures at the driver boundary.
 * WHY: Every failure after opening must close the source once.
 * HOW: Delegate normal operations to the actual POSIX driver. */
static brix_sd_obj_t *source_open(brix_sd_instance_t *inst, const char *key,
    int flags, mode_t permissions, int *error)
{
    if (mode("source-open")) { *error = EACCES; return NULL; }
    brix_sd_obj_t *obj = brix_sd_posix_driver.open(inst, key, flags, permissions, error);
    if (obj) { state()->opens++; obj->driver = &state()->source_ops; }
    return obj;
}
static ssize_t source_read(brix_sd_obj_t *obj, void *bytes, size_t len, off_t off)
{
    if (mode("source-read")) { errno = EIO; return -1; }
    return brix_sd_posix_driver.pread(obj, bytes, len, off);
}
static ngx_int_t source_close(brix_sd_obj_t *obj)
{ state()->closes++; return brix_sd_posix_driver.close(obj); }
static ngx_int_t source_stat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    if (mode("source-stat")) { errno = EIO; return NGX_ERROR; }
    return brix_sd_posix_driver.fstat(obj, out);
}
static ngx_int_t source_digest(brix_sd_obj_t *obj, const char *algo, char *out, size_t capacity)
{
    assert(obj && !strcmp(algo, "sha256") && capacity > strlen(state()->digest));
    strcpy(out, state()->digest); return NGX_OK;
}

/* WHAT: Observe the real staged-write lifecycle and inject finite storage errors.
 * WHY: Failed fills must abort their private staging file instead of publishing it.
 * HOW: Count ownership transfers and delegate every successful operation. */
static brix_sd_staged_t *stage_open(brix_sd_instance_t *inst, const char *key,
    mode_t permissions, off_t size, int *error)
{
    assert(permissions == 0600);
    if (mode("stage-open")) { *error = ENOSPC; return NULL; }
    brix_sd_staged_t *stage = brix_sd_posix_driver.staged_open(inst, key, permissions, size, error);
    if (stage) { state()->stages++; }
    return stage;
}
static ssize_t stage_write(brix_sd_staged_t *stage, const void *bytes, size_t len, off_t off)
{
    if (mode("stage-write")) { errno = ENOSPC; return -1; }
    return brix_sd_posix_driver.staged_write(stage, bytes, len, off);
}
static ngx_int_t stage_commit(brix_sd_staged_t *stage, brix_sd_precond_t *pre)
{
    if (mode("commit")) { errno = EIO; return NGX_ERROR; }
    ngx_int_t rc = brix_sd_posix_driver.staged_commit(stage, pre);
    if (rc == NGX_OK) { state()->commits++; }
    return rc;
}
static void stage_abort(brix_sd_staged_t *stage)
{ state()->aborts++; brix_sd_posix_driver.staged_abort(stage); }
static ngx_int_t sink_stat(brix_sd_instance_t *inst, const char *key, brix_sd_stat_t *out)
{
    if (mode("commit-stat")) { errno = EIO; return NGX_ERROR; }
    return brix_sd_posix_driver.stat(inst, key, out);
}

/* WHAT: Build actual configured storage instances in private directories.
 * WHY: This verifies staged publication, file permissions and sidecar integrity.
 * HOW: Attach fault-observing copies of the production vtables to two instances. */
static brix_sd_instance_t *setup(fixture *f, char **argv)
{
    f->cycle.log = &f->log; ngx_cycle = &f->cycle; ngx_os_argv = argv;
    ngx_time_init(); assert(ngx_os_init(&f->log) == NGX_OK);
    f->cycle.pool = ngx_create_pool(16384, &f->log); assert(f->cycle.pool);
    f->conf.cache_root = (ngx_str_t) {.data = (u_char *) argv[2], .len = strlen(argv[2])};
    snprintf(f->conf.common.root_canon, sizeof(f->conf.common.root_canon), "%s", argv[1]);
    assert(brix_cache_storage_init(&f->conf, &f->cycle) == NGX_OK);
    brix_sd_instance_t *sink = brix_cache_storage(&f->conf); assert(sink); f->storage = sink;
    f->sink_ops = *sink->driver; sink->driver = &f->sink_ops;
    f->sink_ops.staged_open = stage_open; f->sink_ops.staged_write = stage_write;
    f->sink_ops.staged_commit = stage_commit; f->sink_ops.staged_abort = stage_abort;
    f->sink_ops.stat = sink_stat;
    int error = 0;
    brix_sd_instance_t *source = brix_sd_instance_create(&f->log, "posix", argv[1], &error);
    assert(source); f->source_ops = *source->driver; source->driver = &f->source_ops;
    f->source_ops.open = source_open; f->source_ops.pread = source_read;
    f->source_ops.close = source_close; f->source_ops.query_checksum = source_digest;
    f->source_ops.fstat = source_stat;
    return source;
}

int main(int argc, char **argv)
{
    assert(argc == 6); fixture f = {0}; f.mode = argv[3]; f.digest = argv[4];
    brix_sd_instance_t *source = setup(&f, argv);
    brix_cache_fill_t task = {.conf = &f.conf, .source_inst = source};
    strcpy(task.clean_path, "/file");
    assert(snprintf(task.cache_path, sizeof(task.cache_path), "%s/file", argv[2])
           < (int) sizeof(task.cache_path));
    if (mode("no-source")) { task.source_inst = NULL; }
    if (mode("no-storage")) { f.conf.cache_storage_inst = NULL; }
    if (mode("no-root")) { f.conf.cache_root.len = 0; }
    if (mode("wrong-root")) { strcpy(task.cache_path, "/elsewhere/file"); }
    if (mode("admission")) { f.conf.cache_max_file_size = 1; }
    f.conf.common.cache_verify_mode = atoi(argv[5]) ? BRIX_CACHE_VERIFY_BESTEFFORT : BRIX_CACHE_VERIFY_OFF;
    ngx_str_set(&f.conf.common.cache_verify_digest, "sha256");
    int rc = brix_cache_fetch_origin(&task);
    printf("rc=%d\nerror=%d\nsize=%llu\nopens=%u\ncloses=%u\nstages=%u\naborts=%u\ncommits=%u\n",
        rc, task.xrd_error, (unsigned long long) task.file_size,
        f.opens, f.closes, f.stages, f.aborts, f.commits);
    assert(f.opens == f.closes && f.stages == f.aborts + f.commits);
    if (!rc) {
        brix_cache_meta_t meta;
        assert(brix_cache_meta_read(&f.log, task.cache_path, &meta) == NGX_OK);
        assert(task.file_size >= 0 && meta.size == (uint64_t) task.file_size);
        if (atoi(argv[5])) { assert(!strcmp(meta.cks_alg, "sha256") && !strcmp(meta.cks_hex, f.digest)); }
    }
    brix_sd_instance_destroy(source); f.conf.cache_storage_inst = f.storage;
    brix_cache_storage_cleanup(&f.conf);
    ngx_destroy_pool(f.cycle.pool); ngx_cycle = NULL; return 0;
}
