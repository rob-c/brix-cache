/* Real archive writer/index/extractor with finite durability-boundary failures. */
#include "fs/backend/frm/sd_frm_arc_internal.h"
#include "native_alloc_fail.h"
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode, *base;
    unsigned migrations, purges, syncs, renames;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return state() && !strcmp(state()->mode, name); }
int __real_fsync(int);
int __wrap_fsync(int fd)
{
    state()->syncs++;
    if ((mode("archive-sync") && state()->syncs == 1) || (mode("index-sync") && state()->syncs == 2)) {
        errno = EIO; return -1;
    }
    return __real_fsync(fd);
}
int __real_rename(const char *, const char *);
int __wrap_rename(const char *from, const char *to)
{
    state()->renames++;
    if ((mode("archive-rename") && state()->renames == 1) || (mode("index-rename") && state()->renames == 2)) {
        errno = EACCES; return -1;
    }
    return __real_rename(from, to);
}
static int migrate(void *opaque, const char *key)
{
    fixture *f = opaque; f->migrations++;
    if ((mode("migrate-archive") && strstr(key, BRIX_ARC_SUFFIX)) ||
        (mode("migrate-marker") && strstr(key, BRIX_ARC_MARKER))) { errno = EIO; return -1; }
    return 0;
}
static int create(void *opaque, const char *key, mode_t permissions)
{
    fixture *f = opaque; char path[PATH_MAX];
    if (mode("create")) { errno = ENOSPC; return -1; }
    assert(frm_online_path(f->base, key, path, sizeof(path)) == 0);
    frm_mkparents(path); return open(path, O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW, permissions);
}
static int purge(void *opaque, const char *key)
{
    fixture *f = opaque; char path[PATH_MAX]; f->purges++;
    assert(frm_online_path(f->base, key, path, sizeof(path)) == 0); return unlink(path);
}
static int residency(void *opaque, const char *key, off_t *size, time_t *mtime)
{ (void) opaque; (void) key; (void) size; (void) mtime; return BRIX_RESIDENCY_ABSENT; }
static int opened(void *opaque, const char *key)
{ (void) opaque; (void) key; errno = ENOENT; return -1; }
static int recall(void *opaque, const char *key)
{ (void) opaque; (void) key; return 0; }
static void destroy(void *opaque) { (void) opaque; }

int main(int argc, char **argv)
{
    assert(argc == 5); fixture f = {0}; f.mode = argv[2]; f.base = argv[3]; ngx_cycle = &f.cycle;
    brix_mss_adapter_t inner = {.migrate = migrate, .create_online = create, .purge = purge,
        .residency = residency, .open_online = opened, .recall_begin = recall,
        .recall_poll = recall, .destroy = destroy};
    arc_ctx_t *ctx = brix_mss_arc_create(&inner, &f, f.base, 1, NULL); assert(ctx);
    arc_key_t key;
    arc_classify(ctx, argv[4], &key);
    if (mode("realloc")) { native_alloc_arm("realloc", 0); }
    if (mode("strdup")) { native_alloc_arm("strdup", 0); }
    if (mode("calloc")) { native_alloc_arm("calloc", 0); }
    int rc = !strcmp(argv[1], "compose") ? arc_compose(ctx, &key) : arc_extract(ctx, &key);
    int saved = errno; native_alloc_disarm();
    printf("rc=%d\nerrno=%d\nmigrations=%u\npurges=%u\n", rc, saved, f.migrations, f.purges);
    brix_mss_arc_adapter.destroy(ctx); ngx_cycle = NULL; return 0;
}
