/* Metadata carrier decisions over the real encoder and an observed driver boundary. */
#include "fs/meta/xmeta_carrier.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ngx_cycle_t cycle;
    brix_sd_staged_t staged;
    const char *mode;
    int error, armed, opened, aborted, committed, removed, closed, attrs;
    uint8_t *encoded, *published;
    size_t length;
} fixture;

static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }

void *__real_malloc(size_t);
void *__real_realloc(void *, size_t);
/* WHAT: Refuse carrier buffer ownership. WHY: Failed reads must free all state.
 * HOW: Select only the carrier's 64 KiB allocation after encoding has finished. */
void *__wrap_malloc(size_t size)
{
    return state() && state()->armed && mode("malloc") && size == BRIX_XMETA_XATTR_MAX
           ? NULL : __real_malloc(size);
}
void *__wrap_realloc(void *old, size_t size)
{
    return state() && state()->armed && mode("realloc") ? NULL : __real_realloc(old, size);
}

/* WHAT: Check reserved xattr publication. WHY: Arbitrary driver errors cannot
 * silently select another carrier. HOW: Compare every byte to the real codec. */
static ngx_int_t set_attr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *bytes, size_t length, int flags)
{
    fixture *f = inst->state; f->attrs++;
    assert(!strcmp(path, "object") && !strcmp(name, BRIX_XMETA_XATTR_NAME) && !flags);
    assert(length == f->length && !memcmp(bytes, f->encoded, length));
    if (f->error) { errno = f->error; return NGX_ERROR; }
    return NGX_OK;
}

static ssize_t get_attr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *bytes, size_t capacity)
{
    fixture *f = inst->state; f->attrs++;
    assert(!strcmp(path, "object") && !strcmp(name, BRIX_XMETA_XATTR_NAME));
    if (f->error) { errno = f->error; return -1; }
    assert(f->length <= capacity); memcpy(bytes, f->encoded, f->length);
    return (ssize_t) f->length;
}

static ngx_int_t remove_attr(brix_sd_instance_t *inst, const char *path, const char *name)
{
    (void) path; assert(!strcmp(name, BRIX_XMETA_XATTR_NAME));
    ((fixture *) inst->state)->removed++; return NGX_OK;
}

/* WHAT: Observe staged sidecar lifetime. WHY: Publication must be private and atomic.
 * HOW: Enforce 0600, exact size and explicit abort on write/commit failures. */
static brix_sd_staged_t *stage_open(brix_sd_instance_t *inst, const char *path,
    mode_t permissions, off_t length, int *error)
{
    fixture *f = inst->state; f->opened++;
    assert(!strcmp(path, "object.cinfo") && permissions == 0600 && length == (off_t) f->length);
    if (mode("open")) { *error = f->error; return NULL; }
    f->staged.inst = inst; f->staged.state = f; return &f->staged;
}

static ssize_t stage_write(brix_sd_staged_t *st, const void *bytes, size_t length, off_t offset)
{
    fixture *f = st->state; assert(!offset && length == f->length);
    assert(!memcmp(bytes, f->encoded, length));
    if (mode("write")) { errno = f->error; return -1; }
    f->published = malloc(length); assert(f->published); memcpy(f->published, bytes, length);
    return (ssize_t) length;
}

static ngx_int_t stage_commit(brix_sd_staged_t *st, brix_sd_precond_t *pre)
{
    fixture *f = st->state; assert(pre == NULL);
    if (mode("commit")) { errno = f->error; return NGX_ERROR; }
    f->committed++; return NGX_OK;
}

static void stage_abort(brix_sd_staged_t *st) { ((fixture *) st->state)->aborted++; }

/* WHAT: Supply a heap-owned sidecar object. WHY: Error cleanup must close its shell.
 * HOW: Real carrier reads and frees it; the fixture only supplies finite bytes. */
static brix_sd_obj_t *read_open(brix_sd_instance_t *inst, const char *path,
    int flags, mode_t permissions, int *error)
{
    fixture *f = inst->state; f->opened++;
    assert(!strcmp(path, "object.cinfo") && flags == BRIX_SD_O_READ && !permissions);
    if (mode("open")) { *error = f->error; errno = f->error; return NULL; }
    brix_sd_obj_t *obj = calloc(1, sizeof(*obj)); assert(obj);
    obj->state = f; obj->inst = inst; obj->heap_shell = 1; return obj;
}

static ssize_t read_bytes(brix_sd_obj_t *obj, void *bytes, size_t capacity, off_t offset)
{
    fixture *f = obj->state;
    if (mode("read")) { errno = f->error; return -1; }
    if (mode("empty") || (size_t) offset == f->length) { return 0; }
    size_t count = f->length - (size_t) offset;
    if (count > capacity) { count = capacity; }
    if (mode("partial") && count > 7) { count = 7; }
    memcpy(bytes, f->encoded + offset, count); return (ssize_t) count;
}

static ngx_int_t close_object(brix_sd_obj_t *obj)
{
    ((fixture *) obj->state)->closed++; errno = ECANCELED; return NGX_OK;
}

/* WHAT: Remove selected optional slots. WHY: Missing backend capabilities must
 * fail explicitly. HOW: Keep the rest of the driver boundary unchanged. */
static void configure(brix_sd_driver_t *driver, const char *carrier)
{
    if (strcmp(carrier, "xattr")) { driver->setxattr = NULL; driver->getxattr = NULL; }
    if (mode("no-open")) { driver->open = NULL; driver->staged_open = NULL; }
    if (mode("no-read")) { driver->pread = NULL; }
    if (mode("no-write")) { driver->staged_write = NULL; }
    if (mode("no-commit")) { driver->staged_commit = NULL; }
}

/* WHAT: Check a complete carrier operation and its ownership counters.
 * WHY: The neutral API must preserve errno, metadata and one published carrier.
 * HOW: Compare against a genuine encoded record and explicit expected outcomes. */
int main(int argc, char **argv)
{
    assert(argc == 7); fixture f = {0}; ngx_cycle = &f.cycle;
    f.mode = argv[3]; f.error = atoi(argv[4]);
    brix_xmeta_t input = {0}, output = {0}; assert(brix_xmeta_init(&input, 8193, 4096) == 0);
    assert(brix_xmeta_encode(&input, &f.encoded, &f.length) == 0);
    brix_sd_driver_t driver = {.setxattr = set_attr, .getxattr = get_attr,
        .removexattr = remove_attr, .staged_open = stage_open, .staged_write = stage_write,
        .staged_commit = stage_commit, .staged_abort = stage_abort,
        .open = read_open, .pread = read_bytes, .close = close_object};
    configure(&driver, argv[2]); brix_sd_instance_t store = {.driver = &driver, .state = &f};
    char longkey[PATH_MAX + 1]; memset(longkey, 'x', PATH_MAX); longkey[PATH_MAX] = 0;
    const char *key = mode("long-key") ? longkey : "object";
    brix_sd_instance_t *selected = mode("null-store") ? NULL : &store;
    f.armed = 1; errno = 0;
    int writing = !strcmp(argv[1], "save");
    ngx_int_t rc = writing ? brix_xmeta_save(selected, key, &input)
                          : brix_xmeta_load(selected, key, &output);
    int error = errno; f.armed = 0;
    assert(rc == atoi(argv[5]));
    if (rc == NGX_ERROR) { assert(error == atoi(argv[6])); }
    if (rc == NGX_OK && !writing) {
        assert(output.file_size == input.file_size && output.buffer_size == input.buffer_size);
        assert(output.nblocks == input.nblocks);
    }
    if (writing && rc == NGX_OK && f.opened) { assert(f.committed == 1 && f.removed == 1); }
    if (writing && (mode("write") || mode("commit"))) { assert(f.aborted == 1 && !f.committed && !f.removed); }
    if (!writing && f.opened && !mode("open")) { assert(f.closed == 1); }
    free(f.encoded); free(f.published); brix_xmeta_free(&input); brix_xmeta_free(&output);
    ngx_cycle = NULL; return 0;
}
