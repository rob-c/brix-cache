/* Copy/verify/delete ordering for flat and striped Ceph objects.
 * The real driver moves bytes and attributes over observed SDK boundaries. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/rados/sd_ceph_internal.h"
#include "native_alloc_fail.h"

#if BRIX_HAVE_CEPH && defined(BRIX_HAVE_RADOSSTRIPER)
typedef struct {
    const char *mode;
    int striped, destination_striped, source, destination, attributes;
    int probes, reads, writes, removed_source, removed_destination, iterator, ended;
    size_t size, destination_size;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle->conf_ctx; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }
static int is_source(const char *oid) {
    assert(!strcmp(oid, "prefix/source") || !strcmp(oid, "prefix/destination"));
    return !strcmp(oid, "prefix/source");
}

/* WHAT: Answer source/destination metadata independently of the copy loop.
 * WHY: Verification must detect an absent, truncated or unreadable destination.
 * HOW: Observe the selected storage layout and inject only the requested fault. */
static int stat_failure(int source) {
    fixture *f = state();
    if (source && mode("source-stat")) { return -EACCES; }
    if (!source && mode("destination-stat") && !f->writes) { return -EIO; }
    if (!source && mode("verify-stat") && f->writes) { return -EIO; }
    return 0;
}
static int stat_object(const char *oid, uint64_t *size, time_t *mtime, int striped) {
    fixture *f = state(); int source = is_source(oid); f->probes++;
    int rc = stat_failure(source); if (rc) { return rc; }
    if (striped != (source ? f->striped : f->destination_striped)) { return -ENOENT; }
    if (!(source ? f->source : f->destination)) { return -ENOENT; }
    if (!source && mode("verify-missing") && f->writes) { return -ENOENT; }
    *size = source ? f->size : f->destination_size; *mtime = 100;
    if (!source && mode("verify-size") && f->writes) { (*size)++; }
    return 0;
}
int __wrap_rados_stat(rados_ioctx_t io, const char *oid, uint64_t *size, time_t *mtime) {
    assert(io == state()); return stat_object(oid, size, mtime, 0);
}
int __wrap_sd_ceph_striper_stat(rados_striper_t s, const char *oid, uint64_t *size, time_t *mtime) {
    assert(s == state()); return stat_object(oid, size, mtime, 1);
}
int __wrap_sd_ceph_striper_create(rados_ioctx_t io, const sd_ceph_striper_layout_t *layout,
    rados_striper_t *out) {
    assert(io == state() && layout == NULL); *out = state(); return 0;
}

/* WHAT: Supply deterministic bytes, including short reads or a shrinking source.
 * WHY: Rename must copy the advertised extent exactly before removing source.
 * HOW: Generate an offset-dependent pattern at the actual SDK read boundary. */
static ssize_t read_object(const char *oid, void *buffer, size_t size, uint64_t offset) {
    fixture *f = state(); assert(is_source(oid)); f->reads++;
    if (mode("read-error")) { return -EACCES; }
    if (mode("shrink")) { return 0; }
    assert(offset < f->size); size = ngx_min(size, f->size - offset);
    if (mode("short-read")) { size = ngx_min(size, 3); }
    for (size_t i = 0; i < size; i++) { ((unsigned char *) buffer)[i] = (unsigned char) ((offset+i) % 251); }
    return (ssize_t) size;
}
int __wrap_rados_read(rados_ioctx_t io, const char *oid, char *buffer, size_t size, uint64_t offset) {
    assert(io == state()); return (int) read_object(oid, buffer, size, offset);
}
ssize_t __wrap_sd_ceph_striper_read(rados_striper_t s, const char *oid, void *buffer, size_t size, uint64_t offset) {
    assert(s == state()); return read_object(oid, buffer, size, offset);
}

/* WHAT: Validate each copied extent and remember the resulting remote size.
 * WHY: A byte-count-only oracle would miss wrong offsets or corrupted payloads.
 * HOW: Check every byte, require contiguous writes, then publish metadata. */
static int write_object(const char *oid, const void *buffer, size_t size, uint64_t offset, int striped) {
    fixture *f = state(); assert(!is_source(oid)); f->writes++;
    if (mode("write-error")) { return -ENOSPC; }
    assert(offset == f->destination_size);
    for (size_t i = 0; i < size; i++) { assert(((const unsigned char *) buffer)[i] == (offset+i) % 251); }
    f->destination = 1; f->destination_size += size; f->destination_striped = striped; return 0;
}
int __wrap_rados_write(rados_ioctx_t io, const char *oid, const char *buffer, size_t size, uint64_t offset) {
    assert(io == state()); return write_object(oid, buffer, size, offset, 0);
}
int __wrap_rados_write_full(rados_ioctx_t io, const char *oid, const char *buffer, size_t size) {
    assert(io == state() && size == 0); return write_object(oid, buffer, size, 0, 0);
}
ssize_t __wrap_sd_ceph_striper_write(rados_striper_t s, const char *oid, const void *buffer, size_t size, uint64_t offset) {
    assert(s == state()); int rc = write_object(oid, buffer, size, offset, 1);
    return rc < 0 ? rc : (ssize_t) size;
}

/* WHAT: Observe source deletion and best-effort destination cleanup separately.
 * WHY: A failed copy may discard its partial destination but must retain source.
 * HOW: Inject removal errors and reject source removal before full publication. */
static int remove_object(const char *oid) {
    fixture *f = state();
    if (is_source(oid)) {
        f->removed_source++;
        assert(f->destination && f->destination_size == f->size && f->attributes == 1);
        if (mode("source-remove")) { return -EACCES; }
        f->source = 0; return 0;
    }
    f->removed_destination++;
    if (mode("destination-remove") || mode("cleanup-error")) { return -EACCES; }
    f->destination = 0; f->destination_size = 0; f->attributes = 0; return 0;
}
int __wrap_rados_remove(rados_ioctx_t io, const char *oid) { assert(io == state()); return remove_object(oid); }
int __wrap_sd_ceph_striper_remove(rados_striper_t s, const char *oid) { assert(s == state()); return remove_object(oid); }

/* WHAT: Supply and validate one user attribute plus a striper-private attribute.
 * WHY: User metadata must survive, while striper layout metadata must not copy.
 * HOW: Use the two SDK attribute surfaces and count iterator cleanup exactly. */
int __wrap_rados_getxattrs(rados_ioctx_t io, const char *oid, rados_xattrs_iter_t *it) {
    assert(io == state() && is_source(oid));
    if (mode("attrs-open")) { return -EACCES; }
    *it = state(); return 0;
}
int __wrap_rados_getxattrs_next(rados_xattrs_iter_t it, const char **name, const char **value, size_t *length) {
    fixture *f = state(); assert(it == f);
    if (mode("attrs-next")) { return -EIO; }
    *name = f->iterator++ ? NULL : "user.value"; *value = "tag"; *length = 3; return 0;
}
void __wrap_rados_getxattrs_end(rados_xattrs_iter_t it) { assert(it == state()); state()->ended++; }
static int set_attribute(const char *oid, const char *name, const void *value, size_t length) {
    assert(!is_source(oid) && !strcmp(name, "user.value"));
    assert(length == 3 && !memcmp(value, "tag", 3));
    if (mode("attrs-set") || mode("cleanup-error")) { return -EIO; }
    state()->attributes++; return 0;
}
int __wrap_rados_setxattr(rados_ioctx_t io, const char *oid, const char *name, const char *value, size_t length) {
    assert(io == state()); return set_attribute(oid, name, value, length);
}
int __wrap_sd_ceph_striper_setxattr(rados_striper_t s, const char *oid, const char *name, const void *value, size_t length) {
    assert(s == state()); return set_attribute(oid, name, value, length);
}
ssize_t __wrap_sd_ceph_striper_listxattr(rados_striper_t s, const char *oid, char *buffer, size_t capacity) {
    const char names[] = "striper.layout\0user.value\0";
    assert(s == state() && is_source(oid) && capacity >= sizeof(names)-1);
    if (mode("attrs-open")) { return -EACCES; }
    memcpy(buffer, names, sizeof(names)-1); return sizeof(names)-1;
}
ssize_t __wrap_sd_ceph_striper_getxattr(rados_striper_t s, const char *oid, const char *name, void *buffer, size_t capacity) {
    assert(s == state() && is_source(oid) && !strcmp(name, "user.value") && capacity >= 3);
    if (mode("attrs-next")) { return -EIO; }
    memcpy(buffer, "tag", 3); return 3;
}

int __wrap_rados_nobjects_list_open(rados_ioctx_t io, rados_list_ctx_t *it) {
    assert(io == state()); *it = state(); return 0;
}
int __wrap_rados_nobjects_list_next(rados_list_ctx_t it, const char **entry, const char **key, const char **ns) {
    assert(it == state()); (void) key; (void) ns;
    if (!mode("directory") || state()->iterator++) { return -ENOENT; }
    *entry = "prefix/source/child"; return 0;
}
void __wrap_rados_nobjects_list_close(rados_list_ctx_t it) { assert(it == state()); }

/* WHAT: Invoke the real rename and emit an externally checkable state snapshot.
 * WHY: Success, failure and hostile-path cases share the identical driver path.
 * HOW: Configure caller-owned objects, arm one fault, invoke, check ownership. */
int main(int argc, char **argv) {
    assert(argc == 6);
    fixture f = {.mode = argv[1], .striped = atoi(argv[2]), .size = strtoull(argv[3], NULL, 10), .source = 1};
    ngx_log_t log = {0}; ngx_cycle_t cycle = {.log = &log, .conf_ctx = (void ****) &f};
    ngx_cycle = &cycle; ngx_time_init();
    if (mode("missing") || mode("directory")) { f.source = 0; }
    if (mode("replace") || mode("exclusive") || mode("destination-remove")) {
        f.destination = 1; f.destination_size = 99;
    }
    sd_ceph_state_t driver = {.ioctx = &f, .key_prefix = "prefix"};
    brix_sd_instance_t inst = {.state = &driver, .driver = &brix_sd_ceph_driver};
    const char *src = mode("unsafe-source") ? "/../escape" : "/source";
    const char *dst = mode("unsafe-destination") ? "/../escape" : "/destination";
    if (mode("same")) { dst = src; }
    if (!strncmp(f.mode, "allocation", 10)) { native_alloc_arm("malloc", (unsigned) atoi(f.mode+10)); }
    errno = 0;
    int rc = (int) sd_ceph_rename(&inst, src, dst, mode("exclusive"));
    int saved = errno; native_alloc_disarm();
    int expected = atoi(argv[4]); assert(rc == (expected ? -1 : 0));
    if (expected) { assert(saved == expected); }
    assert(f.source == atoi(argv[5]));
    printf("rc=%d source=%d destination=%d size=%zu attrs=%d probes=%d reads=%d writes=%d source_removes=%d destination_removes=%d ended=%d\n",
        rc, f.source, f.destination, f.destination_size, f.attributes, f.probes, f.reads, f.writes,
        f.removed_source, f.removed_destination, f.ended);
    return 0;
}
#else
int main(void) { return 77; }
#endif
