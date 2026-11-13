/* Verify the production Ceph striper adapter against the installed SDK ABI. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/rados/sd_ceph_striper.h"
#include <assert.h>

#if defined(BRIX_HAVE_RADOSSTRIPER)
typedef struct {
    int error, calls, ended, next, empty, layouts;
} fixture;

/* WHAT: Recover observer state. WHY: No production hook. HOW: Test cycle slot. */
static fixture *state(void) { return (fixture *) ngx_cycle->conf_ctx; }

/* WHAT: Validate SDK routing. WHY: Prevent wrong object/handle use. HOW: Identity. */
static int observe(rados_striper_t handle, const char *object)
{
    assert(handle == state() && strcmp(object, "fixture/object") == 0);
    state()->calls++;
    return -state()->error;
}

/* WHAT: Create an observed SDK handle. WHY: Check error ownership. HOW: Sentinel. */
int __wrap_rados_striper_create(rados_ioctx_t io, rados_striper_t *out)
{
    assert(io == state()); state()->calls++;
    if (state()->error) { return -state()->error; }
    *out = state(); return 0;
}

/* WHAT: Observe destruction. WHY: Require exactly one release. HOW: Counter. */
void __wrap_rados_striper_destroy(rados_striper_t handle)
{
    assert(handle == state()); state()->ended++;
}

/* WHAT: Check stripe unit. WHY: Preserve configured layout. HOW: Exact value. */
int __wrap_rados_striper_set_object_layout_stripe_unit(rados_striper_t s, unsigned n)
{
    assert(s == state() && n == 65536); state()->layouts |= 1; return 0;
}

/* WHAT: Check stripe count. WHY: Preserve configured layout. HOW: Exact value. */
int __wrap_rados_striper_set_object_layout_stripe_count(rados_striper_t s, unsigned n)
{
    assert(s == state() && n == 4); state()->layouts |= 2; return 0;
}

/* WHAT: Check object size. WHY: Preserve configured layout. HOW: Exact value. */
int __wrap_rados_striper_set_object_layout_object_size(rados_striper_t s, unsigned n)
{
    assert(s == state() && n == 4194304); state()->layouts |= 4; return 0;
}

/* WHAT: Return SDK read counts. WHY: Partial reads differ from writes. HOW: Bytes. */
int __wrap_rados_striper_read(rados_striper_t s, const char *oid, char *buf, size_t n, uint64_t off)
{
    int rc = observe(s, oid); assert(n == 8 && off == 123);
    if (rc < 0) { return rc; }
    memcpy(buf, "data", 4); return 4;
}

/* WHAT: Return zero on SDK write success. WHY: Adapter must return bytes. HOW: ABI. */
int __wrap_rados_striper_write(rados_striper_t s, const char *oid, const char *buf, size_t n, uint64_t off)
{
    assert(n == 4 && off == 123 && memcmp(buf, "data", 4) == 0);
    return observe(s, oid);
}

/* WHAT: Validate truncation. WHY: Preserve a 64-bit extent. HOW: Large argument. */
int __wrap_rados_striper_trunc(rados_striper_t s, const char *oid, uint64_t size)
{
    assert(size == 1ULL << 40); return observe(s, oid);
}

/* WHAT: Observe removal. WHY: Preserve SDK errno. HOW: Common observer. */
int __wrap_rados_striper_remove(rados_striper_t s, const char *oid)
{
    return observe(s, oid);
}

/* WHAT: Supply metadata. WHY: Errors must not publish stale outputs. HOW: Sentinels. */
int __wrap_rados_striper_stat(rados_striper_t s, const char *oid, uint64_t *size, time_t *mtime)
{
    int rc = observe(s, oid); *size = 1ULL << 40; *mtime = 123456; return rc;
}

/* WHAT: Return an attribute. WHY: Keep binary values intact. HOW: Embedded NUL. */
int __wrap_rados_striper_getxattr(rados_striper_t s, const char *oid, const char *name, char *buf, size_t cap)
{
    int rc = observe(s, oid); assert(strcmp(name, "user.test") == 0 && cap == 8);
    if (rc < 0) { return rc; }
    memcpy(buf, "a\0b", 3); return 3;
}

/* WHAT: Check attribute bytes. WHY: Never truncate at NUL. HOW: Explicit length. */
int __wrap_rados_striper_setxattr(rados_striper_t s, const char *oid, const char *name, const char *buf, size_t n)
{
    assert(strcmp(name, "user.test") == 0 && n == 3 && memcmp(buf, "a\0b", 3) == 0);
    return observe(s, oid);
}

/* WHAT: Observe attribute deletion. WHY: Preserve name/error. HOW: Exact match. */
int __wrap_rados_striper_rmxattr(rados_striper_t s, const char *oid, const char *name)
{
    assert(strcmp(name, "user.test") == 0); return observe(s, oid);
}

/* WHAT: Start attribute enumeration. WHY: Failed opens own no iterator. HOW: Gate. */
int __wrap_rados_striper_getxattrs(rados_striper_t s, const char *oid, rados_xattrs_iter_t *iter)
{
    int rc = observe(s, oid);
    if (rc < 0) { return rc; }
    *iter = state(); return 0;
}

/* WHAT: Enumerate names. WHY: Check terminators and midstream errors. HOW: Sequence. */
int __wrap_rados_striper_getxattrs_next(rados_xattrs_iter_t iter, const char **name,
    const char **value, size_t *length)
{
    fixture *f = state(); assert(iter == f); f->next++;
    if (f->empty == 3) { return -EIO; }
    *value = "value"; *length = 5;
    if (f->empty == 1 || f->next > 2) { *name = NULL; return 0; }
    if (f->empty == 2) { *name = ""; return 0; }
    *name = f->next == 1 ? "user.one" : "user.two";
    return 0;
}

/* WHAT: Observe iterator release. WHY: Check every success/error exit. HOW: Count. */
void __wrap_rados_striper_getxattrs_end(rados_xattrs_iter_t iter)
{
    assert(iter == state()); state()->ended++;
}

/* WHAT: Verify lifecycle/layout contracts. WHY: Null output must not call SDK.
 * HOW: Test individual fields and compare successful handle publication. */
static void lifecycle(int mask)
{
    fixture *f = state(); rados_striper_t out = NULL;
    sd_ceph_striper_layout_t layout = { mask & 1 ? 65536 : 0,
        mask & 2 ? 4 : 0, mask & 4 ? 4194304 : 0 };
    int rc = sd_ceph_striper_create(f, mask < 0 ? NULL : &layout, mask == 8 ? NULL : &out);
    if (mask == 8) { assert(rc == -EINVAL && f->calls == 0); return; }
    assert(rc == -f->error);
    if (rc < 0) { assert(out == NULL && !f->layouts); return; }
    assert(out == f && f->layouts == (mask < 0 ? 0 : mask));
    sd_ceph_striper_destroy(out); assert(f->ended == 1);
}

/* WHAT: Verify data-plane return conventions. WHY: SDK zero-write means success.
 * HOW: Read/write binary values and check stat output remains untouched on error. */
static void data_plane(int optional)
{
    fixture *f = state(); const char *oid = "fixture/object";
    char buf[8] = {0}; uint64_t size = 77; time_t mtime = 88;
    int rc = -f->error;
    assert(sd_ceph_striper_read(f, oid, buf, sizeof(buf), 123) == (rc ? rc : 4));
    assert(rc || memcmp(buf, "data", 4) == 0);
    assert(sd_ceph_striper_write(f, oid, "data", 4, 123) == (rc ? rc : 4));
    assert(sd_ceph_striper_trunc(f, oid, 1ULL << 40) == rc);
    assert(sd_ceph_striper_remove(f, oid) == rc);
    assert(sd_ceph_striper_stat(f, oid, optional & 1 ? NULL : &size,
        optional & 2 ? NULL : &mtime) == rc);
    assert(size == (rc || optional & 1 ? 77 : 1ULL << 40));
    assert(mtime == (rc || optional & 2 ? 88 : 123456));
    assert(sd_ceph_striper_getxattr(f, oid, "user.test", buf, 8) == (rc ? rc : 3));
    assert(rc || memcmp(buf, "a\0b", 3) == 0);
    assert(sd_ceph_striper_setxattr(f, oid, "user.test", "a\0b", 3) == rc);
    assert(sd_ceph_striper_rmxattr(f, oid, "user.test") == rc);
    assert(f->calls == 8);
}

/* WHAT: Verify bounded NUL-separated name output. WHY: No overwrite or leak.
 * HOW: Guard bytes surround the caller buffer and cleanup is counted. */
static void attributes(int capacity)
{
    fixture *f = state(); unsigned char buf[32]; ssize_t expected;
    memset(buf, 0xa5, sizeof(buf));
    expected = f->empty ? 0 : 18;
    if (capacity < expected) { expected = -ERANGE; }
    if (f->empty == 3) { expected = -EIO; }
    if (f->error) { expected = -f->error; }
    assert(sd_ceph_striper_listxattr(f, "fixture/object", (char *) buf + 1,
        (size_t) capacity) == expected);
    assert(buf[0] == 0xa5 && buf[1 + capacity] == 0xa5);
    assert(f->ended == (f->error ? 0 : 1));
    if (expected > 0) { assert(memcmp(buf + 1, "user.one\0user.two", 18) == 0); }
}

/* WHAT: Run a finite adapter contract. WHY: Expose assertions independently.
 * HOW: Stack-owned observer selected by the command line. */
int main(int argc, char **argv)
{
    fixture f = {0}; ngx_cycle_t cycle = {0};
    assert(argc == 5); cycle.conf_ctx = (void ****) &f; ngx_cycle = &cycle;
    f.error = atoi(argv[2]); f.empty = atoi(argv[4]);
    if (!strcmp(argv[1], "create")) { lifecycle(atoi(argv[3])); }
    else if (!strcmp(argv[1], "io")) { data_plane(atoi(argv[3])); }
    else { assert(!strcmp(argv[1], "attrs")); attributes(atoi(argv[3])); }
    printf("calls=%d ended=%d\n", f.calls, f.ended); return 0;
}
#else
int main(void) { return 77; }
#endif
