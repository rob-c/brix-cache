/* Client storage vtables over real private files, with one-shot resource failures. */
#include "fs/vfs.h"
#include "core/aio/uring.h"
#include "_brix_net_ext.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

const brix_vfs_backend *brix_vfs_posix_backend(void);
const brix_vfs_backend *brix_vfs_block_backend(void);

/* WHAT: Consume one failure. WHY: Cleanup must run under normal conditions.
 * HOW: Match an armed operation and clear its process-local flag immediately. */
static int fault(const char *name)
{
    const char *value = getenv("BRIX_CLIENT_VFS_FAULT");
    if (value == NULL || strcmp(value, name)) { return 0; }
    assert(unsetenv("BRIX_CLIENT_VFS_FAULT") == 0); errno = EIO; return 1;
}

/* WHAT: Arm an explicit syscall boundary. WHY: Failures must be reproducible.
 * HOW: Use process-local environment state without altering production globals. */
static void arm(const char *name)
{
    assert(setenv("BRIX_CLIENT_VFS_FAULT", name, 1) == 0);
}

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
char *__real_strdup(const char *);
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __real_pwrite(int, const void *, size_t, off_t);
int __real_fstat(int, struct stat *);
int __real_stat(const char *, struct stat *);
int __real_fsync(int);
int __real_ftruncate(int, off_t);
int __real_rename(const char *, const char *);
int __real_brix_uring_available(void);
brix_disk_ring *__real_brix_disk_ring_create(int, unsigned, size_t, int, brix_status *);
int __real_brix_disk_ring_pwrite(brix_disk_ring *, int64_t, const uint8_t *, size_t, brix_status *);
int __real_brix_disk_ring_flush(brix_disk_ring *, brix_status *);

/* WHAT: Refuse one allocation. WHY: Opening owns several independently fallible resources.
 * HOW: Interpose only the selected allocator, otherwise retaining real allocation. */
void *__wrap_malloc(size_t n) { return fault("malloc") ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t s) { return fault("calloc") ? NULL : __real_calloc(n, s); }
char *__wrap_strdup(const char *s) { return fault("strdup") ? NULL : __real_strdup(s); }

/* WHAT: Refuse one data or metadata syscall. WHY: VFS errors must propagate.
 * HOW: Return EIO before touching any bytes; unarmed operations stay real. */
ssize_t __wrap_pread(int fd, void *p, size_t n, off_t off) {
    return fault("pread") ? -1 : __real_pread(fd, p, n, off);
}
ssize_t __wrap_pwrite(int fd, const void *p, size_t n, off_t off) {
    return fault("pwrite") ? -1 : __real_pwrite(fd, p, n, off);
}
int __wrap_fstat(int fd, struct stat *s) { return fault("fstat") ? -1 : __real_fstat(fd, s); }
int __wrap_stat(const char *p, struct stat *s) { return fault("stat") ? -1 : __real_stat(p, s); }
int __wrap_fsync(int fd) { return fault("fsync") ? -1 : __real_fsync(fd); }
int __wrap_ftruncate(int fd, off_t n) {
    return fault("ftruncate") ? -1 : __real_ftruncate(fd, n);
}
int __wrap_rename(const char *a, const char *b) {
    return fault("rename") ? -1 : __real_rename(a, b);
}

/* WHAT: Exercise unavailable and failed ring startup independently.
 * WHY: AUTO falls back while ON must surface the original failure.
 * HOW: Otherwise invoke the actual configured kernel ring implementation. */
int __wrap_brix_uring_available(void) {
    return fault("unavailable") ? 0 : __real_brix_uring_available();
}
brix_disk_ring *__wrap_brix_disk_ring_create(int fd, unsigned depth, size_t size,
                                             int direct, brix_status *status)
{
    if (fault("create")) {
        brix_status_set(status, XRDC_EIO, EIO, "injected ring create"); return NULL;
    }
    return __real_brix_disk_ring_create(fd, depth, size, direct, status);
}

/* WHAT: Inject queued-write and drain failures. WHY: No failed queue may be committed.
 * HOW: Real rings remain caller-owned and are destroyed normally after the failure. */
int __wrap_brix_disk_ring_pwrite(brix_disk_ring *ring, int64_t off,
                                 const uint8_t *bytes, size_t n, brix_status *status)
{
    if (fault("ring-write")) {
        brix_status_set(status, XRDC_EIO, EIO, "injected ring write"); return -1;
    }
    return __real_brix_disk_ring_pwrite(ring, off, bytes, n, status);
}
int __wrap_brix_disk_ring_flush(brix_disk_ring *ring, brix_status *status)
{
    if (fault("flush")) {
        brix_status_set(status, XRDC_EIO, EIO, "injected ring flush"); return -1;
    }
    return __real_brix_disk_ring_flush(ring, status);
}

/* WHAT: Seed and verify private backing bytes. WHY: Error checks must include data integrity.
 * HOW: Use a real seven-byte file, always beneath the pytest-owned directory. */
static void seed(const char *path)
{
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    assert(fd >= 0 && write(fd, "original", 8) == 8); close(fd);
}
static void verify(const char *path, const char *bytes, size_t size)
{
    char buffer[16] = {0}; int fd = open(path, O_RDONLY); assert(fd >= 0);
    assert(read(fd, buffer, sizeof(buffer)) == (ssize_t)size);
    assert(!memcmp(buffer, bytes, size)); close(fd);
}

/* WHAT: Detect leaked staging names. WHY: Failed open must reclaim unpublished output.
 * HOW: Enumerate the isolated fixture directory after all handles are closed. */
static void no_stages(const char *directory)
{
    DIR *dir = opendir(directory); assert(dir); struct dirent *entry;
    while ((entry = readdir(dir))) { assert(strstr(entry->d_name, ".xrdvfs-tmp.") == NULL); }
    closedir(dir);
}

/* WHAT: Exercise read and write publication with actual ring or synchronous I/O.
 * WHY: Storage capabilities and final-file visibility are public contracts.
 * HOW: Assert bytes before/after commit or abort, then reopen through the same backend. */
static void roundtrip(const brix_vfs_backend *be, const char *path,
                      brix_vfs_open_opts *opts, const char *mode)
{
    brix_status st = {0}; brix_vfs_file *f = NULL; brix_vfs_stat info;
    int block = !strcmp(be->scheme, "block");
    assert(be->open(be, path, XRDC_VFS_WRITE | XRDC_VFS_FORCE, opts, &f, &st) == 0);
    assert(!!(brix_vfs_get_caps(f) & XRDC_VFS_CAP_ATOMIC_TEMP) == !block);
    assert(brix_vfs_pwrite(f, 0, "changed!", 8, &st) == 0);
    assert(brix_vfs_sync(f, &st) == 0);
    assert(brix_vfs_fstat(f, &info, &st) == 0 && info.size == 8 && info.exists);
    if (block) { assert(f->ops->truncate(f, 8, &st) == -1 && st.kxr == XRDC_EUSAGE); }
    else { assert(brix_vfs_truncate(f, 8, &st) == 0); verify(path, "original", 8); }
    int aborting = !strcmp(mode, "abort");
    if (aborting) { brix_vfs_abort(f); }
    else { assert(brix_vfs_commit(f, &st) == 0); }
    brix_vfs_close(f);
    const char *want = aborting && !block ? "original" : "changed!";
    verify(path, want, 8);
    assert(be->open(be, path, XRDC_VFS_READ, opts, &f, &st) == 0);
    char bytes[9] = {0}; assert(brix_vfs_pread(f, 0, bytes, sizeof(bytes), &st) == 8);
    assert(!memcmp(bytes, want, 8));
    if (!block) { assert(brix_vfs_commit(f, &st) == 0); }
    brix_vfs_abort(f); brix_vfs_close(f);
}

/* WHAT: Enforce read-only descriptors and filesystem metadata semantics.
 * WHY: Callers cannot mutate a read handle or mistake ENOENT for another error.
 * HOW: Invoke the public vtable and verify the backing object remains unchanged. */
static void read_only(const brix_vfs_backend *be, const char *path, brix_vfs_open_opts *opts)
{
    brix_vfs_file *f = NULL; brix_status st = {0}; brix_vfs_stat info;
    assert(be->open(be, path, XRDC_VFS_READ, opts, &f, &st) == 0);
    /* Async writes report descriptor errors when drained. */
    int rc = brix_vfs_pwrite(f, 0, "no", 2, &st);
    if (rc == 0) { assert(brix_vfs_sync(f, &st) == -1); }
    assert(brix_vfs_truncate(f, 1, &st) == -1);
    assert(brix_vfs_fstat(f, &info, &st) == 0 && info.size == 8);
    brix_vfs_abort(f); brix_vfs_close(f); verify(path, "original", 8);
}
static void metadata(const brix_vfs_backend *be, const char *path, const char *dir)
{
    brix_vfs_stat info = {0}; brix_status st = {0};
    assert(be->stat(be, path, &info, &st) == 0 && info.exists && info.size == 8);
    assert(be->stat(be, dir, &info, &st) == 0 && info.is_dir);
    assert(unlink(path) == 0);
    assert(be->stat(be, path, &info, &st) == 0 && !info.exists && info.size == 0);
}

/* WHAT: Exercise allocation, path and mandatory ring failures during open.
 * WHY: No failed open may publish a handle, change the final file or retain a temp.
 * HOW: Arm only after seed creation and require a failed result with NULL ownership. */
static void open_failure(const brix_vfs_backend *be, const char *path,
                         brix_vfs_open_opts *opts, const char *mode)
{
    brix_vfs_file *f = NULL; brix_status st = {0}; char selected[4096];
    snprintf(selected, sizeof(selected), "%s", path);
    int writing = strncmp(mode, "read-", 5) != 0;
    int flags = writing ? XRDC_VFS_WRITE | XRDC_VFS_FORCE : XRDC_VFS_READ;
    if (!strcmp(mode, "existing")) { flags = XRDC_VFS_WRITE; }
    else if (strstr(mode, "missing")) { snprintf(selected, sizeof(selected), "%s/no/file", path); }
    else if (strstr(mode, "symlink")) {
        snprintf(selected, sizeof(selected), "%s-link", path);
        assert(symlink(path, selected) == 0); flags |= XRDC_VFS_NOFOLLOW;
        /* File writers replace a symlink atomically; read-NOFOLLOW is the refusal contract. */
        if (!strcmp(be->scheme, "file")) { flags = XRDC_VFS_READ | XRDC_VFS_NOFOLLOW; }
    } else if (!strncmp(mode, "ring-", 5)) { opts->io_uring = XRDC_IO_URING_ON; arm(mode + 5); }
    else { arm(strchr(mode, '-') + 1); }
    assert(be->open(be, selected, flags, opts, &f, &st) == -1 && f == NULL);
    assert(st.msg[0]); assert(getenv("BRIX_CLIENT_VFS_FAULT") == NULL);
    verify(path, "original", 8);
}

/* WHAT: Run one armed operation on a valid live handle.
 * WHY: Failure propagation must preserve the public diagnostic and ownership.
 * HOW: Dispatch the selected I/O boundary and require the injected failure to fire. */
static void fail_operation(brix_vfs_file *f, const char *mode)
{
    brix_status st = {0}; brix_vfs_stat info; char byte;
    const char *operation = strchr(mode, '-') + 1;
    arm(operation);
    int rc;
    if (!strcmp(mode, "ring-write")) { arm(mode); }
    if (!strcmp(operation, "pread")) { rc = (int)brix_vfs_pread(f, 0, &byte, 1, &st); }
    else if (!strcmp(operation, "fstat")) { rc = brix_vfs_fstat(f, &info, &st); }
    else if (!strcmp(operation, "ftruncate")) { rc = brix_vfs_truncate(f, 3, &st); }
    else if (!strcmp(operation, "pwrite") || !strcmp(mode, "ring-write")) {
        rc = brix_vfs_pwrite(f, 0, "change", 6, &st);
    } else if (!strncmp(mode, "commit-", 7)) { rc = brix_vfs_commit(f, &st); }
    else { rc = brix_vfs_sync(f, &st); }
    assert(rc == -1 && st.msg[0]); assert(getenv("BRIX_CLIENT_VFS_FAULT") == NULL);
}

/* WHAT: Exercise I/O errors after successful setup.
 * WHY: Atomic-file failures must preserve the original destination; blocks stay readable.
 * HOW: Keep the handle valid through the assertion, then abort and close normally. */
static void io_failure(const brix_vfs_backend *be, const char *path,
                       brix_vfs_open_opts *opts, const char *mode)
{
    brix_vfs_file *f = NULL; brix_status st = {0};
    if (strstr(mode, "ring-") || strstr(mode, "flush")) { opts->io_uring = XRDC_IO_URING_ON; }
    int flags = !strncmp(mode, "read-", 5) ? XRDC_VFS_READ : XRDC_VFS_WRITE | XRDC_VFS_FORCE;
    assert(be->open(be, path, flags, opts, &f, &st) == 0);
    fail_operation(f, mode); brix_vfs_abort(f); brix_vfs_close(f);
    verify(path, "original", 8);
}

/* WHAT: Select a contract family. WHY: Fault setup must happen at its actual ownership boundary.
 * HOW: Use explicit mode lists for open failures; all remaining failures operate on a live handle. */
static void dispatch(const brix_vfs_backend *be, const char *path, const char *dir,
                      brix_vfs_open_opts *opts, const char *mode)
{
    if (!strcmp(mode, "roundtrip") || !strcmp(mode, "abort")) { roundtrip(be, path, opts, mode); return; }
    if (!strcmp(mode, "read-only")) { read_only(be, path, opts); return; }
    if (!strcmp(mode, "stat")) { metadata(be, path, dir); return; }
    if (!strncmp(mode, "auto-", 5)) { arm(mode + 5); roundtrip(be, path, opts, mode); return; }
    if (!strcmp(mode, "stat-fail")) {
        brix_vfs_stat info; brix_status st = {0}; arm("stat");
        assert(be->stat(be, path, &info, &st) == -1 && st.sys_errno == EIO); return;
    }
    const char *opens[] = {"read-strdup", "read-calloc", "write-strdup", "write-calloc",
        "write-malloc", "read-missing", "write-missing", "symlink", "read-symlink",
        "existing", "ring-unavailable", "ring-create"};
    for (size_t i = 0; i < sizeof(opens) / sizeof(opens[0]); ++i) {
        if (!strcmp(mode, opens[i])) { open_failure(be, path, opts, mode); return; }
    }
    io_failure(be, path, opts, mode);
}

/* WHAT: Run one isolated storage contract. WHY: Fixtures must never touch host devices.
 * HOW: Both file and block backends use a new ordinary file under the supplied temp root. */
int main(int argc, char **argv)
{
    assert(argc == 5); const char *mode = argv[2];
    int ring = XRDC_IO_URING_OFF;
    if (!strcmp(argv[3], "on")) { ring = XRDC_IO_URING_ON; }
    if (!strcmp(argv[3], "auto")) { ring = XRDC_IO_URING_AUTO; }
    int needs_ring = ring != XRDC_IO_URING_OFF || strstr(mode, "ring-") || strstr(mode, "flush");
    if (needs_ring && !__real_brix_uring_available()) { return 77; }
    brix_vfs_open_opts opts = {.io_uring = ring, .expected_size = -1};
    const brix_vfs_backend *be = !strcmp(argv[1], "file")
        ? brix_vfs_posix_backend() : brix_vfs_block_backend();
    char path[2048]; snprintf(path, sizeof(path), "%s/object", argv[4]); seed(path);
    dispatch(be, path, argv[4], &opts, mode);
    assert(getenv("BRIX_CLIENT_VFS_FAULT") == NULL); no_stages(argv[4]); return 0;
}
