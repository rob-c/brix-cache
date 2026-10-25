"""Writer extent refusals must happen before backend I/O, not as SIGXFSZ."""
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope="module")
def writer_range_driver(native_compile):
    """Link the real writer; spies own only storage and policy side effects."""
    return native_compile("writer-ranges", _DRIVER,
                          ["src/fs/vfs/vfs_writer.c", "src/fs/vfs/vfs_policy.c"],
                          ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"])


@pytest.mark.parametrize("case", ["success", "backend-error", "overflow", "readonly"])
@pytest.mark.parametrize("entry", ["buffer", "fd"])
def test_writer_range_and_mutation_precedence(writer_range_driver, case, entry):
    """Valid boundaries, storage errors, hostile overflow and EROFS stay distinct."""
    result = subprocess.run([str(writer_range_driver), case, entry],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope="module", params=[False, True], ids=["native", "asan-ubsan"])
def core_range_driver(native_compile, request):
    """Exercise the shared server/client loops with an object-owned I/O spy."""
    instrumentation = ["-fsanitize=address,undefined"] if request.param else []
    return native_compile("core-ranges", _CORE_DRIVER, ["src/fs/core/vfs_core.c"],
                          ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                           *instrumentation])


@pytest.mark.parametrize("case", ["success", "backend-error", "overflow", "negative",
                                  "huge", "interrupt", "zero"])
@pytest.mark.parametrize("entry", ["read", "once", "write", "window"])
def test_core_range_before_backend(core_range_driver, case, entry):
    """Invalid extents never dispatch; valid boundaries retain native I/O errors."""
    result = subprocess.run([str(core_range_driver), case, entry],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("case,entry", [
    ("partial-error", "read"), ("partial-error", "write"),
    ("eof", "read"), ("eof", "window"), ("zero-write", "write"),
    ("huge-buffer", "window"),
])
def test_core_short_io_contract(core_range_driver, case, entry):
    """Preserve partial counts and bounded copy windows without signed casts."""
    result = subprocess.run([str(core_range_driver), case, entry],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


_CORE_DRIVER = r'''
#include "fs/core/vfs_core.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const char *mode; unsigned calls; } probe_t;

static ssize_t transfer(brix_sd_obj_t *obj, size_t len, off_t off)
{
    probe_t *probe = obj->state;
    assert(xvfs_check_extent(off, len) == 0);
    probe->calls++;
    if (strcmp(probe->mode, "interrupt") == 0 && probe->calls == 1) {
        errno = EINTR; return -1;
    }
    if (strcmp(probe->mode, "backend-error") == 0 ||
        (strcmp(probe->mode, "partial-error") == 0 && probe->calls == 2)) {
        errno = ENOSPC; return -1;
    }
    if (strcmp(probe->mode, "eof") == 0 || strcmp(probe->mode, "zero-write") == 0)
        return 0;
    return (ssize_t) (len < 2 ? len : 2);
}

static ssize_t read_bytes(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    ssize_t n = transfer(obj, len, off);
    if (n > 0) memset(buf, 'x', (size_t) n);
    return n;
}

static ssize_t write_bytes(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    assert(len == 0 || ((const char *) buf)[0] == 'x');
    return transfer(obj, len, off);
}

/* Only xvfs_stage_fd's unused link closure; calling either is a test bug. */
const brix_sd_driver_t brix_sd_posix_driver = {0};
int brix_plat_fd_reopen_readonly(int fd) { (void) fd; abort(); }

static int submit(brix_sd_obj_t *obj, const char *entry, char *buf, size_t len,
                  off_t off, size_t *count, int *short_io, const char *mode)
{
    if (strcmp(entry, "read") == 0) return xvfs_pread_full(obj, buf, len, off, count);
    if (strcmp(entry, "write") == 0)
        return xvfs_pwrite_full(obj, buf, len, off, count, short_io);
    if (strcmp(entry, "once") == 0) {
        ssize_t n = xvfs_pread_once(obj, buf, len, off);
        *count = n < 0 ? 0 : (size_t) n;
        return n < 0 ? -1 : 0;
    }
    xvfs_window_t win = {off, (off_t) len, -99};
    size_t bufsz = strcmp(mode, "huge-buffer") == 0 ? SIZE_MAX : 3;
    if (strcmp(mode, "huge") == 0) { win.len = -1; bufsz = SIZE_MAX; }
    int rc = xvfs_drain_window(obj, obj, buf, bufsz, &win);
    assert(rc == 0 || win.end == -99);
    *count = rc == 0 ? (size_t) (win.end - off) : 0;
    return rc;
}

static void check_result(const char *mode, int rc, size_t count, int short_io,
                         unsigned calls, int once, int writing)
{
    if (strcmp(mode, "overflow") == 0 || strcmp(mode, "negative") == 0 ||
        strcmp(mode, "huge") == 0) {
        assert(rc == -1 && errno == EINVAL && calls == 0 && count == 0);
        assert(short_io == 0);
    } else if (strcmp(mode, "backend-error") == 0) {
        assert(rc == -1 && errno == ENOSPC && calls == 1 && count == 0);
    } else if (strcmp(mode, "partial-error") == 0) {
        assert(rc == -1 && errno == ENOSPC && calls == 2 && count == 2);
        assert(short_io == writing);
    } else if (strcmp(mode, "zero-write") == 0) {
        assert(rc == -1 && errno == EIO && count == 0 && short_io == 1);
    } else if (strcmp(mode, "eof") == 0) {
        assert(count == 0 && calls == 1);
        assert(rc == 0 || (rc == -1 && errno == EIO));
    } else {
        assert(rc == 0 && short_io == 0);
        assert(count == (strcmp(mode, "zero") == 0 ? 0U : once ? 2U : 3U));
    }
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    const char *mode = argv[1], *entry = argv[2];
    const brix_sd_driver_t driver = {.pread = read_bytes, .pwrite = write_bytes};
    probe_t probe = {mode, 0};
    brix_sd_obj_t obj = {.driver = &driver, .state = &probe};
    char buf[3] = {'x', 'x', 'x'};
    size_t count = 99, len = 3;
    int short_io = 99;
    off_t off = NGX_MAX_OFF_T_VALUE - 3;
    if (strcmp(mode, "overflow") == 0) off = NGX_MAX_OFF_T_VALUE - 1;
    if (strcmp(mode, "negative") == 0) off = -1;
    if (strcmp(mode, "huge") == 0) { off = 0; len = SIZE_MAX; }
    if (strcmp(mode, "zero") == 0) { off = NGX_MAX_OFF_T_VALUE; len = 0; }
    short_io = strcmp(entry, "write") == 0 ? 99 : 0;
    int rc = submit(&obj, entry, buf, len, off, &count, &short_io, mode);
    check_result(mode, rc, count, short_io, probe.calls,
                 strcmp(entry, "once") == 0, strcmp(entry, "write") == 0);
    return 0;
}
'''


_DRIVER = r'''
#include "fs/vfs/vfs_writer_internal.h"
#include "core/compat/copy_range.h"
#include <assert.h>
#include <string.h>

static unsigned io_calls;
static int refuse_io;

ngx_int_t brix_vfs_gate_mutation(const brix_vfs_ctx_t *ctx, brix_vfs_mutation_op_t op)
{
    assert(op == BRIX_VFS_MUTATE_WRITE);
    if (ctx->mutation_policy != brix_vfs_policy_from_write_enable(1)) {
        errno = EROFS;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ssize_t brix_vfs_file_pwrite(brix_vfs_file_t *file, const void *bytes, size_t len, off_t off)
{
    (void) file; (void) bytes;
    assert(off >= 0 && (uint64_t) len <= (uint64_t) (NGX_MAX_OFF_T_VALUE - off));
    io_calls++;
    if (refuse_io) { errno = ENOSPC; return -1; }
    return (ssize_t) len;
}

ngx_fd_t brix_vfs_file_sendfile_fd(const brix_vfs_file_t *file)
{
    (void) file;
    io_calls++;
    return 12;
}

ngx_int_t brix_copy_range(ngx_log_t *log, int src, off_t src_off, int dst,
                        off_t dst_off, size_t len, const char *sp, const char *dp)
{
    (void) log; (void) sp; (void) dp;
    assert(src == 11 && dst == 12);
    assert((uint64_t) len <= (uint64_t) (NGX_MAX_OFF_T_VALUE - src_off));
    assert((uint64_t) len <= (uint64_t) (NGX_MAX_OFF_T_VALUE - dst_off));
    io_calls++;
    if (refuse_io) { errno = ENOSPC; return NGX_ERROR; }
    return NGX_OK;
}

ngx_int_t brix_vfs_writer_spill_enter(brix_vfs_writer_t *w, off_t off, size_t len)
{ (void) w; (void) off; (void) len; abort(); }
ngx_int_t brix_vfs_writer_spill_put(brix_vfs_writer_t *w, const void *b, size_t l, off_t o)
{ (void) w; (void) b; (void) l; (void) o; abort(); }
ngx_int_t brix_vfs_staged_write(brix_vfs_staged_t *s, const void *b, size_t l, off_t o)
{ (void) s; (void) b; (void) l; (void) o; abort(); }
int brix_wverify_update(brix_wverify_t *w, const void *b, off_t o, size_t l)
{ (void) w; (void) b; (void) o; (void) l; abort(); }

static ngx_int_t submit(brix_vfs_writer_t *writer, int fd, off_t source,
                       off_t destination, size_t len)
{
    return fd ? brix_vfs_writer_write_fd(writer, 11, source, len, destination)
              : brix_vfs_writer_write(writer, "bytes", len, destination);
}

int main(int argc, char **argv)
{
    brix_vfs_ctx_t ctx = {0};
    brix_vfs_writer_t writer = {0};
    int fd;
    assert(argc == 3);
    fd = strcmp(argv[2], "fd") == 0;
    ctx.mutation_policy = brix_vfs_policy_from_write_enable(1);
    writer.ctx = &ctx;
    writer.mode = BRIX_VFS_WRITER_RANDOM;
    if (strcmp(argv[1], "success") == 0) {
        assert(submit(&writer, fd, 0, 0, 1) == NGX_OK);
        assert(submit(&writer, fd, NGX_MAX_OFF_T_VALUE - 1,
                      NGX_MAX_OFF_T_VALUE - 1, 1) == NGX_OK);
        assert(writer.written == 2 && io_calls == (fd ? 4U : 2U));
    } else if (strcmp(argv[1], "backend-error") == 0) {
        refuse_io = 1;
        assert(submit(&writer, fd, 0, 0, 1) == NGX_ERROR && errno == ENOSPC);
        assert(writer.written == 0 && io_calls == (fd ? 2U : 1U));
    } else {
        int readonly = strcmp(argv[1], "readonly") == 0;
        assert(readonly || strcmp(argv[1], "overflow") == 0);
        if (readonly) ctx.mutation_policy = brix_vfs_policy_from_write_enable(0);
        assert(submit(&writer, fd, 0, NGX_MAX_OFF_T_VALUE, 1) == NGX_ERROR);
        assert(errno == (readonly ? EROFS : EINVAL) && io_calls == 0);
        if (fd) {
            assert(submit(&writer, fd, NGX_MAX_OFF_T_VALUE, 0, 1) == NGX_ERROR);
            assert(errno == (readonly ? EROFS : EINVAL) && io_calls == 0);
        }
        assert(submit(&writer, fd, 0, 0, SIZE_MAX) == NGX_ERROR);
        assert(errno == (readonly ? EROFS : EINVAL) && io_calls == 0);
        writer.written = NGX_MAX_OFF_T_VALUE;
        assert(submit(&writer, fd, 0, 0, 1) == NGX_ERROR);
        assert(errno == (readonly ? EROFS : EINVAL) && io_calls == 0);
    }
    return 0;
}
'''
