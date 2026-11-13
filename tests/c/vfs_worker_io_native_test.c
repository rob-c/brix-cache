/* Worker I/O runs against a finite storage vtable with observable progress. */
#include "core/ngx_brix_module.h"
#include "fs/vfs/vfs_io_core_internal.h"
#include "core/compat/crc32c.h"
#include <assert.h>

typedef struct {
    const char *mode;
    unsigned calls, syncs;
    size_t size;
    unsigned char bytes[16];
} fixture;
static int mode(fixture *f, const char *name) { return strcmp(f->mode, name) == 0; }
static ssize_t step(fixture *f, size_t length, off_t offset)
{
    unsigned index = ++f->calls; assert(index < 20 && offset >= 0);
    if (mode(f, "intr") && index == 1) { errno = EINTR; return -1; }
    if (mode(f, "error") || (mode(f, "partial-error") && index > 1)) {
        errno = ENOSPC; return -1;
    }
    if (mode(f, "zero") || (mode(f, "partial-zero") && index > 1)) { return 0; }
    if (strstr(f->mode, "partial") && length > 3) { length = 3; }
    return (ssize_t) length;
}
static ssize_t read_bytes(brix_sd_obj_t *obj, void *buffer, size_t length, off_t offset)
{
    fixture *f = obj->state;
    ssize_t count = step(f, length, offset);
    if (count <= 0) { return count; }
    assert((size_t) offset <= f->size);
    if ((size_t) count > f->size - (size_t) offset) { count = f->size - (size_t) offset; }
    memcpy(buffer, f->bytes + offset, (size_t) count); return count;
}
static ssize_t write_bytes(brix_sd_obj_t *obj, const void *buffer, size_t length, off_t offset)
{
    fixture *f = obj->state;
    ssize_t count = step(f, length, offset);
    if (count <= 0) { return count; }
    assert((size_t) offset + (size_t) count <= sizeof(f->bytes));
    assert(memcmp(buffer, "abcdefgh" + offset, (size_t) count) == 0);
    memcpy(f->bytes + offset, buffer, (size_t) count); return count;
}
static ngx_int_t sync_bytes(brix_sd_obj_t *obj)
{
    fixture *f = obj->state; f->syncs++;
    if (mode(f, "error")) { errno = EIO; return NGX_ERROR; }
    return NGX_OK;
}
static ngx_int_t truncate_bytes(brix_sd_obj_t *obj, off_t length)
{
    fixture *f = obj->state; f->calls++;
    if (mode(f, "error")) { errno = EIO; return NGX_ERROR; }
    assert(length == 4); f->size = length; return NGX_OK;
}

static void invalid_input(brix_vfs_job_t *job, const char *name)
{
    if (!strcmp(name, "bad-fd")) { job->fd = -1; job->obj.driver = NULL; }
    if (!strcmp(name, "negative")) { job->offset = -1; }
    if (!strcmp(name, "null-buffer")) { job->buf = NULL; }
    if (!strcmp(name, "capacity")) { job->buf_cap = job->length - 1; }
    if (!strcmp(name, "empty")) { job->length = 0; }
    if (!strcmp(name, "null-error")) { job->err_msg = NULL; }
    if (!strcmp(name, "zero-error")) { job->err_msg_cap = 0; }
}
static void prepare_vector(brix_vfs_job_t *job, brix_vfs_writev_seg_t *segments,
                            const char *name)
{
    for (unsigned i = 0; i < 3; ++i) {
        segments[i].obj = job->obj; segments[i].fd = -1;
        segments[i].offset = i ? 4 : 0;
        segments[i].wlen = i == 1 ? 0 : 4;
        segments[i].data = (const u_char *) "abcdefgh" + segments[i].offset;
    }
    job->segs = segments; job->nsegs = 3; job->do_sync = 1;
    if (!strcmp(name, "no-segments")) { job->segs = NULL; }
    if (!strcmp(name, "zero-segments")) { job->nsegs = 0; }
}
static void assert_read(brix_vfs_job_t *job, fixture *f)
{
    if (job->nio <= 0) { return; }
    if (job->op == BRIX_VFS_IO_READ) {
        assert(memcmp(job->buf, f->bytes, job->out_size) == 0);
        assert(job->crc32c == brix_crc32c_value(job->buf, job->out_size));
    }
    if (job->op == BRIX_VFS_IO_PGREAD) {
        assert(job->out_size == (size_t) job->nio + 4);
        assert(memcmp(job->buf + 4, f->bytes, job->nio) == 0);
        assert(xrdw_get_u32(job->buf) == brix_crc32c_value(job->buf + 4, job->nio));
    }
}
int main(int argc, char **argv)
{
    assert(argc == 6);
    fixture f = {.mode = argv[2], .size = 8}; memcpy(f.bytes, "abcdefgh", 8);
    brix_sd_driver_t driver = {.name = "posix", .pread = read_bytes, .pwrite = write_bytes,
                               .fsync = sync_bytes, .ftruncate = truncate_bytes};
    brix_vfs_job_t job = {0}; brix_vfs_writev_seg_t segments[3] = {0};
    unsigned char buffer[64]; char error[128];
    memset(buffer, 0xa5, sizeof(buffer)); memset(error, 0, sizeof(error));
    ngx_cycle_t cycle = {0}; ngx_log_t log = {0}; cycle.log = &log; ngx_cycle = &cycle;
    job.op = atoi(argv[1]); job.fd = -1; job.obj.driver = &driver; job.obj.state = &f;
    job.buf = buffer + 8; job.length = 8; job.buf_cap = 32; job.want_pgcrc = 1;
    job.mutation_policy = brix_vfs_policy_from_write_enable(1);
    job.err_msg = error; job.err_msg_cap = sizeof(error);
    if (job.op == BRIX_VFS_IO_TRUNCATE) { job.offset = 4; }
    if (job.op == BRIX_VFS_IO_WRITE) { memcpy(job.buf, "abcdefgh", 8); }
    if (job.op == BRIX_VFS_IO_WRITEV) { prepare_vector(&job, segments, f.mode); }
    invalid_input(&job, f.mode);
    job.nio = 91; job.out_size = 92; job.crc32c = 93; job.io_errno = 94; job.short_io = 1;
    if (mode(&f, "reuse")) { job.csi_mismatch = 1; }
    brix_vfs_io_execute(NULL); brix_vfs_io_execute(&job);
    fprintf(stderr, "nio=%ld out=%zu errno=%d short=%u csi=%u calls=%u sync=%u %s\n",
        (long) job.nio, job.out_size, job.io_errno, job.short_io, job.csi_mismatch,
        f.calls, f.syncs, error);
    assert(job.nio == atol(argv[3]) && job.io_errno == atoi(argv[4]));
    assert(job.out_size == strtoul(argv[5], NULL, 10) && !job.csi_mismatch);
    for (unsigned i = 0; i < 8; ++i) { assert(buffer[i] == 0xa5 && buffer[40 + i] == 0xa5); }
    assert_read(&job, &f);
    if (job.op == BRIX_VFS_IO_TRUNCATE && !job.io_errno) { assert(f.size == 4); }
    return 0;
}
