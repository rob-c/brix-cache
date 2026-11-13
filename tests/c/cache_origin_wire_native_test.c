/* Origin operations exchange real wire frames over an inherited socketpair. */
#include "fs/cache/cache_internal.h"
#include <assert.h>
#include <signal.h>
#include <sys/socket.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *fault;
    unsigned allocations, fail_allocation, sends, receives;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
static int fail_allocation(void)
{
    fixture *f = state();
    if (f && f->fail_allocation && ++f->allocations == f->fail_allocation) {
        errno = ENOMEM; return 1;
    }
    return 0;
}
void *__wrap_malloc(size_t size)
{ return fail_allocation() ? NULL : __real_malloc(size); }
void *__wrap_calloc(size_t count, size_t size)
{ return fail_allocation() ? NULL : __real_calloc(count, size); }
ssize_t __real_send(int, const void *, size_t, int);
ssize_t __wrap_send(int fd, const void *data, size_t size, int flags)
{
    fixture *f = state(); f->sends++;
    if (!strcmp(f->fault, "send-error")
        || (!strcmp(f->fault, "payload-error") && f->sends == 2)) {
        errno = EIO; return -1;
    }
    if (!strcmp(f->fault, "send-zero")) { return 0; }
    if (!strcmp(f->fault, "send-eintr") && f->sends == 1) { errno = EINTR; return -1; }
    return __real_send(fd, data, size, flags);
}
ssize_t __real_recv(int, void *, size_t, int);
ssize_t __wrap_recv(int fd, void *data, size_t size, int flags)
{
    fixture *f = state(); f->receives++;
    if (!strcmp(f->fault, "recv-eintr") && f->receives == 1) { errno = EINTR; return -1; }
    return __real_recv(fd, data, size, flags);
}

/* WHAT: Exercise the fixed-handle write lifecycle with a wide wire offset.
 * WHY: Error replies must retain their reason and never become successful writes.
 * HOW: Use the real request packers, transport and response decoder. */
static int write_operation(brix_cache_fill_t *task, brix_cache_origin_conn_t *conn,
    const char *op, const char *path, u_char handle[4])
{
    uint64_t offset = UINT64_C(0x0102030405060708);
    if (!strcmp(op, "open")) {
        return brix_cache_origin_open_write(task, conn, path, 0600, handle);
    }
    if (!strcmp(op, "read-open")) { return brix_cache_origin_open(task, conn, handle); }
    if (!strcmp(op, "write") || !strcmp(op, "write-large") || !strcmp(op, "write-empty")) {
        size_t length = !strcmp(op, "write-large") ? (size_t) INT32_MAX + 1
                      : !strcmp(op, "write-empty") ? 0 : 7;
        return brix_cache_origin_write_chunk(task, conn, handle, offset,
                                             (const u_char *) "payload", length);
    }
    if (!strcmp(op, "truncate")) { return brix_cache_origin_truncate(task, conn, handle, offset); }
    if (!strcmp(op, "truncate-path")) { return brix_cache_origin_truncate_path(task, conn, path, offset); }
    if (!strcmp(op, "sync")) { return brix_cache_origin_sync(task, conn, handle); }
    assert(!strcmp(op, "close")); brix_cache_origin_close_file(conn, handle); return 0;
}

/* WHAT: Cover namespace errors using the same real origin exchange.
 * WHY: Callers need ENOENT, EACCES and ENOTEMPTY to remain distinct.
 * HOW: Dispatch public APIs while the peer supplies exact response bytes. */
static int namespace_operation(brix_cache_fill_t *task, brix_cache_origin_conn_t *conn,
    const char *op, const char *path)
{
    if (!strcmp(op, "rename")) { return brix_cache_origin_rename(task, conn, path, "/destination"); }
    if (!strcmp(op, "rm")) { return brix_cache_origin_rm(task, conn, path); }
    if (!strcmp(op, "rmdir")) { return brix_cache_origin_rmdir(task, conn, path); }
    if (!strcmp(op, "mkdir")) { return brix_cache_origin_mkdir(task, conn, path, 0750); }
    if (!strcmp(op, "chmod")) { return brix_cache_origin_chmod(task, conn, path, 0640); }
    if (!strcmp(op, "evict")) { return brix_cache_origin_prepare_evict(task, conn, path); }
    assert(!strcmp(op, "stage")); char request[40];
    int rc = brix_cache_origin_prepare_stage(task, conn, path, request);
    if (!rc) { printf("request=%s\n", request); }
    return rc;
}

int main(int argc, char **argv)
{
    assert(argc == 7); fixture f = {0}; ngx_cycle = &f.cycle;
    f.fault = argv[4]; f.fail_allocation = (unsigned) atoi(argv[5]);
    (void) signal(SIGPIPE, SIG_IGN);
    brix_cache_origin_conn_t conn = {.fd = atoi(argv[1])};
    brix_cache_fill_t task = {0};
    const char *op = argv[2], *path = !strcmp(argv[3], "<null>") ? NULL : argv[3];
    if (path) { snprintf(task.clean_path, sizeof(task.clean_path), "%s", path); }
    u_char handle[4] = {0x12, 0x34, 0x56, 0x78}; errno = 0;
    int rc = !strcmp(argv[6], "namespace")
        ? namespace_operation(&task, &conn, op, path)
        : write_operation(&task, &conn, op, path, handle);
    int error = errno;
    printf("rc=%d\nerrno=%d\nxrd_error=%d\nsize=%llu\nhandle=%02x%02x%02x%02x\nsends=%u\n",
        rc, error, task.xrd_error, (unsigned long long) task.file_size,
        handle[0], handle[1], handle[2], handle[3], f.sends);
    assert(close(conn.fd) == 0); ngx_cycle = NULL; return 0;
}
