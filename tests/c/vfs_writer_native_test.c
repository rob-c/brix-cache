/* Exercise the real VFS writer, disk publication and read-back verifier. */
#include "fs/vfs/vfs_writer_internal.h"
#include "fs/vfs/vfs_backend_registry.h"
#include <assert.h>

/* WHAT: Select one writer scenario.
 * WHY: Fault choices belong to this process.
 * HOW: Compare the explicit case name. */
static int mode(const char *value)
{
    return strcmp(getenv("BRIX_WRITER_CASE"), value) == 0;
}

void *__real_ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *__real_ngx_palloc(ngx_pool_t *pool, size_t size);
ssize_t __real_pread64(int fd, void *buffer, size_t length, off_t offset);
brix_wverify_t *__real_brix_wverify_begin(void);

/* WHAT: Refuse the context-clone allocation.
 * WHY: Opening must fail before storage is created.
 * HOW: Consume the one-shot fault or use the real pool allocator. */
void *__wrap_ngx_palloc(ngx_pool_t *pool, size_t size)
{
    if (getenv("BRIX_WRITER_CLONE_FAIL") != NULL) {
        assert(unsetenv("BRIX_WRITER_CLONE_FAIL") == 0);
        errno = ENOMEM; return NULL;
    }
    return __real_ngx_palloc(pool, size);
}

/* WHAT: Refuse one counted allocation.
 * WHY: Partial construction must report ENOMEM.
 * HOW: Decrement the armed counter and delegate every other allocation. */
void *__wrap_ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    const char *pending = getenv("BRIX_WRITER_ALLOC");
    if (pending != NULL) {
        int remaining = atoi(pending) - 1;
        char next[16]; snprintf(next, sizeof(next), "%d", remaining);
        assert(setenv("BRIX_WRITER_ALLOC", next, 1) == 0);
        if (remaining == 0) {
            assert(unsetenv("BRIX_WRITER_ALLOC") == 0);
            errno = ENOMEM; return NULL;
        }
    }
    return __real_ngx_pcalloc(pool, size);
}

/* WHAT: Refuse verifier creation.
 * WHY: An opened writer must release its resources.
 * HOW: Fail only the selected case; otherwise create the real verifier. */
brix_wverify_t *__wrap_brix_wverify_begin(void)
{
    if (mode("verify-allocation")) { return NULL; }
    return __real_brix_wverify_begin();
}

/* WHAT: Interrupt one source read.
 * WHY: Ingestion must retry without changing its offset.
 * HOW: Consume the interrupt flag, then perform real reads. */
ssize_t __wrap_pread64(int fd, void *buffer, size_t length, off_t offset)
{
    if (getenv("BRIX_WRITER_INTERRUPT") != NULL) {
        assert(unsetenv("BRIX_WRITER_INTERRUPT") == 0);
        errno = EINTR; return -1;
    }
    return __real_pread64(fd, buffer, length, offset);
}

/* Only configuration lookup is supplied by the fixture; storage stays real. */
/* WHAT: Supply the fixture spill configuration.
 * WHY: Storage and mutation checks must remain real.
 * HOW: Validate the export and return its owned scratch root and limit. */
ngx_int_t __wrap_brix_vfs_backend_spill(const char *root,
    const char **scratch, off_t *limit)
{
    assert(strcmp(root, getenv("BRIX_WRITER_EXPORT")) == 0);
    *scratch = getenv("BRIX_WRITER_SCRATCH");
    *limit = mode("spill-limit") ? 4 : 0;
    return NGX_OK;
}

/* WHAT: Check invalid and finished writer calls.
 * WHY: Invalid input must not mutate storage.
 * HOW: Assert refusal, accounting, and idempotent abort. */
static void invalid_arguments(brix_vfs_writer_t *writer)
{
    assert(brix_vfs_writer_expected_off(NULL) == -1);
    assert(brix_vfs_writer_fd(NULL) == -1);
    assert(brix_vfs_writer_staged(NULL) == NULL);
    assert(brix_vfs_writer_commit(NULL) == NGX_ERROR);
    brix_vfs_writer_abort(NULL);
    assert(brix_vfs_writer_write(NULL, "x", 1, 0) == NGX_ERROR && errno == EINVAL);
    assert(brix_vfs_writer_write(writer, NULL, 1, 0) == NGX_ERROR && errno == EINVAL);
    assert(brix_vfs_writer_write(writer, "x", 1, -1) == NGX_ERROR && errno == EINVAL);
    assert(brix_vfs_writer_write_fd(writer, -1, 0, 1, 0) == NGX_ERROR && errno == EINVAL);
    assert(brix_vfs_writer_write(writer, "", 0, 0) == NGX_OK);
    assert(brix_vfs_writer_write(writer, "x", SIZE_MAX, 0) == NGX_ERROR && errno == EINVAL);
    assert(brix_vfs_writer_expected_off(writer) == 0);
    brix_vfs_writer_abort(writer);
    assert(brix_vfs_writer_write(writer, "x", 1, 0) == NGX_ERROR && errno == EINVAL);
    assert(brix_vfs_writer_commit(writer) == NGX_ERROR);
}

/* WHAT: Ingest a bounded real file extent.
 * WHY: Source errors must preserve descriptor ownership.
 * HOW: Seed bytes, execute the requested fault, and check close ownership. */
static void ingest_fd(brix_vfs_writer_t *writer, const char *path)
{
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    assert(fd >= 0 && write(fd, "0123456789", 10) == 10);
    if (mode("fd-error")) {
        assert(close(fd) == 0);
        assert(brix_vfs_writer_write_fd(writer, fd, 0, 10, 0) == NGX_ERROR);
        assert(errno == EBADF);
        brix_vfs_writer_abort(writer);
        return;
    }
    if (mode("fd-eintr")) { assert(setenv("BRIX_WRITER_INTERRUPT", "1", 1) == 0); }
    if (mode("fd-short")) {
        assert(brix_vfs_writer_write_fd(writer, fd, 0, 11, 0) == NGX_ERROR);
        assert(errno == EIO);
        brix_vfs_writer_abort(writer);
    } else {
        assert(brix_vfs_writer_write_fd(writer, fd, 0, 0, 0) == NGX_OK);
        assert(brix_vfs_writer_write_fd(writer, fd, 2, 6, 0) == NGX_OK);
        assert(brix_vfs_writer_expected_off(writer) == 6);
        assert(brix_vfs_writer_commit(writer) == NGX_OK);
    }
    assert(fcntl(fd, F_GETFD) >= 0);
    assert(close(fd) == 0);
}

/* WHAT: Exercise extent growth and its hard limit.
 * WHY: Sparse fragments must remain bounded and exact.
 * HOW: Insert disjoint bytes, fill gaps or refuse exhaustion, then commit. */
static void fragmented_spill(brix_vfs_writer_t *writer)
{
    unsigned fragments = mode("spill-cap") ? 8193 : 130;
    for (unsigned index = 0; index < fragments; index++) {
        ngx_int_t result = brix_vfs_writer_write(writer, "A", 1, 2 * index + 1);
        if (index == 8192) {
            assert(result == NGX_ERROR && errno == ENOSPC);
            assert(brix_vfs_writer_commit(writer) == NGX_ERROR && errno == ENOSPC);
            return;
        }
        assert(result == NGX_OK);
    }
    for (unsigned index = 0; index < fragments; index++) {
        assert(brix_vfs_writer_write(writer, "B", 1, 2 * index) == NGX_OK);
    }
    assert(brix_vfs_writer_expected_off(writer) == 2 * fragments);
    assert(brix_vfs_writer_commit(writer) == NGX_OK);
}

/* WHAT: Exercise reordered writes and refused gaps.
 * WHY: A staged object must never publish invented bytes.
 * HOW: Write bounded extents and check overlap, capacity and commit results. */
static void spill_writes(brix_vfs_writer_t *writer)
{
    if (mode("spill-limit")) {
        assert(brix_vfs_writer_write(writer, "6789", 4, 6) == NGX_ERROR);
        assert(errno == ENOSPC);
        assert(brix_vfs_writer_write(writer, "x", 1, 0) == NGX_ERROR);
        assert(errno == ENOSPC);
        assert(brix_vfs_writer_commit(writer) == NGX_ERROR && errno == ENOSPC);
        return;
    }
    assert(brix_vfs_writer_write(writer, "6789", 4, 6) == NGX_OK);
    assert(brix_vfs_writer_expected_off(writer) == 10);
    assert(brix_vfs_writer_fd(writer) == NGX_INVALID_FILE);
    assert(brix_vfs_writer_staged(writer) == NULL);
    if (mode("spill-hole")) {
        assert(brix_vfs_writer_commit(writer) == NGX_ERROR && errno == EINVAL);
        return;
    }
    assert(brix_vfs_writer_write(writer, "01", 2, 0) == NGX_OK);
    assert(brix_vfs_writer_write(writer, "45", 2, 4) == NGX_OK);
    assert(brix_vfs_writer_write(writer, "23", 2, 2) == NGX_OK);
    assert(brix_vfs_writer_write(writer, "X", 1, 5) == NGX_ERROR && errno == EINVAL);
    assert(brix_vfs_writer_commit(writer) == NGX_OK);
}

/* WHAT: Complete, corrupt or abort a write.
 * WHY: Commit must report durability and integrity honestly.
 * HOW: Write exact bytes, select the completion case and assert its result. */
static void ordinary_writes(brix_vfs_writer_t *writer)
{
    assert(brix_vfs_writer_write(writer, "01234", 5, 0) == NGX_OK);
    assert(brix_vfs_writer_write(writer, "56789", 5, 5) == NGX_OK);
    assert(brix_vfs_writer_expected_off(writer) == 10);
    if (mode("abort")) {
        brix_vfs_writer_abort(writer);
        brix_vfs_writer_abort(writer);
        return;
    }
    if (mode("corrupt")) {
        assert(pwrite(brix_vfs_writer_fd(writer), "X", 1, 0) == 1);
        assert(brix_vfs_writer_commit(writer) == NGX_ERROR);
        return;
    }
    if (mode("precondition")) {
        brix_sd_precond_t pre = { .kind = BRIX_SD_PRECOND_MATCH_ETAG };
        assert(brix_vfs_writer_commit_pre(writer, &pre) == NGX_ERROR);
        assert(errno == ENOTSUP);
    }
    assert(brix_vfs_writer_commit(writer) == NGX_OK);
    assert(brix_vfs_writer_commit(writer) == NGX_ERROR);
}

/* WHAT: Run one isolated writer contract.
 * WHY: The real VFS must own every session and temporary file.
 * HOW: Create the context, execute the case and release its pool. */
int main(int argc, char **argv)
{
    assert(argc == 6);
    assert(setenv("BRIX_WRITER_CASE", argv[3], 1) == 0);
    assert(setenv("BRIX_WRITER_EXPORT", argv[1], 1) == 0);
    assert(setenv("BRIX_WRITER_SCRATCH", argv[2], 1) == 0);
    ngx_open_file_t error_file = { .fd = STDERR_FILENO };
    ngx_log_t log = { .log_level = NGX_LOG_ERR, .file = &error_file };
    ngx_cycle_t cycle = { .log = &log };
    ngx_cycle = &cycle; ngx_os_argv = argv; ngx_time_init();
    assert(ngx_os_init(&log) == NGX_OK);
    cycle.pool = ngx_create_pool(16384, &log); assert(cycle.pool != NULL);
    char destination[PATH_MAX], source[PATH_MAX];
    assert(snprintf(destination, sizeof(destination), "%s/output", argv[1]) < PATH_MAX);
    assert(snprintf(source, sizeof(source), "%s/input", argv[1]) < PATH_MAX);
    brix_vfs_ctx_t ctx;
    brix_vfs_ctx_init(&ctx, cycle.pool, &log, BRIX_PROTO_ROOT, argv[1], NULL,
        brix_vfs_policy_from_write_enable(!mode("readonly")), 0, NULL, destination);
    int error = 0;
    assert(brix_vfs_writer_open(NULL, 0, 0, &error) == NULL && error == EINVAL);
    unsigned flags = atoi(argv[4]) ? BRIX_VFS_O_ATOMIC : BRIX_VFS_O_TRUNC;
    if (mode("allocation")) { assert(setenv("BRIX_WRITER_ALLOC", "1", 1) == 0); }
    if (mode("clone-allocation")) { assert(setenv("BRIX_WRITER_CLONE_FAIL", "1", 1) == 0); }
    brix_vfs_writer_t *writer = brix_vfs_writer_open(&ctx, flags, atoi(argv[5]), &error);
    if (mode("readonly")) {
        assert(writer == NULL && error == EROFS);
    } else if (strstr(argv[3], "allocation") != NULL) {
        assert(writer == NULL && error == ENOMEM);
    } else {
        assert(writer != NULL && error == 0);
        /* The session owns its context: a later caller policy must not alter it. */
        ctx.mutation_policy = BRIX_VFS_MUTATION_READ_ONLY;
        if (mode("invalid")) { invalid_arguments(writer); }
        else if (strncmp(argv[3], "fd-", 3) == 0) { ingest_fd(writer, source); }
        else if (mode("spill-grow") || mode("spill-cap")) { fragmented_spill(writer); }
        else if (strncmp(argv[3], "spill", 5) == 0) { spill_writes(writer); }
        else { ordinary_writes(writer); }
    }
    ngx_destroy_pool(cycle.pool);
    puts("writer contract preserved");
    return 0;
}
