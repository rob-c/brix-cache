/* Real FUSE metadata and retry code with owned, finite remote responses. */
#include "apps/fs/xrootdfs_internal.h"
#include <assert.h>

typedef struct {
    const char *scenario;
    brix_conn connection;
    unsigned identities, gets, puts, calls, sleeps, clock;
} fixture;

/* WHAT: Recover the owned fixture.
 * WHY: Transport seams share no mutable production globals.
 * HOW: Decode the pointer from this child process environment. */
static fixture *state(void)
{
    void *value = NULL;
    assert(sscanf(getenv("BRIX_META_FIXTURE"), "%p", &value) == 1 && value != NULL);
    return value;
}

/* WHAT: Select one metadata response.
 * WHY: Scenario state must stay attached to this fixture.
 * HOW: Compare the supplied case name. */
static int mode(const char *name) { return strcmp(state()->scenario, name) == 0; }

/* WHAT: Return a classified remote error.
 * WHY: The real errno and retry mapping must run.
 * HOW: Populate status and return failure. */
static int fail(brix_status *status, int code)
{
    brix_status_set(status, code, 0, "finite metadata refusal");
    return -1;
}

/* WHAT: Select or refuse the caller transport.
 * WHY: Metadata must never fall back to another uid.
 * HOW: Check uid, count lookup and return the owned pool. */
int __wrap_xfs_ident_get(uid_t uid, brix_pool **pool, brix_mgr **manager)
{
    fixture *f = state();
    assert(uid == 731 && manager == NULL);
    f->identities++;
    if (mode("identity")) { return -EACCES; }
    *pool = (brix_pool *) f;
    return 0;
}

/* WHAT: Supply a finite pool outcome.
 * WHY: Retry bounds must cover checkout failures.
 * HOW: Check pool identity, count attempts and supply a connection or error. */
brix_conn *__wrap_brix_pool_checkout(brix_pool *pool, brix_status *status)
{
    fixture *f = state(); assert(pool == (brix_pool *) f); f->gets++;
    if (mode("checkout-denied")) { fail(status, kXR_NotAuthorized); return NULL; }
    if (mode("checkout-retry") && f->gets == 1) {
        fail(status, XRDC_ESOCK); return NULL;
    }
    return &f->connection;
}

/* WHAT: Observe connection return.
 * WHY: Each borrowed connection must return to its owner.
 * HOW: Check pointers, transport health and return count. */
void __wrap_brix_pool_checkin(brix_pool *pool, brix_conn *connection, int healthy)
{
    fixture *f = state(); assert(pool == (brix_pool *) f && connection == &f->connection);
    assert(healthy == 0 || healthy == 1);
    if (mode("timeout") || mode("count")) { assert(!healthy); }
    f->puts++;
}

/* WHAT: Observe retry backoff without waiting.
 * WHY: Retries must be bounded and ordered.
 * HOW: Check the attempt number and count the delay. */
void __wrap_brix_backoff_sleep_fast(unsigned attempt)
{
    assert(attempt == state()->sleeps++ && attempt < 10);
}

/* WHAT: Advance a deterministic deadline clock.
 * WHY: Timeout tests must not depend on wall time.
 * HOW: Return the next ten-millisecond tick. */
uint64_t __wrap_brix_mono_ns(void) { return (uint64_t) ++state()->clock * 10000000; }

/* WHAT: Supply a bounded symlink response.
 * WHY: Literal targets and permanent refusals must survive metadata handling.
 * HOW: Check the rebased path and return bytes or the selected error. */
ssize_t __wrap_brix_readlink(brix_conn *connection, const char *path,
                            char *buffer, size_t capacity, brix_status *status)
{
    fixture *f = state(); f->calls++;
    assert(connection == &f->connection && strcmp(path, "/export/file") == 0);
    if (mode("denied")) { return fail(status, kXR_NotAuthorized); }
    if (mode("timeout") || mode("count") || (mode("retry") && f->calls == 1)) {
        return fail(status, XRDC_ESOCK);
    }
    const char target[] = "../literal-target";
    assert(capacity >= sizeof(target)); memcpy(buffer, target, sizeof(target));
    return sizeof(target) - 1;
}

/* WHAT: Supply remote metadata or a refusal.
 * WHY: Staged-writer fallback must apply only to missing names.
 * HOW: Check the path, classify the selected case and populate metadata. */
static int stat_reply(const char *path, brix_statinfo *info, brix_status *status)
{
    fixture *f = state(); f->calls++;
    assert(strcmp(path, "/export/file") == 0);
    if (strstr(f->scenario, "missing")) { return fail(status, kXR_NotFound); }
    if (strstr(f->scenario, "denied")) { return fail(status, kXR_NotAuthorized); }
    memset(info, 0, sizeof(*info)); info->size = 33; info->mtime = 123;
    return 0;
}

/* WHAT: Answer a root-protocol metadata request.
 * WHY: The connection identity must remain intact.
 * HOW: Check the borrowed connection and use the finite response. */
int __wrap_brix_lstat(brix_conn *connection, const char *path,
                     brix_statinfo *info, brix_status *status)
{
    assert(connection == &state()->connection);
    return stat_reply(path, info, status);
}

/* WHAT: Answer a WebDAV metadata request.
 * WHY: Web mounts must use their own transport.
 * HOW: Check the selected web pool and use the finite response. */
int __wrap_brix_web_stat_pooled(struct brix_cpool *pool, const char *path,
                              brix_statinfo *info, brix_status *status)
{
    assert(pool == g_web_pool);
    return stat_reply(path, info, status);
}

/* WHAT: Exercise a complete readlink call.
 * WHY: Errors must leave the caller buffer untouched.
 * HOW: Set policy, invoke the real retry loop and check bytes and canaries. */
static int read_link(void)
{
    char buffer[128]; memset(buffer, 0x5a, sizeof(buffer));
    g_ext_readlink = !mode("disabled");
    g_web = mode("web");
    g_max_stall = mode("timeout") ? 25 : 0;
    int rc = xfs_readlink(731, "/file", buffer, mode("empty") ? 0 : sizeof(buffer));
    if (rc == 0) { assert(strcmp(buffer, "../literal-target") == 0); }
    else { assert(buffer[0] == 0x5a); }
    assert(buffer[sizeof(buffer) - 1] == 0x5a);
    return rc;
}

/* WHAT: Exercise metadata and staged-handle fallback.
 * WHY: A denial must not become fabricated writer metadata.
 * HOW: Provide an owned handle and assert the returned type and size. */
static int get_attributes(void)
{
    struct stat output; memset(&output, 0, sizeof(output)); output.st_size = -1;
    afh handle = {0}; handle.writable = !mode("reader-missing"); handle.wsize = 71;
    struct fuse_file_info file = { .fh = (uint64_t) (uintptr_t) &handle };
    struct fuse_file_info *pointer = mode("null-missing") ? NULL : &file;
    if (mode("empty-missing")) { file.fh = 0; }
    g_web = strncmp(state()->scenario, "web-", 4) == 0;
    int rc = xfs_getattr(731, mode("root") ? "/" : "/file", &output, pointer);
    if (rc != 0) { assert(output.st_size == -1); }
    else if (mode("root")) { assert(S_ISDIR(output.st_mode) && output.st_nlink == 2); }
    else {
        assert(S_ISREG(output.st_mode));
        assert(output.st_size == (mode("writer-missing") ? 71 : 33));
    }
    return rc;
}

/* WHAT: Check the read-only WebDAV namespace contract.
 * WHY: Rejected writes must never acquire a root connection.
 * HOW: Invoke each mutation and inspect statfs defaults. */
static int web_refusals(void)
{
    struct timespec times[2] = {{1, 2}, {3, 4}};
    g_web = 1;
    assert(xfs_mkdir(731, "/file", 0777) == -EROFS);
    assert(xfs_unlink(731, "/file") == -EROFS);
    assert(xfs_rmdir(731, "/file") == -EROFS);
    assert(xfs_rename(731, "/file", "/other", 0) == -EROFS);
    assert(xfs_chmod(731, "/file", 0777, NULL) == -EROFS);
    assert(xfs_truncate(731, "/file", 0, NULL) == -EROFS);
    assert(xfs_utimens(731, "/file", times, NULL) == -EROFS);
    assert(xfs_chown(731, "/file", 1, 2, NULL) == -EROFS);
    assert(xfs_symlink(731, "../target", "/file") == -EROFS);
    assert(xfs_link(731, "/file", "/other") == -EROFS);
    assert(xfs_access(731, "/file", W_OK) == -EROFS);
    assert(xfs_access(731, "/file", R_OK) == 0);
    struct statvfs space; memset(&space, 0xa5, sizeof(space));
    assert(xfs_statfs(731, "/", &space) == 0);
    assert(space.f_bsize == 1048576 && space.f_blocks == 0 && space.f_namemax == 255);
    return 0;
}

/* WHAT: Run one finite metadata scenario.
 * WHY: Transport observations must belong to one process.
 * HOW: Initialize context, invoke the operation and print counted outcomes. */
int main(int argc, char **argv)
{
    assert(argc == 3);
    fixture f = { .scenario = argv[2] };
    char pointer[64]; snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_META_FIXTURE", pointer, 1) == 0);
    strcpy(g_base, "/export"); g_max_retries = 2; g_max_stall = 0;
    int rc;
    if (!strcmp(argv[1], "readlink")) { rc = read_link(); }
    else if (!strcmp(argv[1], "getattr")) { rc = get_attributes(); }
    else { assert(!strcmp(argv[1], "web")); rc = web_refusals(); }
    printf("%d %u %u %u %u %u\n", rc, f.identities, f.gets, f.puts, f.calls, f.sleeps);
    assert(unsetenv("BRIX_META_FIXTURE") == 0);
    return 0;
}
