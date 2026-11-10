/* Confined namespace mutations with real files, preconditions and injected I/O errors. */
#include "core/compat/namespace_ops.h"
#include "core/compat/copy_range.h"
#include "fs/path/beneath.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int __real_brix_unlink_beneath(int, const char *, int);
ngx_int_t __real_brix_copy_range(ngx_log_t *, int, off_t, int, off_t, size_t,
                                 const char *, const char *);

/* WHAT: Inject one removal error. WHY: Every errno has a public neutral disposition.
 * HOW: Read the explicit numeric errno only after setup has finished. */
int __wrap_brix_unlink_beneath(int fd, const char *path, int is_dir)
{
    const char *value = getenv("BRIX_NS_UNLINK_ERROR");
    if (value != NULL) {
        int error = atoi(value); unsetenv("BRIX_NS_UNLINK_ERROR"); errno = error; return -1;
    }
    return __real_brix_unlink_beneath(fd, path, is_dir);
}

/* WHAT: Refuse one data copy. WHY: A staged error must never publish partial output.
 * HOW: Otherwise run the actual confined-fd transfer helper. */
ngx_int_t __wrap_brix_copy_range(ngx_log_t *log, int from, off_t from_offset,
                                 int to, off_t to_offset, size_t size,
                                 const char *source, const char *destination)
{
    if (getenv("BRIX_NS_COPY_ERROR") != NULL) {
        unsetenv("BRIX_NS_COPY_ERROR"); errno = EIO; return NGX_ERROR;
    }
    return __real_brix_copy_range(log, from, from_offset, to, to_offset, size, source, destination);
}

/* WHAT: Seed and inspect fixture bytes. WHY: Results must reflect stored data.
 * HOW: Use private test files and exact byte assertions. */
static void put(const char *path, const char *data)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600); assert(fd >= 0);
    assert(write(fd, data, strlen(data)) == (ssize_t)strlen(data)); close(fd);
}
static void expect(const char *path, const char *data)
{
    char bytes[64] = {0}; int fd = open(path, O_RDONLY); assert(fd >= 0);
    assert(read(fd, bytes, sizeof(bytes)) == (ssize_t)strlen(data));
    assert(!memcmp(bytes, data, strlen(data))); close(fd);
}

/* WHAT: Prepare a target of the selected filesystem type.
 * WHY: Removal classification differs for files, directories and symlinks.
 * HOW: Create each private target with a child only for nonempty cases. */
static void delete_target(const char *mode, const char *path)
{
    if (!strcmp(mode, "missing") || !strcmp(mode, "idempotent") || !strcmp(mode, "outside")) { return; }
    if (strstr(mode, "dir") && strcmp(mode, "require-dir")) {
        assert(mkdir(path, 0700) == 0);
        if (!strcmp(mode, "full-dir")) {
            char child[PATH_MAX + 8]; snprintf(child, sizeof(child), "%s/child", path); put(child, "child");
        }
    } else if (!strcmp(mode, "require-empty")) {
        assert(mkdir(path, 0700) == 0);
        char child[PATH_MAX + 8]; snprintf(child, sizeof(child), "%s/child", path); put(child, "child");
    } else if (!strcmp(mode, "symlink")) { assert(symlink("../outside", path) == 0); }
    else { put(path, "original"); }
}

/* WHAT: Check deletion results and outside-file preservation.
 * WHY: Recursive and idempotent options must not weaken confinement or type gates.
 * HOW: Run the real orchestrator and compare its result to the fixture's contract. */
static void delete_case(ngx_log_t *log, const char *root, const char *mode, int recursive)
{
    char path[PATH_MAX], outside[PATH_MAX];
    snprintf(path, sizeof(path), "%s/target", root);
    snprintf(outside, sizeof(outside), "%s/../outside", root); put(outside, "secret");
    delete_target(mode, path);
    brix_ns_delete_opts_t options = {.recursive = recursive,
        .require_directory = !strcmp(mode, "require-dir"),
        .require_empty_dir = !strcmp(mode, "require-empty"),
        .idempotent_missing = !strcmp(mode, "idempotent")};
    brix_ns_result_t result = brix_ns_delete(log, root,
        !strcmp(mode, "outside") ? outside : path, &options);
    brix_ns_status_t expected = BRIX_NS_OK;
    if (!strcmp(mode, "missing")) { expected = BRIX_NS_NOT_FOUND; }
    if (!strcmp(mode, "outside")) {
        /* Recursive lstat uses RESOLVE_IN_ROOT: ../outside is clamped to the
         * absent root/outside. Direct unlink uses RESOLVE_BENEATH and refuses. */
        expected = recursive ? BRIX_NS_NOT_FOUND : BRIX_NS_DENIED;
    }
    if (!strcmp(mode, "require-dir")) { expected = BRIX_NS_IO_ERROR; }
    if (!strcmp(mode, "require-empty") || (!recursive && !strcmp(mode, "full-dir"))) {
        expected = BRIX_NS_NOT_EMPTY;
    }
    assert(result.status == expected);
    if (result.status == BRIX_NS_OK) { assert(access(path, F_OK) == -1); }
    if (!strcmp(mode, "require-dir")) { assert(result.sys_errno == ENOTDIR); expect(path, "original"); }
    expect(outside, "secret");
}

/* WHAT: Configure one destination precondition. WHY: Direct and staged copies agree.
 * HOW: Match real destination stat or deliberately change one compared value. */
static void precondition(const char *mode, const char *destination,
                          brix_sd_precond_t *pre)
{
    if (!strncmp(mode, "absent", 6)) { pre->kind = BRIX_SD_PRECOND_ABSENT; }
    if (!strncmp(mode, "meta-", 5)) {
        pre->kind = BRIX_SD_PRECOND_MATCH_META;
        struct stat st;
        if (stat(destination, &st) == 0) { pre->size = st.st_size; pre->mtime = st.st_mtime; }
        if (!strcmp(mode, "meta-mismatch")) { pre->size++; }
    }
    if (!strcmp(mode, "etag")) {
        pre->kind = BRIX_SD_PRECOND_MATCH_ETAG; pre->etag = "\"wrong\""; pre->etag_len = 7;
    }
    if (!strcmp(mode, "bad-kind")) { pre->kind = (brix_sd_precond_kind_t)99; }
}

/* WHAT: Set up overwrite and conditional-copy targets.
 * WHY: An absent destination must stay distinct from an existing incompatible target.
 * HOW: Create an old payload for the selected compare/replace scenarios. */
static void copy_target(const char *mode, const char *destination)
{
    if (!strcmp(mode, "destination-dir")) { assert(mkdir(destination, 0700) == 0); return; }
    const char *existing[] = {"overwrite", "no-overwrite", "absent-existing",
        "meta-match", "meta-mismatch", "etag", "bad-kind"};
    for (size_t i = 0; i < sizeof(existing) / sizeof(existing[0]); ++i) {
        if (!strcmp(mode, existing[i])) { put(destination, "old"); return; }
    }
}

/* WHAT: Assert byte publication or a precise copy refusal.
 * WHY: A failed condition must preserve the pre-existing destination.
 * HOW: Validate success bytes, classify expected conflicts and inspect old content. */
static void copy_result(brix_ns_result_t result, const char *mode, const char *destination)
{
    if (!strcmp(mode, "copy") || !strcmp(mode, "overwrite")
        || !strcmp(mode, "absent") || !strcmp(mode, "meta-match")) {
        assert(result.status == BRIX_NS_OK && result.created && result.bytes == 7);
        expect(destination, "payload"); return;
    }
    assert(result.status != BRIX_NS_OK);
    if (!strcmp(mode, "source-dir")) { assert(result.status == BRIX_NS_CONFLICT); }
    if (!strcmp(mode, "outside")) { assert(result.status == BRIX_NS_DENIED); }
    if (!strcmp(mode, "no-overwrite") || !strcmp(mode, "absent-existing")) {
        assert(result.status == BRIX_NS_EXISTS); expect(destination, "old");
    }
    if (!strcmp(mode, "meta-mismatch") || !strcmp(mode, "etag") || !strcmp(mode, "bad-kind")) {
        expect(destination, "old");
    }
}

/* WHAT: Run direct and staged copies with the same public preconditions.
 * WHY: Open-time and publish-time enforcement must produce equivalent refusals.
 * HOW: Seed bytes, choose one condition and call the real orchestrator. */
static void copy_case(ngx_log_t *log, const char *root, const char *mode, int staged)
{
    char source[PATH_MAX], destination[PATH_MAX];
    snprintf(source, sizeof(source), "%s/source", root);
    snprintf(destination, sizeof(destination), "%s/%s", root,
             !strcmp(mode, "parent-missing") ? "absent/dest" : "destination");
    if (!strcmp(mode, "source-dir")) { assert(mkdir(source, 0700) == 0); }
    else if (strcmp(mode, "source-missing")) { put(source, "payload"); }
    copy_target(mode, destination);
    brix_sd_precond_t pre = {0}; precondition(mode, destination, &pre);
    brix_ns_copy_opts_t options = {.staged_commit = staged, .preserve_xattrs = 1,
                                  .overwrite = strcmp(mode, "no-overwrite") != 0,
                                  .precond = &pre};
    if (!strcmp(mode, "io-error")) { assert(setenv("BRIX_NS_COPY_ERROR", "1", 1) == 0); }
    brix_ns_result_t result = brix_ns_local_copy(log, root, source,
        !strcmp(mode, "outside") ? "/outside" : destination, &options);
    copy_result(result, mode, destination);
    if (staged && !strcmp(mode, "io-error")) { assert(access(destination, F_OK) == -1); }
}

/* WHAT: Validate documented neutral errno categories.
 * WHY: Protocol edges rely on a single classification of syscall failures.
 * HOW: Inject a known errno and require both that exact errno and its status. */
static void errno_case(ngx_log_t *log, const char *root, const char *error)
{
    char path[PATH_MAX]; snprintf(path, sizeof(path), "%s/file", root); put(path, "payload");
    assert(setenv("BRIX_NS_UNLINK_ERROR", error, 1) == 0);
    brix_ns_delete_opts_t options = {0};
    brix_ns_result_t result = brix_ns_delete(log, root, path, &options);
    brix_ns_status_t expected = BRIX_NS_IO_ERROR;
    int value = atoi(error);
    switch (value) {
    case EACCES: case EPERM: case ELOOP: case EXDEV: expected = BRIX_NS_DENIED; break;
    case EEXIST: expected = BRIX_NS_EXISTS; break;
    case ENOTEMPTY: expected = BRIX_NS_NOT_EMPTY; break;
    case ENAMETOOLONG: expected = BRIX_NS_TOO_LONG; break;
    case ENOSPC: case EDQUOT: expected = BRIX_NS_NO_SPACE; break;
    case EBUSY: case EINVAL: expected = BRIX_NS_CONFLICT; break;
    default: break;
    }
    assert(result.status == expected && result.sys_errno == value); expect(path, "payload");
}

/* WHAT: Execute a finite namespace contract. WHY: Side effects stay in one test root.
 * HOW: Initialize host context and dispatch only the requested family. */
int main(int argc, char **argv)
{
    assert(argc == 5); ngx_log_t log = {0}; ngx_cycle_t cycle = {0};
    cycle.log = &log; ngx_cycle = &cycle; ngx_os_argv = argv;
    ngx_time_init(); assert(ngx_os_init(&log) == NGX_OK);
    if (!strcmp(argv[1], "delete")) { delete_case(&log, argv[4], argv[2], atoi(argv[3])); }
    else if (!strcmp(argv[1], "copy")) { copy_case(&log, argv[4], argv[2], atoi(argv[3])); }
    else { errno_case(&log, argv[4], argv[3]); }
    return 0;
}
