/* Actual confined staging and publication, with finite syscall boundary failures. */
#include "core/compat/staged_file.h"
#include "core/compat/crypto.h"
#include "fs/path/beneath.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int __real_fsync(int);
int __real_brix_open_beneath(int, const char *, int, mode_t);

/* WHAT: Fail the data or directory durability barrier independently.
 * WHY: Both failures must surface, despite differing publication state.
 * HOW: Classify the real descriptor before injecting one EIO. */
int __wrap_fsync(int fd)
{
    const char *fault = getenv("BRIX_STAGE_FAULT");
    struct stat st;
    assert(fstat(fd, &st) == 0);
    if (fault != NULL && ((!strcmp(fault, "fsync") && S_ISREG(st.st_mode))
                         || (!strcmp(fault, "dirsync") && S_ISDIR(st.st_mode)))) {
        assert(unsetenv("BRIX_STAGE_FAULT") == 0); errno = EIO; return -1;
    }
    return __real_fsync(fd);
}

/* WHAT: Exhaust exclusive-create collisions. WHY: Retry count must be bounded.
 * HOW: Return EEXIST only for private O_EXCL creates while the fixture is armed. */
int __wrap_brix_open_beneath(int root, const char *path, int flags, mode_t mode)
{
    if (getenv("BRIX_STAGE_COLLISION") != NULL && (flags & O_EXCL)) {
        errno = EEXIST; return -1;
    }
    return __real_brix_open_beneath(root, path, flags, mode);
}

/* WHAT: Require a closed, inactive stage. WHY: Failure cannot leak its descriptor.
 * HOW: Check the public ownership fields after every commit/abort. */
static void closed_stage(const brix_staged_file_t *stage)
{
    assert(!stage->active && stage->fd == NGX_INVALID_FILE);
}

/* WHAT: Assert exact published bytes and permissions. WHY: Publication restores mode.
 * HOW: Read through a real fd and compare metadata after closing the stage. */
static void published(const char *path)
{
    char data[8] = {0}; struct stat st;
    int fd = open(path, O_RDONLY); assert(fd >= 0);
    assert(read(fd, data, sizeof(data)) == 7 && !memcmp(data, "payload", 7));
    assert(fstat(fd, &st) == 0 && (st.st_mode & 0777) == 0640); close(fd);
}

/* WHAT: Test publish outcomes with real confined rename and fsync.
 * WHY: An exclusive conflict, early flush failure and late barrier differ.
 * HOW: Set up one condition, commit, check ownership and visible bytes. */
static void commit_case(ngx_log_t *log, brix_staged_open_req_t *req,
                         brix_staged_file_t *stage, const char *mode)
{
    char saved[PATH_MAX]; strcpy(saved, stage->tmp_path);
    int conflict = !strcmp(mode, "exclusive-exists");
    if (conflict || !strcmp(mode, "rename")) { assert(mkdir(req->final_path, 0700) == 0); }
    if (!strcmp(mode, "fsync") || !strcmp(mode, "dirsync")) {
        assert(setenv("BRIX_STAGE_FAULT", mode, 1) == 0);
    }
    if (!strcmp(mode, "closed-fd")) {
        assert(fchmod(stage->fd, req->mode) == 0);
        close(stage->fd); stage->fd = NGX_INVALID_FILE;
    }
    ngx_int_t rc = !strncmp(mode, "exclusive", 9)
        ? brix_staged_commit_excl(log, req->root_canon, stage, req->final_path)
        : brix_staged_commit(log, req->root_canon, stage, req->final_path);
    int bad = conflict || !strcmp(mode, "rename") || !strcmp(mode, "fsync")
              || !strcmp(mode, "dirsync");
    assert(rc == (bad ? NGX_ERROR : NGX_OK));
    closed_stage(stage); assert(access(saved, F_OK) == -1 && errno == ENOENT);
    if (!bad || !strcmp(mode, "dirsync")) { published(req->final_path); }
    if (!strcmp(mode, "fsync")) { assert(access(req->final_path, F_OK) == -1); }
    assert(getenv("BRIX_STAGE_FAULT") == NULL);
}

/* WHAT: Exercise invalid commit confinement and abort disposition.
 * WHY: A bad final/root path must never create a file outside the export.
 * HOW: Keep the original temp pathname to inspect and explicitly remove leftovers. */
static void lifecycle_refusal(ngx_log_t *log, brix_staged_open_req_t *req,
                               brix_staged_file_t *stage, const char *mode)
{
    char saved[PATH_MAX], outside[PATH_MAX]; strcpy(saved, stage->tmp_path);
    snprintf(outside, sizeof(outside), "%s/../outside", req->root_canon);
    if (!strncmp(mode, "abort-", 6)) {
        const char *root = !strcmp(mode, "abort-outside") ? "/no-such-export" : req->root_canon;
        brix_staged_abort(log, root, stage, strcmp(mode, "abort-retain") != 0);
        closed_stage(stage);
        assert((access(saved, F_OK) == 0) == (strcmp(mode, "abort-remove") != 0));
        unlink(saved); return;
    }
    const char *root = req->root_canon, *final = outside;
    if (!strcmp(mode, "commit-root-missing")) { root = "/no-such-export"; final = req->final_path; }
    if (!strcmp(mode, "commit-temp-outside")) { strcpy(stage->tmp_path, "/outside"); final = req->final_path; }
    assert(brix_staged_commit(log, root, stage, final) == NGX_ERROR);
    closed_stage(stage); assert(access(outside, F_OK) == -1);
    unlink(saved);
}

/* WHAT: Preserve resume bytes and isolate identity-keyed partials.
 * WHY: A later request may resume only its own upload, including external staging.
 * HOW: Close without deletion, reopen, check length/content and refuse a symlink. */
static void resume_case(ngx_log_t *log, brix_staged_open_req_t *req, const char *mode)
{
    brix_staged_file_t stage; off_t length = -1;
    if (strcmp(mode, "resume")) { req->stage_dir = req->root_canon; }
    req->principal = "user-one";
    assert(brix_staged_open_resume(log, req, &stage, &length) == NGX_OK && length == 0);
    assert(write(stage.fd, "payload", 7) == 7);
    char saved[PATH_MAX]; strcpy(saved, stage.tmp_path);
    brix_staged_abort(log, req->root_canon, &stage, 0);
    if (!strcmp(mode, "resume-symlink")) {
        assert(unlink(saved) == 0 && symlink("../outside", saved) == 0);
        assert(brix_staged_open_resume(log, req, &stage, &length) == NGX_ERROR);
        assert(errno == ELOOP); unlink(saved); return;
    }
    assert(brix_staged_open_resume(log, req, &stage, &length) == NGX_OK && length == 7);
    char data[8] = {0}; assert(read(stage.fd, data, sizeof(data)) == 7 && !strcmp(data, "payload"));
    brix_staged_abort(log, req->root_canon, &stage, 0);
    req->principal = "user-two";
    assert(brix_staged_open_resume(log, req, &stage, NULL) == NGX_OK);
    assert(strcmp(saved, stage.tmp_path));
    brix_staged_abort(log, req->root_canon, &stage, 1); unlink(saved);
}

/* WHAT: Check nullable arguments and inactive stages. WHY: Bad callers cannot mutate.
 * HOW: Select one invalid API input and require EINVAL without a live descriptor. */
static void null_case(ngx_log_t *log, brix_staged_open_req_t *req, const char *mode)
{
    brix_staged_file_t stage = {.fd = NGX_INVALID_FILE};
    if (!strcmp(mode, "null-request")) {
        assert(brix_staged_open(log, NULL, &stage) == NGX_ERROR && errno == EINVAL);
        assert(brix_staged_open_resume(log, NULL, &stage, NULL) == NGX_ERROR && errno == EINVAL);
    } else if (!strcmp(mode, "null-stage")) {
        assert(brix_staged_open(log, req, NULL) == NGX_ERROR && errno == EINVAL);
        assert(brix_staged_open_resume(log, req, NULL, NULL) == NGX_ERROR && errno == EINVAL);
    } else if (!strcmp(mode, "null-path")) {
        req->final_path = NULL;
        assert(brix_staged_open(log, req, &stage) == NGX_ERROR && errno == EINVAL);
        assert(brix_staged_open_resume(log, req, &stage, NULL) == NGX_ERROR && errno == EINVAL);
    } else {
        assert(brix_staged_commit(log, req->root_canon,
            !strcmp(mode, "null-commit") ? NULL : &stage, req->final_path) == NGX_ERROR);
        assert(errno == EINVAL);
    }
    brix_staged_abort(log, req->root_canon, NULL, 1);
}

/* WHAT: Refuse failed/escaping opens and bounded collision exhaustion.
 * WHY: A temporary upload must always remain inside its selected confinement root.
 * HOW: Alter one request field or create error and assert a closed error result. */
static void open_refusal(ngx_log_t *log, brix_staged_open_req_t *req, const char *mode)
{
    char longpath[PATH_MAX + 128]; memset(longpath, 'a', sizeof(longpath) - 1);
    longpath[sizeof(longpath) - 1] = '\0';
    if (strstr(mode, "long")) { req->final_path = longpath; }
    if (strstr(mode, "outside")) { req->final_path = "/outside"; }
    if (strstr(mode, "root-missing")) { req->root_canon = "/no-such-export"; }
    if (!strcmp(mode, "collision")) {
        req->attempts = 2; assert(setenv("BRIX_STAGE_COLLISION", "1", 1) == 0);
    }
    brix_staged_file_t stage; off_t length = -1;
    int rc = !strncmp(mode, "resume-", 7)
        ? brix_staged_open_resume(log, req, &stage, &length)
        : brix_staged_open(log, req, &stage);
    assert(rc == NGX_ERROR); closed_stage(&stage);
    if (!strcmp(mode, "collision")) { assert(errno == EEXIST); unsetenv("BRIX_STAGE_COLLISION"); }
}

/* WHAT: Exercise parent-directory synchronization errors.
 * WHY: Missing parents and absent anchors must not be reported as durable.
 * HOW: Pass a null path, an absent parent, or an absent export root. */
static void dirsync_refusal(ngx_log_t *log, const char *root, const char *mode)
{
    const char *path = "absent/final";
    if (!strcmp(mode, "dirsync-null")) { path = NULL; }
    if (!strcmp(mode, "dirsync-root-missing")) { root = "/no-such-export"; path = "final"; }
    assert(brix_publish_dirsync(log, -1, root, path) == NGX_ERROR);
}

/* WHAT: Execute one actual staging lifecycle. WHY: No global fixture state leaks.
 * HOW: Initialize nginx's host context, build a request and select one finite case. */
int main(int argc, char **argv)
{
    assert(argc == 3); ngx_log_t log = {0}; ngx_cycle_t cycle = {0};
    cycle.log = &log; ngx_cycle = &cycle; ngx_os_argv = argv;
    ngx_time_init(); assert(ngx_os_init(&log) == NGX_OK);
    assert(brix_crypto_init() == 1);
    char final[PATH_MAX]; snprintf(final, sizeof(final), "%s/final", argv[2]);
    brix_staged_open_req_t req = {.root_canon = argv[2], .final_path = final,
                                 .mode = 0640, .open_flags = O_WRONLY};
    const char *mode = argv[1];
    if (!strncmp(mode, "null-", 5) || !strcmp(mode, "inactive-commit")) { null_case(&log, &req, mode); }
    else if (!strncmp(mode, "open-", 5) || !strcmp(mode, "collision")
             || strstr(mode, "resume-long") || strstr(mode, "resume-outside")
             || strstr(mode, "resume-root-missing")) { open_refusal(&log, &req, mode); }
    else if (!strncmp(mode, "resume", 6)) { resume_case(&log, &req, mode); }
    else if (!strncmp(mode, "dirsync-", 8)) { dirsync_refusal(&log, argv[2], mode); }
    else {
        brix_staged_file_t stage; struct stat st;
        assert(brix_staged_open(&log, &req, &stage) == NGX_OK);
        assert(fstat(stage.fd, &st) == 0 && (st.st_mode & 0777) == 0600);
        assert(write(stage.fd, "payload", 7) == 7);
        if (!strncmp(mode, "abort-", 6) || !strncmp(mode, "commit-", 7)) {
            lifecycle_refusal(&log, &req, &stage, mode);
        } else { commit_case(&log, &req, &stage, mode); }
    }
    brix_crypto_cleanup();
    return 0;
}
