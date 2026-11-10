/* Startup rollback keeps its real confined namespace and atomic staged writes. */
#include "core/ngx_brix_module.h"
#include "protocols/root/write/chkpoint.h"
#include "core/compat/staged_file.h"
#include "core/compat/copy_range.h"
#include <assert.h>
#include <dirent.h>
#include <sys/file.h>

typedef struct { ngx_cycle_t cycle; const char *mode; int snapshot; } fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }
int __real_brix_vfs_open_fd(ngx_log_t *, const char *, const char *, int, mode_t);
int __wrap_brix_vfs_open_fd(ngx_log_t *log, const char *root, const char *path, int flags, mode_t permissions)
{
    if ((mode("root-open") && !strcmp(root, path)) || (mode("snapshot-open") && strstr(path, ".ckp"))) {
        errno = EIO; return -1;
    }
    if (strstr(path, "/child") && strncmp(state()->mode, "child-", 6) == 0) {
        errno = atoi(state()->mode + 6); return -1;
    }
    int fd = __real_brix_vfs_open_fd(log, root, path, flags, permissions);
    if (strstr(path, ".ckp")) { state()->snapshot = fd; }
    return fd;
}
int __real_fstat64(int, struct stat64 *);
int __wrap_fstat64(int fd, struct stat64 *st)
{
    if (mode("snapshot-stat") && fd == state()->snapshot) { errno = EIO; return -1; }
    int rc = __real_fstat64(fd, st);
    if (!rc && mode("snapshot-type") && fd == state()->snapshot) { st->st_mode = S_IFDIR | 0700; }
    return rc;
}
int __real_fstatat64(int, const char *, struct stat64 *, int);
int __wrap_fstatat64(int fd, const char *name, struct stat64 *st, int flags)
{ if (mode("entry-stat") && strstr(name, ".ckp")) { errno = ENOENT; return -1; } return __real_fstatat64(fd, name, st, flags); }
DIR *__real_fdopendir(int);
DIR *__wrap_fdopendir(int fd)
{ if (mode("fdopendir")) { errno = EMFILE; return NULL; } return __real_fdopendir(fd); }
int __real_dirfd(DIR *);
int __wrap_dirfd(DIR *dir)
{ if (mode("dirfd")) { errno = EBADF; return -1; } return __real_dirfd(dir); }
int __real_flock(int, int);
int __wrap_flock(int fd, int operation)
{ if (mode("lock") && operation == LOCK_EX) { errno = EIO; return -1; } return __real_flock(fd, operation); }
ngx_int_t __real_brix_staged_open(ngx_log_t *, const brix_staged_open_req_t *, brix_staged_file_t *);
ngx_int_t __wrap_brix_staged_open(ngx_log_t *log, const brix_staged_open_req_t *request, brix_staged_file_t *staged)
{ if (mode("stage")) { errno = ENOSPC; return NGX_ERROR; } return __real_brix_staged_open(log, request, staged); }
ngx_int_t __real_brix_copy_range(ngx_log_t *, int, off_t, int, off_t, size_t, const char *, const char *);
ngx_int_t __wrap_brix_copy_range(ngx_log_t *log, int from, off_t source, int to, off_t destination,
    size_t length, const char *source_path, const char *destination_path)
{
    if (mode("copy")) { errno = EIO; return NGX_ERROR; }
    return __real_brix_copy_range(log, from, source, to, destination, length, source_path, destination_path);
}
int __real_brix_rename_beneath(int, const char *, const char *);
int __wrap_brix_rename_beneath(int rootfd, const char *from, const char *to)
{ if (mode("commit")) { errno = EIO; return -1; } return __real_brix_rename_beneath(rootfd, from, to); }
int __real_brix_vfs_unlink_path(ngx_log_t *, const char *, const char *);
int __wrap_brix_vfs_unlink_path(ngx_log_t *log, const char *root, const char *path)
{ if (mode("unlink") && strstr(path, ".ckp")) { errno = EIO; return -1; } return __real_brix_vfs_unlink_path(log, root, path); }
int main(int argc, char **argv)
{
    assert(argc == 3); fixture f = {0}; f.mode = argv[1]; f.snapshot = -1; ngx_cycle = &f.cycle;
    ngx_log_t log = {0}; ngx_open_file_t file = {.fd=STDERR_FILENO}; log.file = &file;
    f.cycle.log = &log; ngx_time_init();
    int rc = brix_chkpoint_recover_root(&log, argv[2]);
    if (f.snapshot >= 0) { assert(fcntl(f.snapshot, F_GETFD) == -1 && errno == EBADF); }
    printf("%d\n", rc); ngx_cycle = NULL; return 0;
}
