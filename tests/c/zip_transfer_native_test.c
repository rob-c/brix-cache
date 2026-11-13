/* Real ZIP copy orchestration with bounded, fd-backed remote file operations. */
#include "xfer/copy_internal.h"
#include <assert.h>

typedef struct {
    const char *mode, *remote;
    int remote_fd, sink_fd;
    unsigned connected, closed, opened, file_closed, reads, writes, sink_writes;
} fixture;
static fixture *state(void)
{
    return (fixture *)(uintptr_t) strtoull(getenv("BRIX_ZIP_TRANSFER_STATE"), NULL, 16);
}
static int mode(const char *name) { return strcmp(state()->mode, name) == 0; }
static int refused(brix_status *st, const char *operation)
{
    brix_status_set(st, XRDC_ESOCK, EIO, "%s refused", operation); return -1;
}

int __wrap_brix_connect(brix_conn *c, const brix_url *u, const brix_opts *o,
                        brix_status *st)
{
    (void) u; (void) o;
    if (mode("connect")) { return refused(st, "connect"); }
    memset(c, 0, sizeof(*c)); state()->connected++; return 0;
}
void __wrap_brix_close(brix_conn *c)
{
    (void) c; state()->closed++;
    assert(state()->closed == state()->connected);
}
int __wrap_brix_stat(brix_conn *c, const char *path, brix_statinfo *out, brix_status *st)
{
    (void) c; (void) path;
    struct stat sb;
    if (mode("stat") || stat(state()->remote, &sb) != 0) { return refused(st, "stat"); }
    memset(out, 0, sizeof(*out)); out->size = sb.st_size; return 0;
}
static int open_remote(brix_file *file, int flags, brix_status *st, const char *kind)
{
    fixture *f = state();
    if (mode("open")) { return refused(st, "open"); }
    assert(f->remote_fd == -1);
    f->remote_fd = open(f->remote, flags, 0600);
    assert(f->remote_fd >= 0);
    memset(file, 0, sizeof(*file)); f->opened++;
    fprintf(stderr, "open=%s\n", kind); return 0;
}
int __wrap_brix_file_open_read(brix_conn *c, const char *path, brix_file *f, brix_status *st)
{
    (void) c; (void) path; return open_remote(f, O_RDONLY, st, "read");
}
int __wrap_brix_file_open_update(brix_conn *c, const char *path, int posc,
                                brix_file *f, brix_status *st)
{
    (void) c; (void) path; assert(posc == 0); return open_remote(f, O_RDWR, st, "update");
}
int __wrap_brix_file_open_write(brix_conn *c, const char *path, int force, int posc,
                               brix_file *f, brix_status *st)
{
    (void) c; (void) path; assert(force == 1 && posc == 0);
    return open_remote(f, O_RDWR | O_CREAT | O_TRUNC, st, "write");
}
ssize_t __wrap_brix_file_read(brix_conn *c, brix_file *file, int64_t offset,
                             void *buffer, size_t length, brix_status *st)
{
    (void) c; (void) file; fixture *f = state(); f->reads++;
    assert(f->reads < 100);
    if (mode("read")) { return refused(st, "read"); }
    return pread(f->remote_fd, buffer, length, (off_t) offset);
}
int __wrap_brix_file_write(brix_conn *c, brix_file *file, int64_t offset,
                           const void *buffer, size_t length, brix_status *st)
{
    (void) c; (void) file; fixture *f = state(); f->writes++;
    assert(f->writes < 100);
    if (mode("write") || mode("write-close")) { return refused(st, "write"); }
    assert(pwrite(f->remote_fd, buffer, length, (off_t) offset) == (ssize_t) length);
    return 0;
}
int __wrap_brix_file_close(brix_conn *c, brix_file *file, brix_status *st)
{
    (void) c; (void) file; fixture *f = state();
    assert(f->remote_fd >= 0 && close(f->remote_fd) == 0);
    f->remote_fd = -1; f->file_closed++;
    if (mode("close") || mode("write-close")) { return refused(st, "close"); }
    return 0;
}
int __real_open_download_temp(const char *, char *, size_t, brix_status *);
int __wrap_open_download_temp(const char *dest, char *temp, size_t cap, brix_status *st)
{
    int fd = __real_open_download_temp(dest, temp, cap, st); state()->sink_fd = fd; return fd;
}
ssize_t __real_write(int, const void *, size_t);
ssize_t __wrap_write(int fd, const void *buffer, size_t length)
{
    if (getenv("BRIX_ZIP_TRANSFER_STATE") == NULL) { return __real_write(fd, buffer, length); }
    fixture *f = state();
    if (fd != f->sink_fd) { return __real_write(fd, buffer, length); }
    f->sink_writes++; assert(f->sink_writes < 100000);
    if (mode("sink-error")) { errno = ENOSPC; return -1; }
    if (mode("sink-intr") && f->sink_writes == 1) { errno = EINTR; return -1; }
    if (mode("sink-short") && length > 7) { length = 7; }
    return __real_write(fd, buffer, length);
}
int __real_rename(const char *, const char *);
int __wrap_rename(const char *old, const char *dest)
{
    if (mode("rename")) { errno = EACCES; return -1; }
    return __real_rename(old, dest);
}

static int execute(int argc, char **argv)
{
    assert(argc == 9);
    brix_url source = {0}, dest = {0}; brix_opts options = {0};
    brix_copy_opts copy = {0}; brix_status status = {0};
    fixture f = {.mode = argv[4], .remote_fd = -1, .sink_fd = -1};
    char pointer[32]; int result;
    snprintf(pointer, sizeof(pointer), "%llx", (unsigned long long) (uintptr_t) &f);
    assert(setenv("BRIX_ZIP_TRANSFER_STATE", pointer, 1) == 0);
    snprintf(source.path, sizeof(source.path), "%s", argv[2]);
    snprintf(dest.path, sizeof(dest.path), "%s", argv[3]);
    copy.force = atoi(argv[5]); copy.zip_append = atoi(argv[6]);
    source.scheme = XRDC_SCHEME_LOCAL; dest.scheme = XRDC_SCHEME_LOCAL;
    if (!strcmp(argv[1], "unzip")) {
        f.remote = argv[2]; source.scheme = XRDC_SCHEME_ROOT;
        if (mode("stdout")) { dest.scheme = XRDC_SCHEME_STDIO; f.sink_fd = STDOUT_FILENO; }
        result = copy_unzip(&source, source.path, argv[8], &dest, &copy, &options, &status);
    } else {
        assert(!strcmp(argv[1], "store") || !strcmp(argv[1], "remote"));
        f.remote = argv[3];
        if (!strcmp(argv[1], "remote")) { dest.scheme = XRDC_SCHEME_ROOT; }
        if (mode("stdin")) { source.scheme = XRDC_SCHEME_STDIO; }
        result = copy_zip_store(&source, &dest, &copy, &options, &status);
    }
    fprintf(stderr, "result=%d connect=%u close=%u open=%u fileclose=%u reads=%u writes=%u\n%s\n",
        result, f.connected, f.closed, f.opened, f.file_closed, f.reads, f.writes, status.msg);
    assert(result == atoi(argv[7]));
    assert(f.connected == f.closed && f.opened == f.file_closed && f.remote_fd == -1);
    if (f.sink_fd > STDERR_FILENO) { assert(fcntl(f.sink_fd, F_GETFD) == -1 && errno == EBADF); }
    assert(unsetenv("BRIX_ZIP_TRANSFER_STATE") == 0);
    return 0;
}
int main(int argc, char **argv) { return execute(argc, argv); }
