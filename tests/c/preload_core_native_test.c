/* Real preload routing/shadow descriptors, with private names for libc exports. */
#include "brix.h"
#include "../../client/preload/brixposix_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#define DECLARE(name) extern __typeof__(name) probe_##name;
DECLARE(open) DECLARE(openat) DECLARE(read) DECLARE(pread) DECLARE(write)
DECLARE(pwrite) DECLARE(lseek) DECLARE(close) DECLARE(stat) DECLARE(lstat)
DECLARE(fstat) DECLARE(fstatat) DECLARE(access)
DECLARE(opendir) DECLARE(readdir) DECLARE(closedir) DECLARE(rewinddir)
DECLARE(telldir) DECLARE(seekdir) DECLARE(dirfd) DECLARE(fopen) DECLARE(freopen)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
DECLARE(readdir_r)
#pragma GCC diagnostic pop

/* WHAT: Select a remote fault. WHY: Keep each process independent. HOW: Env. */
static int fault(const char *name) { return !strcmp(getenv("BRIX_PRELOAD_FAULT"), name); }

/* WHAT: Count boundary calls. WHY: Check reuse and refusals. HOW: Fixed env buffer. */
static unsigned count(const char *name)
{
    const char *old = getenv(name); char value[32];
    unsigned n = old ? (unsigned) atoi(old) : 0;
    snprintf(value, sizeof(value), "%u", n + 1); assert(setenv(name, value, 1) == 0);
    return n;
}

/* WHAT: Return a real protocol denial. WHY: Test errno normalization. HOW: Status. */
static int denied(brix_status *st)
{
    brix_status_set(st, kXR_NotAuthorized, 0, "finite denial"); return -1;
}

void *__real_calloc(size_t, size_t);
/* WHAT: Fail one directory allocation. WHY: Refusal must not fetch remote data.
 * HOW: A one-shot arm leaves all unrelated library allocations unaffected. */
void *__wrap_calloc(size_t n, size_t size)
{
    if (getenv("BRIX_PRELOAD_ALLOC")) {
        assert(unsetenv("BRIX_PRELOAD_ALLOC") == 0); errno = ENOMEM; return NULL;
    }
    return __real_calloc(n, size);
}

FILE *__real_fopencookie(void *, const char *, cookie_io_functions_t);
/* WHAT: Fail creation of a real FILE wrapper. WHY: Its shadow fd must close.
 * HOW: Inject ENOMEM at the libc cookie constructor boundary. */
FILE *__wrap_fopencookie(void *cookie, const char *mode, cookie_io_functions_t functions)
{
    if (fault("cookie")) { errno = ENOMEM; return NULL; }
    return __real_fopencookie(cookie, mode, functions);
}

/* WHAT: Supply a directory snapshot. WHY: Test type/inode synthesis and cursors.
 * HOW: Known entries with/without metadata, or an explicit authorization denial. */
int __wrap_brix_dirlist(brix_conn *c, const char *path, int want_stat,
    brix_dirent **out, size_t *size, brix_status *st)
{
    brix_dirent *entries;
    assert(c == &g_conn && !strcmp(path, "/base/file") && want_stat == 1);
    count("BRIX_PRELOAD_LIST");
    if (fault("listing")) { return denied(st); }
    entries = calloc(3, sizeof(*entries)); assert(entries != NULL);
    snprintf(entries[0].name, sizeof(entries[0].name), "file");
    entries[0].have_stat = 1; entries[0].st.id = 42;
    snprintf(entries[1].name, sizeof(entries[1].name), "folder");
    entries[1].have_stat = 1; entries[1].st.flags = kXR_isDir;
    snprintf(entries[2].name, sizeof(entries[2].name), "unknown");
    *out = entries; *size = fault("empty") ? 0 : 3; return 0;
}

/* WHAT: Observe lazy connections. WHY: Prefix routing must not dial elsewhere.
 * HOW: Validate parsed endpoint and count reconnect attempts. */
int __wrap_brix_connect(brix_conn *c, const brix_url *url, const brix_opts *opts, brix_status *st)
{
    assert(c == &g_conn && opts == NULL && !strcmp(url->host, "fixture.invalid"));
    count("BRIX_PRELOAD_CONNECT"); return fault("connect") ? denied(st) : 0;
}

/* WHAT: Simulate an inherited unusable session. WHY: Fresh opens must reconnect.
 * HOW: Refuse just the first reuse probe. */
int __wrap_brix_conn_usable(const brix_conn *c)
{
    assert(c == &g_conn); return !(fault("fork") && count("BRIX_PRELOAD_USABLE") == 0);
}

/* WHAT: Observe remote read opens. WHY: Mapping and read policy must survive.
 * HOW: Check canonical path and seed the real shadow slot's borrowed handle. */
int __wrap_brix_rfile_open_read(brix_conn *c, const char *path, const char *opaque,
    int pgrw, int stall, brix_rfile *file, brix_status *st)
{
    assert(c == &g_conn && opaque == NULL && pgrw == 0 && stall == -1);
    assert(!strcmp(path, "/base/file")); count("BRIX_PRELOAD_OPEN");
    file->c = c; return fault("open") ? denied(st) : 0;
}

/* WHAT: Observe write force selection. WHY: POSIX create/truncate differ.
 * HOW: Compare the expected force and preserve the handle identity. */
int __wrap_brix_rfile_open_write(brix_conn *c, const char *path, int force, int posc,
    int pgrw, int stall, brix_rfile *file, brix_status *st)
{
    assert(c == &g_conn && !strcmp(path, "/base/file") && !posc && !pgrw && stall == -1);
    assert(force == atoi(getenv("BRIX_PRELOAD_FORCE"))); count("BRIX_PRELOAD_OPEN");
    file->c = c; return fault("open") ? denied(st) : 0;
}

/* WHAT: Supply metadata. WHY: Stat failures must not fabricate successful metadata.
 * HOW: Known regular-file size or a protocol authorization failure. */
int __wrap_brix_stat(brix_conn *c, const char *path, brix_statinfo *si, brix_status *st)
{
    assert(c == &g_conn && !strcmp(path, "/base/file")); count("BRIX_PRELOAD_STAT");
    if (fault("stat")) { return denied(st); }
    memset(si, 0, sizeof(*si)); si->size = 10; si->id = 42; return 0;
}

/* WHAT: Supply offset-dependent reads. WHY: pread cannot advance the shared cursor.
 * HOW: Exact expected data, EOF clipping and one explicit remote error. */
ssize_t __wrap_brix_rfile_pread(brix_rfile *file, int64_t off, void *buf, size_t len, brix_status *st)
{
    assert(file->c == &g_conn && off >= 0); count("BRIX_PRELOAD_READ");
    if (fault("read")) { return denied(st); }
    if (off >= 10) { return 0; }
    if (len > 10 - (size_t) off) { len = 10 - (size_t) off; }
    memcpy(buf, "abcdefghij" + off, len); return (ssize_t) len;
}

/* WHAT: Observe writes. WHY: Sequential and explicit offsets must differ.
 * HOW: Require source bytes and their known offsets before returning status. */
int __wrap_brix_rfile_pwrite(brix_rfile *file, int64_t off, const void *buf, size_t len, brix_status *st)
{
    assert(file->c == &g_conn && off >= 0 && off <= 6 && len == 2);
    assert(!memcmp(buf, "abcdefghij" + off, len)); count("BRIX_PRELOAD_WRITE");
    return fault("write") ? denied(st) : 0;
}

/* WHAT: Observe close release. WHY: A slot must become reusable even on failure.
 * HOW: Track calls and leave actual shadow-table ownership to production. */
int __wrap_brix_rfile_close(brix_rfile *file, brix_status *st)
{
    assert(file->c == &g_conn); count("BRIX_PRELOAD_CLOSE");
    return fault("close") ? denied(st) : 0;
}

/* WHAT: Exercise read cursor/metadata semantics. WHY: Shadow fd behavior is POSIX.
 * HOW: Compare bytes, seeks, wrong-direction errors and a second lazy open. */
static void reads(int fd)
{
    char data[8]; struct stat info; ssize_t n;
    assert(probe_fstat(fd, &info) == 0 && S_ISREG(info.st_mode));
    assert(info.st_size == (fault("stat") ? 0 : 10));
    n = probe_read(fd, data, 2);
    if (fault("read")) {
        assert(n == -1 && errno == EACCES);
        assert(probe_pread(fd, data, 2, 4) == -1 && errno == EACCES);
        assert(probe_lseek(fd, 0, SEEK_CUR) == 0); return;
    }
    assert(n == 2 && !memcmp(data, "ab", 2));
    assert(probe_pread(fd, data, 2, 4) == 2 && !memcmp(data, "ef", 2));
    assert(probe_lseek(fd, 0, SEEK_CUR) == 2);
    assert(probe_lseek(fd, 1, SEEK_SET) == 1 && probe_lseek(fd, 2, SEEK_CUR) == 3);
    assert(probe_lseek(fd, -1, SEEK_END) == (fault("stat") ? -1 : 9));
    assert(probe_lseek(fd, 0, 12345) == -1 && errno == EINVAL);
    assert(probe_write(fd, "ab", 2) == -1 && errno == EBADF);
    assert(probe_pwrite(fd, "ab", 2, 0) == -1 && errno == EBADF);
}

/* WHAT: Exercise write-only cursor semantics. WHY: Failed writes cannot advance.
 * HOW: Sequential and explicit writes are checked at the transport boundary. */
static void writes(int fd)
{
    char data[4]; ssize_t n = probe_write(fd, "ab", 2);
    if (fault("write")) {
        assert(n == -1 && errno == EACCES);
        assert(probe_pwrite(fd, "cd", 2, 2) == -1 && errno == EACCES);
        assert(probe_lseek(fd, 0, SEEK_CUR) == 0);
    } else {
        assert(n == 2 && probe_pwrite(fd, "ef", 2, 4) == 2);
        assert(probe_lseek(fd, 0, SEEK_CUR) == 2);
        assert(probe_write(fd, "cd", 2) == 2);
    }
    assert(probe_read(fd, data, 2) == -1 && errno == EBADF);
    assert(probe_pread(fd, data, 2, 0) == -1 && errno == EBADF);
}

/* WHAT: Check mapped metadata entry points. WHY: Errors must preserve errno.
 * HOW: All path variants observe the same remote stat policy. */
static void metadata(const char *path, int expected)
{
    struct stat info;
    assert(probe_stat(path, &info) == expected);
    assert(probe_lstat(path, &info) == expected);
    assert(probe_fstatat(-1, path, &info, AT_SYMLINK_NOFOLLOW) == expected);
    assert(probe_access(path, R_OK) == expected);
    if (expected) { assert(errno == (fault("connect") ? EIO : EACCES)); }
    else { assert(info.st_size == 10 && S_ISREG(info.st_mode)); }
}

/* WHAT: Exhaust and reuse the bounded table. WHY: EMFILE must not deadlock.
 * HOW: Fill all slots, release one, then require the same descriptor is reused. */
static void exhausted(void)
{
    int fds[XFS_FD_MAX], replacement;
    for (int i = 0; i < XFS_FD_MAX; i++) { fds[i] = probe_open("/v/file", O_RDONLY); assert(fds[i] >= XFS_FD_BASE); }
    assert(probe_open("/v/file", O_RDONLY) == -1 && errno == EMFILE);
    assert(probe_close(fds[0]) == 0); replacement = probe_open("/v/file", O_RDONLY);
    assert(replacement == fds[0]);
    for (int i = 0; i < XFS_FD_MAX; i++) { assert(probe_close(fds[i]) == 0); }
}

/* WHAT: Check directory cursor and inode contracts. WHY: Callers cannot infer fd.
 * HOW: Read a known snapshot, rewind/seek it and preserve errno at EOF. */
static void directory_entries(DIR *dir)
{
    struct dirent *entry, copy, *result = NULL;
    size_t expected = fault("empty") ? 2 : 5, index = 0;
    while ((entry = probe_readdir(dir)) != NULL) {
        assert(entry->d_ino != 0);
        if (index == 2) { assert(entry->d_ino == 42 && entry->d_type == DT_REG); }
        if (index == 3) { assert(entry->d_type == DT_DIR && !strcmp(entry->d_name, "folder")); }
        if (index == 4) { assert(entry->d_type == DT_UNKNOWN); }
        index++;
    }
    assert(index == expected && probe_telldir(dir) == (long) expected);
    errno = ENOSPC; assert(probe_readdir(dir) == NULL && errno == ENOSPC);
    assert(probe_dirfd(dir) == -1 && errno == ENOTSUP);
    probe_rewinddir(dir); assert(probe_telldir(dir) == 0);
    probe_seekdir(dir, 1); probe_seekdir(dir, -1); assert(probe_telldir(dir) == 1);
    assert(probe_readdir_r(dir, &copy, &result) == 0 && result == &copy && !strcmp(copy.d_name, ".."));
    probe_seekdir(dir, 100); assert(probe_readdir_r(dir, &copy, &result) == 0 && result == NULL);
}

/* WHAT: Exercise remote directory creation/errors/table limits.
 * WHY: A failed or exhausted listing must not remain registered.
 * HOW: Fill and release the real bounded registry, with exact error assertions. */
static void directories(const char *path, int error)
{
    DIR *dir; char mapped[128];
    assert(map_path(path, mapped, sizeof(mapped)) == 1);
    if (fault("allocation")) { assert(setenv("BRIX_PRELOAD_ALLOC", "1", 1) == 0); }
    dir = probe_opendir(path);
    if (error) { assert(dir == NULL && errno == error); return; }
    assert(dir != NULL); directory_entries(dir); assert(probe_closedir(dir) == 0);
    if (fault("dir-full")) {
        DIR *dirs[128];
        for (int i = 0; i < 128; i++) { dirs[i] = probe_opendir(path); assert(dirs[i]); }
        assert(probe_opendir(path) == NULL && errno == EMFILE);
        for (int i = 0; i < 128; i++) { assert(probe_closedir(dirs[i]) == 0); }
        dir = probe_opendir(path); assert(dir && probe_closedir(dir) == 0);
    }
}

/* WHAT: Validate libc buffering over a shadow fd. WHY: fread/fwrite use cookies.
 * HOW: Known bytes, explicit flush/seek and selected read/write failures. */
static void stream_io(FILE *stream, const char *mode)
{
    char data[12] = {0};
    if (mode[0] == 'w') {
        assert(fwrite("ab", 1, 2, stream) == 2);
        if (fault("write")) { assert(fflush(stream) == EOF && ferror(stream)); }
        else { assert(fflush(stream) == 0); }
    } else if (fault("read")) {
        assert(fread(data, 1, 2, stream) == 0 && ferror(stream));
    } else {
        assert(fread(data, 1, 10, stream) == 10 && !memcmp(data, "abcdefghij", 10));
        assert(fgetc(stream) == EOF && feof(stream));
        assert(fseek(stream, 3, SEEK_SET) == 0 && fgetc(stream) == 'd');
    }
}

/* WHAT: Check stdio refusal and cleanup. WHY: Unsupported remote modes must not
 * create local shadows. HOW: Real FILE operations and preserved reopen identity. */
static void streams(const char *path, const char *mode, int error)
{
    FILE *stream;
    if (fault("reopen")) {
        stream = tmpfile(); assert(stream && fputs("kept", stream) >= 0);
        assert(probe_freopen(path, "r", stream) == NULL && errno == ENOTSUP);
        rewind(stream); assert(fgetc(stream) == 'k'); assert(fclose(stream) == 0); return;
    }
    stream = probe_fopen(path, !strcmp(mode, "<null>") ? NULL : mode);
    if (error) { assert(stream == NULL && errno == error); return; }
    assert(stream != NULL); stream_io(stream, mode); assert(fclose(stream) == 0);
    assert(slot_of(XFS_FD_BASE) == NULL);
}

/* WHAT: Run one routing/descriptor contract. WHY: pthread_once must start fresh.
 * HOW: One subprocess per mapping, with exact expected local/remote outcomes. */
int main(int argc, char **argv)
{
    int fd, flags, expected; char mapped[128] = {0};
    assert(argc == 6); flags = atoi(argv[3]); expected = atoi(argv[4]);
    if (!strcmp(argv[1], "directory")) { directories(argv[2], expected); return 0; }
    if (!strcmp(argv[1], "stdio")) { streams(argv[2], argv[5], expected); return 0; }
    if (!strcmp(argv[1], "map")) {
        assert(map_path(!strcmp(argv[2], "<null>") ? NULL : argv[2], mapped, (size_t) flags) == expected);
        if (expected) { assert(!strcmp(mapped, argv[5])); } return 0;
    }
    if (!strcmp(argv[1], "stat")) { metadata(argv[2], expected); return 0; }
    if (!strcmp(argv[1], "full")) { exhausted(); return 0; }
    fd = !strcmp(argv[1], "openat") ? probe_openat(-1, argv[2], flags, 0600)
                                     : probe_open(argv[2], flags, 0600);
    if (expected < 0) { assert(fd == -1 && errno == atoi(argv[5])); return 0; }
    assert(fd >= XFS_FD_BASE && slot_of(fd) != NULL);
    if ((flags & O_ACCMODE) == O_WRONLY) { writes(fd); } else { reads(fd); }
    assert(probe_close(fd) == 0 && slot_of(fd) == NULL);
    assert(slot_of(XFS_FD_BASE + XFS_FD_MAX) == NULL);
    assert(probe_close(fd) == -1 && errno == EBADF);
    fd = probe_open(argv[2], O_RDONLY); assert(fd >= XFS_FD_BASE); assert(probe_close(fd) == 0);
    printf("connects=%s opens=%s\n", getenv("BRIX_PRELOAD_CONNECT"), getenv("BRIX_PRELOAD_OPEN"));
    return 0;
}
