/* Linux process PAL contracts with real descriptors and finite procfs failures. */
#include "core/ngx_brix_module.h"
#include "platform/platform_api.h"
#include <assert.h>
#include <dirent.h>
#include <stdarg.h>
#include <sys/syscall.h>

typedef struct { ngx_cycle_t cycle; const char *mode; int bootfd; } fixture;

static int mode(const char *name) { return ngx_cycle && !strcmp(((fixture *) ngx_cycle)->mode, name); }

long __real_syscall(long, ...);
/* WHAT: Select the close-from fallback. WHY: Older kernels must close the same fds.
 * HOW: Decode only the explicitly exercised syscall's three arguments. */
long __wrap_syscall(long number, ...)
{
    assert(number == SYS_close_range);
    if (!mode("native")) { errno = ENOSYS; return -1; }
    va_list args; va_start(args, number);
    unsigned first = va_arg(args, unsigned), last = va_arg(args, unsigned);
    unsigned flags = va_arg(args, unsigned); va_end(args);
    return __real_syscall(number, first, last, flags);
}

DIR *__real_opendir(const char *);
/* WHAT: Make procfs enumeration unavailable. WHY: The final bounded loop is required.
 * HOW: Refuse only the process-fd directory for explicit fallback cases. */
DIR *__wrap_opendir(const char *path)
{
    if ((mode("loop") || mode("loop-default")) && !strcmp(path, "/proc/self/fd")) {
        errno = ENOENT; return NULL;
    }
    return __real_opendir(path);
}

long __real_sysconf(int);
long __wrap_sysconf(int key)
{
    if (key == _SC_OPEN_MAX && mode("loop-default")) { return -1; }
    if (key == _SC_OPEN_MAX && mode("loop")) { return 64; }
    return __real_sysconf(key);
}

ssize_t __real_readlink(const char *, char *, size_t);
ssize_t __wrap_readlink(const char *path, char *out, size_t cap)
{
    if (mode("readlink-error")) { errno = EACCES; return -1; }
    return __real_readlink(path, out, cap);
}

int __real_open64(const char *, int, ...);
/* WHAT: Refuse or identify the boot-id fd. WHY: Error handling must retain errno.
 * HOW: All unrelated opens and their optional modes remain real. */
int __wrap_open64(const char *path, int flags, ...)
{
    mode_t permissions = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags); permissions = va_arg(args, int); va_end(args);
    }
    int boot = !strcmp(path, "/proc/sys/kernel/random/boot_id");
    if (boot && mode("open-error")) { errno = EACCES; return -1; }
    int fd = __real_open64(path, flags, permissions);
    if (boot && ngx_cycle) { ((fixture *) ngx_cycle)->bootfd = fd; }
    return fd;
}

ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_read(int fd, void *buf, size_t length)
{
    if (ngx_cycle && fd == ((fixture *) ngx_cycle)->bootfd) {
        if (mode("read-error")) { errno = EIO; return -1; }
        if (mode("empty")) { return 0; }
    }
    return __real_read(fd, buf, length);
}

/* WHAT: Close high descriptors while preserving low ones.
 * WHY: Exec hygiene must be equivalent across kernel, procfs and loop paths.
 * HOW: Duplicate real pipes above the threshold and verify EBADF afterward. */
static void closefrom_case(void)
{
    int pair[2]; assert(pipe(pair) == 0);
    int first = fcntl(pair[0], F_DUPFD, 20), second = fcntl(pair[1], F_DUPFD, 30);
    assert(first >= 20 && second >= 30 && pair[0] < 20 && pair[1] < 20);
    assert(brix_plat_close_from(20) == 0);
    assert(fcntl(first, F_GETFD) == -1 && errno == EBADF);
    assert(fcntl(second, F_GETFD) == -1 && errno == EBADF);
    assert(write(pair[1], "x", 1) == 1); char byte;
    assert(read(pair[0], &byte, 1) == 1 && byte == 'x');
    close(pair[0]); close(pair[1]);
}

/* WHAT: Query credentials only from a real local peer.
 * WHY: Invalid descriptors must never supply an identity.
 * HOW: Check all fields and nullable outputs without changing caller canaries. */
static void peer(void)
{
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    uid_t uid = (uid_t) -1; gid_t gid = (gid_t) -1; pid_t pid = -1;
    if (mode("invalid")) {
        assert(brix_plat_peer_cred(-1, &uid, &gid, &pid) == -1 && errno == EBADF);
        assert(uid == (uid_t) -1 && gid == (gid_t) -1 && pid == -1);
    } else {
        assert(brix_plat_peer_cred(pair[0], &uid, &gid, &pid) == 0);
        assert(uid == getuid() && gid == getgid() && pid == getpid());
        assert(brix_plat_peer_cred(pair[0], NULL, NULL, NULL) == 0);
    }
    close(pair[0]); close(pair[1]);
}

/* WHAT: Query complete process identities or fail with an untouched output.
 * WHY: A truncated boot id cannot identify a boot safely.
 * HOW: Surround a bounded buffer with canaries and inspect the exact result. */
static void identity(const char *operation, size_t capacity, int expected)
{
    unsigned char output[4096 + 32]; memset(output, 0xa5, sizeof(output));
    assert(capacity <= 4096); char *buffer = (char *) output + 16;
    int rc = !strcmp(operation, "boot") ? brix_plat_boot_id(buffer, capacity)
                                        : brix_plat_self_exe(buffer, capacity);
    for (size_t i = 0; i < 16; i++) {
        assert(output[i] == 0xa5 && output[16 + capacity + i] == 0xa5);
    }
    if (expected) { assert(rc == -1 && errno == expected); }
    else {
        assert(rc == 0 && strlen(buffer) < capacity && strlen(buffer));
        if (!strcmp(operation, "boot")) { assert(strlen(buffer) == 36 && !strchr(buffer, '\n')); }
        else { assert(buffer[0] == '/'); }
    }
}

int main(int argc, char **argv)
{
    assert(argc == 5); fixture f = {0}; ngx_cycle = &f.cycle; f.mode = argv[2]; f.bootfd = -99;
    if (!strcmp(argv[1], "closefrom")) { closefrom_case(); }
    else if (!strcmp(argv[1], "peer")) { peer(); }
    else { identity(argv[1], strtoul(argv[3], NULL, 10), atoi(argv[4])); }
    ngx_cycle = NULL;
    return 0;
}
