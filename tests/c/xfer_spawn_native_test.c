/* Real reparented commands with finite admission and result-channel failures. */
#include "fs/xfer/xfer_spawn.h"
#include <ngx_core.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    unsigned forks, reads, writes, waits;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return state() && !strcmp(state()->mode, name); }

pid_t __real_fork(void);
pid_t __wrap_fork(void)
{
    unsigned index = ++state()->forks;
    if ((mode("fork-parent") && index == 1) || (mode("fork-agent") && index == 2)
        || (mode("fork-command") && index == 3)) { errno = EAGAIN; return -1; }
    return __real_fork();
}

int __real_socketpair(int domain, int type, int protocol, int descriptors[2]);
int __wrap_socketpair(int domain, int type, int protocol, int descriptors[2])
{
    if (mode("socketpair")) { errno = EMFILE; return -1; }
    return __real_socketpair(domain, type, protocol, descriptors);
}

ssize_t __real_read(int fd, void *buffer, size_t length);
ssize_t __wrap_read(int fd, void *buffer, size_t length)
{
    if (state() && state()->reads++ == 0) {
        if (mode("read-error")) { errno = EIO; return -1; }
        if (mode("read-eintr")) { errno = EINTR; return -1; }
    }
    return __real_read(fd, buffer, mode("partial") && length > 1 ? 1 : length);
}

ssize_t __real_write(int fd, const void *buffer, size_t length);
ssize_t __wrap_write(int fd, const void *buffer, size_t length)
{
    if (state() && state()->writes++ == 0) {
        if (mode("write-error")) { errno = EIO; return -1; }
        if (mode("write-eintr")) { errno = EINTR; return -1; }
    }
    return __real_write(fd, buffer, mode("partial") && length > 1 ? 1 : length);
}

pid_t __real_waitpid(pid_t child, int *status, int options);
pid_t __wrap_waitpid(pid_t child, int *status, int options)
{
    if (mode("wait-eintr") && state()->waits++ == 0) { errno = EINTR; return -1; }
    return __real_waitpid(child, status, options);
}

void __gcov_dump(void) __attribute__((weak));
void __gcov_reset(void) __attribute__((weak));
int __real_brix_plat_execvpe(const char *file, char *const args[], char *const environment[]);
int __wrap_brix_plat_execvpe(const char *file, char *const args[], char *const environment[])
{
    if (__gcov_dump && __gcov_reset) { __gcov_dump(); __gcov_reset(); }
    return __real_brix_plat_execvpe(file, args, environment);
}

void __real__exit(int status) __attribute__((noreturn));
void __wrap__exit(int status)
{
    if (__gcov_dump) { __gcov_dump(); }
    __real__exit(status);
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    fixture f = {0}; f.mode = argv[1]; ngx_cycle = &f.cycle;
    signal(SIGPIPE, SIG_IGN);
    const char *command[] = {"/bin/sh", "-c", "exit 17", NULL};
    char *environment[] = {"BRIX_SPAWN_SECRET=passed", "PATH=/bin:/usr/bin", NULL};
    int descriptor = open("/dev/null", O_RDONLY); assert(descriptor >= 0);
    int high = fcntl(descriptor, F_DUPFD, 200); assert(high >= 200);
    char security_command[160];
    if (mode("security")) {
        snprintf(security_command, sizeof(security_command),
                 "test \"$BRIX_SPAWN_SECRET\" = passed && test ! -e /proc/self/fd/%d", high);
        command[2] = security_command;
    }
    if (mode("signal")) { command[2] = "kill -TERM $$"; }
    if (mode("missing")) { command[0] = "/no/such/brix-test-program"; }
    if (mode("path")) { command[0] = "sh"; }
    if (mode("null-element")) { command[0] = NULL; }
    sigset_t before, after;
    assert(sigprocmask(SIG_SETMASK, NULL, &before) == 0);
    int rc = brix_xfer_run_reparented(mode("null") ? NULL : command,
                                     mode("security") ? environment : NULL);
    assert(rc == atoi(argv[2]));
    assert(sigprocmask(SIG_SETMASK, NULL, &after) == 0);
    assert(sigismember(&before, SIGCHLD) == sigismember(&after, SIGCHLD));
    assert(fcntl(high, F_GETFD) >= 0); /* Closing children must preserve parent ownership. */
    close(high); close(descriptor);
    ngx_cycle = NULL;
    return 0;
}
