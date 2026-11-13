/* Automount startup and teardown with real control threads/self-pipes.
 * FUSE and child-process seams never mount, signal, or reap host resources. */
#include "apps/fs/brixautofs_ext_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    const char *mode;
    atomic_int mounts, unmounts, destroys, exits, creates, joins;
    atomic_int child_unmounts, reaped, killed, expiry;
    int piped;
} observer_t;

static observer_t *observer(void)
{
    return (observer_t *)(uintptr_t) strtoull(getenv("BRIX_AUTOFS_OBSERVER"), NULL, 16);
}
static int mode(const char *name) { return strcmp(observer()->mode, name) == 0; }
static void checked_fuse(struct fuse *f) { assert(f == (struct fuse *) observer()); }

struct fuse *__wrap_fuse_new(struct fuse_args *args, const struct fuse_operations *ops,
                              size_t size, void *data)
{
    assert(ops == &af_ops && size == sizeof(af_ops) && data == NULL);
    assert(args->argc >= 3 && strcmp(args->argv[args->argc - 2], "-o") == 0);
    printf("OPTIONS %s\n", args->argv[args->argc - 1]);
    printf("CONFIG strict=%d repos=%s ghosts=%d timeout=%d idle=%d debug=%d\n",
        g_af.strict, g_af.repos, g_af.nghost, g_af.o.spawn_timeout_s, g_af.o.idle_s, g_af.o.debug);
    return mode("new") ? NULL : (struct fuse *) observer();
}
int __wrap_fuse_mount(struct fuse *f, const char *path)
{
    checked_fuse(f); assert(strcmp(path, g_af.mnt) == 0);
    atomic_fetch_add(&observer()->mounts, 1);
    return mode("mount") ? -1 : 0;
}
int __wrap_fuse_daemonize(int foreground)
{
    assert(foreground == g_af.o.foreground);
    return mode("daemon") ? -1 : 0;
}
void __wrap_fuse_unmount(struct fuse *f)
{
    checked_fuse(f); atomic_fetch_add(&observer()->unmounts, 1);
}
void __wrap_fuse_destroy(struct fuse *f)
{
    checked_fuse(f); atomic_fetch_add(&observer()->destroys, 1);
}
void __wrap_fuse_exit(struct fuse *f)
{
    checked_fuse(f); atomic_fetch_add(&observer()->exits, 1);
}

int __real_pipe(int [2]);
int __wrap_pipe(int descriptors[2])
{
    if (mode("pipe")) { errno = EMFILE; return -1; }
    int rc = __real_pipe(descriptors);
    if (rc == 0) { observer()->piped = 1; }
    return rc;
}
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __real_pthread_join(pthread_t, void **);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                          void *(*start)(void *), void *arg)
{
    int index = atomic_fetch_add(&observer()->creates, 1);
    if (mode("controller") || (mode("idle-thread") && index == 1)) { return EAGAIN; }
    return __real_pthread_create(thread, attributes, start, arg);
}
int __wrap_pthread_join(pthread_t thread, void **value)
{
    int rc = __real_pthread_join(thread, value);
    assert(rc == 0); atomic_fetch_add(&observer()->joins, 1);
    return rc;
}

int __wrap_af_umount_path(const char *path)
{
    assert(strcmp(path, g_af.mnt) == 0 || strncmp(path, g_af.farm, strlen(g_af.farm)) == 0);
    atomic_fetch_add(&observer()->child_unmounts, 1);
    return 0;
}
int __wrap_af_is_mounted(const char *path)
{
    assert(strncmp(path, g_af.farm, strlen(g_af.farm)) == 0);
    return !mode("reap-unmounted");
}
int __wrap_brix_plat_umount_expire(const char *path)
{
    assert(strncmp(path, g_af.farm, strlen(g_af.farm)) == 0);
    atomic_fetch_add(&observer()->expiry, 1);
    if (mode("expire")) { return 0; }
    errno = EPERM; return -1;
}
pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
    *status = 0;
    if (pid == -1) {
        int index = atomic_fetch_add(&observer()->reaped, 1);
        if (index == 0) { return 440045; }
        return index == 1 ? 440044 : 0;
    }
    assert(pid == 440044);
    if (mode("hung-child") && options == WNOHANG) { return 0; }
    return pid;
}
int __wrap_kill(pid_t pid, int signal_number)
{
    assert(pid == 440044 && signal_number == SIGTERM);
    atomic_fetch_add(&observer()->killed, 1);
    return 0;
}
int __real_nanosleep(const struct timespec *, struct timespec *);
int __wrap_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    if (mode("hung-child")) { return 0; }
    return __real_nanosleep(request, remaining);
}

static void wait_observation(atomic_int *value)
{
    for (int i = 0; i < 3000 && atomic_load(value) == 0; i++) {
        struct timespec delay = {0, 1000000};
        __real_nanosleep(&delay, NULL);
    }
    assert(atomic_load(value) != 0);
}

int __wrap_fuse_loop_mt_31(struct fuse *f, int clone_fd)
{
    checked_fuse(f); assert(clone_fd == 0);
    pthread_mutex_lock(&g_af.tab.mu);
    int slot = brixautofs_claim_locked(&g_af.tab, "repo.example");
    assert(slot >= 0);
    brixautofs_commit_locked(&g_af.tab, slot, 440044);
    pthread_mutex_unlock(&g_af.tab.mu);
    if (mode("reap") || mode("reap-unmounted")) {
        assert(raise(SIGCHLD) == 0);
        wait_observation(&observer()->reaped);
    }
    if (mode("terminate")) {
        assert(raise(SIGTERM) == 0);
        wait_observation(&observer()->exits);
    }
    if (mode("expire") || mode("expire-denied")) { wait_observation(&observer()->expiry); }
    return mode("loop") ? -1 : 0;
}

int brixautofs_main(int, char **);
int main(int argc, char **argv)
{
    observer_t state = {0};
    char pointer[32];
    int rc;
    assert(argc >= 3);
    state.mode = argv[1];
    snprintf(pointer, sizeof(pointer), "%llx", (unsigned long long) (uintptr_t) &state);
    assert(setenv("BRIX_AUTOFS_OBSERVER", pointer, 1) == 0);
    g_af.sigpipe[0] = -1; g_af.sigpipe[1] = -1;
    rc = brixautofs_main(argc - 2, argv + 2);
    if (state.piped) {
        assert(fcntl(g_af.sigpipe[0], F_GETFD) == -1 && errno == EBADF);
        assert(fcntl(g_af.sigpipe[1], F_GETFD) == -1 && errno == EBADF);
    }
    printf("COUNTS mounts=%d unmounts=%d destroys=%d joins=%d children=%d kills=%d expires=%d\n",
        (int) state.mounts, (int) state.unmounts, (int) state.destroys, (int) state.joins,
        (int) state.child_unmounts, (int) state.killed, (int) state.expiry);
    pthread_mutex_destroy(&g_af.tab.mu);
    return rc;
}
