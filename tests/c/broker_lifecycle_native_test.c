/* Real broker double-fork/socket/fd sealing with finite identity/serve boundaries. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "auth/impersonate/lifecycle.h"
#include "auth/impersonate/lifecycle_internal.h"
#include "auth/impersonate/impersonate.h"
#include <assert.h>
#include <pwd.h>
#include <poll.h>
#include <sys/wait.h>

typedef struct {
    ngx_cycle_t cycle;
    struct passwd account;
    const char *mode;
    int published, maps, chowns, foreign_fd, read_pipe, write_pipe;
    uid_t worker;
} fixture;
extern ngx_uint_t ngx_test_config;
extern void brix_imp_broker_seal_fds(int, int, ngx_log_t *);

/* WHAT: Recover test state. WHY: Avoid production globals. HOW: Enclosing cycle. */
static fixture *state(void) { return (fixture *) ngx_cycle; }

/* WHAT: Select a scenario. WHY: Keep faults local. HOW: Fixture mode string. */
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Observe version publication. WHY: Config checks cannot bump generation.
 * HOW: Count the real lifecycle's publish call without shared metrics state. */
void __wrap_brix_config_version_publish(ngx_cycle_t *cycle)
{
    assert(cycle == ngx_cycle); state()->published++;
}

/* WHAT: Supply master identity. WHY: Exercise the privilege gate as an ordinary uid.
 * HOW: Override identity query only; no credential or capability changes. */
uid_t __wrap_geteuid(void) { return mode("nonroot") ? 504 : 0; }

/* WHAT: Resolve test accounts. WHY: Cover missing/root/same-uid refusal.
 * HOW: Return stack-owned passwd records for named broker/nobody lookups. */
struct passwd *__wrap_getpwnam(const char *name)
{
    fixture *f = state();
    if (!strcmp(name, "nobody")) {
        if (mode("no-nobody")) { return NULL; }
        f->account.pw_uid = 65534; f->account.pw_gid = 65534; return &f->account;
    }
    assert(!strcmp(name, "fixture-broker"));
    if (mode("missing-user")) { return NULL; }
    f->account.pw_uid = mode("root-user") ? 0 : 6001;
    if (mode("same-user")) { f->account.pw_uid = f->worker; }
    f->account.pw_gid = 6002; return &f->account;
}

/* WHAT: Observe socket ownership. WHY: Check the worker uid without host changes.
 * HOW: Assert arguments and return a selected chown failure. */
int __wrap_chown(const char *path, uid_t uid, gid_t gid)
{
    assert(!strcmp(path, (char *) imp_settings.socket.data));
    assert(uid == state()->worker && gid == (gid_t) -1); state()->chowns++;
    if (mode("chown-fail")) { errno = EPERM; return -1; }
    return 0;
}

/* WHAT: Validate carried idmap policy. WHY: Forks must inherit the exact policy.
 * HOW: Compare settings and refuse a selected map load. */
ngx_int_t __wrap_brix_idmap_init(const brix_idmap_conf_t *conf, ngx_log_t *log)
{
    assert(log == ngx_cycle->log && conf->worker_uid == state()->worker);
    assert(conf->cache_ttl == 71 && conf->gridmap_path.len == 7);
    assert(conf->min_uid == (mode("negative-min") ? 0 : 1000));
    assert(conf->default_user.len == 7 && conf->single_user.len == 6);
    assert(conf->forbidden_users.len == 4 && conf->forbidden_groups.len == 5);
    state()->maps++; return mode("map-fail") ? NGX_ERROR : NGX_OK;
}

pid_t __real_fork(void);
/* WHAT: Inject first-fork failure. WHY: Both parent fds must close. HOW: EAGAIN. */
pid_t __wrap_fork(void)
{
    if (mode("fork-fail")) { errno = EAGAIN; return -1; }
    return __real_fork();
}

extern void __gcov_dump(void) __attribute__((weak));
extern void __gcov_reset(void) __attribute__((weak));
void __real__exit(int) __attribute__((noreturn));
/* WHAT: Persist child coverage. WHY: Production deliberately uses _exit.
 * HOW: Flush/reset the existing instrumentation before the real exit. */
void __wrap__exit(int status)
{
    if (__gcov_dump) { __gcov_dump(); }
    if (__gcov_reset) { __gcov_reset(); }
    __real__exit(status);
}

/* WHAT: Terminate the broker after checking inherited resources.
 * WHY: A privileged child must not pin unrelated listeners/logs/stdio.
 * HOW: Real fd probes plus a kept diagnostic pipe report successful sealing. */
int __wrap_brix_imp_broker_run(int listener, int root, const volatile sig_atomic_t *stop, ngx_log_t *log)
{
    fixture *f = state(); struct stat info;
    assert(stop == NULL && log == ngx_cycle->log);
    assert(fstat(listener, &info) == 0 && S_ISSOCK(info.st_mode));
    assert(fstat(root, &info) == 0 && S_ISDIR(info.st_mode));
    assert(fcntl(f->foreign_fd, F_GETFD) == -1 && errno == EBADF);
    assert(fcntl(f->read_pipe, F_GETFD) == -1 && errno == EBADF);
    assert(fcntl(STDIN_FILENO, F_GETFD) >= 0 && fcntl(STDOUT_FILENO, F_GETFD) >= 0);
    assert(brix_imp_get_broker_allow_uid() == (f->worker == (uid_t) -1 ? 0 : f->worker));
    assert(brix_imp_get_broker_user_uid() == (mode("no-broker-user") ? (uid_t) -1 : 6001));
    assert(write(f->write_pipe, "K", 1) == 1);
    return mode("serve-fail") ? -1 : 0;
}

/* WHAT: Bind stack settings. WHY: Exercise the public lifecycle entry point.
 * HOW: Real core configuration, temporary paths, explicit idmap policy. */
static void settings(fixture *f, ngx_core_conf_t *core, void **contexts,
    const char *directory, char *socket_path, char *root_path)
{
    snprintf(socket_path, 240, "%s/broker.sock", directory);
    snprintf(root_path, 240, "%s%s", directory, mode("root-missing") ? "/absent" : "");
    if (mode("socket-long")) { memset(socket_path, 'x', 200); socket_path[200] = 0; }
    if (mode("socket-parent")) { snprintf(socket_path, 240, "%s/absent/broker", directory); }
    memset(&imp_settings, 0, sizeof(imp_settings));
    imp_settings.mode = mode("off") ? BRIX_IMP_OFF : BRIX_IMP_MAP;
    imp_settings.socket = (ngx_str_t) {strlen(socket_path), (u_char *) socket_path};
    imp_settings.export_root = (ngx_str_t) {strlen(root_path), (u_char *) root_path};
    ngx_str_set(&imp_settings.broker_user, "fixture-broker");
    if (mode("no-broker-user")) { imp_settings.broker_user.len = 0; }
    ngx_str_set(&imp_settings.gridmap, "gridmap"); ngx_str_set(&imp_settings.default_user, "default");
    ngx_str_set(&imp_settings.single_user, "single"); ngx_str_set(&imp_settings.forbidden_users, "root");
    ngx_str_set(&imp_settings.forbidden_groups, "wheel");
    imp_settings.cache_ttl = 71; imp_settings.min_uid = mode("negative-min") ? -1 : 1000;
    core->user = f->worker; ngx_core_module.index = 0; contexts[0] = core;
    f->cycle.conf_ctx = (void ****) contexts;
    if (mode("fallback") || mode("no-nobody")) { core->user = (ngx_uid_t) NGX_CONF_UNSET_UINT; }
    if (mode("no-core")) { contexts[0] = NULL; }
    ngx_test_config = mode("config-test");
}

/* WHAT: Create a disposable stale broker. WHY: Reload must terminate only its pid.
 * HOW: A child sleeping in pause and a pidfile wholly inside the test directory. */
static pid_t stale(const char *path)
{
    char pidfile[260]; FILE *stream; pid_t pid = 0;
    if (!mode("stale") && !mode("stale-invalid")) { return 0; }
    if (mode("stale")) {
        pid = __real_fork(); assert(pid >= 0);
        if (pid == 0) { for (;;) { pause(); } }
    }
    snprintf(pidfile, sizeof(pidfile), "%s.pid", path);
    stream = fopen(pidfile, "w"); assert(stream != NULL);
    assert(fprintf(stream, "%ld\n", pid ? (long) pid : 1L) > 0);
    assert(fclose(stream) == 0); return pid;
}

/* WHAT: Wait for the finite child. WHY: No detached harness remains on success.
 * HOW: Poll the diagnostic pipe, then verify the stale child was terminated. */
static void completion(fixture *f, int spawned, pid_t old)
{
    if (spawned) {
        char marker; struct pollfd ready = {f->read_pipe, POLLIN, 0};
        assert(poll(&ready, 1, 5000) == 1);
        assert(read(f->read_pipe, &marker, 1) == 1 && marker == 'K');
        assert(poll(&ready, 1, 5000) == 1);
        assert(read(f->read_pipe, &marker, 1) == 0);
    }
    if (old) {
        int status; assert(waitpid(old, &status, 0) == old);
        assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
    }
}

/* WHAT: Count descriptors. WHY: Failed startup must release listener/root fds.
 * HOW: Probe the small fixture descriptor range without opening another file. */
static int descriptors(void)
{
    int count = 0;
    for (int fd = 0; fd < 256; fd++) { count += fcntl(fd, F_GETFD) >= 0; }
    return count;
}

/* WHAT: Exercise sealing without a normal logfile. WHY: Optional logs still
 * must not retain inherited fds. HOW: A finite fork probes kept and closed fds. */
static void seal_only(fixture *f, ngx_log_t *log)
{
    pid_t pid = __real_fork(); int status;
    assert(pid >= 0);
    if (pid == 0) {
        int high = fcntl(f->read_pipe, F_DUPFD, 128); assert(high >= 128);
        if (mode("seal-no-file")) { log->file = NULL; }
        if (mode("seal-invalid-log")) { log->file->fd = NGX_INVALID_FILE; }
        if (mode("seal-stderr")) { log->file->fd = STDERR_FILENO; }
        brix_imp_broker_seal_fds(f->write_pipe, f->foreign_fd,
            mode("seal-no-log") ? NULL : log);
        assert(fcntl(high, F_GETFD) == -1 && errno == EBADF);
        assert(fcntl(f->read_pipe, F_GETFD) == -1 && errno == EBADF);
        assert(fcntl(f->foreign_fd, F_GETFD) >= 0);
        assert(write(f->write_pipe, "K", 1) == 1);
        __wrap__exit(0);
    }
    close(f->write_pipe); f->write_pipe = -1; completion(f, 1, 0);
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
}

/* WHAT: Execute one startup outcome. WHY: Cover failure cleanup and spawn gates.
 * HOW: Temporary sockets, real forks, bounded completion, explicit assertions. */
int main(int argc, char **argv)
{
    fixture f = {0}; ngx_core_conf_t core = {0}; void *contexts[1];
    ngx_log_t log = {0}; ngx_open_file_t logfile = {0}; int pipefd[2];
    char socket_path[240], root_path[240]; pid_t old; ngx_int_t result; int before;
    assert(argc == 6); f.mode = argv[1]; ngx_cycle = &f.cycle; f.cycle.log = &log;
    f.worker = mode("no-nobody") ? (uid_t) -1 : 5001;
    if (mode("fallback") || mode("no-core")) { f.worker = 65534; }
    assert(pipe(pipefd) == 0); f.read_pipe = pipefd[0]; f.write_pipe = pipefd[1];
    logfile.fd = f.write_pipe; log.file = &logfile;
    f.foreign_fd = open("/dev/null", O_RDONLY); assert(f.foreign_fd >= 0);
    if (!strncmp(f.mode, "seal-", 5)) {
        seal_only(&f, &log); close(f.foreign_fd); close(f.read_pipe); return 0;
    }
    settings(&f, &core, contexts, argv[2], socket_path, root_path);
    old = stale(socket_path); before = descriptors(); result = brix_imp_init_module(&f.cycle);
    assert(descriptors() == before);
    assert(result == atoi(argv[3]) && f.published == !ngx_test_config);
    assert(f.maps == atoi(argv[4])); close(f.write_pipe); f.write_pipe = -1;
    completion(&f, atoi(argv[5]), old);
    if (result == NGX_OK && atoi(argv[5])) {
        struct stat info; assert(stat(socket_path, &info) == 0);
        assert((info.st_mode & 0777) == 0600);
    }
    assert(close(f.foreign_fd) == 0); close(f.read_pipe); close(f.write_pipe);
    printf("result=%ld maps=%d chowns=%d\n", (long) result, f.maps, f.chowns);
    return 0;
}
