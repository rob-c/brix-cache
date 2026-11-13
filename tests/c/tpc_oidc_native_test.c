/* Public HTTP delegation through a real fork/exec CLI and controlled envp.
 * Capture the return value only after checking signal-mask restoration and
 * child ownership. Transport admission failures are injected at libc seams.
 */
#include "protocols/webdav/tpc_cred_internal.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

int __real_pipe(int fds[2]);
pid_t __real_fork(void);
void *__real_ngx_pnalloc(ngx_pool_t *pool, size_t size);

/* WHAT: Select one explicit failure. WHY: Bound fault injection to this case.
 * HOW: Compare the fixture's switch without changing process-wide state. */
static int failing(const char *kind)
{
    const char *fault = getenv("BRIX_TPC_TEST_FAIL");
    return fault != NULL && strcmp(fault, kind) == 0;
}

/* WHAT: Refuse pipe creation. WHY: No child may launch without owned output.
 * HOW: Inject EMFILE or retain the real pipe syscall. */
int __wrap_pipe(int fds[2])
{
    if (failing("pipe")) { errno = EMFILE; return -1; }
    return __real_pipe(fds);
}

/* WHAT: Refuse child creation. WHY: Failed setup must restore the signal mask.
 * HOW: Inject EAGAIN or retain the real fork syscall. */
pid_t __wrap_fork(void)
{
    if (failing("fork")) { errno = EAGAIN; return -1; }
    return __real_fork();
}

/* WHAT: Refuse token allocation. WHY: A failed copy cannot publish a credential.
 * HOW: Inject at the pool-copy boundary after the actual helper has exited. */
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    if (failing("allocation")) { return NULL; }
    return __real_ngx_pnalloc(pool, size);
}

/* WHAT: Run HTTP delegation on a minimal real request and location config.
 * WHY: The public dispatcher must validate helper results before use.
 * HOW: Initialize request ownership, fetch once, verify cleanup, emit the token. */
int main(int argc, char **argv)
{
    assert(argc == 3);
    ngx_log_t log = {0};
    ngx_connection_t connection = {.log = &log};
    ngx_http_brix_webdav_loc_conf_t conf = {0};
    ngx_http_request_t request = {.connection = &connection};
    ngx_str_t token = ngx_null_string;
    void *locations[1] = {&conf};
    sigset_t before, after;
    ngx_time_init();
    request.pool = ngx_create_pool(4096, &log);
    assert(request.pool != NULL);
    request.loc_conf = locations;
    ngx_http_brix_webdav_module.ctx_index = 0;
    if (strcmp(argv[2], "blocked") == 0) {
        sigemptyset(&before); sigaddset(&before, SIGCHLD);
        assert(sigprocmask(SIG_BLOCK, &before, NULL) == 0);
    }
    assert(sigprocmask(SIG_SETMASK, NULL, &before) == 0);
    ngx_int_t result = webdav_tpc_cred_obtain_token(&request,
        BRIX_TPC_CRED_OIDC_AGENT, argv[1], NULL, "storage.read", &token);
    assert(sigprocmask(SIG_SETMASK, NULL, &after) == 0);
    assert(sigismember(&before, SIGCHLD) == sigismember(&after, SIGCHLD));
    assert(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
    printf("%ld\n", (long)result);
    if (result == NGX_OK) {
        assert(token.len > 0 && token.data != NULL);
        assert(fwrite(token.data, 1, token.len, stdout) == token.len);
    }
    ngx_destroy_pool(request.pool);
    return 0;
}
