/* Exercise real delegation dispatch and subprocess capture with fixture helpers. */
#include "tpc/engine/tpc_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int __real_pipe(int fds[2]);
pid_t __real_fork(void);

static int
failing(const char *kind)
{
    const char *fault = getenv("BRIX_TPC_TEST_FAIL");
    return fault != NULL && !strcmp(fault, kind);
}

int __wrap_pipe(int fds[2])
{
    if (failing("pipe")) { errno = EMFILE; return -1; }
    return __real_pipe(fds);
}

pid_t __wrap_fork(void)
{
    if (failing("fork")) { errno = EAGAIN; return -1; }
    return __real_fork();
}

int
main(int argc, char **argv)
{
    ngx_log_t log = {0};
    ngx_connection_t connection = {.log = &log};
    ngx_stream_brix_srv_conf_t conf = {0};
    brix_tpc_pull_t *task = calloc(1, sizeof(*task));
    assert(argc == 3 && task != NULL);
    ngx_time_init();
    task->c = &connection; task->conf = &conf;
    assert(strlen(argv[1]) < sizeof(task->token_mode));
    assert(strlen(argv[2]) < sizeof(task->delegated_token));
    strcpy(task->token_mode, argv[1]);
    strcpy(task->delegated_token, argv[2]);
    int rc = tpc_fetch_delegated_token(task);
    printf("%d %d\n", rc, task->xrd_error);
    if (rc == 0) { fputs(task->delegated_token, stdout); }
    free(task);
    return 0;
}
