/* Run cache-origin credential exchange on an inherited real socket. The peer
 * checks wire bytes independently; only named local allocation/stdio failures
 * are injected, without replacing crypto, key parsing, framing, or socket I/O.
 */
#include "fs/cache/cache_internal.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *__real_malloc(size_t size);
FILE *__real_fdopen(int fd, const char *mode);

/* WHAT: Select one fixture fault. WHY: Keep each refusal independent.
 * HOW: Read the process-local fault name and compare exactly. */
static int fault(const char *name)
{
    const char *selected = getenv("BRIX_ORIGIN_AUTH_FAULT");
    return getenv("BRIX_ORIGIN_AUTH_ARMED") != NULL
        && selected != NULL && strcmp(selected, name) == 0;
}

/* WHAT: Refuse an owned payload allocation. WHY: No partial credential is sent.
 * HOW: Inject ENOMEM, otherwise retain the real allocation. */
void *__wrap_malloc(size_t size)
{
    if (fault("allocation")) { errno = ENOMEM; return NULL; }
    return __real_malloc(size);
}

/* WHAT: Refuse stdio adoption of a key file. WHY: The raw descriptor must close.
 * HOW: Inject EMFILE or use the actual stream. */
FILE *__wrap_fdopen(int fd, const char *mode)
{
    if (fault("fdopen")) { errno = EMFILE; return NULL; }
    return __real_fdopen(fd, mode);
}

/* WHAT: Run one production authentication exchange and publish its status.
 * WHY: The peer test must observe both bytes and exact protocol error mapping.
 * HOW: Initialize time, use the inherited socket, authenticate, close, report. */
int main(int argc, char **argv)
{
    assert(argc == 5);
    signal(SIGPIPE, SIG_IGN);
    ngx_time_init();
    brix_cache_fill_t *task = calloc(1, sizeof(*task));
    assert(task != NULL);
    brix_cache_origin_conn_t connection = {.fd = atoi(argv[2])};
    int result;
    assert(setenv("BRIX_ORIGIN_AUTH_ARMED", "1", 1) == 0);
    if (strcmp(argv[1], "sss") == 0) {
        const char *identity = strcmp(argv[4], "-") == 0 ? NULL : argv[4];
        result = brix_cache_origin_auth_sss(task, &connection, argv[3], identity);
    } else if (strcmp(argv[1], "ztn") == 0) {
        ngx_str_t token = {.data = (u_char *)argv[4], .len = strlen(argv[4])};
        result = brix_cache_origin_auth_ztn(task, &connection, &token);
    } else {
        result = cache_origin_send_kxr_auth(&connection, "ztn", NULL, 0);
    }
    unsetenv("BRIX_ORIGIN_AUTH_ARMED");
    close(connection.fd);
    printf("%d %d %d\n%s", result, task->xrd_error, task->sys_errno, task->err_msg);
    free(task);
    return 0;
}
