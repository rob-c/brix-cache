/* Finite subprocess contracts, including the agent's real fork/exec branches.
 * Only this single-threaded test consumer flushes coverage before exec/_exit.
 */
#include "core/compat/subprocess.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

void __gcov_dump(void) __attribute__((weak));
void __gcov_reset(void) __attribute__((weak));
void __real__exit(int) __attribute__((noreturn));
int __real_execvp(const char *, char *const []);
pid_t __real_fork(void);
int __real_pipe2(int [2], int);
int __real_socketpair(int, int, int, int [2]);

/* WHAT: Retain the executed child path before the real non-returning syscall.
 * WHY: Normal gcov exit handlers never run across exec or _exit.
 * HOW: 1. Dump when the optional runtime is linked. 2. Perform the real syscall.
 */
void __wrap__exit(int status)
{
    if (__gcov_dump != NULL) { __gcov_dump(); }
    __real__exit(status);
}

/* WHAT: Flush this finite consumer before the real helper executable starts.
 * WHY: Replacing the process would otherwise discard all of its counters.
 * HOW: 1. Dump instrumentation if present. 2. Delegate unchanged argv to exec.
 */
int __wrap_execvp(const char *file, char *const args[])
{
    if (__gcov_dump != NULL && __gcov_reset != NULL) {
        __gcov_dump();
        __gcov_reset();
    }
    return __real_execvp(file, args);
}

/* WHAT: Fail one selected generation of the actual double-fork chain.
 * WHY: Parent, intermediate and agent fork failures must never report success.
 * HOW: 1. Inherit the per-process call count. 2. Fail only the selected ordinal.
 */
pid_t __wrap_fork(void)
{
    static unsigned ordinal;
    const char *selected = getenv("BRIX_SUBPROCESS_TEST_FORK");
    ++ordinal;
    if (selected != NULL && ordinal == strtoul(selected, NULL, 10)) {
        errno = EAGAIN;
        return -1;
    }
    return __real_fork();
}

/* WHAT: Inject pipe allocation failure before spawning any helper.
 * WHY: No successful child status exists when capture setup failed.
 * HOW: 1. Honor the private fault selector. 2. Otherwise call the real PAL syscall.
 */
int __wrap_pipe2(int descriptors[2], int flags)
{
    if (getenv("BRIX_SUBPROCESS_TEST_PIPE") != NULL) {
        errno = EMFILE;
        return -1;
    }
    return __real_pipe2(descriptors, flags);
}

/* WHAT: Fail creation of the agent's status channel on demand.
 * WHY: A missing status transport must not become an exit code of zero.
 * HOW: 1. Honor the fault selector. 2. Otherwise preserve socketpair semantics.
 */
int __wrap_socketpair(int domain, int type, int protocol, int pair[2])
{
    if (getenv("BRIX_SUBPROCESS_TEST_SOCKET") != NULL) {
        errno = EMFILE;
        return -1;
    }
    return __real_socketpair(domain, type, protocol, pair);
}

/* WHAT: Select a failure before the subprocess kernel runs.
 * WHY: Fault injection must be local to one independently launched test case.
 * HOW: 1. Decode the explicit fault name. 2. Set only private test variables.
 */
static void select_fault(const char *mode)
{
    if (strncmp(mode, "fork-", 5) == 0) {
        assert(setenv("BRIX_SUBPROCESS_TEST_FORK", mode + 5, 1) == 0);
    } else if (strcmp(mode, "pipe-failure") == 0) {
        assert(setenv("BRIX_SUBPROCESS_TEST_PIPE", "1", 1) == 0);
    } else if (strcmp(mode, "socket-failure") == 0) {
        assert(setenv("BRIX_SUBPROCESS_TEST_SOCKET", "1", 1) == 0);
    }
}

/* WHAT: Capture one real Python helper or one deterministic setup failure.
 * WHY: Returned bytes, exit status, timeout and descriptor isolation are public ABI.
 * HOW: 1. Own a non-CLOEXEC socket. 2. Run the helper. 3. Report bounded results.
 */
int main(int argc, char **argv)
{
    assert(argc == 4);
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(dup2(pair[0], 400) == 400);
    close(pair[0]); close(pair[1]);
    select_fault(argv[1]);
    char output[16];
    memset(output, 0xa5, sizeof(output));
    char *command[] = {argv[2], "-c", argv[3], NULL};
    brix_subprocess_req_t request = {command, output, sizeof(output), 0};
    if (strcmp(argv[1], "timeout") == 0) { request.timeout_ms = 250; }
    if (strcmp(argv[1], "inherit") == 0) { request.out = NULL; request.outsz = 0; }
    if (strcmp(argv[1], "invalid") == 0) { request.outsz = 0; }
    if (strcmp(argv[1], "missing") == 0) { command[0] = "/missing-brix-test-helper"; }
    size_t length = 999;
    int status = 999;
    errno = 0;
    int result = brix_subprocess_run(&request, &length, &status);
    int saved_errno = errno;
    assert(length < sizeof(output));
    if (length != 0) { assert(output[length] == '\0'); }
    assert(fcntl(400, F_GETFD) >= 0);
    close(400);
    printf("%d:%d:%d:%zu:", result, status, saved_errno, length);
    for (size_t index = 0; index < length; ++index) {
        printf("%02x", (unsigned char) output[index]);
    }
    puts("");
    return 0;
}
