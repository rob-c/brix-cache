/* Test-only counter retention at a single-threaded CLI's real exec boundary.
 * The private test executable still runs the real exec syscalls and children.
 */
#include <unistd.h>

void __gcov_dump(void) __attribute__((weak));
void __gcov_reset(void) __attribute__((weak));
int __real_execv(const char *, char *const []);
int __real_execvp(const char *, char *const []);
int __real_execve(const char *, char *const [], char *const []);
void __real__exit(int) __attribute__((noreturn));

/* WHAT: Persist executed counters, then allow a failed exec to keep measuring.
 * WHY: Exec replaces the process without running gcov's normal exit handler.
 * HOW: 1. Dump when linked. 2. Reset the dump guard and counters before exec.
 */
static void retain_before_exec(void)
{
    if (__gcov_dump != NULL && __gcov_reset != NULL) {
        __gcov_dump();
        __gcov_reset();
    }
}

/* WHAT: Preserve the real execv result and child argv.
 * WHY: Tests validate sibling dispatch, not an emulated command launcher.
 * HOW: 1. Retain counters. 2. Delegate to libc unchanged.
 */
int __wrap_execv(const char *path, char *const args[])
{
    retain_before_exec();
    return __real_execv(path, args);
}

/* WHAT: Preserve the real PATH search and execvp failure behavior.
 * WHY: Prefix fallback must execute the actual selected fixture program.
 * HOW: 1. Retain counters. 2. Delegate to libc unchanged.
 */
int __wrap_execvp(const char *file, char *const args[])
{
    retain_before_exec();
    return __real_execvp(file, args);
}

/* WHAT: Preserve the real explicit environment and execve result.
 * WHY: Credential helpers must execute with their controlled child environment.
 * HOW: 1. Retain counters. 2. Delegate the unchanged path, argv, and environment.
 */
int __wrap_execve(const char *path, char *const args[], char *const environment[])
{
    retain_before_exec();
    return __real_execve(path, args, environment);
}

/* WHAT: Retain a terminal dispatch failure before the real _exit.
 * WHY: A missing sibling must still report its actual exit code of 127.
 * HOW: 1. Dump counters. 2. Leave through the original syscall.
 */
void __wrap__exit(int status)
{
    if (__gcov_dump != NULL) { __gcov_dump(); }
    __real__exit(status);
}
