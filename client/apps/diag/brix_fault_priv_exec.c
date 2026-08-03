/* brix_fault_priv_exec.c — subprocess runners + argument validators for the
 * privileged fault levers.
 *
 * WHAT: The two fork+exec helpers every `tc`/`nft`/`ip` invocation goes through
 *       (one plain, one feeding a ruleset on stdin) and the validators that
 *       every operator-supplied fragment must clear before it can reach an
 *       argv: interface name, percentage, bounded unsigned, and rate.
 *
 * WHY:  Split out of brix_fault_priv.c, which crossed the 600-line cap
 *       (coding-standards §1). These are the pure, state-free half of that TU —
 *       no lock, no global lever state — so they move without exporting any
 *       new mutable state.
 *
 * HOW:  Contracts live in brix_fault_priv_internal.h. Validators return 1 on
 *       accept / 0 on reject and never mutate their input; runners return the
 *       child exit status, or -1 if the child could not be created. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "brix_fault_priv.h"
#include "brix_fault_priv_internal.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* fork+execvp `argv` with stdout silenced (stderr inherited for diagnostics).
 * Returns 0 on a clean exit(0), the child's non-zero exit code otherwise, or -1
 * if the process could not be created. */
int
priv_run(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0) {
            dup2(nul, STDOUT_FILENO);
            close(nul);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
        /* retry */
    }
    if (WIFEXITED(st)) {
        return WEXITSTATUS(st);
    }
    return -1;
}

/* fork+execvp `argv`, piping `input` to the child's stdin (for `nft -f -`).
 * Same return convention as priv_run(). */
int
priv_run_stdin(char *const argv[], const char *input)
{
    int pfd[2];
    if (pipe(pfd) != 0) {
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(pfd[0], STDIN_FILENO);
        close(pfd[0]);
        close(pfd[1]);
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0) {
            dup2(nul, STDOUT_FILENO);
            close(nul);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pfd[0]);
    size_t len = strlen(input), off = 0;
    while (off < len) {
        ssize_t w = write(pfd[1], input + off, len - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        off += (size_t) w;
    }
    close(pfd[1]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
        /* retry */
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* ------------------------------------------------------------ validation ---- */

/* An interface name that both matches a conservative charset and actually exists
 * under /sys/class/net (so a bad --priv-iface fails loudly, not silently). */
int
valid_iface(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n >= IFNAMSIZ) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!isalnum((unsigned char) c) && c != '.' && c != '_' &&
            c != '-' && c != '@') {
            return 0;
        }
    }
    char path[64 + IFNAMSIZ];
    snprintf(path, sizeof(path), "/sys/class/net/%s", s);
    struct stat sb;
    return stat(path, &sb) == 0;
}

/* Format a 0..100 percentage token ("3", "0.1" -> "3%", "0.1%"). Returns 0 ok. */
int
fmt_pct(const char *s, char *out, size_t osz)
{
    char  *end;
    double v = strtod(s, &end);
    if (end == s || v < 0.0 || v > 100.0) {
        return -1;
    }
    snprintf(out, osz, "%g%%", v);
    return 0;
}

/* Format a bounded non-negative integer token. max<=0 means "no upper bound". */
int
fmt_uint(const char *s, char *out, size_t osz, long max)
{
    char *end;
    long  v = strtol(s, &end, 10);
    if (end == s || v < 0 || (max > 0 && v > max)) {
        return -1;
    }
    snprintf(out, osz, "%ld", v);
    return 0;
}

/* A `tc`-style rate token: digits then an optional bit/byte unit. */
int
valid_rate(const char *s)
{
    const char *p = s;
    if (!isdigit((unsigned char) *p)) {
        return 0;
    }
    while (isdigit((unsigned char) *p)) {
        p++;
    }
    static const char *units[] = { "", "bit", "kbit", "mbit", "gbit", "tbit",
                                   "bps", "kbps", "mbps", "gbps", NULL };
    for (int i = 0; units[i]; i++) {
        if (strcmp(p, units[i]) == 0) {
            return 1;
        }
    }
    return 0;
}
