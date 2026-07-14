#include "query_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * prepare_cmd.c — Fire-and-forget subprocess invocation for kXR_prepare staging.
 *
 * WHAT: When a kXR_prepare request carries the kXR_stage flag and
 *       brix_prepare_command is configured, this module forks a subprocess
 *       that exec()s the configured command with the resolved absolute paths as
 *       arguments.  The parent returns immediately (fire-and-forget); SIGCHLD
 *       is handled by nginx's existing reap-children logic (double-fork or
 *       signal handler).
 *
 * WHY:  Tape backends (EOS tape, dCache nearline, Rucio + FTS) expose a
 *       scriptable hook interface for staging recalls.  Delegating to an
 *       external command keeps the nginx module agnostic of the specific
 *       backend API.
 *
 * HOW:  fork() → child closes inherited fds (fd ≥ 3) → execv(command, argv)
 *       → _exit(127) on exec failure.  The parent does NOT waitpid(): the
 *       child becomes an orphan immediately reaped by init/systemd.
 *
 *       argv layout:   argv[0]   = command path (first token of prepare_command)
 *                      argv[1..n]= absolute resolved paths
 *                      argv[n+1] = NULL
 *
 * SECURITY:
 *   - Path arguments have already been confined and auth-checked by the
 *     caller (brix_handle_prepare); no further validation is needed here.
 *   - All fds ≥ 3 are closed in the child to avoid leaking nginx sockets.
 *   - FD_CLOEXEC is the belt; closing explicitly is the suspenders.
 *   - The command is execv()ed directly — no shell expansion, no injection.
 */

/* Maximum resolved paths passed to the staging command per request — defined
 * in query_internal.h as BRIX_PREPARE_CMD_MAX_PATHS (512). */

/* ---- Build the NULL-terminated execv() argv for the staging command ----
 *
 * WHAT: Allocates and fills the argv vector handed to execv(): argv[0] is the
 *       configured command path, argv[1..count] are the resolved absolute
 *       paths, and argv[count+1] is NULL. Returns the vector, or NULL on
 *       allocation failure (caller maps NULL to NGX_ERROR).
 *
 * WHY:  Isolating vector construction keeps the fork/exec orchestrator free of
 *       index arithmetic and makes the argv layout — the security-relevant
 *       "no shell, direct execv" contract — reviewable in one place.
 *
 * HOW:  1. ngx_alloc (count + 2) pointer slots from the worker; bail on NULL.
 *       2. Store the command path (already validated by the caller) at argv[0].
 *       3. Copy each resolved path pointer into argv[1..count].
 *       4. NULL-terminate at argv[count+1] and return the vector.
 */
static char **
brix_prepare_build_argv(ngx_log_t *log, ngx_stream_brix_srv_conf_t *conf,
    const char **paths, ngx_uint_t count)
{
    char       **argv;
    ngx_uint_t   i;

    argv = ngx_alloc((count + 2) * sizeof(char *), log);
    if (argv == NULL) {
        return NULL;
    }

    argv[0] = (char *) conf->prepare_command.data;
    for (i = 0; i < count; i++) {
        argv[i + 1] = (char *) paths[i];
    }
    argv[count + 1] = NULL;

    return argv;
}

/* ---- Close every inherited file descriptor >= 3 in the exec child ----
 *
 * WHAT: Closes all file descriptors at or above 3 (leaving stdin/out/err) so
 *       the external staging command inherits none of nginx's listening
 *       sockets, log fds, or pipe ends. No return value.
 *
 * WHY:  FD_CLOEXEC is the belt; this explicit close is the suspenders —
 *       descriptors opened without CLOEXEC would otherwise leak across execv,
 *       exposing nginx internals to an untrusted subprocess.
 *
 * HOW:  1. On Linux, opendir("/proc/self/fd") for the exact set of open fds.
 *       2. Capture dirfd(dp) and skip it — closing the stream's own backing fd
 *          mid-scan would invalidate readdir; closedir releases it afterward.
 *       3. For each entry, parse the decimal fd name; close it when >= 3 and it
 *          is not dirfd_self ("." / ".." parse to 0 and fail the >= 3 guard).
 *       4. If opendir fails (or off Linux), brute-force close 3..sysconf limit,
 *          defaulting the limit to 1024 when sysconf reports unknown.
 */
static void
brix_prepare_close_inherited_fds(void)
{
    int fd, maxfd;

#if defined(__linux__)
    {
        DIR *dp = opendir("/proc/self/fd");  /* vfs-seam-allow: /proc fd hygiene before execv, not export storage */
        if (dp != NULL) {
            struct dirent *de;
            /*
             * dirfd_self captures the fd backing this very directory stream.
             * It appears as one of the /proc/PID/fd entries we iterate, so we
             * must skip closing it: closing it out from under readdir would
             * invalidate the open DIR* mid-scan, and closedir(dp) below is what
             * properly releases it. Every OTHER fd >= 3 is an inherited nginx
             * socket/log/pipe and is closed before execv.
             */
            int            dirfd_self = dirfd(dp);
            while ((de = readdir(dp)) != NULL) {  /* vfs-seam-allow: /proc fd hygiene, not export storage */
                /* entry names are decimal fd numbers; non-numeric ("." "..")
                 * parse to 0 and are filtered by the fd >= 3 guard. */
                fd = (int) strtol(de->d_name, NULL, 10);
                if (fd >= 3 && fd != dirfd_self) {
                    close(fd);
                }
            }
            closedir(dp);
            return;
        }
        /* opendir failed: fall through to brute-force scan */
    }
#endif

    maxfd = (int) sysconf(_SC_OPEN_MAX);
    if (maxfd < 0) { maxfd = 1024; }
    for (fd = 3; fd < maxfd; fd++) { close(fd); }
}

/* ---- Grandchild tail: sanitise environment/fds, then execv the command ----
 *
 * WHAT: Runs in the reparented grandchild. Optionally exports the coloc marker,
 *       closes inherited fds, and execv()s the staging command. Never returns:
 *       execv replaces the image on success, and _exit(127) terminates on any
 *       exec failure.
 *
 * WHY:  The exec tail is the single point where an untrusted external image
 *       takes over the process, so its environment/fd hygiene is grouped here,
 *       separate from the fork orchestration, to keep that contract auditable.
 *
 * HOW:  1. If coloc, set BRIX_PREPARE_COLOC=1 in the environment (before exec).
 *       2. Close all inherited fds >= 3 (see brix_prepare_close_inherited_fds).
 *       3. execv(argv[0], argv) — direct exec, no shell, no injection.
 *       4. Only reached on exec error: _exit(127).
 */
static void
brix_prepare_exec_child(char **argv, ngx_flag_t coloc)
{
    if (coloc) {
        setenv("BRIX_PREPARE_COLOC", "1", 1);
    }

    brix_prepare_close_inherited_fds();

    execv(argv[0], argv);

    /* execv() only returns on error */
    _exit(127);
}

ngx_int_t
brix_prepare_invoke_command(ngx_log_t *log,
    ngx_stream_brix_srv_conf_t *conf,
    const char **paths, ngx_uint_t count, ngx_flag_t coloc)
{
    pid_t   pid;
    char  **argv;

    argv = brix_prepare_build_argv(log, conf, paths, count);
    if (argv == NULL) {
        return NGX_ERROR;
    }

    pid = fork();
    if (pid < 0) {
        ngx_free(argv);
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix: prepare_command fork() failed");
        return NGX_ERROR;
    }

    if (pid == 0) {
        /* First child: double-fork so that the grandchild that actually runs
         * the staging command is reparented to init/PID-1, not to the nginx
         * worker.  Without the double-fork, when the staging script exits,
         * SIGCHLD is delivered to the nginx worker, which crashes because
         * the forked pid is not in nginx's internal process table. */
        pid_t gpid = fork();
        if (gpid != 0) {
            /* First child exits immediately regardless of fork result.
             * On success: grandchild carries on. On failure: nothing runs,
             * but at least the worker does not crash. */
            _exit(0);
        }
        /* Grandchild: run the exec tail; never returns. */
        brix_prepare_exec_child(argv, coloc);
    }

    /* Parent (nginx worker): wait for the first child only — it exits
     * almost immediately, so this waitpid() is nearly instantaneous and
     * does NOT block the event loop for a meaningful duration.
     * The grandchild is now an orphan reaped by init. */
    int wstatus;
    waitpid(pid, &wstatus, 0);
    ngx_free(argv);
    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "brix: prepare_command spawned pid %P for %ui path(s)%s",
                  pid, count, coloc ? " (coloc)" : "");
    return NGX_OK;
}
