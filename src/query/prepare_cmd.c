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
 *       xrootd_prepare_command is configured, this module forks a subprocess
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
 *     caller (xrootd_handle_prepare); no further validation is needed here.
 *   - All fds ≥ 3 are closed in the child to avoid leaking nginx sockets.
 *   - FD_CLOEXEC is the belt; closing explicitly is the suspenders.
 *   - The command is execv()ed directly — no shell expansion, no injection.
 */

/* Maximum resolved paths passed to the staging command per request — defined
 * in query_internal.h as XROOTD_PREPARE_CMD_MAX_PATHS (512). */

ngx_int_t
xrootd_prepare_invoke_command(ngx_log_t *log,
    ngx_stream_xrootd_srv_conf_t *conf,
    const char **paths, ngx_uint_t count, ngx_flag_t coloc)
{
    pid_t   pid;
    char  **argv;
    ngx_uint_t i;
    int     fd, maxfd;

    /* argv[0] = command, argv[1..count] = paths, argv[count+1] = NULL */
    argv = ngx_alloc((count + 2) * sizeof(char *), log);
    if (argv == NULL) {
        return NGX_ERROR;
    }

    argv[0] = (char *) conf->prepare_command.data;
    for (i = 0; i < count; i++) {
        argv[i + 1] = (char *) paths[i];
    }
    argv[count + 1] = NULL;

    pid = fork();
    if (pid < 0) {
        ngx_free(argv);
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd: prepare_command fork() failed");
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
        /* Grandchild falls through to the fd-closing + execv path below. */
    }

    if (pid > 0) {
        /* Parent (nginx worker): wait for the first child only — it exits
         * almost immediately, so this waitpid() is nearly instantaneous and
         * does NOT block the event loop for a meaningful duration.
         * The grandchild is now an orphan reaped by init. */
        int wstatus;
        waitpid(pid, &wstatus, 0);
        ngx_free(argv);
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "xrootd: prepare_command spawned pid %P for %ui path(s)%s",
                      pid, count, coloc ? " (coloc)" : "");
        return NGX_OK;
    }

    /* --- grandchild process --- */

    if (coloc) {
        setenv("XROOTD_PREPARE_COLOC", "1", 1);
    }

    /* Close all inherited file descriptors ≥ 3 so we don't leak nginx
     * listening sockets, log file descriptors, or pipe ends to the external
     * command.  /proc/self/fd is the fast path on Linux; fall back to a
     * brute-force scan up to the system limit. */
#if defined(__linux__)
    {
        DIR *dp = opendir("/proc/self/fd");
        if (dp != NULL) {
            struct dirent *de;
            int            dirfd_self = dirfd(dp);
            while ((de = readdir(dp)) != NULL) {
                fd = (int) strtol(de->d_name, NULL, 10);
                if (fd >= 3 && fd != dirfd_self) {
                    close(fd);
                }
            }
            closedir(dp);
        } else {
            /* opendir failed: fall through to brute-force scan */
            maxfd = (int) sysconf(_SC_OPEN_MAX);
            if (maxfd < 0) { maxfd = 1024; }
            for (fd = 3; fd < maxfd; fd++) { close(fd); }
        }
    }
#else
    maxfd = (int) sysconf(_SC_OPEN_MAX);
    if (maxfd < 0) { maxfd = 1024; }
    for (fd = 3; fd < maxfd; fd++) { close(fd); }
#endif

    execv(argv[0], argv);

    /* execv() only returns on error */
    _exit(127);
}
