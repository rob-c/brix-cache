/*
 * tpc_cred_oidc.c — HTTP-TPC oidc-agent credential delegation
 *
 * The oidc-agent delegation mode: acquire an OAuth2/OIDC access token for a
 * third-party-copy pull transfer via a local oidc-agent daemon (UNIX-socket
 * JSON IPC) or the `oidc-token` CLI fallback.  Split verbatim from tpc_cred.c
 * (mechanical file-size split) — the credential-parse cluster stays in
 * tpc_cred.c.
 *
 * Non-blocking from the nginx-worker perspective: an external process is
 * fork/exec'd and its output read synchronously in a small helper that exits
 * once the token is returned.
 */

#include "tpc_cred_internal.h"
#include "tpc_config.h"
#include "webdav.h"
#include "core/compat/log_diag.h"
#include "tpc/common/credential.h"
#include "core/compat/subprocess.h"   /* shared SIGCHLD-safe fork/exec capture */

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>


/* Path to the dedicated oidc-agent helper binary. */
#define TPC_CRED_HELPER_PATH    "/usr/local/sbin/nginx-xrootd-tpc-cred"

/*
 * WHAT: Resolve the oidc-token binary to an absolute path — first honours an
 *       explicit override env var, then probes standard install locations.
 * WHY:  The fallback exec path must not be subject to $PATH substitution in the
 *       daemon's environment (a compromised PATH entry could shadow the real binary).
 * HOW:  secure_getenv("BRIX_OIDC_TOKEN_BIN") if access(X_OK) passes; else
 *       walk a fixed candidate list; return NULL if none executable.
 */
static const char *
resolve_oidc_token_binary(void)
{
    static const char *const candidates[] = {
        "/usr/bin/oidc-token", "/usr/local/bin/oidc-token", NULL
    };
    const char *const *p;
    const char *override = secure_getenv("BRIX_OIDC_TOKEN_BIN");

    if (override != NULL && access(override, X_OK) == 0) {
        return override;
    }
    for (p = candidates; *p != NULL; p++) {
        if (access(*p, X_OK) == 0) {
            return *p;
        }
    }
    return NULL;
}


/*
 * WHAT: Resolve the oidc-agent UNIX-socket path from the environment.
 * WHY:  A per-user oidc-agent exports its control socket via $OIDC_SOCK; when
 *       unset we fall back to the conventional systemd user-runtime location so
 *       the helper still has a well-known path to try.
 * HOW:  Return $OIDC_SOCK verbatim when non-empty, else the fixed default; the
 *       result aliases process-owned storage, so the caller must not free it.
 */
static ngx_str_t
oidc_resolve_socket_path(const char *sock_env)
{
    ngx_str_t sock_path;

    if (sock_env != NULL && *sock_env != '\0') {
        sock_path.data = (u_char *) sock_env;
        sock_path.len = strlen(sock_env);
        return sock_path;
    }

    /* Default oidc-agent socket location. */
    sock_path.data = (u_char *) "/run/user/1000/oidc/oidc_agent.sock";
    sock_path.len = strlen((char *) sock_path.data);
    return sock_path;
}


/*
 * WHAT: Choose the executable that fetches the token — the dedicated helper if
 *       installed, otherwise the `oidc-token` CLI on $PATH.
 * WHY:  Deployments that ship the packaged helper get the socket-IPC path; a
 *       plain oidc-agent install still works through the CLI fallback.
 * HOW:  Probe TPC_CRED_HELPER_PATH with access(X_OK); on failure return the
 *       literal "oidc-token" so the child branch can exec it via $PATH.
 */
static ngx_str_t
oidc_resolve_helper_path(void)
{
    ngx_str_t helper_path;

    helper_path.data = (u_char *) TPC_CRED_HELPER_PATH;
    helper_path.len = strlen(TPC_CRED_HELPER_PATH);

    if (access((char *) helper_path.data, X_OK) == 0) {
        return helper_path;
    }

    /* Fall back to oidc-token CLI (must be in PATH). */
    helper_path.data = (u_char *) "oidc-token";
    helper_path.len = 10;
    return helper_path;
}


/*
 * WHAT: Derive the oidc-agent client name from a source URL's host, with an
 *       option-injection guard, into the caller-provided buffer.
 * WHY:  oidc-agent clients are conventionally named by host, but that host
 *       becomes the value of oidc-token's "-c" flag; a host beginning with '-'
 *       (impossible under RFC 952/1123) would be reparsed by getopt as a flag.
 * HOW:  Copy the URL authority up to the first '/', clamp to the buffer, then
 *       replace any leading-'-'/empty result with the safe literal "default".
 */
static void
oidc_derive_client_name(const char *source_url, char *out, size_t out_sz)
{
    const char *host_start = strstr(source_url, "://");

    if (host_start != NULL) {
        const char *host_end;
        size_t host_len;

        host_start += 3;
        host_end = strchr(host_start, '/');
        if (host_end != NULL) {
            host_len = (size_t) (host_end - host_start);
        } else {
            host_len = strlen(host_start);
        }

        if (host_len >= out_sz) {
            host_len = out_sz - 1;
        }
        ngx_memcpy(out, host_start, host_len);
        out[host_len] = '\0';
    } else {
        ngx_memcpy(out, "default", sizeof("default"));
    }

    /*
     * W3 — option-injection guard.  A legitimate hostname never begins with '-'
     * (RFC 952/1123), so reject one that does and fall back to "default".
     */
    if (out[0] == '-' || out[0] == '\0') {
        ngx_memcpy(out, "default", sizeof("default"));
    }
}


/*
 * WHAT: In the forked child, exec the `oidc-token` CLI fallback for a client.
 * WHY:  The CLI must run with an absolute binary path and a minimal controlled
 *       environment — a compromised $PATH or inherited env in the daemon could
 *       otherwise shadow the binary or influence its behaviour.
 * HOW:  Resolve the absolute oidc-token binary, build "-c <client>" argv and a
 *       PATH/HOME/OIDC_SOCK/XDG_RUNTIME_DIR envp, then execve; return on failure
 *       so the caller can _exit (this runs only in the child, never returns on
 *       success).
 */
static void
oidc_child_exec_cli(const char *source_url, const char *sock_env)
{
    const char *fb_bin = resolve_oidc_token_binary();
    char cli_client[64];
    char cli_flag[3];

    if (fb_bin == NULL) {
        return;
    }

    oidc_derive_client_name(source_url, cli_client, sizeof(cli_client));

    cli_flag[0] = '-';
    cli_flag[1] = 'c';
    cli_flag[2] = '\0';

    {
        const char *home_val = getenv("HOME");
        const char *xdg_val  = getenv("XDG_RUNTIME_DIR");
        char  home_buf[280], oidc_buf[280], xdg_buf[280];
        char *fb_argv[4] = { (char *) fb_bin, cli_flag, cli_client, NULL };
        char *fb_envp[5];
        int   ei = 0;

        fb_envp[ei++] = "PATH=/usr/bin:/bin";
        if (home_val != NULL) {
            snprintf(home_buf, sizeof(home_buf), "HOME=%s", home_val);
            fb_envp[ei++] = home_buf;
        }
        if (sock_env != NULL && *sock_env != '\0') {
            snprintf(oidc_buf, sizeof(oidc_buf), "OIDC_SOCK=%s", sock_env);
            fb_envp[ei++] = oidc_buf;
        }
        if (xdg_val != NULL) {
            snprintf(xdg_buf, sizeof(xdg_buf), "XDG_RUNTIME_DIR=%s", xdg_val);
            fb_envp[ei++] = xdg_buf;
        }
        fb_envp[ei] = NULL;
        execve(fb_bin, fb_argv, fb_envp);
    }
}


/*
 * WHAT: The child half of the fork — wire stdout to the pipe and exec either the
 *       dedicated helper or the oidc-token CLI.  Never returns.
 * WHY:  Isolating the child path keeps the parent orchestrator linear and makes
 *       the exec choices auditable in one place.
 * HOW:  dup2 the write end onto STDOUT, then dispatch on helper_path: CLI branch
 *       delegates to oidc_child_exec_cli, helper branch execs the packaged
 *       binary with "<sock> <url>" argv; _exit(127) if any exec fails.
 */
static void
oidc_run_child(int pipefd[2], ngx_str_t helper_path, ngx_str_t sock_path,
               const char *source_url, const char *sock_env)
{
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);

    if (ngx_strcmp((char *) helper_path.data, "oidc-token") == 0) {
        oidc_child_exec_cli(source_url, sock_env);
    } else {
        /* Exec the dedicated helper: <helper> <sock-path> <source-url>. */
        char helper_buf[512];
        char *argv[4];

        ngx_snprintf((u_char *) helper_buf, sizeof(helper_buf),
                     "%s", (char *) sock_path.data);
        argv[0] = (char *) helper_path.data;
        argv[1] = helper_buf;          /* socket path */
        argv[2] = (char *) source_url; /* source URL (for issuer) */
        argv[3] = NULL;

        execve(argv[0], argv, NULL);
    }

    _exit(127);
}


/*
 * WHAT: Drain a pipe read end fully into buf, NUL-terminating it, and close it.
 * WHY:  The child's token can arrive in several read() chunks; a single owned
 *       loop keeps the parent orchestrator flat.
 * HOW:  Read until EOF/error or the buffer is one byte from full, NUL-terminate
 *       at the byte count, close read_fd, and return the count.  buf_sz >= 1.
 */
static ssize_t
oidc_drain_pipe(int read_fd, char *buf, size_t buf_sz)
{
    ssize_t nread = 0;

    while (nread < (ssize_t) buf_sz - 1) {
        ssize_t nr = read(read_fd, buf + nread,
                          buf_sz - 1 - (size_t) nread);
        if (nr <= 0) {
            break;
        }
        nread += nr;
    }
    buf[nread] = '\0';
    close(read_fd);
    return nread;
}


/*
 * WHAT: Reap the child and restore the pre-fork signal mask, mapping its exit to
 *       NGX_OK / NGX_ERROR.
 * WHY:  SIGCHLD is blocked across the fork so nginx's handler cannot reap our
 *       PID first; the wait + mask restore must happen together, exactly once.
 * HOW:  waitpid, restore old_mask, then treat any non-zero / signalled exit as a
 *       fetch failure.
 */
static ngx_int_t
oidc_reap_child(ngx_http_request_t *r, ngx_pid_t pid, const sigset_t *old_mask)
{
    int wstatus = 0;

    waitpid(pid, &wstatus, 0);
    sigprocmask(SIG_SETMASK, old_mask, NULL);

    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred(oidc): helper exited with status %d",
                      WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * WHAT: Turn the child's raw stdout into a token in *token_out.
 * WHY:  The helper may emit either a JSON access-token response or a bare token
 *       string; both must resolve to the same ngx_str_t token result.
 * HOW:  Strip trailing whitespace, then parse as JSON when it opens with '{',
 *       else pool-copy the trimmed bytes as the literal token.
 */
static ngx_int_t
oidc_finalize_token(ngx_http_request_t *r, char *buf, ssize_t nread,
                    ngx_str_t *token_out)
{
    while (nread > 0 &&
           (buf[nread - 1] == '\n' || buf[nread - 1] == '\r' ||
            buf[nread - 1] == ' '))
    {
        nread--;
    }
    buf[nread] = '\0';

    /* Try to parse as JSON first (helper may return JSON). */
    if (buf[0] == '{') {
        return tpc_cred_parse_token_response(r, buf, token_out);
    }

    /* Fallback: treat as raw token string. */
    token_out->len = (size_t) nread;
    token_out->data = ngx_pnalloc(r->pool, nread + 1);
    if (token_out->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred(oidc): pnalloc failed for token");
        return NGX_ERROR;
    }
    memcpy(token_out->data, buf, nread);
    token_out->data[nread] = '\0';

    return NGX_OK;
}


/**
 * Send a JSON request to the oidc-agent UNIX socket and read the token.
 *
 * Spawns a tiny fork/exec pipeline:
 *   nginx-worker → fork → exec "oidc-token -c <client>" or socket helper
 *
 * If the OIDC_SOCK environment variable is set, we connect directly to it.
 * Otherwise we fall back to the default oidc-agent socket location.
 *
 * The helper process is: src/webdav/tpc_cred_oidc_helper (built separately)
 * which handles the socket IPC.  If that helper binary is not found we
 * attempt a simpler approach using the `oidc-token` CLI if available.
 */
ngx_int_t
tpc_cred_oidc_agent_fetch(ngx_http_request_t *r,
                          const char *source_url,
                          const char *scope,
                          ngx_str_t *token_out)
{
    ngx_pid_t pid;
    int pipefd[2];
    char buf[TPC_CRED_MAX_TOKEN_LEN + 64];
    ssize_t nread = 0;
    const char *sock_env = getenv("OIDC_SOCK");
    ngx_str_t sock_path = oidc_resolve_socket_path(sock_env);
    ngx_str_t helper_path = oidc_resolve_helper_path();
    sigset_t old_mask, blk_mask;
    ngx_int_t rc;

    (void) scope;

    /* Block SIGCHLD before fork so nginx's handler can't reap our child
     * before we do.  We restore the mask after waitpid(). */
    sigemptyset(&blk_mask);
    sigaddset(&blk_mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &blk_mask, &old_mask);

    /* Create a pipe for the child's stdout → parent's read end. */
    if (pipe(pipefd) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                      "tpc_cred(oidc): pipe() failed");
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        return NGX_ERROR;
    }

    pid = fork();
    if (pid == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                      "tpc_cred(oidc): fork() failed");
        close(pipefd[0]);
        close(pipefd[1]);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        return NGX_ERROR;
    }

    if (pid == 0) {
        /* Child process — never returns. */
        oidc_run_child(pipefd, helper_path, sock_path, source_url, sock_env);
    }

    /* Parent: read child's stdout, then reap it. */
    close(pipefd[1]);

    nread = oidc_drain_pipe(pipefd[0], buf, sizeof(buf));

    rc = oidc_reap_child(r, pid, &old_mask);
    if (rc != NGX_OK) {
        return rc;
    }

    return oidc_finalize_token(r, buf, nread, token_out);
}
