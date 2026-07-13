/*
 * tpc_cred.c — HTTP-TPC credential delegation implementation
 *
 * Acquires OAuth2/OIDC access tokens for third-party-copy pull transfers.
 * Two delegation modes:
 *
 *   oidc-agent     — UNIX-socket JSON IPC to a local oidc-agent daemon
 *   token-exchange — RFC 8693 token-exchange request to an external OAuth2
 *                    token endpoint
 *
 * Both paths are non-blocking from the nginx-worker perspective: external
 * processes are fork/exec'd and their output is read synchronously in a
 * small helper that exits once the token is returned.
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


ngx_int_t
webdav_tpc_cred_metric_increment(ngx_http_request_t *r,
                                 brix_tpc_cred_metrics_e idx)
{
    BRIX_WEBDAV_METRIC_INC(tpc_cred_total[idx]);
    (void) r;
    return NGX_OK;
}

static ngx_int_t
webdav_tpc_cred_validate_token(ngx_http_request_t *r, ngx_str_t *token)
{
    brix_tpc_credential_t cred;

    if (token == NULL || token->data == NULL || token->len == 0) {
        return NGX_ERROR;
    }

    if (brix_tpc_credential_parse(token, BRIX_TPC_CREDENTIAL_TOKEN,
                                    &cred, r->pool, r->connection->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return brix_tpc_credential_validate(&cred, r->connection->log);
}

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
static ngx_int_t
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


/**
 * Perform an RFC 8693 token-exchange request.
 *
 * Sends a POST to the configured token endpoint with:
 *   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
 *   subject_token=<JWT>
 *   resource=<source_url>
 *   audience=<source_url>
 *   scope=<scope>
 *
 * Uses a fork/exec'd curl subprocess (same pattern as tpc_curl.c).
 */
static ngx_int_t
tpc_cred_rfc8693_exchange(ngx_http_request_t *r,
                          const char *subject_token,
                          const char *source_url,
                          const char *scope,
                          const char *token_endpoint,
                          const char *client_id,
                          const char *client_secret,
                          ngx_str_t *token_out)
{
    char buf[TPC_CRED_MAX_TOKEN_LEN + 256];
    char *curl_argv[16];
    int argc = 0;
    char body_buf[2048];
    char body_file[NGX_MAX_PATH];
    int body_fd;

    /* Build the POST body. */
    ngx_snprintf((u_char *) body_buf, sizeof(body_buf),
                  "grant_type=urn:ietf:params:oauth:grant-type:"
                  "token-exchange"
                  "&subject_token=%s"
                  "&resource=%s"
                  "&audience=%s"
                  "&scope=%s",
                  subject_token, source_url, source_url, scope);

    /* Write body to a temp file (curl --data @file). */
    ngx_snprintf((u_char *) body_file, sizeof(body_file),
                 "/tmp/tpc_cred_body_XXXXXX");
    body_fd = mkstemp(body_file);
    if (body_fd == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred(rfc8693): temp file creation failed");
        return NGX_ERROR;
    }

    {
        ssize_t nw = write(body_fd, body_buf, strlen(body_buf));
        (void) nw;
    }
    close(body_fd);

    /* Build curl argv. */
    curl_argv[argc++] = (char *) "curl";
    curl_argv[argc++] = (char *) "-s";          /* silent */
    curl_argv[argc++] = (char *) "-S";          /* show errors */
    curl_argv[argc++] = (char *) "-f";          /* fail on HTTP error */
    curl_argv[argc++] = (char *) "-X";
    curl_argv[argc++] = (char *) "POST";
    curl_argv[argc++] = (char *) "-H";
    curl_argv[argc++] = (char *) "Content-Type: application/x-www-form-urlencoded";
    if (client_id && *client_id) {
        /* Basic auth with client credentials. */
        curl_argv[argc++] = (char *) "-u";
        /* We'd need to base64 encode client_id:client_secret here.
         * For simplicity, pass them separately to curl. */
        curl_argv[argc++] = (char *) client_id;
        curl_argv[argc++] = (char *) client_secret;
    }
    curl_argv[argc++] = (char *) "-d";
    curl_argv[argc++] = (char *) body_file;
    /* W3 — end-of-options terminator so the endpoint URL can never be parsed
     * as a curl option, even if a misconfigured token_endpoint begins with '-'. */
    curl_argv[argc++] = (char *) "--";
    curl_argv[argc++] = (char *) token_endpoint;
    curl_argv[argc++] = NULL;

    /*
     * Run curl synchronously and capture its stdout via the shared SIGCHLD-safe
     * fork/exec helper (src/compat/subprocess.c) — it blocks SIGCHLD across the
     * fork/waitpid internally so nginx's handler can't reap the child first. A
     * non-zero rc = pipe/fork failure or signal-kill; a non-zero child exit
     * (incl. curl -f on HTTP >= 400) is a credential-fetch failure.
     */
    {
        int ec = -1;

        if (brix_subprocess_capture(curl_argv, buf, sizeof(buf), NULL, &ec)
            != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                          "tpc_cred(rfc8693): curl subprocess failed "
                          "(pipe/fork or signal)");
            unlink(body_file);  /* vfs-seam-allow: /tmp credential temp, not export storage */
            return NGX_ERROR;
        }
        if (ec != 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "tpc_cred(rfc8693): curl exited %d: %s", ec, buf);
            unlink(body_file);  /* vfs-seam-allow: /tmp credential temp, not export storage */
            return NGX_ERROR;
        }
    }

    /* Clean up temp file. */
    unlink(body_file);  /* vfs-seam-allow: /tmp credential temp, not export storage */

    /* Parse JSON response for access_token. */
    return tpc_cred_parse_token_response(r, buf, token_out);
}


brix_tpc_cred_mode_e
webdav_tpc_cred_parse_mode(const char *value, size_t len)
{
    if (len == 4 && ngx_strncmp((u_char *) value,
                                (u_char *) "none", 4) == 0)
        return BRIX_TPC_CRED_NONE;

    if (len == 10 && ngx_strncmp((u_char *) value,
                                 (u_char *) "oidc-agent", 10) == 0)
        return BRIX_TPC_CRED_OIDC_AGENT;

    if (len == 14 && ngx_strncmp((u_char *) value,
                                 (u_char *) "token-exchange", 14) == 0)
        return BRIX_TPC_CRED_TOKEN_EXCHANGE;

    return BRIX_TPC_CRED_UNKNOWN;
}

/*
 * WHAT: Immutable bundle of the inputs a single credential-obtain attempt needs.
 * WHY:  It threads the request/URL/subject-token/scope plus the resolved output
 *       slot through the per-mode helpers without re-plumbing the frozen
 *       6-parameter public entry point's argument list at each step.
 * HOW:  Populated once in webdav_tpc_cred_obtain_token and passed by const
 *       pointer; token_out is the caller-owned result slot (mutated in place).
 */
typedef struct {
    ngx_http_request_t *r;
    const char         *source_url;
    const char         *subject_token;
    const char         *scope;
    ngx_str_t          *token_out;
} tpc_cred_request_t;


/*
 * WHAT: Record the success/error metric for a completed obtain attempt.
 * WHY:  Both mode paths share the same "validate on OK, then count" tail, so it
 *       lives once to keep the metric labels identical across modes.
 * HOW:  On NGX_OK re-validate the fetched token, then bump NSUCCESS/NERROR by
 *       the (possibly downgraded) result and return it.
 */
static ngx_int_t
tpc_cred_finish(ngx_http_request_t *r, ngx_str_t *token_out, ngx_int_t rc)
{
    if (rc == NGX_OK) {
        rc = webdav_tpc_cred_validate_token(r, token_out);
    }
    if (rc == NGX_OK) {
        webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NSUCCESS);
    } else {
        webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NERROR);
    }
    return rc;
}


/*
 * WHAT: Run the oidc-agent delegation mode for one request.
 * WHY:  Isolates the OIDC branch so the public dispatcher stays a flat switch.
 * HOW:  Fetch via the oidc-agent pipeline, then fold into the shared
 *       validate-and-count tail.
 */
static ngx_int_t
tpc_cred_run_oidc_agent(const tpc_cred_request_t *req)
{
    ngx_int_t rc = tpc_cred_oidc_agent_fetch(req->r, req->source_url,
                                             req->scope, req->token_out);
    return tpc_cred_finish(req->r, req->token_out, rc);
}


/*
 * WHAT: Run the RFC 8693 token-exchange delegation mode for one request.
 * WHY:  Isolates the exchange branch — config presence, subject-token presence,
 *       then the curl exchange — from the dispatcher.
 * HOW:  Fail-closed (NERROR + diagnostic) when the token endpoint or subject
 *       token is missing; otherwise exchange and fold into the shared tail.
 */
static ngx_int_t
tpc_cred_run_token_exchange(const tpc_cred_request_t *req,
                            ngx_http_brix_webdav_loc_conf_t *wconf)
{
    ngx_http_request_t *r = req->r;
    ngx_int_t rc;

    if (wconf->tpc_cred.token_endpoint.len == 0
        || wconf->tpc_cred.token_endpoint.data == NULL) {
        BRIX_DIAG_ERR(r->connection->log, 0,
            "tpc_cred: token-exchange is selected but no token endpoint "
            "is configured",
            "third-party-copy credential mode is token-exchange, but "
            "brix_webdav_tpc_token_endpoint is unset",
            "set the OAuth token endpoint for your IdP, or switch the TPC "
            "credential mode away from token-exchange");
        webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NERROR);
        return NGX_ERROR;
    }
    if (req->subject_token == NULL || *req->subject_token == '\0') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred: no subject token for token-exchange");
        webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NERROR);
        return NGX_ERROR;
    }

    rc = tpc_cred_rfc8693_exchange(
        r, req->subject_token, req->source_url, req->scope,
        (const char *) wconf->tpc_cred.token_endpoint.data,
        wconf->tpc_cred.token_client_id.len > 0 ?
            (const char *) wconf->tpc_cred.token_client_id.data : NULL,
        wconf->tpc_cred.token_client_secret.len > 0 ?
            (const char *) wconf->tpc_cred.token_client_secret.data : NULL,
        req->token_out);

    return tpc_cred_finish(r, req->token_out, rc);
}


ngx_int_t
webdav_tpc_cred_obtain_token(ngx_http_request_t *r,
                             brix_tpc_cred_mode_e mode,
                             const char *source_url,
                             const char *subject_token,
                             const char *scope,
                             ngx_str_t *token_out)
{
    ngx_http_brix_webdav_loc_conf_t *wconf;
    tpc_cred_request_t req = {
        r, source_url, subject_token, scope, token_out
    };

    wconf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (wconf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred: no WebDAV location config");
        return NGX_ERROR;
    }

    /* Increment started counter. */
    (void) webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NSTARTED);

    switch (mode) {
    case BRIX_TPC_CRED_OIDC_AGENT:
        return tpc_cred_run_oidc_agent(&req);

    case BRIX_TPC_CRED_TOKEN_EXCHANGE:
        return tpc_cred_run_token_exchange(&req, wconf);

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred: unknown delegation mode %d", (int) mode);
        webdav_tpc_cred_metric_increment(r, BRIX_TPC_CRED_NUNKNOWN_MODE);
        return NGX_ERROR;
    }
}

const char *
webdav_tpc_cred_metric_name(brix_tpc_cred_metrics_e idx)
{
    switch (idx) {
    case BRIX_TPC_CRED_NSTARTED:    return "tpc_cred_started";
    case BRIX_TPC_CRED_NSUCCESS:    return "tpc_cred_success";
    case BRIX_TPC_CRED_NERROR:      return "tpc_cred_error";
    case BRIX_TPC_CRED_NUNKNOWN_MODE: return "tpc_cred_unknown_mode";
    case BRIX_TPC_CRED_NPARSE_ERROR: return "tpc_cred_parse_error";
    default:                          return "tpc_cred_unknown";
    }
}
