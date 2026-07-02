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
#include "compat/log_diag.h"
#include "tpc/common/credential.h"
#include "compat/subprocess.h"   /* shared SIGCHLD-safe fork/exec capture */

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
                                 xrootd_tpc_cred_metrics_e idx)
{
    XROOTD_WEBDAV_METRIC_INC(tpc_cred_total[idx]);
    (void) r;
    return NGX_OK;
}

static ngx_int_t
webdav_tpc_cred_validate_token(ngx_http_request_t *r, ngx_str_t *token)
{
    xrootd_tpc_credential_t cred;

    if (token == NULL || token->data == NULL || token->len == 0) {
        return NGX_ERROR;
    }

    if (xrootd_tpc_credential_parse(token, XROOTD_TPC_CREDENTIAL_TOKEN,
                                    &cred, r->pool, r->connection->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return xrootd_tpc_credential_validate(&cred, r->connection->log);
}

/* Path to the dedicated oidc-agent helper binary. */
#define TPC_CRED_HELPER_PATH    "/usr/local/sbin/nginx-xrootd-tpc-cred"

/*
 * WHAT: Resolve the oidc-token binary to an absolute path — first honours an
 *       explicit override env var, then probes standard install locations.
 * WHY:  The fallback exec path must not be subject to $PATH substitution in the
 *       daemon's environment (a compromised PATH entry could shadow the real binary).
 * HOW:  secure_getenv("XROOTD_OIDC_TOKEN_BIN") if access(X_OK) passes; else
 *       walk a fixed candidate list; return NULL if none executable.
 */
static const char *
resolve_oidc_token_binary(void)
{
    static const char *const candidates[] = {
        "/usr/bin/oidc-token", "/usr/local/bin/oidc-token", NULL
    };
    const char *const *p;
    const char *override = secure_getenv("XROOTD_OIDC_TOKEN_BIN");

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
    ssize_t nread;
    const char *sock_env;
    ngx_str_t sock_path;
    ngx_str_t helper_path;
    char *argv[4];
    char helper_buf[512];

    /* Determine the OIDC socket path. */
    sock_env = getenv("OIDC_SOCK");
    if (sock_env && *sock_env) {
        sock_path.data = (u_char *) sock_env;
        sock_path.len = strlen(sock_env);
    } else {
        /* Default oidc-agent socket location. */
        sock_path.data = (u_char *) "/run/user/1000/oidc/oidc_agent.sock";
        sock_path.len = strlen((char *) sock_path.data);
    }

    /* Try the dedicated helper binary first. */
    helper_path.data = (u_char *) TPC_CRED_HELPER_PATH;
    helper_path.len = strlen(TPC_CRED_HELPER_PATH);

    if (access((char *) helper_path.data, X_OK) == 0) {
        /* Helper exists — use it. */
    } else {
        /* Fall back to oidc-token CLI (must be in PATH). */
        helper_path.data = (u_char *) "oidc-token";
        helper_path.len = 10;
    }

    /* Block SIGCHLD before fork so nginx's handler can't reap our child
     * before we do.  We restore the mask after waitpid(). */
    sigset_t _old_mask_oidc, _blk_mask_oidc;
    sigemptyset(&_blk_mask_oidc);
    sigaddset(&_blk_mask_oidc, SIGCHLD);
    sigprocmask(SIG_BLOCK, &_blk_mask_oidc, &_old_mask_oidc);

    /* Create a pipe for the child's stdout → parent's read end. */
    if (pipe(pipefd) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                      "tpc_cred(oidc): pipe() failed");
        sigprocmask(SIG_SETMASK, &_old_mask_oidc, NULL);
        return NGX_ERROR;
    }

    pid = fork();
    if (pid == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                      "tpc_cred(oidc): fork() failed");
        close(pipefd[0]);
        close(pipefd[1]);
        sigprocmask(SIG_SETMASK, &_old_mask_oidc, NULL);
        return NGX_ERROR;
    }

    if (pid == 0) {
        /* Child process. */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        /* Re-exec: either the helper binary or oidc-token CLI. */
        if (ngx_strcmp((char *) helper_path.data, "oidc-token") == 0) {
            /* Use oidc-token CLI: oidc-token -c <client> */
            /* For simplicity, use the source URL host as the client name.
             * oidc-agent clients are typically named by host. */
            const char *host_start = strstr((char *) source_url, "://");
            char cli_argv[3][64];

            if (host_start) {
                host_start += 3;
                const char *host_end = strchr(host_start, '/');
                size_t host_len;
                if (host_end)
                    host_len = (size_t)(host_end - host_start);
                else
                    host_len = strlen(host_start);

                if (host_len >= sizeof(cli_argv[0]))
                    host_len = sizeof(cli_argv[0]) - 1;
                ngx_memcpy(cli_argv[0], host_start, host_len);
                cli_argv[0][host_len] = '\0';
            } else {
                ngx_memcpy(cli_argv[0], "default", sizeof("default"));
            }

            /*
             * W3 — option-injection guard.  cli_argv[0] is the client-derived
             * host passed as the value of oidc-token's "-c" flag.  oidc-token
             * parses options with getopt, so a host like "-x" or "--config"
             * would be misinterpreted as a flag.  A legitimate hostname never
             * begins with '-' (RFC 952/1123), so reject one that does and fall
             * back to the safe literal "default".
             */
            if (cli_argv[0][0] == '-' || cli_argv[0][0] == '\0') {
                ngx_memcpy(cli_argv[0], "default", sizeof("default"));
            }

            cli_argv[1][0] = '-';
            cli_argv[1][1] = 'c';
            cli_argv[1][2] = '\0';

            /* Resolve to an absolute path — avoid $PATH substitution risk in
             * the daemon's potentially untrusted environment.  Build a minimal
             * controlled envp: PATH + HOME + OIDC_SOCK + XDG_RUNTIME_DIR only. */
            {
                const char *fb_bin = resolve_oidc_token_binary();
                if (fb_bin != NULL) {
                    const char *home_val = getenv("HOME");
                    const char *xdg_val  = getenv("XDG_RUNTIME_DIR");
                    const char *oidc_val = sock_env;  /* already resolved above */
                    char  home_buf[280], oidc_buf[280], xdg_buf[280];
                    char *fb_argv[4] = {
                        (char *) fb_bin, cli_argv[1], cli_argv[0], NULL
                    };
                    char *fb_envp[5];
                    int   ei = 0;

                    fb_envp[ei++] = "PATH=/usr/bin:/bin";
                    if (home_val != NULL) {
                        snprintf(home_buf, sizeof(home_buf), "HOME=%s", home_val);
                        fb_envp[ei++] = home_buf;
                    }
                    if (oidc_val != NULL && *oidc_val != '\0') {
                        snprintf(oidc_buf, sizeof(oidc_buf),
                                 "OIDC_SOCK=%s", oidc_val);
                        fb_envp[ei++] = oidc_buf;
                    }
                    if (xdg_val != NULL) {
                        snprintf(xdg_buf, sizeof(xdg_buf),
                                 "XDG_RUNTIME_DIR=%s", xdg_val);
                        fb_envp[ei++] = xdg_buf;
                    }
                    fb_envp[ei] = NULL;
                    execve(fb_bin, fb_argv, fb_envp);
                }
            }
            _exit(127);
        } else {
            /* Exec the dedicated helper. */
            /* Build a null-terminated argv array. */
            ngx_snprintf((u_char *) helper_buf, sizeof(helper_buf),
                         "%s", (char *) sock_path.data);
            argv[0] = (char *) helper_path.data;
            argv[1] = helper_buf;          /* socket path */
            argv[2] = (char *) source_url; /* source URL (for issuer) */
            argv[3] = NULL;

            execve(argv[0], argv, NULL);
            _exit(127);
        }
    }

    /* Parent: read child's stdout. */
    close(pipefd[1]);

    nread = 0;
    while (nread < (ssize_t) sizeof(buf) - 1) {
        ssize_t nr = read(pipefd[0], buf + nread, sizeof(buf) - 1 - (size_t) nread);
        if (nr <= 0)
            break;
        nread += nr;
    }
    buf[nread] = '\0';
    close(pipefd[0]);

    /* Wait for child.  SIGCHLD is still blocked so nginx's signal handler
     * cannot reap this PID out from under us.  Restore mask afterwards. */
    {
        int wstatus;
        waitpid(pid, &wstatus, 0);
        sigprocmask(SIG_SETMASK, &_old_mask_oidc, NULL);
        if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "tpc_cred(oidc): helper exited with status %d",
                          WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);
            return NGX_ERROR;
        }
    }

    /* Strip trailing whitespace/newlines. */
    while (nread > 0 &&
           (buf[nread - 1] == '\n' || buf[nread - 1] == '\r' ||
            buf[nread - 1] == ' '))
        nread--;
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

        if (xrootd_subprocess_capture(curl_argv, buf, sizeof(buf), NULL, &ec)
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


xrootd_tpc_cred_mode_e
webdav_tpc_cred_parse_mode(const char *value, size_t len)
{
    if (len == 4 && ngx_strncmp((u_char *) value,
                                (u_char *) "none", 4) == 0)
        return XROOTD_TPC_CRED_NONE;

    if (len == 10 && ngx_strncmp((u_char *) value,
                                 (u_char *) "oidc-agent", 10) == 0)
        return XROOTD_TPC_CRED_OIDC_AGENT;

    if (len == 14 && ngx_strncmp((u_char *) value,
                                 (u_char *) "token-exchange", 14) == 0)
        return XROOTD_TPC_CRED_TOKEN_EXCHANGE;

    return XROOTD_TPC_CRED_UNKNOWN;
}

ngx_int_t
webdav_tpc_cred_obtain_token(ngx_http_request_t *r,
                             xrootd_tpc_cred_mode_e mode,
                             const char *source_url,
                             const char *subject_token,
                             const char *scope,
                             ngx_str_t *token_out)
{
    ngx_http_xrootd_webdav_loc_conf_t *wconf;
    ngx_int_t rc;

    wconf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (wconf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred: no WebDAV location config");
        return NGX_ERROR;
    }

    /* Increment started counter. */
    rc = webdav_tpc_cred_metric_increment(r, XROOTD_TPC_CRED_NSTARTED);
    (void) rc;

    switch (mode) {
    case XROOTD_TPC_CRED_OIDC_AGENT:
        rc = tpc_cred_oidc_agent_fetch(r, source_url, scope, token_out);
        if (rc == NGX_OK) {
            rc = webdav_tpc_cred_validate_token(r, token_out);
        }
        if (rc == NGX_OK) {
            webdav_tpc_cred_metric_increment(r, XROOTD_TPC_CRED_NSUCCESS);
        } else {
            webdav_tpc_cred_metric_increment(r, XROOTD_TPC_CRED_NERROR);
        }
        return rc;

    case XROOTD_TPC_CRED_TOKEN_EXCHANGE:
        if (wconf->tpc_cred.token_endpoint.len == 0
            || wconf->tpc_cred.token_endpoint.data == NULL) {
            XROOTD_DIAG_ERR(r->connection->log, 0,
                "tpc_cred: token-exchange is selected but no token endpoint "
                "is configured",
                "third-party-copy credential mode is token-exchange, but "
                "xrootd_webdav_tpc_token_endpoint is unset",
                "set the OAuth token endpoint for your IdP, or switch the TPC "
                "credential mode away from token-exchange");
            webdav_tpc_cred_metric_increment(r, XROOTD_TPC_CRED_NERROR);
            return NGX_ERROR;
        }
        if (subject_token == NULL || *subject_token == '\0') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "tpc_cred: no subject token for token-exchange");
            webdav_tpc_cred_metric_increment(r, XROOTD_TPC_CRED_NERROR);
            return NGX_ERROR;
        }
        rc = tpc_cred_rfc8693_exchange(
            r, subject_token, source_url, scope,
            (const char *) wconf->tpc_cred.token_endpoint.data,
            wconf->tpc_cred.token_client_id.len > 0 ?
                (const char *) wconf->tpc_cred.token_client_id.data : NULL,
            wconf->tpc_cred.token_client_secret.len > 0 ?
                (const char *) wconf->tpc_cred.token_client_secret.data : NULL,
            token_out);
        if (rc == NGX_OK) {
            rc = webdav_tpc_cred_validate_token(r, token_out);
        }
        if (rc == NGX_OK) {
            webdav_tpc_cred_metric_increment(r, XROOTD_TPC_CRED_NSUCCESS);
        } else {
            webdav_tpc_cred_metric_increment(r, XROOTD_TPC_CRED_NERROR);
        }
        return rc;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred: unknown delegation mode %d", (int) mode);
        webdav_tpc_cred_metric_increment(r, XROOTD_TPC_CRED_NUNKNOWN_MODE);
        return NGX_ERROR;
    }
}

const char *
webdav_tpc_cred_metric_name(xrootd_tpc_cred_metrics_e idx)
{
    switch (idx) {
    case XROOTD_TPC_CRED_NSTARTED:    return "tpc_cred_started";
    case XROOTD_TPC_CRED_NSUCCESS:    return "tpc_cred_success";
    case XROOTD_TPC_CRED_NERROR:      return "tpc_cred_error";
    case XROOTD_TPC_CRED_NUNKNOWN_MODE: return "tpc_cred_unknown_mode";
    case XROOTD_TPC_CRED_NPARSE_ERROR: return "tpc_cred_parse_error";
    default:                          return "tpc_cred_unknown";
    }
}
