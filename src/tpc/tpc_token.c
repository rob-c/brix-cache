/* ---- File: tpc_token.c — OAuth2/OIDC delegated token fetching for TPC source auth ----
 *
 * WHAT: Three static helper functions + one public API function fetch OAuth2/OIDC access tokens for native XRootD TPC outbound authentication. Two delegation modes: oidc-agent → fork/exec UNIX-socket JSON IPC to local oidc-agent daemon (tries dedicated helper binary first, falls back to oidc-token CLI) — reads pipe stdout, trims trailing whitespace, parses JSON {"access_token":...} or returns plain token string; token-exchange → RFC 8693 POST to external OAuth2 token endpoint via fork/exec curl — builds subject_token from tpc_outbound_bearer_file, constructs grant_type=urn:ietf:params:oauth:grant-type:token-exchange POST body with subject_token/resource/audience/scope params into temp file, executes curl -s -S -f -X POST with Content-Type application/x-www-form-urlencoded and optional client_id/client_secret basic auth — reads pipe stdout, parses JSON access_token; tpc_fetch_delegated_token (public API) dispatches to oidc-agent or token-exchange based on t->token_mode ("none"=skip, "oidc-agent"=mode1, "token-exchange"=mode2), validates token_endpoint configured for mode2, returns 0 on success, -1 with err_msg/xrd_error set on failure.
 *
 * WHY: TPC source authentication may require delegated OAuth2/OIDC access tokens when the destination server needs to authenticate as a different identity to the remote origin. oidc-agent mode fetches tokens from a local agent daemon (common in CMS/Fermilab environments); token-exchange mode performs RFC 8693 exchange using a bearer file subject token against an external OAuth2 endpoint. Both modes fork-exec subprocesses and read stdout via pipe — EINTR-safe with waitpid status check. JSON parsing delegates to xrootd_oauth2_parse_access_token(); plain-token paths copy directly into t->delegated_token buffer with size guard.
 *
 * HOW: fetch_delegated_token → token_mode=="none" return 0; "oidc-agent"→tpc_token_oidc_agent(pipe fork exec helper/oidc-token read parse); "token-exchange"→validate token_endpoint configured→tpc_token_rfc8693(read bearer file build POST body mkstemp temp write curl -X POST pipe read parse JSON); oidc_agent → pipe() fork dup2 STDOUT execve helper binary or execlp oidc-token read pipe trim trailing whitespace if buf[0]=='{'parse_json else copy_plain; rfc8693 → read bearer file snprintf POST body mkstemp temp write curl_argv -s -S -f -X POST -H Content-Type -u client_id/client_secret -d body_file token_endpoint pipe fork execvp curl read waitpid unlink parse JSON. */

/*
 * tpc_token.c — OAuth2/OIDC token fetching for native XRootD TPC pulls.
 *
 * Two delegation modes:
 *
 *   oidc-agent     — UNIX-socket JSON IPC to a local oidc-agent daemon
 *   token-exchange — RFC 8693 token-exchange request to an external OAuth2
 *                    token endpoint (subject token from tpc_outbound_bearer_file)
 */

#include "tpc_internal.h"
#include "../token/file.h"
#include "../token/oauth2.h"


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <ctype.h>

#define TPC_TOKEN_MAX_LEN  65536
#define TPC_TOKEN_HELPER_PATH  "/usr/local/sbin/nginx-xrootd-tpc-token"

/* ---- Function: tpc_trim_trailing() — trailing whitespace/newline removal ---- */
/* WHAT: Trims trailing whitespace characters (space, tab), newline ('\n'), and carriage return ('\r') from string s by decrementing len and setting each trimmed position to '\0'. Returns early if s is NULL or already empty. Enforces strlen() boundary via while(len > 0) guard to prevent underflow when trimming an all-whitespace string.
 * WHY: TPC token helper outputs may arrive with trailing whitespace from subprocess execution; this cleanup ensures clean token strings before parsing and comparison operations downstream. Prevents token validation failures caused by invisible trailing characters from subprocess stdout buffering or terminal emulation artifacts.
 * HOW: NULL/empty check → strlen(s) → while loop decrementing len from end, replacing each whitespace/newline/carriage-return byte with '\0' → stops when first non-trimmable character reached or len reaches 0 (all-whitespace string case). */

static void
tpc_trim_trailing(char *s)
{
    size_t len;

    if (s == NULL || *s == '\0') {
        return;
    }

    len = strlen(s);
    while (len > 0 && (isspace((unsigned char) s[len - 1]) || s[len - 1] == '\n'
                       || s[len - 1] == '\r')) {
        s[--len] = '\0';
    }
}

static int
tpc_token_parse_access_token(const char *json, char *out, size_t out_sz)
{
    char err[256];

    if (xrootd_oauth2_parse_access_token(json, out, out_sz, err, sizeof(err))
        != NGX_OK)
    {
        snprintf(out, out_sz, "%s", err);
        return -1;
    }

    return 0;
}

/* ---- Function: tpc_token_oidc_agent() — OIDC agent UNIX-socket token fetch ---- */
/* WHAT: Fetches OAuth2/OIDC access token via fork/exec to local oidc-agent daemon using UNIX-socket JSON IPC. Creates pipe → forks child → dup2 STDOUT → execve dedicated helper binary (nginx-xrootd-tpc-token) with OIDC_SOCK env or fallback /run/user/1000/oidc/oidc_agent.sock → if execve fails falls back to execlp oidc-token -c default → parent reads pipe stdout into buffer → waitpid checks WIFEXITED+WEXITSTATUS==0 → tpc_trim_trailing(buf) → if buf[0]=='{' parses JSON via xrootd_oauth2_parse_access_token else copies plain token with size guard. Returns 0 on success, -1 with err_msg/xrd_error=kXR_AuthFailed on failure.
 * WHY: CMS/Fermilab environments use oidc-agent daemons for OIDC token management. This function provides a robust fallback chain (dedicated helper binary → generic oidc-token CLI) ensuring token fetch works even when the custom binary is absent. JSON parsing handles agent daemon's structured output; plain-token paths handle oidc-token CLI's raw output. Pipe-based IPC avoids TOCTOU race on executable path (execve without access() pre-check).
 * HOW: pipe() → fork() → child close(pipefd[0]) dup2(pipefd[1],STDOUT) execve helper binary or execlp oidc-token → parent close(pipefd[1]) read loop into buffer null-terminate waitpid check trim trailing whitespace if JSON parse access_token else memcpy plain token. */
static int
tpc_token_oidc_agent(xrootd_tpc_pull_t *t, char *token_out, size_t token_out_sz)
{
    int pipefd[2];
    pid_t pid;
    char buf[TPC_TOKEN_MAX_LEN + 256];
    ssize_t nread;
    int wstatus;
    const char *sock_env;
    char *argv[3];

    pipefd[0] = -1;
    pipefd[1] = -1;

    if (pipe(pipefd) == -1) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC token: pipe() failed: %s", strerror(errno));
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    pid = fork();
    if (pid == -1) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC token: fork() failed: %s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        /* Try the dedicated helper first; fall through to oidc-token if
         * execve fails (binary absent / not executable). Avoid access()
         * before execve — that is a TOCTOU race on the executable path. */
        sock_env = getenv("OIDC_SOCK");
        argv[0] = (char *) TPC_TOKEN_HELPER_PATH;
        argv[1] = sock_env ? (char *) sock_env
                           : (char *) "/run/user/1000/oidc/oidc_agent.sock";
        argv[2] = NULL;
        execve(argv[0], argv, NULL);
        /* execve returned — helper not found or not executable; continue */

        execlp("oidc-token", "oidc-token", "-c", "default", (char *) NULL);
        _exit(127);
    }

    close(pipefd[1]);

    nread = 0;
    while ((ssize_t) nread < (ssize_t) sizeof(buf) - 1) {
        ssize_t nr = read(pipefd[0], buf + nread, sizeof(buf) - 1 - nread);
        if (nr <= 0) {
            break;
        }
        nread += nr;
    }
    buf[nread] = '\0';
    close(pipefd[0]);

    waitpid(pid, &wstatus, 0);
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC token: oidc-agent helper exited with status %d",
                 WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    tpc_trim_trailing(buf);

    if (buf[0] == '{') {
        if (tpc_token_parse_access_token(buf, token_out, token_out_sz) != 0) {
            t->xrd_error = kXR_AuthFailed;
            return -1;
        }
    } else {
        size_t tok_len = strlen(buf);
        if (tok_len >= token_out_sz) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC token: token too long");
            t->xrd_error = kXR_AuthFailed;
            return -1;
        }
        ngx_memcpy(token_out, buf, tok_len + 1);
    }

    return 0;
}

/* ---- Function: tpc_token_rfc8693() — RFC 8693 OAuth2 token-exchange via curl ---- */
/* WHAT: Fetches delegated OAuth2/OIDC access token via RFC 8693 token-exchange POST to external OAuth2 endpoint using fork/exec curl. Reads subject_token from tpc_outbound_bearer_file → builds POST body with grant_type=urn:ietf:params:oauth:grant-type:token-exchange + subject_token/resource/audience/scope params into mkstemp temp file → constructs curl argv (-s -S -f -X POST -H Content-Type application/x-www-form-urlencoded optional -u client_id/client_secret -d body_file token_endpoint) → pipe fork execvp curl → parent reads pipe stdout → waitpid checks exit status 0 → unlink temp file → parses JSON access_token via xrootd_oauth2_parse_access_token. Returns 0 on success, -1 with err_msg/xrd_error set on failure.
 * WHY: When TPC source requires a delegated token (different identity from client), RFC 8693 token-exchange converts the destination's bearer file subject token into an access token scoped for the remote origin. curl subprocess handles HTTP POST with form-urlencoded body; temp file avoids shell quoting issues with long tokens; unlink ensures cleanup on both success and failure paths. Optional client_id/client_secret basic auth supports OAuth2 client credential requirements.
 * HOW: read bearer file → snprintf POST body (grant_type+subject_token+resource+audience+scope) → mkstemp temp write body_buf → close body_fd → curl_argv build (-s -S -f -X POST -H Content-Type optional -u client_id/client_secret -d body_file token_endpoint) → pipe fork dup2 STDOUT execvp curl → parent read loop null-terminate waitpid check unlink → parse JSON access_token. */
static int
tpc_token_rfc8693(xrootd_tpc_pull_t *t, char *token_out, size_t token_out_sz)
{
    int pipefd[2];
    pid_t pid;
    char buf[TPC_TOKEN_MAX_LEN + 256];
    ssize_t nread;
    int wstatus;
    char *curl_argv[20];
    int argc = 0;
    char body_buf[4096];
    char body_file[NGX_MAX_PATH];
    int body_fd;
    char subject_token[TPC_TOKEN_MAX_LEN];

    if (xrootd_token_read_file(&t->conf->tpc_outbound_bearer_file,
                               (u_char *) subject_token, sizeof(subject_token),
                               NULL, NULL, "TPC token")
        != NGX_OK)
    {
        if (errno == EINVAL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC token: bearer file not configured or empty");
            t->xrd_error = kXR_ArgInvalid;
        } else {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC token: cannot read bearer file: %s", strerror(errno));
            t->xrd_error = kXR_IOError;
        }
        return -1;
    }

    /* Build the POST body. */
    ngx_snprintf((u_char *) body_buf, sizeof(body_buf),
                 "grant_type=urn:ietf:params:oauth:grant-type:"
                 "token-exchange"
                 "&subject_token=%s"
                 "&resource=%s"
                 "&audience=%s"
                 "&scope=%s",
                 subject_token,
                 t->src_host,
                 t->src_host,
                 t->token_scope);

    {
        char tmpl[NGX_MAX_PATH];
        ngx_snprintf((u_char *) tmpl, sizeof(tmpl),
                     "/tmp/tpc_token_body_XXXXXX");
        body_fd = mkstemp(tmpl);
        if (body_fd == -1) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC token: temp file creation failed: %s", strerror(errno));
            t->xrd_error = kXR_IOError;
            return -1;
        }
        ngx_memcpy(body_file, tmpl, strlen(tmpl) + 1);
    }

    {
        ssize_t nw = write(body_fd, body_buf, strlen(body_buf));
        (void) nw;
    }
    close(body_fd);

    /* Build curl argv. */
    curl_argv[argc++] = "curl";
    curl_argv[argc++] = "-s";
    curl_argv[argc++] = "-S";
    curl_argv[argc++] = "-f";
    curl_argv[argc++] = "-X";
    curl_argv[argc++] = "POST";
    curl_argv[argc++] = "-H";
    curl_argv[argc++] = "Content-Type: application/x-www-form-urlencoded";

    if (t->conf->tpc_outbound_client_id.len > 0
        && t->conf->tpc_outbound_client_secret.len > 0) {
        curl_argv[argc++] = "-u";
        curl_argv[argc++] = (char *) t->conf->tpc_outbound_client_id.data;
        curl_argv[argc++] = (char *) t->conf->tpc_outbound_client_secret.data;
    }

    curl_argv[argc++] = "-d";
    curl_argv[argc++] = body_file;
    curl_argv[argc++] = (char *) t->conf->tpc_outbound_token_endpoint.data;
    curl_argv[argc++] = NULL;

    if (pipe(pipefd) == -1) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC token: pipe() failed: %s", strerror(errno));
        unlink(body_file);
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    pid = fork();
    if (pid == -1) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC token: fork() failed: %s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        unlink(body_file);
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execvp("curl", curl_argv);
        _exit(127);
    }

    close(pipefd[1]);

    nread = 0;
    while ((ssize_t) nread < (ssize_t) sizeof(buf) - 1) {
        ssize_t nr = read(pipefd[0], buf + nread, sizeof(buf) - 1 - nread);
        if (nr <= 0) {
            break;
        }
        nread += nr;
    }
    buf[nread] = '\0';
    close(pipefd[0]);

    waitpid(pid, &wstatus, 0);
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC token: token exchange failed (curl exit %d)",
                 WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);
        unlink(body_file);
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    unlink(body_file);

    if (tpc_token_parse_access_token(buf, token_out, token_out_sz) != 0) {
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    return 0;
}


/* ---- Function: tpc_fetch_delegated_token() — OAuth2/OIDC token delegation dispatcher (public API) ---- */
/* WHAT: Public entry point that dispatches delegated token fetching based on t->token_mode. Returns 0 immediately for "none" or empty mode; delegates to tpc_token_oidc_agent() for "oidc-agent" mode (UNIX-socket JSON IPC); delegates to tpc_token_rfc8693() for "token-exchange" mode (RFC 8693 POST, validates token_endpoint configured first). Returns -1 with err_msg/xrd_error set on unknown mode or dispatch failure.
 * WHY: TPC source authentication requires delegated tokens when the destination server authenticates as a different identity to the remote origin. This dispatcher centralizes mode selection — callers pass t->token_mode and receive the fetched token in t->delegated_token without knowing which backend mechanism was used. Prevents callers from duplicating mode-switch logic across launch.c/thread.c.
 * HOW: token_mode=="none"/empty → return 0; "oidc-agent" → call tpc_token_oidc_agent(t, delegated_token, sizeof); "token-exchange" → validate conf->tpc_outbound_token_endpoint.len>0 else error → call tpc_token_rfc8693(t, delegated_token, sizeof); unknown mode → snprintf err_msg/xrd_error=kXR_ArgInvalid → return -1. */
int
tpc_fetch_delegated_token(xrootd_tpc_pull_t *t)
{
    if (t->token_mode[0] == '\0'
        || ngx_strcmp(t->token_mode, "none") == 0) {
        return 0;
    }

    if (ngx_strcmp(t->token_mode, "oidc-agent") == 0) {
        return tpc_token_oidc_agent(t, t->delegated_token,
                                    sizeof(t->delegated_token));
    }

    if (ngx_strcmp(t->token_mode, "token-exchange") == 0) {
        if (t->conf->tpc_outbound_token_endpoint.len == 0) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC token: token_endpoint not configured for "
                     "token-exchange mode");
            t->xrd_error = kXR_ArgInvalid;
            return -1;
        }
        return tpc_token_rfc8693(t, t->delegated_token,
                                 sizeof(t->delegated_token));
    }

    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC token: unknown delegation mode \"%s\"", t->token_mode);
    t->xrd_error = kXR_ArgInvalid;
    return -1;
}

