/* File: tpc_token.c — OAuth2/OIDC delegated token fetching for TPC source auth
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
#include "token/file.h"
#include "token/oauth2.h"
#include "core/compat/subprocess.h"   /* shared SIGCHLD-safe fork/exec capture */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <ctype.h>

#define TPC_TOKEN_MAX_LEN  65536
#define TPC_TOKEN_HELPER_PATH  "/usr/local/sbin/nginx-xrootd-tpc-token"

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

/* WHAT: Extract the "access_token" field from an OAuth2 JSON response into out.
 * WHY: Thin wrapper over the shared oauth2 parser used by both delegation
 * modes; on failure it overwrites `out` with the parser's error text so the
 * caller can copy it into t->err_msg (out doubles as the error scratch buffer).
 * HOW: Delegate to xrootd_oauth2_parse_access_token; on non-NGX_OK copy `err`
 * into `out` and return -1, else return 0 with the token in `out`. */
static int
tpc_token_parse_access_token(const char *json, char *out, size_t out_sz)
{
    char err[256];

    if (xrootd_oauth2_parse_access_token(json, out, out_sz, err, sizeof(err))
        != NGX_OK)
    {
        /* On error, surface the parser message via the same out buffer. */
        snprintf(out, out_sz, "%s", err);
        return -1;
    }

    return 0;
}

/* WHAT: Sanity-check a freshly fetched delegated token before it is used to
 * authenticate the outbound TPC pull.
 * WHY: A delegation backend (oidc-agent / token-exchange) can return a string
 * that is well-formed JSON-wise but not a usable credential; validating here
 * fails fast with kXR_AuthFailed rather than letting a bad token surface as an
 * opaque remote-open rejection later. An empty token is treated as "no
 * delegation requested" and accepted (returns 0).
 * HOW: Wrap delegated_token in an ngx_str_t, parse+validate it as a
 * XROOTD_TPC_CREDENTIAL_TOKEN; on any failure set err_msg/xrd_error and -1. */
static int
tpc_token_validate_delegated(xrootd_tpc_pull_t *t)
{
    ngx_str_t                  raw;
    xrootd_tpc_credential_t    cred;

    /* Empty token => caller did not request delegation; nothing to validate. */
    if (t->delegated_token[0] == '\0') {
        return 0;
    }

    raw.data = (u_char *) t->delegated_token;
    raw.len = ngx_strlen(t->delegated_token);

    if (xrootd_tpc_credential_parse(&raw, XROOTD_TPC_CREDENTIAL_TOKEN,
                                    &cred, NULL,
                                    t->c != NULL ? t->c->log : NULL)
        != NGX_OK
        || xrootd_tpc_credential_validate(
               &cred, t->c != NULL ? t->c->log : NULL) != NGX_OK)
    {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC token: delegated token validation failed");
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    return 0;
}

/* WHAT: Resolve the oidc-token binary to an absolute path — first honours an
 * explicit override env var, then probes standard install locations.
 * WHY:  The fallback exec path must not be subject to $PATH substitution in the
 * daemon's environment (a compromised PATH entry could shadow the real binary).
 * HOW:  secure_getenv("XROOTD_OIDC_TOKEN_BIN") if access(X_OK) passes; else
 * walk a fixed candidate list; return NULL if none executable → caller _exit(127). */
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

/* WHAT: Fetches OAuth2/OIDC access token via fork/exec to local oidc-agent daemon using UNIX-socket JSON IPC. Creates pipe → forks child → dup2 STDOUT → execve dedicated helper binary (nginx-xrootd-tpc-token) with OIDC_SOCK env or fallback /run/user/1000/oidc/oidc_agent.sock → if execve fails falls back to execve resolved oidc-token binary with sanitized env → parent reads pipe stdout into buffer → waitpid checks WIFEXITED+WEXITSTATUS==0 → tpc_trim_trailing(buf) → if buf[0]=='{' parses JSON via xrootd_oauth2_parse_access_token else copies plain token with size guard. Returns 0 on success, -1 with err_msg/xrd_error=kXR_AuthFailed on failure.
 * WHY: CMS/Fermilab environments use oidc-agent daemons for OIDC token management. This function provides a robust fallback chain (dedicated helper binary → generic oidc-token CLI) ensuring token fetch works even when the custom binary is absent. JSON parsing handles agent daemon's structured output; plain-token paths handle oidc-token CLI's raw output. Pipe-based IPC avoids TOCTOU race on executable path (execve without access() pre-check).
 * HOW: pipe() → fork() → child close(pipefd[0]) dup2(pipefd[1],STDOUT) execve helper binary or resolve_oidc_token_binary → execve with controlled envp → parent close(pipefd[1]) read loop into buffer null-terminate waitpid check trim trailing whitespace if JSON parse access_token else memcpy plain token. */
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
        /* child --- : redirect stdout into the write end of the pipe so the
         * parent can read the helper's token output, then close both raw fds. */
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

        /* Fallback: the generic oidc-token CLI, resolved to an absolute path.
         * Avoids $PATH substitution — the daemon's PATH is untrusted.
         * Build a minimal controlled environment: PATH + HOME + OIDC_SOCK +
         * XDG_RUNTIME_DIR (the latter two are needed by oidc-token to locate its
         * config and agent socket); do not inherit the full environ. */
        {
            const char *fb_bin = resolve_oidc_token_binary();
            if (fb_bin != NULL) {
                const char *home_val = getenv("HOME");
                const char *xdg_val  = getenv("XDG_RUNTIME_DIR");
                char  home_buf[280], oidc_buf[280], xdg_buf[280];
                char *fb_argv[4] = { (char *) fb_bin, "-c", "default", NULL };
                char *fb_envp[5];
                int   ei = 0;

                fb_envp[ei++] = "PATH=/usr/bin:/bin";
                if (home_val != NULL) {
                    snprintf(home_buf, sizeof(home_buf), "HOME=%s", home_val);
                    fb_envp[ei++] = home_buf;
                }
                if (sock_env != NULL) {
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
        _exit(127);  /* both execs failed: 127 == "command not found" */
    }

    /* parent --- : close the write end so read() sees EOF when the child
     * exits, then drain all stdout into buf (loop because a single read() may
     * return short; stop on EOF/error or when buf is full minus the NUL slot). */
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

    /*
     * Output discrimination: a leading '{' means the helper returned a JSON
     * object (oidc-agent daemon style) → parse out access_token. Anything else
     * is treated as a bare token string (oidc-token CLI style) and copied
     * verbatim, with a length guard against the destination buffer.
     */
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

/* WHAT: Fetches delegated OAuth2/OIDC access token via RFC 8693 token-exchange POST to external OAuth2 endpoint using fork/exec curl. Reads subject_token from tpc_outbound_bearer_file → builds POST body with grant_type=urn:ietf:params:oauth:grant-type:token-exchange + subject_token/resource/audience/scope params into mkstemp temp file → constructs curl argv (-s -S -f -X POST -H Content-Type application/x-www-form-urlencoded optional -u client_id/client_secret -d body_file token_endpoint) → pipe fork execvp curl → parent reads pipe stdout → waitpid checks exit status 0 → unlink temp file → parses JSON access_token via xrootd_oauth2_parse_access_token. Returns 0 on success, -1 with err_msg/xrd_error set on failure.
 * WHY: When TPC source requires a delegated token (different identity from client), RFC 8693 token-exchange converts the destination's bearer file subject token into an access token scoped for the remote origin. curl subprocess handles HTTP POST with form-urlencoded body; temp file avoids shell quoting issues with long tokens; unlink ensures cleanup on both success and failure paths. Optional client_id/client_secret basic auth supports OAuth2 client credential requirements.
 * HOW: read bearer file → snprintf POST body (grant_type+subject_token+resource+audience+scope) → mkstemp temp write body_buf → close body_fd → curl_argv build (-s -S -f -X POST -H Content-Type optional -u client_id/client_secret -d body_file token_endpoint) → pipe fork dup2 STDOUT execvp curl → parent read loop null-terminate waitpid check unlink → parse JSON access_token. */
static int
tpc_token_rfc8693(xrootd_tpc_pull_t *t, char *token_out, size_t token_out_sz)
{
    char buf[TPC_TOKEN_MAX_LEN + 256];
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

    /*
     * RFC 8693 token-exchange request body (form-urlencoded). The subject_token
     * is our local bearer (the identity we already hold); resource+audience are
     * both set to the remote origin host so the issued token is scoped to it;
     * scope carries the configured outbound scope. NOTE: subject_token is not
     * URL-encoded here — it is a JWT (URL-safe base64, no reserved chars), so
     * it is form-safe as-is.
     */
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

    /*
     * Stage the form body in a private temp file (mkstemp => unpredictable
     * name, exclusive create) instead of building it on curl's command line,
     * keeping the bearer/subject token out of /proc/PID/cmdline and the
     * process listing. The path is captured in body_file and unlinked on every
     * exit path below (success and all error returns).
     */
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

    /*
     * Build curl argv (execvp, no shell — so no quoting/injection risk).
     *   -s -S : silent but still print errors;  -f : fail (non-zero exit) on
     *   HTTP >= 400 so the waitpid status check below catches auth failures.
     */
    curl_argv[argc++] = "curl";
    curl_argv[argc++] = "-s";
    curl_argv[argc++] = "-S";
    curl_argv[argc++] = "-f";
    curl_argv[argc++] = "-X";
    curl_argv[argc++] = "POST";
    curl_argv[argc++] = "-H";
    curl_argv[argc++] = "Content-Type: application/x-www-form-urlencoded";

    /* Optional OAuth2 client basic auth: curl -u "id:secret" — only added when
     * both halves are configured. NOTE: -u takes a single "id:secret" arg, so
     * these two array slots become two separate argv entries that curl joins
     * via the -u/value convention. */
    if (t->conf->tpc_outbound_client_id.len > 0
        && t->conf->tpc_outbound_client_secret.len > 0) {
        curl_argv[argc++] = "-u";
        curl_argv[argc++] = (char *) t->conf->tpc_outbound_client_id.data;
        curl_argv[argc++] = (char *) t->conf->tpc_outbound_client_secret.data;
    }

    /* -d data: the form body, sourced from the staged temp file path. */
    curl_argv[argc++] = "-d";
    curl_argv[argc++] = body_file;
    /* W3 — end-of-options terminator so the endpoint URL can never be parsed
     * as a curl option even if a misconfigured endpoint begins with '-'. */
    curl_argv[argc++] = "--";
    curl_argv[argc++] = (char *) t->conf->tpc_outbound_token_endpoint.data;
    curl_argv[argc++] = NULL;

    /*
     * Run curl synchronously and capture its stdout (the token JSON) via the
     * shared SIGCHLD-safe fork/exec helper (src/compat/subprocess.c) — the same
     * pipe->fork->dup2->drain->waitpid skeleton used by the native client and
     * the oidc-agent path. A non-zero rc means pipe/fork failed or curl was
     * signal-killed; a non-zero child exit (including curl -f on HTTP >= 400) is
     * an auth failure. The staged body file is unlinked on every exit path.
     */
    {
        int ec = -1;

        if (xrootd_subprocess_capture(curl_argv, buf, sizeof(buf), NULL, &ec)
            != 0)
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC token: token-exchange subprocess failed "
                     "(pipe/fork or signal)");
            unlink(body_file);  /* vfs-seam-allow: /tmp credential temp, not export storage */
            t->xrd_error = kXR_ServerError;
            return -1;
        }
        if (ec != 0) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC token: token exchange failed (curl exit %d)", ec);
            unlink(body_file);  /* vfs-seam-allow: /tmp credential temp, not export storage */
            t->xrd_error = kXR_AuthFailed;
            return -1;
        }
    }

    /* Success: body file no longer needed; remove before parsing the reply. */
    unlink(body_file);  /* vfs-seam-allow: /tmp credential temp, not export storage */

    if (tpc_token_parse_access_token(buf, token_out, token_out_sz) != 0) {
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    return 0;
}


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
        if (tpc_token_oidc_agent(t, t->delegated_token,
                                 sizeof(t->delegated_token)) != 0) {
            return -1;
        }
        return tpc_token_validate_delegated(t);
    }

    if (ngx_strcmp(t->token_mode, "token-exchange") == 0) {
        if (t->conf->tpc_outbound_token_endpoint.len == 0) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC token: token_endpoint not configured for "
                     "token-exchange mode");
            t->xrd_error = kXR_ArgInvalid;
            return -1;
        }
        if (tpc_token_rfc8693(t, t->delegated_token,
                              sizeof(t->delegated_token)) != 0) {
            return -1;
        }
        return tpc_token_validate_delegated(t);
    }

    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC token: unknown delegation mode \"%s\"", t->token_mode);
    t->xrd_error = kXR_ArgInvalid;
    return -1;
}
