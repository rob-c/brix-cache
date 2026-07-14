/* File: tpc_token.c — OAuth2/OIDC delegated token fetching for TPC source auth
 * WHAT: Three static helper functions + one public API function fetch OAuth2/OIDC access tokens for native XRootD TPC outbound authentication. Two delegation modes: oidc-agent → fork/exec UNIX-socket JSON IPC to local oidc-agent daemon (tries dedicated helper binary first, falls back to oidc-token CLI) — reads pipe stdout, trims trailing whitespace, parses JSON {"access_token":...} or returns plain token string; token-exchange → RFC 8693 POST to external OAuth2 token endpoint via fork/exec curl — builds subject_token from tpc_outbound_bearer_file, constructs grant_type=urn:ietf:params:oauth:grant-type:token-exchange POST body with subject_token/resource/audience/scope params into temp file, executes curl -s -S -f -X POST with Content-Type application/x-www-form-urlencoded and optional client_id/client_secret basic auth — reads pipe stdout, parses JSON access_token; tpc_fetch_delegated_token (public API) dispatches to oidc-agent or token-exchange based on t->token_mode ("none"=skip, "oidc-agent"=mode1, "token-exchange"=mode2), validates token_endpoint configured for mode2, returns 0 on success, -1 with err_msg/xrd_error set on failure.
 *
 * WHY: TPC source authentication may require delegated OAuth2/OIDC access tokens when the destination server needs to authenticate as a different identity to the remote origin. oidc-agent mode fetches tokens from a local agent daemon (common in CMS/Fermilab environments); token-exchange mode performs RFC 8693 exchange using a bearer file subject token against an external OAuth2 endpoint. Both modes fork-exec subprocesses and read stdout via pipe — EINTR-safe with waitpid status check. JSON parsing delegates to brix_oauth2_parse_access_token(); plain-token paths copy directly into t->delegated_token buffer with size guard.
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

#include "tpc/engine/tpc_internal.h"
#include "tpc/outbound/tpc_token_internal.h"   /* cross-file: rfc8693 path (tpc_token_exchange.c) */
#include "auth/token/file.h"
#include "auth/token/oauth2.h"
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
 * HOW: Delegate to brix_oauth2_parse_access_token; on non-NGX_OK copy `err`
 * into `out` and return -1, else return 0 with the token in `out`. */
int
tpc_token_parse_access_token(const char *json, char *out, size_t out_sz)
{
    char err[256];

    if (brix_oauth2_parse_access_token(json, out, out_sz, err, sizeof(err))
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
 * BRIX_TPC_CREDENTIAL_TOKEN; on any failure set err_msg/xrd_error and -1. */
static int
tpc_token_validate_delegated(brix_tpc_pull_t *t)
{
    ngx_str_t                  raw;
    brix_tpc_credential_t    cred;

    /* Empty token => caller did not request delegation; nothing to validate. */
    if (t->delegated_token[0] == '\0') {
        return 0;
    }

    raw.data = (u_char *) t->delegated_token;
    raw.len = ngx_strlen(t->delegated_token);

    if (brix_tpc_credential_parse(&raw, BRIX_TPC_CREDENTIAL_TOKEN,
                                    &cred, NULL,
                                    t->c != NULL ? t->c->log : NULL)
        != NGX_OK
        || brix_tpc_credential_validate(
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
 * HOW:  secure_getenv("BRIX_OIDC_TOKEN_BIN") if access(X_OK) passes; else
 * walk a fixed candidate list; return NULL if none executable → caller _exit(127). */
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

/* WHAT: In the forked child, resolve the generic oidc-token CLI to an absolute
 * path and execve it with a minimal controlled environment; returns only if the
 * binary is unresolved or execve fails (caller then _exit(127)).
 * WHY: The dedicated helper binary may be absent, so oidc-token is the fallback
 * token source. It must run with an absolute path (no $PATH substitution — the
 * daemon's PATH is untrusted) and a curated environment: PATH + HOME + OIDC_SOCK
 * + XDG_RUNTIME_DIR (the latter two let oidc-token locate its config and agent
 * socket); the full environ is deliberately NOT inherited.
 * HOW: resolve_oidc_token_binary(); if found, read HOME/XDG_RUNTIME_DIR, build a
 * fixed argv (-c default) and a curated envp (PATH always, HOME/OIDC_SOCK/
 * XDG_RUNTIME_DIR only when set), then execve. */
static void
tpc_oidc_exec_fallback(const char *sock_env)
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

/* WHAT: Child-process body of the oidc-agent fetch — redirects stdout to the
 * pipe write end and execs the token helper chain; never returns (ends in
 * _exit(127) if both execs fail).
 * WHY: Isolating the post-fork child path keeps the orchestrator flat and puts
 * the exec fallback chain (dedicated helper → generic oidc-token) in one place.
 * The dedicated helper is tried first via execve with an absolute path (avoiding
 * a TOCTOU access()-before-exec race), then the CLI fallback.
 * HOW: close read end; dup2 write end onto STDOUT; close write end; read
 * OIDC_SOCK (default the standard user socket path); execve the dedicated helper
 * with a two-arg argv; on return call tpc_oidc_exec_fallback(); _exit(127). */
static void
tpc_oidc_child_run(int *pipefd)
{
    const char *sock_env;
    char *argv[3];

    /* redirect stdout into the write end of the pipe so the parent can read the
     * helper's token output, then close both raw fds. */
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);

    /* Try the dedicated helper first; fall through to oidc-token if execve fails
     * (binary absent / not executable). Avoid access() before execve — that is a
     * TOCTOU race on the executable path. */
    sock_env = getenv("OIDC_SOCK");
    argv[0] = (char *) TPC_TOKEN_HELPER_PATH;
    argv[1] = sock_env ? (char *) sock_env
                       : (char *) "/run/user/1000/oidc/oidc_agent.sock";
    argv[2] = NULL;
    execve(argv[0], argv, NULL);
    /* execve returned — helper not found or not executable; try the fallback. */

    tpc_oidc_exec_fallback(sock_env);
    _exit(127);  /* both execs failed: 127 == "command not found" */
}

/* WHAT: Parent-side drain of the child's stdout — reads up to bufsz-1 bytes from
 * fd into buf and NUL-terminates it. Returns the byte count read.
 * WHY: A single read() may return short, so the token output must be drained in
 * a loop until EOF/error or the buffer is full (minus the NUL slot). Factoring
 * this out keeps the orchestrator's control flow linear.
 * HOW: loop read()ing into buf at the running offset while space remains; stop on
 * EOF/error (nr <= 0); NUL-terminate at the accumulated length. */
static ssize_t
tpc_oidc_read_all(int fd, char *buf, size_t bufsz)
{
    ssize_t nread = 0;

    while ((size_t) nread < bufsz - 1) {
        ssize_t nr = read(fd, buf + nread, bufsz - 1 - nread);
        if (nr <= 0) {
            break;
        }
        nread += nr;
    }
    buf[nread] = '\0';
    return nread;
}

/* WHAT: Extracts the usable token from the (already whitespace-trimmed) helper
 * output buf into token_out. Returns 0 on success, -1 (with err_msg/xrd_error
 * set) on parse failure or oversize plain token.
 * WHY: The two token producers differ in shape — the oidc-agent daemon emits a
 * JSON object, the oidc-token CLI emits a bare token — and this discrimination
 * belongs in one pure helper so the orchestrator does not branch on output form.
 * HOW: a leading '{' means JSON → tpc_token_parse_access_token(); otherwise a
 * bare token → length-guard against token_out_sz and ngx_memcpy verbatim. */
static int
tpc_oidc_extract_token(brix_tpc_pull_t *t, const char *buf,
                       char *token_out, size_t token_out_sz)
{
    if (buf[0] == '{') {
        if (tpc_token_parse_access_token(buf, token_out, token_out_sz) != 0) {
            t->xrd_error = kXR_AuthFailed;
            return -1;
        }
        return 0;
    }

    {
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

/* WHAT: Fetches an OAuth2/OIDC access token via fork/exec to a local oidc-agent
 * (dedicated helper binary, falling back to the oidc-token CLI) using pipe IPC.
 * Returns 0 on success (token in token_out), -1 with err_msg/xrd_error set on
 * pipe/fork failure, non-zero child exit, parse failure, or oversize token.
 * WHY: CMS/Fermilab environments use oidc-agent daemons for OIDC token
 * management. The fallback chain (dedicated helper → generic oidc-token CLI)
 * ensures token fetch works even when the custom binary is absent. Pipe-based
 * IPC with execve (no access() pre-check) avoids a TOCTOU race on the exec path.
 * HOW: pipe() then fork(); child runs tpc_oidc_child_run(); parent closes the
 * write end, drains stdout via tpc_oidc_read_all(), waitpid()s and checks the
 * exit status, trims trailing whitespace, then tpc_oidc_extract_token(). */
static int
tpc_token_oidc_agent(brix_tpc_pull_t *t, char *token_out, size_t token_out_sz)
{
    int pipefd[2];
    pid_t pid;
    char buf[TPC_TOKEN_MAX_LEN + 256];
    int wstatus;

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
        tpc_oidc_child_run(pipefd);
    }

    /* parent --- : close the write end so read() sees EOF when the child exits,
     * then drain all stdout into buf. */
    close(pipefd[1]);
    tpc_oidc_read_all(pipefd[0], buf, sizeof(buf));
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

    return tpc_oidc_extract_token(t, buf, token_out, token_out_sz);
}

/* WHAT: Public entry point that dispatches delegated token fetching based on t->token_mode. Returns 0 immediately for "none" or empty mode; for "passthrough" (explicit/strict) validates the client's inbound bearer JWT already snapshotted into t->delegated_token (empty → kXR_AuthFailed); for "passthrough-opt" (default/opportunistic) validates the inbound JWT when present but returns 0 with no token when absent (fall back to bearer-file/GSI/anon); delegates to tpc_token_oidc_agent() for "oidc-agent" mode (UNIX-socket JSON IPC); delegates to tpc_token_rfc8693() for "token-exchange" mode (RFC 8693 POST, validates token_endpoint configured first). Returns -1 with err_msg/xrd_error set on unknown mode or dispatch failure.
 * WHY: TPC source authentication requires delegated tokens when the destination server authenticates as a different identity to the remote origin. This dispatcher centralizes mode selection — callers pass t->token_mode and receive the fetched token in t->delegated_token without knowing which backend mechanism was used. Prevents callers from duplicating mode-switch logic across launch.c/thread.c. The passthrough modes differ: no fetch happens here — the token was captured on the event loop (launch.c) — so they only inspect the snapshot. "passthrough" (client asked for it) fails closed when it is empty; "passthrough-opt" (server default) instead returns 0 so the outbound auth path can fall back, so making passthrough the default never denies a previously-anonymous/GSI-only pull.
 * HOW: token_mode=="none"/empty → return 0; "passthrough" → require t->delegated_token[0] set (else err_msg/xrd_error=kXR_AuthFailed) → tpc_token_validate_delegated; "passthrough-opt" → empty token → return 0, else tpc_token_validate_delegated; "oidc-agent" → call tpc_token_oidc_agent(t, delegated_token, sizeof); "token-exchange" → validate conf->tpc_outbound_token_endpoint.len>0 else error → call tpc_token_rfc8693(t, delegated_token, sizeof); unknown mode → snprintf err_msg/xrd_error=kXR_ArgInvalid → return -1. */
int
tpc_fetch_delegated_token(brix_tpc_pull_t *t)
{
    if (t->token_mode[0] == '\0'
        || ngx_strcmp(t->token_mode, "none") == 0) {
        return 0;
    }

    /*
     * passthrough (STRICT) — an explicit client tpc.token_mode=passthrough. The
     * client's own inbound bearer JWT was already snapshotted into
     * t->delegated_token on the event loop (tpc_pull_capture_passthrough_token in
     * launch.c). There is nothing to fetch; just require the token to be present
     * and valid so the source authenticates the end user. An empty token (no
     * inbound bearer / one too large to forward) is a clean kXR_AuthFailed —
     * never a silent anonymous/service fallback, because the client asked for it.
     */
    if (ngx_strcmp(t->token_mode, "passthrough") == 0) {
        if (t->delegated_token[0] == '\0') {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC token: passthrough requested but no inbound bearer "
                     "token was presented by the client");
            t->xrd_error = kXR_AuthFailed;
            return -1;
        }
        return tpc_token_validate_delegated(t);
    }

    /*
     * passthrough-opt (OPPORTUNISTIC) — the default-on brix_tpc_outbound_passthrough
     * mode. Same event-loop capture as strict passthrough, but the ABSENCE of an
     * inbound token is NOT an error: return 0 with delegated_token left empty so
     * the outbound auth path (gsi_outbound_finish) falls back to the static bearer
     * file, then GSI proxy delegation, then anonymous — exactly as it did before
     * this mode became the default. This guarantees a flipped default never turns
     * a previously-succeeding GSI-only or anonymous TPC pull into a new denial.
     * When an inbound token IS present, use it (validate + forward via ztn).
     */
    if (ngx_strcmp(t->token_mode, "passthrough-opt") == 0) {
        if (t->delegated_token[0] == '\0') {
            return 0;
        }
        return tpc_token_validate_delegated(t);
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
