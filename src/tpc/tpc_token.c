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

#if (NGX_THREADS)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <ctype.h>
#include <fcntl.h>

#define TPC_TOKEN_MAX_LEN  65536
#define TPC_TOKEN_HELPER_PATH  "/usr/local/sbin/nginx-xrootd-tpc-token"

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

static const char *
tpc_token_json_find_string(const char *json, const char *key)
{
    const char *p;
    size_t key_len;

    key_len = strlen(key);
    p = (const char *) ngx_strstrn((u_char *) json, (char *) key, key_len - 1);
    if (p == NULL) {
        return NULL;
    }

    p += key_len;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (*p != ':') {
        return NULL;
    }
    p++;
    while (*p == ' ' || *p == '\t') {
        p++;
    }

    if (*p != '"') {
        return NULL;
    }
    return p;
}

static int
tpc_token_parse_access_token(const char *json, char *out, size_t out_sz)
{
    const char *val;
    const char *end;
    size_t tok_len;

    val = tpc_token_json_find_string(json, "access_token");
    if (val == NULL) {
        snprintf(out, out_sz, "no \"access_token\" in token response");
        return -1;
    }

    val++;
    end = val;
    while (*end && *end != '"') {
        if ((size_t)(end - val) >= TPC_TOKEN_MAX_LEN) {
            snprintf(out, out_sz, "token exceeds max length");
            return -1;
        }
        end++;
    }

    if (*end != '"') {
        snprintf(out, out_sz, "unterminated token string");
        return -1;
    }

    tok_len = (size_t)(end - val);
    if (tok_len >= out_sz) {
        snprintf(out, out_sz, "token too long for output buffer");
        return -1;
    }

    ngx_memcpy(out, val, tok_len);
    out[tok_len] = '\0';
    return 0;
}

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

        if (access(TPC_TOKEN_HELPER_PATH, X_OK) == 0) {
            sock_env = getenv("OIDC_SOCK");
            argv[0] = (char *) TPC_TOKEN_HELPER_PATH;
            argv[1] = sock_env ? (char *) sock_env
                               : (char *) "/run/user/1000/oidc/oidc_agent.sock";
            argv[2] = NULL;
            execve(argv[0], argv, NULL);
        }

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
    size_t subject_token_len;

    /* Read subject token from the bearer file. */
    if (t->conf->tpc_outbound_bearer_file.len == 0
        || t->conf->tpc_outbound_bearer_file.len >= sizeof(subject_token)) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC token: bearer file not configured for token-exchange");
        t->xrd_error = kXR_ArgInvalid;
        return -1;
    }

    {
        FILE *fp = fopen((char *) t->conf->tpc_outbound_bearer_file.data, "rb");
        if (fp == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC token: cannot open bearer file: %s", strerror(errno));
            t->xrd_error = kXR_IOError;
            return -1;
        }
        subject_token_len = fread(subject_token, 1, sizeof(subject_token) - 1, fp);
        fclose(fp);
    }
    subject_token[subject_token_len] = '\0';
    tpc_trim_trailing(subject_token);

    if (subject_token_len == 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC token: bearer file is empty");
        t->xrd_error = kXR_ArgInvalid;
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

#endif /* NGX_THREADS */
