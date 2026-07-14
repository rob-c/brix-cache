/*
 * tpc_token_exchange.c — RFC 8693 OAuth2 token-exchange path for native XRootD
 * TPC outbound delegated authentication (split from tpc_token.c, phase-79).
 *
 * WHAT: Fetches a delegated OAuth2 access token by exchanging the destination's
 *       own bearer (subject) token at an external OAuth2 token endpoint, via a
 *       fork/exec of curl. The public entry point tpc_token_rfc8693 is invoked
 *       by tpc_fetch_delegated_token (tpc_token.c) for token_mode
 *       "token-exchange".
 * WHY:  When a TPC source requires the destination to authenticate as a
 *       different identity than the client, RFC 8693 converts the destination's
 *       bearer file subject token into an access token scoped for the remote
 *       origin. Keeping this path in its own file holds each half of the token
 *       fetcher under the file-size cap and focused on one delegation mode.
 * HOW:  read subject token → stage the form body in a private temp file →
 *       build the curl argv → run curl and capture stdout → parse the JSON
 *       access_token (shared parser in tpc_token.c). Every step records
 *       err_msg / xrd_error on failure and the body temp file is unlinked on
 *       every exit path.
 */

#include "tpc/engine/tpc_internal.h"
#include "tpc/outbound/tpc_token_internal.h"
#include "auth/token/file.h"
#include "core/compat/subprocess.h"   /* shared SIGCHLD-safe fork/exec capture */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#define TPC_TOKEN_MAX_LEN  65536

/* WHAT: Reads the local bearer (subject) token from tpc_outbound_bearer_file
 * into subject_token. Returns 0 on success, -1 with err_msg/xrd_error set
 * (kXR_ArgInvalid when unconfigured/empty, kXR_IOError on read failure).
 * WHY: The RFC 8693 exchange needs the destination's own bearer as the subject
 * token; isolating the read keeps its errno-dependent error mapping out of the
 * orchestrator.
 * HOW: brix_token_read_file(); on non-NGX_OK map errno==EINVAL to the
 * "not configured or empty" ArgInvalid case, anything else to IOError. */
static int
tpc_rfc8693_read_subject(brix_tpc_pull_t *t, char *subject_token,
                         size_t subject_token_sz)
{
    if (brix_token_read_file(&t->conf->tpc_outbound_bearer_file,
                               (u_char *) subject_token, subject_token_sz,
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

    return 0;
}

/* WHAT: Builds the form-urlencoded RFC 8693 request body from subject_token and
 * stages it in a private temp file, returning the temp path in body_file.
 * Returns 0 on success, -1 with err_msg/xrd_error=kXR_IOError on temp-file
 * failure.
 * WHY: Staging the body in an mkstemp file (unpredictable name, exclusive
 * create) instead of on curl's command line keeps the bearer/subject token out
 * of the process listing (proc cmdline). The caller unlinks body_file on every
 * exit path.
 * HOW: ngx_snprintf the grant_type/subject_token/resource/audience/scope body;
 * mkstemp a /tmp template; on success write the body and close the fd, copying
 * the resolved path into body_file. subject_token is a JWT (URL-safe base64), so
 * it is form-safe without URL-encoding. */
static int
tpc_rfc8693_stage_body(brix_tpc_pull_t *t, const char *subject_token,
                       char *body_file, size_t body_file_sz)
{
    char body_buf[4096];
    char tmpl[NGX_MAX_PATH];
    int  body_fd;
    ssize_t nw;

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

    ngx_snprintf((u_char *) tmpl, sizeof(tmpl),
                 "/tmp/tpc_token_body_XXXXXX");
    body_fd = mkstemp(tmpl);
    if (body_fd == -1) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC token: temp file creation failed: %s", strerror(errno));
        t->xrd_error = kXR_IOError;
        return -1;
    }

    (void) body_file_sz;
    ngx_memcpy(body_file, tmpl, strlen(tmpl) + 1);

    nw = write(body_fd, body_buf, strlen(body_buf));
    (void) nw;
    close(body_fd);

    return 0;
}

/* WHAT: Fills curl_argv with the token-exchange curl invocation (no shell,
 * execvp-style) sourcing the form body from body_file.
 * WHY: Building the argv in one place keeps the curl option set (and the
 * security-relevant -f fail-on-HTTP-error, "--" options terminator, and optional
 * client basic-auth) reviewable and the orchestrator flat.
 * HOW: append curl -s -S -f -X POST -H Content-Type; when both client_id and
 * client_secret are configured, append -u id secret (curl joins per its -u
 * convention); append -d body_file, the "--" end-of-options terminator, the
 * token endpoint URL, and a NULL terminator. */
static void
tpc_rfc8693_build_argv(brix_tpc_pull_t *t, char **curl_argv,
                       const char *body_file)
{
    int argc = 0;

    /*
     * -s -S : silent but still print errors;  -f : fail (non-zero exit) on
     * HTTP >= 400 so the caller's exit-status check catches auth failures.
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
    curl_argv[argc++] = (char *) body_file;
    /* W3 — end-of-options terminator so the endpoint URL can never be parsed
     * as a curl option even if a misconfigured endpoint begins with '-'. */
    curl_argv[argc++] = "--";
    curl_argv[argc++] = (char *) t->conf->tpc_outbound_token_endpoint.data;
    curl_argv[argc++] = NULL;
}

/* WHAT: Runs curl synchronously (via the shared SIGCHLD-safe capture helper),
 * captures its stdout into buf, and unlinks the staged body file. Returns 0 on
 * success, -1 with err_msg/xrd_error set on subprocess failure or non-zero curl
 * exit.
 * WHY: Centralizing the capture + status mapping + temp-file cleanup keeps every
 * exit path unlinking body_file exactly once. A non-zero rc means pipe/fork
 * failed or curl was signal-killed (kXR_ServerError); a non-zero child exit
 * (including curl -f on HTTP >= 400) is an auth failure (kXR_AuthFailed).
 * HOW: brix_subprocess_capture(); on rc!=0 unlink+ServerError; on child exit!=0
 * unlink+AuthFailed; otherwise unlink and return 0 with the reply in buf. */
static int
tpc_rfc8693_run_curl(brix_tpc_pull_t *t, char **curl_argv,
                     const char *body_file, char *buf, size_t bufsz)
{
    int ec = -1;

    if (brix_subprocess_capture(curl_argv, buf, bufsz, NULL, &ec) != 0) {
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

    /* Success: body file no longer needed; remove before parsing the reply. */
    unlink(body_file);  /* vfs-seam-allow: /tmp credential temp, not export storage */
    return 0;
}

/* WHAT: Fetches a delegated OAuth2/OIDC access token via an RFC 8693
 * token-exchange POST to the external OAuth2 endpoint (fork/exec curl). Returns
 * 0 on success (token in token_out), -1 with err_msg/xrd_error set on failure.
 * WHY: When the TPC source requires a delegated token (a different identity from
 * the client), RFC 8693 converts the destination's bearer file subject token
 * into an access token scoped for the remote origin. The subject token, its
 * staging, the curl argv, and the run/cleanup are each isolated so the exchange
 * reads as a short linear sequence.
 * HOW: tpc_rfc8693_read_subject() -> tpc_rfc8693_stage_body() ->
 * tpc_rfc8693_build_argv() -> tpc_rfc8693_run_curl() ->
 * tpc_token_parse_access_token(). Any step's failure returns -1 with the error
 * already recorded. */
int
tpc_token_rfc8693(brix_tpc_pull_t *t, char *token_out, size_t token_out_sz)
{
    char buf[TPC_TOKEN_MAX_LEN + 256];
    char *curl_argv[20];
    char body_file[NGX_MAX_PATH];
    char subject_token[TPC_TOKEN_MAX_LEN];

    if (tpc_rfc8693_read_subject(t, subject_token, sizeof(subject_token)) != 0) {
        return -1;
    }

    if (tpc_rfc8693_stage_body(t, subject_token, body_file, sizeof(body_file))
        != 0)
    {
        return -1;
    }

    tpc_rfc8693_build_argv(t, curl_argv, body_file);

    if (tpc_rfc8693_run_curl(t, curl_argv, body_file, buf, sizeof(buf)) != 0) {
        return -1;
    }

    if (tpc_token_parse_access_token(buf, token_out, token_out_sz) != 0) {
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    return 0;
}
