/*
 * tpc_cred_exchange.c — HTTP-TPC RFC 8693 token-exchange credential delegation
 *
 * The token-exchange delegation mode: acquire an OAuth2/OIDC access token for a
 * third-party-copy pull transfer via an RFC 8693 token-exchange request to an
 * external OAuth2 token endpoint.  Split verbatim from tpc_cred.c (mechanical
 * file-size split) — the credential-parse cluster stays in tpc_cred.c.
 *
 * Non-blocking from the nginx-worker perspective: curl is fork/exec'd and its
 * output captured synchronously via the shared SIGCHLD-safe helper.
 */

#include "tpc_cred_internal.h"
#include "tpc_config.h"
#include "webdav.h"
#include "core/compat/log_diag.h"
#include "tpc/common/credential.h"
#include "core/compat/subprocess.h"   /* shared SIGCHLD-safe fork/exec capture */
#include "core/compat/cred_stage.h"   /* private 0700 credential staging (A-5)  */

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
#include <openssl/crypto.h>           /* OPENSSL_cleanse */


static ngx_int_t
tpc_cred_stage_exchange_body(ngx_http_request_t *r,
                             const char *subject_token,
                             const char *source_url,
                             const char *scope,
                             char *body_file, size_t body_file_size)
{
    char body_buf[2048];
    u_char *body_end;

    body_end = ngx_snprintf((u_char *) body_buf, sizeof(body_buf),
                  "grant_type=urn:ietf:params:oauth:grant-type:"
                  "token-exchange"
                  "&subject_token=%s"
                  "&resource=%s"
                  "&audience=%s"
                  "&scope=%s",
                  subject_token, source_url, source_url, scope);

    /* A-5: stage the body (carrying the live subject token) in the shared
     * private 0700 tmpfs facility for curl --data @file, never in
     * world-traversable /tmp; fail closed if a private dir can't be secured. */
    if (brix_cred_stage_write("tpc_cred_body_", body_buf,
                              (size_t) (body_end - (u_char *) body_buf),
                              body_file, body_file_size) != 0)
    {
        OPENSSL_cleanse(body_buf, sizeof(body_buf));
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                      "tpc_cred(rfc8693): cannot stage credential body "
                      "privately — refusing world-readable /tmp fallback");
        return NGX_ERROR;
    }

    OPENSSL_cleanse(body_buf, sizeof(body_buf));
    return NGX_OK;
}

static ngx_int_t
tpc_cred_make_body_arg(ngx_http_request_t *r, const char *body_file,
                       char *body_arg, size_t body_arg_size)
{
    size_t body_len = ngx_strlen(body_file);

    if (body_len + 2 > body_arg_size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred(rfc8693): staged body path is too long");
        unlink(body_file);  /* vfs-seam-allow: staged credential temp, not export storage */
        return NGX_ERROR;
    }
    body_arg[0] = '@';
    ngx_memcpy(body_arg + 1, body_file, body_len + 1);
    return NGX_OK;
}

static ngx_int_t
tpc_cred_build_basic_auth(ngx_http_request_t *r,
                          const char *client_id,
                          const char *client_secret,
                          char **basic_auth_out, size_t *auth_len_out)
{
    size_t client_id_len;
    size_t client_secret_len;
    size_t auth_len;
    char *basic_auth;

    if (client_id && *client_id && client_secret && *client_secret) {
        client_id_len = ngx_strlen(client_id);
        client_secret_len = ngx_strlen(client_secret);
        if (client_secret_len > NGX_MAX_PATH - 2
            || client_id_len > NGX_MAX_PATH - client_secret_len - 2) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "tpc_cred(rfc8693): client credentials are too long");
            return NGX_ERROR;
        }
        auth_len = client_id_len + 1 + client_secret_len;
        basic_auth = malloc(auth_len + 1);
        if (basic_auth == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "tpc_cred(rfc8693): cannot allocate client credentials");
            return NGX_ERROR;
        }
        ngx_memcpy(basic_auth, client_id, client_id_len);
        basic_auth[client_id_len] = ':';
        ngx_memcpy(basic_auth + client_id_len + 1,
                   client_secret, client_secret_len + 1);
        *basic_auth_out = basic_auth;
        *auth_len_out = auth_len;
    }
    return NGX_OK;
}

static ngx_int_t
tpc_cred_run_curl(ngx_http_request_t *r,
                  const char *token_endpoint,
                  const char *curl_path,
                  char *basic_auth,
                  char *body_arg,
                  char *buf, size_t buf_size)
{
    char *curl_argv[16];
    int argc = 0;
    int ec = -1;

    curl_argv[argc++] = (char *) ((curl_path && *curl_path) ? curl_path : "curl");
    curl_argv[argc++] = (char *) "-s";          /* silent */
    curl_argv[argc++] = (char *) "-S";          /* show errors */
    curl_argv[argc++] = (char *) "-f";          /* fail on HTTP error */
    curl_argv[argc++] = (char *) "-X";
    curl_argv[argc++] = (char *) "POST";
    curl_argv[argc++] = (char *) "-H";
    curl_argv[argc++] = (char *) "Content-Type: application/x-www-form-urlencoded";
    if (basic_auth != NULL) {
        /* Basic auth with client credentials. */
        curl_argv[argc++] = (char *) "-u";
        curl_argv[argc++] = basic_auth;
    }
    curl_argv[argc++] = (char *) "-d";
    curl_argv[argc++] = body_arg;
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
    if (brix_subprocess_capture(curl_argv, buf, buf_size, NULL, &ec) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
                      "tpc_cred(rfc8693): curl subprocess failed "
                      "(pipe/fork or signal)");
        return NGX_ERROR;
    }
    if (ec != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "tpc_cred(rfc8693): curl exited %d: %s", ec, buf);
        return NGX_ERROR;
    }
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
ngx_int_t
tpc_cred_rfc8693_exchange(ngx_http_request_t *r,
                          const char *subject_token,
                          const char *source_url,
                          const char *scope,
                          const char *token_endpoint,
                          const char *client_id,
                          const char *client_secret,
                          const char *curl_path,
                          ngx_str_t *token_out)
{
    char buf[TPC_CRED_MAX_TOKEN_LEN + 256];
    char body_file[NGX_MAX_PATH];
    char body_arg[NGX_MAX_PATH + 1];
    char *basic_auth = NULL;
    size_t auth_len = 0;

    if (tpc_cred_stage_exchange_body(r, subject_token, source_url, scope,
                                     body_file, sizeof(body_file)) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (tpc_cred_make_body_arg(r, body_file, body_arg, sizeof(body_arg))
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (tpc_cred_build_basic_auth(r, client_id, client_secret,
                                  &basic_auth, &auth_len) != NGX_OK)
    {
        unlink(body_file);  /* vfs-seam-allow: staged credential temp, not export storage */
        return NGX_ERROR;
    }
    if (tpc_cred_run_curl(r, token_endpoint, curl_path, basic_auth, body_arg,
                          buf, sizeof(buf)) != NGX_OK)
    {
        unlink(body_file);  /* vfs-seam-allow: staged credential temp, not export storage */
        if (basic_auth != NULL) {
            OPENSSL_cleanse(basic_auth, auth_len + 1);
            free(basic_auth);
        }
        return NGX_ERROR;
    }

    /* Clean up temp file. */
    unlink(body_file);  /* vfs-seam-allow: staged credential temp, not export storage */
    if (basic_auth != NULL) {
        OPENSSL_cleanse(basic_auth, auth_len + 1);
        free(basic_auth);
    }

    /* Parse JSON response for access_token. */
    return tpc_cred_parse_token_response(r, buf, token_out);
}
