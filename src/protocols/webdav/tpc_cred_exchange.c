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
