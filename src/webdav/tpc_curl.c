/*
 * tpc_curl.c - external curl helper execution for HTTP-TPC COPY pull and push.
 */

#include "webdav.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

ngx_int_t
webdav_tpc_run_curl_pull(ngx_http_request_t *r,
                         ngx_http_xrootd_webdav_loc_conf_t *conf,
                         const char *source_url, const char *tmp_path,
                         ngx_array_t *transfer_headers)
{
    char       *argv[WEBDAV_TPC_MAX_ARGS];
    ngx_uint_t  argc = 0;
    ngx_uint_t  i;
    ngx_str_t  *headers;
    pid_t       pid;
    int         status;
    char        timeout_buf[32];

#define WEBDAV_TPC_ARG(v)                                                   \
    do {                                                                    \
        if (argc + 1 >= WEBDAV_TPC_MAX_ARGS) {                              \
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,                \
                          "xrootd_webdav: HTTP-TPC curl argv too long");    \
            return NGX_HTTP_INTERNAL_SERVER_ERROR;                          \
        }                                                                   \
        argv[argc++] = (char *) (v);                                         \
    } while (0)

    WEBDAV_TPC_ARG((char *) conf->tpc_curl.data);
    WEBDAV_TPC_ARG("--fail");
    WEBDAV_TPC_ARG("--location");
    WEBDAV_TPC_ARG("--silent");
    WEBDAV_TPC_ARG("--show-error");
    WEBDAV_TPC_ARG("--proto");
    WEBDAV_TPC_ARG("=https");

    if (conf->tpc_timeout > 0) {
        (void) snprintf(timeout_buf, sizeof(timeout_buf), "%u",
                        (unsigned) conf->tpc_timeout);
        WEBDAV_TPC_ARG("--max-time");
        WEBDAV_TPC_ARG(timeout_buf);
    }

    if (conf->tpc_cert.len > 0) {
        WEBDAV_TPC_ARG("--cert");
        WEBDAV_TPC_ARG((char *) conf->tpc_cert.data);
    }
    if (conf->tpc_key.len > 0) {
        WEBDAV_TPC_ARG("--key");
        WEBDAV_TPC_ARG((char *) conf->tpc_key.data);
    }
    if (conf->tpc_cafile.len > 0) {
        WEBDAV_TPC_ARG("--cacert");
        WEBDAV_TPC_ARG((char *) conf->tpc_cafile.data);
    }
    if (conf->tpc_cadir.len > 0) {
        WEBDAV_TPC_ARG("--capath");
        WEBDAV_TPC_ARG((char *) conf->tpc_cadir.data);
    }

    if (transfer_headers != NULL && transfer_headers->nelts > 0) {
        headers = transfer_headers->elts;
        for (i = 0; i < transfer_headers->nelts; i++) {
            WEBDAV_TPC_ARG("-H");
            WEBDAV_TPC_ARG((char *) headers[i].data);
        }
    }

    WEBDAV_TPC_ARG("--output");
    WEBDAV_TPC_ARG((char *) tmp_path);
    WEBDAV_TPC_ARG((char *) source_url);
    argv[argc] = NULL;

#undef WEBDAV_TPC_ARG

    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_STARTED]);

    pid = fork();
    if (pid < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "xrootd_webdav: fork() failed for HTTP-TPC curl");
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (pid == 0) {
        int  nullfd;
        long fd;
        long maxfd;

        nullfd = open("/dev/null", O_RDONLY);
        if (nullfd >= 0) {
            (void) dup2(nullfd, STDIN_FILENO);
            if (nullfd > STDERR_FILENO) {
                close(nullfd);
            }
        }

        maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd < 0 || maxfd > 65536) {
            maxfd = 65536;
        }
        for (fd = STDERR_FILENO + 1; fd < maxfd; fd++) {
            close((int) fd);
        }

        if (strchr((const char *) conf->tpc_curl.data, '/') != NULL) {
            execv((const char *) conf->tpc_curl.data, argv);
        } else {
            execvp((const char *) conf->tpc_curl.data, argv);
        }

        _exit(127);
    }

    for (;;) {
        if (waitpid(pid, &status, 0) >= 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "xrootd_webdav: waitpid() failed for HTTP-TPC curl");
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_SUCCESS]);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "xrootd_webdav: HTTP-TPC curl failed status=%d",
                  status);
    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_ERROR]);
    return NGX_HTTP_BAD_GATEWAY;
}


/*
 * webdav_tpc_run_curl_push — run curl to push a local file to a remote HTTPS
 * destination (HTTP-TPC push mode).
 *
 * Invokes: curl --upload-file <local_path> <dest_url>
 *
 * The destination receives a plain HTTP PUT.  TPC transfer headers forwarded
 * from the original COPY request (Authorization, TransferHeader* stripped and
 * re-attached) are passed via -H flags exactly as in the pull direction.
 *
 * Returns NGX_OK on curl exit 0, NGX_HTTP_BAD_GATEWAY on remote error,
 * NGX_HTTP_INTERNAL_SERVER_ERROR on fork/exec failure.
 */
ngx_int_t
webdav_tpc_run_curl_push(ngx_http_request_t *r,
                         ngx_http_xrootd_webdav_loc_conf_t *conf,
                         const char *dest_url, const char *local_path,
                         ngx_array_t *transfer_headers)
{
    char       *argv[WEBDAV_TPC_MAX_ARGS];
    ngx_uint_t  argc = 0;
    ngx_uint_t  i;
    ngx_str_t  *headers;
    pid_t       pid;
    int         status;
    char        timeout_buf[32];

#define WEBDAV_TPC_PUSH_ARG(v)                                              \
    do {                                                                    \
        if (argc + 1 >= WEBDAV_TPC_MAX_ARGS) {                             \
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,              \
                          "xrootd_webdav: HTTP-TPC push curl argv overflow"); \
            return NGX_HTTP_INTERNAL_SERVER_ERROR;                          \
        }                                                                   \
        argv[argc++] = (char *) (v);                                        \
    } while (0)

    WEBDAV_TPC_PUSH_ARG((char *) conf->tpc_curl.data);
    WEBDAV_TPC_PUSH_ARG("--fail");
    WEBDAV_TPC_PUSH_ARG("--location");
    WEBDAV_TPC_PUSH_ARG("--silent");
    WEBDAV_TPC_PUSH_ARG("--show-error");
    WEBDAV_TPC_PUSH_ARG("--proto");
    WEBDAV_TPC_PUSH_ARG("=https");

    if (conf->tpc_timeout > 0) {
        (void) snprintf(timeout_buf, sizeof(timeout_buf), "%u",
                        (unsigned) conf->tpc_timeout);
        WEBDAV_TPC_PUSH_ARG("--max-time");
        WEBDAV_TPC_PUSH_ARG(timeout_buf);
    }

    if (conf->tpc_cert.len > 0) {
        WEBDAV_TPC_PUSH_ARG("--cert");
        WEBDAV_TPC_PUSH_ARG((char *) conf->tpc_cert.data);
    }
    if (conf->tpc_key.len > 0) {
        WEBDAV_TPC_PUSH_ARG("--key");
        WEBDAV_TPC_PUSH_ARG((char *) conf->tpc_key.data);
    }
    if (conf->tpc_cafile.len > 0) {
        WEBDAV_TPC_PUSH_ARG("--cacert");
        WEBDAV_TPC_PUSH_ARG((char *) conf->tpc_cafile.data);
    }
    if (conf->tpc_cadir.len > 0) {
        WEBDAV_TPC_PUSH_ARG("--capath");
        WEBDAV_TPC_PUSH_ARG((char *) conf->tpc_cadir.data);
    }

    if (transfer_headers != NULL && transfer_headers->nelts > 0) {
        headers = transfer_headers->elts;
        for (i = 0; i < transfer_headers->nelts; i++) {
            WEBDAV_TPC_PUSH_ARG("-H");
            WEBDAV_TPC_PUSH_ARG((char *) headers[i].data);
        }
    }

    /* --upload-file sends a PUT to the destination URL. */
    WEBDAV_TPC_PUSH_ARG("--upload-file");
    WEBDAV_TPC_PUSH_ARG((char *) local_path);
    WEBDAV_TPC_PUSH_ARG((char *) dest_url);
    argv[argc] = NULL;

#undef WEBDAV_TPC_PUSH_ARG

    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_STARTED]);

    pid = fork();
    if (pid < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "xrootd_webdav: fork() failed for HTTP-TPC push curl");
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (pid == 0) {
        int  nullfd;
        long fd;
        long maxfd;

        nullfd = open("/dev/null", O_RDONLY);
        if (nullfd >= 0) {
            (void) dup2(nullfd, STDIN_FILENO);
            if (nullfd > STDERR_FILENO) {
                close(nullfd);
            }
        }

        maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd < 0 || maxfd > 65536) {
            maxfd = 65536;
        }
        for (fd = STDERR_FILENO + 1; fd < maxfd; fd++) {
            close((int) fd);
        }

        if (strchr((const char *) conf->tpc_curl.data, '/') != NULL) {
            execv((const char *) conf->tpc_curl.data, argv);
        } else {
            execvp((const char *) conf->tpc_curl.data, argv);
        }

        _exit(127);
    }

    for (;;) {
        if (waitpid(pid, &status, 0) >= 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "xrootd_webdav: waitpid() failed for HTTP-TPC push curl");
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_SUCCESS]);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "xrootd_webdav: HTTP-TPC push curl failed status=%d",
                  status);
    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_CURL_ERROR]);
    return NGX_HTTP_BAD_GATEWAY;
}
