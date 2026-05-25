/*
 * tpc.c - HTTP-TPC COPY pull and push handler for the WebDAV module.
 */

#include "webdav.h"
#include "../compat/http_headers.h"
#include "../compat/staged_file.h"
#include "../dashboard/dashboard_tracking.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *
webdav_dashboard_identity(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_req_ctx_t *wctx;

    wctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    return (wctx != NULL && wctx->dn[0] != '\0') ? wctx->dn : "anonymous";
}

static ngx_int_t
webdav_tpc_extract_subject_token(ngx_http_request_t *r,
                                 ngx_table_elt_t *auth_hdr,
                                 const char **subject_token)
{
    ngx_str_t bearer;
    ngx_int_t rc;
    char     *token;

    *subject_token = NULL;

    if (auth_hdr == NULL) {
        return NGX_OK;
    }

    rc = xrootd_http_extract_bearer(&auth_hdr->value, &bearer);
    if (rc != NGX_OK) {
        return NGX_OK;
    }

    token = webdav_tpc_pstrndup0(r->pool, bearer.data, bearer.len);
    if (token == NULL) {
        return NGX_ERROR;
    }

    *subject_token = token;
    return NGX_OK;
}

/*
 * webdav_tpc_handle_push — HTTP-TPC push: read a local file and PUT it to a
 * remote HTTPS destination.
 *
 * The request URI identifies the local source file.  The Destination: header
 * carries the remote URL to push to.  No temp-file dance is needed: the local
 * file is only read, never written.
 *
 * OAuth2/OIDC delegation: when Credential: header is "oidc-agent" or
 * "token-exchange", the server obtains a delegated access token for the
 * remote destination and injects it as an Authorization: Bearer header.
 */
static ngx_int_t
webdav_tpc_handle_push(ngx_http_request_t *r,
                       ngx_http_xrootd_webdav_loc_conf_t *conf,
                       ngx_table_elt_t *dest_hdr)
{
    ngx_table_elt_t *credential_hdr;
    ngx_table_elt_t *overwrite_hdr;
    ngx_table_elt_t *auth_hdr;
    ngx_array_t     *transfer_headers = NULL;
    ngx_str_t        delegated_token;
    char            *dest_url;
    char             path[WEBDAV_MAX_PATH];
    struct stat      sb;
    ngx_int_t        rc;
    xrootd_tpc_cred_mode_e mode;
    const char      *subject_token;

    if (dest_hdr->value.len < sizeof("https://") - 1
        || ngx_strncasecmp(dest_hdr->value.data,
                           (u_char *) "https://",
                           sizeof("https://") - 1) != 0
        || webdav_tpc_str_has_ctl(dest_hdr->value.data, dest_hdr->value.len))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: HTTP-TPC push Destination must be"
                      " an https URL");
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }

    dest_url = webdav_tpc_pstrndup0(r->pool, dest_hdr->value.data,
                                    dest_hdr->value.len);
    if (dest_url == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = webdav_tpc_collect_transfer_headers(r, &transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

    credential_hdr = webdav_tpc_find_header(r, "Credential",
                                            sizeof("Credential") - 1);
    if (credential_hdr == NULL) {
        credential_hdr = webdav_tpc_find_header(r, "Credentials",
                                                sizeof("Credentials") - 1);
    }

    /*
     * Parse the Credential header. "none" (or absent) means no delegation.
     * "oidc-agent" or "token-exchange" triggers token acquisition for the
     * remote destination.
     */
    if (credential_hdr != NULL
        && !webdav_tpc_header_value_equals(&credential_hdr->value, "none"))
    {
        mode = webdav_tpc_cred_parse_mode(
            (const char *) credential_hdr->value.data,
            credential_hdr->value.len);

        if (mode == XROOTD_TPC_CRED_UNKNOWN) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: unsupported HTTP-TPC credential "
                          "delegation mode \"%V\"", &credential_hdr->value);
            XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_BAD_REQUEST]);
            return NGX_HTTP_BAD_REQUEST;
        }

        /*
         * Extract the subject token from the request's Authorization header
         * (the authenticated session token).  Required for token-exchange mode;
         * optional for oidc-agent mode.
         */
        auth_hdr = webdav_tpc_find_header(r, "Authorization",
                                          sizeof("Authorization") - 1);
        subject_token = NULL;
        rc = webdav_tpc_extract_subject_token(r, auth_hdr, &subject_token);
        if (rc != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = webdav_tpc_cred_obtain_token(r, mode, dest_url,
                                          subject_token,
                                          conf->tpc_cred.token_scope.len > 0
                                              ? (const char *) conf->tpc_cred.token_scope.data
                                              : "storage.read",
                                          &delegated_token);
        if (rc != NGX_OK) {
            return NGX_HTTP_BAD_GATEWAY;
        }

        /* Inject delegated token as Authorization header into transfer_headers. */
        {
            size_t total_len = sizeof("Authorization: Bearer ") - 1
                               + delegated_token.len;
            ngx_str_t *dst = ngx_array_push(transfer_headers);
            if (dst == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            dst->data = ngx_pnalloc(r->pool, total_len + 1);
            if (dst->data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_memcpy(dst->data, "Authorization: Bearer ",
                       sizeof("Authorization: Bearer ") - 1);
            ngx_memcpy(dst->data + sizeof("Authorization: Bearer ") - 1,
                       delegated_token.data, delegated_token.len);
            dst->len = total_len;
            dst->data[dst->len] = '\0';
        }
    }

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }
    if (S_ISDIR(sb.st_mode)) {
        return NGX_HTTP_CONFLICT;
    }

    (void) xrootd_dashboard_http_start_identity(r, path,
        webdav_dashboard_identity(r), "", XROOTD_XFER_PROTO_WEBDAV,
        XROOTD_XFER_DIR_TPC, "TPC_PUSH", (int64_t) sb.st_size);
    xrootd_dashboard_http_tpc_remote(r, dest_url, 0, 0);

    /* Forward Overwrite header if present.
     * WebDAV COPY uses Overwrite: F, but the outbound TPC push uses PUT.
     * PUT doesn't support Overwrite: F; it uses If-None-Match: *. */
    overwrite_hdr = webdav_tpc_find_header(r, "Overwrite",
                                           sizeof("Overwrite") - 1);
    if (overwrite_hdr != NULL) {
        ngx_str_t *dst = ngx_array_push(transfer_headers);
        if (dst == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (overwrite_hdr->value.len == 1 && overwrite_hdr->value.data[0] == 'F') {
            dst->len = sizeof("If-None-Match: *") - 1;
            dst->data = (u_char *) "If-None-Match: *";
        } else {
            dst->len = sizeof("Overwrite: ") - 1 + overwrite_hdr->value.len;
            dst->data = ngx_pnalloc(r->pool, dst->len + 1);
            if (dst->data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_memcpy(dst->data, "Overwrite: ", sizeof("Overwrite: ") - 1);
            ngx_memcpy(dst->data + sizeof("Overwrite: ") - 1,
                       overwrite_hdr->value.data, overwrite_hdr->value.len);
            dst->data[dst->len] = '\0';
        }
    }

    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PUSH_STARTED]);

    rc = webdav_tpc_post_thread_task(r, conf, 1, 0, 0,
                                     dest_url, path, NULL, transfer_headers);
    if (rc != NGX_DECLINED) {
        if (rc == NGX_ERROR) {
            xrootd_dashboard_http_error(r, "webdav TPC push task post failed");
            xrootd_dashboard_http_finish(r);
        }
        return (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : rc;
    }

    rc = webdav_tpc_run_curl_push(r->connection->log, conf, dest_url, path,
                                  transfer_headers);
    if (rc != NGX_OK) {
        xrootd_dashboard_http_error(r, "webdav TPC push failed");
        xrootd_dashboard_http_finish(r);
        return rc;
    }

    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) sb.st_size);
    xrootd_dashboard_http_finish(r);
    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PUSH_SUCCESS]);
    r->headers_out.status           = NGX_HTTP_CREATED;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/**
 * WHAT: Handle HTTP-TPC (Third-Party Copy) COPY requests — implements GridFTP-style
 * cross-server file transfer layered on WebDAV. Supports two modes: pull (fetch remote → local)
 * and push (local → upload remote). Both modes use external curl process to perform the actual
 * data transfer while nginx handles authentication, path confinement, and HTTP header management.
 * Returns 201 Created for new files or 204 No Content for overwrites on pull; 201 Created on
 * push success. Rejects requests with ambiguous headers (both Source + Destination present) or
 * missing required headers via 400 Bad Request. Uses temporary file staging (<path>.nginx-xrootd-tpc.<pid>.<time>)
 * for pull mode to ensure atomic commit — rename/link on success, unlink on failure.
 */
ngx_int_t
ngx_http_xrootd_webdav_tpc_handle_copy(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t *source_hdr;
    ngx_table_elt_t *dest_hdr;
    ngx_table_elt_t *credential_hdr;
    ngx_table_elt_t *overwrite_hdr;
    ngx_array_t     *transfer_headers = NULL;
    char            *source_url;
    char             path[WEBDAV_MAX_PATH];
    struct stat      sb;
    ngx_int_t        rc;
    ngx_flag_t       existed;
    ngx_flag_t       overwrite = 1;
    ngx_int_t        status;
    xrootd_staged_file_t staged;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    source_hdr = webdav_tpc_find_header(r, "Source", sizeof("Source") - 1);
    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);

    if (source_hdr == NULL && dest_hdr == NULL) {
        /* Neither Source nor Destination — not a TPC request. */
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }

    if (source_hdr != NULL && dest_hdr != NULL) {
        /* Both headers present — ambiguous; reject. */
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }

    if (source_hdr == NULL) {
        /* Push mode: Destination present, no Source. */
        return webdav_tpc_handle_push(r, conf, dest_hdr);
    }

    if (source_hdr->value.len < sizeof("https://") - 1
        || ngx_strncasecmp(source_hdr->value.data,
                           (u_char *) "https://",
                           sizeof("https://") - 1) != 0
        || webdav_tpc_str_has_ctl(source_hdr->value.data,
                                  source_hdr->value.len))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: HTTP-TPC Source must be an https URL");
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }

    source_url = webdav_tpc_pstrndup0(r->pool, source_hdr->value.data,
                                       source_hdr->value.len);
    if (source_url == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = webdav_tpc_collect_transfer_headers(r, &transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

    credential_hdr = webdav_tpc_find_header(r, "Credential",
                                            sizeof("Credential") - 1);
    if (credential_hdr == NULL) {
        credential_hdr = webdav_tpc_find_header(r, "Credentials",
                                                sizeof("Credentials") - 1);
    }

    /*
     * OAuth2/OIDC credential delegation: parse the Credential header and
     * obtain a delegated token for the source.  The delegated token is
     * injected into transfer_headers before the curl subprocess runs.
     */
    if (credential_hdr != NULL
        && !webdav_tpc_header_value_equals(&credential_hdr->value, "none"))
    {
        xrootd_tpc_cred_mode_e mode;
        ngx_str_t            delegated_token;
        ngx_table_elt_t     *auth_hdr;
        const char          *subject_token = NULL;

        mode = webdav_tpc_cred_parse_mode(
            (const char *) credential_hdr->value.data,
            credential_hdr->value.len);

        if (mode == XROOTD_TPC_CRED_UNKNOWN) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: unsupported HTTP-TPC credential "
                          "delegation mode \"%V\"", &credential_hdr->value);
            XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_BAD_REQUEST]);
            return NGX_HTTP_BAD_REQUEST;
        }

        /* Extract the subject token from the request's Authorization header. */
        auth_hdr = webdav_tpc_find_header(r, "Authorization",
                                          sizeof("Authorization") - 1);
        rc = webdav_tpc_extract_subject_token(r, auth_hdr, &subject_token);
        if (rc != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = webdav_tpc_cred_obtain_token(r, mode, source_url,
                                          subject_token,
                                          conf->tpc_cred.token_scope.len > 0
                                              ? (const char *) conf->tpc_cred.token_scope.data
                                              : "storage.read",
                                          &delegated_token);
        if (rc != NGX_OK) {
            return NGX_HTTP_BAD_GATEWAY;
        }

        /* Inject delegated token as Authorization header. */
        {
            size_t total_len = sizeof("Authorization: Bearer ") - 1
                               + delegated_token.len;
            ngx_str_t *dst = ngx_array_push(transfer_headers);
            if (dst == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            dst->data = ngx_pnalloc(r->pool, total_len + 1);
            if (dst->data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_memcpy(dst->data, "Authorization: Bearer ",
                       sizeof("Authorization: Bearer ") - 1);
            ngx_memcpy(dst->data + sizeof("Authorization: Bearer ") - 1,
                       delegated_token.data, delegated_token.len);
            dst->len = total_len;
            dst->data[dst->len] = '\0';
        }
    }
    (void) credential_hdr;

    overwrite_hdr = webdav_tpc_find_header(r, "Overwrite",
                                           sizeof("Overwrite") - 1);
    if (overwrite_hdr != NULL) {
        if (webdav_tpc_header_value_equals(&overwrite_hdr->value, "F")) {
            overwrite = 0;
        } else if (webdav_tpc_header_value_equals(&overwrite_hdr->value, "T")) {
            overwrite = 1;
        } else {
            XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_BAD_REQUEST]);
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon, path,
                                             sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

    existed = (stat(path, &sb) == 0) ? 1 : 0;
    if (existed && S_ISDIR(sb.st_mode)) {
        return NGX_HTTP_CONFLICT;
    }
    if (existed && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    if (xrootd_staged_open(r->connection->log, conf->common.root_canon, path,
                           O_WRONLY, 0600, 16, &staged) != NGX_OK)
    {
        return errno == ENAMETOOLONG ? NGX_HTTP_REQUEST_URI_TOO_LARGE
                                     : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_close_file(staged.fd);
    staged.fd = NGX_INVALID_FILE;

    (void) xrootd_dashboard_http_start_identity(r, path,
        webdav_dashboard_identity(r), "", XROOTD_XFER_PROTO_WEBDAV,
        XROOTD_XFER_DIR_TPC, "TPC_PULL", -1);
    xrootd_dashboard_http_tpc_remote(r, source_url, 0, 0);

    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PULL_STARTED]);

    rc = webdav_tpc_post_thread_task(r, conf, 0, existed, overwrite,
                                     source_url, staged.tmp_path, path,
                                     transfer_headers);
    if (rc != NGX_DECLINED) {
        if (rc == NGX_ERROR) {
            xrootd_dashboard_http_error(r, "webdav TPC pull task post failed");
            xrootd_dashboard_http_finish(r);
            xrootd_staged_abort(r->connection->log, conf->common.root_canon,
                                &staged, 1);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return rc;  /* NGX_DONE */
    }

    rc = webdav_tpc_run_curl_pull(r->connection->log, conf, source_url,
                                  staged.tmp_path, transfer_headers);
    if (rc != NGX_OK) {
        xrootd_dashboard_http_error(r, "webdav TPC pull failed");
        xrootd_dashboard_http_finish(r);
        xrootd_staged_abort(r->connection->log, conf->common.root_canon, &staged, 1);
        return rc;
    }

    if (!overwrite) {
        if (xrootd_link_confined_canon(r->connection->log, conf->common.root_canon,
                                       staged.tmp_path, path) != 0) {
            status = (errno == EEXIST) ? NGX_HTTP_PRECONDITION_FAILED
                                       : NGX_HTTP_INTERNAL_SERVER_ERROR;
            xrootd_staged_abort(r->connection->log, conf->common.root_canon,
                                &staged, 1);
            XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_COMMIT_ERROR]);
            xrootd_dashboard_http_error(r, "webdav TPC pull commit failed");
            xrootd_dashboard_http_finish(r);
            return status;
        }
        xrootd_staged_abort(r->connection->log, conf->common.root_canon, &staged, 1);
    } else if (xrootd_staged_commit(r->connection->log, conf->common.root_canon,
                                    &staged, path) != NGX_OK) {
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "xrootd_webdav: HTTP-TPC rename failed for: \"%s\"",
                             path);
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_COMMIT_ERROR]);
        xrootd_dashboard_http_error(r, "webdav TPC pull commit failed");
        xrootd_dashboard_http_finish(r);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (stat(path, &sb) == 0) {
        xrootd_dashboard_http_add(r, (ngx_atomic_int_t) sb.st_size);
    }
    xrootd_dashboard_http_finish(r);
    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PULL_SUCCESS]);
    status = existed ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}
