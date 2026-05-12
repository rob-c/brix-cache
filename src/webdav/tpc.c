/*
 * tpc.c - HTTP-TPC COPY pull and push handler for the WebDAV module.
 */

#include "webdav.h"

#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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
        const char *subject_token = NULL;
        if (auth_hdr != NULL) {
            /* Skip "Bearer " prefix. */
            const char *bearer_prefix = "Bearer ";
            size_t prefix_len = sizeof("Bearer ") - 1;
            if (auth_hdr->value.len > prefix_len
                && ngx_strncasecmp(auth_hdr->value.data,
                                   (u_char *) bearer_prefix,
                                   prefix_len) == 0)
            {
                subject_token = (const char *) (auth_hdr->value.data + prefix_len);
            }
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

    rc = webdav_tpc_collect_transfer_headers(r, &transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

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
    rc = webdav_tpc_run_curl_push(r, conf, dest_url, path, transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PUSH_SUCCESS]);
    r->headers_out.status           = NGX_HTTP_CREATED;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}


/*
 * ngx_http_xrootd_webdav_tpc_handle_copy — handle HTTP-TPC COPY requests.
 *
 * HTTP-TPC (Third-Party Copy) is a GridFTP-style protocol layered on WebDAV
 * COPY.  Two modes are supported:
 *
 * Pull mode (Source: header present):
 *   The server fetches a file from the given HTTPS source URL and writes it
 *   to the local path derived from the request URI.
 *   Flow:
 *     1. Validate Source URL (must be https://, no control chars).
 *     2. Check Credential header (only "none" is accepted — no delegation).
 *     3. Resolve local destination path; check Overwrite: header.
 *     4. Write to a temp file (<path>.nginx-xrootd-tpc.<pid>.<time>).
 *     5. Run curl via webdav_tpc_run_curl_pull.
 *     6. On success: rename temp → final.  On failure: unlink temp.
 *     7. Return 201 Created (new file) or 204 No Content (overwrite).
 *
 * Push mode (Destination: header present, no Source: header):
 *   The server reads a local file (identified by the request URI) and uploads
 *   it to the given HTTPS destination URL via HTTP PUT.
 *   Flow:
 *     1. Validate Destination URL (must be https://, no control chars).
 *     2. Check Credential header (only "none" is accepted).
 *     3. Resolve and stat the local source path — must exist, not a directory.
 *     4. Run curl via webdav_tpc_run_curl_push (--upload-file).
 *     5. Return 201 Created on success.
 *
 * Both modes reject requests with both Source: and Destination: present, and
 * requests with neither header.
 *
 * Overwrite: F applies to pull only (prevents overwriting a local file).
 * For push the server does not know the state of the remote destination.
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
    char             tmp_path[WEBDAV_MAX_PATH];
    struct stat      sb;
    ngx_int_t        rc;
    ngx_flag_t       existed;
    ngx_flag_t       overwrite = 1;
    ngx_int_t        status;

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
        if (auth_hdr != NULL) {
            const char *bearer_prefix = "Bearer ";
            size_t prefix_len = sizeof("Bearer ") - 1;
            if (auth_hdr->value.len > prefix_len
                && ngx_strncasecmp(auth_hdr->value.data,
                                   (u_char *) bearer_prefix,
                                   prefix_len) == 0)
            {
                subject_token = (const char *) (auth_hdr->value.data + prefix_len);
            }
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

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
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

    if ((size_t) snprintf(tmp_path, sizeof(tmp_path),
                          "%s.nginx-xrootd-tpc.%ld.%ld",
                          path, (long) getpid(), (long) time(NULL))
        >= sizeof(tmp_path))
    {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    (void) xrootd_unlink_confined_canon(r->connection->log, conf->root_canon,
                                        tmp_path, 0);

    rc = webdav_tpc_collect_transfer_headers(r, &transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PULL_STARTED]);
    rc = webdav_tpc_run_curl_pull(r, conf, source_url, tmp_path,
                                  transfer_headers);
    if (rc != NGX_OK) {
        (void) xrootd_unlink_confined_canon(r->connection->log,
                                            conf->root_canon, tmp_path, 0);
        return rc;
    }

    if (!overwrite) {
        if (xrootd_link_confined_canon(r->connection->log, conf->root_canon,
                                       tmp_path, path) != 0) {
            status = (errno == EEXIST) ? NGX_HTTP_PRECONDITION_FAILED
                                       : NGX_HTTP_INTERNAL_SERVER_ERROR;
            (void) xrootd_unlink_confined_canon(r->connection->log,
                                                conf->root_canon, tmp_path, 0);
            XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_COMMIT_ERROR]);
            return status;
        }
        (void) xrootd_unlink_confined_canon(r->connection->log,
                                            conf->root_canon, tmp_path, 0);
    } else if (xrootd_rename_confined_canon(r->connection->log,
                                            conf->root_canon, tmp_path,
                                            path) != 0) {
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                             ngx_errno,
                                             "xrootd_webdav: HTTP-TPC rename failed for",
                                             path);
        (void) xrootd_unlink_confined_canon(r->connection->log,
                                            conf->root_canon, tmp_path, 0);
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_COMMIT_ERROR]);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PULL_SUCCESS]);
    status = existed ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}
