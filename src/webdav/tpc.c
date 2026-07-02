/*
 * tpc.c - HTTP-TPC COPY pull and push handler for the WebDAV module.
 */

#include "webdav.h"
#include "path/path.h"
#include "fs/vfs.h"   /* xrootd_vfs_probe (confined stat via the VFS seam) */
#include "core/compat/http_headers.h"
#include "core/compat/staged_file.h"
#include "dashboard/dashboard_tracking.h"
#include "fs/xfer/xfer.h"     /* unified transfer audit ledger (kind=tpc) */
#include "tpc/common/auth.h"
#include "tpc/common/metrics.h"
#include "tpc/common/registry.h"

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Confined no-follow stat of `path` through the VFS probe, projected into the
 * struct stat fields the TPC handler reads (mode for the dir check, size for the
 * dashboard/registry/ledger). Non-metered. NGX_OK / NGX_DECLINED (errno kept). */
static ngx_int_t
webdav_tpc_probe(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *path, struct stat *sb)
{
    ngx_http_xrootd_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    xrootd_vfs_ctx_t   vctx;
    xrootd_vfs_stat_t  vst;
    int                is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    xrootd_vfs_ctx_init(&vctx, r->pool, r->connection->log, XROOTD_PROTO_WEBDAV,
        conf->common.root_canon, conf->cache_root_canon, conf->common.allow_write,
        is_tls, (rx != NULL) ? rx->identity : NULL, path);
    if (xrootd_vfs_probe(&vctx, 1 /* no-follow */, &vst) != NGX_OK) {
        return NGX_DECLINED;
    }
    ngx_memzero(sb, sizeof(*sb));
    sb->st_mode  = (mode_t) vst.mode;
    sb->st_size  = vst.size;
    sb->st_mtime = vst.mtime;
    return NGX_OK;
}

/* Display identity for the live-transfer dashboard: the authenticated DN, or
 * "anonymous" when the request carried no usable identity. */
static const char *
webdav_dashboard_identity(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_req_ctx_t *wctx;

    wctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    return (wctx != NULL && wctx->dn[0] != '\0') ? wctx->dn : "anonymous";
}

/* The authenticated identity object (DN/VO/token claims) attached to this
 * request by the auth phase, or NULL for an unauthenticated request. */
static xrootd_identity_t *
webdav_tpc_request_identity(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_req_ctx_t *wctx;

    wctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    return wctx != NULL ? wctx->identity : NULL;
}

/*
 * Extract just the path component of a (possibly scheme-qualified) URL for use
 * as an authorization scope, e.g. "https://host/a/b" -> "/a/b".
 * `out` points into the caller's `url` buffer (no copy); defaults to "/" when
 * the URL has no path.  Used to scope-check the remote endpoint of a TPC.
 */
static void
webdav_tpc_url_path(const char *url, ngx_str_t *out)
{
    const char *scheme;
    const char *path;

    out->data = (u_char *) "/";   /* default scope when URL has no path */
    out->len = 1;

    if (url == NULL) {
        return;
    }

    /* If "://" is present, the path is the first '/' after it; otherwise the
     * first '/' in the whole string. */
    scheme = strstr(url, "://");
    path = scheme != NULL ? strchr(scheme + 3, '/') : strchr(url, '/');
    if (path == NULL || *path == '\0') {
        return;
    }

    out->data = (u_char *) path;
    out->len = ngx_strlen(path);
}

/*
 * Authorize a TPC against the request identity: src_path is the read scope,
 * dst_path the write scope (NULL when the operation only reads, i.e. push).
 * Returns NGX_OK if permitted, else NGX_HTTP_FORBIDDEN (and bumps the bad-request
 * metric).  This is the access-control gate before any data movement starts.
 */
static ngx_int_t
webdav_tpc_authorize(ngx_http_request_t *r, const ngx_str_t *src_path,
    const ngx_str_t *dst_path)
{
    if (xrootd_tpc_check_authz(webdav_tpc_request_identity(r), src_path,
                               dst_path, r->connection->log)
        != NGX_OK)
    {
        XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}

/*
 * Register a new in-flight transfer in the cross-process TPC registry so it is
 * visible to /metrics and the dashboard.  Returns a non-zero transfer id used to
 * update/remove the entry as the transfer progresses; returns 0 if the registry
 * is full (caller maps that to 503).
 */
static uint64_t
webdav_tpc_register_transfer(ngx_http_request_t *r, ngx_uint_t direction,
    const char *src, const char *dst, off_t bytes_total)
{
    xrootd_tpc_transfer_t transfer;
    ngx_str_t             src_str;
    ngx_str_t             dst_str;

    if (src == NULL || dst == NULL) {
        return 0;
    }

    src_str.data = (u_char *) src;
    src_str.len = ngx_strlen(src);
    dst_str.data = (u_char *) dst;
    dst_str.len = ngx_strlen(dst);

    ngx_memzero(&transfer, sizeof(transfer));
    transfer.protocol = XROOTD_TPC_PROTO_WEBDAV;
    transfer.direction = direction;
    transfer.src_url = src_str;
    transfer.dst_path = dst_str;
    transfer.bytes_total = bytes_total > 0 ? bytes_total : 0;
    transfer.state = XROOTD_TPC_STATE_PENDING;

    return xrootd_tpc_registry_add(&transfer, r->connection->log);
}

/*
 * Pull the bearer token out of the request's Authorization header for use as the
 * "subject token" in OAuth2 token-exchange delegation.  A missing/non-bearer
 * header is not an error: *subject_token stays NULL and NGX_OK is returned
 * (oidc-agent mode does not need it; token-exchange mode will fail later).
 * NGX_ERROR only on allocation failure.  The token is copied (NUL-terminated)
 * into the request pool so it outlives the header table.
 */
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
    ngx_str_t        src_scope;
    uint64_t         transfer_id;

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

        /* Build "Authorization: Bearer <token>" as one full header line and push
         * it onto the outbound transfer-header list curl will send to the remote
         * destination.  (Mechanical string assembly, NUL-terminated for curl.) */
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

    src_scope = r->uri;
    rc = webdav_tpc_authorize(r, &src_scope, NULL);
    if (rc != NGX_OK) {
        return rc;
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
    xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV, XROOTD_TPC_DIR_PUSH,
                               XROOTD_TPC_METRIC_STARTED, 0,
                               r->connection->log);

    /* Preferred path: hand the push off to the thread pool so the event loop is
     * never blocked on curl.  NGX_DECLINED means "no thread pool configured" and
     * we fall through to running curl synchronously below; NGX_DONE means the
     * task was queued (response finalized later); any other rc is terminal. */
    rc = webdav_tpc_post_thread_task(r, conf, 1, 0, 0,
                                     dest_url, path, NULL, transfer_headers, 1);
    if (rc != NGX_DECLINED) {
        if (rc != NGX_DONE) {
            xrootd_dashboard_http_error(r, "webdav TPC push task post failed");
            xrootd_dashboard_http_finish(r);
        }
        return (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : rc;
    }

    /* Synchronous fallback (blocks the worker for the duration of the push). */
    transfer_id = webdav_tpc_register_transfer(r, XROOTD_TPC_DIR_PUSH, path,
                                               dest_url, sb.st_size);
    if (transfer_id == 0) {
        xrootd_dashboard_http_error(r, "webdav TPC registry full");
        xrootd_dashboard_http_finish(r);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    rc = webdav_tpc_run_curl_push(r->connection->log, conf, dest_url, path,
                                  transfer_headers, transfer_id);
    if (rc != NGX_OK) {
        (void) xrootd_tpc_registry_update(transfer_id, 0,
                                          XROOTD_TPC_STATE_ERROR,
                                          r->connection->log);
        xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                   XROOTD_TPC_DIR_PUSH,
                                   XROOTD_TPC_METRIC_ERROR, 0,
                                   r->connection->log);
        (void) xrootd_tpc_registry_remove(transfer_id, r->connection->log);
        xrootd_dashboard_http_error(r, "webdav TPC push failed");
        xrootd_dashboard_http_finish(r);
        xrootd_xfer_finish(XROOTD_XFER_TPC, "out", path, NULL, 0,
                           XROOTD_XFER_DST_ERR, 0, r->connection->log);
        return rc;
    }

    (void) xrootd_tpc_registry_update(transfer_id, sb.st_size,
                                      XROOTD_TPC_STATE_DONE,
                                      r->connection->log);
    xrootd_xfer_finish(XROOTD_XFER_TPC, "out", path, NULL, (size_t) sb.st_size,
                       XROOTD_XFER_OK, 0, r->connection->log);
    xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV, XROOTD_TPC_DIR_PUSH,
                               XROOTD_TPC_METRIC_SUCCESS, (size_t) sb.st_size,
                               r->connection->log);
    (void) xrootd_tpc_registry_remove(transfer_id, r->connection->log);
    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) sb.st_size);
    xrootd_dashboard_http_finish(r);
    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PUSH_SUCCESS]);
    return webdav_send_no_body(r, NGX_HTTP_CREATED);
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

/* OAuth2/OIDC credential delegation for an HTTP-TPC pull: parse the Credential /
 * Credentials request header and, unless it is absent or "none", obtain a
 * delegated token for source_url and inject it as an "Authorization: Bearer"
 * entry into transfer_headers (consumed by the curl subprocess).  Returns NGX_OK
 * to continue (whether or not delegation happened), or an NGX_HTTP_* status the
 * caller must return on a parse/obtain/alloc failure. */
static ngx_int_t
webdav_tpc_apply_credential_delegation(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *source_url,
    ngx_array_t *transfer_headers)
{
    ngx_table_elt_t       *credential_hdr;
    xrootd_tpc_cred_mode_e mode;
    ngx_str_t              delegated_token;
    ngx_table_elt_t       *auth_hdr;
    const char            *subject_token = NULL;
    ngx_int_t              rc;

    credential_hdr = webdav_tpc_find_header(r, "Credential",
                                            sizeof("Credential") - 1);
    if (credential_hdr == NULL) {
        credential_hdr = webdav_tpc_find_header(r, "Credentials",
                                                sizeof("Credentials") - 1);
    }
    if (credential_hdr == NULL
        || webdav_tpc_header_value_equals(&credential_hdr->value, "none"))
    {
        return NGX_OK;
    }

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

    return NGX_OK;
}

ngx_int_t
ngx_http_xrootd_webdav_tpc_handle_copy(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t *source_hdr;
    ngx_table_elt_t *dest_hdr;
    ngx_table_elt_t *overwrite_hdr;
    ngx_table_elt_t *streams_hdr;
    ngx_array_t     *transfer_headers = NULL;
    char            *source_url;
    char             path[WEBDAV_MAX_PATH];
    struct stat      sb;
    ngx_int_t        rc;
    ngx_flag_t       existed;
    ngx_flag_t       overwrite = 1;
    ngx_int_t        status;
    xrootd_staged_file_t staged;
    ngx_str_t        src_scope;
    ngx_str_t        dst_scope;
    uint64_t         transfer_id;
    ngx_uint_t       n_streams;

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

    /* X-Number-Of-Streams: N — negotiate parallel pull streams.
     * Capped at tpc_max_streams (default 1; multi-stream disabled unless
     * xrootd_webdav_tpc_max_streams is set to > 1 in the config). */
    streams_hdr = webdav_tpc_find_header(r, "X-Number-Of-Streams",
                                         sizeof("X-Number-Of-Streams") - 1);
    n_streams = 1;
    if (streams_hdr != NULL && streams_hdr->value.len > 0) {
        ngx_int_t v = ngx_atoi(streams_hdr->value.data, streams_hdr->value.len);
        if (v > 1) {
            n_streams = (ngx_uint_t) v;
        }
    }
    if (n_streams > conf->tpc_max_streams && conf->tpc_max_streams > 0) {
        n_streams = conf->tpc_max_streams;
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

    /* OAuth2/OIDC credential delegation: obtain a delegated token for the source
     * and inject it into transfer_headers before the curl subprocess runs. */
    rc = webdav_tpc_apply_credential_delegation(r, conf, source_url,
                                                transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

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

    existed = (webdav_tpc_probe(r, conf, path, &sb) == NGX_OK) ? 1 : 0;
    if (existed && S_ISDIR(sb.st_mode)) {
        return NGX_HTTP_CONFLICT;
    }
    if (existed && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    /* Pull authorization: read scope = remote source path, write scope = our URI. */
    webdav_tpc_url_path(source_url, &src_scope);
    dst_scope = r->uri;
    rc = webdav_tpc_authorize(r, &src_scope, &dst_scope);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Open a confined temp file (path.nginx-xrootd-tpc.PID.TIME) that curl will
     * fill; on success it is atomically committed (rename/link) over `path`, on
     * failure it is unlinked.  We only needed to create/validate it here, so the
     * fd is closed immediately — curl reopens the temp path by name. */
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
    xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV, XROOTD_TPC_DIR_PULL,
                               XROOTD_TPC_METRIC_STARTED, 0,
                               r->connection->log);

    /*
     * Pull executes via the first available of three tiers:
     *  (1) 202-streaming marker path (this block) when tpc_marker_interval > 0:
     *      async transfer that dribbles Performance-Marker lines to the client.
     *  (2) thread-pool task (below) when a thread pool is configured.
     *  (3) synchronous curl (final fallback) that blocks the worker.
     * Each tier returns NGX_DECLINED to mean "not applicable, try the next".
     * The staged temp file must be aborted (unlinked) on every error exit so a
     * failed pull never leaves a partial file behind.
     */
    if (conf->tpc_marker_interval > 0) {
        transfer_id = webdav_tpc_register_transfer(r, XROOTD_TPC_DIR_PULL,
                                                   source_url, path, 0);
        if (transfer_id == 0) {
            xrootd_dashboard_http_error(r, "webdav TPC registry full");
            xrootd_dashboard_http_finish(r);
            xrootd_staged_abort(r->connection->log, conf->common.root_canon,
                                &staged, 1);
            return NGX_HTTP_SERVICE_UNAVAILABLE;
        }
        rc = webdav_tpc_marker_start(r, conf, n_streams, source_url,
                                     staged.tmp_path, path,
                                     1 /* is_pull */, overwrite, existed,
                                     transfer_headers, transfer_id);
        if (rc != NGX_DECLINED) {
            if (rc != NGX_DONE) {
                (void) xrootd_tpc_registry_remove(transfer_id,
                                                  r->connection->log);
                xrootd_dashboard_http_error(r, "webdav TPC marker start failed");
                xrootd_dashboard_http_finish(r);
                xrootd_staged_abort(r->connection->log, conf->common.root_canon,
                                    &staged, 1);
                return (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : rc;
            }
            return NGX_DONE;
        }
        /* Marker path declined (no thread pool) — drop its registry entry and
         * fall through to the thread-task / synchronous 201 path below. */
        (void) xrootd_tpc_registry_remove(transfer_id, r->connection->log);
    }

    /* Tier 2: offload to the thread pool (NGX_DECLINED -> synchronous tier 3). */
    rc = webdav_tpc_post_thread_task(r, conf, 0, existed, overwrite,
                                     source_url, staged.tmp_path, path,
                                     transfer_headers, n_streams);
    if (rc != NGX_DECLINED) {
        if (rc != NGX_DONE) {
            xrootd_dashboard_http_error(r, "webdav TPC pull task post failed");
            xrootd_dashboard_http_finish(r);
            xrootd_staged_abort(r->connection->log, conf->common.root_canon,
                                &staged, 1);
            return (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : rc;
        }
        return rc;  /* NGX_DONE */
    }

    /* Tier 3: run curl synchronously on the worker. */
    transfer_id = webdav_tpc_register_transfer(r, XROOTD_TPC_DIR_PULL,
                                               source_url, path, 0);
    if (transfer_id == 0) {
        xrootd_dashboard_http_error(r, "webdav TPC registry full");
        xrootd_dashboard_http_finish(r);
        xrootd_staged_abort(r->connection->log, conf->common.root_canon,
                            &staged, 1);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    rc = webdav_tpc_run_curl_pull(r->connection->log, conf, source_url,
                                  staged.tmp_path, transfer_headers,
                                  transfer_id);
    if (rc != NGX_OK) {
        (void) xrootd_tpc_registry_update(transfer_id, 0,
                                          XROOTD_TPC_STATE_ERROR,
                                          r->connection->log);
        xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                   XROOTD_TPC_DIR_PULL,
                                   XROOTD_TPC_METRIC_ERROR, 0,
                                   r->connection->log);
        (void) xrootd_tpc_registry_remove(transfer_id, r->connection->log);
        xrootd_dashboard_http_error(r, "webdav TPC pull failed");
        xrootd_dashboard_http_finish(r);
        xrootd_staged_abort(r->connection->log, conf->common.root_canon, &staged, 1);
        xrootd_xfer_finish(XROOTD_XFER_TPC, "in", path, NULL, 0,
                           XROOTD_XFER_SRC_ERR, 0, r->connection->log);
        return rc;
    }

    /* Commit the staged temp file. Two strategies by overwrite policy:
     *  - no-overwrite (Overwrite: F): link() the temp into place, which fails
     *    with EEXIST if a file appeared meanwhile -> 412 (atomic create-only).
     *  - overwrite: rename() the temp over any existing file.
     * Either way the temp is removed afterward (link leaves the temp; rename
     * consumes it), and any failure aborts/cleans up and records an error. */
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
            (void) xrootd_tpc_registry_update(transfer_id, 0,
                                              XROOTD_TPC_STATE_ERROR,
                                              r->connection->log);
            xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                       XROOTD_TPC_DIR_PULL,
                                       XROOTD_TPC_METRIC_ERROR, 0,
                                       r->connection->log);
            (void) xrootd_tpc_registry_remove(transfer_id,
                                              r->connection->log);
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
        (void) xrootd_tpc_registry_update(transfer_id, 0,
                                          XROOTD_TPC_STATE_ERROR,
                                          r->connection->log);
        xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                   XROOTD_TPC_DIR_PULL,
                                   XROOTD_TPC_METRIC_ERROR, 0,
                                   r->connection->log);
        (void) xrootd_tpc_registry_remove(transfer_id, r->connection->log);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (webdav_tpc_probe(r, conf, path, &sb) == NGX_OK) {
        xrootd_dashboard_http_add(r, (ngx_atomic_int_t) sb.st_size);
        (void) xrootd_tpc_registry_update(transfer_id, sb.st_size,
                                          XROOTD_TPC_STATE_DONE,
                                          r->connection->log);
        xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                   XROOTD_TPC_DIR_PULL,
                                   XROOTD_TPC_METRIC_SUCCESS,
                                   (size_t) sb.st_size,
                                   r->connection->log);
    } else {
        (void) xrootd_tpc_registry_update(transfer_id, 0,
                                          XROOTD_TPC_STATE_DONE,
                                          r->connection->log);
        xrootd_tpc_metric_transfer(XROOTD_TPC_PROTO_WEBDAV,
                                   XROOTD_TPC_DIR_PULL,
                                   XROOTD_TPC_METRIC_SUCCESS, 0,
                                   r->connection->log);
    }
    (void) xrootd_tpc_registry_remove(transfer_id, r->connection->log);
    xrootd_dashboard_http_finish(r);
    XROOTD_WEBDAV_METRIC_INC(tpc_total[XROOTD_WEBDAV_TPC_PULL_SUCCESS]);
    xrootd_xfer_finish(XROOTD_XFER_TPC, "in", path, NULL,
                       (size_t) (webdav_tpc_probe(r, conf, path, &sb) == NGX_OK
                           ? sb.st_size : 0),
                       XROOTD_XFER_OK, 0, r->connection->log);
    return webdav_send_no_body(r, existed ? NGX_HTTP_NO_CONTENT
                                          : NGX_HTTP_CREATED);
}
