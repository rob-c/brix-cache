/*
 * tpc.c - HTTP-TPC COPY pull and push handler for the WebDAV module.
 */

#include "webdav.h"
#include "tpc_user_proxy.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_probe (confined stat via the VFS seam) */
#include "core/http/http_headers.h"
#include "core/compat/staged_file.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "observability/sesslog/sesslog_ngx.h"
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
    ngx_http_brix_webdav_loc_conf_t *conf, const char *path, struct stat *sb)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    brix_vfs_ctx_t   vctx;
    brix_vfs_stat_t  vst;
    int                is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_WEBDAV,
        conf->common.root_canon, conf->cache_root_canon, conf->common.allow_write,
        is_tls, (rx != NULL) ? rx->identity : NULL, path);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &vst) != NGX_OK) {
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
    ngx_http_brix_webdav_req_ctx_t *wctx;

    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    return (wctx != NULL && wctx->dn[0] != '\0') ? wctx->dn : "anonymous";
}

/* The authenticated identity object (DN/VO/token claims) attached to this
 * request by the auth phase, or NULL for an unauthenticated request. */
static brix_identity_t *
webdav_tpc_request_identity(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *wctx;

    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    return wctx != NULL ? wctx->identity : NULL;
}

static void
webdav_tpc_note_client_copy_xfer(ngx_http_request_t *r, off_t bytes,
    int64_t expected)
{
    ngx_http_brix_webdav_req_ctx_t *wctx;
    uint64_t                        moved;

    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (wctx == NULL || !wctx->sess_xfer_started) {
        return;
    }

    if (expected >= 0) {
        wctx->sess_xfer.expected = expected;
    }

    moved = bytes > 0 ? (uint64_t) bytes : 0;
    if (moved > wctx->sess_xfer.bytes) {
        brix_sess_xfer_add(&wctx->sess_xfer, moved - wctx->sess_xfer.bytes);
    }
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
    if (brix_tpc_check_authz(webdav_tpc_request_identity(r), src_path,
                               dst_path, r->connection->log)
        != NGX_OK)
    {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
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
    brix_tpc_transfer_t transfer;
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
    transfer.protocol = BRIX_TPC_PROTO_WEBDAV;
    transfer.direction = direction;
    transfer.src_url = src_str;
    transfer.dst_path = dst_str;
    transfer.bytes_total = bytes_total > 0 ? bytes_total : 0;
    transfer.state = BRIX_TPC_STATE_PENDING;

    return brix_tpc_registry_add(&transfer, r->connection->log);
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

    rc = brix_http_extract_bearer(&auth_hdr->value, &bearer);
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

static ngx_int_t
webdav_tpc_add_bearer_header(ngx_http_request_t *r, ngx_array_t *headers,
                             ngx_str_t *delegated_token)
{
    size_t total_len;
    ngx_str_t *dst;

    total_len = sizeof("Authorization: Bearer ") - 1 + delegated_token->len;
    dst = ngx_array_push(headers);
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
               delegated_token->data, delegated_token->len);
    dst->len = total_len;
    dst->data[dst->len] = '\0';
    return NGX_OK;
}

static ngx_int_t
webdav_tpc_push_apply_credential(ngx_http_request_t *r,
                                 ngx_http_brix_webdav_loc_conf_t *conf,
                                 char *dest_url, ngx_array_t *headers)
{
    ngx_table_elt_t      *credential_hdr;
    ngx_table_elt_t      *auth_hdr;
    ngx_str_t             delegated_token;
    ngx_int_t             rc;
    brix_tpc_cred_mode_e  mode;
    const char           *subject_token;

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
        (const char *) credential_hdr->value.data, credential_hdr->value.len);
    if (mode == BRIX_TPC_CRED_UNKNOWN) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_webdav: unsupported HTTP-TPC credential "
                      "delegation mode \"%V\"", &credential_hdr->value);
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }

    auth_hdr = webdav_tpc_find_header(r, "Authorization",
                                      sizeof("Authorization") - 1);
    subject_token = NULL;
    rc = webdav_tpc_extract_subject_token(r, auth_hdr, &subject_token);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = webdav_tpc_cred_obtain_token(r, mode, dest_url, subject_token,
                                      conf->tpc_cred.token_scope.len > 0
                                          ? (const char *) conf->tpc_cred.token_scope.data
                                          : "storage.read",
                                      &delegated_token);
    if (rc != NGX_OK) {
        return NGX_HTTP_BAD_GATEWAY;
    }

    return webdav_tpc_add_bearer_header(r, headers, &delegated_token);
}

static ngx_int_t
webdav_tpc_push_dest_url(ngx_http_request_t *r, ngx_table_elt_t *dest_hdr,
                         char **dest_url)
{
    if (dest_hdr->value.len < sizeof("https://") - 1
        || ngx_strncasecmp(dest_hdr->value.data, (u_char *) "https://",
                           sizeof("https://") - 1) != 0
        || webdav_tpc_str_has_ctl(dest_hdr->value.data, dest_hdr->value.len))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_webdav: HTTP-TPC push Destination must be"
                      " an https URL");
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }

    *dest_url = webdav_tpc_pstrndup0(r->pool, dest_hdr->value.data,
                                     dest_hdr->value.len);
    return (*dest_url == NULL) ? NGX_HTTP_INTERNAL_SERVER_ERROR : NGX_OK;
}

static ngx_int_t
webdav_tpc_push_add_overwrite_value(ngx_http_request_t *r,
                                    ngx_array_t *headers,
                                    ngx_table_elt_t *overwrite_hdr)
{
    ngx_str_t *dst;

    dst = ngx_array_push(headers);
    if (dst == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (overwrite_hdr->value.len == 1 && overwrite_hdr->value.data[0] == 'F') {
        dst->len = sizeof("If-None-Match: *") - 1;
        dst->data = (u_char *) "If-None-Match: *";
        return NGX_OK;
    }

    dst->len = sizeof("Overwrite: ") - 1 + overwrite_hdr->value.len;
    dst->data = ngx_pnalloc(r->pool, dst->len + 1);
    if (dst->data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(dst->data, "Overwrite: ", sizeof("Overwrite: ") - 1);
    ngx_memcpy(dst->data + sizeof("Overwrite: ") - 1,
               overwrite_hdr->value.data, overwrite_hdr->value.len);
    dst->data[dst->len] = '\0';
    return NGX_OK;
}

static ngx_int_t
webdav_tpc_push_forward_overwrite(ngx_http_request_t *r,
                                  ngx_array_t *headers)
{
    ngx_table_elt_t *overwrite_hdr;

    overwrite_hdr = webdav_tpc_find_header(r, "Overwrite",
                                           sizeof("Overwrite") - 1);
    if (overwrite_hdr == NULL) {
        return NGX_OK;
    }

    return webdav_tpc_push_add_overwrite_value(r, headers, overwrite_hdr);
}

static ngx_int_t
webdav_tpc_push_post_thread(ngx_http_request_t *r,
                            ngx_http_brix_webdav_loc_conf_t *conf,
                            char *dest_url, char *path,
                            ngx_array_t *headers)
{
    ngx_int_t rc;

    rc = webdav_tpc_post_thread_task(r, conf, 1, 0, 0, dest_url, path, NULL,
                                     headers, 1, NULL, NULL);
    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }
    if (rc != NGX_DONE) {
        brix_dashboard_http_error(r, "webdav TPC push task post failed");
        brix_dashboard_http_finish(r);
    }
    return (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : rc;
}

static ngx_int_t
webdav_tpc_push_sync_error(ngx_http_request_t *r, uint64_t transfer_id,
                           char *path, off_t expected_bytes, ngx_int_t rc)
{
    (void) brix_tpc_registry_update(transfer_id, 0, BRIX_TPC_STATE_ERROR,
                                    r->connection->log);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PUSH,
                             BRIX_TPC_METRIC_ERROR, 0, r->connection->log);
    (void) brix_tpc_registry_remove(transfer_id, r->connection->log);
    brix_dashboard_http_error(r, "webdav TPC push failed");
    brix_dashboard_http_finish(r);
    brix_xfer_finish(BRIX_XFER_TPC, "out", path, NULL, 0, BRIX_XFER_DST_ERR,
                     0, r->connection->log);
    webdav_tpc_note_client_copy_xfer(r, 0, (int64_t) expected_bytes);
    return rc;
}

/*
 * WHAT: Bundle of the shared state threaded through the file-local HTTP-TPC push
 *       exec helpers (currently the synchronous fallback tier).
 * WHY:  These helpers otherwise pass the same request/config/endpoint/header set
 *       through many positional parameters; collecting them into one stack-local
 *       context keeps each helper at =5 params and makes the shared data flow
 *       explicit without introducing any global state.
 * HOW:  Zero-initialised with ngx_memzero by the push handler, then populated
 *       with the exact values previously passed positionally and handed to each
 *       helper by pointer. Fields carry identical values and are read in the same
 *       order, so behaviour (curl PUT, credential headers, registry/dashboard
 *       ordering) is unchanged.
 */
typedef struct {
    ngx_http_request_t              *r;             /* current request */
    ngx_http_brix_webdav_loc_conf_t *conf;          /* location config */
    char                            *dest_url;      /* remote https destination */
    char                            *path;          /* local source path */
    ngx_array_t                     *headers;       /* outbound transfer headers */
    off_t                            expected_bytes;/* source size for accounting */
} webdav_tpc_push_ctx_t;

static ngx_int_t
webdav_tpc_push_sync_exec(webdav_tpc_push_ctx_t *px)
{
    ngx_http_request_t              *r = px->r;
    ngx_http_brix_webdav_loc_conf_t *conf = px->conf;
    char                            *dest_url = px->dest_url;
    char                            *path = px->path;
    ngx_array_t                     *headers = px->headers;
    off_t                            expected_bytes = px->expected_bytes;
    ngx_int_t rc;
    uint64_t transfer_id;

    transfer_id = webdav_tpc_register_transfer(r, BRIX_TPC_DIR_PUSH, path,
                                               dest_url, expected_bytes);
    if (transfer_id == 0) {
        brix_dashboard_http_error(r, "webdav TPC registry full");
        brix_dashboard_http_finish(r);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    rc = webdav_tpc_run_curl_push(r->connection->log, conf, dest_url, path,
                                  headers, transfer_id);
    if (rc != NGX_OK) {
        return webdav_tpc_push_sync_error(r, transfer_id, path, expected_bytes,
                                          rc);
    }

    (void) brix_tpc_registry_update(transfer_id, expected_bytes,
                                    BRIX_TPC_STATE_DONE, r->connection->log);
    brix_xfer_finish(BRIX_XFER_TPC, "out", path, NULL,
                     (size_t) expected_bytes, BRIX_XFER_OK, 0,
                     r->connection->log);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PUSH,
                             BRIX_TPC_METRIC_SUCCESS,
                             (size_t) expected_bytes, r->connection->log);
    (void) brix_tpc_registry_remove(transfer_id, r->connection->log);
    brix_dashboard_http_add(r, (ngx_atomic_int_t) expected_bytes);
    brix_dashboard_http_finish(r);
    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PUSH_SUCCESS]);
    webdav_tpc_note_client_copy_xfer(r, expected_bytes,
                                     (int64_t) expected_bytes);
    return webdav_send_no_body(r, NGX_HTTP_CREATED);
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
                       ngx_http_brix_webdav_loc_conf_t *conf,
                       ngx_table_elt_t *dest_hdr)
{
    ngx_array_t     *transfer_headers = NULL;
    char            *dest_url;
    char             path[WEBDAV_MAX_PATH];
    struct stat      sb;
    ngx_int_t        rc;
    ngx_str_t        src_scope;

    rc = webdav_tpc_push_dest_url(r, dest_hdr, &dest_url);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_tpc_collect_transfer_headers(r, &transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

    /*
     * Parse the Credential header. "none" (or absent) means no delegation.
     * "oidc-agent" or "token-exchange" triggers token acquisition for the
     * remote destination.
     */
    rc = webdav_tpc_push_apply_credential(r, conf, dest_url, transfer_headers);
    if (rc != NGX_OK) {
        return rc;
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

    (void) brix_dashboard_http_start_identity(r, path,
        webdav_dashboard_identity(r), "", BRIX_XFER_PROTO_WEBDAV,
        BRIX_XFER_DIR_TPC, "TPC_PUSH", (int64_t) sb.st_size);
    brix_dashboard_http_tpc_remote(r, dest_url, 0, 0);

    /* Forward Overwrite header if present.
     * WebDAV COPY uses Overwrite: F, but the outbound TPC push uses PUT.
     * PUT doesn't support Overwrite: F; it uses If-None-Match: *. */
    rc = webdav_tpc_push_forward_overwrite(r, transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PUSH_STARTED]);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PUSH,
                               BRIX_TPC_METRIC_STARTED, 0,
                               r->connection->log);

    /* Preferred path: hand the push off to the thread pool so the event loop is
     * never blocked on curl.  NGX_DECLINED means "no thread pool configured" and
     * we fall through to running curl synchronously below; NGX_DONE means the
     * task was queued (response finalized later); any other rc is terminal. */
    rc = webdav_tpc_push_post_thread(r, conf, dest_url, path,
                                     transfer_headers);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Synchronous fallback (blocks the worker for the duration of the push). */
    {
        webdav_tpc_push_ctx_t px;

        ngx_memzero(&px, sizeof(px));
        px.r              = r;
        px.conf           = conf;
        px.dest_url       = dest_url;
        px.path           = path;
        px.headers        = transfer_headers;
        px.expected_bytes = sb.st_size;
        return webdav_tpc_push_sync_exec(&px);
    }
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
    ngx_http_brix_webdav_loc_conf_t *conf, const char *source_url,
    ngx_array_t *transfer_headers)
{
    ngx_table_elt_t       *credential_hdr;
    brix_tpc_cred_mode_e mode;
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

    if (mode == BRIX_TPC_CRED_UNKNOWN) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_webdav: unsupported HTTP-TPC credential "
                      "delegation mode \"%V\"", &credential_hdr->value);
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
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

static ngx_int_t
webdav_tpc_validate_copy_headers(ngx_table_elt_t *source_hdr,
    ngx_table_elt_t *dest_hdr)
{
    if ((source_hdr == NULL && dest_hdr == NULL)
        || (source_hdr != NULL && dest_hdr != NULL))
    {
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }
    return NGX_OK;
}

static ngx_uint_t
webdav_tpc_parse_stream_count(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf)
{
    ngx_table_elt_t *streams_hdr;
    ngx_uint_t       n_streams = 1;

    streams_hdr = webdav_tpc_find_header(r, "X-Number-Of-Streams",
                                         sizeof("X-Number-Of-Streams") - 1);
    if (streams_hdr != NULL && streams_hdr->value.len > 0) {
        ngx_int_t v = ngx_atoi(streams_hdr->value.data, streams_hdr->value.len);
        if (v > 1) {
            n_streams = (ngx_uint_t) v;
        }
    }
    if (n_streams > conf->tpc_max_streams && conf->tpc_max_streams > 0) {
        n_streams = conf->tpc_max_streams;
    }
    return n_streams;
}

static ngx_int_t
webdav_tpc_source_url(ngx_http_request_t *r, ngx_table_elt_t *source_hdr,
    char **source_url)
{
    if (source_hdr->value.len < sizeof("https://") - 1
        || ngx_strncasecmp(source_hdr->value.data, (u_char *) "https://",
                           sizeof("https://") - 1) != 0
        || webdav_tpc_str_has_ctl(source_hdr->value.data,
                                  source_hdr->value.len))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "brix_webdav: HTTP-TPC Source must be an https URL");
        BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
        return NGX_HTTP_BAD_REQUEST;
    }

    *source_url = webdav_tpc_pstrndup0(r->pool, source_hdr->value.data,
                                       source_hdr->value.len);
    return (*source_url == NULL) ? NGX_HTTP_INTERNAL_SERVER_ERROR : NGX_OK;
}

static ngx_int_t
webdav_tpc_parse_overwrite(ngx_http_request_t *r, ngx_flag_t *overwrite)
{
    ngx_table_elt_t *overwrite_hdr;

    overwrite_hdr = webdav_tpc_find_header(r, "Overwrite",
                                           sizeof("Overwrite") - 1);
    *overwrite = 1;
    if (overwrite_hdr == NULL) {
        return NGX_OK;
    }
    if (webdav_tpc_header_value_equals(&overwrite_hdr->value, "F")) {
        *overwrite = 0;
        return NGX_OK;
    }
    if (webdav_tpc_header_value_equals(&overwrite_hdr->value, "T")) {
        *overwrite = 1;
        return NGX_OK;
    }
    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
    return NGX_HTTP_BAD_REQUEST;
}

/*
 * WHAT: Bundle of the shared state threaded through the file-local HTTP-TPC pull
 *       exec helpers (target preparation, the three transfer tiers, commit and
 *       success finalisation).
 * WHY:  Each pull helper otherwise repeated the same long positional parameter
 *       list (request, config, source URL, staged temp file, transfer headers,
 *       stream count and the overwrite/existed flags). Collecting them into one
 *       stack-local context keeps every helper at =5 params and makes the shared
 *       pull state explicit without any global state.
 * HOW:  Zero-initialised with ngx_memzero by ngx_http_brix_webdav_tpc_handle_copy,
 *       populated once with the exact values previously passed positionally, then
 *       handed to each helper by pointer. `path`/`path_len`/`sb`/`staged` alias
 *       the caller's own stack storage (unchanged addresses); `transfer_id` is
 *       produced by the sync tier and consumed by commit/finish. Field values and
 *       read order are identical, so the pull semantics (probe, authorize, staged
 *       open, marker/thread/sync tiers, link-vs-rename commit, registry/dashboard
 *       ordering) are unchanged.
 */
typedef struct {
    ngx_http_request_t              *r;             /* current request */
    ngx_http_brix_webdav_loc_conf_t *conf;          /* location config */
    const char                      *source_url;    /* remote https source */
    char                            *path;          /* confined local target path */
    size_t                           path_len;      /* capacity of `path` */
    struct stat                     *sb;            /* target stat (existence/size) */
    ngx_array_t                     *transfer_headers; /* outbound curl headers */
    brix_staged_file_t              *staged;        /* atomic-commit temp file */
    const char                      *user_cert;     /* per-user pull-leg cert (or NULL) */
    const char                      *user_key;      /* per-user pull-leg key  (or NULL) */
    uint64_t                         transfer_id;   /* registry id (sync tier) */
    ngx_uint_t                       n_streams;     /* negotiated parallel streams */
    ngx_flag_t                       overwrite;     /* Overwrite: T/F policy */
    ngx_flag_t                       existed;       /* target pre-existed */
} webdav_tpc_pull_ctx_t;

static ngx_int_t
webdav_tpc_prepare_pull_target(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *source_url = pl->source_url;
    ngx_flag_t                       overwrite = pl->overwrite;
    char                            *path = pl->path;
    size_t                           path_len = pl->path_len;
    struct stat                     *sb = pl->sb;
    brix_staged_file_t              *staged = pl->staged;
    ngx_int_t rc;
    ngx_str_t src_scope;
    ngx_str_t dst_scope;

    rc = ngx_http_brix_webdav_resolve_path(r, conf->common.root_canon, path,
                                           path_len);
    if (rc != NGX_OK) {
        return rc;
    }

    pl->existed = (webdav_tpc_probe(r, conf, path, sb) == NGX_OK) ? 1 : 0;
    if (pl->existed && S_ISDIR(sb->st_mode)) {
        return NGX_HTTP_CONFLICT;
    }
    if (pl->existed && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    webdav_tpc_url_path(source_url, &src_scope);
    dst_scope = r->uri;
    rc = webdav_tpc_authorize(r, &src_scope, &dst_scope);
    if (rc != NGX_OK) {
        return rc;
    }

    {
        brix_staged_open_req_t  oreq = {
            .root_canon = conf->common.root_canon,
            .final_path = path,
            .open_flags = O_WRONLY,
            .mode       = 0600,
            .attempts   = 16,
        };
        if (brix_staged_open(r->connection->log, &oreq, staged) != NGX_OK) {
            return errno == ENAMETOOLONG ? NGX_HTTP_REQUEST_URI_TOO_LARGE
                                         : NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    ngx_close_file(staged->fd);
    staged->fd = NGX_INVALID_FILE;
    return NGX_OK;
}

static void
webdav_tpc_pull_start_accounting(ngx_http_request_t *r, const char *path,
    const char *source_url)
{
    (void) brix_dashboard_http_start_identity(r, path,
        webdav_dashboard_identity(r), "", BRIX_XFER_PROTO_WEBDAV,
        BRIX_XFER_DIR_TPC, "TPC_PULL", -1);
    brix_dashboard_http_tpc_remote(r, source_url, 0, 0);
    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PULL_STARTED]);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                             BRIX_TPC_METRIC_STARTED, 0, r->connection->log);
}

static ngx_int_t
webdav_tpc_pull_marker_exec(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *source_url = pl->source_url;
    const char                      *path = pl->path;
    brix_staged_file_t              *staged = pl->staged;
    ngx_array_t                     *transfer_headers = pl->transfer_headers;
    ngx_uint_t                       n_streams = pl->n_streams;
    ngx_flag_t                       overwrite = pl->overwrite;
    ngx_flag_t                       existed = pl->existed;
    ngx_int_t rc;
    uint64_t  transfer_id;

    if (conf->tpc_marker_interval <= 0) {
        return NGX_DECLINED;
    }
    transfer_id = webdav_tpc_register_transfer(r, BRIX_TPC_DIR_PULL,
                                               source_url, path, 0);
    if (transfer_id == 0) {
        brix_dashboard_http_error(r, "webdav TPC registry full");
        brix_dashboard_http_finish(r);
        brix_staged_abort(r->connection->log, conf->common.root_canon,
                          staged, 1);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }
    rc = webdav_tpc_marker_start(r, conf, n_streams, source_url,
                                 staged->tmp_path, path, 1, overwrite, existed,
                                 transfer_headers, transfer_id,
                                 pl->user_cert, pl->user_key);
    if (rc == NGX_DECLINED) {
        (void) brix_tpc_registry_remove(transfer_id, r->connection->log);
        return NGX_DECLINED;
    }
    if (rc != NGX_DONE) {
        (void) brix_tpc_registry_remove(transfer_id, r->connection->log);
        brix_dashboard_http_error(r, "webdav TPC marker start failed");
        brix_dashboard_http_finish(r);
        brix_staged_abort(r->connection->log, conf->common.root_canon,
                          staged, 1);
        return (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : rc;
    }
    return NGX_DONE;
}

static ngx_int_t
webdav_tpc_pull_thread_exec(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *source_url = pl->source_url;
    const char                      *path = pl->path;
    brix_staged_file_t              *staged = pl->staged;
    ngx_array_t                     *transfer_headers = pl->transfer_headers;
    ngx_uint_t                       n_streams = pl->n_streams;
    ngx_flag_t                       overwrite = pl->overwrite;
    ngx_flag_t                       existed = pl->existed;
    ngx_int_t rc = webdav_tpc_post_thread_task(r, conf, 0, existed, overwrite,
                                               source_url, staged->tmp_path,
                                               path, transfer_headers,
                                               n_streams, pl->user_cert,
                                               pl->user_key);
    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }
    if (rc != NGX_DONE) {
        brix_dashboard_http_error(r, "webdav TPC pull task post failed");
        brix_dashboard_http_finish(r);
        brix_staged_abort(r->connection->log, conf->common.root_canon,
                          staged, 1);
        return (rc == NGX_ERROR) ? NGX_HTTP_INTERNAL_SERVER_ERROR : rc;
    }
    return NGX_DONE;
}

static ngx_int_t
webdav_tpc_pull_sync_exec(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *source_url = pl->source_url;
    const char                      *path = pl->path;
    brix_staged_file_t              *staged = pl->staged;
    ngx_array_t                     *transfer_headers = pl->transfer_headers;
    ngx_int_t rc;

    pl->transfer_id = webdav_tpc_register_transfer(r, BRIX_TPC_DIR_PULL,
                                                   source_url, path, 0);
    if (pl->transfer_id == 0) {
        brix_dashboard_http_error(r, "webdav TPC registry full");
        brix_dashboard_http_finish(r);
        brix_staged_abort(r->connection->log, conf->common.root_canon,
                          staged, 1);
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }

    rc = webdav_tpc_run_curl_pull(r->connection->log, conf, source_url,
                                  staged->tmp_path, transfer_headers,
                                  pl->transfer_id, pl->user_cert, pl->user_key);
    if (rc == NGX_OK) {
        return NGX_OK;
    }
    (void) brix_tpc_registry_update(pl->transfer_id, 0, BRIX_TPC_STATE_ERROR,
                                    r->connection->log);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                             BRIX_TPC_METRIC_ERROR, 0, r->connection->log);
    (void) brix_tpc_registry_remove(pl->transfer_id, r->connection->log);
    brix_dashboard_http_error(r, "webdav TPC pull failed");
    brix_dashboard_http_finish(r);
    brix_staged_abort(r->connection->log, conf->common.root_canon, staged, 1);
    brix_xfer_finish(BRIX_XFER_TPC, "in", path, NULL, 0,
                     BRIX_XFER_SRC_ERR, 0, r->connection->log);
    webdav_tpc_note_client_copy_xfer(r, 0, -1);
    return rc;
}

static ngx_int_t
webdav_tpc_commit_pulled_file(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *path = pl->path;
    brix_staged_file_t              *staged = pl->staged;
    uint64_t                         transfer_id = pl->transfer_id;
    ngx_flag_t                       overwrite = pl->overwrite;
    ngx_int_t status;

    if (!overwrite) {
        if (brix_link_confined_canon(r->connection->log, conf->common.root_canon,
                                     staged->tmp_path, path) == 0)
        {
            brix_staged_abort(r->connection->log, conf->common.root_canon,
                              staged, 1);
            return NGX_OK;
        }
        status = (errno == EEXIST) ? NGX_HTTP_PRECONDITION_FAILED
                                   : NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else if (brix_staged_commit(r->connection->log, conf->common.root_canon,
                                  staged, path) == NGX_OK) {
        return NGX_OK;
    } else {
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                           "brix_webdav: HTTP-TPC rename failed for: \"%s\"",
                           path);
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_COMMIT_ERROR]);
    brix_dashboard_http_error(r, "webdav TPC pull commit failed");
    brix_dashboard_http_finish(r);
    brix_staged_abort(r->connection->log, conf->common.root_canon, staged, 1);
    (void) brix_tpc_registry_update(transfer_id, 0, BRIX_TPC_STATE_ERROR,
                                    r->connection->log);
    brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                             BRIX_TPC_METRIC_ERROR, 0, r->connection->log);
    (void) brix_tpc_registry_remove(transfer_id, r->connection->log);
    return status;
}

static ngx_int_t
webdav_tpc_finish_pull_success(webdav_tpc_pull_ctx_t *pl)
{
    ngx_http_request_t              *r = pl->r;
    ngx_http_brix_webdav_loc_conf_t *conf = pl->conf;
    const char                      *path = pl->path;
    struct stat                     *sb = pl->sb;
    uint64_t                         transfer_id = pl->transfer_id;
    ngx_flag_t                       existed = pl->existed;
    off_t completed_bytes = 0;

    if (webdav_tpc_probe(r, conf, path, sb) == NGX_OK) {
        completed_bytes = sb->st_size;
        brix_dashboard_http_add(r, (ngx_atomic_int_t) sb->st_size);
        (void) brix_tpc_registry_update(transfer_id, sb->st_size,
                                        BRIX_TPC_STATE_DONE,
                                        r->connection->log);
        brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                                 BRIX_TPC_METRIC_SUCCESS, (size_t) sb->st_size,
                                 r->connection->log);
    } else {
        (void) brix_tpc_registry_update(transfer_id, 0, BRIX_TPC_STATE_DONE,
                                        r->connection->log);
        brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, BRIX_TPC_DIR_PULL,
                                 BRIX_TPC_METRIC_SUCCESS, 0,
                                 r->connection->log);
    }
    (void) brix_tpc_registry_remove(transfer_id, r->connection->log);
    brix_dashboard_http_finish(r);
    BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_PULL_SUCCESS]);
    brix_xfer_finish(BRIX_XFER_TPC, "in", path, NULL, (size_t) completed_bytes,
                     BRIX_XFER_OK, 0, r->connection->log);
    webdav_tpc_note_client_copy_xfer(r, completed_bytes,
        completed_bytes > 0 ? (int64_t) completed_bytes : -1);
    return webdav_send_no_body(r, existed ? NGX_HTTP_NO_CONTENT
                                          : NGX_HTTP_CREATED);
}

/*
 * webdav_tpc_transfer_headers_have_authorization — does the outbound header set
 * already carry an Authorization entry?
 *
 * WHAT: scans the collected "Name: value" transfer-header strings for one whose
 *       name (up to the ':') is "Authorization", case-insensitively.
 * WHY:  the opportunistic default bearer-forward must never override a bearer the
 *       client explicitly delegated — an explicit TransferHeaderAuthorization, or
 *       a Credential-mode token-exchange result, already sits in this array and
 *       must win over the requesting user's ambient token.
 * HOW:  matches the fixed prefix "authorization:"; returns 1 on the first hit,
 *       0 when none is present (or the array is empty/NULL).
 */
static int
webdav_tpc_transfer_headers_have_authorization(const ngx_array_t *headers)
{
    static const u_char  name[] = "authorization";
    const size_t         name_len = sizeof(name) - 1;
    const ngx_str_t     *elts;
    ngx_uint_t           i;

    if (headers == NULL) {
        return 0;
    }

    elts = headers->elts;
    for (i = 0; i < headers->nelts; i++) {
        if (elts[i].len > name_len
            && elts[i].data[name_len] == ':'
            && ngx_strncasecmp(elts[i].data, (u_char *) name, name_len) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/*
 * webdav_tpc_forward_user_bearer — opportunistic default: present the requesting
 * user's own captured bearer token to the pull source.
 *
 * WHAT: when credential forwarding is enabled (the default) and the outbound
 *       header set does not already carry an Authorization entry, appends the raw
 *       JWT the request authenticated with (rctx->bearer_token) as an
 *       "Authorization: Bearer <token>" transfer header.
 * WHY:  a TPC pull should act as the END USER against the source by default —
 *       this is the HTTP equivalent of the native root:// bearer passthrough. It
 *       is OPPORTUNISTIC: the absence of a captured token is not an error (the leg
 *       falls back to the service x509 cert / anonymous exactly as before), and a
 *       client-supplied Authorization is never overridden.
 * HOW:  no-ops (NGX_OK) when the toggle is off, no rctx/token is present, or an
 *       Authorization header already exists; otherwise reuses
 *       webdav_tpc_add_bearer_header. Returns its NGX_HTTP_* only on an allocation
 *       failure — never a denial.
 */
static ngx_int_t
webdav_tpc_forward_user_bearer(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_array_t *transfer_headers)
{
    ngx_http_brix_webdav_req_ctx_t *rctx;

    if (!conf->tpc_credential_forward) {
        return NGX_OK;
    }

    rctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (rctx == NULL || rctx->bearer_token.len == 0
        || rctx->bearer_token.data == NULL)
    {
        return NGX_OK;
    }

    if (webdav_tpc_transfer_headers_have_authorization(transfer_headers)) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "brix_webdav: TPC pull forwarding requesting user's bearer"
                  " token to source (opportunistic default)");
    return webdav_tpc_add_bearer_header(r, transfer_headers,
                                        &rctx->bearer_token);
}

ngx_int_t
ngx_http_brix_webdav_tpc_handle_copy(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    ngx_table_elt_t *source_hdr;
    ngx_table_elt_t *dest_hdr;
    ngx_array_t     *transfer_headers = NULL;
    char            *source_url;
    char             path[WEBDAV_MAX_PATH];
    struct stat      sb;
    ngx_int_t        rc;
    ngx_flag_t       overwrite;
    brix_staged_file_t staged;
    ngx_uint_t       n_streams;
    webdav_tpc_pull_ctx_t pl;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    source_hdr = webdav_tpc_find_header(r, "Source", sizeof("Source") - 1);
    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);

    rc = webdav_tpc_validate_copy_headers(source_hdr, dest_hdr);
    if (rc != NGX_OK) {
        return rc;
    }

    /* X-Number-Of-Streams: N — negotiate parallel pull streams.
     * Capped at tpc_max_streams (default 1; multi-stream disabled unless
     * brix_webdav_tpc_max_streams is set to > 1 in the config). */
    n_streams = webdav_tpc_parse_stream_count(r, conf);

    if (source_hdr == NULL) {
        /* Push mode: Destination present, no Source. */
        return webdav_tpc_handle_push(r, conf, dest_hdr);
    }

    rc = webdav_tpc_source_url(r, source_hdr, &source_url);
    if (rc != NGX_OK) {
        return rc;
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

    /* Opportunistic default: when the client did not explicitly delegate a
     * bearer (via TransferHeaderAuthorization or Credential: token-exchange),
     * forward the requesting user's own captured token to the source so the
     * pull acts as the END USER.  A no-op when forwarding is off or no token is
     * present — never a new denial. */
    rc = webdav_tpc_forward_user_bearer(r, conf, transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_tpc_parse_overwrite(r, &overwrite);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&pl, sizeof(pl));

    /* Present the requesting user's delegated x509 proxy to the source (so the
     * source authenticates the END USER, not our service cert) when one is
     * available; otherwise fall back to conf->tpc_cert.  This per-user forwarding
     * is the default (brix_webdav_tpc_credential_forward on) and is independent of
     * brix_backend_delegation, which governs the data-plane backend leg.
     * OPPORTUNISTIC: absence of any per-user proxy leaves pl.user_cert NULL so the
     * leg falls back to the static service cert exactly as before; only an
     * explicit delegated proxy we could not materialise (up.deny) aborts, never
     * silently downgrading to the service identity.  Forwarding off = service-cert
     * only. */
    if (conf->tpc_credential_forward) {
        webdav_tpc_user_proxy_t up;

        webdav_tpc_user_proxy_resolve(r, conf, &up);
        if (up.deny) {
            BRIX_WEBDAV_METRIC_INC(tpc_total[BRIX_WEBDAV_TPC_BAD_REQUEST]);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        pl.user_cert = up.have ? up.cert_path : NULL;
        pl.user_key  = up.have ? up.key_path  : NULL;
    }
    pl.r                = r;
    pl.conf             = conf;
    pl.source_url       = source_url;
    pl.path             = path;
    pl.path_len         = sizeof(path);
    pl.sb               = &sb;
    pl.transfer_headers = transfer_headers;
    pl.staged           = &staged;
    pl.n_streams        = n_streams;
    pl.overwrite        = overwrite;

    rc = webdav_tpc_prepare_pull_target(&pl);
    if (rc != NGX_OK) {
        return rc;
    }

    webdav_tpc_pull_start_accounting(r, path, source_url);

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
    rc = webdav_tpc_pull_marker_exec(&pl);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Tier 2: offload to the thread pool (NGX_DECLINED -> synchronous tier 3). */
    rc = webdav_tpc_pull_thread_exec(&pl);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    /* Tier 3: run curl synchronously on the worker. */
    rc = webdav_tpc_pull_sync_exec(&pl);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Commit the staged temp file. Two strategies by overwrite policy:
     *  - no-overwrite (Overwrite: F): link() the temp into place, which fails
     *    with EEXIST if a file appeared meanwhile -> 412 (atomic create-only).
     *  - overwrite: rename() the temp over any existing file.
     * Either way the temp is removed afterward (link leaves the temp; rename
     * consumes it), and any failure aborts/cleans up and records an error. */
    rc = webdav_tpc_commit_pulled_file(&pl);
    if (rc != NGX_OK) {
        return rc;
    }

    return webdav_tpc_finish_pull_success(&pl);
}
