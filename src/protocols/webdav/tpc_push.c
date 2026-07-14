/*
 * tpc_push.c - HTTP-TPC COPY push handler for the WebDAV module.
 *
 * WHAT: Implements the push direction of HTTP-TPC (Third-Party Copy): read a
 *       local export file and PUT it to a remote HTTPS Destination. Owns the
 *       Destination-URL validation, the OAuth2/OIDC Credential delegation and
 *       Overwrite forwarding for the outbound leg, and the thread-pool /
 *       synchronous-curl execution tiers.
 * WHY:  Split from tpc.c (which was over the 500-line cap) so the push concern
 *       is grouped and individually reviewable, separate from the COPY dispatcher,
 *       the request parsing, and the staged pull execution.
 * HOW:  webdav_tpc_handle_push (the sole cross-file entry, declared in
 *       tpc_internal_split.h) validates the destination, collects transfer
 *       headers, applies credential delegation, stats the source, authorizes,
 *       forwards Overwrite, then hands off to the thread pool, falling back to the
 *       synchronous exec. The shared request helpers (authorize, register,
 *       subject-token extract, bearer append, session-xfer note, dashboard
 *       identity) live in tpc.c and are reached through the split header.
 */

#include "tpc_internal_split.h"

#include "webdav.h"
#include "tpc_user_proxy.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"
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
ngx_int_t
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
