/*
 * tpc.c - HTTP-TPC COPY dispatcher and shared request helpers for the WebDAV
 * module.
 *
 * WHAT: Owns the COPY dispatcher (ngx_http_brix_webdav_tpc_handle_copy) that
 *       routes a request to the pull or push direction, plus the small request
 *       helpers shared across the TPC files: the dashboard display identity, the
 *       session-xfer note, the authorization gate, the live-transfer registry
 *       add, the OAuth2 subject-token extract, and the Authorization: Bearer
 *       header append.
 * WHY:  This file was one 1324-line module — far over the 500-line cap. The
 *       phase-79 split moves the push handler to tpc_push.c, the COPY request
 *       parsing + credential/user-proxy helpers to tpc_copy.c, and the staged
 *       pull execution to tpc_pull.c. The dispatcher and the helpers that every
 *       direction shares stay here; the cross-file entry points are declared in
 *       tpc_internal_split.h.
 * HOW:  The dispatcher parses the pull-xor-push headers, delegates push to
 *       tpc_push.c, and for a pull collects/credential-decorates the transfer
 *       headers (tpc_copy.c), prepares the staged target and runs the tiered pull
 *       (tpc_pull.c). Every helper here is a small side-effect-honest primitive
 *       reused by those files. No behaviour change from the split.
 */

#include "tpc_internal_split.h"

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

/* Display identity for the live-transfer dashboard: the authenticated DN, or
 * "anonymous" when the request carried no usable identity. */
const char *
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

void
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
 * Authorize a TPC against the request identity: src_path is the read scope,
 * dst_path the write scope (NULL when the operation only reads, i.e. push).
 * Returns NGX_OK if permitted, else NGX_HTTP_FORBIDDEN (and bumps the bad-request
 * metric).  This is the access-control gate before any data movement starts.
 */
ngx_int_t
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
uint64_t
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
ngx_int_t
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

ngx_int_t
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

    /* X-Number-Of-Streams: N — capped at tpc_max_streams (default 1; multi-stream
     * disabled unless brix_webdav_tpc_max_streams > 1 in the config). */
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

    /* Opportunistic default: absent an explicit client delegation, forward the
     * requesting user's own captured token so the pull acts as the END USER.
     * A no-op when forwarding is off or no token is present — never a denial. */
    rc = webdav_tpc_forward_user_bearer(r, conf, transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_tpc_parse_overwrite(r, &overwrite);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&pl, sizeof(pl));

    /* Present the requesting user's delegated x509 proxy to the source (END USER
     * identity, not our service cert) when available; otherwise fall back to
     * conf->tpc_cert. See webdav_tpc_apply_user_proxy for the full contract. */
    rc = webdav_tpc_apply_user_proxy(r, conf, &pl);
    if (rc != NGX_OK) {
        return rc;
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

    /* Run the staged pull across the three execution tiers (marker/thread/sync),
     * then commit and finalise. The staged temp file is aborted (unlinked) on
     * every error exit so a failed pull never leaves a partial file behind. */
    return webdav_tpc_pull_execute(&pl);
}
