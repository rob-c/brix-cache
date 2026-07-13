/*
 * put_finalize.c - extracted concern
 * Phase-38 split of put.c; behavior-identical.
 */
#include "s3_put_internal.h"
#include "fs/xfer/xfer.h"   /* unified transfer audit ledger (S3 PUT = STAGE) */

#include <sys/stat.h>



/*
 * s3_commit_put — W6b: commit the staged temp file to its final path, honouring
 * an exclusive (create-if-absent) PutObject.  When the request carried
 * `If-None-Match: *` the commit uses renameat2(RENAME_NOREPLACE); otherwise the
 * plain rename.  Returns NGX_OK; or NGX_ERROR with ngx_errno preserved (EEXIST
 * when an exclusive create lost the race — the caller maps that to 412).  Runs
 * on the event loop (all three PUT commit sites do), so the request ctx is live.
 */
ngx_int_t
s3_commit_put(ngx_http_request_t *r, ngx_log_t *log, const char *root_canon,
    brix_vfs_staged_t *staged, const char *final_path)
{
    ngx_http_s3_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    size_t      bytes;
    ngx_int_t   rc;
    int         e;

    (void) root_canon;   /* the staged handle carries its own final/tmp paths */
    /* Publish through the VFS staged surface (routes through sd_stage when a stage
     * store is composed; a local temp+rename otherwise) — §6.5/G9 unified staging. */
    rc = brix_vfs_staged_commit(staged,
             (rx != NULL && rx->exclusive_create) ? 1 : 0);

    /* Unified ledger: S3 PutObject (chunked / aio path) is a STAGE publish — the
     * same audit line as S3 POST, WebDAV PUT, and root:// uploads. The staged fd
     * is already closed by the body handler before commit, so the committed
     * object's size comes from a confined stat of the published path. */
    if (rc == NGX_OK) {
        brix_vfs_ctx_t  fctx;
        brix_vfs_stat_t fst;

        brix_vfs_ctx_init(&fctx, r->pool, log, BRIX_PROTO_S3, root_canon,
            NULL, 0 /* allow_write */, 0 /* is_tls */, NULL, final_path);
        {
            ngx_http_s3_loc_conf_t *acf =
                ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
            if (acf != NULL) {
                /* Decorates a probe/stat-only ctx; Phase-2-forward — namespace
                 * scoping already routes the credential via the VFS ns gate. */
                brix_vfs_ctx_bind_backend_cred(&fctx,
                    &acf->common.storage_credential_dir,
                    acf->common.storage_credential_fallback);
                s3_vfs_bind_deleg(r, acf, &fctx);
            }
        }
        bytes = (brix_vfs_probe(&fctx, 1 /* no-follow */, &fst) == NGX_OK
                 && fst.is_regular) ? (size_t) fst.size : 0;
        brix_xfer_finish(BRIX_XFER_STAGE, "in", final_path, NULL, bytes,
                           BRIX_XFER_OK, 0, log);
    } else {
        e = errno;
        brix_xfer_finish(BRIX_XFER_STAGE, "in", final_path, NULL, 0,
                           BRIX_XFER_COMMIT_ERR, e, log);
        errno = e;   /* preserve EEXIST → 412 for the caller */
    }
    return rc;
}


/*
 * s3_put_commit_conflict — after s3_commit_put() returned NGX_ERROR, send the
 * 412 PreconditionFailed for an exclusive create that lost the race and return
 * 1; return 0 when the failure was something else (caller handles as 500).
 */
int
s3_put_commit_conflict(ngx_http_request_t *r)
{
    if (ngx_errno != EEXIST) {
        return 0;
    }
    s3_put_finalize_client_error(r, NGX_HTTP_PRECONDITION_FAILED,
        "PreconditionFailed",
        "At least one of the preconditions you specified did not hold "
        "(If-None-Match).");
    return 1;
}

/*
 * s3_put_finalize_error — send 500 and increment internal-error metric.
 *
 * Called from any failure path inside the handler. The response is final;
 * this function does not return NGX_DONE (the caller already incremented
 * r->main->count via ngx_http_read_client_request_body).
 */

void
s3_put_finalize_error(ngx_http_request_t *r)
{
    brix_dashboard_http_error(r, "s3 write failed");
    brix_dashboard_http_finish(r);
    BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]);
    s3_metrics_finalize_request_method(r, BRIX_S3_METHOD_PUT,
                                       NGX_HTTP_INTERNAL_SERVER_ERROR);
}


/*
 * s3_put_finalize_fs_error — finalize a PUT that failed at a filesystem op,
 * mapping the captured errno to the correct HTTP status instead of a blanket 500.
 *
 * WHAT: A cross-tenant / DAC-denied create (e.g. alice PUT into bob's 0755 dir →
 *       EACCES on the staged temp create) is a forbidden request, not a server
 *       fault.  Route the captured errno through brix_http_errno_to_status()
 *       (the same map S3 GET/CopyObject already use): EACCES/EPERM/EXDEV/ELOOP →
 *       403 AccessDenied, ENOENT/ENOTDIR → 404 NoSuchKey, ENOSPC → 507, etc.
 *       Any errno that maps to 5xx falls back to the existing internal-error path.
 * WHY:  A genuine permission denial must surface as 403 (clean 4xx contract), not
 *       HTTP 500 — a 500 misreports a bounded, well-formed request as an internal
 *       error and is the robustness defect the impersonation red-team flagged.
 * HOW:  The caller MUST capture errno into saved_errno BEFORE any intervening
 *       syscall (logging, staged_abort) clobbers it, then pass it here.
 */
void
s3_put_finalize_fs_error(ngx_http_request_t *r, int saved_errno)
{
    int         status;
    const char *code;
    const char *message;

    status = (int) brix_http_errno_to_status(saved_errno);

    /* errno that has no clean 4xx contract (e.g. EIO) keeps the 500 path. */
    if (status >= 500) {
        s3_put_finalize_error(r);
        return;
    }

    switch (status) {
    case 403:
        code = "AccessDenied";
        message = "Access Denied.";
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_ACCESS_DENIED]);
        break;
    case 404:
        code = "NoSuchKey";
        message = "The specified key does not exist.";
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_NO_SUCH_KEY]);
        break;
    case 409:
        code = "BucketAlreadyExists";
        message = "The requested resource already exists.";
        break;
    case 414:
        code = "KeyTooLongError";
        message = "Your key is too long.";
        break;
    default:
        code = "InvalidRequest";
        message = "The request could not be completed.";
        break;
    }

    brix_dashboard_http_error(r, message);
    brix_dashboard_http_finish(r);
    (void) s3_send_xml_error(r, (ngx_uint_t) status, code, message);
    s3_metrics_finalize_request_method(r, BRIX_S3_METHOD_PUT,
                                       (ngx_int_t) status);
}


void
s3_put_finalize_empty_ok(ngx_http_request_t *r)
{
    ngx_int_t rc;

    /*
     * S3 PutObject succeeds with 200 + an ETag header.  A PUT response must
     * NEVER be reinterpreted as a conditional-GET result: when the client sends
     * If-None-Match / If-Modified-Since, nginx core's not-modified filter would
     * otherwise rewrite this 200 into a 304 Not Modified (304 is a GET/HEAD-only
     * status — RFC 9110 §15.4.5).  The object is written either way, but the
     * status would be wrong and could break S3 SDKs that set conditional headers
     * by default.  Disable the not-modified filter for this response.
     */
    r->disable_not_modified          = 1;
    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);

    rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    brix_dashboard_http_finish(r);
    s3_metrics_finalize_request_method(r, BRIX_S3_METHOD_PUT, rc);
}


void
s3_put_finalize_ok(ngx_http_request_t *r, size_t body_bytes,
    ngx_uint_t body_mode)
{
    brix_dashboard_http_add(r, (ngx_atomic_int_t) body_bytes);
    BRIX_S3_METRIC_ADD(bytes_rx_total, body_bytes);
    if (r->connection && r->connection->sockaddr
        && r->connection->sockaddr->sa_family == AF_INET6) {
        BRIX_S3_METRIC_ADD(bytes_rx_ipv6_total, body_bytes);
    } else {
        BRIX_S3_METRIC_ADD(bytes_rx_ipv4_total, body_bytes);
    }
    BRIX_S3_METRIC_INC(put_body_total[body_mode]);
    s3_put_finalize_empty_ok(r);
}


/*
 * s3_put_finalize_bad_digest — reject a PUT whose client checksum mismatched.
 * The object was already removed by s3_put_checksum_apply; send 400 BadDigest
 * and finalize the dashboard/metrics for the request.
 */
void
s3_put_finalize_bad_digest(ngx_http_request_t *r)
{
    brix_dashboard_http_error(r, "s3 checksum mismatch");
    brix_dashboard_http_finish(r);
    (void) s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "BadDigest",
        "The checksum you specified did not match what was received.");
    s3_metrics_finalize_request_method(r, BRIX_S3_METHOD_PUT,
                                       NGX_HTTP_BAD_REQUEST);
}


/*
 * s3_put_finalize_invalid_request — reject a PUT whose checksum selection was
 * ambiguous or named an unsupported algorithm (the object was already removed
 * by s3_put_checksum_apply); send 400 InvalidRequest.
 */
void
s3_put_finalize_invalid_request(ngx_http_request_t *r)
{
    brix_dashboard_http_error(r, "s3 invalid checksum request");
    brix_dashboard_http_finish(r);
    (void) s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "InvalidRequest",
        "The checksum algorithm selection is invalid or ambiguous.");
    s3_metrics_finalize_request_method(r, BRIX_S3_METHOD_PUT,
                                       NGX_HTTP_BAD_REQUEST);
}


/*
 * s3_put_finalize_codec_error — reject a PUT whose Content-Encoding could not be
 * decoded (phase-42 W1).  Maps the decoder's HTTP status to a clean S3 XML error
 * instead of a blanket 500: a bomb-guard trip → 413 EntityTooLarge, an
 * unsupported/disabled codec or a malformed/truncated stream → 400 InvalidRequest.
 * The staged object has already been aborted by the caller, so no partial bytes
 * are ever stored.  A genuine I/O/internal failure stays a 500 (caller routes it
 * to s3_put_finalize_error instead).
 */
void
s3_put_finalize_codec_error(ngx_http_request_t *r, ngx_int_t status)
{
    const char *code = "InvalidRequest";
    const char *msg  = "The request body could not be decoded with the "
                       "requested Content-Encoding.";

    if (status == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE) {
        code = "EntityTooLarge";
        msg  = "The decompressed body exceeds the maximum allowed size.";
    }
    brix_dashboard_http_error(r, "s3 content-encoding decode failed");
    brix_dashboard_http_finish(r);
    (void) s3_send_xml_error(r, status, code, msg);
    s3_metrics_finalize_request_method(r, BRIX_S3_METHOD_PUT, status);
}


/*
 * s3_put_checksum_failed — verify+echo the client's full-object checksum and, on
 * a terminal failure, send the corresponding 400 response.
 *
 * Returns 1 when a failure response was already sent (the caller must stop), or
 * 0 to proceed with the success finalize.  A compute error (S3_CKSUM_ERROR) is
 * non-fatal — the object stands, just without an echoed checksum header.
 */
int
s3_put_checksum_failed(ngx_http_request_t *r, const char *fs_path,
    const char *root_canon)
{
    switch (s3_put_checksum_apply(r, fs_path, root_canon)) {
    case S3_CKSUM_MISMATCH:
        s3_put_finalize_bad_digest(r);
        return 1;
    case S3_CKSUM_CONFLICT:
        s3_put_finalize_invalid_request(r);
        return 1;
    default:
        return 0;   /* S3_CKSUM_OK or S3_CKSUM_ERROR — proceed */
    }
}


/*
 * s3_put_finalize_ok — send 200 with ETag header and update metrics.
 *
 * Parameters:
 *   body_bytes   — total bytes written from the client request body
 *   body_mode    — classification enum (BRIX_S3_PUT_*), used as metric index
 *
 * Flow:
 *   1. Increment bytes_rx_total by body_bytes
 *   2. Increment put_body_total[body_mode]
 *   3. Call s3_put_finalize_empty_ok() which sends the HTTP response
 */
/*
 * s3_put_body_handler — ngx_http_read_client_request_body() completion
 * callback for S3 PutObject.
 *
 * Retrieves the filesystem path from the per-request module context (set by
 * ngx_http_s3_handler before calling ngx_http_read_client_request_body).
 *
 * Special case — directory sentinels: S3 clients represent directories as
 * zero-byte objects whose key ends with the S3_DIR_SENTINEL suffix (typically
 * "_$folder$").  These are handled by creating the real directory rather than
 * a file.
 *
 * Normal case: write body to a temp file (O_EXCL for atomicity), then rename
 * onto the final path.  On any error the temp file is unlinked.
 *
 * Ownership: the response is finalised via s3_put_finalize_ok() which calls
 *   ngx_http_send_header() and ngx_http_send_special().  The function must not
 *   return NGX_DONE (the caller already incremented r->main->count via
 *   ngx_http_read_client_request_body).
 */

/*
 * s3_put_finalize_client_error — send an S3 XML 4xx for a malformed PUT and
 * finalize dashboard/metrics (used by the aws-chunked decode path).
 */
void
s3_put_finalize_client_error(ngx_http_request_t *r, int status,
    const char *code, const char *message)
{
    brix_dashboard_http_error(r, message);
    brix_dashboard_http_finish(r);
    (void) s3_send_xml_error(r, (ngx_uint_t) status, code, message);
    s3_metrics_finalize_request_method(r, BRIX_S3_METHOD_PUT,
                                       (ngx_int_t) status);
}
