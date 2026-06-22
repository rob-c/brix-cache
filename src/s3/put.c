/*
 * put.c — S3 PUT handler: body callback, directory-sentinel mkdir,
 *          atomic write via temp file + rename.
 *
 * Thread-pool path (NGX_THREADS): for in-memory bodies, dispatches the
 * pwrite + staged commit to a worker thread via ngx_thread_task_post so the
 * nginx event loop is not blocked during large object writes.
 */
/*
 * ============================================================
 * WHAT: S3 PutObject handler — body callback after client request
 *      is fully read by nginx.
 * ============================================================
 *
 * This file implements the completion callback for S3 PUT requests.
 * ngx_http_s3_handler() sets r->ctx to the resolved filesystem path,
 * then calls ngx_http_read_client_request_body(). When the body is
 * fully received, s3_put_body_handler() fires as the async callback.
 *
 * Two paths:
 *   1. Directory sentinel — key ends with S3_DIR_SENTINEL ("_$folder$")
 *      → mkdir parent + create zero-byte sentinel file.
 *   2. Normal object write — body to temp file via O_EXCL, then rename.
 *      The temp file guarantees atomicity: no concurrent PUT can corrupt
 *      the final path because O_EXCL fails if the tmp file already exists.
 * ============================================================
 *
 * WHY atomic temp+rename:
 *   - If the process crashes mid-write, only the .tmp.{pid}.{random} file
 *     is orphaned (cleaned up by staged_abort). The final path is untouched.
 *   - Clients never see a partially-written object.
 * ============================================================
 *
 * Body write modes:
 *   XROOTD_S3_PUT_EMPTY — no body bytes (e.g. sentinel)
 *   XROOTD_S3_PUT_MEMORY — all buffers in-memory (buf->in_file=0)
 *   XROOTD_S3_PUT_SPOOLED — all buffers spooled to nginx temp files
 *     (buf->in_file=1, read via pread())
 *   XROOTD_S3_PUT_MIXED — combination of both modes
 * ============================================================
 *
 * Security/integrity:
 *   - O_EXCL on temp file prevents concurrent PUT corruption
 *   - Confined canon check via xrootd_open_confined_canon() and
 *     xrootd_staged_commit() (rename confined to root_canon)
 *   - Path escape detection already done in handler.c (s3_resolve_key)
 *   - allow_write config gate checked before body read starts
 */

#include "s3.h"
#include "aws_chunked.h"
#include "tagging.h"
#include "../compat/http_body.h"
#include "../compat/http_headers.h"
#include "../compat/staged_file.h"
#include "../path/path.h"
#include "../dashboard/dashboard_tracking.h"
#include "../impersonate/lifecycle.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

static void s3_put_finalize_error(ngx_http_request_t *r);
static void s3_put_finalize_fs_error(ngx_http_request_t *r, int saved_errno);
static void s3_put_finalize_empty_ok(ngx_http_request_t *r);
static void s3_put_finalize_bad_digest(ngx_http_request_t *r);
static void s3_put_finalize_invalid_request(ngx_http_request_t *r);
static int  s3_put_checksum_failed(ngx_http_request_t *r,
    const char *fs_path, const char *root_canon);
static void s3_put_streaming(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    xrootd_staged_file_t *staged, const char *fs_path, ngx_uint_t body_mode);

static const char *
s3_dashboard_put_op(ngx_http_request_t *r)
{
    char upload_id[128];
    char part_num[16];

    if (s3_get_query_param(r, "uploadId", upload_id, sizeof(upload_id))
        && s3_get_query_param(r, "partNumber", part_num, sizeof(part_num)))
    {
        return "UploadPart";
    }

    return "PutObject";
}

static void
s3_dashboard_identity(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
                      char *out, size_t outsz)
{
    ngx_http_s3_req_ctx_t *s3ctx;
    const char            *subject;

    if (out == NULL || outsz == 0) {
        return;
    }

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    subject = s3ctx != NULL
              ? xrootd_identity_subject_cstr(s3ctx->identity) : "";
    if (subject[0] != '\0') {
        ngx_cpystrn((u_char *) out, (u_char *) subject, outsz);
        return;
    }

    if (cf->access_key.len > 0 && cf->access_key.data != NULL) {
        size_t n = cf->access_key.len < outsz - 1
                   ? cf->access_key.len
                   : outsz - 1;
        ngx_memcpy(out, cf->access_key.data, n);
        out[n] = '\0';
        return;
    }

    ngx_cpystrn((u_char *) out, (u_char *) "anonymous", outsz);
}

typedef struct {
    ngx_http_request_t   *r;
    xrootd_staged_file_t  staged;
    size_t                len;
    ssize_t               nwritten;
    int                   io_errno;
    ngx_uint_t            body_mode;
    size_t                body_bytes;
    char                  final_path[PATH_MAX];
    char                  root_canon[PATH_MAX];
} s3_put_aio_t;

/*
 * s3_thread_pool — resolve (and cache) the async-I/O thread pool for this
 * location.
 *
 * WHY: the S3 postconfiguration only resolves common.thread_pool on the
 * *server-level* loc-conf, but `xrootd_s3 on` is normally inside a `location {}`
 * block whose loc-conf never gets that pointer set — so the offload below would
 * silently never engage.  Mirror the WebDAV COPY/MOVE pattern
 * (src/webdav/copy.c, move.c): resolve lazily at request time via ngx_cycle and
 * cache the result into the loc-conf for subsequent requests.
 */
ngx_thread_pool_t *
s3_thread_pool(ngx_http_s3_loc_conf_t *cf)
{
    static ngx_str_t   default_name = ngx_string("default");
    ngx_str_t         *pname;
    ngx_thread_pool_t *pool;

    if (cf->common.thread_pool != NULL) {
        return cf->common.thread_pool;
    }
    pname = cf->common.thread_pool_name.len > 0
            ? &cf->common.thread_pool_name : &default_name;
    pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
    if (pool != NULL) {
        cf->common.thread_pool = pool;   /* cache for subsequent requests */
    }
    return pool;
}

static void s3_put_finalize_client_error(ngx_http_request_t *r, int status,
    const char *code, const char *message);

/*
 * s3_commit_put — W6b: commit the staged temp file to its final path, honouring
 * an exclusive (create-if-absent) PutObject.  When the request carried
 * `If-None-Match: *` the commit uses renameat2(RENAME_NOREPLACE); otherwise the
 * plain rename.  Returns NGX_OK; or NGX_ERROR with ngx_errno preserved (EEXIST
 * when an exclusive create lost the race — the caller maps that to 412).  Runs
 * on the event loop (all three PUT commit sites do), so the request ctx is live.
 */
static ngx_int_t
s3_commit_put(ngx_http_request_t *r, ngx_log_t *log, const char *root_canon,
    xrootd_staged_file_t *staged, const char *final_path)
{
    ngx_http_s3_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);

    if (rx != NULL && rx->exclusive_create) {
        return xrootd_staged_commit_excl(log, root_canon, staged, final_path);
    }
    return xrootd_staged_commit(log, root_canon, staged, final_path);
}

/*
 * s3_put_commit_conflict — after s3_commit_put() returned NGX_ERROR, send the
 * 412 PreconditionFailed for an exclusive create that lost the race and return
 * 1; return 0 when the failure was something else (caller handles as 500).
 */
static int
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

static void
s3_put_aio_thread(void *data, ngx_log_t *log)
{
    s3_put_aio_t *t = data;

    (void) log;

    t->io_errno = 0;

    /*
     * Phase 31 W2 / phase-46 W1a: stream every body buf straight to the staged
     * temp fd — no full-body contiguous copy.  Memory bufs go via pwrite(2);
     * spooled bufs via kernel copy_file_range from the nginx temp file.  Both are
     * blocking syscalls, which is exactly why they run here on the thread pool
     * rather than the event loop.
     */
    if (xrootd_http_body_write_to_fd(t->r, t->staged.fd, t->final_path, NULL)
        != NGX_OK)
    {
        t->io_errno = errno;
        t->nwritten = -1;
        return;
    }

    t->nwritten = (ssize_t) t->len;
}

static void
s3_put_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    s3_put_aio_t       *t = task->ctx;
    ngx_http_request_t *r = t->r;
    ngx_log_t          *log = r->connection->log;

    if (t->nwritten < 0 || (size_t) t->nwritten < t->len) {
        xrootd_log_safe_path(log, NGX_LOG_ERR,
                             (ngx_uint_t) t->io_errno,
                             "s3: async write() failed for: \"%s\"",
                             t->final_path);
        xrootd_staged_abort(log, t->root_canon, &t->staged, 1);
        s3_put_finalize_error(r);
        return;
    }

    ngx_close_file(t->staged.fd);
    t->staged.fd = NGX_INVALID_FILE;

    if (s3_commit_put(r, log, t->root_canon, &t->staged,
                      t->final_path) != NGX_OK)
    {
        if (s3_put_commit_conflict(r)) {
            return;
        }
        xrootd_log_safe_path(log, NGX_LOG_ERR, ngx_errno,
                             "s3: async staged commit to \"%s\" failed",
                             t->final_path);
        s3_put_finalize_error(r);
        return;
    }

    /* S3 PutObject requires an ETag on the 200 response (the synchronous path
     * sets it too — keep the offload path's response identical). */
    {
        struct stat final_sb;
        char        etag_buf[48];
        if (stat(t->final_path, &final_sb) == 0) {
            s3_etag(&final_sb, etag_buf, sizeof(etag_buf));
            (void) s3_set_header(r, "ETag", etag_buf);
        }
    }

    /* Full-object checksum verify (client-supplied) + echo; failures remove the
     * object and send the matching 400. */
    if (s3_put_checksum_failed(r, t->final_path, t->root_canon)) {
        return;
    }

    /* x-amz-tagging (best-effort): store the request's tag set on the object. */
    (void) s3_apply_put_tagging_header(r, t->final_path, t->root_canon);

    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) t->body_bytes);
    XROOTD_S3_METRIC_ADD(bytes_rx_total, t->body_bytes);
    if (r->connection && r->connection->sockaddr
        && r->connection->sockaddr->sa_family == AF_INET6) {
        XROOTD_S3_METRIC_ADD(bytes_rx_ipv6_total, t->body_bytes);
    } else {
        XROOTD_S3_METRIC_ADD(bytes_rx_ipv4_total, t->body_bytes);
    }
    XROOTD_S3_METRIC_INC(put_body_total[t->body_mode]);
    s3_put_finalize_empty_ok(r);
}
/*
 * s3_put_body_mode — classify the body into one of four modes.
 *
 * WHY this classification:
 *   Prometheus metrics track put operations by body mode so we can see
 *   how much traffic is in-memory vs spooled. The enum values are used
 *   as indices into XROOTD_S3_METRIC_INC(put_body_total[...]).
 */

static ngx_uint_t
s3_put_body_mode(const xrootd_http_body_summary_t *summary)
{
    if (summary->has_spooled && summary->has_memory) {
        return XROOTD_S3_PUT_MIXED;
    }
    if (summary->has_spooled) {
        return XROOTD_S3_PUT_SPOOLED;
    }
    if (summary->has_memory) {
        return XROOTD_S3_PUT_MEMORY;
    }
    return XROOTD_S3_PUT_EMPTY;
}
/*
 * s3_put_finalize_error — send 500 and increment internal-error metric.
 *
 * Called from any failure path inside the handler. The response is final;
 * this function does not return NGX_DONE (the caller already incremented
 * r->main->count via ngx_http_read_client_request_body).
 */

static void
s3_put_finalize_error(ngx_http_request_t *r)
{
    xrootd_dashboard_http_error(r, "s3 write failed");
    xrootd_dashboard_http_finish(r);
    XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT,
                                       NGX_HTTP_INTERNAL_SERVER_ERROR);
}

/*
 * s3_put_finalize_fs_error — finalize a PUT that failed at a filesystem op,
 * mapping the captured errno to the correct HTTP status instead of a blanket 500.
 *
 * WHAT: A cross-tenant / DAC-denied create (e.g. alice PUT into bob's 0755 dir →
 *       EACCES on the staged temp create) is a forbidden request, not a server
 *       fault.  Route the captured errno through xrootd_http_errno_to_status()
 *       (the same map S3 GET/CopyObject already use): EACCES/EPERM/EXDEV/ELOOP →
 *       403 AccessDenied, ENOENT/ENOTDIR → 404 NoSuchKey, ENOSPC → 507, etc.
 *       Any errno that maps to 5xx falls back to the existing internal-error path.
 * WHY:  A genuine permission denial must surface as 403 (clean 4xx contract), not
 *       HTTP 500 — a 500 misreports a bounded, well-formed request as an internal
 *       error and is the robustness defect the impersonation red-team flagged.
 * HOW:  The caller MUST capture errno into saved_errno BEFORE any intervening
 *       syscall (logging, staged_abort) clobbers it, then pass it here.
 */
static void
s3_put_finalize_fs_error(ngx_http_request_t *r, int saved_errno)
{
    int         status;
    const char *code;
    const char *message;

    status = (int) xrootd_http_errno_to_status(saved_errno);

    /* errno that has no clean 4xx contract (e.g. EIO) keeps the 500 path. */
    if (status >= 500) {
        s3_put_finalize_error(r);
        return;
    }

    switch (status) {
    case 403:
        code = "AccessDenied";
        message = "Access Denied.";
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_ACCESS_DENIED]);
        break;
    case 404:
        code = "NoSuchKey";
        message = "The specified key does not exist.";
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_NO_SUCH_KEY]);
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

    xrootd_dashboard_http_error(r, message);
    xrootd_dashboard_http_finish(r);
    (void) s3_send_xml_error(r, (ngx_uint_t) status, code, message);
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT,
                                       (ngx_int_t) status);
}

static void
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
    xrootd_dashboard_http_finish(r);
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT, rc);
}

static void
s3_put_finalize_ok(ngx_http_request_t *r, size_t body_bytes,
    ngx_uint_t body_mode)
{
    xrootd_dashboard_http_add(r, (ngx_atomic_int_t) body_bytes);
    XROOTD_S3_METRIC_ADD(bytes_rx_total, body_bytes);
    if (r->connection && r->connection->sockaddr
        && r->connection->sockaddr->sa_family == AF_INET6) {
        XROOTD_S3_METRIC_ADD(bytes_rx_ipv6_total, body_bytes);
    } else {
        XROOTD_S3_METRIC_ADD(bytes_rx_ipv4_total, body_bytes);
    }
    XROOTD_S3_METRIC_INC(put_body_total[body_mode]);
    s3_put_finalize_empty_ok(r);
}

/*
 * s3_put_finalize_bad_digest — reject a PUT whose client checksum mismatched.
 * The object was already removed by s3_put_checksum_apply; send 400 BadDigest
 * and finalize the dashboard/metrics for the request.
 */
static void
s3_put_finalize_bad_digest(ngx_http_request_t *r)
{
    xrootd_dashboard_http_error(r, "s3 checksum mismatch");
    xrootd_dashboard_http_finish(r);
    (void) s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "BadDigest",
        "The checksum you specified did not match what was received.");
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT,
                                       NGX_HTTP_BAD_REQUEST);
}

/*
 * s3_put_finalize_invalid_request — reject a PUT whose checksum selection was
 * ambiguous or named an unsupported algorithm (the object was already removed
 * by s3_put_checksum_apply); send 400 InvalidRequest.
 */
static void
s3_put_finalize_invalid_request(ngx_http_request_t *r)
{
    xrootd_dashboard_http_error(r, "s3 invalid checksum request");
    xrootd_dashboard_http_finish(r);
    (void) s3_send_xml_error(r, NGX_HTTP_BAD_REQUEST, "InvalidRequest",
        "The checksum algorithm selection is invalid or ambiguous.");
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT,
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
static void
s3_put_finalize_codec_error(ngx_http_request_t *r, ngx_int_t status)
{
    const char *code = "InvalidRequest";
    const char *msg  = "The request body could not be decoded with the "
                       "requested Content-Encoding.";

    if (status == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE) {
        code = "EntityTooLarge";
        msg  = "The decompressed body exceeds the maximum allowed size.";
    }
    xrootd_dashboard_http_error(r, "s3 content-encoding decode failed");
    xrootd_dashboard_http_finish(r);
    (void) s3_send_xml_error(r, status, code, msg);
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT, status);
}

/*
 * s3_put_checksum_failed — verify+echo the client's full-object checksum and, on
 * a terminal failure, send the corresponding 400 response.
 *
 * Returns 1 when a failure response was already sent (the caller must stop), or
 * 0 to proceed with the success finalize.  A compute error (S3_CKSUM_ERROR) is
 * non-fatal — the object stands, just without an echoed checksum header.
 */
static int
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
 *   body_mode    — classification enum (XROOTD_S3_PUT_*), used as metric index
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
static void s3_put_body_inner(ngx_http_request_t *r);

/*
 * s3_put_finalize_client_error — send an S3 XML 4xx for a malformed PUT and
 * finalize dashboard/metrics (used by the aws-chunked decode path).
 */
static void
s3_put_finalize_client_error(ngx_http_request_t *r, int status,
    const char *code, const char *message)
{
    xrootd_dashboard_http_error(r, message);
    xrootd_dashboard_http_finish(r);
    (void) s3_send_xml_error(r, (ngx_uint_t) status, code, message);
    s3_metrics_finalize_request_method(r, XROOTD_S3_METHOD_PUT,
                                       (ngx_int_t) status);
}

/*
 * s3_chunk_finalize — post-decode steps that must run on the event loop:
 * commit the staged object, set the ETag, verify the (trailer or default)
 * checksum, store tags, and send 200.  Shared by the synchronous fallback and
 * the offload completion; `staged` has been written but not yet committed.
 */
static void
s3_chunk_finalize(ngx_http_request_t *r, const char *root_canon,
    const char *fs_path, xrootd_staged_file_t *staged,
    const s3_chunk_trailer_t *trailer, uint64_t expected, ngx_uint_t body_mode)
{
    if (s3_commit_put(r, r->connection->log, root_canon, staged,
                      fs_path) != NGX_OK)
    {
        if (s3_put_commit_conflict(r)) {
            return;
        }
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "s3: staged commit to \"%s\" failed", fs_path);
        s3_put_finalize_error(r);
        return;
    }

    {
        struct stat sb;
        char        etag_buf[48];
        if (stat(fs_path, &sb) == 0) {
            s3_etag(&sb, etag_buf, sizeof(etag_buf));
            (void) s3_set_header(r, "ETag", etag_buf);
        }
    }

    if (trailer->algo_token[0] != '\0') {
        switch (s3_put_trailer_checksum_apply(r, fs_path, root_canon,
                                              trailer->algo_token,
                                              trailer->value))
        {
        case S3_CKSUM_MISMATCH:
            s3_put_finalize_bad_digest(r);
            return;
        case S3_CKSUM_CONFLICT:
            s3_put_finalize_invalid_request(r);
            return;
        default:
            break;
        }
    } else if (s3_put_checksum_failed(r, fs_path, root_canon)) {
        return;
    }

    (void) s3_apply_put_tagging_header(r, fs_path, root_canon);
    s3_put_finalize_ok(r, expected, body_mode);
}

/* Decode-failure path: abort the staged temp and send the mapped S3 error. */
static void
s3_chunk_decode_failed(ngx_http_request_t *r, const char *root_canon,
    xrootd_staged_file_t *staged, int http_status)
{
    xrootd_staged_abort(r->connection->log, root_canon, staged, 1);
    if (http_status >= 500) {
        s3_put_finalize_error(r);
    } else if (http_status == NGX_HTTP_FORBIDDEN) {
        /* W6a: a per-chunk signature mismatch — surface as SignatureDoesNotMatch. */
        s3_put_finalize_client_error(r, NGX_HTTP_FORBIDDEN,
            "SignatureDoesNotMatch",
            "The chunk signature does not match the calculated signature.");
    } else {
        s3_put_finalize_client_error(r, NGX_HTTP_BAD_REQUEST, "InvalidRequest",
            "The aws-chunked request body could not be decoded.");
    }
}

/*
 * phase-46 W1b: aws-chunked decode offload.  The decode is a blocking
 * pread/pwrite state machine over the (often spooled) body, so it runs on the
 * thread pool; the completion commits/checksums/finalizes on the event loop.
 * The worker uses the task's own `window` scratch — it never touches r->pool.
 */
typedef struct {
    ngx_http_request_t   *r;
    xrootd_staged_file_t  staged;
    char                  fs_path[PATH_MAX];
    char                  root_canon[PATH_MAX];
    uint64_t              expected;
    ngx_uint_t            body_mode;
    s3_chunk_trailer_t    trailer;       /* filled by the worker */
    s3_chunk_verify_t     verify;        /* W6a: per-chunk SigV4 verify ctx */
    ngx_int_t             rc;            /* decode result        */
    int                   http_status;   /* decode error status  */
    u_char                window[S3_CHUNK_READ_WINDOW];
} s3_chunk_aio_t;

static void
s3_chunk_aio_thread(void *data, ngx_log_t *log)
{
    s3_chunk_aio_t *t = data;

    (void) log;
    t->http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    t->rc = s3_aws_chunked_decode_to_fd(t->r, t->staged.fd, t->fs_path,
                                        t->expected, &t->trailer,
                                        &t->http_status, t->window,
                                        &t->verify);
}

/*
 * s3_build_chunk_verify — W6a: assemble the per-chunk verification context from
 * the location flag + the SigV4 material auth retained on the request ctx.  Left
 * disabled (zeroed) unless verification is configured AND a signed request was
 * authenticated (an anonymous endpoint has no secret to verify against).
 */
static void
s3_build_chunk_verify(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    s3_chunk_verify_t *v)
{
    ngx_http_s3_req_ctx_t *rx;

    ngx_memzero(v, sizeof(*v));
    if (!cf->verify_chunk_signatures) {
        return;
    }
    rx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    if (rx == NULL || !rx->have_sigv4) {
        return;
    }
    v->enabled = 1;
    ngx_memcpy(v->signing_key, rx->sigv4_signing_key, 32);
    ngx_cpystrn((u_char *) v->seed_signature,
                (u_char *) rx->sigv4_seed_signature, sizeof(v->seed_signature));
    ngx_cpystrn((u_char *) v->amz_date,
                (u_char *) rx->sigv4_amz_date, sizeof(v->amz_date));
    ngx_cpystrn((u_char *) v->scope,
                (u_char *) rx->sigv4_scope, sizeof(v->scope));
}

static void
s3_chunk_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    s3_chunk_aio_t     *t = task->ctx;
    ngx_http_request_t *r = t->r;

    if (t->rc != NGX_OK) {
        s3_chunk_decode_failed(r, t->root_canon, &t->staged, t->http_status);
        return;
    }
    s3_chunk_finalize(r, t->root_canon, t->fs_path, &t->staged, &t->trailer,
                      t->expected, t->body_mode);
}

/*
 * s3_put_streaming — decode an aws-chunked PUT/UploadPart body and finalize.
 *
 * Reads x-amz-decoded-content-length, then either offloads the chunk decode to
 * the thread pool (so the blocking pread/pwrite state machine does not stall the
 * event loop) or, when no pool is configured, decodes synchronously.  Either way
 * the commit/ETag/checksum/tagging/200 run on the event loop (s3_chunk_finalize).
 */
static void
s3_put_streaming(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    xrootd_staged_file_t *staged, const char *fs_path, ngx_uint_t body_mode)
{
    const char        *root_canon = cf->common.root_canon;
    ngx_table_elt_t   *dcl;
    uint64_t           expected = 0;
    ngx_thread_pool_t *pool;
    size_t             i;

    dcl = xrootd_http_find_header(r, "x-amz-decoded-content-length",
                                  sizeof("x-amz-decoded-content-length") - 1);
    if (dcl == NULL || dcl->value.len == 0) {
        xrootd_staged_abort(r->connection->log, root_canon, staged, 1);
        s3_put_finalize_client_error(r, NGX_HTTP_BAD_REQUEST,
            "MissingContentLength",
            "Streaming upload is missing x-amz-decoded-content-length.");
        return;
    }
    for (i = 0; i < dcl->value.len; i++) {
        u_char d = dcl->value.data[i];
        if (d < '0' || d > '9') {
            xrootd_staged_abort(r->connection->log, root_canon, staged, 1);
            s3_put_finalize_client_error(r, NGX_HTTP_BAD_REQUEST,
                "InvalidArgument",
                "x-amz-decoded-content-length is not a valid length.");
            return;
        }
        expected = expected * 10 + (uint64_t) (d - '0');
    }

    pool = s3_thread_pool(cf);
    if (pool != NULL) {
        ngx_thread_task_t *task =
            ngx_thread_task_alloc(r->pool, sizeof(s3_chunk_aio_t));
        s3_chunk_aio_t    *t;

        if (task == NULL) {
            xrootd_staged_abort(r->connection->log, root_canon, staged, 1);
            s3_put_finalize_error(r);
            return;
        }
        t = task->ctx;                  /* ngx_thread_task_alloc zeroes ctx */
        t->r         = r;
        t->staged    = *staged;
        t->expected  = expected;
        t->body_mode = body_mode;
        s3_build_chunk_verify(r, cf, &t->verify);   /* W6a */
        ngx_cpystrn((u_char *) t->fs_path, (u_char *) fs_path,
                    sizeof(t->fs_path));
        ngx_cpystrn((u_char *) t->root_canon, (u_char *) root_canon,
                    sizeof(t->root_canon));
        task->handler       = s3_chunk_aio_thread;
        task->event.handler = s3_chunk_aio_done;
        task->event.data    = task;

        if (ngx_thread_task_post(pool, task) != NGX_OK) {
            xrootd_staged_abort(r->connection->log, root_canon, staged, 1);
            s3_put_finalize_error(r);
            return;
        }
        r->main->count++;
        return;
    }

    /* Synchronous fallback (no thread pool): decode inline, then finalize. */
    {
        s3_chunk_trailer_t trailer;
        s3_chunk_verify_t  verify;
        int                status = NGX_HTTP_INTERNAL_SERVER_ERROR;

        s3_build_chunk_verify(r, cf, &verify);   /* W6a */
        if (s3_aws_chunked_decode_to_fd(r, staged->fd, fs_path, expected,
                                        &trailer, &status, NULL, &verify)
            != NGX_OK)
        {
            s3_chunk_decode_failed(r, root_canon, staged, status);
            return;
        }
        s3_chunk_finalize(r, root_canon, fs_path, staged, &trailer, expected,
                          body_mode);
    }
}

/*
 * Phase 40: the S3 PUT body is read asynchronously (after inline SigV4 auth has
 * already populated s3ctx->identity), so this callback re-establishes the
 * impersonation principal for the duration of the object write.  The create
 * (xrootd_open_confined_canon) then routes to the broker and the new object is
 * owned by the mapped user.  No-op unless map mode is active.
 */
void
s3_put_body_handler(ngx_http_request_t *r)
{
    ngx_http_s3_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);

    xrootd_imp_request_begin(rx != NULL ? rx->identity : NULL);
    s3_put_body_inner(r);
    xrootd_imp_request_end();
}

static void
s3_put_body_inner(ngx_http_request_t *r)
{
    u_char              *fs_path;
    ngx_http_s3_loc_conf_t *cf;
    ngx_http_s3_req_ctx_t  *s3ctx;
    int                  fd = -1;
    int                  is_sentinel;
    xrootd_codec_id_t    put_codec = XROOTD_CODEC_IDENTITY;
    size_t               body_bytes = 0;
    ngx_uint_t           body_mode = XROOTD_S3_PUT_EMPTY;
    xrootd_staged_file_t staged;
    xrootd_http_body_summary_t body_summary;
    char                 identity[128];

    cf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_s3_module);
    s3ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);
    fs_path = s3ctx != NULL ? (u_char *) s3ctx->fs_path : NULL;

    if (fs_path == NULL) {
        s3_put_finalize_error(r);
        return;
    }

    /* Check for directory sentinel */
    {
        size_t plen = ngx_strlen(fs_path);
        size_t slen = sizeof(S3_DIR_SENTINEL) - 1;
        is_sentinel = (plen >= slen
            && ngx_strncmp(fs_path + plen - slen,
                           (u_char *) S3_DIR_SENTINEL, slen) == 0);
    }

    if (is_sentinel) {
        /* Create the directory that the sentinel lives in */
        char parent[PATH_MAX];
        size_t plen = ngx_strlen(fs_path);
        if (plen >= sizeof(parent)) {
            s3_put_finalize_error(r);
            return;
        }
        memcpy(parent, fs_path, plen + 1);
        char *slash = strrchr(parent, '/');
        if (slash != NULL) {
            *slash = '\0';
        }
        if (xrootd_mkdir_confined_canon(r->connection->log, cf->common.root_canon,
                                        parent, 0755) != 0
            && errno != EEXIST)
        {
            int mk_errno = errno;  /* capture before logging clobbers it */
            xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, mk_errno,
                                 "s3: mkdir(\"%s\") failed", parent);
            s3_put_finalize_fs_error(r, mk_errno);
            return;
        }

        /* Write the zero-byte sentinel */
        fd = xrootd_open_confined_canon(r->connection->log, cf->common.root_canon,
                                        (const char *) fs_path,
                                        O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            int open_errno = errno;  /* capture before logging clobbers it */
            xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, open_errno,
                                 "s3: open(\"%s\") for sentinel failed",
                                 (const char *) fs_path);
            s3_put_finalize_fs_error(r, open_errno);
            return;
        }
        close(fd);

        s3_dashboard_identity(r, cf, identity, sizeof(identity));
        (void) xrootd_dashboard_http_start_identity(r, (const char *) fs_path,
            identity, "", XROOTD_XFER_PROTO_S3, XROOTD_XFER_DIR_WRITE,
            "PutObjectSentinel", 0);
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_DIR_SENTINEL]);
        XROOTD_S3_METRIC_INC(put_body_total[XROOTD_S3_PUT_EMPTY]);
        s3_put_finalize_empty_ok(r);
        return;
    }

    /* Create parent directories if needed using the shared confined mkdir helper. */
    {
        char   parent[PATH_MAX];
        char  *last_slash;
        size_t flen = strlen((const char *) fs_path);

        if (flen < sizeof(parent)) {
            memcpy(parent, fs_path, flen + 1);
            last_slash = strrchr(parent, '/');
            if (last_slash && last_slash != parent) {
                struct stat pdir;

                *last_slash = '\0';

                /*
                 * phase-46 W2a: fast-path the common "many objects into one
                 * prefix" pattern.  A single confined lstat that finds an
                 * existing directory replaces the per-path-component
                 * mkdirat(EEXIST) storm of xrootd_mkdir_recursive_confined_canon.
                 * A symlink (S_ISLNK) or a miss falls through to the recursive
                 * confined mkdir, which re-enforces confinement.
                 */
                if (xrootd_lstat_confined_canon(r->connection->log,
                        cf->common.root_canon, parent, &pdir, 1) == 0
                    && S_ISDIR(pdir.st_mode))
                {
                    /* parent prefix already exists — nothing to create */
                } else if (xrootd_mkdir_recursive_confined_canon(
                               r->connection->log, cf->common.root_canon,
                               parent, 0755, NULL) != 0
                           && errno != EEXIST) {
                    int mk_errno = errno;  /* capture before logging clobbers it */
                    xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                         mk_errno,
                                         "s3: mkdirs_for(\"%s\") failed",
                                         (const char *) fs_path);
                    /* DAC-denied create of a parent dir → 403, not 500. */
                    s3_put_finalize_fs_error(r, mk_errno);
                    return;
                }
            }
        }
    }

    if (xrootd_staged_open(r->connection->log, cf->common.root_canon,
                           (const char *) fs_path, O_WRONLY, 0600, 16,
                           &staged) != NGX_OK)
    {
        int open_errno = errno;   /* capture before logging clobbers errno */
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, open_errno,
                             "s3: staged open for \"%s\" failed",
                             (const char *) fs_path);
        /* A DAC-denied / confinement-blocked create is a 403, not a 500. */
        s3_put_finalize_fs_error(r, open_errno);
        return;
    }

    if (xrootd_http_body_summary(r, &body_summary) != NGX_OK) {
        xrootd_staged_abort(r->connection->log, cf->common.root_canon, &staged, 1);
        s3_put_finalize_error(r);
        return;
    }

    body_bytes = body_summary.bytes;
    body_mode = s3_put_body_mode(&body_summary);
    s3_dashboard_identity(r, cf, identity, sizeof(identity));
    (void) xrootd_dashboard_http_start_identity(r, (const char *) fs_path,
        identity, "", XROOTD_XFER_PROTO_S3, XROOTD_XFER_DIR_WRITE,
        s3_dashboard_put_op(r), (int64_t) body_bytes);

    /*
     * AWS streaming upload (aws-chunked): the body carries chunk framing that
     * must be decoded to the object bytes — storing it verbatim corrupts every
     * object from a default modern SDK/CLI client.  Routed through its own
     * decode → commit → checksum → finalize path.
     */
    if (s3_body_is_aws_chunked(r)) {
        /* A combined Content-Encoding such as "aws-chunked,gzip" means the body
         * was compressed THEN chunk-framed.  The streaming de-chunker strips only
         * the chunk envelope, so the inner-compressed payload would be stored
         * still compressed (silent object corruption).  Reject rather than store
         * undecoded bytes — the same invariant the non-chunked path enforces with
         * 400 below.  Plain aws-chunked (no inner coding) continues normally. */
        if (s3_aws_chunked_has_inner_coding(r)) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                &staged, 1);
            s3_put_finalize_codec_error(r, NGX_HTTP_BAD_REQUEST);
            return;
        }
        s3_put_streaming(r, cf, &staged, (const char *) fs_path, body_mode);
        return;
    }

    {
        ngx_table_elt_t  *ce = xrootd_http_find_header(
            r, "Content-Encoding", sizeof("Content-Encoding") - 1);
        if (ce != NULL && ce->value.len > 0) {
            const xrootd_codec_desc_t *d = xrootd_codec_by_http_token(
                (const char *) ce->value.data, ce->value.len);
            if (d == NULL || !d->available) {
                /* Unknown / not-compiled-in Content-Encoding: never store the
                 * undecoded bytes — reject as a client error (400), not 500. */
                xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                    &staged, 1);
                s3_put_finalize_codec_error(r, NGX_HTTP_BAD_REQUEST);
                return;
            }
            put_codec = d->id;
        }
    }

    /*
     * phase-46 W1a: offload the body write to the thread pool for ALL plain
     * (identity-encoded) bodies — including spooled and mixed ones, not just
     * in-memory.  The worker fn (s3_put_aio_thread) already streams every buf,
     * memory and file-backed, via xrootd_http_body_write_to_fd (kernel
     * copy_file_range for the spooled nginx temp file), so large uploads — the
     * ones nginx spools to disk — stop blocking the event loop.  Content-Encoding
     * decode (put_codec != IDENTITY) and aws-chunked (handled above) still run
     * synchronously.
     */
    if (body_summary.bytes > 0
        && put_codec == XROOTD_CODEC_IDENTITY && s3_thread_pool(cf) != NULL)
    {
        ngx_thread_task_t *task;
        s3_put_aio_t      *t;

        task = ngx_thread_task_alloc(r->pool, sizeof(s3_put_aio_t));
        if (task == NULL) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon, &staged, 1);
            s3_put_finalize_error(r);
            return;
        }

        t = task->ctx;
        t->r         = r;
        t->staged    = staged;
        t->len       = body_summary.bytes;
        t->body_mode = body_mode;
        t->body_bytes = body_bytes;
        ngx_cpystrn((u_char *) t->final_path, fs_path, sizeof(t->final_path));
        ngx_cpystrn((u_char *) t->root_canon,
                    (u_char *) cf->common.root_canon, sizeof(t->root_canon));

        /*
         * Phase 31 W2: no full-body collection — the thread streams the
         * in-memory body bufs straight to the staged fd (s3_put_aio_thread).
         */

        task->handler       = s3_put_aio_thread;
        task->event.handler = s3_put_aio_done;
        task->event.data    = task;

        if (ngx_thread_task_post(cf->common.thread_pool, task) != NGX_OK) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon, &staged, 1);
            s3_put_finalize_error(r);
            return;
        }

        r->main->count++;
        return;
    }

    {
        ngx_int_t  wrc;
        ngx_int_t  decode_status = 0;

        if (put_codec != XROOTD_CODEC_IDENTITY) {
            wrc = xrootd_http_body_decode_to_fd(r, staged.fd,
                                                (const char *) fs_path,
                                                put_codec,
                                                XROOTD_DECODE_MAX_OUTPUT,
                                                &body_summary,
                                                &decode_status);
        } else {
            wrc = xrootd_http_body_write_to_fd(r, staged.fd,
                                                (const char *) fs_path,
                                                &body_summary);
        }
        if (wrc != NGX_OK) {
            xrootd_staged_abort(r->connection->log, cf->common.root_canon,
                                &staged, 1);
            /* Map a decode failure to a clean S3 client error (413 bomb / 400
             * malformed); a genuine I/O failure (decode_status 0 or 5xx) stays
             * a 500. */
            if (decode_status == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
                || decode_status == NGX_HTTP_BAD_REQUEST
                || decode_status == NGX_HTTP_UNSUPPORTED_MEDIA_TYPE)
            {
                s3_put_finalize_codec_error(r, decode_status
                    == NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
                    ? NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
                    : NGX_HTTP_BAD_REQUEST);
            } else {
                s3_put_finalize_error(r);
            }
            return;
        }
    }

    if (s3_commit_put(r, r->connection->log, cf->common.root_canon, &staged,
                      (const char *) fs_path) != NGX_OK)
    {
        if (s3_put_commit_conflict(r)) {
            return;
        }
        xrootd_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "s3: staged commit to \"%s\" failed",
                             (const char *) fs_path);
        s3_put_finalize_error(r);
        return;
    }

    /* S3 API requires ETag on PutObject 200 response */
    {
        struct stat  final_sb;
        char         etag_buf[48];

        if (stat((const char *) fs_path, &final_sb) == 0) {
            s3_etag(&final_sb, etag_buf, sizeof(etag_buf));
            (void) s3_set_header(r, "ETag", etag_buf);
        }
    }

    /* Full-object checksum verify (client-supplied) + echo; failures remove the
     * object and send the matching 400. */
    if (s3_put_checksum_failed(r, (const char *) fs_path,
                               cf->common.root_canon))
    {
        return;
    }

    (void) s3_apply_put_tagging_header(r, (const char *) fs_path,
                                       cf->common.root_canon);
    s3_put_finalize_ok(r, body_bytes, body_mode);
}
