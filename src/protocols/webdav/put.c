/*
 * put.c - WebDAV PUT body handling, including optional thread-pool writes.
 *
 * Phase 39 (WS8/HTTP-4): the body is written to a staged temp file and atomically
 * renamed onto the final path on success (brix_staged_open/commit/abort, the
 * same crash-safe lifecycle S3 PUT uses).  So a client that drops mid-upload, a
 * crash, or a failed inflate never leaves a partial/truncated object at the final
 * path, and a concurrent GET only ever observes the old or the new object — never
 * a half-written one.
 */

#include "webdav.h"
#include "core/http/etag.h"
#include "core/http/http_body.h"
#include "core/compat/integrity_info.h"
#include "core/http/http_conditionals.h"
#include "core/compat/range.h"
#include "core/compat/staged_file.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "fs/vfs/vfs.h"
#include "auth/impersonate/lifecycle.h"
#include "fs/path/path.h"
#include "core/compat/cstr.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "put_internal.h"

/*
 * webdav_handle_put_body — write the request body to the destination file.
 *
 * This is the ngx_http_read_client_request_body() completion callback.  By
 * the time it runs, nginx has either buffered the body in memory
 * (r->request_body->bufs with in_file=0) or spooled it to a temp file
 * (in_file=1).
 *
 * The body is always written to a STAGED temp file (brix_staged_open) and
 * atomically committed onto the final path on success (brix_staged_commit) or
 * aborted on any error (brix_staged_abort) — so a partial/failed/aborted PUT
 * never leaves a readable object at the final path (WS8/HTTP-4).
 *
 * The function chooses one of three write paths in order of preference:
 *   1. Thread-pool async write (NGX_THREADS && memory body only): streams the
 *      body to the staged fd on the pool and commits in webdav_put_aio_done().
 *   2. Synchronous spooled-file copy.
 *   3. Synchronous in-memory write (+ optional inflate).
 *
 * Preconditions: the caller holds a reference count increment on r->main
 *   (done by ngx_http_read_client_request_body) so nginx will not free the
 *   request while this callback is pending.
 *
 * Ownership: the staged temp is opened here.  The async path transfers the
 *   staged struct into the task (committed/aborted in the done handler); the
 *   synchronous paths commit or abort before sending the response.
 *
 * Pool allocation lifetime: all ngx_palloc calls here use r->pool.
 */
static void webdav_put_body_inner(ngx_http_request_t *r);

/*
 * Phase 40: the PUT body is read asynchronously, so the outer dispatch wrapper
 * has already cleared the impersonation principal by the time this callback runs.
 * Re-establish it for the duration of the (synchronous) body write — the staged
 * open (brix_staged_open) then routes to the broker and the new file is
 * owned by the mapped user.  No-op unless map mode is active.
 */
void
webdav_handle_put_body(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    webdav_put_body_inner(r);
    brix_imp_request_end();
}

/*
 * webdav_put_commit — atomically publish the staged temp and reply.
 *
 * WHAT: Commits the staged temp onto the final path (excl=0 == replace),
 *   persists any on-write checksums, and sends the terminal 201/204 with a
 *   zero-length body.  A commit failure logs the path and finalizes 500.
 *
 * WHY: The commit + checksum + status trio is the single success epilogue for
 *   the sync and empty-PUT paths; keeping it here mirrors the async done
 *   handler's tail and keeps the orchestrator flat.  Status codes/headers are
 *   byte-identical to the prior inline tail.
 *
 * HOW:
 *   1. brix_vfs_staged_commit; failure → log + finalize 500, return.
 *   2. Persist checksum-on-write digests (§8.3, best-effort).
 *   3. Emit 201 Created (new file) or 204 No Content, content-length 0, send
 *      headers, and finalize with ngx_http_send_special(NGX_HTTP_LAST).
 */
static void
webdav_put_commit(ngx_http_request_t *r, const char *path,
    brix_vfs_staged_t *staged, int created)
{
    ngx_int_t status;

    brix_dashboard_http_finish(r);

    /* Atomically publish the staged temp onto the final path (an empty PUT
     * commits an empty file).  excl=0 == replace (the prior brix_staged_commit
     * non-EXCL semantics). */
    if (brix_vfs_staged_commit(staged, 0) != NGX_OK) {
        brix_log_safe_path(r->connection->log, NGX_LOG_ERR, ngx_errno,
                             "brix_webdav: staged commit failed for: \"%s\"",
                             path);
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    webdav_put_persist_checksums(r, path);   /* §8.3 */

    status = created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    /* r->header_only is false for PUT (clients don't send HEAD-like PUT);
     * no need to check it here, but ngx_http_send_special handles it. */
    webdav_metrics_finalize_request(r, ngx_http_send_special(r,
                                                             NGX_HTTP_LAST));
}

static void
webdav_put_body_inner(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf;
    char                             path[WEBDAV_MAX_PATH];
    brix_vfs_ctx_t                   vctx;
    brix_vfs_staged_t               *staged = NULL;
    int                              created = 0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);

    if (webdav_put_precheck(r, conf, path, &created) == WEBDAV_PUT_DONE) {
        return;
    }

    if (webdav_put_open_target(r, conf, path, &vctx, &staged)
        == WEBDAV_PUT_DONE)
    {
        return;
    }

    if (webdav_put_stream_body(r, conf, path, staged, created)
        == WEBDAV_PUT_DONE)
    {
        return;
    }

    webdav_put_commit(r, path, staged, created);
}
