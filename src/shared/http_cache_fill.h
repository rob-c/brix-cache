#ifndef XROOTD_HTTP_CACHE_FILL_H
#define XROOTD_HTTP_CACHE_FILL_H

/*
 * http_cache_fill.h - off-event-loop cache-miss fill for the HTTP read plane
 * (phase-64 SP2 "shell -> full").
 *
 * WHAT: One helper, xrootd_http_cache_fill_if_needed(), that the WebDAV GET and
 *       S3 GetObject handlers call before their inline open+serve. When a read
 *       would be a cache MISS over a remote tier (a source the worker must reach
 *       over a socket, or a store it writes over the network), the helper runs
 *       the fill on the shared thread pool and suspends the request, re-entering
 *       the handler - now a cache HIT, served zero-copy - on completion.
 *
 * WHY:  The cache decorator (sd_cache) fills a miss synchronously inside open().
 *       That is correct on a worker thread but a stall on the nginx event loop:
 *       a socket wire client (sd_xroot) cannot do blocking I/O on the un-pumped
 *       loop (it fails EIO), and an in-process store (rados) freezes the whole
 *       worker for the transfer. The HTTP data plane runs storage I/O on the
 *       loop, so the fill must be moved off it. This mirrors the established
 *       thread-task pattern already used by WebDAV COPY/MOVE/PUT and S3 PUT.
 *
 * HOW:  xrootd_sd_cache_fill_needs_offload() answers (without blocking) whether
 *       the inline open would stall; if so the helper posts an
 *       xrootd_sd_cache_fill_key() task and takes r->main->count++, returning
 *       NGX_DONE. The completion event (on the loop) re-enters the handler on
 *       success or finalizes with 502 on a fill failure. A COMPLETE hit, a local
 *       source+store, a slice object, or a missing thread pool all return
 *       NGX_DECLINED so the caller proceeds with its normal inline path.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../config/shared_conf.h"      /* ngx_http_xrootd_shared_conf_t */
#include "../fs/backend/sd.h"           /* xrootd_sd_instance_t */

/* The handler re-entry callback: invoked on the event loop after a successful
 * fill to serve the now-cached object. `data` is the opaque pointer passed to
 * xrootd_http_cache_fill_if_needed (NULL for handlers that re-resolve from r).
 * Returns the handler's terminal rc (passed to ngx_http_finalize_request). */
typedef ngx_int_t (*xrootd_http_cache_reenter_pt)(ngx_http_request_t *r,
    void *data);

/*
 * If a read-open of `key` on `inst` (the composed storage instance) would block
 * the event loop on a remote cache-miss fill, offload the fill to the shared
 * thread pool and suspend the request (held via r->main->count++); the request
 * is re-entered through reenter(r, reenter_data) once the object is cached.
 *
 * Returns:
 *   NGX_DECLINED - no offload needed (hit / local tier / non-cache / no pool):
 *                  the caller proceeds with its normal inline open + serve.
 *   NGX_DONE     - fill posted; the request is suspended. The caller MUST return
 *                  NGX_DONE up the stack without further touching r.
 *   NGX_ERROR    - task alloc/post failed; the caller should return 500.
 */
ngx_int_t xrootd_http_cache_fill_if_needed(ngx_http_request_t *r,
    xrootd_sd_instance_t *inst, const char *key,
    ngx_http_xrootd_shared_conf_t *common,
    xrootd_http_cache_reenter_pt reenter, void *reenter_data);

#endif /* XROOTD_HTTP_CACHE_FILL_H */
