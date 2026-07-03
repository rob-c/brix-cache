#ifndef BRIX_HTTP_SERVE_OFFLOAD_H
#define BRIX_HTTP_SERVE_OFFLOAD_H

/*
 * http_serve_offload.h - off-event-loop serve of a remote (socket-wire) object
 * (phase-64 SP3: the serve-readback complement to the off-loop cache FILL).
 *
 * WHAT: One helper, brix_http_serve_offload_remote(), that the WebDAV GET and S3
 *       GetObject handlers call BEFORE the inline brix_vfs_open when the export's
 *       serve path reads from a socket-wire backend (xroot) - a primary root://
 *       backend, or a cache_store / stage_store served from one. It runs the WHOLE
 *       read - driver open (eager connect), cinfo load, miss fill, and the byte
 *       read - on the thread pool, materialising the object into a local temp file,
 *       then serves THAT through the normal sendfile pipeline.
 *
 * WHY:  A socket wire client (sd_xroot) cannot do blocking I/O on the un-pumped
 *       event loop: not just the byte read (file_serve.c memory-backed serve) but
 *       even the open (sd_xroot_open eagerly connects + stats) and the cinfo load
 *       (kXR_fattr on a remote cache_store) fail there. So the entire serve, from
 *       open onward, must move off the loop - the read-only complement to the
 *       off-loop FILL that already moved cache-miss writes off the loop. In-process
 *       (rados) and curl (s3/http) backends block-but-complete on-loop and are
 *       served inline as before.
 *
 * HOW:  A single thread task opens the composed instance for `key` (a cache open
 *       runs cinfo/fill/serve; a bare backend just opens), copies the object into an
 *       O_TMPFILE temp, and closes it. The completion adopts the temp fd as a POSIX
 *       VFS handle and calls brix_http_serve_file_ranged on it (zero-copy
 *       sendfile, owning range/headers/backpressure/lifecycle), runs the caller's
 *       protocol metrics callback, and finalises. A non-socket serve, a HEAD, or no
 *       thread pool returns NGX_DECLINED so the caller serves inline as before.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "file_serve.h"                 /* brix_http_serve_opts_t/_result_t */
#include "core/config/shared_conf.h"      /* ngx_http_brix_shared_conf_t */
#include "fs/backend/sd.h"           /* brix_sd_instance_t */

/* Protocol metrics callback: run on the event loop after the materialised object is
 * served, with the same result the inline serve would report. WebDAV and S3 pass
 * their own (range_total / bytes_tx_total increments). */
typedef void (*brix_http_serve_metrics_pt)(ngx_http_request_t *r,
    const brix_http_serve_result_t *result);

/*
 * Serve `key` on the composed instance `inst` off the event loop when its serve
 * path reads from a socket-wire backend; otherwise decline so the caller serves
 * inline (its own brix_vfs_open + brix_http_serve_file_ranged).
 *
 * Returns:
 *   NGX_DECLINED - not a socket-wire serve (local / in-process / curl / HEAD / no
 *                  pool): the caller proceeds with its normal inline open + serve.
 *   NGX_DONE     - offloaded; the request is suspended. The caller MUST return
 *                  NGX_DONE without opening the object itself.
 *   NGX_ERROR    - setup failed; the caller should return 500.
 */
ngx_int_t brix_http_serve_offload_remote(ngx_http_request_t *r,
    brix_sd_instance_t *inst, const char *key, const char *fs_path,
    const brix_http_serve_opts_t *opts,
    ngx_http_brix_shared_conf_t *common,
    brix_http_serve_metrics_pt metrics_cb);

#endif /* BRIX_HTTP_SERVE_OFFLOAD_H */
