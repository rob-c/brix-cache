/*
 * copy_internal.h - shared internal contract between the WebDAV COPY
 * orchestrator (copy.c) and the collection (directory) COPY machinery
 * (copy_collection.c).  Not part of the public webdav API.
 */

#ifndef BRIX_WEBDAV_COPY_INTERNAL_H
#define BRIX_WEBDAV_COPY_INTERNAL_H

#include "webdav.h"

/*
 * WHAT: The resolved, validated state of one COPY request: the confined source
 * and destination paths, their stat records, and the overwrite/depth flags plus
 * whether the destination already existed.
 *
 * WHY: The COPY handler's pre-flight (parse → resolve → validate) produces a
 * cluster of related values that the file and collection execute paths both
 * consume. Threading them as one struct keeps the orchestrator flat and each
 * pre-flight helper single-purpose, instead of a long function with a dozen
 * loose locals.
 *
 * HOW: Filled incrementally — webdav_copy_parse_request sets the flags and the
 * decoded destination, webdav_copy_resolve_pair fills the paths/stats/existed —
 * then read by the execute helpers. Zero-initialised at declaration.
 */
typedef struct {
    char         src_path[WEBDAV_MAX_PATH];
    char         dst_path[WEBDAV_MAX_PATH];
    char         dest_decoded[WEBDAV_MAX_PATH];
    struct stat  src_sb;
    struct stat  dst_sb;
    int          dst_existed;
    int          overwrite;
    int          depth_infinity;
} webdav_copy_req_t;

/*
 * Execute a collection (directory) COPY for a resolved request — offload to the
 * thread pool when possible, else run it inline.  Returns NGX_DONE when queued,
 * NGX_OK on inline success, or an HTTP error status.  Defined in
 * copy_collection.c.
 */
ngx_int_t
webdav_copy_do_collection(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const webdav_copy_req_t *req);

#endif /* BRIX_WEBDAV_COPY_INTERNAL_H */
