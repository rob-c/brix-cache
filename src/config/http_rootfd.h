#ifndef XROOTD_HTTP_ROOTFD_H
#define XROOTD_HTTP_ROOTFD_H

/*
 * http_rootfd.h — persistent confinement rootfd for the HTTP protocols.
 *
 * WHAT: Opens the O_PATH directory fd (common->rootfd) that WebDAV and S3 file
 *       operations anchor openat2(RESOLVE_BENEATH) on, mirroring the stream
 *       module's per-worker rootfd (src/config/process.c).
 *
 * WHY: The kernel-confinement API (src/path/beneath.h) needs a persistent fd on
 *      the export root. The stream side opens it per worker in init_process by
 *      iterating cmcf->servers. HTTP location config (root_canon) is finalised
 *      per-location in merge_loc_conf, so the natural, walk-free place to open it
 *      is right after canonicalisation succeeds.
 *
 * HOW: Called from the WebDAV/S3 merge_loc_conf once root_canon is set. Opens
 *      the fd in the master at config time (inherited by every worker via fork —
 *      an O_PATH directory handle is safe to share) and registers a cf->pool
 *      cleanup so the fd is closed when the cycle is torn down on reload/shutdown
 *      — no fd accumulation across reloads. No-op when the protocol is disabled
 *      or no export root is configured (rootfd stays -1).
 */

#include "shared_conf.h"

char *xrootd_http_open_rootfd(ngx_conf_t *cf,
                              ngx_http_xrootd_shared_conf_t *common);

#endif /* XROOTD_HTTP_ROOTFD_H */
