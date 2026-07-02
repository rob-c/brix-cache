#ifndef XROOTD_DIRLIST_H
#define XROOTD_DIRLIST_H

#include "core/ngx_xrootd_module.h"

/*
 * xrootd_handle_dirlist — directory listing with optional per-entry dStat.
 *
 * @ctx:    stream session context (file-handle table, protocol state)
 * @c:      nginx connection for sending kXR_oksofar/kXR_ok wire responses
 * @conf:   server configuration containing root path and dirlist settings
 *
 * Opens the requested directory via openat(), iterates entries with readdir(),
 * dispatches to per-entry formatters (stat body + optional checksum token),
 * sends chunked kXR_oksofar continuation frames for large directories,
 * terminates with kXR_ok when listing completes. Supports plain mode
 * (filename-only) and dStat mode (per-entry stat line with inode/size/mtime).
 *
 * Returns NGX_OK on successful listing, NGX_ERROR if directory cannot be opened.
 */
ngx_int_t xrootd_handle_dirlist(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif /* XROOTD_DIRLIST_H */
