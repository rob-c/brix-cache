#ifndef XROOTD_DIRLIST_H
#define XROOTD_DIRLIST_H

#include "../ngx_xrootd_module.h"

/* kXR_dirlist — directory listing with optional per-entry dStat. */
ngx_int_t xrootd_handle_dirlist(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif /* XROOTD_DIRLIST_H */
