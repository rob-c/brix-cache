#ifndef XROOTD_READ_SLICE_READ_H
#define XROOTD_READ_SLICE_READ_H

/*
 * slice_read.h — Phase 26 Step D: stream-plane slice-cache open and read.
 *
 * When xrootd_cache_slice is configured, a read-mode kXR_open on a cacheable
 * path registers a "slice-mode" handle (xrootd_file_t.slice_mode) instead of
 * fetching the whole file: the handle records the whole-file cache path and the
 * origin clean path, and kXR_read is served from per-slice cache files, filling
 * missing slices from the origin (suspending the request like the whole-file
 * cache fill does).
 */

#include "../ngx_xrootd_module.h"

/*
 * xrootd_open_slice_handle — open a slice-mode read handle.
 *
 * Schedules an async fill of slice 0 (which also discovers the origin file size
 * for the open response) and, in the completion callback, registers the
 * slice-mode handle and sends the kXR_open response.  Returns NGX_OK with the
 * connection suspended in XRD_ST_AIO, or an error response on failure.
 *
 * cache_path is the whole-file cache path (cache_root + rel clean_path); slice
 * files are named off it.  Called from xrootd_open_cached_read after the VO ACL
 * check, only when conf->cache_slice_size > 0.
 */
ngx_int_t xrootd_open_slice_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *clean_path,
    const char *cache_path, uint16_t options);

/*
 * xrootd_read_from_slices — serve a kXR_read from the slice cache.
 *
 * Enumerates the slices covering [offset, offset+rlen).  If all are present,
 * stitches them into the response.  If any is missing, schedules a fill for the
 * first missing slice and suspends the request; the fill's completion callback
 * re-enters this function.  Called from xrootd_handle_read when the handle is
 * slice_mode.
 */
ngx_int_t xrootd_read_from_slices(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, off_t offset, size_t rlen);

#endif /* XROOTD_READ_SLICE_READ_H */
