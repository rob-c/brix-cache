/*
 * tape_rest.h — WLCG HTTP Tape REST API router (Phase 35 / Phase 2).
 *
 * Exposes the standard /api/v1/{stage,release,unpin,archiveinfo,fileinfo}
 * surface so FTS / gfal2 can drive tape staging over davs:// against the same
 * durable FRM queue that root:// uses. The implementation lives in tape_rest.c;
 * dispatch.c routes /api/v1/ requests here when xrootd_webdav_tape_rest is on.
 */

#ifndef NGX_XROOTD_WEBDAV_TAPE_REST_H
#define NGX_XROOTD_WEBDAV_TAPE_REST_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * Handle a /api/v1/ Tape REST request. For GET/DELETE returns an NGX_HTTP_*
 * status (handled inline by the caller); for POST it dispatches async body
 * reading and returns NGX_DONE (the body handler finalises the request). The
 * caller must already have confirmed the /api/v1/ prefix and that tape_rest is
 * enabled.
 */
ngx_int_t webdav_tape_handle(ngx_http_request_t *r);

#endif /* NGX_XROOTD_WEBDAV_TAPE_REST_H */
