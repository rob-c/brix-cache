#ifndef BRIX_WEBDAV_LOCKS_REQUEST_H
#define BRIX_WEBDAV_LOCKS_REQUEST_H

#include "protocols/webdav/webdav.h"

/*
 * Parse the WebDAV "Timeout" request header into an ABSOLUTE expiry instant.
 * Returns ngx_time() + seconds, i.e. an absolute Unix WALL-CLOCK-seconds deadline
 * (not a duration, and NOT the monotonic ngx_current_msec — the value is
 * persisted in the lock xattr and must survive a reboot). Accepts "Second-<n>"
 * and "Infinite"; missing/garbage defaults to 3600s. Requested seconds are
 * clamped to [1, conf->lock_timeout], so "Infinite" and any oversized value
 * yield conf->lock_timeout. Never fails.
 */
int64_t webdav_lock_parse_timeout(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf);
/*
 * Test whether the client presented a given lock token for refresh/unlock.
 * Returns 1 if NUL-terminated C string `token` occurs as a SUBSTRING of the
 * "If" header (falling back to "Lock-Token" for noncompliant clients), else 0.
 * Note: substring match, not a structured "If"-list parse; `token` is borrowed.
 */
int webdav_lock_if_header_matches(ngx_http_request_t *r, const char *token);
/*
 * Parse the "Depth" header for LOCK. Sets *depth_infinity to 0 only for "0",
 * to 1 for absent or "infinity" (default = infinity per RFC 4918). Returns
 * NGX_OK, or NGX_HTTP_BAD_REQUEST for any other depth value (e.g. "1").
 */
ngx_int_t webdav_lock_parse_depth(ngx_http_request_t *r,
    int *depth_infinity);
/*
 * Parse the LOCKINFO XML request body. Writes the lock owner into caller-owned
 * `owner` (NUL-terminated, truncated to owner_len) and sets *exclusive (default
 * 1 = exclusive). No-op if owner_len == 0; on absent/empty body owner becomes
 * "" and *exclusive stays 1. Borrows the already-buffered r->request_body;
 * does not read from the socket. Returns nothing (best-effort, never fails).
 */
void webdav_lock_parse_body(ngx_http_request_t *r, char *owner,
    size_t owner_len, int *exclusive);

#endif /* BRIX_WEBDAV_LOCKS_REQUEST_H */
