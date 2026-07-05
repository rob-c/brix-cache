/*
 * webdav/webdav_lock.h
 *
 * WebDAV LOCK support: the xattr-backed lock record encode/decode/read/write/
 * delete primitives (prop_xattr.c), the startup sweep, the path/tree lock
 * checks enforced before mutating methods, and the <D:lockdiscovery> /
 * <D:supportedlock> body builders.  Split out of webdav.h so the LOCK surface
 * is grouped by concern and individually reviewable.  Includes webdav.h for the
 * shared request/config/lock-record types.
 */

#ifndef NGX_HTTP_BRIX_WEBDAV_LOCK_H
#define NGX_HTTP_BRIX_WEBDAV_LOCK_H

#include "webdav.h"

/* Lock xattr encode/decode/read/write/delete (prop_xattr.c) */
/* Serialise a lock entry to the pipe-delimited xattr value form in out[outsz].
 * NGX_OK, or NGX_ERROR if it would not fit. */
ngx_int_t webdav_lock_xattr_encode(const webdav_lock_xattr_t *e,
    char *out, size_t outsz);
/* Parse a stored lock value raw[rawlen] back into *e.  NGX_OK; NGX_DECLINED if
 * empty/oversized or no token field was found (not a valid lock record). */
ngx_int_t webdav_lock_xattr_decode(const char *raw, size_t rawlen,
    webdav_lock_xattr_t *e);
/* setxattr the encoded lock onto `path`.  Pass flags=XATTR_CREATE for atomic
 * cross-worker lock acquisition: NGX_DECLINED means another worker won the race
 * (EEXIST -> caller maps to 423).  NGX_OK / NGX_ERROR otherwise.  Takes the
 * request (not just a log) so the lock xattr is written as the mapped user under
 * impersonation (root_canon is derived from the request's loc conf). */
ngx_int_t webdav_lock_xattr_write(ngx_http_request_t *r, const char *path,
    const webdav_lock_xattr_t *e, int flags);
/* getxattr+decode the lock on `path`.  NGX_OK; NGX_DECLINED if no lock present
 * (or path gone); NGX_ERROR on a real getxattr fault. */
ngx_int_t webdav_lock_xattr_read(ngx_http_request_t *r, const char *path,
    webdav_lock_xattr_t *e);
/* removexattr the lock on `path`.  Idempotent: NGX_OK even if absent; NGX_ERROR
 * only on an unexpected fault. */
ngx_int_t webdav_lock_xattr_delete(ngx_http_request_t *r, const char *path);

/*
 * webdav_lock_startup_sweep — recursively remove every persisted lock xattr
 * (WEBDAV_LOCK_XATTR_KEY) under root_canon.  Used at startup when
 * brix_webdav_lock_startup_sweep is on, to restore ephemeral lock semantics.
 * Returns the number of lock xattrs removed.
 */
ngx_uint_t webdav_lock_startup_sweep(ngx_pool_t *pool, ngx_log_t *log,
    const char *root_canon);

/* Walk path -> export root checking each level's lock xattr (O(path_depth)
 * getxattr calls); expired locks are lazily deleted in passing.  NGX_HTTP_LOCKED
 * if an unexpired lock not matched by the request If header covers `path`; 500
 * on a getxattr fault; NGX_OK otherwise.  need_write is currently advisory. */
ngx_int_t webdav_check_locks(ngx_http_request_t *r, const char *path,
    int need_write);
/* webdav_check_locks() plus, when `path` is a directory, a recursive descendant
 * scan (opendir walk).  Use for DELETE/COPY/MOVE on collections so a lock on any
 * child blocks the op.  Same return codes as webdav_check_locks(). */
ngx_int_t webdav_check_locks_tree(ngx_http_request_t *r, const char *path);
/* Append <D:lockdiscovery> for `path` to the head/tail chain (r->pool), reading
 * the live lock xattr (empty element if none/expired; owner XML-escaped; expired
 * locks lazily deleted).  NGX_OK / NGX_ERROR on chain alloc failure. */
ngx_int_t webdav_lock_append_discovery(ngx_http_request_t *r, const char *path,
    ngx_chain_t **head, ngx_chain_t **tail);
/* Append the static <D:supportedlock> element (exclusive+shared write) to the
 * head/tail chain (r->pool).  NGX_OK / NGX_ERROR on chain alloc failure. */
ngx_int_t webdav_lock_append_supported(ngx_http_request_t *r,
    ngx_chain_t **head, ngx_chain_t **tail);

#endif /* NGX_HTTP_BRIX_WEBDAV_LOCK_H */
