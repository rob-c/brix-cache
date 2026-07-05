/*
 * webdav/webdav_methods.h
 *
 * WebDAV HTTP-method handler prototypes dispatched from dispatch.c: OPTIONS,
 * HEAD/GET, PUT, DELETE, MKCOL, PROPFIND/PROPPATCH, SEARCH, ACL, MOVE, COPY,
 * LOCK/UNLOCK — plus the macaroon token-issuance endpoints and the XrdDig
 * entry point.  Split out of webdav.h so the request-method surface is grouped
 * by concern and individually reviewable.  Includes webdav.h for the shared
 * request/config types.
 */

#ifndef NGX_HTTP_BRIX_WEBDAV_METHODS_H
#define NGX_HTTP_BRIX_WEBDAV_METHODS_H

#include "webdav.h"

/* HTTP methods.  Unless noted, each fully handles its method and returns NGX_OK
 * or an NGX_HTTP_* status for the dispatcher to finalise; the `void` ones own
 * the response and finalise the request themselves (async/body paths). */
/* OPTIONS: emit DAV/DASL/Allow headers (Allow derived from the live op table). */
ngx_int_t webdav_handle_options(ngx_http_request_t *r);
/* HEAD/GET-metadata: resolve+stat, set Content-Length/Type/Last-Modified/ETag
 * and send headers; send_body=0 (or r->header_only) emits no body. */
ngx_int_t webdav_handle_head(ngx_http_request_t *r, int send_body);
/* GET a file body (range/multipart aware, cache-backed); 403 on a directory. */
ngx_int_t webdav_handle_get(ngx_http_request_t *r);
/* PUT: body read callback — streams the request body to the destination file
 * and finalises the request (it self-finalises; do not also return its rc). */
void webdav_handle_put_body(ngx_http_request_t *r);
/* DELETE: lock-checked recursive removal (204, or 404/409/500). */
ngx_int_t webdav_handle_delete(ngx_http_request_t *r);
/* Recursively remove the tree at `path` under confinement (no request/lock
 * context).  Returns the underlying remove-tree result. */
ngx_int_t webdav_delete_path_recursive(ngx_log_t *log, const char *root_canon,
    const char *path);
/* MKCOL: create one collection (201; 409 if parent missing, 405 if exists). */
ngx_int_t webdav_handle_mkcol(ngx_http_request_t *r);
/* PROPFIND: 207 Multi-Status (Depth 0/1) incl. live + dead properties + locks. */
ngx_int_t webdav_handle_propfind(ngx_http_request_t *r);
/* PROPPATCH: set/remove dead (xattr) properties; rejects protected DAV: props. */
ngx_int_t webdav_handle_proppatch(ngx_http_request_t *r);
/* SEARCH (RFC 5323 DAV:basicsearch) over the request-URI scope. */
ngx_int_t webdav_handle_search(ngx_http_request_t *r);
/* ACL: read-only export — always 403 with a cannot-modify-protected-property
 * error body (client-side ACL mutation is not permitted). */
ngx_int_t webdav_handle_acl(ngx_http_request_t *r);

/* MOVE: lock-checked rename within the export (201/204; may finalise -> NGX_DONE). */
ngx_int_t webdav_handle_move(ngx_http_request_t *r);
/* COPY: in-export copy (NOT third-party — see tpc_handle_copy for Source/Dest). */
ngx_int_t webdav_handle_copy(ngx_http_request_t *r);
/* LOCK: create/refresh a lock and send the lockdiscovery body; self-finalises. */
void webdav_handle_lock(ngx_http_request_t *r);
/* UNLOCK: remove the lock named by the Lock-Token header (204; 400/409/412). */
ngx_int_t webdav_handle_unlock(ngx_http_request_t *r);

/* Macaroon token issuance endpoints (macaroon_endpoint.c) */
/* GET /.well-known/oauth-authorization-server discovery document. */
ngx_int_t webdav_handle_macaroon_discovery(ngx_http_request_t *r);
/* POST /.oauth2/token: mint a scoped macaroon; self-finalises the request. */
void webdav_handle_macaroon_token(ngx_http_request_t *r);
/* POST <path> with Content-Type: application/macaroon-request (dCache/XrdMacaroons
 * convention): mint a macaroon from a JSON {caveats[],validity} body, returning the
 * dCache {macaroon, uri{...}} shape. Self-finalises the request. */
void webdav_handle_macaroon_request(ngx_http_request_t *r);

/* §3 XrdDig: GET/HEAD /.well-known/dig/<export>/<rel> — read-only, RESOLVE_BENEATH-
 * confined, allow-file-gated exposure of whitelisted server files. Returns an HTTP
 * status, or NGX_DECLINED when dig is disabled / the path is not a dig path (so
 * normal WebDAV handling proceeds). Defined in src/dig/dig.c. */
ngx_int_t brix_dig_handle(ngx_http_request_t *r);

#endif /* NGX_HTTP_BRIX_WEBDAV_METHODS_H */
