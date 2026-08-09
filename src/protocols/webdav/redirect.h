#ifndef BRIX_WEBDAV_REDIRECT_H
#define BRIX_WEBDAV_REDIRECT_H

/*
 * webdav/redirect.h — §6.1 HTTP redirect-to-dataserver + signed-CGI handoff.
 *
 * Two halves, one contract (see redirect.c):
 *
 *   webdav_redirect_dataserver() — MANAGER side, called from the content
 *   dispatcher for GET/HEAD/PUT.  With brix_webdav_redirect_dataserver on
 *   and a CMS-registry data server matching the request path, answers 307
 *   with Location = <scheme>://<node>:<port><path>?<client CGI>&<signed
 *   identity CGI> and returns the finished status; returns NGX_DECLINED to
 *   serve locally (feature off, no registry match, or a loop guard hit).
 *
 *   webdav_redirect_signed_auth() — DATA-SERVER side, called FIRST in the
 *   access-phase authentication gate.  A request carrying brixrdr.mac is
 *   verified against brix_http_secretkey (HMAC-SHA256 over method, path,
 *   expiry, user, vo; constant-time compare; expiry window) and, on success,
 *   the embedded identity is adopted (NGX_OK — skip other credential
 *   sources).  A bad/expired MAC is 403, fail-closed (NGX_HTTP_FORBIDDEN);
 *   a request without the CGI — or a server without the key — is
 *   NGX_DECLINED (normal authentication proceeds).
 *
 * Requires: webdav.h before inclusion.
 */

ngx_int_t webdav_redirect_dataserver(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf);

ngx_int_t webdav_redirect_signed_auth(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf);

#endif /* BRIX_WEBDAV_REDIRECT_H */
