/* MOVE's paired client-visible and confined destination representation.
 * Requires the WebDAV request and location types from webdav.h.
 */
#pragma once

#include "webdav.h"

/* Destination carries both policy and storage representations.  Keeping them
 * together prevents a later caller from authorizing the client-visible name
 * while mutating a separately decoded/confined path. */
typedef struct {
    char logical[WEBDAV_MAX_PATH];
    char resolved[WEBDAV_MAX_PATH];
} webdav_move_destination_t;

ngx_int_t webdav_move_resolve_dest(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, webdav_move_destination_t *dest);
