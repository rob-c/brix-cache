/*
 * postconfig_internal.h - cross-file prototypes for the WebDAV
 * postconfiguration hook split across postconfig*.c siblings.
 *
 * WHAT: Declares the postconfiguration helpers that live in a sibling
 * translation unit but are invoked from ngx_http_brix_webdav_postconfiguration()
 * in postconfig.c.
 *
 * WHY: The proxy_ssl_capath second-half walk is a self-contained concept that
 * was extracted into postconfig_proxy_capath.c to keep every postconfig*.c file
 * under the size guard; its single entry point must be reachable from the hook.
 */
#ifndef BRIX_WEBDAV_POSTCONFIG_INTERNAL_H
#define BRIX_WEBDAV_POSTCONFIG_INTERNAL_H

#include "webdav.h"

/*
 * webdav_postconf_setup_proxy_capath - walk every location of every server
 * and apply the brix_proxy_ssl_capath second half where the directive is set.
 * Defined in postconfig_proxy_capath.c.
 */
ngx_int_t webdav_postconf_setup_proxy_capath(ngx_conf_t *cf,
                                             ngx_http_core_main_conf_t *cmcf);

#endif /* BRIX_WEBDAV_POSTCONFIG_INTERNAL_H */
