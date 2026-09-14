/* darwin_config_stub.h — common body for existing Darwin configuration stubs.
 * Requires: ngx_conf_t and ngx_command_t from the nginx headers.
 * These handlers retain the port's current no-op behavior; this helper does
 * not provide certificate validation or establish native Darwin coverage.
 */
#pragma once

/* WHAT: Preserve the existing stub result for unused configuration arguments.
 * WHY: Keep the provisional Darwin directive bodies in one place.
 * HOW: Mark arguments unused and return the existing NGX_CONF_OK result.
 */
static inline char *
brix_webdav_darwin_config_stub(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    (void) cf;
    (void) cmd;
    (void) conf;
    return NGX_CONF_OK;
}
