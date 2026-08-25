/* conf_handler.h — shared directive-setter glue for HTTP content-handler
 * endpoints.
 *
 * WHAT: brix_conf_flag_install_handler — parse an `on|off` directive via
 *       ngx_conf_set_flag_slot and, when the parse succeeds, install the
 *       given content handler on the enclosing location's core loc-conf.
 *
 * WHY:  Every endpoint-style directive (brix_metrics, brix_health, brix_srr,
 *       brix_dashboard, …) repeats the same two steps; each module's setter
 *       reduces to a one-line wrapper naming its handler.
 */
#ifndef BRIX_CORE_CONFIG_CONF_HANDLER_H
#define BRIX_CORE_CONFIG_CONF_HANDLER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static inline char *
brix_conf_flag_install_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf,
    ngx_http_handler_pt handler)
{
    ngx_http_core_loc_conf_t *clcf;
    char                     *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = handler;
    return NGX_CONF_OK;
}

#endif /* BRIX_CORE_CONFIG_CONF_HANDLER_H */
