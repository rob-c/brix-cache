#ifndef BRIX_DASHBOARD_MODULE_INTERNAL_H
#define BRIX_DASHBOARD_MODULE_INTERNAL_H

/*
 * dashboard/module_internal.h - private cross-file declarations for the split
 * dashboard HTTP module implementation.
 *
 * WHAT: Declares symbols DEFINED in one dashboard module translation unit but
 *       REFERENCED from another after the mechanical file-size split of
 *       module.c into module.c + module_config.c + module_dispatch.c.
 * WHY:  A cross-file symbol must be non-static and declared once; symbols used
 *       within a single .c file stay static and are NOT listed here.
 * NOTE: Included by module.c, module_config.c and module_dispatch.c only.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * Directive setter for `brix_dashboard_users <file>` — loads an htpasswd-style
 * "username:hash" file into the loc-conf users array. Defined in
 * module_config.c; referenced from the command table in module.c.
 */
char *ngx_http_brix_dashboard_set_users(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

#endif /* BRIX_DASHBOARD_MODULE_INTERNAL_H */
