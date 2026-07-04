/*
 * module_acc_directives.h — declarations for the shared XrdAcc HTTP directive
 * setters (defined in module_acc_directives.c).
 *
 * These back the brix_acc_* HTTP directives and are referenced by the WebDAV
 * command table in module.c.  Each setter populates BOTH the WebDAV and S3
 * loc-confs, so the directive is registered only once.
 */
#ifndef BRIX_WEBDAV_MODULE_ACC_DIRECTIVES_H
#define BRIX_WEBDAV_MODULE_ACC_DIRECTIVES_H

#include <ngx_config.h>
#include <ngx_core.h>

char *brix_http_set_ktls(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_acc_http_set_authdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_acc_http_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_acc_http_set_audit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_acc_http_set_refresh(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_acc_http_set_gidlifetime(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *brix_acc_http_set_nisdomain(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *brix_acc_http_set_pgo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_acc_http_set_resolve_hosts(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *brix_acc_http_set_spacechar(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *brix_acc_http_set_encoding(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *brix_acc_http_set_gidretran(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#endif /* BRIX_WEBDAV_MODULE_ACC_DIRECTIVES_H */
