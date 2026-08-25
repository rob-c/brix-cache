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
char *brix_http_set_cache_store_endpoint(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *brix_acc_http_set_authdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_acc_http_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_acc_http_set_audit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* Generic scalar setters: cmd->offset carries the offsetof into
 * brix_acc_http_t (nginx *_slot pattern). _num sets an ngx_int_t
 * (brix_authdb_refresh, brix_acc_gidlifetime); _onoff an ngx_flag_t
 * (brix_acc_pgo, brix_acc_resolve_hosts, brix_acc_encoding). */
char *brix_acc_http_set_num(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_acc_http_set_onoff(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *brix_acc_http_set_nisdomain(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *brix_acc_http_set_spacechar(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *brix_acc_http_set_gidretran(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#endif /* BRIX_WEBDAV_MODULE_ACC_DIRECTIVES_H */
