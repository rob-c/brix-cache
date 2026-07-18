/*
 * webdav_module_internal.h - private split contract for module.c and its Phase-38 siblings.
 * Not a public API: include only from src/webdav/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_WEBDAV_MODULE_INTERNAL_H
#define BRIX_WEBDAV_MODULE_INTERNAL_H

#include "webdav.h"
#include "module_acc_directives.h" 
#include "core/compat/integrity_info.h"   
#include "auth/authz/acc/acc.h"            
#include "protocols/s3/s3.h"
#include "core/shm/kv.h"             
#include "core/shm/rate_limit.h"     
#include "auth/token/token_cache.h"  
#include "net/mirror/http_mirror.h" 
#include "net/ratelimit/ratelimit.h" 
#include <curl/curl.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
extern ngx_conf_enum_t  webdav_auth_values[];
extern ngx_conf_enum_t  brix_webdav_cks_xattr_formats[];

extern ngx_command_t ngx_http_brix_webdav_commands[];
extern ngx_http_module_t ngx_http_brix_webdav_module_ctx;


/* module_directives.c */
char * webdav_conf_add_cors_origin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char * webdav_conf_dig_export(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char * webdav_conf_proxy_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr);
ngx_int_t webdav_open_file_cache_arg(ngx_str_t *arg, ngx_int_t *max, time_t *inactive, ngx_flag_t *off);
char * webdav_conf_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* module_init.c */
ngx_int_t brix_http_protocol_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t brix_http_delegated_cred_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t brix_http_add_protocol_variables(ngx_conf_t *cf);
ngx_int_t ngx_http_brix_webdav_preconfiguration(ngx_conf_t *cf);
ngx_int_t ngx_http_brix_webdav_init_process(ngx_cycle_t *cycle);
void ngx_http_brix_webdav_exit_process(ngx_cycle_t *cycle);

#endif /* BRIX_WEBDAV_MODULE_INTERNAL_H */
