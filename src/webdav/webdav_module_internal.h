/*
 * webdav_module_internal.h - private split contract for module.c and its Phase-38 siblings.
 * Not a public API: include only from src/webdav/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_WEBDAV_MODULE_INTERNAL_H
#define XROOTD_WEBDAV_MODULE_INTERNAL_H

#include "webdav.h"
#include "module_acc_directives.h" 
#include "compat/integrity_info.h"   
#include "acc/acc.h"            
#include "s3/s3.h"
#include "shm/kv.h"             
#include "shm/rate_limit.h"     
#include "token/token_cache.h"  
#include "mirror/http_mirror.h" 
#include "ratelimit/ratelimit.h" 
#include <curl/curl.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
extern ngx_conf_enum_t  webdav_auth_values[];
extern ngx_conf_enum_t  xrootd_webdav_cks_xattr_formats[];

extern ngx_command_t ngx_http_xrootd_webdav_commands[];
extern ngx_http_module_t ngx_http_xrootd_webdav_module_ctx;


/* module_directives.c */
char * webdav_conf_add_cors_origin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char * webdav_conf_dig_export(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char * webdav_conf_proxy_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr);
ngx_int_t webdav_open_file_cache_arg(ngx_str_t *arg, ngx_int_t *max, time_t *inactive, ngx_flag_t *off);
char * webdav_conf_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* module_init.c */
ngx_int_t xrootd_http_protocol_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t xrootd_http_add_protocol_variables(ngx_conf_t *cf);
ngx_int_t ngx_http_xrootd_webdav_preconfiguration(ngx_conf_t *cf);
ngx_int_t ngx_http_xrootd_webdav_init_process(ngx_cycle_t *cycle);
void ngx_http_xrootd_webdav_exit_process(ngx_cycle_t *cycle);

#endif /* XROOTD_WEBDAV_MODULE_INTERNAL_H */
