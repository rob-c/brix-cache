/*
 * module.c - (kept) module glue only: the ngx_module_t definition and its
 * ngx_http_module_t context — the symbols nginx wires by name. The directive
 * command table + enum value arrays were split verbatim into module_commands.c
 * (see webdav_module_internal.h for the cross-TU extern contract).
 * Phase-38 split of module.c; behavior-identical.
 */
#include "webdav_module_internal.h"

ngx_module_t ngx_http_brix_webdav_module = {
    NGX_MODULE_V1,
    &ngx_http_brix_webdav_module_ctx,
    ngx_http_brix_webdav_commands,
    NGX_HTTP_MODULE,
    NULL,  /* init_master */
    NULL,  /* init_module */
    ngx_http_brix_webdav_init_process,  /* init_process */
    NULL,  /* init_thread */
    NULL,  /* exit_thread */
    ngx_http_brix_webdav_exit_process,  /* exit_process */
    NULL,  /* exit_master */
    NGX_MODULE_V1_PADDING
};
ngx_http_module_t ngx_http_brix_webdav_module_ctx = {
    ngx_http_brix_webdav_preconfiguration,  /* preconfiguration */
    ngx_http_brix_webdav_postconfiguration, /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */
    ngx_http_brix_webdav_create_loc_conf,   /* create location config */
    ngx_http_brix_webdav_merge_loc_conf,    /* merge location config */
};
