#include "metrics_internal.h"


static void *
ngx_http_xrootd_metrics_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_xrootd_metrics_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) { return NULL; }
    conf->enable = NGX_CONF_UNSET;
    return conf;
}


static char *
ngx_http_xrootd_metrics_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_xrootd_metrics_loc_conf_t *prev = parent;
    ngx_http_xrootd_metrics_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    return NGX_CONF_OK;
}


static char *
ngx_http_xrootd_metrics_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) { return rv; }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_xrootd_metrics_handler;
    return NGX_CONF_OK;
}


static ngx_command_t ngx_http_xrootd_metrics_commands[] = {

    { ngx_string("xrootd_metrics"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_xrootd_metrics_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_metrics_loc_conf_t, enable),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_xrootd_metrics_module_ctx = {
    NULL,                                      /* preconfiguration    */
    NULL,                                      /* postconfiguration   */
    NULL,                                      /* create main conf    */
    NULL,                                      /* init main conf      */
    NULL,                                      /* create srv conf     */
    NULL,                                      /* merge srv conf      */
    ngx_http_xrootd_metrics_create_loc_conf,   /* create loc conf     */
    ngx_http_xrootd_metrics_merge_loc_conf     /* merge loc conf      */
};


ngx_module_t ngx_http_xrootd_metrics_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_metrics_module_ctx,
    ngx_http_xrootd_metrics_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};
