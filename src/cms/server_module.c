#include "server.h"


/* ------------------------------------------------------------------ */
/* Config callbacks                                                     */
/* ------------------------------------------------------------------ */

static void *
xrootd_cms_srv_create_conf(ngx_conf_t *cf)
{
    ngx_stream_xrootd_cms_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable   = NGX_CONF_UNSET;
    conf->interval = NGX_CONF_UNSET;

    return conf;
}


static char *
xrootd_cms_srv_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_xrootd_cms_srv_conf_t *prev = parent;
    ngx_stream_xrootd_cms_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable,   prev->enable,   0);
    ngx_conf_merge_value(conf->interval, prev->interval, 60);

    return NGX_CONF_OK;
}


/* ------------------------------------------------------------------ */
/* Directive: xrootd_cms_server on|off                                 */
/* ------------------------------------------------------------------ */

static char *
xrootd_cms_srv_set_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_stream_xrootd_cms_srv_conf_t  *conf = conf_ptr;
    ngx_stream_core_srv_conf_t        *cscf;
    char                              *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf_ptr);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (!conf->enable) {
        return NGX_CONF_OK;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = xrootd_cms_srv_handler;

    return NGX_CONF_OK;
}


/* ------------------------------------------------------------------ */
/* Directive table                                                      */
/* ------------------------------------------------------------------ */

static ngx_command_t  xrootd_cms_srv_commands[] = {

    { ngx_string("xrootd_cms_server"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      xrootd_cms_srv_set_enable,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_cms_srv_conf_t, enable),
      NULL },

    { ngx_string("xrootd_cms_server_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_cms_srv_conf_t, interval),
      NULL },

    ngx_null_command
};


/* ------------------------------------------------------------------ */
/* Module context and descriptor                                        */
/* ------------------------------------------------------------------ */

static ngx_stream_module_t  xrootd_cms_srv_module_ctx = {
    NULL,                        /* preconfiguration  */
    NULL,                        /* postconfiguration */
    NULL,                        /* create main conf  */
    NULL,                        /* init main conf    */
    xrootd_cms_srv_create_conf,  /* create srv conf   */
    xrootd_cms_srv_merge_conf,   /* merge srv conf    */
};


ngx_module_t  ngx_stream_xrootd_cms_srv_module = {
    NGX_MODULE_V1,
    &xrootd_cms_srv_module_ctx,
    xrootd_cms_srv_commands,
    NGX_STREAM_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};
