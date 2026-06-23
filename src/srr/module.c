/*
 * module.c — nginx HTTP sub-module for the WLCG SRR endpoint.
 *
 * WHAT: Declares ngx_http_xrootd_srr_module: the xrootd_srr* directives, the
 *   per-location config lifecycle (create/merge), and the binding of the
 *   content handler.  Standalone HTTP module, exactly like the /metrics module
 *   (src/metrics/module.c).
 *
 * WHY: Keeping SRR in its own location-level module means a site enables it with
 *   one `xrootd_srr on;` inside whatever location it wants the document served
 *   at (commonly /.well-known/wlcg-storage-resource-reporting or /srr), then
 *   records that URL in CRIC.  No interaction with the data-plane modules.
 *
 * HOW: `xrootd_srr` is a FLAG that also sets clcf->handler.  The string fields
 *   use ngx_conf_set_str_slot; the repeatable share/endpoint directives use
 *   custom setters that push onto per-location ngx_array_t's.
 *
 * Directives:
 *   xrootd_srr               on|off          enable + bind handler
 *   xrootd_srr_name          <name>          storageservice.name
 *   xrootd_srr_id            <id>            storageservice.id (default = name)
 *   xrootd_srr_quality       <level>         qualitylevel (default "production")
 *   xrootd_srr_version       <ver>           implementationversion (default "1.0")
 *   xrootd_srr_share         <name> <path> [vos]   repeatable storageshares[] entry
 *   xrootd_srr_endpoint      <name> <iftype> <url>  repeatable storageendpoints[] entry
 */

#include "srr.h"
#include "../compat/alloc_guard.h"


static void *ngx_http_xrootd_srr_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_xrootd_srr_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_xrootd_srr_set(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xrootd_srr_add_share(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_xrootd_srr_add_endpoint(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_http_xrootd_srr_commands[] = {

    { ngx_string("xrootd_srr"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_xrootd_srr_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_srr_loc_conf_t, enable),
      NULL },

    { ngx_string("xrootd_srr_name"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_srr_loc_conf_t, name),
      NULL },

    { ngx_string("xrootd_srr_id"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_srr_loc_conf_t, id),
      NULL },

    { ngx_string("xrootd_srr_quality"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_srr_loc_conf_t, quality),
      NULL },

    { ngx_string("xrootd_srr_version"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_srr_loc_conf_t, version),
      NULL },

    { ngx_string("xrootd_srr_share"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE23,
      ngx_http_xrootd_srr_add_share,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_srr_endpoint"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE3,
      ngx_http_xrootd_srr_add_endpoint,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_xrootd_srr_module_ctx = {
    NULL,                                   /* preconfiguration    */
    NULL,                                   /* postconfiguration   */
    NULL,                                   /* create main conf    */
    NULL,                                   /* init main conf      */
    NULL,                                   /* create srv conf     */
    NULL,                                   /* merge srv conf      */
    ngx_http_xrootd_srr_create_loc_conf,    /* create loc conf     */
    ngx_http_xrootd_srr_merge_loc_conf      /* merge loc conf      */
};


ngx_module_t ngx_http_xrootd_srr_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_srr_module_ctx,
    ngx_http_xrootd_srr_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_xrootd_srr_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_xrootd_srr_loc_conf_t *conf;

    XROOTD_PCALLOC_OR_RETURN(conf, cf->pool, sizeof(*conf), NULL);

    /* str fields: zero-initialised (len 0) → treated as "unset" by merge.
     * arrays: NULL → inherit from parent in merge.                        */
    conf->enable = NGX_CONF_UNSET;
    return conf;
}


static char *
ngx_http_xrootd_srr_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_xrootd_srr_loc_conf_t *prev = parent;
    ngx_http_xrootd_srr_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->name, prev->name, "");
    ngx_conf_merge_str_value(conf->id, prev->id, "");
    ngx_conf_merge_str_value(conf->quality, prev->quality, "production");
    ngx_conf_merge_str_value(conf->version, prev->version, "1.0");

    if (conf->shares == NULL) {
        conf->shares = prev->shares;
    }
    if (conf->endpoints == NULL) {
        conf->endpoints = prev->endpoints;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_xrootd_srr_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char                     *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_xrootd_srr_handler;
    return NGX_CONF_OK;
}


static char *
ngx_http_xrootd_srr_add_share(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_srr_loc_conf_t *lcf = conf;
    ngx_str_t                      *value = cf->args->elts;
    xrootd_srr_share_t             *sh;

    if (lcf->shares == NULL) {
        lcf->shares = ngx_array_create(cf->pool, 4,
                                       sizeof(xrootd_srr_share_t));
        if (lcf->shares == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    sh = ngx_array_push(lcf->shares);
    if (sh == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(sh, sizeof(*sh));

    sh->name = value[1];
    sh->path = value[2];
    if (cf->args->nelts == 4) {     /* optional comma-separated VO list */
        sh->vos = value[3];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_xrootd_srr_add_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_srr_loc_conf_t *lcf = conf;
    ngx_str_t                      *value = cf->args->elts;
    xrootd_srr_endpoint_t          *ep;

    if (lcf->endpoints == NULL) {
        lcf->endpoints = ngx_array_create(cf->pool, 4,
                                          sizeof(xrootd_srr_endpoint_t));
        if (lcf->endpoints == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ep = ngx_array_push(lcf->endpoints);
    if (ep == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(ep, sizeof(*ep));

    ep->name          = value[1];
    ep->interfacetype = value[2];
    ep->url           = value[3];

    return NGX_CONF_OK;
}
