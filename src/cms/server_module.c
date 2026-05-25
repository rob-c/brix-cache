#include "server.h"

/* ------------------------------------------------------------------ */
/* Config callbacks                                                     */
/* ------------------------------------------------------------------ */

/* ---- xrootd_cms_srv_create_conf — allocate CMS server config with unset defaults ----
 * WHAT: Creates a new srv_conf instance for the CMS server module, initializing enable=NGX_CONF_UNSET and interval=NGX_CONF_UNSET so merge can apply proper fallback values. WHY: Unset markers allow ngx_conf_merge_value() to distinguish "not configured" from "configured as zero", ensuring default interval=60 applies even when user omits xrootd_cms_server_interval directive. */

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

/* ---- xrootd_cms_srv_merge_conf — merge CMS server config from parent to child level ----
 * WHAT: Merges CMS server configuration values from main/srv-level conf into the current srv-level conf. enable defaults to 0 (off), interval defaults to 60 seconds. WHY: nginx config hierarchy requires merging: each level may override parent values, and NGX_CONF_UNSET markers indicate "use parent value or apply default". */

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

/* ---- xrootd_cms_srv_set_enable — parse xrootd_cms_server directive and install session handler ----
 * WHAT: Delegates flag parsing to ngx_conf_set_flag_slot, then if enable=1 installs the CMS server session handler (xrootd_cms_srv_handler) as the stream connection handler. WHY: The CMS server module only needs to intercept incoming connections when enabled — otherwise nginx uses its default stream handler and ignores CMS traffic. HOW: 1) Parse flag via ngx_conf_set_flag_slot → 2) If enabled, grab core srv conf → 3) Set cscf->handler = xrootd_cms_srv_handler → 4) Return NGX_CONF_OK. */

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
