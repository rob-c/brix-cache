#include "server.h"
#include "config/config.h"   /* xrootd_sss_load_keytab */


/* xrootd_cms_srv_create_conf — allocate the CMS-server srv_conf with enable and
 * interval = NGX_CONF_UNSET, so merge can tell "not configured" from "set to zero"
 * and apply the interval=60 default. */

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
    /* allow / sss_keytab / sss_keys are zero-initialised by pcalloc (NULL). */

    conf->login_timeout    = NGX_CONF_UNSET_MSEC;
    conf->idle_timeout     = NGX_CONF_UNSET_MSEC;
    conf->max_connections  = NGX_CONF_UNSET;
    conf->max_connections_per_ip = NGX_CONF_UNSET;
    conf->tcp_keepalive    = NGX_CONF_UNSET;
    conf->tcp_user_timeout = NGX_CONF_UNSET_MSEC;

    return conf;
}

/* xrootd_cms_srv_merge_conf — merge the CMS-server config parent→child: enable
 * defaults to 0 (off), interval to 60s (NGX_CONF_UNSET = use parent or default). */

static char *
xrootd_cms_srv_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_xrootd_cms_srv_conf_t *prev = parent;
    ngx_stream_xrootd_cms_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable,   prev->enable,   0);
    ngx_conf_merge_value(conf->interval, prev->interval, 60);
    if (conf->interval < 1) {
        conf->interval = 1;   /* never derive a 0ms self-rearming ping timer */
    }

    /*
     * Phase 50: accept-side resilience deadlines + connection cap.  Resolved
     * after interval so an unset idle timeout auto-derives from it.  Generous
     * ON-by-default values; an explicit 0 disables a timeout / uncaps.
     */
    ngx_conf_merge_msec_value(conf->login_timeout, prev->login_timeout, 10000);
    if (conf->idle_timeout == NGX_CONF_UNSET_MSEC) {
        if (prev->idle_timeout != NGX_CONF_UNSET_MSEC) {
            conf->idle_timeout = prev->idle_timeout;
        } else {
            ngx_msec_t d = (ngx_msec_t) conf->interval * 3 * 1000;
            conf->idle_timeout = (d > 90000) ? d : 90000;
        }
    }
    ngx_conf_merge_value(conf->max_connections, prev->max_connections, 4096);
    ngx_conf_merge_value(conf->max_connections_per_ip,
                         prev->max_connections_per_ip, 256);
    ngx_conf_merge_value(conf->tcp_keepalive,   prev->tcp_keepalive,   1);
    if (conf->tcp_user_timeout == NGX_CONF_UNSET_MSEC) {
        conf->tcp_user_timeout =
            (prev->tcp_user_timeout != NGX_CONF_UNSET_MSEC)
                ? prev->tcp_user_timeout
                : conf->idle_timeout;
    }

    /* Inherit auth config from the parent block when the child omitted it. */
    if (conf->allow == NULL) {
        conf->allow = prev->allow;
    }
    if (conf->sss_keys == NULL) {
        conf->sss_keys   = prev->sss_keys;
        conf->sss_keytab = prev->sss_keytab;
    }

    return NGX_CONF_OK;
}


/* xrootd_cms_srv_set_enable — parse the xrootd_cms_server flag (ngx_conf_set_flag_slot)
 * and, when enabled, install xrootd_cms_srv_handler as the stream connection handler
 * so the module only intercepts connections when on. */

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


/* xrootd_cms_srv_set_allow — parse a CIDR allowlist of permitted
 * data-node IPs.  Mirrors xrootd_admin_set_allow (dashboard/api_admin.c):
 * accumulate ngx_cidr_t entries that the accept-time gate matches the peer
 * address against.  Compatible with vanilla nodes — a node from a trusted
 * subnet connects unchanged. */
static char *
xrootd_cms_srv_set_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_stream_xrootd_cms_srv_conf_t *conf = conf_ptr;
    ngx_str_t  *value = cf->args->elts;
    ngx_uint_t  i;

    (void) cmd;

    if (conf->allow == NULL) {
        conf->allow = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                       sizeof(ngx_cidr_t));
        if (conf->allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_cidr_t *cidr = ngx_array_push(conf->allow);
        ngx_int_t   rc;
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }
        rc = ngx_ptocidr(&value[i], cidr);
        if (rc == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid CIDR \"%V\" in xrootd_cms_server_allow", &value[i]);
            return NGX_CONF_ERROR;
        }
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "low address bits of \"%V\" in xrootd_cms_server_allow "
                "were ignored", &value[i]);
        }
    }
    return NGX_CONF_OK;
}


/* xrootd_cms_srv_set_sss_keytab — load the cluster sss keytab at config
 * time using the shared loader (enforces 0600/0640 private permissions).
 * When set, a data node must complete the kYR_xauth sss handshake before it
 * is admitted to the registry (fail-closed).  Reuses the same keytab format
 * and parser as the main module's xrootd_sss_keytab. */
static char *
xrootd_cms_srv_set_sss_keytab(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf_ptr)
{
    ngx_stream_xrootd_cms_srv_conf_t *conf = conf_ptr;
    ngx_str_t  *value = cf->args->elts;
    ngx_str_t   path  = value[1];

    (void) cmd;

    if (conf->sss_keys != NULL) {
        return "is duplicate";
    }
    if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    conf->sss_keytab = path;

    if (xrootd_sss_load_keytab(cf, &conf->sss_keytab, &conf->sss_keys)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "xrootd: CMS server sss auth configured - keytab=%V "
                       "keys=%ui", &conf->sss_keytab, conf->sss_keys->nelts);
    return NGX_CONF_OK;
}


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

    { ngx_string("xrootd_cms_server_allow"),
      NGX_STREAM_SRV_CONF | NGX_CONF_1MORE,
      xrootd_cms_srv_set_allow,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_cms_server_sss_keytab"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_cms_srv_set_sss_keytab,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Phase 50: accept-side resilience deadlines + connection cap. */
    { ngx_string("xrootd_cms_server_login_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_cms_srv_conf_t, login_timeout),
      NULL },

    { ngx_string("xrootd_cms_server_idle_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_cms_srv_conf_t, idle_timeout),
      NULL },

    { ngx_string("xrootd_cms_server_max_connections"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_cms_srv_conf_t, max_connections),
      NULL },

    { ngx_string("xrootd_cms_server_max_connections_per_ip"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_cms_srv_conf_t, max_connections_per_ip),
      NULL },

    { ngx_string("xrootd_cms_server_tcp_keepalive"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_cms_srv_conf_t, tcp_keepalive),
      NULL },

    { ngx_string("xrootd_cms_server_tcp_user_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_cms_srv_conf_t, tcp_user_timeout),
      NULL },

    ngx_null_command
};


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
