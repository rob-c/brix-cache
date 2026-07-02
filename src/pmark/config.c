/*
 * config.c — pmark per-server config lifecycle + directive parsing.
 *
 * WHAT: Initialise/merge the xrootd_pmark_conf_t embedded in the shared config
 *   preamble (config/shared_conf.h), and the custom directive setters for the
 *   repeatable / multi-token directives (firefly_dest, map_experiment,
 *   map_activity, domain).  Simple flag/str directives use the stock
 *   ngx_conf_set_*_slot setters wired directly in each module's command table.
 *
 * WHY: pmark config is shared across the stream (root://) and HTTP (WebDAV/S3)
 *   modules.  Because ngx_http_xrootd_shared_conf_t is the FIRST member of every
 *   protocol conf struct, a custom setter can cast its `conf` argument straight
 *   to ngx_http_xrootd_shared_conf_t* and reach ->pmark, so ONE setter serves all
 *   three protocols.
 *
 * HOW: init sets NGX_CONF_UNSET sentinels; merge applies SciTags-sane defaults
 *   (opt-in disabled; firefly + flowlabel + scitag-cgi on; domain remote; firefly
 *   port 10514).  Arrays inherit from the parent when the child did not set them.
 */

#include "pmark.h"
#include "core/config/shared_conf.h"


void
xrootd_pmark_conf_init(xrootd_pmark_conf_t *c)
{
    c->enable         = NGX_CONF_UNSET;
    c->firefly        = NGX_CONF_UNSET;
    c->flowlabel      = NGX_CONF_UNSET;
    c->scitag_cgi     = NGX_CONF_UNSET;
    c->firefly_origin = NGX_CONF_UNSET;
    c->http_plain     = NGX_CONF_UNSET;
    c->echo           = NGX_CONF_UNSET_MSEC;
    c->domain         = NGX_CONF_UNSET_UINT;
}


char *
xrootd_pmark_conf_merge(ngx_conf_t *cf, xrootd_pmark_conf_t *prev,
    xrootd_pmark_conf_t *conf)
{
    (void) cf;

    ngx_conf_merge_value(conf->enable,         prev->enable,         0);
    ngx_conf_merge_value(conf->firefly,        prev->firefly,        1);
    ngx_conf_merge_value(conf->flowlabel,      prev->flowlabel,      1);
    ngx_conf_merge_value(conf->scitag_cgi,     prev->scitag_cgi,     1);
    ngx_conf_merge_value(conf->firefly_origin, prev->firefly_origin, 0);
    ngx_conf_merge_value(conf->http_plain,     prev->http_plain,     0);
    ngx_conf_merge_msec_value(conf->echo,      prev->echo,           0);
    ngx_conf_merge_uint_value(conf->domain,    prev->domain,
                              XROOTD_PMARK_DOMAIN_REMOTE);
    ngx_conf_merge_str_value(conf->appname,    prev->appname,        "nginx-xrootd");
    ngx_conf_merge_str_value(conf->defsfile,   prev->defsfile,       "");

    if (conf->firefly_dest == NULL) { conf->firefly_dest = prev->firefly_dest; }
    if (conf->exp_rules    == NULL) { conf->exp_rules    = prev->exp_rules;    }
    if (conf->act_rules    == NULL) { conf->act_rules    = prev->act_rules;    }

    return NGX_CONF_OK;
}


/* Reach the pmark config from any protocol conf (common is the first member). */
static xrootd_pmark_conf_t *
pmark_conf(void *conf)
{
    return &((ngx_http_xrootd_shared_conf_t *) conf)->pmark;
}


char *
xrootd_pmark_set_firefly_dest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_pmark_conf_t *pm = pmark_conf(conf);
    ngx_str_t           *value = cf->args->elts;
    ngx_str_t           *dest;

    (void) cmd;

    if (pm->firefly_dest == NULL) {
        pm->firefly_dest = ngx_array_create(cf->pool, 2, sizeof(ngx_str_t));
        if (pm->firefly_dest == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    dest = ngx_array_push(pm->firefly_dest);
    if (dest == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Stored verbatim as "host[:port]"; resolved to a sockaddr per worker at
     * init (defaults to port 10514 when no :port is given). */
    *dest = value[1];
    return NGX_CONF_OK;
}


char *
xrootd_pmark_set_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_pmark_conf_t *pm = pmark_conf(conf);
    ngx_str_t           *value = cf->args->elts;

    (void) cmd;

    if (ngx_strcmp(value[1].data, "any") == 0) {
        pm->domain = XROOTD_PMARK_DOMAIN_ANY;
    } else if (ngx_strcmp(value[1].data, "local") == 0) {
        pm->domain = XROOTD_PMARK_DOMAIN_LOCAL;
    } else if (ngx_strcmp(value[1].data, "remote") == 0) {
        pm->domain = XROOTD_PMARK_DOMAIN_REMOTE;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid xrootd_pmark_domain \"%V\" (use any|local|remote)",
            &value[1]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


char *
xrootd_pmark_set_map_experiment(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_pmark_conf_t     *pm = pmark_conf(conf);
    ngx_str_t               *value = cf->args->elts;
    xrootd_pmark_exp_rule_t *rule;

    (void) cmd;

    if (pm->exp_rules == NULL) {
        pm->exp_rules = ngx_array_create(cf->pool, 4,
                                         sizeof(xrootd_pmark_exp_rule_t));
        if (pm->exp_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(pm->exp_rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(rule, sizeof(*rule));

    /* default <exp>  |  path <glob> <exp>  |  vo <name> <exp> */
    if (ngx_strcmp(value[1].data, "default") == 0 && cf->args->nelts == 3) {
        rule->kind     = XROOTD_PMARK_EXP_DEFAULT;
        rule->exp_name = value[2];
    } else if (ngx_strcmp(value[1].data, "path") == 0 && cf->args->nelts == 4) {
        rule->kind     = XROOTD_PMARK_EXP_PATH;
        rule->match    = value[2];
        rule->exp_name = value[3];
    } else if (ngx_strcmp(value[1].data, "vo") == 0 && cf->args->nelts == 4) {
        rule->kind     = XROOTD_PMARK_EXP_VO;
        rule->match    = value[2];
        rule->exp_name = value[3];
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_pmark_map_experiment: use "
            "\"default <exp>\" | \"path <glob> <exp>\" | \"vo <name> <exp>\"");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


char *
xrootd_pmark_set_map_activity(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_pmark_conf_t     *pm = pmark_conf(conf);
    ngx_str_t               *value = cf->args->elts;
    xrootd_pmark_act_rule_t *rule;

    (void) cmd;

    if (pm->act_rules == NULL) {
        pm->act_rules = ngx_array_create(cf->pool, 4,
                                         sizeof(xrootd_pmark_act_rule_t));
        if (pm->act_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(pm->act_rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(rule, sizeof(*rule));

    /* <exp> default <act>  |  <exp> role <name> <act>  |  <exp> user <name> <act> */
    rule->exp_name = value[1];
    if (ngx_strcmp(value[2].data, "default") == 0 && cf->args->nelts == 4) {
        rule->kind     = XROOTD_PMARK_ACTR_DEFAULT;
        rule->act_name = value[3];
    } else if (ngx_strcmp(value[2].data, "role") == 0 && cf->args->nelts == 5) {
        rule->kind     = XROOTD_PMARK_ACTR_ROLE;
        rule->match    = value[3];
        rule->act_name = value[4];
    } else if (ngx_strcmp(value[2].data, "user") == 0 && cf->args->nelts == 5) {
        rule->kind     = XROOTD_PMARK_ACTR_USER;
        rule->match    = value[3];
        rule->act_name = value[4];
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_pmark_map_activity: use \"<exp> default <act>\" | "
            "\"<exp> role <name> <act>\" | \"<exp> user <name> <act>\"");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
