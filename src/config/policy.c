#include "config.h"

char *
xrootd_conf_set_authdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;

    value = cf->args->elts;

    if (xcf->auth != XROOTD_AUTH_GSI && xcf->auth != XROOTD_AUTH_TOKEN
        && xcf->auth != (XROOTD_AUTH_GSI | XROOTD_AUTH_TOKEN))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_authdb requires xrootd_auth gsi, token or both");
        return NGX_CONF_ERROR;
    }

    xcf->authdb = value[1];

    if (xcf->authdb_rules == NULL) {
        xcf->authdb_rules = ngx_array_create(cf->pool, 4,
                                             sizeof(xrootd_authdb_rule_t));
        if (xcf->authdb_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (xrootd_parse_authdb(cf, &xcf->authdb, xcf->authdb_rules) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char *
xrootd_conf_set_require_vo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    xrootd_vo_rule_t             *rule;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->vo_rules == NULL) {
        xcf->vo_rules = ngx_array_create(cf->pool, 2, sizeof(xrootd_vo_rule_t));
        if (xcf->vo_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(xcf->vo_rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));

    if (xrootd_normalize_policy_path(cf->pool, &value[1], &rule->path) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_require_vo: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (xrootd_copy_conf_string(cf, &value[2], &rule->vo) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

char *
xrootd_conf_set_inherit_parent_group(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    xrootd_group_rule_t          *rule;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->group_rules == NULL) {
        xcf->group_rules = ngx_array_create(cf->pool, 2,
                                            sizeof(xrootd_group_rule_t));
        if (xcf->group_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(xcf->group_rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));

    if (xrootd_normalize_policy_path(cf->pool, &value[1], &rule->path) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_inherit_parent_group: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

ngx_int_t
xrootd_config_finalize_policy(ngx_conf_t *cf,
    ngx_stream_xrootd_srv_conf_t *xcf)
{
    if (xcf->vo_rules != NULL
        && xcf->auth != XROOTD_AUTH_GSI
        && xcf->auth != XROOTD_AUTH_TOKEN
        && xcf->auth != XROOTD_AUTH_BOTH)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_require_vo requires xrootd_auth gsi, token or both");
        return NGX_ERROR;
    }

    if (xcf->vo_rules != NULL) {
        if (!xrootd_voms_available()) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_require_vo requires libvomsapi.so.1 at runtime "
                "(install voms-libs on EL9)");
            return NGX_ERROR;
        }
        if (xcf->vomsdir.len == 0 || xcf->voms_cert_dir.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_require_vo requires xrootd_vomsdir and xrootd_voms_cert_dir");
            return NGX_ERROR;
        }

        if (xrootd_validate_path(cf, "xrootd_vomsdir", &xcf->vomsdir,
                                 XROOTD_PATH_DIRECTORY, R_OK | X_OK)
            != NGX_OK
            || xrootd_validate_path(cf, "xrootd_voms_cert_dir",
                                    &xcf->voms_cert_dir,
                                    XROOTD_PATH_DIRECTORY, R_OK | X_OK)
               != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    if (xrootd_finalize_vo_rules(cf->log, &xcf->root, xcf->vo_rules)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd: failed to finalize xrootd_require_vo rules for root \"%V\"",
            &xcf->root);
        return NGX_ERROR;
    }

    if (xrootd_finalize_authdb_rules(cf->log, &xcf->root, xcf->authdb_rules)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd: failed to finalize xrootd_authdb rules for root \"%V\"",
            &xcf->root);
        return NGX_ERROR;
    }

    if (xrootd_finalize_group_rules(cf->log, &xcf->root,
                                    xcf->group_rules) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd: failed to finalize xrootd_inherit_parent_group rules for root \"%V\"",
            &xcf->root);
        return NGX_ERROR;
    }

    return NGX_OK;
}
