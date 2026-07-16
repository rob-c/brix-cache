/*
 * policy.c — authorization-policy directive handlers (authdb / require_vo /
 * inherit_parent_group) and their postconfiguration finalization.
 */

#include "config.h"

/* `authdb <path>` — load identity-based ACL rules.  Requires brix_auth gsi,
 * token, or both; stores the path and parses its entries into authdb_rules.
 * Returns NGX_CONF_OK, or NGX_CONF_ERROR (emerg-logged) on a bad prerequisite
 * or parse error. */
char *
brix_conf_set_authdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;

    value = cf->args->elts;

    /*
     * The auth-mode requirement (authdb needs gsi/token for the native engine)
     * is validated at merge time, where `brix_authdb_format` is final — the
     * xrdacc engine also authorizes anonymous `u *` rules, so it is exempt.
     * (Directive order means xcf->auth / acc_format are not yet settled here.)
     */
    xcf->authdb = value[1];

    if (xcf->authdb_rules == NULL) {
        xcf->authdb_rules = ngx_array_create(cf->pool, 4,
                                             sizeof(brix_authdb_rule_t));
        if (xcf->authdb_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (brix_parse_authdb(cf, &xcf->authdb, xcf->authdb_rules) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* `brix_require_vo <path> <vo>` — append a VO ACL rule to vo_rules.  Returns
 * NGX_CONF_OK, or NGX_CONF_ERROR (emerg-logged) on bad args. */
char *
brix_conf_set_require_vo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    brix_vo_rule_t             *rule;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->vo_rules == NULL) {
        xcf->vo_rules = ngx_array_create(cf->pool, 2, sizeof(brix_vo_rule_t));
        if (xcf->vo_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(xcf->vo_rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));

    if (brix_normalize_policy_path(cf->pool, &value[1], &rule->path) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_require_vo: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (brix_copy_conf_string(cf, &value[2], &rule->vo) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* `inherit_parent_group <group>` — append a group-inheritance rule to
 * group_rules.  Returns NGX_CONF_OK, or NGX_CONF_ERROR (emerg-logged). */
char *
brix_conf_set_inherit_parent_group(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    brix_group_rule_t          *rule;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->group_rules == NULL) {
        xcf->group_rules = ngx_array_create(cf->pool, 2,
                                            sizeof(brix_group_rule_t));
        if (xcf->group_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(xcf->group_rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));

    if (brix_normalize_policy_path(cf->pool, &value[1], &rule->path) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_inherit_parent_group: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* Postconfiguration finalization for the policy rules: validate cross-directive
 * prerequisites once every directive has settled.  Returns NGX_OK / NGX_ERROR. */
ngx_int_t
brix_config_finalize_policy(ngx_conf_t *cf,
    ngx_stream_brix_srv_conf_t *xcf)
{
    if (xcf->vo_rules != NULL
        && xcf->auth != BRIX_AUTH_GSI
        && xcf->auth != BRIX_AUTH_TOKEN
        && xcf->auth != BRIX_AUTH_BOTH)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_require_vo requires brix_auth gsi, token or both");
        return NGX_ERROR;
    }

    if (xcf->vo_rules != NULL) {
        if (!brix_voms_available()) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_require_vo requires libvomsapi.so.1 at runtime "
                "(install voms-libs on EL9)");
            return NGX_ERROR;
        }
        if (xcf->vomsdir.len == 0 || xcf->voms_cert_dir.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_require_vo requires brix_vomsdir and brix_voms_cert_dir");
            return NGX_ERROR;
        }

        if (brix_validate_path(cf, "brix_vomsdir", &xcf->vomsdir,
                                 BRIX_PATH_DIRECTORY, R_OK | X_OK)
            != NGX_OK
            || brix_validate_path(cf, "brix_voms_cert_dir",
                                    &xcf->voms_cert_dir,
                                    BRIX_PATH_DIRECTORY, R_OK | X_OK)
               != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    if (brix_finalize_vo_rules(cf->log, &xcf->common.root, xcf->vo_rules)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: failed to finalize brix_require_vo rules for root \"%V\"",
            &xcf->common.root);
        return NGX_ERROR;
    }

    if (brix_finalize_authdb_rules(cf->log, &xcf->common.root, xcf->authdb_rules)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: failed to finalize brix_authdb rules for root \"%V\"",
            &xcf->common.root);
        return NGX_ERROR;
    }

    if (brix_finalize_group_rules(cf->log, &xcf->common.root,
                                    xcf->group_rules) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: failed to finalize brix_inherit_parent_group rules for root \"%V\"",
            &xcf->common.root);
        return NGX_ERROR;
    }

    return NGX_OK;
}
