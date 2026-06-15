/* ------------------------------------------------------------------ */
/* Section: VO ACL and AuthDB Policy Configuration                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements policy configuration directive handlers for VO ACL rules (require_vo), authdb rules
 *      (authdb), group inheritance rules (inherit_parent_group), and postconfiguration finalization of all policies.
 *      Each handler parses a config directive, normalizes paths using policy conventions, stores entries in arrays,
 *      then validates prerequisite conditions during finalize phase. */

/* ------------------------------------------------------------------ */
/* Section: AuthDB Directive Handler                                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_conf_set_authdb() parses the "authdb" config directive creating ACL rules based on user identity.
 *      Requires xrootd_auth to be configured with gsi, token or both before authdb can take effect. Creates authdb_rules
 *      array, stores the authdb path from value[1], then calls xrootd_parse_authdb() to parse rule entries into the array. */

/* ---- Function: xrootd_conf_set_authdb() ----
 *
 * WHAT: Parses the "authdb" config directive creating ACL rules based on user identity for authorization decisions.
 *      Requires xrootd_auth configured with gsi, token or both before authdb can take effect. Creates authdb_rules array,
 *      stores the authdb path from value[1], then calls xrootd_parse_authdb() to parse rule entries into the array.
 *      Returns NGX_CONF_OK on success; NGX_CONF_ERROR with emerg-level log on prerequisite or parsing failure. */

/* ---- WHY: AuthDB allows fine-grained access control based on user identity beyond VO membership — rules can grant or deny
 *      specific operations for individual users regardless of their VO affiliation. Requires authentication subsystem (GSI or
 *      token) to be active before authdb rules can evaluate user credentials against the rule database. ---- */

/* ------------------------------------------------------------------ */
/* Section: Require VO Directive Handler                                  */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_conf_set_require_vo() parses the "require_vo" config directive creating path-level VO membership requirements.
 *      Each entry associates a prefix path with an required VO name — access is denied if user's VOMS proxy lacks membership
 *      in that VO for that path segment. Creates vo_rules array, normalizes path, copies VO string via xrootd_copy_conf_string(). */

/* ---- Function: xrootd_conf_set_require_vo() ----
 *
 * WHAT: Parses the "require_vo" config directive creating path-level VO membership requirements for authorization decisions.
 *      Each entry associates a prefix path with an required VO name — access is denied if user's VOMS proxy lacks membership
 *      in that VO for that path segment. Creates vo_rules array, normalizes path via policy conventions, copies VO string via
 *      xrootd_copy_conf_string(). Returns NGX_CONF_OK on success; NGX_CONF_ERROR with emerg-level log on parsing failure. */

/* ---- WHY: VO ACL rules restrict access to specific namespaces based on user's VOMS proxy membership — users without the
 *      required VO cannot access files under that path prefix even if they have other authorization credentials. Path normalization
 *      ensures consistent policy-style prefixes across all entries for efficient matching during runtime authorization checks. ---- */

/* ------------------------------------------------------------------ */
/* Section: Inherit Parent Group Directive Handler                        */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_conf_set_inherit_parent_group() parses the "inherit_parent_group" config directive creating path-level group
 *      inheritance rules for ownership resolution. Each entry associates a prefix path with parent group inheritance behavior —
 *      when accessing files under that prefix, ownership is resolved by inheriting from parent directory rather than file metadata.
 *      Creates group_rules array, normalizes path via policy conventions. */

/* ---- Function: xrootd_conf_set_inherit_parent_group() ----
 *
 * WHAT: Parses the "inherit_parent_group" config directive creating path-level group inheritance rules for ownership resolution.
 *      Each entry associates a prefix path with parent group inheritance behavior — when accessing files under that prefix,
 *      ownership is resolved by inheriting from parent directory rather than file metadata. Creates group_rules array, normalizes
 *      path via policy conventions. Returns NGX_CONF_OK on success; NGX_CONF_ERROR with emerg-level log on parsing failure. */

/* ---- WHY: Group inheritance allows consistent access control across namespace hierarchies where individual files may have
 *      different ownership than their parent directory — inheritance rules ensure authorization decisions are based on the
 *      parent group rather than potentially inconsistent file-level metadata, preventing edge-case access violations in nested paths. ---- */

#include "config.h"

char *
xrootd_conf_set_authdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;

    value = cf->args->elts;

    /*
     * The auth-mode requirement (authdb needs gsi/token for the native engine)
     * is validated at merge time, where `xrootd_authdb_format` is final — the
     * xrdacc engine also authorizes anonymous `u *` rules, so it is exempt.
     * (Directive order means xcf->auth / acc_format are not yet settled here.)
     */
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

/* ------------------------------------------------------------------ */
/* Section: Policy Finalization                                         */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_config_finalize_policy() performs postconfiguration validation of all policy rules created during directive parsing.
 *      Validates prerequisite conditions (VO rules require GSI/token auth + vomsdir/voms_cert_dir paths), checks path existence via
 *      xrootd_validate_path(), then calls finalize functions for vo_rules, authdb_rules, and group_rules to build efficient lookup structures. */

/* ---- Function: xrootd_config_finalize_policy() ----
 *
 * WHAT: Performs postconfiguration validation of all policy rules created during directive parsing phase. Validates prerequisite
 *      conditions (VO rules require GSI/token auth + vomsdir/voms_cert_dir paths exist), checks path accessibility via
 *      xrootd_validate_path(), then calls finalize functions for vo_rules, authdb_rules, and group_rules to build efficient
 *      lookup structures for runtime authorization decisions. Returns NGX_OK on success; NGX_ERROR with emerg-level log on any failure. */

/* ---- WHY: Finalization ensures all policy rules are valid before accepting client connections — prerequisite validation prevents
 *      runtime failures where nginx would attempt to evaluate policies without required subsystems (VOMS library, certificate directory).
 *      Path validation catches misconfigured voms directories during startup rather than failing under load. Finalize functions build
 *      optimized lookup structures from parsed rule entries for efficient matching during authorization decisions. ---- */

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
    if (xrootd_finalize_vo_rules(cf->log, &xcf->common.root, xcf->vo_rules)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd: failed to finalize xrootd_require_vo rules for root \"%V\"",
            &xcf->common.root);
        return NGX_ERROR;
    }

    if (xrootd_finalize_authdb_rules(cf->log, &xcf->common.root, xcf->authdb_rules)
        != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd: failed to finalize xrootd_authdb rules for root \"%V\"",
            &xcf->common.root);
        return NGX_ERROR;
    }

    if (xrootd_finalize_group_rules(cf->log, &xcf->common.root,
                                    xcf->group_rules) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd: failed to finalize xrootd_inherit_parent_group rules for root \"%V\"",
            &xcf->common.root);
        return NGX_ERROR;
    }

    return NGX_OK;
}
