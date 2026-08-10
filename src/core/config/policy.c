/*
 * policy.c — authorization-policy directive handlers (authdb / require_vo /
 * inherit_parent_group) and their postconfiguration finalization.
 */

#include "config.h"
#include "auth/protbind/protbind.h"
#include "core/compat/checksum.h"   /* brix_checksum_parse (tpc_verify_checksum) */
#include "core/compat/str_dup.h"    /* brix_pstrdupz */

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

/* `brix_protbind <host-template> [none | [only] <proto>...]` — append a
 * per-host authentication-protocol binding.  The grammar and every rejection
 * message are owned by the shared engine in src/auth/protbind/ so the stream
 * and HTTP frontends parse identically; this setter only names the array slot.
 * Returns NGX_CONF_OK or NGX_CONF_ERROR. */
char *
brix_conf_set_protbind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;

    return brix_protbind_conf(cf, cmd, &xcf->protbind);
}

/* Same directive on the HTTP planes (phase-101 W4): the shared preamble is member
 * 0 of the common-module conf, so a cast to the preamble type is valid; the array
 * lands in common.protbind and is adopted into every HTTP protocol conf.  Same
 * shared engine, so stream and HTTP parse identically. */
char *
brix_http_conf_set_protbind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_shared_conf_t *sc = conf;

    return brix_protbind_conf(cf, cmd, &sc->protbind);
}

/* Shared `brix_require_vo <path> <vo>` grammar (phase-101 W4): append one VO ACL
 * rule to *slot, lazily creating the array.  The stream setter below, the HTTP
 * setter (registered on the common module) AND the stream_common owner (W3) all
 * call this, so require_vo parses byte-identically on every plane.  Non-static so
 * stream_common.c can reuse it (declared in ngx_brix_module.h).  Returns
 * NGX_CONF_OK / NGX_CONF_ERROR. */
char *
brix_vo_rules_append(ngx_conf_t *cf, ngx_str_t *value, ngx_array_t **slot)
{
    brix_vo_rule_t *rule;

    if (*slot == NULL) {
        *slot = ngx_array_create(cf->pool, 2, sizeof(brix_vo_rule_t));
        if (*slot == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(*slot);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));

    if (brix_normalize_policy_path(cf->pool, &value[1], &rule->path) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_require_vo: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    return brix_copy_conf_string(cf, &value[2], &rule->vo);
}

/* `brix_require_vo <path> <vo>` on the STREAM (root) plane — appends to the
 * per-server vo_rules.  Returns NGX_CONF_OK / NGX_CONF_ERROR. */
char *
brix_conf_set_require_vo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;

    (void) cmd;
    return brix_vo_rules_append(cf, cf->args->elts, &xcf->vo_rules);
}

/* `brix_tpc_verify_checksum on|off|<alg>` on EVERY plane (phase-101 W4): unify the
 * native-TPC boolean grammar and the webdav <alg> grammar into one.  Normalizes to
 * common.tpc_verify_checksum — "off"/absent => "" (off); "on" => "adler32" (the
 * XRootD/WLCG default checksum); a checksum algorithm name => its canonical
 * spelling.  `common` is member 0 of every plane's conf, so the cast is valid.
 * The native (root) TPC reads the field as a boolean gate (kXR_Qcksum negotiates
 * its own algorithm); the webdav curl-COPY uses the algorithm for Want-Digest and
 * the post-copy recompute.  Returns NGX_CONF_OK / NGX_CONF_ERROR. */
char *
brix_conf_set_tpc_verify_checksum(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_shared_conf_t *sc = conf;
    ngx_str_t                   *value = cf->args->elts;
    brix_checksum_alg_t          alg;
    char                         norm[32];

    (void) cmd;

    if (value[1].len == 3
        && ngx_strncasecmp(value[1].data, (u_char *) "off", 3) == 0)
    {
        ngx_str_null(&sc->tpc_verify_checksum);   /* explicit off */
        return NGX_CONF_OK;
    }
    if (value[1].len == 2
        && ngx_strncasecmp(value[1].data, (u_char *) "on", 2) == 0)
    {
        ngx_str_set(&sc->tpc_verify_checksum, "adler32");  /* XRootD/WLCG default */
        return NGX_CONF_OK;
    }
    if (brix_checksum_parse((const char *) value[1].data, value[1].len,
                            &alg, norm, sizeof(norm)) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_tpc_verify_checksum: expected on, off, or a checksum algorithm "
            "(adler32, crc32, crc32c, md5, sha1, sha256, crc64), got \"%V\"",
            &value[1]);
        return NGX_CONF_ERROR;
    }
    if (brix_pstrdupz(cf->pool, &sc->tpc_verify_checksum,
                      (u_char *) norm, ngx_strlen(norm)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

/* `brix_require_vo <path> <vo>` on the HTTP planes (phase-101 W4) — the shared
 * preamble is member 0 of the common-module conf, so a cast to the preamble type
 * is valid; appends to common.vo_rules, adopted into every HTTP protocol conf by
 * brix_shared_adopt_unified().  Returns NGX_CONF_OK / NGX_CONF_ERROR. */
char *
brix_http_conf_set_require_vo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_shared_conf_t *sc = conf;

    (void) cmd;
    return brix_vo_rules_append(cf, cf->args->elts, &sc->vo_rules);
}

/* `brix_authdb <file>` on the HTTP planes (phase-101 W5.2) — parse the native
 * u/g/p/h READ-ACL file into common.authdb_rules (member 0 of the common-module
 * conf), adopted into every HTTP protocol and ENFORCED in the webdav/s3/cvmfs
 * access phases.  Reuses the stream authdb parser (same file format).  Returns
 * NGX_CONF_OK / NGX_CONF_ERROR. */
char *
brix_http_conf_set_authdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_shared_conf_t *sc = conf;
    ngx_str_t                   *value = cf->args->elts;

    (void) cmd;

    if (sc->authdb_rules == NULL) {
        sc->authdb_rules = ngx_array_create(cf->pool, 4,
                                            sizeof(brix_authdb_rule_t));
        if (sc->authdb_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    if (brix_parse_authdb(cf, &value[1], sc->authdb_rules) != NGX_OK) {
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
