/*
 * token/issuer_registry.c — SciTokens multi-issuer registry (see header).
 *
 * WHAT: Loads the upstream XRootD `scitokens.cfg` INI into a read-only table of
 *       issuers, each with its iss URL, audiences, base_path/restricted_path
 *       namespace scope, authorization strategy, and (optional) per-issuer
 *       JWKS. Provides exact-iss lookup and the base/restricted path gate.
 * WHY:  XRootD delegates authorization for a namespace subtree to an external
 *       issuer via this file; parsing the grammar verbatim lets an operator
 *       reuse their existing config unchanged (phase-59 W1, ADR-1).
 * HOW:  brix_ini_parse_file() drives reg_kv() per line; [Issuer N] keys fill
 *       an brix_token_issuer_t, [Global] keys fill shared audiences. After
 *       parsing, each issuer is validated (issuer + base_path required) and its
 *       JWKS loaded. Path scoping reuses brix_token_scope_path_matches().
 *       Unsupported keys are WARN-logged, never silently dropped (R4).
 */

#include "issuer_registry.h"
#include "ini.h"

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/stat.h>

/* eqi — case-insensitive equality */static int
eqi(const char *a, const char *b)
{
    return strcasecmp(a, b) == 0;
}

/* copy_z — bounded NUL-terminated copy */static void
copy_z(char *dst, size_t cap, const char *src)
{
    snprintf(dst, cap, "%s", src);
}

/* parse_bool — accept True/yes/1/on (case-insensitive) */static int
parse_bool(const char *v)
{
    return eqi(v, "true") || eqi(v, "yes") || eqi(v, "1") || eqi(v, "on");
}

/* brix_token_strategy_parse — "capability group mapping" → bits */uint32_t
brix_token_strategy_parse(const char *value)
{
    char     buf[128];
    char    *tok;
    char    *save = NULL;
    uint32_t bits = 0;

    copy_z(buf, sizeof(buf), value);
    for (tok = strtok_r(buf, " ,", &save); tok != NULL;
         tok = strtok_r(NULL, " ,", &save))
    {
        if (eqi(tok, "capability")) {
            bits |= BRIX_AUTHZ_CAPABILITY;
        } else if (eqi(tok, "group")) {
            bits |= BRIX_AUTHZ_GROUP;
        } else if (eqi(tok, "mapping")) {
            bits |= BRIX_AUTHZ_MAPPING;
        }
    }
    return bits;
}

/* reg_add_list — split a comma/space list into a fixed path array */static void
reg_add_list(char (*arr)[BRIX_SCOPE_PATH_MAX], int *count, int cap,
    const char *csv)
{
    char  buf[1024];
    char *tok;
    char *save = NULL;

    copy_z(buf, sizeof(buf), csv);
    for (tok = strtok_r(buf, " ,", &save); tok != NULL && *count < cap;
         tok = strtok_r(NULL, " ,", &save))
    {
        copy_z(arr[*count], BRIX_SCOPE_PATH_MAX, tok);
        (*count)++;
    }
}

/* reg_add_aud — split a comma/space list into the audience array */static void
reg_add_aud(char (*arr)[256], int *count, int cap, const char *csv)
{
    char  buf[1024];
    char *tok;
    char *save = NULL;

    copy_z(buf, sizeof(buf), csv);
    for (tok = strtok_r(buf, " ,", &save); tok != NULL && *count < cap;
         tok = strtok_r(NULL, " ,", &save))
    {
        copy_z(arr[*count], 256, tok);
        (*count)++;
    }
}

/* reg_issuer_for — find-or-create the issuer for a section name */static brix_token_issuer_t *
reg_issuer_for(brix_token_registry_t *reg, const char *name)
{
    brix_token_issuer_t *is;
    int                    i;

    for (i = 0; i < reg->count; i++) {
        if (eqi(reg->issuers[i].name, name)) {
            return &reg->issuers[i];
        }
    }
    if (reg->count >= BRIX_TOKEN_MAX_ISSUERS) {
        return NULL;
    }
    is = &reg->issuers[reg->count];
    copy_z(is->name, sizeof(is->name), name);
    copy_z(is->username_claim, sizeof(is->username_claim), "sub");
    is->enabled = 1;
    is->onmissing_fail = 1;
    is->strategy = reg->default_strategy;
    is->metric_bucket = reg->count;
    reg->count++;
    return is;
}

/* reg_kv — INI callback: dispatch one key line */static int
reg_kv(void *u, const char *section, const char *key, const char *val)
{
    brix_token_registry_t *reg = u;

    if (strncasecmp(section, "Issuer ", 7) == 0) {
        brix_token_issuer_t *is = reg_issuer_for(reg, section + 7);
        if (is == NULL) {
            return -1;                          /* too many issuers */
        }
        if (eqi(key, "issuer")) {
            copy_z(is->issuer, sizeof(is->issuer), val);
        } else if (eqi(key, "base_path")) {
            reg_add_list(is->base_paths, &is->base_path_count,
                BRIX_TOKEN_MAX_BASEPATHS, val);
        } else if (eqi(key, "restricted_path")) {
            reg_add_list(is->restricted_paths, &is->restricted_path_count,
                BRIX_TOKEN_MAX_BASEPATHS, val);
        } else if (eqi(key, "audience") || eqi(key, "audience_json")) {
            reg_add_aud(is->audiences, &is->audience_count,
                BRIX_TOKEN_MAX_AUDIENCES, val);
        } else if (eqi(key, "map_subject")) {
            is->map_subject = parse_bool(val);
        } else if (eqi(key, "username_claim")) {
            copy_z(is->username_claim, sizeof(is->username_claim), val);
        } else if (eqi(key, "groups_claim")) {
            copy_z(is->groups_claim, sizeof(is->groups_claim), val);
        } else if (eqi(key, "default_user")) {
            copy_z(is->default_user, sizeof(is->default_user), val);
        } else if (eqi(key, "name_mapfile")) {
            copy_z(is->name_mapfile, sizeof(is->name_mapfile), val);
        } else if (eqi(key, "jwks_file")) {
            copy_z(is->jwks_path, sizeof(is->jwks_path), val);
        } else if (eqi(key, "onmissing")) {
            is->onmissing_fail = eqi(val, "fail");
        } else if (eqi(key, "enabled")) {
            is->enabled = parse_bool(val);
        } else if (eqi(key, "authorization_strategy")) {
            is->strategy = brix_token_strategy_parse(val);
        } else {
            ngx_log_error(NGX_LOG_WARN, reg->log, 0,
                "scitokens: unsupported issuer key \"%s\" (ignored)", key);
        }
        return 0;
    }

    if (eqi(section, "Global")) {
        if (eqi(key, "audience") || eqi(key, "audience_json")) {
            reg_add_aud(reg->global_audiences, &reg->global_audience_count,
                BRIX_TOKEN_MAX_AUDIENCES, val);
        } else {
            ngx_log_error(NGX_LOG_WARN, reg->log, 0,
                "scitokens: unsupported [Global] key \"%s\" (ignored)", key);
        }
        return 0;
    }

    return 0;                                   /* unknown / no section */
}

/* brix_token_registry_load — parse + validate + load JWKS */ngx_int_t
brix_token_registry_load(brix_token_registry_t *reg, const char *cfg_path,
    uint32_t default_strategy, char *errbuf, size_t errlen)
{
    int i;

    reg->default_strategy = default_strategy;

    if (brix_ini_parse_file(cfg_path, reg_kv, reg, errbuf, errlen) != 0) {
        return NGX_ERROR;
    }
    if (reg->count == 0) {
        snprintf(errbuf, errlen, "%s: no [Issuer ...] section found", cfg_path);
        return NGX_ERROR;
    }

    for (i = 0; i < reg->count; i++) {
        brix_token_issuer_t *is = &reg->issuers[i];

        if (is->issuer[0] == '\0') {
            snprintf(errbuf, errlen,
                "issuer \"%s\": missing issuer= URL", is->name);
            return NGX_ERROR;
        }
        if (is->base_path_count == 0) {
            snprintf(errbuf, errlen,
                "issuer \"%s\": missing base_path", is->name);
            return NGX_ERROR;
        }
        if (is->jwks_path[0] != '\0') {
            struct stat st;

            is->jwks_key_count = brix_jwks_load(reg->log, is->jwks_path,
                is->jwks_keys, BRIX_MAX_JWKS_KEYS);
            if (is->jwks_key_count <= 0) {
                snprintf(errbuf, errlen,
                    "issuer \"%s\": no usable JWKS keys in %s",
                    is->name, is->jwks_path);
                return NGX_ERROR;
            }
            if (stat(is->jwks_path, &st) == 0) {
                is->jwks_mtime = st.st_mtime;
            }
        }
    }
    return NGX_OK;
}

/* brix_token_registry_build — config-time allocate + load + cleanup */ngx_int_t
brix_token_registry_build(ngx_conf_t *cf, const char *cfg_path,
    uint32_t default_strategy, brix_token_registry_t **out)
{
    brix_token_registry_t *reg;
    char                     err[256];
    int                      i;

    reg = ngx_pcalloc(cf->pool, sizeof(*reg));
    if (reg == NULL) {
        return NGX_ERROR;
    }
    reg->log = cf->log;

    if (brix_token_registry_load(reg, cfg_path, default_strategy,
                                   err, sizeof(err)) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_token_config: %s", err);
        return NGX_ERROR;
    }

    /* Free each issuer's loaded EVP_PKEYs when the conf pool is destroyed. */
    for (i = 0; i < reg->count; i++) {
        if (reg->issuers[i].jwks_key_count > 0
            && brix_jwks_register_cleanup(cf->pool, reg->issuers[i].jwks_keys,
                   &reg->issuers[i].jwks_key_count) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix_token: loaded %d issuer(s) from %s", reg->count, cfg_path);
    *out = reg;
    return NGX_OK;
}

/* brix_token_registry_find — exact-iss lookup over enabled issuers */const brix_token_issuer_t *
brix_token_registry_find(const brix_token_registry_t *reg, const char *iss)
{
    int i;

    for (i = 0; i < reg->count; i++) {
        if (reg->issuers[i].enabled
            && strcmp(reg->issuers[i].issuer, iss) == 0)
        {
            return &reg->issuers[i];
        }
    }
    return NULL;
}

/* brix_token_issuer_path_ok — base_path ∧ ¬restricted_path gate */int
brix_token_issuer_path_ok(const brix_token_issuer_t *is,
    const char *req_path)
{
    int i;
    int under_base = 0;

    for (i = 0; i < is->base_path_count; i++) {
        if (brix_token_scope_path_matches(is->base_paths[i], req_path)) {
            under_base = 1;
            break;
        }
    }
    if (!under_base) {
        return 0;
    }
    for (i = 0; i < is->restricted_path_count; i++) {
        if (brix_token_scope_path_matches(is->restricted_paths[i], req_path)) {
            return 0;                           /* explicitly carved out */
        }
    }
    return 1;
}
