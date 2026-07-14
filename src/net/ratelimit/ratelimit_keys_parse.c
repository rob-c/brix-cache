/*
 * ratelimit_keys_parse.c — Phase 25 directive value primitives + zone directive.
 *
 * The value primitives (key=/rate=/burst= grammar) and the brix_rate_limit_zone
 * setter split out of ratelimit_keys.c.  The four rl_parse_* helpers are shared
 * with the rule builders in ratelimit_keys_rules.c and are declared in
 * ratelimit_keys_internal.h.
 */
#include "ratelimit.h"
#include "protocols/webdav/webdav.h"      /* ngx_http_brix_webdav_req_ctx_t */
#include "ratelimit_keys_internal.h"


/* directive parameter parsing */
/* Parse "key=<type>[:<prefix>]" into rule->key_type / rule->key_match.
 * sizeof("key=")-1 == 4 strips the literal prefix; the value tail is then split
 * on the first ':' into <type> and an optional <prefix> (used only by VOLUME). */
ngx_int_t
rl_parse_key(ngx_conf_t *cf, ngx_str_t *v, brix_rl_rule_t *rule)
{
    ngx_str_t  val = { v->len - (sizeof("key=") - 1),
                       v->data + sizeof("key=") - 1 };
    u_char    *colon;
    ngx_str_t  type = val, prefix = { 0, NULL };

    /* If a ':' is present, narrow `type` to the part before it and point
     * `prefix` at the (non-NUL-terminated) remainder after it. */
    colon = ngx_strlchr(val.data, val.data + val.len, ':');
    if (colon != NULL) {
        type.len   = colon - val.data;
        prefix.data = colon + 1;
        prefix.len  = val.data + val.len - (colon + 1);
    }

    if (type.len == 2 && ngx_strncmp(type.data, "vo", 2) == 0) {
        rule->key_type = BRIX_RL_KEY_VO;
    } else if (type.len == 6 && ngx_strncmp(type.data, "issuer", 6) == 0) {
        rule->key_type = BRIX_RL_KEY_ISSUER;
    } else if (type.len == 2 && ngx_strncmp(type.data, "ip", 2) == 0) {
        rule->key_type = BRIX_RL_KEY_IP;
    } else if (type.len == 2 && ngx_strncmp(type.data, "dn", 2) == 0) {
        rule->key_type = BRIX_RL_KEY_DN;
    } else if (type.len == 6 && ngx_strncmp(type.data, "volume", 6) == 0) {
        rule->key_type  = BRIX_RL_KEY_VOLUME;
        rule->key_match = prefix;        /* points into cf->args memory (persists) */
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd rate limit: unknown key \"%V\" (expected"
            " vo|issuer|ip|dn|volume[:<prefix>])", &type);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Parse "<N>r/s" → requests/s (returns the integer N, or NGX_ERROR). */
ngx_int_t
rl_parse_req_rate(ngx_str_t *v)
{
    if (v->len < 4 || ngx_strncmp(v->data + v->len - 3, "r/s", 3) != 0) {
        return NGX_ERROR;
    }
    return ngx_atoi(v->data, v->len - 3);
}

/* Parse "<N>[k|m|g]/s" → bytes/s.  Returns NGX_ERROR on bad input.
 * Layout: strip the trailing "/s", then consume an optional binary-unit suffix
 * (k/m/g = 1024^1..3) off the end so ngx_atoi sees only the digits. */
ssize_t
rl_parse_bw_rate(ngx_str_t *v)
{
    ngx_str_t  num = *v;
    off_t      mult = 1;

    if (v->len < 3 || ngx_strncmp(v->data + v->len - 2, "/s", 2) != 0) {
        return NGX_ERROR;
    }
    num.len = v->len - 2;                         /* drop "/s" */
    switch (num.data[num.len - 1]) {              /* optional unit suffix */
    case 'k': case 'K': mult = 1024;          num.len--; break;
    case 'm': case 'M': mult = 1024 * 1024;   num.len--; break;
    case 'g': case 'G': mult = 1024L * 1024 * 1024; num.len--; break;
    default: break;
    }
    {
        ngx_int_t n = ngx_atoi(num.data, num.len);
        if (n == NGX_ERROR) { return NGX_ERROR; }
        return (ssize_t) ((off_t) n * mult);
    }
}

/* Parse "<N>[k|m|g]" → bytes (burst). */
ssize_t
rl_parse_size(ngx_str_t *v)
{
    return ngx_parse_size(v);   /* nginx: handles k/m/g suffixes */
}


/* zone directive: brix_rate_limit_zone zone=NAME:SIZE */
char *
brix_rl_zone_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t  *value = cf->args->elts;
    ngx_str_t   spec, name, sizestr;
    u_char     *colon;
    ssize_t     size;
    ngx_uint_t  i;

    (void) cmd; (void) conf;

    name.len = 0; name.data = NULL;
    sizestr.len = 0; sizestr.data = NULL;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len > 5
            && ngx_strncmp(value[i].data, "zone=", 5) == 0)
        {
            spec.data = value[i].data + 5;
            spec.len  = value[i].len - 5;
            colon = ngx_strlchr(spec.data, spec.data + spec.len, ':');
            if (colon == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "brix_rate_limit_zone: expected zone=NAME:SIZE");
                return NGX_CONF_ERROR;
            }
            name.data = spec.data;
            name.len  = colon - spec.data;
            sizestr.data = colon + 1;
            sizestr.len  = spec.data + spec.len - (colon + 1);
        }
    }

    if (name.len == 0 || sizestr.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_rate_limit_zone: missing zone=NAME:SIZE");
        return NGX_CONF_ERROR;
    }
    size = rl_parse_size(&sizestr);
    if (size == NGX_ERROR || size <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_rate_limit_zone: bad size \"%V\"", &sizestr);
        return NGX_CONF_ERROR;
    }

    if (brix_rl_zone_add(cf, &name, (size_t) size, NULL) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
