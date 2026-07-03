/*
 * auth_cache.c — directive setter for the auth-result cache (see auth_cache.h).
 *
 * The lookup/store logic lives inline in brix_auth_gate() because that is
 * where every key input is in scope; this file only parses the directive.
 */
#include "core/ngx_brix_module.h"
#include "auth_cache.h"

char *
brix_auth_cache_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_auth_cache_conf_t *ac =
        (brix_auth_cache_conf_t *) ((char *) conf + cmd->offset);
    ngx_str_t   *value = cf->args->elts;
    ngx_str_t    zone  = ngx_null_string;
    ngx_uint_t   ttl   = BRIX_AUTH_CACHE_DEFAULT_TTL;
    ngx_uint_t   i;
    ngx_int_t    n;
    brix_kv_t *kv;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            zone.data = value[i].data + 5;
            zone.len  = value[i].len - 5;
        } else if (ngx_strncmp(value[i].data, "ttl=", 4) == 0) {
            n = ngx_atoi(value[i].data + 4, value[i].len - 4);
            if (n == NGX_ERROR || n <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid brix_auth_cache ttl \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            ttl = (ngx_uint_t) n;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid brix_auth_cache parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (zone.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_auth_cache requires zone=<name>");
        return NGX_CONF_ERROR;
    }

    kv = brix_kv_find(&zone);
    if (kv == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_auth_cache: unknown zone \"%V\" "
            "(declare it with brix_kv_zone first)", &zone);
        return NGX_CONF_ERROR;
    }
    if (kv->key_max < 32 || kv->val_max < sizeof(brix_auth_cache_val_t)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_auth_cache zone \"%V\" too small: need key>=32 val>=%uz",
            &zone, sizeof(brix_auth_cache_val_t));
        return NGX_CONF_ERROR;
    }

    ac->kv       = kv;
    ac->ttl_secs = ttl;
    return NGX_CONF_OK;
}
