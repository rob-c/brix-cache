/*
 * token_cache.c — cross-worker JWT validation cache (see token_cache.h).
 *
 * The cache value is the whole brix_token_claims_t struct, copied verbatim;
 * the key is the 32-byte SHA-256 of the raw token bytes.  A configured zone
 * must therefore have key>=32 and val>=sizeof(brix_token_claims_t), which
 * the directive setter enforces.
 */
#include "core/ngx_brix_module.h"
#include "token_cache.h"
#include "core/compat/crypto.h"

#include <time.h>

/* Never serve a cached token for longer than this regardless of `exp`. */
#define BRIX_TOKEN_CACHE_MAX_TTL_MS  (5 * 60 * 1000)

int
brix_token_cache_lookup(brix_kv_t *kv, const char *token,
    size_t token_len, brix_token_claims_t *claims)
{
    u_char  fp[32];
    size_t  vlen = sizeof(*claims);

    if (kv == NULL || token == NULL || token_len == 0) {
        return 0;
    }
    if (brix_sha256((const u_char *) token, token_len, fp) != 1) {
        return 0;
    }
    if (brix_kv_get(kv, fp, sizeof(fp), claims, &vlen) != 1) {
        return 0;
    }
    if (vlen != sizeof(*claims)) {
        return 0;                          /* unexpected size — ignore */
    }
    /* Defensive: never hand back an already-expired token. */
    if (claims->exp != 0 && claims->exp <= (int64_t) time(NULL)) {
        return 0;
    }
    return 1;
}

void
brix_token_cache_store(brix_kv_t *kv, const char *token,
    size_t token_len, const brix_token_claims_t *claims)
{
    u_char      fp[32];
    int64_t     now, remaining;
    ngx_msec_t  ttl;

    if (kv == NULL || token == NULL || token_len == 0) {
        return;
    }
    if (brix_sha256((const u_char *) token, token_len, fp) != 1) {
        return;
    }

    if (claims->exp <= 0) {
        ttl = BRIX_TOKEN_CACHE_MAX_TTL_MS;
    } else {
        now       = (int64_t) time(NULL);
        remaining = claims->exp - now;
        if (remaining <= 0) {
            return;                        /* already expired — don't cache */
        }
        if (remaining > BRIX_TOKEN_CACHE_MAX_TTL_MS / 1000) {
            ttl = BRIX_TOKEN_CACHE_MAX_TTL_MS;
        } else {
            ttl = (ngx_msec_t) (remaining * 1000);
        }
    }

    (void) brix_kv_set(kv, fp, sizeof(fp), claims, sizeof(*claims), ttl);
}

char *
brix_token_cache_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_kv_t **slot  = (brix_kv_t **) ((char *) conf + cmd->offset);
    ngx_str_t    *value = cf->args->elts;
    ngx_str_t     zone  = ngx_null_string;
    ngx_uint_t    i;
    brix_kv_t  *kv;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            zone.data = value[i].data + 5;
            zone.len  = value[i].len - 5;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid brix_token_cache parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (zone.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_token_cache requires zone=<name>");
        return NGX_CONF_ERROR;
    }

    kv = brix_kv_find(&zone);
    if (kv == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_token_cache: unknown zone \"%V\" "
            "(declare it with brix_kv_zone first)", &zone);
        return NGX_CONF_ERROR;
    }
    if (kv->key_max < 32 || kv->val_max < sizeof(brix_token_claims_t)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_token_cache zone \"%V\" too small: need key>=32 val>=%uz",
            &zone, sizeof(brix_token_claims_t));
        return NGX_CONF_ERROR;
    }

    *slot = kv;
    return NGX_CONF_OK;
}
