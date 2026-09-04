/*
 * vfs_backend_config_n2n.c — config-time validation and registration of the
 * per-export logical-to-physical name mapping.
 *
 * WHAT: Parses brix_n2n_scheme and applies the optional pool/prefix values to
 *       the backend-registry entry for one canonical export root.
 * WHY:  Name mapping has its own validation contract and is independent of the
 *       backend-origin parser. Keeping it in a focused unit holds the config
 *       dispatcher below the source-size limit and keeps each validation step
 *       small enough to audit.
 * HOW:  Parse the scheme, resolve the existing backend entry, validate the
 *       backend/scheme combination and bounded strings, then replace the
 *       entry's mapping and invalidate its lazily built instance.
 */
#include "vfs_backend_config_internal.h"

/* Parse one configured scheme name into the internal mapping vocabulary. */
static ngx_int_t
vfs_n2n_scheme_parse(const ngx_str_t *scheme, brix_n2n_scheme_t *out)
{
    if (scheme->len == sizeof("identity") - 1
        && ngx_strncmp(scheme->data, "identity", scheme->len) == 0)
    {
        *out = BRIX_N2N_IDENTITY;
        return NGX_OK;
    }
    if (scheme->len == sizeof("ral") - 1
        && ngx_strncmp(scheme->data, "ral", scheme->len) == 0)
    {
        *out = BRIX_N2N_RAL;
        return NGX_OK;
    }
    if (scheme->len == sizeof("cephfs_path") - 1
        && ngx_strncmp(scheme->data, "cephfs_path", scheme->len) == 0)
    {
        *out = BRIX_N2N_CEPHFS_PATH;
        return NGX_OK;
    }
    return NGX_DECLINED;
}

/* Refuse scheme/backend combinations that would address a different object. */
static ngx_int_t
vfs_n2n_validate_backend(ngx_conf_t *cf, const brix_vfs_backend_entry_t *entry,
    brix_n2n_scheme_t scheme, const ngx_str_t *pool)
{
    if (scheme == BRIX_N2N_RAL && ngx_strcmp(entry->backend, "ceph") == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "brix_n2n_scheme ral is invalid "
            "for the ceph/RADOS backend: its pool is bound at the ioctx and "
            "objects are named \"<prefix><lfn>\" — use cephfs_path");
        return NGX_ERROR;
    }
    if (scheme == BRIX_N2N_RAL && (pool == NULL || pool->len == 0)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_n2n_scheme ral requires brix_n2n_pool");
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Validate that configured mapping components fit their registry fields. */
static ngx_int_t
vfs_n2n_validate_lengths(ngx_conf_t *cf,
    const brix_vfs_backend_entry_t *entry, const ngx_str_t *pool,
    const ngx_str_t *prefix)
{
    if (pool != NULL && pool->len >= sizeof(entry->n2n.pool)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "brix_n2n_pool is too long "
            "(%uz bytes; max %uz)", pool->len, sizeof(entry->n2n.pool) - 1);
        return NGX_ERROR;
    }
    if (prefix != NULL && prefix->len >= sizeof(entry->n2n.prefix)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "brix_n2n_prefix is too long "
            "(%uz bytes; max %uz)", prefix->len,
            sizeof(entry->n2n.prefix) - 1);
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Store an already-validated mapping and invalidate the cached driver stack. */
static void
vfs_n2n_assign(brix_vfs_backend_entry_t *entry, brix_n2n_scheme_t scheme,
    const ngx_str_t *pool, const ngx_str_t *prefix)
{
    entry->n2n.scheme = scheme;
    if (pool != NULL && pool->len > 0) {
        ngx_cpystrn((u_char *) entry->n2n.pool, pool->data,
                    ngx_min(pool->len + 1, sizeof(entry->n2n.pool)));
    } else if (scheme != BRIX_N2N_RAL) {
        entry->n2n.pool[0] = '\0';
    }
    if (prefix != NULL && prefix->len > 0) {
        ngx_cpystrn((u_char *) entry->n2n.prefix, prefix->data,
                    ngx_min(prefix->len + 1, sizeof(entry->n2n.prefix)));
    }
    entry->inst = NULL;
}

/* Apply the explicit per-export N2N configuration; an unset scheme preserves
 * the backend parser's derived default. Returns NGX_OK or a logged NGX_ERROR. */
ngx_int_t
brix_vfs_backend_config_n2n(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *scheme, const ngx_str_t *pool, const ngx_str_t *prefix)
{
    brix_vfs_backend_entry_t *entry;
    brix_n2n_scheme_t         parsed;

    if (scheme == NULL || scheme->len == 0) {
        return NGX_OK;
    }
    if (vfs_n2n_scheme_parse(scheme, &parsed) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "brix_n2n_scheme: unknown "
            "scheme \"%V\" (want identity | ral | cephfs_path)", scheme);
        return NGX_ERROR;
    }
    entry = brix_vfs_backend_entry_find(root_canon);
    if (entry == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "brix_n2n_scheme: no storage "
            "backend is configured for this export to translate names for");
        return NGX_ERROR;
    }
    if (vfs_n2n_validate_backend(cf, entry, parsed, pool) != NGX_OK
        || vfs_n2n_validate_lengths(cf, entry, pool, prefix) != NGX_OK)
    {
        return NGX_ERROR;
    }
    vfs_n2n_assign(entry, parsed, pool, prefix);
    return NGX_OK;
}
