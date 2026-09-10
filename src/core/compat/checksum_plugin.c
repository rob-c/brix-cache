/*
 * Site checksum plugin registry — see core/compat/checksum_plugin.h.
 */

#include "core/compat/checksum_plugin.h"

#include <dlfcn.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "core/compat/checksum_core.h"

/* The ABI promises a plugin digest always fits a host digest buffer. */
typedef char brix_cks_digest_bound_check[
    (BRIX_CKS_PLUGIN_DIGEST_MAX <= EVP_MAX_MD_SIZE) ? 1 : -1];

#define CKS_PLUGIN_PARMS_MAX  255

typedef struct {
    char                      name[BRIX_CKS_PLUGIN_NAME_MAX + 1];
    char                      parms[CKS_PLUGIN_PARMS_MAX + 1];
    void                     *handle;
    const brix_cks_plugin_t  *api;
} cks_plugin_ent_t;

typedef struct {
    ngx_cycle_t       *cycle;
    ngx_uint_t         n;
    cks_plugin_ent_t   ent[BRIX_CKS_PLUGINS_MAX];
} cks_plugin_registry_t;

/* Process-wide, keyed on the cycle (the dns_registry precedent): the config
 * parser of a new cycle owns it from its first directive on. */
static cks_plugin_registry_t  cks_plugins;


static void
cks_registry_reset(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    if (cks_plugins.cycle == cycle) {
        return;
    }

    for (i = 0; i < cks_plugins.n; i++) {
        if (cks_plugins.ent[i].handle != NULL) {
            dlclose(cks_plugins.ent[i].handle);
        }
    }

    ngx_memzero(&cks_plugins, sizeof(cks_plugins));
    cks_plugins.cycle = cycle;
}


void
brix_cks_plugins_init_worker(ngx_cycle_t *cycle)
{
    cks_registry_reset(cycle);
}


/* Lowercase alnum copy of `name` into `out` (BRIX_CKS_PLUGIN_NAME_MAX + 1
 * wide). NGX_ERROR when the name is empty, too long or carries any other
 * character: a plugin name must round-trip through the wire parser's own
 * normalization (which strips punctuation) unchanged. */
static ngx_int_t
cks_normalize_name(const u_char *p, size_t len, char *out)
{
    size_t  i;

    if (len == 0 || len > BRIX_CKS_PLUGIN_NAME_MAX) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        if (!isalnum((unsigned char) p[i])) {
            return NGX_ERROR;
        }
        out[i] = (char) ngx_tolower(p[i]);
    }

    out[len] = '\0';
    return NGX_OK;
}


static ngx_int_t
cks_plugin_file_ok(ngx_conf_t *cf, ngx_str_t *path)
{
    struct stat  st;

    if (path->len == 0 || path->data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: path \"%V\" must be absolute", path);
        return NGX_ERROR;
    }

    if (stat((const char *) path->data, &st) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix_checksum_plugin: stat(\"%V\") failed", path);
        return NGX_ERROR;
    }

    if (!S_ISREG(st.st_mode)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: \"%V\" is not a regular file", path);
        return NGX_ERROR;
    }

    /* A plugin runs inside every worker; a file another account can rewrite
     * is arbitrary code injection, so refuse it the way sshd refuses a
     * group/world-writable key. */
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: \"%V\" is group- or world-writable", path);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static const char *
cks_api_check(const brix_cks_plugin_t *api, const char *lname)
{
    char  pname[BRIX_CKS_PLUGIN_NAME_MAX + 1];

    if (api->abi != BRIX_CKS_PLUGIN_ABI) {
        return "ABI version mismatch";
    }

    if (api->name == NULL
        || cks_normalize_name((const u_char *) api->name,
                              ngx_strlen(api->name), pname) != NGX_OK
        || ngx_strcmp(pname, lname) != 0)
    {
        return "plugin name does not match the directive";
    }

    if (api->digest_len == 0 || api->digest_len > BRIX_CKS_PLUGIN_DIGEST_MAX) {
        return "digest_len out of range";
    }

    if (api->state_size == 0 || api->state_size > BRIX_CKS_PLUGIN_STATE_MAX) {
        return "state_size out of range";
    }

    if (api->init == NULL || api->update == NULL || api->final == NULL) {
        return "missing init/update/final";
    }

    return NULL;
}


/* Empty-input round trip with the configured parms: a plugin that cannot
 * digest zero bytes at config time will not digest a file in a worker. */
static ngx_int_t
cks_self_test(const brix_cks_plugin_t *api, const char *parms)
{
    unsigned char  state[BRIX_CKS_PLUGIN_STATE_MAX];
    unsigned char  digest[BRIX_CKS_PLUGIN_DIGEST_MAX];

    ngx_memzero(state, sizeof(state));

    if (api->init(state, parms) != 0
        || api->update(state, (const unsigned char *) "", 0) != 0
        || api->final(state, digest) != 0)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
cks_plugin_load(ngx_conf_t *cf, cks_plugin_ent_t *ent, ngx_str_t *path)
{
    const char  *why;
    void        *sym;

    ent->handle = dlopen((const char *) path->data, RTLD_NOW | RTLD_LOCAL);
    if (ent->handle == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: dlopen(\"%V\") failed: %s", path, dlerror());
        return NGX_ERROR;
    }

    sym = dlsym(ent->handle, BRIX_CKS_PLUGIN_SYMBOL);
    if (sym == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: \"%V\" exports no %s symbol",
            path, BRIX_CKS_PLUGIN_SYMBOL);
        return NGX_ERROR;
    }

    ent->api = (const brix_cks_plugin_t *) sym;

    why = cks_api_check(ent->api, ent->name);
    if (why != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: \"%V\": %s", path, why);
        return NGX_ERROR;
    }

    if (cks_self_test(ent->api, ent->parms) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: \"%V\" failed its self-test with parms \"%s\"",
            path, ent->parms);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
brix_cks_plugin_register(ngx_conf_t *cf, ngx_str_t *name, ngx_str_t *path,
    ngx_str_t *parms)
{
    cks_plugin_ent_t     *ent;
    brix_checksum_alg_t   taken;

    cks_registry_reset(cf->cycle);

    if (cks_plugins.n >= BRIX_CKS_PLUGINS_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: at most %ui plugins per server",
            (ngx_uint_t) BRIX_CKS_PLUGINS_MAX);
        return NGX_ERROR;
    }

    ent = &cks_plugins.ent[cks_plugins.n];
    ngx_memzero(ent, sizeof(*ent));

    if (cks_normalize_name(name->data, name->len, ent->name) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: name \"%V\" must be 1..%d letters or digits",
            name, BRIX_CKS_PLUGIN_NAME_MAX);
        return NGX_ERROR;
    }

    /* Built-ins, their aliases (crc64xz) and earlier plugins all resolve
     * through the one parser: a hit means the name is spoken for. */
    if (brix_checksum_parse(ent->name, ngx_strlen(ent->name), &taken,
                            NULL, 0) == NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: name \"%s\" collides with a built-in "
            "algorithm or an earlier plugin", ent->name);
        return NGX_ERROR;
    }

    if (parms->len > CKS_PLUGIN_PARMS_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_checksum_plugin: parms longer than %d bytes",
            CKS_PLUGIN_PARMS_MAX);
        return NGX_ERROR;
    }

    ngx_memcpy(ent->parms, parms->data, parms->len);
    ent->parms[parms->len] = '\0';

    if (cks_plugin_file_ok(cf, path) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cks_plugin_load(cf, ent, path) != NGX_OK) {
        if (ent->handle != NULL) {
            dlclose(ent->handle);
        }
        ngx_memzero(ent, sizeof(*ent));
        return NGX_ERROR;
    }

    cks_plugins.n++;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
        "brix_checksum_plugin: registered \"%s\" from \"%V\" (%uz-byte digest)",
        ent->name, path, ent->api->digest_len);

    return NGX_OK;
}


char *
brix_checksum_plugin_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t  *v = cf->args->elts;
    ngx_str_t   parms = ngx_null_string;

    if (cf->args->nelts == 4) {
        parms = v[3];
    }

    if (brix_cks_plugin_register(cf, &v[1], &v[2], &parms) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static const cks_plugin_ent_t *
cks_plugin_at(brix_checksum_alg_t alg)
{
    ngx_uint_t  i;

    if ((ngx_int_t) alg < BRIX_CHECKSUM_PLUGIN_BASE) {
        return NULL;
    }

    i = (ngx_uint_t) alg - BRIX_CHECKSUM_PLUGIN_BASE;
    if (i >= cks_plugins.n) {
        return NULL;
    }

    return &cks_plugins.ent[i];
}


ngx_int_t
brix_cks_plugin_lookup(const char *lname, brix_checksum_alg_t *alg)
{
    ngx_uint_t  i;

    for (i = 0; i < cks_plugins.n; i++) {
        if (ngx_strcmp(cks_plugins.ent[i].name, lname) == 0) {
            *alg = (brix_checksum_alg_t) (BRIX_CHECKSUM_PLUGIN_BASE + i);
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


const char *
brix_cks_plugin_name(brix_checksum_alg_t alg)
{
    const cks_plugin_ent_t  *ent = cks_plugin_at(alg);

    return (ent != NULL) ? ent->name : NULL;
}


ngx_uint_t
brix_cks_plugin_count(void)
{
    return cks_plugins.n;
}


const char *
brix_cks_plugin_name_at(ngx_uint_t i)
{
    return (i < cks_plugins.n) ? cks_plugins.ent[i].name : NULL;
}


typedef struct {
    const brix_cks_plugin_t  *api;
    void                     *state;
} cks_fold_ctx_t;


static int
cks_fold_chunk(const unsigned char *buf, size_t n, void *arg)
{
    cks_fold_ctx_t  *c = arg;

    return c->api->update(c->state, buf, n);
}


ngx_int_t
brix_cksum_plugin_obj(brix_checksum_alg_t alg, brix_sd_obj_t *obj,
    unsigned char *out, size_t *outlen)
{
    const cks_plugin_ent_t  *ent = cks_plugin_at(alg);
    unsigned char            state[BRIX_CKS_PLUGIN_STATE_MAX];
    cks_fold_ctx_t           ctx;

    if (ent == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(state, ent->api->state_size);
    ctx.api = ent->api;
    ctx.state = state;

    if (ent->api->init(state, ent->parms) != 0) {
        return NGX_ERROR;
    }

    if (brix_cksum_walk_obj(obj, 0, -1, cks_fold_chunk, &ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ent->api->final(state, out) != 0) {
        return NGX_ERROR;
    }

    *outlen = ent->api->digest_len;
    return NGX_OK;
}
