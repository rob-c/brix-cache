/*
 * vfs_backend_config.c — config-time half of the backend registry: the
 * brix_storage_backend directive dispatcher (config_str), the local-driver
 * (pblock/posix) entry builder, the credential setter, and the cache-tier /
 * stage-tier / staging / http-endpoint setters. The per-scheme origin parsers
 * and their per-driver entry builders live in three sibling files (phase-79
 * file-size split):
 *   vfs_backend_config_ceph.c — ceph / rados / cephfsro / tape
 *   vfs_backend_config_http.c — http(s):// origin list
 *   vfs_backend_config_s3.c   — s3:// and root(s):// / local driver
 * All four share the parse record + dispatcher entry-point declarations in
 * vfs_backend_config_internal.h. Building and resolving driver instances stays
 * in vfs_backend_registry.c (phase-38 split of the former single file).
 */
#include "vfs_backend_config_internal.h"

#include <string.h>

void
brix_vfs_backend_config(const char *root_canon, const ngx_str_t *name,
    size_t block_size)
{
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0' || name == NULL
        || name->len == 0)
    {
        return;
    }
    /* Bare local driver names register here: "pblock", and — phase-68 —
     * an EXPLICIT "posix". Naming posix (the default) was a silent no-op
     * before; registering it makes the export visible to census surfaces
     * (the dashboard VFS browser, /metrics backend info) while leaving
     * every config that doesn't name a backend exactly as it was. */
    if (!((name->len == sizeof("pblock") - 1
           && ngx_strncmp(name->data, "pblock", sizeof("pblock") - 1) == 0)
          || (name->len == sizeof("posix") - 1
              && ngx_strncmp(name->data, "posix", sizeof("posix") - 1) == 0)))
    {
        return;
    }

    /* Dedup on root_canon so a config reload updates rather than appends
     * (an existing entry keeps its backend and only refreshes block_size). */
    e = brix_vfs_backend_entry_find(root_canon);
    if (e != NULL) {
        e->block_size = (int64_t) block_size;
        e->inst = NULL;                        /* rebuilt on next resolve */
        return;
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    if (name->data[0] == 'p' && name->data[1] == 'o') {
        ngx_memcpy(e->backend, "posix", sizeof("posix"));
    } else {
        ngx_memcpy(e->backend, "pblock", sizeof("pblock"));
    }
    e->block_size = (int64_t) block_size;
}

void
brix_vfs_backend_set_credential(const char *root_canon,
    const brix_vfs_backend_cred_t *cred)
{
    brix_vfs_backend_cred_t  empty;
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0') {
        return;
    }
    if (cred == NULL) {
        ngx_memzero(&empty, sizeof(empty));     /* NULL ⇒ clear to anonymous */
        cred = &empty;
    }
    e = brix_vfs_backend_entry_find(root_canon);
    if (e != NULL) {
        ngx_cpystrn((u_char *) e->origin_token,
                    (u_char *) (cred->bearer ? cred->bearer : ""),
                    sizeof(e->origin_token));
        ngx_cpystrn((u_char *) e->origin_x509_proxy,
                    (u_char *) (cred->x509_proxy ? cred->x509_proxy : ""),
                    sizeof(e->origin_x509_proxy));
        ngx_cpystrn((u_char *) e->origin_x509_key,
                    (u_char *) (cred->x509_key ? cred->x509_key : ""),
                    sizeof(e->origin_x509_key));
        ngx_cpystrn((u_char *) e->origin_ca_dir,
                    (u_char *) (cred->ca_dir ? cred->ca_dir : ""),
                    sizeof(e->origin_ca_dir));
        ngx_cpystrn((u_char *) e->origin_s3_access_key,
                    (u_char *) (cred->s3_access_key ? cred->s3_access_key : ""),
                    sizeof(e->origin_s3_access_key));
        ngx_cpystrn((u_char *) e->origin_s3_secret_key,
                    (u_char *) (cred->s3_secret_key ? cred->s3_secret_key : ""),
                    sizeof(e->origin_s3_secret_key));
        ngx_cpystrn((u_char *) e->origin_s3_region,
                    (u_char *) (cred->s3_region ? cred->s3_region : ""),
                    sizeof(e->origin_s3_region));
        ngx_cpystrn((u_char *) e->origin_sss_keytab,
                    (u_char *) (cred->sss_keytab ? cred->sss_keytab : ""),
                    sizeof(e->origin_sss_keytab));
        e->inst = NULL;                          /* rebuilt with the credential */
    }
}

ngx_int_t
brix_vfs_backend_config_str(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb, size_t block_size, int family)
{
    ngx_int_t rc;

    if (sb == NULL) {
        return NGX_OK;
    }

    /* An export that names NO backend is the default-POSIX case. Phase-68 made
     * an EXPLICIT "posix" register; register the default too so the census
     * surfaces (dashboard /vfs + storage panel, /metrics info + capacity
     * gauges) see the most common configuration. Guard root_canon "/": a pure
     * cache node's namespace anchor is the whole host fs — never a census row. */
    if (sb->len == 0) {
        if (root_canon != NULL && root_canon[0] == '/'
            && root_canon[1] != '\0')
        {
            static const ngx_str_t posix_name = ngx_string("posix");

            brix_vfs_backend_config(root_canon, &posix_name, block_size);
        }
        return NGX_OK;
    }

    rc = vfs_parse_cephfsro_origin(cf, root_canon, sb);
    if (rc != NGX_DECLINED) { return rc; }
    rc = vfs_parse_ceph_origin(cf, root_canon, sb);
    if (rc != NGX_DECLINED) { return rc; }
    rc = vfs_parse_rados_origin(cf, root_canon, sb);
    if (rc != NGX_DECLINED) { return rc; }
    rc = vfs_parse_tape_origin(cf, root_canon, sb);
    if (rc != NGX_DECLINED) { return rc; }
    rc = vfs_parse_http_origin_list(cf, root_canon, sb);
    if (rc != NGX_DECLINED) { return rc; }
    rc = vfs_parse_s3_origin(cf, root_canon, sb);
    if (rc != NGX_DECLINED) { return rc; }
    return vfs_parse_xroot_or_driver_origin(cf, root_canon, sb, block_size, family);
}

void
brix_vfs_backend_set_staging(const char *root_canon, int on)
{
    brix_vfs_backend_entry_t *e = brix_vfs_backend_entry_find(root_canon);

    if (e != NULL) {
        e->staging = on ? 1 : 0;
    }
}

void
brix_vfs_backend_config_cache_store(const char *root_canon,
    const brix_tier_cfg_t *cfg, const brix_cache_policy_t *policy)
{
    brix_vfs_backend_entry_t *e;

    if (cfg == NULL || !cfg->configured) {
        return;
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    e->cache_tier = *cfg;
    if (policy != NULL) {
        e->cache_policy = *policy;
    }
    e->inst = NULL;                            /* recompose on next resolve */
}

void
brix_vfs_backend_config_cache_cold_store(const char *root_canon,
    const brix_tier_cfg_t *cfg)
{
    brix_vfs_backend_entry_t *e;

    if (cfg == NULL || !cfg->configured) {
        return;
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    e->cold_tier = *cfg;
    e->inst = NULL;                            /* recompose on next resolve */
}

void
brix_vfs_backend_config_cache_peers(const char *root_canon,
    const char (*hosts)[256], const int *ports, int n, int self)
{
    brix_vfs_backend_entry_t *e;
    int                        i;

    if (hosts == NULL || ports == NULL || n <= 0 || self < 0 || self >= n) {
        return;
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    if (n > (int) (sizeof(e->peer_ring) / sizeof(e->peer_ring[0]))) {
        n = (int) (sizeof(e->peer_ring) / sizeof(e->peer_ring[0]));
    }
    for (i = 0; i < n; i++) {
        ngx_cpystrn((u_char *) e->peer_ring[i].host, (u_char *) hosts[i],
                    sizeof(e->peer_ring[i].host));
        e->peer_ring[i].port = ports[i];
    }
    e->n_peer_ring = n;
    e->peer_self   = self;
    e->inst = NULL;                            /* recompose on next resolve */
}

/* Endpoint (host,port) at `idx` of the http backend registered at
 * `root_canon` — index 0 is the primary, 1.. the T11 failover list. Returns
 * 0, or -1 past the end / not an http backend. Pointers alias the registry's
 * stable storage. */
int
brix_vfs_backend_http_endpoint_at(const char *root_canon, int idx,
    const char **host, int *port)
{
    brix_vfs_backend_entry_t *e = brix_vfs_backend_entry_find(root_canon);

    if (e == NULL || ngx_strcmp(e->backend, "http") != 0 || idx < 0
        || idx > e->n_http_extra)
    {
        return -1;
    }
    if (idx == 0) {
        *host = e->origin_host;
        *port = e->origin_port;
    } else {
        *host = e->http_extra[idx - 1].host;
        *port = e->http_extra[idx - 1].port;
    }
    return 0;
}

/* Record config-time selection ranks for the http backend at `root_canon`
 * (T19 geo/static policies); applied when the per-worker instance builds. */
void
brix_vfs_backend_set_http_ranks(const char *root_canon, const int *ranks,
    int n)
{
    brix_vfs_backend_entry_t *e = brix_vfs_backend_entry_find(root_canon);
    int                         i;

    if (e == NULL || ngx_strcmp(e->backend, "http") != 0) {
        return;
    }
    for (i = 0; i < n && i < 8; i++) {
        e->http_ranks[i] = ranks[i];
    }
    e->has_http_ranks = 1;
    e->inst = NULL;                            /* re-apply on next resolve */
}

/* Runtime twin of the config-time http registration (phase-68 T14 proxy
 * mode): register (or reuse) a synthetic per-upstream export entry keyed
 * `up_root`, whose source is the http origin `host`:`port` and whose cache
 * tier mirrors the entry at `template_root` with its store path suffixed
 * `store_suffix` — so objects from different Stratum-1s can never alias in
 * the store. Runs on the worker's event loop only (the entry table is
 * per-process after fork; no cross-thread access). Returns NGX_OK, or
 * NGX_ERROR when the table is full / the paths overflow. */
ngx_int_t
brix_vfs_backend_register_http_upstream(const char *up_root,
    const char *template_root, const char *host, int port, int tls,
    const char *store_suffix)
{
    brix_vfs_backend_entry_t *e, *tpl;

    e = brix_vfs_backend_entry_find(up_root);
    if (e != NULL) {
        return NGX_OK;                          /* already registered */
    }
    tpl = brix_vfs_backend_entry_find(template_root);
    e = brix_vfs_backend_entry_get_or_create(up_root);
    if (e == NULL) {
        return NGX_ERROR;                       /* table full */
    }
    ngx_memcpy(e->backend, "http", sizeof("http"));
    ngx_cpystrn((u_char *) e->origin_host, (u_char *) host,
                sizeof(e->origin_host));
    e->origin_port = port;
    e->origin_tls  = tls;
    e->origin_path[0] = '\0';       /* the request URI carries the full path */

    if (tpl != NULL && tpl->cache_tier.configured) {
        size_t n;

        e->cache_tier   = tpl->cache_tier;
        e->cache_policy = tpl->cache_policy;
        n = ngx_strlen(e->cache_tier.path);
        if (store_suffix != NULL && store_suffix[0] != '\0') {
            if (n + ngx_strlen(store_suffix) + 1 >= sizeof(e->cache_tier.path)) {
                return NGX_ERROR;
            }
            ngx_cpystrn((u_char *) e->cache_tier.path + n,
                        (u_char *) store_suffix,
                        sizeof(e->cache_tier.path) - n);
            /* the cstore mkdirs each KEY's parents but expects its own root
             * to exist — create the per-upstream subtree now (local store) */
            if (ngx_strcmp(e->cache_tier.driver, "posix") == 0) {
                (void) brix_mkdir_recursive(e->cache_tier.path, 0755);
            }
        }
    }
    e->inst = NULL;
    return NGX_OK;
}

void
brix_vfs_backend_config_stage_store(const char *root_canon,
    const brix_tier_cfg_t *cfg, const brix_stage_policy_t *policy)
{
    brix_vfs_backend_entry_t *e;

    if (cfg == NULL || !cfg->configured) {
        return;
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    e->stage_tier = *cfg;
    if (policy != NULL) {
        e->stage_policy = *policy;
    }
    e->inst = NULL;
}
