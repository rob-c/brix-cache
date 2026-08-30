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

/* brix_vfs_backend_entry_claim — see vfs_backend_config_internal.h. */
brix_vfs_backend_entry_t *
brix_vfs_backend_entry_claim(const char *root_canon, const char *backend)
{
    brix_vfs_backend_entry_t *e;

    e = brix_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return NULL;
    }
    VFS_BE_STR(e, backend, backend);
    return e;
}

/*
 * WHAT: Copy the value of one "key=value" query declaration out of an origin
 *       spec into out[cap]; "" when the key is absent.
 * WHY:  The http and s3 origin grammars carry the same query suffix, and the
 *       terminator set is the part that is easy to get wrong: a value runs to
 *       '&' OR to '|' (the T11 pipe that separates failover origins), and a
 *       value that swallowed the pipe would silently take the next origin's URL
 *       with it. Stating that once is the point of this helper.
 * HOW:  `key` carries its own '=' so a key that is a prefix of another cannot
 *       match it. Truncation is refused rather than silently applied — a
 *       half-copied path is a DIFFERENT path — so an oversized value reads as
 *       absent and the declaration it carried simply does not take effect.
 */
void
brix_vfs_origin_opt_str(const u_char *spec, const char *key, char *out,
    size_t cap)
{
    const u_char *p;
    size_t        n = 0;

    if (out == NULL || cap == 0) {
        return;
    }
    out[0] = '\0';
    if (spec == NULL || key == NULL) {
        return;
    }
    p = (const u_char *) ngx_strstr(spec, key);
    if (p == NULL) {
        return;
    }
    p += ngx_strlen(key);
    while (p[n] != '\0' && p[n] != '&' && p[n] != '|') {
        n++;
    }
    if (n == 0 || n >= cap) {
        return;                        /* absent, or too long to carry intact */
    }
    ngx_memcpy(out, p, n);
    out[n] = '\0';
}


/*
 * WHAT: The integer form of brix_vfs_origin_opt_str: the declaration's value as
 *       a non-negative decimal, or `dflt` when it is absent or malformed.
 * WHY:  Tuning values (restore_days) are read exactly like path values, and a
 *       typo must fall back to the documented default rather than to 0 — 0 has
 *       its own meaning in most of these fields.
 * HOW:  ngx_atoi over the extracted span; NGX_ERROR (its "not a number") and an
 *       absent key are the same outcome.
 */
int
brix_vfs_origin_opt_int(const u_char *spec, const char *key, int dflt)
{
    char       buf[32];
    ngx_int_t  v;

    brix_vfs_origin_opt_str(spec, key, buf, sizeof(buf));
    if (buf[0] == '\0') {
        return dflt;
    }
    v = ngx_atoi((u_char *) buf, ngx_strlen(buf));
    if (v == NGX_ERROR) {
        return dflt;
    }
    return (int) v;
}


/* brix_vfs_backend_set_origin — see vfs_backend_config_internal.h. */
void
brix_vfs_backend_set_origin(brix_vfs_backend_entry_t *e, const char *host,
    int port, int tls, const char *path, int put_checksum)
{
    VFS_BE_STR(e, origin_host, host);
    e->origin_port = port;
    e->origin_tls  = tls;
    VFS_BE_STR(e, origin_path, path);
    e->origin_put_checksum = put_checksum ? 1 : 0;   /* #12 */
    e->inst = NULL;                                  /* rebuilt on next resolve */
}

/* Register a fixed-extent block backend (sd_block server plane). `device` is the
 * block device (or a regular file used as one); the export presents it as a flat
 * namespace of equal-size extents "/0".."/N-1". The per-extent size is the
 * export's block_size (0 ⇒ the whole device is a single extent "/0", since
 * brix_storage_backend carries no block_size argument). */
static void
brix_vfs_backend_config_block(const char *root_canon, const char *device,
    size_t block_size)
{
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0'
        || device == NULL || device[0] == '\0')
    {
        return;
    }
    e = brix_vfs_backend_entry_claim(root_canon, "block");
    if (e == NULL) {
        return;
    }
    e->block_size = (int64_t) block_size;      /* per-extent size (0 ⇒ whole dev) */
    VFS_BE_STR(e, origin_path, device);        /* the block device / file path */
    e->inst = NULL;
}

/* "mirage:<size>" → the sizes-only SYNTHETIC backend (sd_mirage, §3 row 14):
 * every path opens read-only as a regular file of <size> bytes whose content is
 * the deterministic offset pattern — protocol/throughput testing with zero
 * storage. <size> takes the usual k/m/g suffixes. Returns NGX_OK if it claimed
 * the value (NGX_ERROR on a malformed size), else NGX_DECLINED. */
static ngx_int_t
vfs_parse_mirage_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb)
{
    ngx_str_t                   szs;
    off_t                       size;
    brix_vfs_backend_entry_t *e;

    if (sb->len <= sizeof("mirage:") - 1
        || ngx_strncmp(sb->data, "mirage:", sizeof("mirage:") - 1) != 0)
    {
        return NGX_DECLINED;
    }
    szs.data = sb->data + sizeof("mirage:") - 1;
    szs.len  = sb->len - (sizeof("mirage:") - 1);

    size = ngx_parse_offset(&szs);
    if (size == NGX_ERROR || size < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend: mirage size \"%V\" is not a valid "
            "non-negative size", &szs);
        return NGX_ERROR;
    }
    if (root_canon == NULL || root_canon[0] == '\0') {
        return NGX_OK;   /* no namespace anchor — nothing to register */
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return NGX_OK;
    }
    ngx_memcpy(e->backend, "mirage", sizeof("mirage"));
    e->origin_path[0] = '\0';            /* no backing path — synthetic */
    e->block_size = (int64_t) size;      /* reused as the synthetic size */
    e->inst = NULL;
    return NGX_OK;
}

/* "block:<device>" / "block://<device>" → a fixed-extent block backend served by
 * sd_block. Returns NGX_OK if it claimed the value, else NGX_DECLINED. */
static ngx_int_t
vfs_parse_block_origin(const char *root_canon, const ngx_str_t *sb,
    size_t block_size)
{
    const u_char *dev = NULL;
    size_t        devn = 0;
    char          buf[1024];

    if (sb->len > sizeof("block://") - 1
        && ngx_strncmp(sb->data, "block://", sizeof("block://") - 1) == 0)
    {
        dev  = sb->data + sizeof("block://") - 1;
        devn = sb->len - (sizeof("block://") - 1);
    } else if (sb->len > sizeof("block:") - 1
        && ngx_strncmp(sb->data, "block:", sizeof("block:") - 1) == 0)
    {
        dev  = sb->data + sizeof("block:") - 1;
        devn = sb->len - (sizeof("block:") - 1);
    }

    if (dev == NULL) {
        return NGX_DECLINED;
    }
    if (devn == 0 || devn >= sizeof(buf)) {
        return NGX_DECLINED;
    }
    ngx_memcpy(buf, dev, devn);
    buf[devn] = '\0';
    brix_vfs_backend_config_block(root_canon, buf, block_size);
    return NGX_OK;
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

    rc = vfs_parse_mirage_origin(cf, root_canon, sb);
    if (rc != NGX_DECLINED) { return rc; }
    rc = vfs_parse_block_origin(root_canon, sb, block_size);
    if (rc != NGX_DECLINED) { return rc; }
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
