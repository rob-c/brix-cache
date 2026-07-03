/*
 * vfs_backend_config.c — config-time half of the backend registry: the
 * xrootd_storage_backend directive parser (config_str), the per-driver entry
 * builders (xroot/http/s3/ceph/cephfsro/tape), and the credential / staging /
 * cache-tier / stage-tier setters. Everything here only fills registry entries;
 * building and resolving driver instances stays in vfs_backend_registry.c
 * (phase-38 split of the former single file).
 */
#include "vfs_backend_internal.h"

#include <string.h>

void
xrootd_vfs_backend_config(const char *root_canon, const ngx_str_t *name,
    size_t block_size)
{
    xrootd_vfs_backend_entry_t *e;

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
    e = xrootd_vfs_backend_entry_find(root_canon);
    if (e != NULL) {
        e->block_size = (int64_t) block_size;
        e->inst = NULL;                        /* rebuilt on next resolve */
        return;
    }
    e = xrootd_vfs_backend_entry_get_or_create(root_canon);
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

static void
xrootd_vfs_backend_set_xroot(xrootd_vfs_backend_entry_t *e, const char *host,
    int port, int tls, int family)
{
    ngx_memcpy(e->backend, "xroot", sizeof("xroot"));
    ngx_cpystrn((u_char *) e->origin_host, (u_char *) host,
                sizeof(e->origin_host));
    e->origin_port   = port;
    e->origin_tls    = tls;
    e->origin_family = family;
    e->inst          = NULL;                   /* rebuilt on next resolve */
}

void
xrootd_vfs_backend_config_xroot(const char *root_canon, const char *host,
    int port, int tls, int family)
{
    xrootd_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || port <= 0 || port > 65535)
    {
        return;
    }

    /* Dedup on root_canon so a config reload updates rather than appends. */
    e = xrootd_vfs_backend_entry_get_or_create(root_canon);
    if (e != NULL) {
        xrootd_vfs_backend_set_xroot(e, host, port, tls, family);
    }
}

void
xrootd_vfs_backend_config_http(const char *root_canon, const char *host,
    int port, int tls, const char *base_path)
{
    xrootd_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || port <= 0 || port > 65535)
    {
        return;
    }
    e = xrootd_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    ngx_memcpy(e->backend, "http", sizeof("http"));
    ngx_cpystrn((u_char *) e->origin_host, (u_char *) host,
                sizeof(e->origin_host));
    e->origin_port = port;
    e->origin_tls  = tls;
    ngx_cpystrn((u_char *) e->origin_path, (u_char *) (base_path ? base_path : ""),
                sizeof(e->origin_path));
    e->n_http_extra = 0;                       /* reload resets the T11 list */
    e->inst = NULL;                            /* rebuilt on next resolve */
}

/* Register a read-only S3 source backend for an export (phase-64): the export's
 * bytes live in a remote S3 bucket, served over the shared libcurl S3 transport
 * (signed Range GET). bucket is the path-style bucket name; port defaults to
 * 80/443 by tls when the URL omits it. The driver is CAP_RANGE_READ only, so an
 * S3 primary is read-only (writes are rejected, exactly like an http:// primary). */
void
xrootd_vfs_backend_config_s3(const char *root_canon, const char *host,
    int port, int tls, const char *bucket)
{
    xrootd_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || bucket == NULL || bucket[0] == '\0'
        || port <= 0 || port > 65535)
    {
        return;
    }
    e = xrootd_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    ngx_memcpy(e->backend, "s3", sizeof("s3"));
    ngx_cpystrn((u_char *) e->origin_host, (u_char *) host,
                sizeof(e->origin_host));
    e->origin_port = port;
    e->origin_tls  = tls;
    ngx_cpystrn((u_char *) e->origin_path, (u_char *) bucket,
                sizeof(e->origin_path));   /* origin_path carries the bucket */
    e->inst = NULL;                            /* rebuilt on next resolve */
}

/* Register a Ceph/RADOS backend for an export. pool is required; conf defaults
 * to /etc/ceph/ceph.conf and key_prefix to "" when NULL/empty. */
static void
xrootd_vfs_backend_config_ceph(const char *root_canon, const char *backend,
    const char *pool, const char *conf, const char *key_prefix)
{
    xrootd_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0'
        || pool == NULL || pool[0] == '\0')
    {
        return;
    }
    e = xrootd_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    ngx_cpystrn((u_char *) e->backend, (u_char *) backend, sizeof(e->backend));
    ngx_cpystrn((u_char *) e->ceph_pool, (u_char *) pool, sizeof(e->ceph_pool));
    ngx_cpystrn((u_char *) e->ceph_conf,
                (u_char *) ((conf && conf[0]) ? conf : "/etc/ceph/ceph.conf"),
                sizeof(e->ceph_conf));
    ngx_cpystrn((u_char *) e->ceph_key_prefix,
                (u_char *) (key_prefix ? key_prefix : ""),
                sizeof(e->ceph_key_prefix));
    e->inst = NULL;                            /* rebuilt on next resolve */
}

/* Register a read-only CephFS-via-RADOS backend. meta_pool + data_pool are
 * required; conf defaults to /etc/ceph/ceph.conf. quiesced is the operator's
 * "the filesystem is quiesced" assertion (the driver refuses to bind without it). */
static void
xrootd_vfs_backend_config_cephfs_ro(const char *root_canon, const char *meta_pool,
    const char *data_pool, const char *conf, int quiesced, int live)
{
    xrootd_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0'
        || meta_pool == NULL || meta_pool[0] == '\0'
        || data_pool == NULL || data_pool[0] == '\0')
    {
        return;
    }
    e = xrootd_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    ngx_memcpy(e->backend, "cephfsro", sizeof("cephfsro"));
    ngx_cpystrn((u_char *) e->ceph_pool, (u_char *) meta_pool, sizeof(e->ceph_pool));
    ngx_cpystrn((u_char *) e->ceph_data_pool, (u_char *) data_pool,
                sizeof(e->ceph_data_pool));
    ngx_cpystrn((u_char *) e->ceph_conf,
                (u_char *) ((conf && conf[0]) ? conf : "/etc/ceph/ceph.conf"),
                sizeof(e->ceph_conf));
    e->cephfs_quiesced = quiesced;
    e->cephfs_live = live;
    e->inst = NULL;                            /* rebuilt on next resolve */
}

/* Register a nearline (tape/MSS) backend (phase-64 SP5). `adapter` ("" = the
 * built-in stub) names the MSS adapter; `base` is its MSS base path. The composing
 * stack requires a cache tier in front (G8, enforced at config time). */
static void
xrootd_vfs_backend_config_tape(const char *root_canon, const char *adapter,
    const char *base)
{
    xrootd_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0'
        || base == NULL || base[0] == '\0')
    {
        return;
    }
    e = xrootd_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    ngx_memcpy(e->backend, "tape", sizeof("tape"));
    ngx_cpystrn((u_char *) e->origin_host, (u_char *) (adapter ? adapter : ""),
                sizeof(e->origin_host));      /* the MSS adapter name */
    ngx_cpystrn((u_char *) e->origin_path, (u_char *) base,
                sizeof(e->origin_path));       /* the MSS base path */
    e->inst = NULL;
}

void
xrootd_vfs_backend_set_credential(const char *root_canon,
    const xrootd_vfs_backend_cred_t *cred)
{
    xrootd_vfs_backend_cred_t  empty;
    xrootd_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0') {
        return;
    }
    if (cred == NULL) {
        ngx_memzero(&empty, sizeof(empty));     /* NULL ⇒ clear to anonymous */
        cred = &empty;
    }
    e = xrootd_vfs_backend_entry_find(root_canon);
    if (e != NULL) {
        ngx_cpystrn((u_char *) e->origin_token,
                    (u_char *) (cred->bearer ? cred->bearer : ""),
                    sizeof(e->origin_token));
        ngx_cpystrn((u_char *) e->origin_x509_proxy,
                    (u_char *) (cred->x509_proxy ? cred->x509_proxy : ""),
                    sizeof(e->origin_x509_proxy));
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

/* 1 iff `data`/`len` starts with an http:// or https:// scheme. */
static int
vfs_backend_is_http_url(const u_char *data, size_t len)
{
    return (len > sizeof("http://") - 1
            && ngx_strncmp(data, "http://", sizeof("http://") - 1) == 0)
        || (len > sizeof("https://") - 1
            && ngx_strncmp(data, "https://", sizeof("https://") - 1) == 0);
}

/* Parse ONE "http(s)://host[:port][/base]" segment into host/port/tls/base.
 * Returns NGX_OK, or NGX_ERROR after an [emerg] for a malformed segment. */
static ngx_int_t
vfs_parse_http_origin(ngx_conf_t *cf, u_char *seg, size_t segn,
    char *host, size_t host_cap, int *port_out, int *tls_out,
    char *base, size_t base_cap)
{
    u_char     *h = NULL;
    size_t      hn = 0;
    int         htls = 0;
    size_t      i, slash, hplen, pathlen, hostn;
    u_char     *colon = NULL;
    const char *path;
    int         port;

    if (segn > sizeof("https://") - 1
        && ngx_strncmp(seg, "https://", sizeof("https://") - 1) == 0)
    {
        h = seg + sizeof("https://") - 1;
        hn = segn - (sizeof("https://") - 1);
        htls = 1;
    } else if (segn > sizeof("http://") - 1
        && ngx_strncmp(seg, "http://", sizeof("http://") - 1) == 0)
    {
        h = seg + sizeof("http://") - 1;
        hn = segn - (sizeof("http://") - 1);
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_storage_backend: every |-separated origin must be an "
            "http:// or https:// URL");
        return NGX_ERROR;
    }

    slash = hn;
    for (i = 0; i < hn; i++) {
        if (h[i] == '/') { slash = i; break; }
    }
    hplen   = slash;
    path    = (slash < hn) ? (const char *) (h + slash) : "";
    pathlen = (slash < hn) ? hn - slash : 0;

    for (i = hplen; i > 0; i--) {
        if (h[i - 1] == ':') { colon = h + i - 1; break; }
    }
    if (colon != NULL) {
        ngx_int_t pn = ngx_atoi(colon + 1, (size_t) (h + hplen - (colon + 1)));

        hostn = (size_t) (colon - h);
        if (pn == NGX_ERROR || pn <= 0 || pn > 65535) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_storage_backend: invalid http origin port");
            return NGX_ERROR;
        }
        port = (int) pn;
    } else {
        hostn = hplen;
        port  = htls ? 443 : 80;
    }
    if (hostn == 0 || hostn >= host_cap || pathlen >= base_cap) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_storage_backend: invalid http origin host/path");
        return NGX_ERROR;
    }
    ngx_memcpy(host, h, hostn);
    host[hostn] = '\0';
    if (pathlen > 0) {
        ngx_memcpy(base, path, pathlen);
        base[pathlen] = '\0';
    } else {
        base[0] = '\0';
    }
    *port_out = port;
    *tls_out  = htls;
    return NGX_OK;
}

/* Append one failover endpoint to the export's http backend entry (phase-68
 * T11). Must run AFTER xrootd_vfs_backend_config_http registered endpoint 0
 * for the same root. */
static ngx_int_t
vfs_backend_add_http_endpoint(ngx_conf_t *cf, const char *root_canon,
    const char *host, int port, int tls, const char *base)
{
    xrootd_vfs_backend_entry_t *e = xrootd_vfs_backend_entry_find(root_canon);
    size_t                      n;

    if (e == NULL || ngx_strcmp(e->backend, "http") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_storage_backend: internal - endpoint list before primary");
        return NGX_ERROR;
    }
    n = sizeof(e->http_extra) / sizeof(e->http_extra[0]);
    if ((size_t) e->n_http_extra >= n) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_storage_backend: too many |-separated origins (max %uz)",
            n + 1);
        return NGX_ERROR;
    }
    if (ngx_strlen(host) >= sizeof(e->http_extra[0].host)
        || ngx_strlen(base) >= sizeof(e->http_extra[0].base))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_storage_backend: origin host/base too long for the "
            "endpoint table");
        return NGX_ERROR;
    }
    ngx_cpystrn((u_char *) e->http_extra[e->n_http_extra].host,
                (u_char *) host, sizeof(e->http_extra[0].host));
    e->http_extra[e->n_http_extra].port = port;
    e->http_extra[e->n_http_extra].tls  = tls;
    ngx_cpystrn((u_char *) e->http_extra[e->n_http_extra].base,
                (u_char *) base, sizeof(e->http_extra[0].base));
    e->n_http_extra++;
    e->inst = NULL;                            /* rebuilt on next resolve */
    return NGX_OK;
}


ngx_int_t
xrootd_vfs_backend_config_str(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb, size_t block_size, int family)
{
    u_char *addr = NULL;
    size_t  addrn = 0;
    int     is_roots = 0;

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

            xrootd_vfs_backend_config(root_canon, &posix_name, block_size);
        }
        return NGX_OK;
    }

    /* "cephfsro:<meta_pool>+<data_pool>[@<conf>][?assume_quiesced=1]" → read-only
     * CephFS-via-RADOS backend. Both pools are required. The fs MUST be quiesced;
     * the operator asserts that with the "?assume_quiesced=1" suffix (the driver
     * refuses to bind otherwise — fail-closed). Checked before "ceph:" since that
     * is a prefix-distinct but related scheme. */
    if (sb->len > sizeof("cephfsro:") - 1
        && ngx_strncmp(sb->data, "cephfsro:", sizeof("cephfsro:") - 1) == 0)
    {
        const u_char *rest = sb->data + (sizeof("cephfsro:") - 1);
        size_t        restn = sb->len - (sizeof("cephfsro:") - 1);
        char          meta[256] = "", data[256] = "", conf[1024] = "", q[64] = "";
        size_t        i, mn = 0, dn = 0, cn = 0, qn = 0;
        int           phase = 0;   /* 0=meta, 1=data (+), 2=conf (@), 3=query (?) */
        int           quiesced, live;

        for (i = 0; i < restn; i++) {
            u_char c = rest[i];
            if (c == '+' && phase == 0) { phase = 1; continue; }
            if (c == '@' && phase < 2)  { phase = 2; continue; }
            if (c == '?')               { phase = 3; continue; }
            if (phase == 0 && mn + 1 < sizeof(meta)) { meta[mn++] = (char) c; }
            else if (phase == 1 && dn + 1 < sizeof(data)) { data[dn++] = (char) c; }
            else if (phase == 2 && cn + 1 < sizeof(conf)) { conf[cn++] = (char) c; }
            else if (phase == 3 && qn + 1 < sizeof(q))    { q[qn++] = (char) c; }
        }
        meta[mn] = '\0'; data[dn] = '\0'; conf[cn] = '\0'; q[qn] = '\0';

        if (meta[0] == '\0' || data[0] == '\0') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "xrootd_storage_backend: "
                "cephfsro needs both pools (cephfsro:<meta>+<data>)");
            return NGX_ERROR;
        }
        quiesced = (ngx_strstr(q, "assume_quiesced=1") != NULL);
        live     = (ngx_strstr(q, "live=1") != NULL);
        if (!quiesced && !live) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "xrootd_storage_backend: "
                "cephfsro requires a consistency assertion: "
                "?assume_quiesced=1 (fs frozen — MDS down/failed, journal flushed) "
                "or ?live=1 (still mounted — best-effort eventually-consistent "
                "reads with optimistic revalidation + retry)");
            return NGX_ERROR;
        }
        xrootd_vfs_backend_config_cephfs_ro(root_canon, meta, data, conf,
                                            quiesced, live);
        return NGX_OK;
    }

    /* "ceph:<pool>[@<conf>][?<key_prefix>]" → flat, block-only RADOS object
     * backend (the pure-librados reference). The pool is required; conf defaults
     * to /etc/ceph/ceph.conf; everything after '@' (to an optional '?') is the
     * ceph.conf path; after '?' is the object-key prefix. */
    {
        const char *backend = NULL;
        size_t      skip = 0;

        if (sb->len > sizeof("ceph:") - 1
            && ngx_strncmp(sb->data, "ceph:", sizeof("ceph:") - 1) == 0)
        {
            backend = "ceph"; skip = sizeof("ceph:") - 1;
        }

        if (backend != NULL) {
            const u_char *rest = sb->data + skip;
            size_t        restn = sb->len - skip;
            char          pool[256] = "", conf[1024] = "", prefix[256] = "";
            size_t        i, pn = 0, cn = 0, xn = 0;
            int           phase = 0;   /* 0=pool, 1=conf (@), 2=prefix (?) */

            for (i = 0; i < restn; i++) {
                u_char c = rest[i];
                if (c == '@' && phase == 0) { phase = 1; continue; }
                if (c == '?') { phase = 2; continue; }
                if (phase == 0 && pn + 1 < sizeof(pool))   { pool[pn++] = (char) c; }
                else if (phase == 1 && cn + 1 < sizeof(conf))   { conf[cn++] = (char) c; }
                else if (phase == 2 && xn + 1 < sizeof(prefix)) { prefix[xn++] = (char) c; }
            }
            pool[pn] = '\0'; conf[cn] = '\0'; prefix[xn] = '\0';
            if (pool[0] == '\0') {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_storage_backend: %s: needs a pool (%s:<pool>)",
                    backend, backend);
                return NGX_ERROR;
            }
            xrootd_vfs_backend_config_ceph(root_canon, backend, pool, conf, prefix);
            return NGX_OK;
        }
    }

    /* "rados://<pool>[/<namespace>]" → the flat librados object backend (the URL
     * alias of "ceph:<pool>"); the tail after the pool is the object-key prefix.
     * Cluster addressing comes from /etc/ceph/ceph.conf, so there is no host:port
     * authority — the authority slot is the pool. */
    if (sb->len >= sizeof("rados://") - 1
        && ngx_strncmp(sb->data, "rados://", sizeof("rados://") - 1) == 0)
    {
        const u_char *rest  = sb->data + sizeof("rados://") - 1;
        size_t        restn = sb->len - (sizeof("rados://") - 1);
        char          pool[256]   = "";
        char          prefix[256] = "";
        size_t        i, slash = restn;

        for (i = 0; i < restn; i++) {
            if (rest[i] == '/') { slash = i; break; }
        }
        if (slash > 0 && slash < sizeof(pool)) {
            ngx_memcpy(pool, rest, slash);
            pool[slash] = '\0';
        }
        if (slash < restn && (restn - slash - 1) < sizeof(prefix)) {
            ngx_memcpy(prefix, rest + slash + 1, restn - slash - 1);  /* drop '/' */
            prefix[restn - slash - 1] = '\0';
        }
        if (pool[0] == '\0') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_storage_backend: rados:// needs \"//<pool>[/<namespace>]\"");
            return NGX_ERROR;
        }
        xrootd_vfs_backend_config_ceph(root_canon, "ceph", pool, NULL, prefix);
        return NGX_OK;
    }

    /* "tape://<adapter>/<base>" (or its alias "frm://...") → a nearline (tape/MSS)
     * backend served by sd_frm (phase-64 SP5). The authority host names the MSS
     * adapter ("" / "stub" = the built-in stub); the path is the adapter's MSS
     * base. */
    {
        const u_char *rest  = NULL;
        size_t        restn = 0;

        if (sb->len > sizeof("tape://") - 1
            && ngx_strncmp(sb->data, "tape://", sizeof("tape://") - 1) == 0)
        {
            rest  = sb->data + sizeof("tape://") - 1;
            restn = sb->len - (sizeof("tape://") - 1);
        } else if (sb->len > sizeof("frm://") - 1
            && ngx_strncmp(sb->data, "frm://", sizeof("frm://") - 1) == 0)
        {
            rest  = sb->data + sizeof("frm://") - 1;
            restn = sb->len - (sizeof("frm://") - 1);
        }

        if (rest != NULL) {
            char   adapter[64] = "";
            char   base[1024]  = "";
            size_t i, slash = restn;

            for (i = 0; i < restn; i++) {
                if (rest[i] == '/') { slash = i; break; }
            }
            if (slash > 0 && slash < sizeof(adapter)) {
                ngx_memcpy(adapter, rest, slash);
                adapter[slash] = '\0';
            }
            if (slash < restn && (restn - slash) < sizeof(base)) {
                ngx_memcpy(base, rest + slash, restn - slash);  /* keeps leading '/' */
                base[restn - slash] = '\0';
            }
            if (base[0] != '/') {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_storage_backend: tape://|frm:// needs "
                    "\"//<adapter>/<base-path>\"");
                return NGX_ERROR;
            }
            xrootd_vfs_backend_config_tape(root_canon, adapter, base);
            return NGX_OK;
        }
    }

    /* "http://host[:port]/base" / "https://..." → a read-only HTTP SOURCE
     * backend. phase-68 T11: a PIPE-SEPARATED ordered list of such URLs
     * registers a multi-endpoint origin set with health-scored read failover
     * (mirrors the CVMFS_SERVER_URL syntax); the first URL is the primary
     * and the write target. */
    if (vfs_backend_is_http_url(sb->data, sb->len)) {
        u_char *seg = sb->data;
        u_char *end = sb->data + sb->len;
        int     first = 1;

        while (seg < end) {
            u_char *pipe = ngx_strlchr(seg, end, '|');
            size_t  segn = (pipe != NULL) ? (size_t) (pipe - seg)
                                          : (size_t) (end - seg);
            char    host[256], base[1024];
            int     port, htls;

            if (vfs_parse_http_origin(cf, seg, segn, host, sizeof(host),
                                      &port, &htls, base, sizeof(base))
                != NGX_OK)
            {
                return NGX_ERROR;              /* [emerg] already logged */
            }
            if (first) {
                xrootd_vfs_backend_config_http(root_canon, host, port, htls,
                                               base);
                first = 0;
            } else if (vfs_backend_add_http_endpoint(cf, root_canon, host,
                                                     port, htls, base)
                       != NGX_OK)
            {
                return NGX_ERROR;
            }
            seg = (pipe != NULL) ? pipe + 1 : end;
        }
        return NGX_OK;
    }

    /* "s3://host[:port]/bucket" → a read-only S3 source backend (path-style): the
     * first path segment is the bucket. Default port 7480 (radosgw), tls off — the
     * same defaults the generic tier parser uses for an s3 store. */
    if (sb->len >= sizeof("s3://") - 1
        && ngx_strncmp(sb->data, "s3://", sizeof("s3://") - 1) == 0)
    {
        u_char     *h  = sb->data + sizeof("s3://") - 1;
        size_t      hn = sb->len - (sizeof("s3://") - 1);
        size_t      i, slash = hn, hplen, pathlen;
        u_char     *colon = NULL;
        const char *path;
        char        host[256], bucket[256];
        size_t      hostn;
        int         port;

        for (i = 0; i < hn; i++) {
            if (h[i] == '/') { slash = i; break; }
        }
        hplen   = slash;
        path    = (slash < hn) ? (const char *) (h + slash) : "";
        pathlen = (slash < hn) ? hn - slash : 0;

        for (i = hplen; i > 0; i--) {
            if (h[i - 1] == ':') { colon = h + i - 1; break; }
        }
        if (colon != NULL) {
            ngx_int_t pn = ngx_atoi(colon + 1, (size_t) (h + hplen - (colon + 1)));
            hostn = (size_t) (colon - h);
            if (pn == NGX_ERROR || pn <= 0 || pn > 65535) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_storage_backend: invalid s3 origin port");
                return NGX_ERROR;
            }
            port = (int) pn;
        } else {
            hostn = hplen;
            port  = 7480;                  /* radosgw S3 default */
        }
        while (pathlen > 0 && path[0] == '/') { path++; pathlen--; }   /* → bucket */
        if (hostn == 0 || hostn >= sizeof(host) || pathlen == 0
            || pathlen >= sizeof(bucket))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_storage_backend: s3:// needs \"//host[:port]/bucket\"");
            return NGX_ERROR;
        }
        ngx_memcpy(host, h, hostn);
        host[hostn] = '\0';
        ngx_memcpy(bucket, path, pathlen);
        bucket[pathlen] = '\0';
        xrootd_vfs_backend_config_s3(root_canon, host, port, 0, bucket);
        return NGX_OK;
    }

    /* "root://host:port" / "roots://host:port" → a remote root:// primary backend;
     * any other value is a local driver name (pblock/posix) handled as before. */
    if (sb->len > sizeof("roots://") - 1
        && ngx_strncmp(sb->data, "roots://", sizeof("roots://") - 1) == 0)
    {
        addr = sb->data + sizeof("roots://") - 1;
        addrn = sb->len - (sizeof("roots://") - 1);
        is_roots = 1;
    } else if (sb->len > sizeof("root://") - 1
        && ngx_strncmp(sb->data, "root://", sizeof("root://") - 1) == 0)
    {
        addr = sb->data + sizeof("root://") - 1;
        addrn = sb->len - (sizeof("root://") - 1);
    }

    if (addr == NULL) {
        xrootd_vfs_backend_config(root_canon, sb, block_size);
        return NGX_OK;
    }

    {
        u_char   *colon = NULL;
        size_t    i, hostn;
        ngx_int_t portnum;
        char      host[256];

        /* Split host:port on the LAST colon (a bracketed [v6]:port keeps it). */
        for (i = addrn; i > 0; i--) {
            if (addr[i - 1] == ':') { colon = addr + i - 1; break; }
        }
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_storage_backend: remote origin needs host:port");
            return NGX_ERROR;
        }
        hostn   = (size_t) (colon - addr);
        portnum = ngx_atoi(colon + 1, (size_t) (addr + addrn - (colon + 1)));
        if (hostn == 0 || hostn >= sizeof(host) || portnum == NGX_ERROR
            || portnum <= 0 || portnum > 65535)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_storage_backend: invalid remote origin host:port");
            return NGX_ERROR;
        }
        ngx_memcpy(host, addr, hostn);
        host[hostn] = '\0';
        xrootd_vfs_backend_config_xroot(root_canon, host, (int) portnum,
                                        is_roots, family);
    }
    return NGX_OK;
}

void
xrootd_vfs_backend_set_staging(const char *root_canon, int on)
{
    xrootd_vfs_backend_entry_t *e = xrootd_vfs_backend_entry_find(root_canon);

    if (e != NULL) {
        e->staging = on ? 1 : 0;
    }
}

void
xrootd_vfs_backend_config_cache_store(const char *root_canon,
    const xrootd_tier_cfg_t *cfg, const xrootd_cache_policy_t *policy)
{
    xrootd_vfs_backend_entry_t *e;

    if (cfg == NULL || !cfg->configured) {
        return;
    }
    e = xrootd_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    e->cache_tier = *cfg;
    if (policy != NULL) {
        e->cache_policy = *policy;
    }
    e->inst = NULL;                            /* recompose on next resolve */
}

/* Endpoint (host,port) at `idx` of the http backend registered at
 * `root_canon` — index 0 is the primary, 1.. the T11 failover list. Returns
 * 0, or -1 past the end / not an http backend. Pointers alias the registry's
 * stable storage. */
int
xrootd_vfs_backend_http_endpoint_at(const char *root_canon, int idx,
    const char **host, int *port)
{
    xrootd_vfs_backend_entry_t *e = xrootd_vfs_backend_entry_find(root_canon);

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
xrootd_vfs_backend_set_http_ranks(const char *root_canon, const int *ranks,
    int n)
{
    xrootd_vfs_backend_entry_t *e = xrootd_vfs_backend_entry_find(root_canon);
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
xrootd_vfs_backend_register_http_upstream(const char *up_root,
    const char *template_root, const char *host, int port, int tls,
    const char *store_suffix)
{
    xrootd_vfs_backend_entry_t *e, *tpl;

    e = xrootd_vfs_backend_entry_find(up_root);
    if (e != NULL) {
        return NGX_OK;                          /* already registered */
    }
    tpl = xrootd_vfs_backend_entry_find(template_root);
    e = xrootd_vfs_backend_entry_get_or_create(up_root);
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
                (void) xrootd_mkdir_recursive(e->cache_tier.path, 0755);
            }
        }
    }
    e->inst = NULL;
    return NGX_OK;
}

void
xrootd_vfs_backend_config_stage_store(const char *root_canon,
    const xrootd_tier_cfg_t *cfg, const xrootd_stage_policy_t *policy)
{
    xrootd_vfs_backend_entry_t *e;

    if (cfg == NULL || !cfg->configured) {
        return;
    }
    e = xrootd_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    e->stage_tier = *cfg;
    if (policy != NULL) {
        e->stage_policy = *policy;
    }
    e->inst = NULL;
}
