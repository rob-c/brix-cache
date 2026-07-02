/*
 * vfs_backend_registry.c — per-export storage-backend resolution (see the header).
 */
#include "vfs_backend_registry.h"
#include "fs/backend/xroot/sd_xroot.h"   /* remote root:// backend (xrootd_sd_xroot_create) */
#include "fs/backend/http/sd_http.h"     /* HTTP source backend (xrootd_sd_http_create) */
#include "fs/backend/remote/sd_remote.h" /* read-only S3 source backend (xrootd_sd_remote_create) */
#include "fs/backend/rados/sd_ceph.h"    /* Ceph/RADOS backend (XROOTD_HAVE_CEPH) */
#include "fs/backend/stage/sd_stage.h"   /* C-2/C-6 write-back stage decorator */
#include "fs/backend/cache/sd_cache.h"   /* phase-64 read-cache decorator */
#include "fs/backend/frm/sd_frm.h"       /* phase-64 SP5 nearline (tape) backend */
#include "fs/tier/tier.h"                /* phase-64 tier cfg/build + the cache/stage setters */
#include "fs/cache/origin/s3_transport.h" /* xrootd_s3_origin_curl_transport (libcurl) */

#include <string.h>

/* One registered export. `inst` is per-worker (copy-on-write after fork): the
 * master leaves it NULL at config time; each worker fills its own on first use. */
typedef struct {
    char                  root_canon[PATH_MAX];
    char                  backend[16];   /* "pblock" | "xroot" */
    int64_t               block_size;
    char                  origin_host[256];   /* xroot/http: remote origin host */
    int                   origin_port;
    int                   origin_tls;
    int                   origin_family;       /* xrootd_af_policy_t for origin connect */
    char                  origin_path[1024];  /* http: URL base path ("" / "/sub") */
    char                  origin_token[4096]; /* §14: bearer token for the source
                                               * upstream ("" = anonymous) */
    char                  origin_x509_proxy[1024]; /* §14/C-3 GSI: proxy PEM path */
    char                  origin_ca_dir[1024];      /* §14/C-3 GSI: origin-cert CA */
    char                  origin_s3_access_key[256]; /* §14 S3 SigV4: access-key id */
    char                  origin_s3_secret_key[256]; /* §14 S3 SigV4: secret key    */
    char                  origin_s3_region[64];      /* §14 S3 SigV4: region scope  */
    char                  origin_sss_keytab[1024];   /* §14 SSS: shared-secret keytab*/
    int                   staging;       /* xroot: stage local + promote on commit */
    /* ceph backend: the export's namespace + data live in a RADOS pool (no local
     * dir); root_canon is just the logical mount point. */
    char                  ceph_pool[256];
    char                  ceph_conf[1024];
    char                  ceph_key_prefix[256];
    /* cephfsro (read-only CephFS-via-RADOS): ceph_pool holds the METADATA pool,
     * ceph_data_pool the DATA pool; cephfs_quiesced is the operator's safety
     * assertion (carried in the backend URI as "?assume_quiesced=1"). */
    char                  ceph_data_pool[256];
    int                   cephfs_quiesced;
    int                   cephfs_live;
    /* phase-64 composable tiers (additive over the flat backend above): when a
     * cache/stage tier is configured, entry_build wraps the source in the
     * sd_stage / sd_cache decorators. */
    xrootd_tier_cfg_t      cache_tier;
    xrootd_cache_policy_t  cache_policy;
    xrootd_tier_cfg_t      stage_tier;
    xrootd_stage_policy_t  stage_policy;
    xrootd_sd_instance_t *inst;          /* lazily built per worker, or NULL */
} xrootd_vfs_backend_entry_t;

/* Exports are few (one per location/server block); a small fixed table avoids any
 * allocation and is scanned linearly. */
#define XROOTD_VFS_BACKEND_MAX 64
static xrootd_vfs_backend_entry_t  xrootd_vfs_backends[XROOTD_VFS_BACKEND_MAX];
static ngx_uint_t                  xrootd_vfs_backend_count;

void
xrootd_vfs_backend_config(const char *root_canon, const ngx_str_t *name,
    size_t block_size)
{
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0' || name == NULL
        || name->len == 0)
    {
        return;
    }
    /* Only "pblock" is a registered non-POSIX backend today. */
    if (name->len != sizeof("pblock") - 1
        || ngx_strncmp(name->data, "pblock", sizeof("pblock") - 1) != 0)
    {
        return;
    }

    /* Dedup on root_canon so a config reload updates rather than appends. */
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            xrootd_vfs_backends[i].block_size = (int64_t) block_size;
            xrootd_vfs_backends[i].inst = NULL;   /* rebuilt on next resolve */
            return;
        }
    }
    if (xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX) {
        return;
    }

    {
        xrootd_vfs_backend_entry_t *e =
            &xrootd_vfs_backends[xrootd_vfs_backend_count++];

        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                    sizeof(e->root_canon));
        ngx_memcpy(e->backend, "pblock", sizeof("pblock"));
        e->block_size = (int64_t) block_size;
    }
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
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || port <= 0 || port > 65535)
    {
        return;
    }

    /* Dedup on root_canon so a config reload updates rather than appends. */
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            xrootd_vfs_backend_set_xroot(&xrootd_vfs_backends[i], host, port,
                                         tls, family);
            return;
        }
    }
    if (xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX) {
        return;
    }
    {
        xrootd_vfs_backend_entry_t *e =
            &xrootd_vfs_backends[xrootd_vfs_backend_count++];

        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                    sizeof(e->root_canon));
        xrootd_vfs_backend_set_xroot(e, host, port, tls, family);
    }
}

void
xrootd_vfs_backend_config_http(const char *root_canon, const char *host,
    int port, int tls, const char *base_path)
{
    ngx_uint_t                  i;
    xrootd_vfs_backend_entry_t *e = NULL;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || port <= 0 || port > 65535)
    {
        return;
    }
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            e = &xrootd_vfs_backends[i];
            break;
        }
    }
    if (e == NULL) {
        if (xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX) {
            return;
        }
        e = &xrootd_vfs_backends[xrootd_vfs_backend_count++];
        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                    sizeof(e->root_canon));
    }
    ngx_memcpy(e->backend, "http", sizeof("http"));
    ngx_cpystrn((u_char *) e->origin_host, (u_char *) host,
                sizeof(e->origin_host));
    e->origin_port = port;
    e->origin_tls  = tls;
    ngx_cpystrn((u_char *) e->origin_path, (u_char *) (base_path ? base_path : ""),
                sizeof(e->origin_path));
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
    ngx_uint_t                  i;
    xrootd_vfs_backend_entry_t *e = NULL;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || bucket == NULL || bucket[0] == '\0'
        || port <= 0 || port > 65535)
    {
        return;
    }
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            e = &xrootd_vfs_backends[i];
            break;
        }
    }
    if (e == NULL) {
        if (xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX) {
            return;
        }
        e = &xrootd_vfs_backends[xrootd_vfs_backend_count++];
        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                    sizeof(e->root_canon));
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
    ngx_uint_t                  i;
    xrootd_vfs_backend_entry_t *e = NULL;

    if (root_canon == NULL || root_canon[0] == '\0'
        || pool == NULL || pool[0] == '\0')
    {
        return;
    }
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            e = &xrootd_vfs_backends[i];
            break;
        }
    }
    if (e == NULL) {
        if (xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX) {
            return;
        }
        e = &xrootd_vfs_backends[xrootd_vfs_backend_count++];
        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                    sizeof(e->root_canon));
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
    ngx_uint_t                  i;
    xrootd_vfs_backend_entry_t *e = NULL;

    if (root_canon == NULL || root_canon[0] == '\0'
        || meta_pool == NULL || meta_pool[0] == '\0'
        || data_pool == NULL || data_pool[0] == '\0')
    {
        return;
    }
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            e = &xrootd_vfs_backends[i];
            break;
        }
    }
    if (e == NULL) {
        if (xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX) {
            return;
        }
        e = &xrootd_vfs_backends[xrootd_vfs_backend_count++];
        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                    sizeof(e->root_canon));
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
    ngx_uint_t                  i;
    xrootd_vfs_backend_entry_t *e = NULL;

    if (root_canon == NULL || root_canon[0] == '\0'
        || base == NULL || base[0] == '\0')
    {
        return;
    }
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            e = &xrootd_vfs_backends[i];
            break;
        }
    }
    if (e == NULL) {
        if (xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX) {
            return;
        }
        e = &xrootd_vfs_backends[xrootd_vfs_backend_count++];
        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                    sizeof(e->root_canon));
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
    ngx_uint_t                 i;

    if (root_canon == NULL || root_canon[0] == '\0') {
        return;
    }
    if (cred == NULL) {
        ngx_memzero(&empty, sizeof(empty));     /* NULL ⇒ clear to anonymous */
        cred = &empty;
    }
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        e = &xrootd_vfs_backends[i];
        if (ngx_strcmp(e->root_canon, root_canon) != 0) {
            continue;
        }
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
        return;
    }
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

    /* "http://host[:port]/base" / "https://..." → a read-only HTTP SOURCE backend
     * (split host[:port] from the URL /path; default port 80/443). */
    {
        u_char *h = NULL;
        size_t  hn = 0;
        int     htls = 0;

        if (sb->len > sizeof("https://") - 1
            && ngx_strncmp(sb->data, "https://", sizeof("https://") - 1) == 0)
        {
            h = sb->data + sizeof("https://") - 1;
            hn = sb->len - (sizeof("https://") - 1);
            htls = 1;
        } else if (sb->len > sizeof("http://") - 1
            && ngx_strncmp(sb->data, "http://", sizeof("http://") - 1) == 0)
        {
            h = sb->data + sizeof("http://") - 1;
            hn = sb->len - (sizeof("http://") - 1);
        }

        if (h != NULL) {
            size_t     i, slash = hn, hplen, pathlen;
            u_char    *colon = NULL;
            const char *path;
            char       host[256], base[1024];
            size_t     hostn;
            int        port;

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
                ngx_int_t pn = ngx_atoi(colon + 1,
                                        (size_t) (h + hplen - (colon + 1)));
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
            if (hostn == 0 || hostn >= sizeof(host) || pathlen >= sizeof(base)) {
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
            xrootd_vfs_backend_config_http(root_canon, host, port, htls, base);
            return NGX_OK;
        }
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
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0') {
        return;
    }
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            xrootd_vfs_backends[i].staging = on ? 1 : 0;
            return;
        }
    }
}

/* Find a registered entry by exact root_canon, or NULL. */
static xrootd_vfs_backend_entry_t *
xrootd_vfs_backend_find(const char *root_canon)
{
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0') {
        return NULL;
    }
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            return &xrootd_vfs_backends[i];
        }
    }
    return NULL;
}

/* Find or create the entry for root_canon. A cache/stage tier may be registered
 * for a default-POSIX export that has no backend entry yet, so create one (backend
 * "" = default POSIX source). NULL when the table is full. */
static xrootd_vfs_backend_entry_t *
xrootd_vfs_backend_get_or_create(const char *root_canon)
{
    xrootd_vfs_backend_entry_t *e = xrootd_vfs_backend_find(root_canon);

    if (e != NULL) {
        return e;
    }
    if (root_canon == NULL || root_canon[0] == '\0'
        || xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX)
    {
        return NULL;
    }
    e = &xrootd_vfs_backends[xrootd_vfs_backend_count++];
    ngx_memzero(e, sizeof(*e));
    ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                sizeof(e->root_canon));
    return e;
}

void
xrootd_vfs_backend_config_cache_store(const char *root_canon,
    const xrootd_tier_cfg_t *cfg, const xrootd_cache_policy_t *policy)
{
    xrootd_vfs_backend_entry_t *e;

    if (cfg == NULL || !cfg->configured) {
        return;
    }
    e = xrootd_vfs_backend_get_or_create(root_canon);
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
xrootd_vfs_backend_config_stage_store(const char *root_canon,
    const xrootd_tier_cfg_t *cfg, const xrootd_stage_policy_t *policy)
{
    xrootd_vfs_backend_entry_t *e;

    if (cfg == NULL || !cfg->configured) {
        return;
    }
    e = xrootd_vfs_backend_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    e->stage_tier = *cfg;
    if (policy != NULL) {
        e->stage_policy = *policy;
    }
    e->inst = NULL;
}

/* Build the entry's RAW source driver instance (no decorators, no memoization). The
 * instance is malloc/pool-owned, worker-safe; SQLite connections are per-worker so
 * this is only ever called after fork. Returns NULL (logged) on init failure. */
static xrootd_sd_instance_t *
xrootd_vfs_backend_build_source(xrootd_vfs_backend_entry_t *e, ngx_log_t *log)
{
    xrootd_sd_instance_t *inst;

    /* Default / explicit POSIX source. Phase-64: an export whose backend is the
     * default POSIX tree but which carries a cache/stage tier still needs a
     * buildable source instance to decorate. */
    if (e->backend[0] == '\0' || ngx_strcmp(e->backend, "posix") == 0) {
        int err = 0;

        inst = xrootd_sd_instance_create(ngx_cycle->pool, log, "posix",
                                         (void *) e->root_canon, &err);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, err,
                "xrootd: posix source init failed for export \"%s\"",
                e->root_canon);
        }
        return inst;
    }

    /* Remote root:// backend: the in-process origin wire client (read + write +
     * staged_open, auth via ztn/gsi). */
    if (ngx_strcmp(e->backend, "xroot") == 0) {
        inst = xrootd_sd_xroot_create_origin(e->origin_host, e->origin_port,
                 e->origin_tls, e->origin_family,
                 (e->origin_token[0] != '\0') ? e->origin_token : NULL,
                 (e->origin_x509_proxy[0] != '\0') ? e->origin_x509_proxy : NULL,
                 (e->origin_ca_dir[0] != '\0') ? e->origin_ca_dir : NULL,
                 (e->origin_sss_keytab[0] != '\0') ? e->origin_sss_keytab : NULL,
                 log);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: remote root:// backend init failed for export \"%s\"",
                e->root_canon);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: remote root:// storage backend ready at \"%s\"",
                e->root_canon);
        }
        return inst;
    }

#if XROOTD_HAVE_CEPH
    /* Ceph/RADOS object backend: flat, block-only key space, data in a pool with
     * no local directory namespace (the pure-librados reference). */
    if (ngx_strcmp(e->backend, "ceph") == 0) {
        xrootd_sd_ceph_conf_t conf;
        int                   sderr = 0;

        ngx_memzero(&conf, sizeof(conf));
        conf.pool       = e->ceph_pool;
        conf.conf_file  = (e->ceph_conf[0] != '\0') ? e->ceph_conf : NULL;
        conf.key_prefix = (e->ceph_key_prefix[0] != '\0') ? e->ceph_key_prefix
                                                          : NULL;

        inst = xrootd_sd_instance_create(ngx_cycle->pool, log, e->backend,
                                         &conf, &sderr);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, sderr,
                "xrootd: %s backend init failed for export \"%s\" (pool=%s)",
                e->backend, e->root_canon, e->ceph_pool);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: %s storage backend ready at \"%s\" (pool=%s)",
                e->backend, e->root_canon, e->ceph_pool);
        }
        return inst;
    }

    /* cephfsro: read-only CephFS served directly from RADOS (meta + data pools). */
    if (ngx_strcmp(e->backend, "cephfsro") == 0) {
        xrootd_sd_cephfs_ro_conf_t conf;
        int                        sderr = 0;

        ngx_memzero(&conf, sizeof(conf));
        conf.meta_pool       = e->ceph_pool;
        conf.data_pool       = e->ceph_data_pool;
        conf.conf_file       = (e->ceph_conf[0] != '\0') ? e->ceph_conf : NULL;
        conf.assume_quiesced = e->cephfs_quiesced;
        conf.live            = e->cephfs_live;

        inst = xrootd_sd_instance_create(ngx_cycle->pool, log, "cephfsro",
                                         &conf, &sderr);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, sderr,
                "xrootd: cephfsro backend init failed for export \"%s\" "
                "(meta=%s data=%s)", e->root_canon, e->ceph_pool,
                e->ceph_data_pool);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: cephfsro (read-only CephFS) backend ready at \"%s\" "
                "(meta=%s data=%s)", e->root_canon, e->ceph_pool,
                e->ceph_data_pool);
        }
        return inst;
    }
#endif

    /* Nearline (tape/MSS) backend (phase-64 SP5): sd_frm over the selected MSS
     * adapter. A cache tier in front (G8) is the recall target. */
    if (ngx_strcmp(e->backend, "tape") == 0) {
        inst = xrootd_sd_frm_create(
            (e->origin_host[0] != '\0') ? e->origin_host : NULL,
            e->origin_path, log);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: tape (frm) backend init failed for export \"%s\"",
                e->root_canon);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: nearline (tape) storage backend ready at \"%s\" "
                "(adapter=%s base=%s)", e->root_canon,
                (e->origin_host[0] != '\0') ? e->origin_host : "stub",
                e->origin_path);
        }
        return inst;
    }

    /* HTTP(S) source backend (read-only): the shared S3/libcurl transport does the
     * HEAD/Range-GET; sd_http carries no libcurl itself. */
    if (ngx_strcmp(e->backend, "http") == 0) {
        xrootd_sd_http_cfg_t cfg;

        ngx_memzero(&cfg, sizeof(cfg));
        cfg.host       = e->origin_host;
        cfg.port       = e->origin_port;
        cfg.tls        = e->origin_tls;
        cfg.base_path  = e->origin_path;
        cfg.transport  = &xrootd_s3_origin_curl_transport;
        cfg.timeout_ms = 60000;
        cfg.bearer_token = (e->origin_token[0] != '\0') ? e->origin_token : NULL;

        inst = xrootd_sd_http_create(&cfg, log);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: http backend init failed for export \"%s\"",
                e->root_canon);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: http storage backend ready at \"%s\"", e->root_canon);
        }
        return inst;
    }

    /* Read-only S3 source backend (phase-64): the export's bytes live in a remote
     * bucket, served over the shared libcurl S3 transport (signed Range GET). The
     * remote driver is CAP_RANGE_READ only, so this primary is read-only — exactly
     * like an http:// primary. origin_path carries the bucket. */
    if (ngx_strcmp(e->backend, "s3") == 0) {
        xrootd_sd_remote_cfg_t cfg;

        ngx_memzero(&cfg, sizeof(cfg));
        cfg.scheme = XROOTD_SD_REMOTE_S3;
        ngx_cpystrn((u_char *) cfg.host, (u_char *) e->origin_host,
                    sizeof(cfg.host));
        cfg.port = e->origin_port;
        cfg.tls  = e->origin_tls;
        ngx_cpystrn((u_char *) cfg.bucket, (u_char *) e->origin_path,
                    sizeof(cfg.bucket));
        cfg.timeout_ms = 60000;
        cfg.transport  = &xrootd_s3_origin_curl_transport;
        /* §14: SigV4 credentials from the attached xrootd_credential (s3_* fields);
         * empty ⇒ anonymous (public bucket). Region defaults to us-east-1. */
        ngx_cpystrn((u_char *) cfg.access_key,
                    (u_char *) e->origin_s3_access_key, sizeof(cfg.access_key));
        ngx_cpystrn((u_char *) cfg.secret_key,
                    (u_char *) e->origin_s3_secret_key, sizeof(cfg.secret_key));
        ngx_cpystrn((u_char *) cfg.region,
                    (u_char *) (e->origin_s3_region[0] != '\0'
                                ? e->origin_s3_region : "us-east-1"),
                    sizeof(cfg.region));

        inst = xrootd_sd_remote_create(&cfg, log);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: s3 backend init failed for export \"%s\" (bucket=%s)",
                e->root_canon, e->origin_path);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: s3 storage backend ready at \"%s\" (host=%s bucket=%s)",
                e->root_canon, e->origin_host, e->origin_path);
        }
        return inst;
    }
#if XROOTD_HAVE_SQLITE
    {
        xrootd_sd_pblock_conf_t conf;
        int                     sderr = 0;

        ngx_memzero(&conf, sizeof(conf));
        conf.root            = e->root_canon;
        conf.busy_timeout_ms = 5000;
        conf.block_size      = e->block_size;

        inst = xrootd_sd_instance_create(ngx_cycle->pool, log, "pblock",
                                         &conf, &sderr);
        if (inst == NULL) {
            ngx_log_error(NGX_LOG_ERR, log, sderr,
                "xrootd: pblock backend init failed for export \"%s\"",
                e->root_canon);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: pblock storage backend ready at \"%s\" "
                "(block_size=%uz)", e->root_canon, (size_t) e->block_size);
        }
        return inst;
    }
#else
    (void) log;
    return NULL;
#endif
}

/* Lazily build + memoize the entry's COMPOSED storage stack (per worker). The
 * registry is the single composition point: build the source, then wrap it
 * bottom-up in the stage decorator and the read-cache decorator (cache outermost,
 * phase-64 section 5). A degraded decorator (a store that is "needs development"
 * or fails to init) is skipped so the export still serves from the tier below. */
static xrootd_sd_instance_t *
xrootd_vfs_backend_entry_build(xrootd_vfs_backend_entry_t *e, ngx_log_t *log)
{
    xrootd_sd_instance_t *top;

    if (e->inst != NULL) {
        return e->inst;                /* already built in this worker */
    }
    top = xrootd_vfs_backend_build_source(e, log);
    if (top == NULL) {
        return NULL;
    }

    /* Legacy local-staging shim (xrootd_storage_staging): buffer on a posix store
     * rooted at the export root and flush to the source on commit. Superseded by an
     * explicit stage tier, so skip it when one is configured. */
    if (e->staging && !e->stage_tier.configured
        && top->driver->staged_open != NULL)
    {
        int                   sderr = 0;
        xrootd_sd_instance_t *store =
            xrootd_sd_instance_create(ngx_cycle->pool, log, "posix",
                                      (void *) e->root_canon, &sderr);
        xrootd_sd_instance_t *dec = (store != NULL)
            ? xrootd_sd_stage_create(top, store, NULL, e->root_canon, log) : NULL;

        if (dec != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: write-back stage decorator composed over \"%s\"",
                e->root_canon);
            top = dec;
        } else {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                "xrootd: stage shim init failed for \"%s\" - source direct",
                e->root_canon);
        }
    }

    /* Phase-64 explicit stage tier (sd_stage over an explicit stage store). */
    if (e->stage_tier.configured) {
        xrootd_sd_instance_t *store = xrootd_tier_build(&e->stage_tier, log);
        xrootd_sd_instance_t *dec = (store != NULL)
            ? xrootd_sd_stage_create(top, store, &e->stage_policy, e->root_canon,
                                     log) : NULL;

        if (dec != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: write-stage tier (%s) composed over \"%s\"",
                e->stage_tier.driver, e->root_canon);
            top = dec;
        }
    }

    /* Phase-64 read-cache tier (sd_cache, outermost). */
    if (e->cache_tier.configured) {
        xrootd_sd_instance_t *store = xrootd_tier_build(&e->cache_tier, log);
        const char           *local_root =
            (ngx_strcmp(e->cache_tier.driver, "posix") == 0
             && e->cache_tier.path[0] != '\0') ? e->cache_tier.path : NULL;
        xrootd_sd_instance_t *dec = (store != NULL)
            ? xrootd_sd_cache_create(top, store, &e->cache_policy, local_root, log)
            : NULL;

        if (dec != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "xrootd: read-cache tier (%s) composed over \"%s\"",
                e->cache_tier.driver, e->root_canon);
            top = dec;
        }
    }

    e->inst = top;
    return e->inst;
}

ngx_uint_t
xrootd_vfs_backend_export_count(void)
{
    return xrootd_vfs_backend_count;
}

ngx_int_t
xrootd_vfs_backend_export_info(ngx_uint_t i, xrootd_vfs_backend_info_t *out)
{
    xrootd_vfs_backend_entry_t *e;

    if (out == NULL || i >= xrootd_vfs_backend_count) {
        return NGX_ERROR;
    }
    e = &xrootd_vfs_backends[i];
    out->root_canon = e->root_canon;
    out->backend    = (e->backend[0] != '\0') ? e->backend : "posix";
    out->host       = e->origin_host;
    out->port       = e->origin_port;
    out->tls        = e->origin_tls;
    out->staging    = e->staging;
    out->has_token  = (e->origin_token[0] != '\0');
    out->has_proxy  = (e->origin_x509_proxy[0] != '\0');
    return NGX_OK;
}

xrootd_sd_instance_t *
xrootd_vfs_backend_resolve(const char *root_canon, ngx_log_t *log)
{
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0'
        || xrootd_vfs_backend_count == 0)
    {
        return NULL;
    }

    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        xrootd_vfs_backend_entry_t *e = &xrootd_vfs_backends[i];

        if (ngx_strcmp(e->root_canon, root_canon) != 0) {
            continue;
        }
        return xrootd_vfs_backend_entry_build(e, log);
    }
    return NULL;
}

xrootd_sd_instance_t *
xrootd_vfs_backend_resolve_for_path(const char *abs_path, const char **root_out,
    ngx_log_t *log)
{
    xrootd_vfs_backend_entry_t *best = NULL;
    size_t                      best_len = 0;
    ngx_uint_t                  i;

    if (abs_path == NULL || abs_path[0] == '\0'
        || xrootd_vfs_backend_count == 0)
    {
        return NULL;
    }

    /* Longest registered export root that is a prefix of abs_path: a match is the
     * root itself or root + "/..." (so "/exp" never matches "/export/x"). */
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        xrootd_vfs_backend_entry_t *e = &xrootd_vfs_backends[i];
        size_t                      rl = ngx_strlen(e->root_canon);

        if (ngx_strncmp(abs_path, e->root_canon, rl) != 0) {
            continue;
        }
        if (abs_path[rl] != '/' && abs_path[rl] != '\0') {
            continue;                  /* shares a prefix but a different name */
        }
        if (rl > best_len) {
            best_len = rl;
            best     = e;
        }
    }
    if (best == NULL) {
        return NULL;
    }
    if (root_out != NULL) {
        *root_out = best->root_canon;
    }
    return xrootd_vfs_backend_entry_build(best, log);
}
