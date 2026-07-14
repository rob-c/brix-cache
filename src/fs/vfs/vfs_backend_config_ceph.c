/*
 * vfs_backend_config_ceph.c — the ceph-family origin parsers and their
 * per-driver registry-entry builders (phase-79 file-size split of
 * vfs_backend_config.c).
 *
 * WHAT: Parses the RADOS/CephFS/nearline backend origin strings —
 *       "ceph:<pool>...", "rados://<pool>...", "cephfsro:<meta>+<data>...",
 *       and "tape://<adapter>/<base>" (alias "frm://...") — into registry
 *       entries, plus the three static entry builders those parsers call
 *       (ceph, read-only CephFS-via-RADOS, tape/MSS).
 * WHY:  These schemes form one cohesive cluster (RADOS-cluster / nearline
 *       storage, distinct from the http/s3/xroot network origins). Splitting
 *       them out keeps every file under the 500-line cap with no behaviour
 *       change: identical parse acceptance/rejection, identical defaults
 *       (/etc/ceph/ceph.conf), and identical [emerg] messages.
 * HOW:  brix_vfs_backend_config_str (vfs_backend_config.c) calls the four
 *       non-static vfs_parse_*_origin entry points declared in
 *       vfs_backend_config_internal.h; each returns NGX_OK / NGX_ERROR /
 *       NGX_DECLINED and, on a match, fills a registry entry through the
 *       static builder for its driver.
 */
#include "vfs_backend_config_internal.h"

#include <string.h>

/*
 * vfs_cephfsro_parts_t — the four caller-owned destination buffers the
 * cephfsro URL splitter fills.
 *
 * WHAT: Bundles the meta-pool / data-pool / conf-path / query destination
 *       buffers (each with its capacity) that "cephfsro:<meta>+<data>[@conf]
 *       [?query]" splits into.
 * WHY:  Passing four (buffer, capacity) pairs as eight separate arguments put
 *       the splitter far past the readability gate; one pointer keeps the
 *       phased scan unchanged while collapsing the signature.
 * HOW:  The caller stack-allocates one, points each field at its own char
 *       array, and passes its address; the splitter writes each phase's bytes
 *       into the matching buffer (capacity-clamped, NUL-terminated) exactly as
 *       before.
 */
typedef struct {
    char    *meta;      size_t meta_cap;
    char    *data;      size_t data_cap;
    char    *conf;      size_t conf_cap;
    char    *query;     size_t query_cap;
} vfs_cephfsro_parts_t;

/*
 * vfs_cephfsro_cfg_t — the already-parsed cephfsro backend settings handed to
 * the per-driver entry builder.
 *
 * WHAT: The meta/data pool names, the ceph.conf path, and the two operator
 *       consistency assertions (quiesced / live) for a read-only CephFS backend.
 * WHY:  The entry builder took these as six positional arguments; grouping the
 *       parsed values keeps the call within the readability gate with no change
 *       to what gets stored.
 * HOW:  The origin parser fills one and passes its address to
 *       brix_vfs_backend_config_cephfs_ro, which copies the fields into the
 *       registry entry exactly as the positional version did.
 */
typedef struct {
    const char *meta_pool;
    const char *data_pool;
    const char *conf;
    int         quiesced;
    int         live;
} vfs_cephfsro_cfg_t;

/* Register a Ceph/RADOS backend for an export. pool is required; conf defaults
 * to /etc/ceph/ceph.conf and key_prefix to "" when NULL/empty. */
static void
brix_vfs_backend_config_ceph(const char *root_canon, const char *backend,
    const char *pool, const char *conf, const char *key_prefix)
{
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0'
        || pool == NULL || pool[0] == '\0')
    {
        return;
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
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
brix_vfs_backend_config_cephfs_ro(const char *root_canon,
    const vfs_cephfsro_cfg_t *cfg)
{
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0'
        || cfg->meta_pool == NULL || cfg->meta_pool[0] == '\0'
        || cfg->data_pool == NULL || cfg->data_pool[0] == '\0')
    {
        return;
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
    if (e == NULL) {
        return;
    }
    ngx_memcpy(e->backend, "cephfsro", sizeof("cephfsro"));
    ngx_cpystrn((u_char *) e->ceph_pool, (u_char *) cfg->meta_pool,
                sizeof(e->ceph_pool));
    ngx_cpystrn((u_char *) e->ceph_data_pool, (u_char *) cfg->data_pool,
                sizeof(e->ceph_data_pool));
    ngx_cpystrn((u_char *) e->ceph_conf,
                (u_char *) ((cfg->conf && cfg->conf[0]) ? cfg->conf
                                                        : "/etc/ceph/ceph.conf"),
                sizeof(e->ceph_conf));
    e->cephfs_quiesced = cfg->quiesced;
    e->cephfs_live = cfg->live;
    e->inst = NULL;                            /* rebuilt on next resolve */
}

/* Register a nearline (tape/MSS) backend (phase-64 SP5). `adapter` ("" = the
 * built-in stub) names the MSS adapter; `base` is its MSS base path. The composing
 * stack requires a cache tier in front (G8, enforced at config time). */
static void
brix_vfs_backend_config_tape(const char *root_canon, const char *adapter,
    const char *base)
{
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0'
        || base == NULL || base[0] == '\0')
    {
        return;
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
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

/* Split "cephfsro:<meta>+<data>[@conf][?query]" into its four component buffers
 * (each capacity-clamped and NUL-terminated). Phased scan: '+' ends meta, '@'
 * ends data, '?' ends conf. */
static void
vfs_parse_cephfsro_parts(const u_char *rest, size_t restn,
    const vfs_cephfsro_parts_t *parts)
{
    size_t i, mn = 0, dn = 0, cn = 0, qn = 0;
    int    phase = 0;   /* 0=meta, 1=data (+), 2=conf (@), 3=query (?) */

    for (i = 0; i < restn; i++) {
        u_char c = rest[i];
        if (c == '+' && phase == 0) { phase = 1; continue; }
        if (c == '@' && phase < 2)  { phase = 2; continue; }
        if (c == '?')               { phase = 3; continue; }
        if (phase == 0 && mn + 1 < parts->meta_cap) { parts->meta[mn++] = (char) c; }
        else if (phase == 1 && dn + 1 < parts->data_cap) { parts->data[dn++] = (char) c; }
        else if (phase == 2 && cn + 1 < parts->conf_cap) { parts->conf[cn++] = (char) c; }
        else if (phase == 3 && qn + 1 < parts->query_cap) { parts->query[qn++] = (char) c; }
    }
    parts->meta[mn] = '\0';
    parts->data[dn] = '\0';
    parts->conf[cn] = '\0';
    parts->query[qn] = '\0';
}

/* "cephfsro:<meta_pool>+<data_pool>[@<conf>][?assume_quiesced=1]" → read-only
 * CephFS-via-RADOS backend. Returns NGX_OK on a handled segment, NGX_ERROR after
 * an [emerg] for a malformed one, or NGX_DECLINED when the scheme is not ours. */
ngx_int_t
vfs_parse_cephfsro_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb)
{
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
        vfs_cephfsro_parts_t parts = {
            meta, sizeof(meta), data, sizeof(data),
            conf, sizeof(conf), q, sizeof(q)
        };
        vfs_cephfsro_cfg_t cfg;

        vfs_parse_cephfsro_parts(rest, restn, &parts);

        if (meta[0] == '\0' || data[0] == '\0') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "brix_storage_backend: "
                "cephfsro needs both pools (cephfsro:<meta>+<data>)");
            return NGX_ERROR;
        }
        cfg.meta_pool = meta;
        cfg.data_pool = data;
        cfg.conf      = conf;
        cfg.quiesced  = (ngx_strstr(q, "assume_quiesced=1") != NULL);
        cfg.live      = (ngx_strstr(q, "live=1") != NULL);
        if (!cfg.quiesced && !cfg.live) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "brix_storage_backend: "
                "cephfsro requires a consistency assertion: "
                "?assume_quiesced=1 (fs frozen — MDS down/failed, journal flushed) "
                "or ?live=1 (still mounted — best-effort eventually-consistent "
                "reads with optimistic revalidation + retry)");
            return NGX_ERROR;
        }
        brix_vfs_backend_config_cephfs_ro(root_canon, &cfg);
        return NGX_OK;
    }


    return NGX_DECLINED;
}

/* "ceph:<pool>[@<conf>][?<key_prefix>]" → flat, block-only RADOS object backend.
 * Returns NGX_OK / NGX_ERROR / NGX_DECLINED as above. */
ngx_int_t
vfs_parse_ceph_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb)
{
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
                    "brix_storage_backend: %s: needs a pool (%s:<pool>)",
                    backend, backend);
                return NGX_ERROR;
            }
            brix_vfs_backend_config_ceph(root_canon, backend, pool, conf, prefix);
            return NGX_OK;
        }
    }


    return NGX_DECLINED;
}

/* "rados://<pool>[/<namespace>]" → the flat librados object backend (URL alias
 * of "ceph:<pool>"). Returns NGX_OK / NGX_ERROR / NGX_DECLINED as above. */
ngx_int_t
vfs_parse_rados_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb)
{
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
                "brix_storage_backend: rados:// needs \"//<pool>[/<namespace>]\"");
            return NGX_ERROR;
        }
        brix_vfs_backend_config_ceph(root_canon, "ceph", pool, NULL, prefix);
        return NGX_OK;
    }


    return NGX_DECLINED;
}

/* "tape://<adapter>/<base>" (alias "frm://...") → nearline (tape/MSS) backend
 * served by sd_frm. Returns NGX_OK / NGX_ERROR / NGX_DECLINED as above. */
ngx_int_t
vfs_parse_tape_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb)
{
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
                    "brix_storage_backend: tape://|frm:// needs "
                    "\"//<adapter>/<base-path>\"");
                return NGX_ERROR;
            }
            brix_vfs_backend_config_tape(root_canon, adapter, base);
            return NGX_OK;
        }
    }


    return NGX_DECLINED;
}
