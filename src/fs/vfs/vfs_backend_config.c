/*
 * vfs_backend_config.c — config-time half of the backend registry: the
 * brix_storage_backend directive parser (config_str), the per-driver entry
 * builders (xroot/http/s3/ceph/cephfsro/tape), and the credential / staging /
 * cache-tier / stage-tier setters. Everything here only fills registry entries;
 * building and resolving driver instances stays in vfs_backend_registry.c
 * (phase-38 split of the former single file).
 */
#include "vfs_backend_internal.h"

#include <string.h>

/*
 * vfs_origin_parse_t — the shared output record for the http:// and s3://
 * origin-segment parsers.
 *
 * WHAT: One caller-owned bundle carrying an origin segment's parse result —
 *       the host and base/bucket destination buffers (with their capacities),
 *       the resolved port and TLS flag, plus a `host_len` scratch slot the
 *       host/port splitter writes and the scheme stripper's `rest`/`rest_len`
 *       intermediates.
 * WHY:  The parse pipeline (strip scheme → split host:port → copy out) threaded
 *       the same host/port/tls/base four-tuple through every stage as separate
 *       by-value + out-pointer arguments, pushing each helper past the 5-param
 *       readability gate. Passing one pointer keeps the data flow explicit while
 *       collapsing the argument lists; behaviour is byte-for-byte identical
 *       (same buffers, same caps, same fields written).
 * HOW:  The caller stack-allocates and zero-inits one of these, sets `host`/
 *       `host_cap`/`base`/`base_cap` to its own char buffers, and passes its
 *       address down the pipeline. Each stage fills the fields it owns; the
 *       final stage copies the host and base into the caller's buffers.
 */
typedef struct {
    char    *host;       /* caller buffer for the NUL-terminated host          */
    size_t   host_cap;   /* capacity of `host` (incl. the NUL)                 */
    char    *base;       /* caller buffer for the base path (http) / bucket(s3)*/
    size_t   base_cap;   /* capacity of `base`                                 */
    int      port;       /* resolved port                                      */
    int      tls;        /* 1 iff https (http parser); 0 for s3                */
    size_t   host_len;   /* scratch: host length within the authority segment  */
    u_char  *rest;       /* scratch: segment remainder after the scheme        */
    size_t   rest_len;   /* scratch: length of `rest`                          */
} vfs_origin_parse_t;

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

static void
brix_vfs_backend_set_xroot(brix_vfs_backend_entry_t *e, const char *host,
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
brix_vfs_backend_config_xroot(const char *root_canon, const char *host,
    int port, int tls, int family)
{
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || port <= 0 || port > 65535)
    {
        return;
    }

    /* Dedup on root_canon so a config reload updates rather than appends. */
    e = brix_vfs_backend_entry_get_or_create(root_canon);
    if (e != NULL) {
        brix_vfs_backend_set_xroot(e, host, port, tls, family);
    }
}

void
brix_vfs_backend_config_http(const char *root_canon, const char *host,
    int port, int tls, const char *base_path)
{
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || port <= 0 || port > 65535)
    {
        return;
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
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
brix_vfs_backend_config_s3(const char *root_canon, const char *host,
    int port, int tls, const char *bucket)
{
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || bucket == NULL || bucket[0] == '\0'
        || port <= 0 || port > 65535)
    {
        return;
    }
    e = brix_vfs_backend_entry_get_or_create(root_canon);
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

/* 1 iff `data`/`len` starts with an http:// or https:// scheme. */
static int
vfs_backend_is_http_url(const u_char *data, size_t len)
{
    return (len > sizeof("http://") - 1
            && ngx_strncmp(data, "http://", sizeof("http://") - 1) == 0)
        || (len > sizeof("https://") - 1
            && ngx_strncmp(data, "https://", sizeof("https://") - 1) == 0);
}

/* Strip a leading http:// or https:// scheme off one origin segment, returning
 * the host-and-path remainder plus its TLS flag. Split out of the origin parser
 * so each function stays within the readability gate. */
static ngx_int_t
vfs_http_origin_strip_scheme(ngx_conf_t *cf, u_char *seg, size_t segn,
    vfs_origin_parse_t *out)
{
    if (segn > sizeof("https://") - 1
        && ngx_strncmp(seg, "https://", sizeof("https://") - 1) == 0)
    {
        out->rest     = seg + sizeof("https://") - 1;
        out->rest_len = segn - (sizeof("https://") - 1);
        out->tls      = 1;
        return NGX_OK;
    }
    if (segn > sizeof("http://") - 1
        && ngx_strncmp(seg, "http://", sizeof("http://") - 1) == 0)
    {
        out->rest     = seg + sizeof("http://") - 1;
        out->rest_len = segn - (sizeof("http://") - 1);
        out->tls      = 0;
        return NGX_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "brix_storage_backend: every |-separated origin must be an "
        "http:// or https:// URL");
    return NGX_ERROR;
}

/* Parse ONE "http(s)://host[:port][/base]" segment into host/port/tls/base.
 * Returns NGX_OK, or NGX_ERROR after an [emerg] for a malformed segment. */
/* Split the host-and-port prefix "host[:port]" (length hplen) into host length
 * and numeric port, defaulting to the scheme port when no ":port" is present.
 * Split out of the origin parser to keep its branching within the readability
 * gate. Returns NGX_OK, or NGX_ERROR after an [emerg] for a bad port. */
static ngx_int_t
vfs_http_origin_host_port(ngx_conf_t *cf, u_char *h, size_t hplen, int htls,
    vfs_origin_parse_t *out)
{
    u_char *colon = NULL;
    size_t  i;

    for (i = hplen; i > 0; i--) {
        if (h[i - 1] == ':') { colon = h + i - 1; break; }
    }
    if (colon != NULL) {
        ngx_int_t pn = ngx_atoi(colon + 1, (size_t) (h + hplen - (colon + 1)));

        if (pn == NGX_ERROR || pn <= 0 || pn > 65535) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_storage_backend: invalid http origin port");
            return NGX_ERROR;
        }
        out->host_len = (size_t) (colon - h);
        out->port     = (int) pn;
        return NGX_OK;
    }
    out->host_len = hplen;
    out->port     = htls ? 443 : 80;
    return NGX_OK;
}

static ngx_int_t
vfs_parse_http_origin(ngx_conf_t *cf, u_char *seg, size_t segn,
    vfs_origin_parse_t *out)
{
    u_char     *h;
    size_t      hn;
    size_t      i, slash, hplen, pathlen, hostn;
    const char *path;

    if (vfs_http_origin_strip_scheme(cf, seg, segn, out) != NGX_OK) {
        return NGX_ERROR;
    }
    h  = out->rest;
    hn = out->rest_len;

    slash = hn;
    for (i = 0; i < hn; i++) {
        if (h[i] == '/') { slash = i; break; }
    }
    hplen   = slash;
    path    = (slash < hn) ? (const char *) (h + slash) : "";
    pathlen = (slash < hn) ? hn - slash : 0;

    if (vfs_http_origin_host_port(cf, h, hplen, out->tls, out) != NGX_OK) {
        return NGX_ERROR;
    }
    hostn = out->host_len;
    if (hostn == 0 || hostn >= out->host_cap || pathlen >= out->base_cap) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend: invalid http origin host/path");
        return NGX_ERROR;
    }
    ngx_memcpy(out->host, h, hostn);
    out->host[hostn] = '\0';
    if (pathlen > 0) {
        ngx_memcpy(out->base, path, pathlen);
        out->base[pathlen] = '\0';
    } else {
        out->base[0] = '\0';
    }
    return NGX_OK;
}

/* Append one failover endpoint to the export's http backend entry (phase-68
 * T11). Must run AFTER brix_vfs_backend_config_http registered endpoint 0
 * for the same root. */
static ngx_int_t
vfs_backend_add_http_endpoint(ngx_conf_t *cf, const char *root_canon,
    const vfs_origin_parse_t *parsed)
{
    brix_vfs_backend_entry_t *e = brix_vfs_backend_entry_find(root_canon);
    size_t                      n;

    if (e == NULL || ngx_strcmp(e->backend, "http") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend: internal - endpoint list before primary");
        return NGX_ERROR;
    }
    n = sizeof(e->http_extra) / sizeof(e->http_extra[0]);
    if ((size_t) e->n_http_extra >= n) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend: too many |-separated origins (max %uz)",
            n + 1);
        return NGX_ERROR;
    }
    if (ngx_strlen(parsed->host) >= sizeof(e->http_extra[0].host)
        || ngx_strlen(parsed->base) >= sizeof(e->http_extra[0].base))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend: origin host/base too long for the "
            "endpoint table");
        return NGX_ERROR;
    }
    ngx_cpystrn((u_char *) e->http_extra[e->n_http_extra].host,
                (u_char *) parsed->host, sizeof(e->http_extra[0].host));
    e->http_extra[e->n_http_extra].port = parsed->port;
    e->http_extra[e->n_http_extra].tls  = parsed->tls;
    ngx_cpystrn((u_char *) e->http_extra[e->n_http_extra].base,
                (u_char *) parsed->base, sizeof(e->http_extra[0].base));
    e->n_http_extra++;
    e->inst = NULL;                            /* rebuilt on next resolve */
    return NGX_OK;
}


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

static ngx_int_t
vfs_parse_cephfsro_origin(ngx_conf_t *cf, const char *root_canon, const ngx_str_t *sb)
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

static ngx_int_t
vfs_parse_ceph_origin(ngx_conf_t *cf, const char *root_canon, const ngx_str_t *sb)
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

static ngx_int_t
vfs_parse_rados_origin(ngx_conf_t *cf, const char *root_canon, const ngx_str_t *sb)
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

static ngx_int_t
vfs_parse_tape_origin(ngx_conf_t *cf, const char *root_canon, const ngx_str_t *sb)
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

static ngx_int_t
vfs_parse_http_origin_list(ngx_conf_t *cf, const char *root_canon, const ngx_str_t *sb)
{
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
            vfs_origin_parse_t parsed;

            ngx_memzero(&parsed, sizeof(parsed));
            parsed.host     = host;
            parsed.host_cap = sizeof(host);
            parsed.base     = base;
            parsed.base_cap = sizeof(base);

            if (vfs_parse_http_origin(cf, seg, segn, &parsed) != NGX_OK) {
                return NGX_ERROR;              /* [emerg] already logged */
            }
            if (first) {
                brix_vfs_backend_config_http(root_canon, parsed.host,
                                               parsed.port, parsed.tls,
                                               parsed.base);
                first = 0;
            } else if (vfs_backend_add_http_endpoint(cf, root_canon, &parsed)
                       != NGX_OK)
            {
                return NGX_ERROR;
            }
            seg = (pipe != NULL) ? pipe + 1 : end;
        }
        return NGX_OK;
    }


    return NGX_DECLINED;
}

static ngx_int_t
vfs_parse_s3_port(ngx_conf_t *cf, const u_char *authority,
    size_t authority_len, vfs_origin_parse_t *out)
{
    const u_char *colon = NULL;
    size_t        i;

    for (i = authority_len; i > 0; i--) {
        if (authority[i - 1] == ':') {
            colon = authority + i - 1;
            break;
        }
    }

    if (colon == NULL) {
        out->host_len = authority_len;
        out->port = 7480;                  /* radosgw S3 default */
        return NGX_OK;
    }

    {
        ngx_int_t pn;
        pn = ngx_atoi((u_char *) colon + 1,
                      (size_t) (authority + authority_len - (colon + 1)));
        if (pn == NGX_ERROR || pn <= 0 || pn > 65535) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_storage_backend: invalid s3 origin port");
            return NGX_ERROR;
        }
        out->host_len = (size_t) (colon - authority);
        out->port = (int) pn;
    }

    return NGX_OK;
}

static ngx_int_t
vfs_parse_s3_url(ngx_conf_t *cf, const ngx_str_t *sb, vfs_origin_parse_t *out)
{
    u_char     *authority = sb->data + sizeof("s3://") - 1;
    size_t      rem = sb->len - (sizeof("s3://") - 1);
    size_t      i, slash = rem, authority_len, path_len, host_len;
    const char *path;

    for (i = 0; i < rem; i++) {
        if (authority[i] == '/') {
            slash = i;
            break;
        }
    }
    authority_len = slash;
    path = (slash < rem) ? (const char *) (authority + slash) : "";
    path_len = (slash < rem) ? rem - slash : 0;

    if (vfs_parse_s3_port(cf, authority, authority_len, out) != NGX_OK) {
        return NGX_ERROR;
    }
    host_len = out->host_len;
    while (path_len > 0 && path[0] == '/') {
        path++;
        path_len--;
    }
    if (host_len == 0 || host_len >= out->host_cap || path_len == 0
        || path_len >= out->base_cap)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_storage_backend: s3:// needs \"//host[:port]/bucket\"");
        return NGX_ERROR;
    }

    ngx_memcpy(out->host, authority, host_len);
    out->host[host_len] = '\0';
    ngx_memcpy(out->base, path, path_len);
    out->base[path_len] = '\0';
    return NGX_OK;
}

static ngx_int_t
vfs_parse_s3_origin(ngx_conf_t *cf, const char *root_canon, const ngx_str_t *sb)
{
    char host[256], bucket[256];
    vfs_origin_parse_t parsed;

    /* "s3://host[:port]/bucket" → a read-only S3 source backend (path-style): the
     * first path segment is the bucket. Default port 7480 (radosgw), tls off — the
     * same defaults the generic tier parser uses for an s3 store. */
    if (sb->len < sizeof("s3://") - 1
        || ngx_strncmp(sb->data, "s3://", sizeof("s3://") - 1) != 0)
    {
        return NGX_DECLINED;
    }

    ngx_memzero(&parsed, sizeof(parsed));
    parsed.host     = host;
    parsed.host_cap = sizeof(host);
    parsed.base     = bucket;   /* origin_path carries the bucket */
    parsed.base_cap = sizeof(bucket);

    if (vfs_parse_s3_url(cf, sb, &parsed) != NGX_OK) {
        return NGX_ERROR;
    }

    brix_vfs_backend_config_s3(root_canon, parsed.host, parsed.port, 0,
                               parsed.base);
    return NGX_OK;

}

static ngx_int_t
vfs_parse_xroot_or_driver_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb, size_t block_size, int family)
{
    u_char *addr = NULL;
    size_t  addrn = 0;
    int     is_roots = 0;
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
        brix_vfs_backend_config(root_canon, sb, block_size);
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
                "brix_storage_backend: remote origin needs host:port");
            return NGX_ERROR;
        }
        hostn   = (size_t) (colon - addr);
        portnum = ngx_atoi(colon + 1, (size_t) (addr + addrn - (colon + 1)));
        if (hostn == 0 || hostn >= sizeof(host) || portnum == NGX_ERROR
            || portnum <= 0 || portnum > 65535)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_storage_backend: invalid remote origin host:port");
            return NGX_ERROR;
        }
        ngx_memcpy(host, addr, hostn);
        host[hostn] = '\0';
        brix_vfs_backend_config_xroot(root_canon, host, (int) portnum,
                                        is_roots, family);
    }

    return NGX_OK;
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
