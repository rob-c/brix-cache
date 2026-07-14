/*
 * vfs_backend_config_s3.c — the s3:// and root(s)://-or-local-driver origin
 * parsers plus their per-driver registry-entry builders (phase-79 file-size
 * split of vfs_backend_config.c).
 *
 * WHAT: Parses "s3://host[:port]/bucket" into a read-only S3 source backend and
 *       "root://host:port" / "roots://host:port" into a remote root:// primary
 *       backend (any other value falling through to the local driver name via
 *       brix_vfs_backend_config). Includes the s3 and xroot entry builders.
 * WHY:  The s3 and root(s):// network-origin schemes form the last cohesive
 *       cluster left after the ceph and http splits; separating them keeps every
 *       file under the 500-line cap with byte-for-byte identical parse
 *       acceptance/rejection, defaults (7480 radosgw for s3, tls off), and
 *       [emerg] messages.
 * HOW:  brix_vfs_backend_config_str (vfs_backend_config.c) calls the non-static
 *       vfs_parse_s3_origin and vfs_parse_xroot_or_driver_origin entry points
 *       declared in vfs_backend_config_internal.h; each fills a registry entry
 *       through the builder for its driver (or defers to the local-driver path).
 */
#include "vfs_backend_config_internal.h"

#include <string.h>

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

/* Split an s3:// authority "host[:port]" into host length and numeric port,
 * defaulting to 7480 (radosgw) when no ":port" is present. Returns NGX_OK, or
 * NGX_ERROR after an [emerg] for a bad port. */
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

/* Parse "s3://host[:port]/bucket" into host/port/base(bucket). Returns NGX_OK,
 * or NGX_ERROR after an [emerg] for a malformed URL. */
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

/* "s3://host[:port]/bucket" → a read-only S3 source backend. Returns NGX_OK on a
 * handled segment, NGX_ERROR after an [emerg] for a malformed one, or
 * NGX_DECLINED when the scheme is not ours. */
ngx_int_t
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

/* "root://host:port" / "roots://host:port" → a remote root:// primary backend;
 * any other value is a local driver name (pblock/posix) handled by
 * brix_vfs_backend_config. Returns NGX_OK, or NGX_ERROR after an [emerg] for a
 * malformed remote origin. */
ngx_int_t
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
