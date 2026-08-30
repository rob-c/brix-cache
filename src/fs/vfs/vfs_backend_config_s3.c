/*
 * vfs_backend_config_s3.c — the s3:// and root(s)://-or-local-driver origin
 * parsers plus their per-driver registry-entry builders (phase-79 file-size
 * split of vfs_backend_config.c).
 *
 * WHAT: Parses "s3://host[:port]/bucket" into an S3 source backend and
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

/* Register an S3 source backend for an export (phase-64): the export's bytes
 * live in a remote S3 bucket, served over the shared libcurl S3 transport
 * (signed Range GET; writes are staged whole-object uploads — single PUT or
 * MPU — via the driver's .staged_* slots, plus .unlink/DELETE). bucket is the
 * path-style bucket name; port defaults to 80/443 by tls when the URL omits
 * it. The driver caps are CAP_RANGE_READ|CAP_MEMFILE — no CAP_RANDOM_WRITE, so
 * in-place partial writes are rejected at the cap layer while sequential
 * uploads go through the staged path. */
void
brix_vfs_backend_config_s3(const char *root_canon, const char *host,
    int port, int tls, const char *bucket,
    const brix_vfs_s3_origin_opts_t *opts)
{
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || bucket == NULL || bucket[0] == '\0'
        || port <= 0 || port > 65535)
    {
        return;
    }
    e = brix_vfs_backend_entry_claim(root_canon, "s3");
    if (e == NULL) {
        return;
    }
    /* origin_path carries the bucket */
    brix_vfs_backend_set_origin(e, host, port, tls, bucket,
                                (opts != NULL) ? opts->put_checksum : 0);
    /* Both are stamped unconditionally so a reload that drops "?nearline=1"
     * leaves the export a plain bucket rather than keeping the previous cycle's
     * declaration — the cap commits the export to a cache tier, so a stale one
     * would be a config-time failure nobody asked for. */
    e->origin_nearline     = (opts != NULL && opts->nearline) ? 1 : 0;
    e->origin_restore_days = (opts != NULL) ? opts->restore_days : 0;
}

static void
brix_vfs_backend_set_xroot(brix_vfs_backend_entry_t *e,
    const brix_vfs_xroot_origin_t *o)
{
    ngx_memcpy(e->backend, "xroot", sizeof("xroot"));
    ngx_cpystrn((u_char *) e->origin_host, (u_char *) o->host,
                sizeof(e->origin_host));
    e->origin_port     = o->port;
    e->origin_tls      = o->tls;
    e->origin_family   = o->family;
    e->origin_nearline = o->nearline;
    e->inst            = NULL;                 /* rebuilt on next resolve */
}

void
brix_vfs_backend_config_xroot(const char *root_canon,
    const brix_vfs_xroot_origin_t *o)
{
    brix_vfs_backend_entry_t *e;

    if (root_canon == NULL || root_canon[0] == '\0' || o == NULL
        || o->host == NULL || o->host[0] == '\0' || o->port <= 0
        || o->port > 65535)
    {
        return;
    }

    /* Dedup on root_canon so a config reload updates rather than appends. */
    e = brix_vfs_backend_entry_get_or_create(root_canon);
    if (e != NULL) {
        brix_vfs_backend_set_xroot(e, o);
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
    /* Trim an optional "?opt=val" query suffix (e.g. ?put_checksum=1, #12) so the
     * bucket name stays clean; the caller scans the raw URL for the option. */
    {
        size_t q;
        for (q = 0; q < path_len; q++) {
            if (path[q] == '?') { path_len = q; break; }
        }
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

    /* #12: opt-in origin-enforced body integrity. "s3://host/bucket?put_checksum=1"
     * makes every PUT/UploadPart carry a signed x-amz-checksum-crc32 so the origin
     * validates the bytes and rejects a wire-corrupted upload with 400 BadDigest —
     * the outbound-leg analogue of the ingest Content-MD5 gate (#7). Off by default
     * (UNSIGNED-PAYLOAD): unknown-header-rejecting origins stay working untouched. */
    {
        brix_vfs_s3_origin_opts_t opts;

        ngx_memzero(&opts, sizeof(opts));
        opts.put_checksum = (ngx_strstr(sb->data, "put_checksum=1") != NULL);
        /* "?nearline=1" declares the bucket archive-backed: residency then comes
         * from x-amz-storage-class / x-amz-restore and recall from
         * RestoreObject (sd_remote_nearline.c). It is a DECLARATION and never
         * inferred from a storage class seen at runtime, because arming the cap
         * commits the export to carrying a cache tier as the recall target
         * (§9.4) — inferring it would turn a working bucket into a config-time
         * failure the first time someone tiered one object to GLACIER.
         * "?restore_days=N" tunes how long the restored copy stays readable. */
        opts.nearline     = (ngx_strstr(sb->data, "nearline=1") != NULL);
        opts.restore_days = brix_vfs_origin_opt_int(sb->data, "restore_days=",
                                                    0);
        brix_vfs_backend_config_s3(root_canon, parsed.host, parsed.port, 0,
                                   parsed.base, &opts);
    }
    return NGX_OK;

}

/* Configure a bare local-driver backend (the non-root:// fallback). Misconfig
 * guard: a URL-ish value no scheme claimed used to be SILENTLY ignored (a
 * `pblock:<dir>` typo ran the default POSIX backend). The legacy single-colon
 * posix:/pblock: spellings stay accepted (warned); any other colon form is an
 * [emerg]. Returns NGX_OK, or NGX_ERROR on an unrecognized scheme. */
static ngx_int_t
vfs_config_local_backend(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb, size_t block_size)
{
    if (memchr(sb->data, ':', sb->len) != NULL) {
        if ((sb->len > sizeof("posix:") - 1
             && ngx_strncmp(sb->data, "posix:", sizeof("posix:") - 1) == 0)
            || (sb->len > sizeof("pblock:") - 1
                && ngx_strncmp(sb->data, "pblock:", sizeof("pblock:") - 1) == 0))
        {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "brix_storage_backend \"%V\": the single-colon form is "
                "legacy — use \"%s\" bare (default root) or "
                "\"pblock://<dir>[?opts]\"", sb,
                sb->data[1] == 'o' ? "posix" : "pblock");
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_storage_backend \"%V\": unrecognized backend scheme "
                "(known: posix, pblock, pblock://, mirage:, block:, "
                "root://, roots://, root+tape://, roots+tape://, "
                "tape://, frm://, http(s)://, s3://, "
                "ceph:, rados:, cephfsro:)", sb);
            return NGX_ERROR;
        }
    }
    brix_vfs_backend_config(root_canon, sb, block_size);
    return NGX_OK;
}

/* The remote root:// spellings of a primary backend URL, longest first. "roots"
 * selects TLS; the "+tape" pair additionally declares that the origin fronts an
 * MSS, which arms the driver's nearline pair (residency from kXR_stat's
 * kXR_offline, recall via kXR_prepare/kXR_stage) instead of letting a first read
 * block a worker for the length of a tape mount. None of the four is a prefix of
 * another today, but the scan is ordered so it never starts to matter. */
static const struct {
    const char *prefix;
    size_t      len;
    int         tls;
    int         nearline;
} vfs_xroot_scheme_table[] = {
    { "roots+tape://", sizeof("roots+tape://") - 1, 1, 1 },
    { "root+tape://",  sizeof("root+tape://") - 1,  0, 1 },
    { "roots://",      sizeof("roots://") - 1,      1, 0 },
    { "root://",       sizeof("root://") - 1,       0, 0 },
};

/* "root[s][+tape]://host:port" → a remote root:// primary backend; any other
 * value is a local driver name (pblock/posix) handled by
 * brix_vfs_backend_config. Returns NGX_OK, or NGX_ERROR after an [emerg] for a
 * malformed remote origin. */
ngx_int_t
vfs_parse_xroot_or_driver_origin(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb, size_t block_size, int family)
{
    u_char *addr = NULL;
    size_t  addrn = 0;
    int     is_roots = 0;
    int     is_nearline = 0;
    size_t  s;

    for (s = 0; s < sizeof(vfs_xroot_scheme_table)
                    / sizeof(vfs_xroot_scheme_table[0]); s++)
    {
        size_t n = vfs_xroot_scheme_table[s].len;

        if (sb->len > n
            && ngx_strncmp(sb->data, vfs_xroot_scheme_table[s].prefix, n) == 0)
        {
            addr        = sb->data + n;
            addrn       = sb->len - n;
            is_roots    = vfs_xroot_scheme_table[s].tls;
            is_nearline = vfs_xroot_scheme_table[s].nearline;
            break;
        }
    }

    if (addr == NULL) {
        return vfs_config_local_backend(cf, root_canon, sb, block_size);
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
        {
            brix_vfs_xroot_origin_t o = {
                .host     = host,
                .port     = (int) portnum,
                .tls      = is_roots,
                .family   = family,
                .nearline = is_nearline,
            };

            brix_vfs_backend_config_xroot(root_canon, &o);
        }
    }

    return NGX_OK;
}
