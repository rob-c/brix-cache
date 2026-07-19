/*
 * vfs_backend_config_http.c — the http(s):// origin parser (with T11
 * multi-endpoint failover lists) and the http per-driver registry-entry
 * builder (phase-79 file-size split of vfs_backend_config.c).
 *
 * WHAT: Parses "http://host[:port][/base]" / "https://..." backend origins —
 *       including a pipe-separated ordered list that registers a ranked
 *       multi-endpoint origin set (phase-68 T11) — into registry entries, and
 *       registers each endpoint (primary via brix_vfs_backend_config_http,
 *       failovers via the http_extra list).
 * WHY:  The http scheme (a read-only HTTP source backend served over the shared
 *       libcurl transport) is its own cohesive cluster; splitting it out keeps
 *       every file under the 500-line cap with byte-for-byte identical parse
 *       acceptance/rejection, defaults (443/80 by scheme), and [emerg] messages.
 * HOW:  brix_vfs_backend_config_str (vfs_backend_config.c) calls the non-static
 *       vfs_parse_http_origin_list entry point declared in
 *       vfs_backend_config_internal.h; the per-segment pipeline (strip scheme →
 *       split host:port → copy out) fills a vfs_origin_parse_t, then registers
 *       the primary endpoint and appends any failovers.
 */
#include "vfs_backend_config_internal.h"

#include <string.h>

/* Register a read-only HTTP source backend for an export (endpoint 0). host/port
 * are required; base_path is the URL base ("" / "/sub"). Resets the T11 failover
 * list so a reload re-registers cleanly. */
void
brix_vfs_backend_config_http(const char *root_canon, const char *host,
    int port, int tls, const char *base_path, int put_checksum)
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
    e->origin_put_checksum = put_checksum ? 1 : 0;   /* #12 */
    e->n_http_extra = 0;                       /* reload resets the T11 list */
    e->inst = NULL;                            /* rebuilt on next resolve */
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

/* Parse ONE "http(s)://host[:port][/base]" segment into host/port/tls/base.
 * Returns NGX_OK, or NGX_ERROR after an [emerg] for a malformed segment. */
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

    /* Trim an optional "?opt=val" query suffix (e.g. ?put_checksum=1, #12) off the
     * URL base so the write-target path stays clean; the list parser scans the raw
     * segment for the option itself. */
    {
        size_t q;
        for (q = 0; q < pathlen; q++) {
            if (path[q] == '?') { pathlen = q; break; }
        }
    }

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

/* "http://host[:port]/base" / "https://..." → a read-only HTTP SOURCE backend,
 * as a pipe-separated ordered failover list (phase-68 T11). Returns NGX_OK on a
 * handled set, NGX_ERROR after an [emerg] for a malformed one, or NGX_DECLINED
 * when the scheme is not ours. */
ngx_int_t
vfs_parse_http_origin_list(ngx_conf_t *cf, const char *root_canon,
    const ngx_str_t *sb)
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
        /* #12: opt-in origin-enforced body integrity. "...?put_checksum=1" makes the
         * commit PUT (endpoint 0, the write target) carry Content-MD5 so the origin
         * validates the bytes and rejects a wire-corrupted upload. Off by default:
         * an origin that ignores Content-MD5 stays working untouched. */
        int     put_checksum = (ngx_strstr(sb->data, "put_checksum=1") != NULL);

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
                                               parsed.base, put_checksum);
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
