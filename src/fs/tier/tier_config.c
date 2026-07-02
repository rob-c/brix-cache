/*
 * tier_config.c - parse a store URL into a tier cfg, and report a tier's
 * readiness against its role contract (phase-64 section 4.2 / 2.2, Appendix L/F).
 *
 * xrootd_tier_parse_store turns "<scheme>:<location> [credential=][block_size=]"
 * into an xrootd_tier_cfg_t: scheme -> driver (root[s]->xroot, http[s]->http),
 * a local path confined via xrootd_prepare_export_root, or a remote //host[:port]
 * authority with a scheme default port. An unknown scheme / unknown credential /
 * missing port is an OPERATOR error ([emerg], fails nginx -t, Appendix F).
 *
 * xrootd_tier_status checks the built driver against the per-role slot+cap
 * contract (section 2.2): a missing slot/cap is a tracked "needs development"
 * (NEEDS_DEV + the closing sub-project), never a hard failure (P1).
 */
#include "tier.h"
#include "core/config/root_prepare.h"   /* xrootd_prepare_export_root */

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* scheme -> { driver, tls, nearline } table (the only scheme knowledge). */
static const struct {
    const char *scheme;
    const char *driver;
    int         tls;
    int         nearline;
} tier_schemes[] = {
    { "posix",  "posix",  0, 0 },
    { "pblock", "pblock", 0, 0 },
    { "root",   "xroot",  0, 0 },
    { "roots",  "xroot",  1, 0 },
    { "http",   "http",   0, 0 },
    { "https",  "http",   1, 0 },
    { "webdav", "http",   0, 0 },   /* WebDAV is HTTP; davs is HTTPS */
    { "davs",   "http",   1, 0 },
    { "s3",     "s3",     0, 0 },
    { "rados",  "rados",  0, 0 },
    { "ceph",   "ceph",   0, 0 },   /* librados object store (alias of rados) */
    { "tape",   "tape",   0, 1 },
    { "frm",    "frm",    0, 1 },   /* nearline MSS/HSM (alias of tape) */
};

/* ---- small helpers -------------------------------------------------------- */

/* Format an operator-error message into err[errcap] and, when log_emerg, also emit
 * it as an [emerg] so nginx -t fails (Appendix F). Always returns NGX_ERROR. */
static ngx_int_t
tier_fail(ngx_conf_t *cf, int log_emerg, char *err, size_t errcap,
    const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

static ngx_int_t
tier_fail(ngx_conf_t *cf, int log_emerg, char *err, size_t errcap,
    const char *fmt, ...)
{
    va_list ap;
    char    buf[256];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (err != NULL && errcap > 0) {
        ngx_cpystrn((u_char *) err, (u_char *) buf, errcap);
    }
    if (log_emerg && cf != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", buf);
    }
    return NGX_ERROR;
}

/* The consuming directive name for a role (used in path-validation errors). */
static const char *
tier_role_directive(xrootd_tier_role_t role)
{
    switch (role) {
    case XROOTD_TIER_BACKEND: return "xrootd_storage_backend";
    case XROOTD_TIER_CACHE:   return "xrootd_cache_store";
    case XROOTD_TIER_STAGE:   return "xrootd_stage_store";
    }
    return "xrootd_store";
}

/* Default TCP port for a remote scheme (0 = the driver/adapter decides, e.g.
 * rados pools and tape MSS endpoints carry no TCP port). */
static int
tier_default_port(const char *driver, int tls)
{
    if (ngx_strcmp(driver, "xroot") == 0) { return 1094; }
    if (ngx_strcmp(driver, "http") == 0)  { return tls ? 443 : 80; }
    if (ngx_strcmp(driver, "s3") == 0)    { return 7480; }
    return 0;
}

/* The sub-project that closes a gap for (driver, role) - the §3 status matrix. */
static const char *
tier_sp_for(const char *driver, xrootd_tier_role_t role)
{
    (void) role;
    if (ngx_strcmp(driver, "pblock") == 0 || ngx_strcmp(driver, "xroot") == 0) {
        return "SP2";
    }
    if (ngx_strcmp(driver, "tape") == 0) {
        return "SP5";
    }
    return "SP3";   /* writable http/s3 + rados stores */
}

/* Parse a remote "//host[:port][/path]" authority (IPv6-bracket aware) into out. */
static ngx_int_t
tier_parse_authority(ngx_conf_t *cf, u_char *loc, size_t loclen,
    xrootd_tier_cfg_t *out, char *err, size_t errcap)
{
    u_char    *authority;
    u_char    *path;
    size_t     authlen;
    size_t     hostlen;
    size_t     pathlen;
    size_t     i;
    ngx_int_t  portnum = 0;

    if (loclen < 2 || loc[0] != '/' || loc[1] != '/') {
        return tier_fail(cf, 1, err, errcap, "remote store needs \"//host\"");
    }
    authority = loc + 2;
    authlen   = loclen - 2;
    for (i = 0; i < authlen; i++) {
        if (authority[i] == '/') {
            authlen = i;
            break;
        }
    }
    path    = authority + authlen;
    pathlen = (size_t) ((loc + loclen) - path);

    if (authlen > 0 && authority[0] == '[') {           /* [v6]:port */
        u_char *rb = NULL;

        for (i = 1; i < authlen; i++) {
            if (authority[i] == ']') { rb = authority + i; break; }
        }
        if (rb == NULL) {
            return tier_fail(cf, 1, err, errcap, "unbalanced \"[\" in store host");
        }
        hostlen = (size_t) (rb - (authority + 1));
        if (rb + 1 < authority + authlen && rb[1] == ':') {
            portnum = ngx_atoi(rb + 2, (size_t) (authority + authlen - (rb + 2)));
            if (portnum == NGX_ERROR || portnum <= 0 || portnum > 65535) {
                return tier_fail(cf, 1, err, errcap, "invalid store port");
            }
        }
        if (hostlen == 0 || hostlen >= sizeof(out->host)) {
            return tier_fail(cf, 1, err, errcap, "invalid store host");
        }
        ngx_memcpy(out->host, authority + 1, hostlen);
    } else {                                            /* host[:port] */
        u_char *colon = NULL;

        for (i = authlen; i > 0; i--) {
            if (authority[i - 1] == ':') { colon = authority + i - 1; break; }
        }
        if (colon != NULL && colon + 1 < authority + authlen) {
            hostlen = (size_t) (colon - authority);
            portnum = ngx_atoi(colon + 1,
                               (size_t) (authority + authlen - (colon + 1)));
            if (portnum == NGX_ERROR || portnum <= 0 || portnum > 65535) {
                return tier_fail(cf, 1, err, errcap, "invalid store port");
            }
        } else if (colon != NULL) {
            hostlen = (size_t) (colon - authority);   /* "host:" trailing colon, no port */
        } else {
            hostlen = authlen;
        }
        if (hostlen == 0 || hostlen >= sizeof(out->host)) {
            return tier_fail(cf, 1, err, errcap, "invalid store host");
        }
        ngx_memcpy(out->host, authority, hostlen);
    }
    out->host[(hostlen < sizeof(out->host)) ? hostlen : sizeof(out->host) - 1] = '\0';
    out->port = (portnum > 0) ? (int) portnum : 0;

    /* Collapse a leading "//" (the "host://path" form) to one '/' so the path is a
     * single canonical absolute path regardless of host/path delimiter style. */
    while (pathlen >= 2 && path[0] == '/' && path[1] == '/') {
        path++;
        pathlen--;
    }

    if (pathlen >= sizeof(out->path)) {
        return tier_fail(cf, 1, err, errcap, "store path too long");
    }
    if (pathlen > 0) {
        ngx_memcpy(out->path, path, pathlen);
        out->path[pathlen] = '\0';
    }
    return NGX_OK;
}

/* Parse the trailing "credential=<n>" / "block_size=<n>" params. */
static ngx_int_t
tier_parse_args(ngx_conf_t *cf, ngx_array_t *args, xrootd_tier_cfg_t *out,
    char *err, size_t errcap)
{
    ngx_str_t  *a;
    ngx_uint_t  i;

    if (args == NULL) {
        return NGX_OK;
    }
    a = args->elts;
    for (i = 0; i < args->nelts; i++) {
        static const char cred[] = "credential=";
        static const char blk[]  = "block_size=";

        if (a[i].len > sizeof(cred) - 1
            && ngx_strncmp(a[i].data, cred, sizeof(cred) - 1) == 0)
        {
            const xrootd_credential_t *c;
            char   name[256];
            size_t nl = a[i].len - (sizeof(cred) - 1);

            if (nl == 0 || nl >= sizeof(name)) {
                return tier_fail(cf, 1, err, errcap, "invalid credential name");
            }
            ngx_memcpy(name, a[i].data + sizeof(cred) - 1, nl);
            name[nl] = '\0';
            c = xrootd_credential_lookup(name);
            if (c == NULL) {
                return tier_fail(cf, 1, err, errcap,
                    "no xrootd_credential \"%s\"", name);
            }
            out->credential = c;
        } else if (a[i].len > sizeof(blk) - 1
            && ngx_strncmp(a[i].data, blk, sizeof(blk) - 1) == 0)
        {
            ngx_str_t v;
            ssize_t   sz;

            v.len  = a[i].len - (sizeof(blk) - 1);
            v.data = a[i].data + sizeof(blk) - 1;
            sz = ngx_parse_size(&v);
            if (sz == NGX_ERROR) {
                return tier_fail(cf, 1, err, errcap, "invalid block_size");
            }
            out->block_size = (size_t) sz;
        } else {
            return tier_fail(cf, 1, err, errcap,
                "unknown store param \"%.*s\"", (int) a[i].len, a[i].data);
        }
    }
    return NGX_OK;
}

/* ---- public: parse a store URL -------------------------------------------- */

ngx_int_t
xrootd_tier_parse_store(ngx_conf_t *cf, ngx_str_t *url, ngx_array_t *args,
    xrootd_tier_role_t role, xrootd_tier_cfg_t *out, char *err, size_t errcap)
{
    const char *driver = NULL;
    u_char     *loc;
    size_t      schemelen;
    size_t      loclen;
    size_t      i;
    int         tls = 0;
    int         nearline = 0;
    int         is_local;

    if (out == NULL || url == NULL || url->len == 0) {
        return tier_fail(cf, 1, err, errcap, "empty store url");
    }
    ngx_memzero(out, sizeof(*out));
    out->role = role;

    for (i = 0; i < url->len; i++) {
        if (url->data[i] == ':') { break; }
    }
    if (i == 0 || i >= url->len) {
        return tier_fail(cf, 1, err, errcap,
            "store url \"%.*s\" has no scheme", (int) url->len, url->data);
    }
    schemelen = i;
    loc       = url->data + i + 1;
    loclen    = url->len - i - 1;

    for (i = 0; i < sizeof(tier_schemes) / sizeof(tier_schemes[0]); i++) {
        if (ngx_strlen(tier_schemes[i].scheme) == schemelen
            && ngx_strncmp(url->data, tier_schemes[i].scheme, schemelen) == 0)
        {
            driver   = tier_schemes[i].driver;
            tls      = tier_schemes[i].tls;
            nearline = tier_schemes[i].nearline;
            break;
        }
    }
    if (driver == NULL) {
        return tier_fail(cf, 1, err, errcap,
            "unknown driver scheme \"%.*s\"", (int) schemelen, url->data);
    }
    ngx_cpystrn((u_char *) out->driver, (u_char *) driver, sizeof(out->driver));
    out->tls      = tls;
    out->nearline = (unsigned) nearline;

    is_local = (ngx_strcmp(driver, "posix") == 0
                || ngx_strcmp(driver, "pblock") == 0);

    if (is_local) {
        xrootd_export_root_opts_t opts;
        ngx_str_t                 loc_str;
        char                      canon[PATH_MAX];

        loc_str.len  = loclen;
        loc_str.data = loc;
        ngx_memzero(&opts, sizeof(opts));
        opts.directive_name = tier_role_directive(role);
        opts.allow_write    = (role != XROOTD_TIER_BACKEND) ? 1 : 0;
        opts.required       = 1;
        opts.canon_size     = sizeof(canon);

        if (xrootd_prepare_export_root(cf, &loc_str, &opts, canon) != NGX_CONF_OK) {
            /* prepare_export_root already emitted an [emerg]. */
            return tier_fail(cf, 0, err, errcap,
                "invalid local store path for %s", opts.directive_name);
        }
        if (ngx_strlen(canon) >= sizeof(out->path)) {
            return tier_fail(cf, 1, err, errcap, "local store path too long");
        }
        ngx_cpystrn((u_char *) out->path, (u_char *) canon, sizeof(out->path));
    } else {
        if (tier_parse_authority(cf, loc, loclen, out, err, errcap) != NGX_OK) {
            return NGX_ERROR;
        }
        if (out->port == 0) {
            out->port = tier_default_port(driver, tls);
        }
        if (out->port == 0
            && (ngx_strcmp(driver, "xroot") == 0
                || ngx_strcmp(driver, "http") == 0
                || ngx_strcmp(driver, "s3") == 0))
        {
            return tier_fail(cf, 1, err, errcap,
                "remote store \"%.*s\" is missing a port", (int) url->len,
                url->data);
        }
    }

    if (tier_parse_args(cf, args, out, err, errcap) != NGX_OK) {
        return NGX_ERROR;
    }

    out->configured = 1;
    return NGX_OK;
}

/* ---- public: report a tier's readiness ------------------------------------ */

xrootd_tier_status_t
xrootd_tier_status(const xrootd_tier_cfg_t *t, xrootd_sd_instance_t *probe,
    xrootd_tier_gap_t *gap_out)
{
    const xrootd_sd_driver_t *d;
    uint32_t                  caps;
    xrootd_tier_gap_t         g;

    ngx_memzero(&g, sizeof(g));

    if (t == NULL || probe == NULL || probe->driver == NULL) {
        ngx_cpystrn((u_char *) g.slot, (u_char *) "open", sizeof(g.slot));
        ngx_cpystrn((u_char *) g.sp_item, (u_char *) "SP1", sizeof(g.sp_item));
        if (gap_out != NULL) { *gap_out = g; }
        return XROOTD_TIER_NEEDS_DEV;
    }
    d    = probe->driver;
    caps = d->caps;
    ngx_cpystrn((u_char *) g.sp_item, (u_char *) tier_sp_for(t->driver, t->role),
                sizeof(g.sp_item));

#define MISS_SLOT(field, nm)                                                   \
    do {                                                                       \
        if (d->field == NULL) {                                                \
            ngx_cpystrn((u_char *) g.slot, (u_char *) (nm), sizeof(g.slot));    \
            if (gap_out != NULL) { *gap_out = g; }                             \
            return XROOTD_TIER_NEEDS_DEV;                                       \
        }                                                                      \
    } while (0)

#define MISS_CAP(bit, nm)                                                      \
    do {                                                                       \
        if ((caps & (bit)) == 0) {                                             \
            ngx_cpystrn((u_char *) g.cap, (u_char *) (nm), sizeof(g.cap));      \
            if (gap_out != NULL) { *gap_out = g; }                             \
            return XROOTD_TIER_NEEDS_DEV;                                       \
        }                                                                      \
    } while (0)

    switch (t->role) {
    case XROOTD_TIER_BACKEND:
        MISS_SLOT(open, "open");
        MISS_SLOT(pread, "pread");
        MISS_SLOT(stat, "stat");
        MISS_SLOT(fstat, "fstat");
        MISS_CAP(XROOTD_SD_CAP_RANGE_READ, "RANGE_READ");
        if (t->nearline) {
            MISS_SLOT(recall, "recall");
            MISS_CAP(XROOTD_SD_CAP_NEARLINE, "NEARLINE");
        }
        break;

    case XROOTD_TIER_CACHE:
        MISS_SLOT(open, "open");
        MISS_SLOT(pread, "pread");
        MISS_SLOT(stat, "stat");
        MISS_SLOT(staged_open, "staged_open");
        MISS_SLOT(staged_write, "staged_write");
        MISS_SLOT(staged_commit, "staged_commit");
        MISS_SLOT(staged_abort, "staged_abort");
        MISS_SLOT(unlink, "unlink");
        MISS_SLOT(opendir, "opendir");
        MISS_SLOT(readdir, "readdir");
        MISS_SLOT(closedir, "closedir");
        MISS_SLOT(getxattr, "getxattr");
        MISS_SLOT(setxattr, "setxattr");
        MISS_CAP(XROOTD_SD_CAP_RANGE_READ, "RANGE_READ");
        MISS_CAP(XROOTD_SD_CAP_RANDOM_WRITE, "RANDOM_WRITE");
        MISS_CAP(XROOTD_SD_CAP_DIRS, "DIRS");
        MISS_CAP(XROOTD_SD_CAP_XATTR, "XATTR");
        break;

    case XROOTD_TIER_STAGE:
        MISS_SLOT(staged_open, "staged_open");
        MISS_SLOT(staged_write, "staged_write");
        MISS_SLOT(staged_commit, "staged_commit");
        MISS_SLOT(staged_abort, "staged_abort");
        MISS_SLOT(open, "open");
        MISS_SLOT(pread, "pread");
        MISS_SLOT(unlink, "unlink");
        MISS_SLOT(getxattr, "getxattr");
        MISS_SLOT(setxattr, "setxattr");
        MISS_CAP(XROOTD_SD_CAP_RANDOM_WRITE, "RANDOM_WRITE");
        MISS_CAP(XROOTD_SD_CAP_XATTR, "XATTR");
        break;
    }

#undef MISS_SLOT
#undef MISS_CAP

    if (gap_out != NULL) {
        ngx_memzero(gap_out, sizeof(*gap_out));   /* READY: no gap */
    }
    return XROOTD_TIER_READY;
}
