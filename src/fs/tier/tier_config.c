/*
 * tier_config.c - parse a store URL into a tier cfg, and report a tier's
 * readiness against its role contract (phase-64 section 4.2 / 2.2, Appendix L/F).
 *
 * brix_tier_parse_store turns "<scheme>:<location> [credential=][block_size=]"
 * into an brix_tier_cfg_t: scheme -> driver (root[s]->xroot, http[s]->http),
 * a local path confined via brix_prepare_export_root, or a remote //host[:port]
 * authority with a scheme default port. An unknown scheme / unknown credential /
 * missing port is an OPERATOR error ([emerg], fails nginx -t, Appendix F).
 *
 * brix_tier_status checks the built driver against the per-role slot+cap
 * contract (section 2.2): a missing slot/cap is a tracked "needs development"
 * (NEEDS_DEV + the closing sub-project), never a hard failure (P1).
 */
#include "tier.h"
#include "core/types/fs_list.h"
#include "core/config/root_prepare.h"   /* brix_prepare_export_root */

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
    /* GENERATED from the central filesystem declaration
     * (core/types/fs_list.h BRIX_FS_SCHEME_LIST) — add schemes there. */
#define S(scheme, driver, tls, nearline) { scheme, driver, tls, nearline },
    BRIX_FS_SCHEME_LIST(S)
#undef S
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
    /* phase72-fp: truncation of an operator-error message is acceptable */
    (void) vsnprintf(buf, sizeof(buf), fmt, ap);
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
tier_role_directive(brix_tier_role_t role)
{
    switch (role) {
    case BRIX_TIER_BACKEND: return "brix_storage_backend";
    case BRIX_TIER_CACHE:   return "brix_cache_store";
    case BRIX_TIER_STAGE:   return "brix_stage_store";
    }
    return "brix_store";
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
tier_sp_for(const char *driver, brix_tier_role_t role)
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

/* The parse context brix_tier_parse_t (config handle + cfg being built +
 * caller's error buffer) lives in tier.h — promoted from a file-local in
 * phase-73 so the extern brix_tier_parse_store takes the ONE context the
 * static helpers already thread. Filled by the caller, threaded down. */

/* Parse a port digit run into *portnum. WHY: the [v6]:port and host:port
 * branches share the exact same validation and operator error. HOW: ngx_atoi
 * + the 1..65535 range check; tier_fail on anything else. */
static ngx_int_t
tier_parse_port(brix_tier_parse_t *p, u_char *digits, size_t len, ngx_int_t *portnum)
{
    *portnum = ngx_atoi(digits, len);
    if (*portnum == NGX_ERROR || *portnum <= 0 || *portnum > 65535) {
        return tier_fail(p->cf, 1, p->err, p->errcap, "invalid store port");
    }
    return NGX_OK;
}

/* Parse a bracketed "[v6][:port]" authority into out->host/out->port.
 * WHY: IPv6 literals embed ':', so the bracket form gets its own scanner.
 * HOW: find ']', take the bracket interior as the host, parse an optional
 * ":port" suffix after the bracket. */
static ngx_int_t
tier_parse_host_v6(brix_tier_parse_t *p, u_char *authority, size_t authlen)
{
    brix_tier_cfg_t *out = p->out;
    u_char          *rb = NULL;
    size_t           i;
    size_t           hostlen;
    ngx_int_t        portnum = 0;

    for (i = 1; i < authlen; i++) {
        if (authority[i] == ']') { rb = authority + i; break; }
    }
    if (rb == NULL) {
        return tier_fail(p->cf, 1, p->err, p->errcap,
            "unbalanced \"[\" in store host");
    }
    hostlen = (size_t) (rb - (authority + 1));
    if (rb + 1 < authority + authlen && rb[1] == ':') {
        if (tier_parse_port(p, rb + 2,
                (size_t) (authority + authlen - (rb + 2)), &portnum) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    if (hostlen == 0 || hostlen >= sizeof(out->host)) {
        return tier_fail(p->cf, 1, p->err, p->errcap, "invalid store host");
    }
    ngx_memcpy(out->host, authority + 1, hostlen);
    out->host[hostlen] = '\0';
    out->port = (portnum > 0) ? (int) portnum : 0;
    return NGX_OK;
}

/* Parse a plain "host[:port]" authority into out->host/out->port.
 * WHY: the non-bracket form splits on the LAST ':' (matching the historical
 * scan direction); a trailing "host:" with no digits is accepted as port-less.
 * HOW: scan for the last colon, validate the port when digits follow it. */
static ngx_int_t
tier_parse_host_plain(brix_tier_parse_t *p, u_char *authority, size_t authlen)
{
    brix_tier_cfg_t *out = p->out;
    u_char          *colon = NULL;
    size_t           i;
    size_t           hostlen;
    ngx_int_t        portnum = 0;

    for (i = authlen; i > 0; i--) {
        if (authority[i - 1] == ':') { colon = authority + i - 1; break; }
    }
    if (colon != NULL && colon + 1 < authority + authlen) {
        hostlen = (size_t) (colon - authority);
        if (tier_parse_port(p, colon + 1,
                (size_t) (authority + authlen - (colon + 1)), &portnum) != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else if (colon != NULL) {
        hostlen = (size_t) (colon - authority);   /* "host:" trailing colon, no port */
    } else {
        hostlen = authlen;
    }
    if (hostlen == 0 || hostlen >= sizeof(out->host)) {
        return tier_fail(p->cf, 1, p->err, p->errcap, "invalid store host");
    }
    ngx_memcpy(out->host, authority, hostlen);
    out->host[hostlen] = '\0';
    out->port = (portnum > 0) ? (int) portnum : 0;
    return NGX_OK;
}

/* Copy the remainder after the authority into out->path.
 * WHY: "host://path" and "host//path" delimiter styles must land on ONE
 * canonical absolute path. HOW: collapse a leading "//" to one '/', bound the
 * length against out->path, copy + NUL-terminate. */
static ngx_int_t
tier_copy_remote_path(brix_tier_parse_t *p, u_char *path, size_t pathlen)
{
    brix_tier_cfg_t *out = p->out;

    /* Collapse a leading "//" (the "host://path" form) to one '/' so the path is a
     * single canonical absolute path regardless of host/path delimiter style. */
    while (pathlen >= 2 && path[0] == '/' && path[1] == '/') {
        path++;
        pathlen--;
    }

    if (pathlen >= sizeof(out->path)) {
        return tier_fail(p->cf, 1, p->err, p->errcap, "store path too long");
    }
    if (pathlen > 0) {
        ngx_memcpy(out->path, path, pathlen);
        out->path[pathlen] = '\0';
    }
    return NGX_OK;
}

/* Parse a remote "//host[:port][/path]" authority (IPv6-bracket aware) into
 * p->out. WHY: the remote grammar has three independent pieces — the "//"
 * marker, the host[:port] (bracketed or plain) and the trailing path — each
 * with its own operator errors. HOW: split the authority at the first '/',
 * dispatch on the '[' bracket form, then copy the path remainder. */
static ngx_int_t
tier_parse_authority(brix_tier_parse_t *p, u_char *loc, size_t loclen)
{
    u_char    *authority;
    u_char    *path;
    size_t     authlen;
    size_t     pathlen;
    size_t     i;
    ngx_int_t  rc;

    if (loclen < 2 || loc[0] != '/' || loc[1] != '/') {
        return tier_fail(p->cf, 1, p->err, p->errcap,
            "remote store needs \"//host\"");
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
        rc = tier_parse_host_v6(p, authority, authlen);
    } else {                                            /* host[:port] */
        rc = tier_parse_host_plain(p, authority, authlen);
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }
    return tier_copy_remote_path(p, path, pathlen);
}

/* Parse the trailing "credential=<n>" / "block_size=<n>" params. */
static ngx_int_t
tier_parse_args(ngx_conf_t *cf, ngx_array_t *args, brix_tier_cfg_t *out,
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
            const brix_credential_t *c;
            char   name[256];
            size_t nl = a[i].len - (sizeof(cred) - 1);

            if (nl == 0 || nl >= sizeof(name)) {
                return tier_fail(cf, 1, err, errcap, "invalid credential name");
            }
            ngx_memcpy(name, a[i].data + sizeof(cred) - 1, nl);
            name[nl] = '\0';
            c = brix_credential_lookup(name);
            if (c == NULL) {
                return tier_fail(cf, 1, err, errcap,
                    "no brix_credential \"%s\"", name);
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

/* Split "<scheme>:<location>" and resolve the scheme via tier_schemes.
 * WHY: the scheme is the ONLY driver selector; an unknown scheme is an
 * operator error (Appendix F). HOW: find the first ':', match the prefix
 * against the generated table, stamp driver/tls/nearline into p->out and
 * return the location remainder through loc/loclen. */
static ngx_int_t
tier_split_scheme(brix_tier_parse_t *p, ngx_str_t *url, u_char **loc, size_t *loclen)
{
    brix_tier_cfg_t *out = p->out;
    const char      *driver = NULL;
    size_t           schemelen;
    size_t           i;
    int              tls = 0;
    int              nearline = 0;

    for (i = 0; i < url->len; i++) {
        if (url->data[i] == ':') { break; }
    }
    if (i == 0 || i >= url->len) {
        return tier_fail(p->cf, 1, p->err, p->errcap,
            "store url \"%.*s\" has no scheme", (int) url->len, url->data);
    }
    schemelen = i;
    *loc      = url->data + i + 1;
    *loclen   = url->len - i - 1;

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
        return tier_fail(p->cf, 1, p->err, p->errcap,
            "unknown driver scheme \"%.*s\"", (int) schemelen, url->data);
    }
    ngx_cpystrn((u_char *) out->driver, (u_char *) driver, sizeof(out->driver));
    out->tls      = tls;
    out->nearline = (unsigned) nearline;
    return NGX_OK;
}

/* Resolve a LOCAL (posix/pblock) store location into a confined canonical
 * path. WHY: local stores must go through brix_prepare_export_root so the
 * store dir is validated/created exactly like an export root. HOW: wrap the
 * location in an ngx_str_t, build the per-role opts, canonicalize into
 * p->out->path. */
static ngx_int_t
tier_parse_local(brix_tier_parse_t *p, u_char *loc, size_t loclen)
{
    brix_tier_cfg_t         *out = p->out;
    brix_export_root_opts_t  opts;
    ngx_str_t                loc_str;
    char                     canon[PATH_MAX];

    loc_str.len  = loclen;
    loc_str.data = loc;
    ngx_memzero(&opts, sizeof(opts));
    opts.directive_name = tier_role_directive(out->role);
    opts.allow_write    = (out->role != BRIX_TIER_BACKEND) ? 1 : 0;
    opts.required       = 1;
    opts.canon_size     = sizeof(canon);

    if (brix_prepare_export_root(p->cf, &loc_str, &opts, canon) != NGX_CONF_OK) {
        /* prepare_export_root already emitted an [emerg]. */
        return tier_fail(p->cf, 0, p->err, p->errcap,
            "invalid local store path for %s", opts.directive_name);
    }
    if (ngx_strlen(canon) >= sizeof(out->path)) {
        return tier_fail(p->cf, 1, p->err, p->errcap,
            "local store path too long");
    }
    ngx_cpystrn((u_char *) out->path, (u_char *) canon, sizeof(out->path));
    return NGX_OK;
}

/* Resolve a REMOTE store location: authority parse + port defaulting.
 * WHY: TCP-carrying schemes (xroot/http/s3) MUST end up with a port — either
 * explicit or the scheme default; port-less schemes (rados pools, tape MSS)
 * legitimately stay at 0. HOW: parse the //host[:port][/path] authority,
 * apply tier_default_port, then reject a still-missing port for the TCP
 * drivers (url kept only for the operator error text). */
static ngx_int_t
tier_parse_remote(brix_tier_parse_t *p, ngx_str_t *url, u_char *loc, size_t loclen)
{
    brix_tier_cfg_t *out = p->out;

    if (tier_parse_authority(p, loc, loclen) != NGX_OK) {
        return NGX_ERROR;
    }
    if (out->port == 0) {
        out->port = tier_default_port(out->driver, out->tls);
    }
    if (out->port == 0
        && (ngx_strcmp(out->driver, "xroot") == 0
            || ngx_strcmp(out->driver, "http") == 0
            || ngx_strcmp(out->driver, "s3") == 0))
    {
        return tier_fail(p->cf, 1, p->err, p->errcap,
            "remote store \"%.*s\" is missing a port", (int) url->len,
            url->data);
    }
    return NGX_OK;
}

/* ---- public: parse a store URL -------------------------------------------- */

ngx_int_t
brix_tier_parse_store(brix_tier_parse_t *p, ngx_str_t *url, ngx_array_t *args,
    brix_tier_role_t role)
{
    brix_tier_cfg_t *out = p->out;
    u_char          *loc = NULL;
    size_t           loclen = 0;
    int              is_local;

    if (out == NULL || url == NULL || url->len == 0) {
        return tier_fail(p->cf, 1, p->err, p->errcap, "empty store url");
    }
    ngx_memzero(out, sizeof(*out));
    out->role = role;

    if (tier_split_scheme(p, url, &loc, &loclen) != NGX_OK) {
        return NGX_ERROR;
    }

    is_local = (ngx_strcmp(out->driver, "posix") == 0
                || ngx_strcmp(out->driver, "pblock") == 0);

    if (is_local) {
        if (tier_parse_local(p, loc, loclen) != NGX_OK) {
            return NGX_ERROR;
        }
    } else if (tier_parse_remote(p, url, loc, loclen) != NGX_OK) {
        return NGX_ERROR;
    }

    if (tier_parse_args(p->cf, args, out, p->err, p->errcap) != NGX_OK) {
        return NGX_ERROR;
    }

    out->configured = 1;
    return NGX_OK;
}

/* ---- public: report a tier's readiness ------------------------------------ */

brix_tier_status_t
brix_tier_status(const brix_tier_cfg_t *t, brix_sd_instance_t *probe,
    brix_tier_gap_t *gap_out)
{
    const brix_sd_driver_t *d;
    uint32_t                  caps;
    brix_tier_gap_t         g;

    ngx_memzero(&g, sizeof(g));

    if (t == NULL || probe == NULL || probe->driver == NULL) {
        ngx_cpystrn((u_char *) g.slot, (u_char *) "open", sizeof(g.slot));
        ngx_cpystrn((u_char *) g.sp_item, (u_char *) "SP1", sizeof(g.sp_item));
        if (gap_out != NULL) { *gap_out = g; }
        return BRIX_TIER_NEEDS_DEV;
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
            return BRIX_TIER_NEEDS_DEV;                                       \
        }                                                                      \
    } while (0)

#define MISS_CAP(bit, nm)                                                      \
    do {                                                                       \
        if ((caps & (bit)) == 0) {                                             \
            ngx_cpystrn((u_char *) g.cap, (u_char *) (nm), sizeof(g.cap));      \
            if (gap_out != NULL) { *gap_out = g; }                             \
            return BRIX_TIER_NEEDS_DEV;                                       \
        }                                                                      \
    } while (0)

    switch (t->role) {
    case BRIX_TIER_BACKEND:
        MISS_SLOT(open, "open");
        MISS_SLOT(pread, "pread");
        MISS_SLOT(stat, "stat");
        MISS_SLOT(fstat, "fstat");
        MISS_CAP(BRIX_SD_CAP_RANGE_READ, "RANGE_READ");
        if (t->nearline) {
            MISS_SLOT(recall, "recall");
            MISS_CAP(BRIX_SD_CAP_NEARLINE, "NEARLINE");
        }
        break;

    case BRIX_TIER_CACHE:
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
        MISS_CAP(BRIX_SD_CAP_RANGE_READ, "RANGE_READ");
        MISS_CAP(BRIX_SD_CAP_RANDOM_WRITE, "RANDOM_WRITE");
        MISS_CAP(BRIX_SD_CAP_DIRS, "DIRS");
        MISS_CAP(BRIX_SD_CAP_XATTR, "XATTR");
        break;

    case BRIX_TIER_STAGE:
        MISS_SLOT(staged_open, "staged_open");
        MISS_SLOT(staged_write, "staged_write");
        MISS_SLOT(staged_commit, "staged_commit");
        MISS_SLOT(staged_abort, "staged_abort");
        MISS_SLOT(open, "open");
        MISS_SLOT(pread, "pread");
        MISS_SLOT(unlink, "unlink");
        MISS_SLOT(getxattr, "getxattr");
        MISS_SLOT(setxattr, "setxattr");
        MISS_CAP(BRIX_SD_CAP_RANDOM_WRITE, "RANDOM_WRITE");
        MISS_CAP(BRIX_SD_CAP_XATTR, "XATTR");
        break;
    }

#undef MISS_SLOT
#undef MISS_CAP

    if (gap_out != NULL) {
        ngx_memzero(gap_out, sizeof(*gap_out));   /* READY: no gap */
    }
    return BRIX_TIER_READY;
}
