/*
 * space_group_conf.c — parser + lookups for `brix_oss_space` (phase-115 W3.3).
 *
 * WHAT: validates one `brix_oss_space <group> <prefix> [quota=...]` line into
 *       the server's brix_oss_space_t table and answers the two lookups the
 *       write gate, kXR_Qspace and kXR_open use (by path, by name).
 *
 * WHY:  a group name reaches the wire verbatim and a prefix is compared to
 *       confined logical paths, so both are pinned at parse time: a name that
 *       could smuggle a second oss.* key, a prefix with dot segments (it could
 *       never match a canonical path, so the quota would silently never
 *       apply) or a duplicate name/prefix fails `nginx -t` instead of
 *       mis-accounting at runtime.
 *
 * HOW:  pure functions over ngx_str_t; the setter appends to an ngx_array_t
 *       created lazily in the config pool. Lookups are linear (tables are a
 *       handful of VOs); longest prefix wins so nested groups nest naturally.
 */
#include "space_group_conf.h"
#include "core/ngx_brix_module.h"   /* ngx_stream_brix_srv_conf_t.oss_spaces */

int
brix_oss_space_name_ok(const ngx_str_t *name)
{
    size_t i;

    if (name->len == 0) {
        return 0;
    }
    for (i = 0; i < name->len; i++) {
        u_char ch = name->data[i];

        if (ch == '&' || ch == '=' || ch == ' ' || ch < 0x20 || ch == 0x7f) {
            return 0;
        }
    }
    return 1;
}

/* One export-relative path segment [seg, seg+n): non-empty, not "." / "..". */
static int
space_prefix_segment_ok(const u_char *seg, size_t n)
{
    if (n == 0) {
        return 0;                                          /* "//" */
    }
    if (seg[0] != '.') {
        return 1;
    }
    return !(n == 1 || (n == 2 && seg[1] == '.'));
}

/* An absolute, normalised prefix: leading '/', every segment well formed, no
 * trailing '/'. The bare root "/" is refused on purpose: that is the
 * export-wide default group, spelled brix_oss_cgroup + brix_oss_quota. */
static int
space_prefix_ok(const ngx_str_t *p)
{
    size_t i, seg;

    if (p->len < 2 || p->data[0] != '/' || p->data[p->len - 1] == '/') {
        return 0;
    }
    for (i = 1, seg = 1; i <= p->len; i++) {
        if (i < p->len && p->data[i] != '/') {
            continue;
        }
        if (!space_prefix_segment_ok(p->data + seg, i - seg)) {
            return 0;
        }
        seg = i + 1;
    }
    return 1;
}

static char *
space_parse_quota(ngx_conf_t *cf, const ngx_str_t *arg, off_t *quota)
{
    ngx_str_t v;

    if (arg->len < 6 || ngx_strncmp(arg->data, "quota=", 6) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oss_space: \"%V\": expected quota=<size> or quota=-1", arg);
        return NGX_CONF_ERROR;
    }
    v.data = arg->data + 6;
    v.len  = arg->len - 6;
    if (v.len == 2 && v.data[0] == '-' && v.data[1] == '1') {
        *quota = -1;
        return NGX_CONF_OK;
    }
    *quota = ngx_parse_offset(&v);
    if (*quota == (off_t) NGX_ERROR || *quota < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oss_space: quota \"%V\" is not a non-negative size or -1", &v);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
space_check_unique(ngx_conf_t *cf, const ngx_array_t *spaces,
    const ngx_str_t *name, const ngx_str_t *prefix)
{
    const brix_oss_space_t *dup;

    if (brix_oss_space_by_name(spaces, name->data, name->len) != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oss_space: group \"%V\" is declared twice", name);
        return NGX_CONF_ERROR;
    }
    dup = brix_oss_space_for_path(spaces, (const char *) prefix->data,
                                  prefix->len);
    if (dup != NULL && dup->prefix.len == prefix->len) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oss_space: prefix \"%V\" already belongs to group \"%V\"",
            prefix, &dup->name);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

char *
brix_conf_set_oss_space(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf   = conf;
    ngx_str_t                  *value = cf->args->elts;
    brix_oss_space_t           *g;
    off_t                       quota = -1;

    (void) cmd;

    if (!brix_oss_space_name_ok(&value[1])) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oss_space: group name \"%V\" is empty or carries a byte that "
            "would break the oss.* CGI report grammar (no & = space or "
            "control chars)", &value[1]);
        return NGX_CONF_ERROR;
    }
    if (!space_prefix_ok(&value[2])) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_oss_space: prefix \"%V\" must be an absolute export-relative "
            "path with no empty or dot segments and no trailing slash (the "
            "export root itself is the default group: brix_oss_cgroup / "
            "brix_oss_quota)", &value[2]);
        return NGX_CONF_ERROR;
    }
    if (cf->args->nelts == 4
        && space_parse_quota(cf, &value[3], &quota) != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    if (xcf->oss_spaces == NULL) {
        xcf->oss_spaces = ngx_array_create(cf->pool, 4,
                                           sizeof(brix_oss_space_t));
        if (xcf->oss_spaces == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    if (space_check_unique(cf, xcf->oss_spaces, &value[1], &value[2])
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    g = ngx_array_push(xcf->oss_spaces);
    if (g == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(g, sizeof(*g));
    g->name   = value[1];
    g->prefix = value[2];
    g->quota  = quota;
    return NGX_CONF_OK;
}

brix_oss_space_t *
brix_oss_space_for_path(const ngx_array_t *spaces, const char *logical,
    size_t len)
{
    brix_oss_space_t *g, *best = NULL;
    ngx_uint_t        i;

    if (spaces == NULL || logical == NULL) {
        return NULL;
    }
    g = spaces->elts;
    for (i = 0; i < spaces->nelts; i++) {
        size_t pl = g[i].prefix.len;

        if (len < pl || ngx_memcmp(logical, g[i].prefix.data, pl) != 0) {
            continue;
        }
        if (len > pl && logical[pl] != '/') {
            continue;                       /* "/atlasdata" is not "/atlas" */
        }
        if (best == NULL || pl > best->prefix.len) {
            best = &g[i];
        }
    }
    return best;
}

brix_oss_space_t *
brix_oss_space_by_name(const ngx_array_t *spaces, const u_char *name,
    size_t len)
{
    brix_oss_space_t *g;
    ngx_uint_t        i;

    if (spaces == NULL || name == NULL) {
        return NULL;
    }
    g = spaces->elts;
    for (i = 0; i < spaces->nelts; i++) {
        if (g[i].name.len == len && ngx_memcmp(g[i].name.data, name, len) == 0) {
            return &g[i];
        }
    }
    return NULL;
}
