/*
 * module_acc_directives.c — shared XrdAcc HTTP directive setters.
 *
 * Moved out of module.c: these setters back the xrootd_acc_* HTTP directives,
 * a concern distinct from the command table + module object that remain there.
 * Each is registered once but populates BOTH the WebDAV and S3 loc-confs (see
 * the block comment below).  Public setters are declared in the matching .h.
 */
#include "webdav.h"
#include "auth/authz/acc/acc.h"   /* XrdAcc enum tables + xrootd_acc_http_t */
#include "protocols/s3/s3.h"     /* S3 loc-conf to populate alongside WebDAV */
#include "module_acc_directives.h"

/*
 * The XrdAcc directives are valid in any http location and must configure BOTH
 * the WebDAV and S3 loc-confs (an S3-only location still needs them), but nginx
 * applies just one module's setter per directive.  These shared setters fetch
 * both loc-confs and populate each, so the directive is registered only once.
 */
char *
xrootd_acc_http_set_authdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_webdav_loc_conf_t *wc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_webdav_module);
    ngx_http_s3_loc_conf_t            *sc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_s3_module);
    ngx_str_t *value = cf->args->elts;
    wc->acc.authdb = value[1];
    sc->acc.authdb = value[1];
    return NGX_CONF_OK;
}

static char *
xrootd_acc_http_set_enum(ngx_conf_t *cf, ngx_conf_enum_t *e, ngx_uint_t *wp,
    ngx_uint_t *sp)
{
    ngx_str_t *value = cf->args->elts;
    ngx_uint_t i;
    for (i = 0; e[i].name.len != 0; i++) {
        if (e[i].name.len == value[1].len
            && ngx_strcmp(e[i].name.data, value[1].data) == 0)
        {
            *wp = *sp = e[i].value;
            return NGX_CONF_OK;
        }
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}

char *
xrootd_acc_http_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_webdav_loc_conf_t *wc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_webdav_module);
    ngx_http_s3_loc_conf_t            *sc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_s3_module);
    return xrootd_acc_http_set_enum(cf, xrootd_acc_format_modes,
                                    &wc->acc.format, &sc->acc.format);
}

char *
xrootd_acc_http_set_audit(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_xrootd_webdav_loc_conf_t *wc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_webdav_module);
    ngx_http_s3_loc_conf_t            *sc =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_s3_module);
    return xrootd_acc_http_set_enum(cf, xrootd_acc_audit_modes,
                                    &wc->acc.audit, &sc->acc.audit);
}

/*
 * Shared scalar setters for the XrdAcc HTTP tunables — registered once but
 * populate BOTH loc-confs (see the authdb setters above for why).  Each grabs
 * the WebDAV + S3 acc blocks and applies the value to the same field in each.
 */
static char *
xrootd_acc_http_both(ngx_conf_t *cf, xrootd_acc_http_t **wc, xrootd_acc_http_t **sc)
{
    ngx_http_xrootd_webdav_loc_conf_t *w =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_webdav_module);
    ngx_http_s3_loc_conf_t            *s =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_xrootd_s3_module);
    *wc = &w->acc;
    *sc = &s->acc;
    return NULL;
}

char *
xrootd_acc_http_set_refresh(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;
    ngx_int_t          n;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid number \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }
    wc->refresh = sc->refresh = n;
    return NGX_CONF_OK;
}

char *
xrootd_acc_http_set_gidlifetime(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;
    ngx_int_t          n;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid number \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }
    wc->gidlifetime = sc->gidlifetime = n;
    return NGX_CONF_OK;
}

char *
xrootd_acc_http_set_nisdomain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    wc->nisdomain = sc->nisdomain = value[1];
    return NGX_CONF_OK;
}

static char *
xrootd_acc_http_set_flag(ngx_conf_t *cf, ngx_flag_t *wp, ngx_flag_t *sp,
    ngx_str_t *val)
{
    if (ngx_strcasecmp(val->data, (u_char *) "on") == 0) {
        *wp = *sp = 1;
    } else if (ngx_strcasecmp(val->data, (u_char *) "off") == 0) {
        *wp = *sp = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" (expected on|off)", val);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

char *
xrootd_acc_http_set_pgo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    return xrootd_acc_http_set_flag(cf, &wc->pgo, &sc->pgo, &value[1]);
}

char *
xrootd_acc_http_set_resolve_hosts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    return xrootd_acc_http_set_flag(cf, &wc->resolve_hosts, &sc->resolve_hosts,
                                    &value[1]);
}

char *
xrootd_acc_http_set_spacechar(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    wc->spacechar = sc->spacechar = value[1];
    return NGX_CONF_OK;
}

char *
xrootd_acc_http_set_encoding(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    return xrootd_acc_http_set_flag(cf, &wc->encoding, &sc->encoding, &value[1]);
}

char *
xrootd_acc_http_set_gidretran(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    xrootd_acc_http_t *wc, *sc;
    ngx_str_t         *value = cf->args->elts;

    (void) xrootd_acc_http_both(cf, &wc, &sc);
    wc->gidretran = sc->gidretran = value[1];
    return NGX_CONF_OK;
}
