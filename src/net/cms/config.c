/* WHAT: Parses "brix_cms_manager host:port [host:port ...]" (repeatable) and */
/*       stores every resolved address so the heartbeat client can log into ALL */
/*       redundant CMS managers concurrently (stock ManList parity). */
/* WHY:  The CMS heartbeat subsystem needs the full redundant manager set: each */
/*       endpoint gets its own login + heartbeat link and locate requests rotate */
/*       across the live links, so one dead manager no longer stalls discovery. */

#include "core/config/config.h"
#include "core/compat/alloc_guard.h"

/* cms_manager_add — resolve ONE host:port argument and append it to the
 * managers array.  Returns an nginx conf-parse verdict string. */
static char *
cms_manager_add(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf,
    ngx_str_t *value)
{
    ngx_url_t                url;
    ngx_addr_t              *addr;
    ngx_uint_t               i;
    brix_cms_manager_ent_t  *ent, *ents;

    if (xcf->cms.managers->nelts >= NGX_BRIX_CMS_MAX_MANAGERS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cms_manager: more than %d managers", NGX_BRIX_CMS_MAX_MANAGERS);
        return NGX_CONF_ERROR;
    }

    ent = ngx_array_push(xcf->cms.managers);
    if (ent == NULL) {
        return NGX_CONF_ERROR;
    }

    if (brix_copy_conf_string(cf, value, &ent->raw) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&url, sizeof(url));
    url.url = ent->raw;
    url.default_port = 0;

    if (ngx_parse_url(cf->pool, &url) != NGX_OK) {
        if (url.err != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cms_manager: %s in \"%V\"", url.err, value);
        }
        return NGX_CONF_ERROR;
    }

    if (url.no_port) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cms_manager: missing port in \"%V\"", value);
        return NGX_CONF_ERROR;
    }

    if (url.naddrs == 0 || url.addrs == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cms_manager: could not resolve \"%V\"", value);
        return NGX_CONF_ERROR;
    }

    if (ngx_inet_get_port(url.addrs[0].sockaddr) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cms_manager: invalid port in \"%V\"", value);
        return NGX_CONF_ERROR;
    }

    /* Reject the same resolved endpoint twice: a duplicate would double-login
     * (a stock manager 30s-blacklists the second identity) and skew rotation. */
    ents = xcf->cms.managers->elts;
    for (i = 0; i + 1 < xcf->cms.managers->nelts; i++) {
        if (ents[i].addr->socklen == url.addrs[0].socklen
            && ngx_memcmp(ents[i].addr->sockaddr, url.addrs[0].sockaddr,
                          url.addrs[0].socklen) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cms_manager: duplicate manager \"%V\"", value);
            return NGX_CONF_ERROR;
        }
    }

    BRIX_PCALLOC_OR_RETURN(addr, cf->pool, sizeof(ngx_addr_t), NGX_CONF_ERROR);

    addr->sockaddr = ngx_pnalloc(cf->pool, url.addrs[0].socklen);
    if (addr->sockaddr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(addr->sockaddr, url.addrs[0].sockaddr, url.addrs[0].socklen);
    addr->socklen = url.addrs[0].socklen;
    addr->name = url.addrs[0].name;
    ent->addr = addr;

    return NGX_CONF_OK;
}

char *
brix_conf_set_cms_manager(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t  *xcf = conf;
    ngx_str_t                   *value;
    ngx_uint_t                   i;
    brix_cms_manager_ent_t      *ents;
    char                        *rc;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cms.managers == NULL) {
        xcf->cms.managers = ngx_array_create(cf->pool, 4,
                                             sizeof(brix_cms_manager_ent_t));
        if (xcf->cms.managers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        rc = cms_manager_add(cf, xcf, &value[i]);
        if (rc != NGX_CONF_OK) {
            return rc;
        }
    }

    /* First entry stays mirrored into manager/addr: those are the "has
     * upstream" gate and the role-log identity across the tree. */
    ents = xcf->cms.managers->elts;
    xcf->cms.manager = ents[0].raw;
    xcf->cms.addr = ents[0].addr;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: CMS manager configured: %V (%ui total)",
        &xcf->cms.manager, xcf->cms.managers->nelts);

    return NGX_CONF_OK;
}
