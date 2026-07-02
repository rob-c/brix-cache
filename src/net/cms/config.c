/* WHAT: Parses the nginx config line "xrootd_cms_manager host:port" and stores */
/*       the parsed address so the heartbeat client can connect to the CMS manager. */
/* WHY:  The CMS heartbeat subsystem needs a TCP endpoint to send periodic load/avail reports */
/*       and receive locate redirects from the central CMS manager node. */

#include "core/config/config.h"
#include "core/compat/alloc_guard.h"

char *
xrootd_conf_set_cms_manager(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    ngx_url_t                     url;
    ngx_addr_t                   *addr;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cms_addr != NULL) {
        return "is duplicate";
    }

    if (xrootd_copy_conf_string(cf, &value[1], &xcf->cms_manager)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&url, sizeof(url));
    url.url = xcf->cms_manager;
    url.default_port = 0;

    if (ngx_parse_url(cf->pool, &url) != NGX_OK) {
        if (url.err != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cms_manager: %s in \"%V\"", url.err, &value[1]);
        }
        return NGX_CONF_ERROR;
    }

    if (url.no_port) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cms_manager: missing port in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (url.naddrs == 0 || url.addrs == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cms_manager: could not resolve \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (ngx_inet_get_port(url.addrs[0].sockaddr) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cms_manager: invalid port in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    XROOTD_PCALLOC_OR_RETURN(addr, cf->pool, sizeof(ngx_addr_t), NGX_CONF_ERROR);

    addr->sockaddr = ngx_pnalloc(cf->pool, url.addrs[0].socklen);
    if (addr->sockaddr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(addr->sockaddr, url.addrs[0].sockaddr, url.addrs[0].socklen);
    addr->socklen = url.addrs[0].socklen;
    addr->name = url.addrs[0].name;
    xcf->cms_addr = addr;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: CMS manager configured: %V", &xcf->cms_manager);

    return NGX_CONF_OK;
}
