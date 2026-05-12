#include "../config/config.h"

#include <stdlib.h>
#include <string.h>

char *
xrootd_conf_set_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    char                         *addr_copy, *colon, *endp;
    long                          pnum;

    value = cf->args->elts;
    (void) cmd;

    addr_copy = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (addr_copy == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(addr_copy, value[1].data, value[1].len);
    addr_copy[value[1].len] = '\0';

    if (addr_copy[0] == '[') {
        /* IPv6 literal [addr]:port */
        char *rb = strchr(addr_copy, ']');
        if (rb == NULL || *(rb + 1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_upstream: invalid address \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(rb - addr_copy - 1);
        xcf->upstream_host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (xcf->upstream_host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(xcf->upstream_host.data, addr_copy + 1, hostlen);
        xcf->upstream_host.data[hostlen] = '\0';
        xcf->upstream_host.len = hostlen;
        pnum = strtol(rb + 2, &endp, 10);
    } else {
        /* hostname:port or IPv4:port - split on last colon */
        colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_upstream: missing port in \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(colon - addr_copy);
        xcf->upstream_host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (xcf->upstream_host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(xcf->upstream_host.data, addr_copy, hostlen);
        xcf->upstream_host.data[hostlen] = '\0';
        xcf->upstream_host.len = hostlen;
        pnum = strtol(colon + 1, &endp, 10);
    }

    if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_upstream: invalid port in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    xcf->upstream_port = (uint16_t) pnum;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: upstream redirector: %s:%d",
        (char *) xcf->upstream_host.data, (int) xcf->upstream_port);

    return NGX_CONF_OK;
}
