#include "core/config/config.h"

#include <stdlib.h>
#include <string.h>
#include "core/compat/alloc_guard.h"
#include "core/compat/str_dup.h"

/*
 *
 * WHAT: Parses nginx config directive value containing upstream server address into host+port components. Two supported formats: IPv6 literal [addr]:port (detected by leading '[' character, split on ']' then ':'), or hostname/IPv4:port (split on last ':' using strrchr). Allocates host string from request pool via ngx_pnalloc() with null-termination, extracts port number via strtol() parsing decimal digits after delimiter. Validates port range 1 ≤ pnum ≤ 65535 and rejects trailing non-digit characters in parsed string — returns NGX_CONF_ERROR with emerg-level log message on any validation failure. On success stores xcf->upstream_host (ngx_str_t) and xcf->upstream_port (uint16_t), logs notice-level entry confirming configuration. All memory allocated from cf->pool ensures proper cleanup during nginx request lifecycle. Returns NGX_CONF_OK only when both host parsing and port validation succeed.
 *
 * WHY: Upstream address parsing must support both IPv4/hostname and IPv6 literal formats — nginx config directives commonly use [::1]:1094 for IPv6 loopback addresses which require bracket-based splitting rather than colon-only splitting. The strrchr approach for non-IPv6 addresses splits on the LAST colon to handle hostnames containing colons (though uncommon in practice). Port validation range 1-65535 ensures only valid TCP port numbers are accepted — zero and negative values rejected immediately, values above 65535 caught by strtol endp check. Emerg-level logging on configuration errors prevents server startup with invalid upstream address that would cause connection failures for all requests. Thread safety: config parsing runs once during nginx startup; no concurrent access after initialization. */

char *
brix_conf_set_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    char                         *addr_copy, *colon, *endp;
    long                          pnum;

    value = cf->args->elts;
    (void) cmd;

    BRIX_PNALLOC_OR_RETURN(addr_copy, cf->pool, value[1].len + 1, NGX_CONF_ERROR);
    ngx_memcpy(addr_copy, value[1].data, value[1].len);
    addr_copy[value[1].len] = '\0';

    if (addr_copy[0] == '[') {
        /* IPv6 literal [addr]:port */
        char *rb = strchr(addr_copy, ']');
        if (rb == NULL || *(rb + 1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_upstream: invalid address \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(rb - addr_copy - 1);
        if (brix_pstrdupz(cf->pool, &xcf->upstream_host,
                            (u_char *) addr_copy + 1, hostlen) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        pnum = strtol(rb + 2, &endp, 10);
    } else {
        /* hostname:port or IPv4:port - split on last colon */
        colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_upstream: missing port in \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(colon - addr_copy);
        if (brix_pstrdupz(cf->pool, &xcf->upstream_host,
                            (u_char *) addr_copy, hostlen) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        pnum = strtol(colon + 1, &endp, 10);
    }

    if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_upstream: invalid port in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    xcf->upstream_port = (uint16_t) pnum;

    /*
     * Resolve the upstream hostname once at configuration time so that
     * request handlers never call getaddrinfo() on the event-loop thread.
     * Resolution failure is non-fatal: start.c falls back to per-request
     * getaddrinfo() when upstream_addr is NULL.
     */
    {
        ngx_url_t   url;
        ngx_addr_t *addr;
        char        hostport[NGX_SOCKADDR_STRLEN + 8];

        ngx_memzero(&url, sizeof(url));
        snprintf(hostport, sizeof(hostport), "%s:%d",
                 (char *) xcf->upstream_host.data, (int) xcf->upstream_port);
        url.url.data = (u_char *) hostport;
        url.url.len  = strlen(hostport);
        url.default_port = (in_port_t) xcf->upstream_port;

        if (ngx_parse_url(cf->pool, &url) == NGX_OK
            && url.naddrs > 0 && url.addrs != NULL)
        {
            addr = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
            if (addr != NULL) {
                addr->sockaddr = ngx_pnalloc(cf->pool, url.addrs[0].socklen);
                if (addr->sockaddr != NULL) {
                    ngx_memcpy(addr->sockaddr, url.addrs[0].sockaddr,
                               url.addrs[0].socklen);
                    addr->socklen = url.addrs[0].socklen;
                    addr->name    = url.addrs[0].name;
                    xcf->upstream_addr = addr;
                }
            }
        }

        if (xcf->upstream_addr == NULL) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "brix: upstream redirector: could not pre-resolve \"%s\""
                " — will resolve per-request (event-loop may block)",
                (char *) xcf->upstream_host.data);
        }
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: upstream redirector: %s:%d",
        (char *) xcf->upstream_host.data, (int) xcf->upstream_port);

    return NGX_CONF_OK;
}
