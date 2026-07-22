#include "config.h"
#include "postconfiguration_internal.h"

/*
 * E-2 (CWE-290): host-based auth (brix_host_allow) trusts the connection's
 * peer address. On a `listen ... proxy_protocol` socket that peer address is
 * whatever the immediate client claims in the PROXY header, so a spoofed
 * header would satisfy a host allowlist — unless a trusted-proxy allowlist
 * (set_real_ip_from, from the realip module) constrains who may send one.
 *
 * This build ships without the realip module, so no trusted-proxy allowlist
 * can be expressed and the combination is unconditionally unsafe. Refuse it at
 * config time (fail nginx -t) rather than serve a silently spoofable ACL.
 *
 * Walk every parsed listen address; for each with proxy_protocol set, resolve
 * the server blocks bound to it and reject if any carries a host allowlist.
 */
#if (nginx_version < 1025005)

/*
 * Pre-1.25.5 stream API (no virtual servers): cmcf->listen holds one
 * ngx_stream_listen_t per listen directive, each bound to exactly one server
 * via its conf ctx — walk that flat list instead of ports/addrs/servers.
 */
ngx_int_t
postconf_proxy_protocol_host_acl(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf)
{
    ngx_stream_listen_t          *ls;
    ngx_stream_brix_srv_conf_t   *xcf;
    ngx_uint_t                     i;

    ls = cmcf->listen.elts;
    for (i = 0; i < cmcf->listen.nelts; i++) {

        if (!ls[i].proxy_protocol) {
            continue;
        }

        xcf = ls[i].ctx->srv_conf[ngx_stream_brix_module.ctx_index];

        if (xcf->host_allow == NULL || xcf->host_allow->nelts == 0) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix: refusing insecure configuration — brix_host_allow "
            "on a \"listen %V proxy_protocol\" socket trusts the "
            "PROXY-header peer address, which the immediate client can "
            "forge; this build has no realip module, so no "
            "set_real_ip_from trusted-proxy allowlist can restrict it. "
            "Remove proxy_protocol from that listen, or drop "
            "brix_host_allow and authenticate another way",
            &ls[i].addr_text);
        return NGX_ERROR;
    }

    return NGX_OK;
}

#else

ngx_int_t
postconf_proxy_protocol_host_acl(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf)
{
    ngx_stream_conf_port_t       *port;
    ngx_stream_conf_addr_t       *addr;
    ngx_stream_core_srv_conf_t  **saddr;
    ngx_stream_brix_srv_conf_t   *xcf;
    ngx_uint_t                     p, a, s;

    if (cmcf->ports == NULL) {
        return NGX_OK;
    }

    port = cmcf->ports->elts;
    for (p = 0; p < cmcf->ports->nelts; p++) {

        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {

            if (!addr[a].opt.proxy_protocol) {
                continue;
            }

            saddr = addr[a].servers.elts;
            for (s = 0; s < addr[a].servers.nelts; s++) {

                xcf = ngx_stream_conf_get_module_srv_conf(saddr[s],
                                                          ngx_stream_brix_module);

                if (xcf->host_allow == NULL || xcf->host_allow->nelts == 0) {
                    continue;
                }

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "brix: refusing insecure configuration — brix_host_allow "
                    "on a \"listen %V proxy_protocol\" socket trusts the "
                    "PROXY-header peer address, which the immediate client can "
                    "forge; this build has no realip module, so no "
                    "set_real_ip_from trusted-proxy allowlist can restrict it. "
                    "Remove proxy_protocol from that listen, or drop "
                    "brix_host_allow and authenticate another way",
                    &addr[a].opt.addr_text);
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}

#endif /* nginx_version >= 1025005 */
