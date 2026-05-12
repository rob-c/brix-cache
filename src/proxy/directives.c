/*
 * directives.c — nginx config directives for xrootd_proxy and xrootd_proxy_upstream.
 */

#include "proxy_internal.h"

#include <stdlib.h>
#include <string.h>

/*
 * Parse "host[:port]" from addr_copy into *host_out / *port_out.
 * addr_copy is NUL-terminated and may be modified (colon zeroing).
 * Returns NGX_CONF_ERROR on parse failure.
 */
static char *
proxy_parse_host_port(ngx_conf_t *cf, ngx_str_t *value,
                      char *addr_copy,
                      ngx_str_t *host_out, uint16_t *port_out)
{
    char  *colon, *endp;
    long   pnum;

    if (addr_copy[0] == '[') {
        /* IPv6 literal: [addr]:port */
        char  *rb = strchr(addr_copy, ']');
        size_t hostlen;

        if (rb == NULL || *(rb + 1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_proxy_upstream: invalid address \"%V\"", value);
            return NGX_CONF_ERROR;
        }
        hostlen = (size_t)(rb - addr_copy - 1);
        host_out->data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (host_out->data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(host_out->data, addr_copy + 1, hostlen);
        host_out->data[hostlen] = '\0';
        host_out->len = hostlen;
        pnum = strtol(rb + 2, &endp, 10);
    } else {
        /* IPv4 or hostname: host:port or host (default port) */
        colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            host_out->data = (u_char *) addr_copy;
            host_out->len  = value->len;
            *port_out      = 1094;
            return NGX_CONF_OK;
        }
        size_t hostlen = (size_t)(colon - addr_copy);
        host_out->data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (host_out->data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memcpy(host_out->data, addr_copy, hostlen);
        host_out->data[hostlen] = '\0';
        host_out->len = hostlen;
        pnum = strtol(colon + 1, &endp, 10);
    }

    if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_proxy_upstream: invalid port in \"%V\"", value);
        return NGX_CONF_ERROR;
    }
    *port_out = (uint16_t) pnum;
    return NGX_CONF_OK;
}

/*
 * xrootd_proxy_upstream "host:port" [auth-policy]
 *
 * Appends to conf->proxy_upstreams (round-robin pool).  The optional second
 * argument overrides the global xrootd_proxy_auth policy for this specific
 * upstream endpoint:
 *
 *   anonymous        — send no credentials to this upstream
 *   forward          — replay the client's bearer token
 *   sss              — build an SSS credential from conf->sss_keys[0]
 *   sss:<keyname>    — build an SSS credential from the named key
 *
 * When the auth argument is omitted the global conf->proxy_auth applies.
 * The directive may appear multiple times to register several backends.
 */
char *
xrootd_conf_set_proxy_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_stream_xrootd_srv_conf_t *conf = conf_ptr;
    ngx_str_t                    *value;
    char                         *addr_copy, *rc;
    ngx_str_t                     host;
    uint16_t                      port = 1094;
    xrootd_proxy_upstream_t      *entry;

    (void) cmd;

    value = cf->args->elts;

    addr_copy = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (addr_copy == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(addr_copy, value[1].data, value[1].len);
    addr_copy[value[1].len] = '\0';

    host.data = NULL;
    host.len  = 0;

    rc = proxy_parse_host_port(cf, &value[1], addr_copy, &host, &port);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    /* Append to the upstreams array (lazily created) */
    if (conf->proxy_upstreams == NULL) {
        conf->proxy_upstreams = ngx_array_create(cf->pool, 2,
                                    sizeof(xrootd_proxy_upstream_t));
        if (conf->proxy_upstreams == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    entry = ngx_array_push(conf->proxy_upstreams);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }
    entry->host            = host;
    entry->port            = port;
    entry->auth            = -1;   /* inherit global proxy_auth by default */
    entry->sss_keyname[0]  = '\0';

    /* Parse optional per-upstream auth policy argument */
    if (cf->args->nelts >= 3) {
        ngx_str_t *auth_arg = &value[2];

        if (auth_arg->len == 9
            && ngx_strncmp(auth_arg->data, "anonymous", 9) == 0)
        {
            entry->auth = XROOTD_PROXY_AUTH_ANONYMOUS;
        } else if (auth_arg->len == 7
                   && ngx_strncmp(auth_arg->data, "forward", 7) == 0)
        {
            entry->auth = XROOTD_PROXY_AUTH_FORWARD;
        } else if (auth_arg->len >= 3
                   && ngx_strncmp(auth_arg->data, "sss", 3) == 0)
        {
            entry->auth = XROOTD_PROXY_AUTH_SSS;
            /* Optional key name after colon: "sss" or "sss:<keyname>" */
            if (auth_arg->len > 4 && auth_arg->data[3] == ':') {
                size_t klen = auth_arg->len - 4;
                if (klen >= XROOTD_SSS_NAME_MAX) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "xrootd_proxy_upstream: sss key name too long");
                    return NGX_CONF_ERROR;
                }
                ngx_memcpy(entry->sss_keyname, auth_arg->data + 4, klen);
                entry->sss_keyname[klen] = '\0';
            }
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_proxy_upstream: invalid auth policy \"%V\"; "
                "use anonymous, forward, sss, or sss:<keyname>", auth_arg);
            return NGX_CONF_ERROR;
        }
    }

    /* Backward compat: first occurrence sets the legacy single-upstream fields */
    if (conf->proxy_host.len == 0) {
        conf->proxy_host = host;
        conf->proxy_port = (ngx_int_t) port;
    }

    return NGX_CONF_OK;
}

/*
 * xrootd_proxy_auth anonymous|forward|sss
 *
 * "anonymous" — upstream login uses no credentials (default).
 * "forward"   — forward the client's WLCG bearer token to upstream on kXR_authmore.
 * "sss"       — build an SSS credential from conf->sss_keys[0] when upstream
 *               requests SSS authentication via kXR_authmore.
 */
char *
xrootd_conf_set_proxy_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_stream_xrootd_srv_conf_t *conf = conf_ptr;
    ngx_str_t                    *value;

    (void) cmd;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "anonymous") == 0) {
        conf->proxy_auth = XROOTD_PROXY_AUTH_ANONYMOUS;
    } else if (ngx_strcmp(value[1].data, "forward") == 0) {
        conf->proxy_auth = XROOTD_PROXY_AUTH_FORWARD;
    } else if (ngx_strcmp(value[1].data, "sss") == 0) {
        conf->proxy_auth = XROOTD_PROXY_AUTH_SSS;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_proxy_auth: invalid value \"%V\"; "
            "use anonymous, forward, or sss", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
 * xrootd_proxy_path_rewrite "/strip-prefix" "/add-prefix"
 *
 * Strip the leading prefix from every outbound path-bearing opcode and
 * prepend add-prefix.  If a path does not start with strip-prefix it is
 * forwarded unchanged.
 */
char *
xrootd_conf_set_proxy_path_rewrite(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf_ptr)
{
    ngx_stream_xrootd_srv_conf_t *conf = conf_ptr;
    ngx_str_t                    *value;

    (void) cmd;

    value = cf->args->elts;

    conf->proxy_path_strip = value[1];
    conf->proxy_path_add   = value[2];

    return NGX_CONF_OK;
}
