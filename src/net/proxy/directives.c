/*
 * directives.c — nginx config directives for brix_proxy and brix_proxy_upstream.
 *
 * WHAT: Parses and validates nginx configuration directives for proxy mode operation.
 *       Provides four directive handlers: brix_conf_set_proxy_upstream (register upstream endpoints),
 *       brix_conf_set_proxy_auth (set global auth policy), brix_conf_set_proxy_login_user
 *       (control username sent to upstream), and brix_conf_set_proxy_path_rewrite (strip/add path prefix).
 *       Also includes static helper proxy_parse_host_port for parsing host:port address strings.
 *
 * WHY: Proxy mode requires configurable upstream endpoints with per-endpoint auth policies,
 *      username passthrough/fixed/anonymous modes, and optional path rewriting for namespace mapping.
 *      These directives populate conf->proxy.upstreams array, conf->proxy.auth policy enum,
 *      conf->proxy.login_user mode, and strip/add prefix strings — all consumed by proxy forward
 *      handlers (forward_request.c, forward_relay.c). Backward compat: first upstream occurrence sets
 *      legacy single-upstream fields (proxy_host/proxy_port) for prior configuration style.
 *
 * HOW: Each directive handler reads cf->args->elts for parsed argument values. proxy_parse_host_port()
 *      handles IPv6 literal [addr]:port and IPv4/hostname host:port formats — zeroing colon delimiter,
 *      extracting host string via ngx_pnalloc, parsing port via strtol with 1-65535 range validation.
 *      brix_conf_set_proxy_upstream() appends to conf->proxy.upstreams array (lazily created), sets
 *      host/port/auth=-1 (inherit global default), parses optional third arg for per-upstream auth override.
 *      brix_conf_set_proxy_auth() maps value string to BRIX_PROXY_AUTH_* enum, logs EMERG on invalid.
 *      brix_conf_set_proxy_login_user() handles anonymous/passthrough/fixed:<name> (1-8 chars) modes.
 *      brix_conf_set_proxy_path_rewrite() copies two argument values to strip/add fields directly.
 */

#include "proxy_internal.h"

#include <stdlib.h>
#include <string.h>
#include "core/compat/alloc_guard.h"
#include "core/compat/cstr.h"

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
                "brix_proxy_upstream: invalid address \"%V\"", value);
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
            "brix_proxy_upstream: invalid port in \"%V\"", value);
        return NGX_CONF_ERROR;
    }
    *port_out = (uint16_t) pnum;
    return NGX_CONF_OK;
}

/* ---- Parse an optional per-upstream auth-policy argument into an entry ----
 *
 * WHAT: Maps auth_arg ("anonymous", "forward", "sss", or "sss:<keyname>") onto
 *       entry->auth (a BRIX_PROXY_AUTH_* value) and, for the keyed sss form,
 *       copies the key name into entry->sss_keyname. Returns NGX_CONF_OK on a
 *       recognised policy and NGX_CONF_ERROR (after logging EMERG) for an
 *       unknown policy or an over-long sss key name.
 *
 * WHY: brix_conf_set_proxy_upstream's optional third argument carries a small
 *      four-way policy grammar with its own nested validation. Confining it to a
 *      single helper keeps the directive handler a flat append-and-validate
 *      sequence and keeps this file's per-function cyclomatic complexity in
 *      bounds without changing any accepted/rejected input or field assignment.
 *
 * HOW: 1. Exact-length compare against "anonymous" (9) and "forward" (7).
 *      2. Prefix-match "sss" (>= 3); set BRIX_PROXY_AUTH_SSS.
 *      3. For the "sss:<keyname>" form (len > 4, data[3] == ':') validate the
 *         key length against BRIX_SSS_NAME_MAX, then copy and NUL-terminate it.
 *      4. Any other value is an error: log EMERG and return NGX_CONF_ERROR.
 */
static char *
proxy_parse_upstream_auth(ngx_conf_t *cf, ngx_str_t *auth_arg,
                          brix_proxy_upstream_t *entry)
{
    if (auth_arg->len == 9
        && ngx_strncmp(auth_arg->data, "anonymous", 9) == 0)
    {
        entry->auth = BRIX_PROXY_AUTH_ANONYMOUS;
        return NGX_CONF_OK;
    }

    if (auth_arg->len == 7
        && ngx_strncmp(auth_arg->data, "forward", 7) == 0)
    {
        entry->auth = BRIX_PROXY_AUTH_FORWARD;
        return NGX_CONF_OK;
    }

    if (auth_arg->len >= 3
        && ngx_strncmp(auth_arg->data, "sss", 3) == 0)
    {
        entry->auth = BRIX_PROXY_AUTH_SSS;
        /* Optional key name after colon: "sss" or "sss:<keyname>" */
        if (auth_arg->len > 4 && auth_arg->data[3] == ':') {
            size_t klen = auth_arg->len - 4;
            if (klen >= BRIX_SSS_NAME_MAX) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "brix_proxy_upstream: sss key name too long");
                return NGX_CONF_ERROR;
            }
            ngx_memcpy(entry->sss_keyname, auth_arg->data + 4, klen);
            entry->sss_keyname[klen] = '\0';
        }
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "brix_proxy_upstream: invalid auth policy \"%V\"; "
        "use anonymous, forward, sss, or sss:<keyname>", auth_arg);
    return NGX_CONF_ERROR;
}

/*
 * brix_proxy_upstream "host:port" [auth-policy]
 *
 * Appends to conf->proxy.upstreams (round-robin pool).  The optional second
 * argument overrides the global brix_proxy_auth policy for this specific
 * upstream endpoint:
 *
 *   anonymous        — send no credentials to this upstream
 *   forward          — replay the client's bearer token
 *   sss              — build an SSS credential from conf->sss_keys[0]
 *   sss:<keyname>    — build an SSS credential from the named key
 *
 * When the auth argument is omitted the global conf->proxy.auth applies.
 * The directive may appear multiple times to register several backends.
 */
char *
brix_conf_set_proxy_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_stream_brix_srv_conf_t *conf = conf_ptr;
    ngx_str_t                    *value;
    char                         *addr_copy, *rc;
    ngx_str_t                     host;
    uint16_t                      port = 1094;
    brix_proxy_upstream_t      *entry;

    (void) cmd;

    value = cf->args->elts;

    addr_copy = brix_pstrdup_z(cf->pool, &value[1]);
    if (addr_copy == NULL) {
        return NGX_CONF_ERROR;
    }

    host.data = NULL;
    host.len  = 0;

    rc = proxy_parse_host_port(cf, &value[1], addr_copy, &host, &port);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    /* Append to the upstreams array (lazily created) */
    if (conf->proxy.upstreams == NULL) {
        conf->proxy.upstreams = ngx_array_create(cf->pool, 2,
                                    sizeof(brix_proxy_upstream_t));
        if (conf->proxy.upstreams == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    entry = ngx_array_push(conf->proxy.upstreams);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }
    entry->host            = host;
    entry->port            = port;
    entry->auth            = -1;   /* inherit global proxy_auth by default */
    entry->sss_keyname[0]  = '\0';

    /* Parse optional per-upstream auth policy argument */
    if (cf->args->nelts >= 3) {
        rc = proxy_parse_upstream_auth(cf, &value[2], entry);
        if (rc != NGX_CONF_OK) {
            return rc;
        }
    }

    /* Backward compat: first occurrence sets the legacy single-upstream fields */
    if (conf->proxy.host.len == 0) {
        conf->proxy.host = host;
        conf->proxy.port = (ngx_int_t) port;
    }

    return NGX_CONF_OK;
}

/*
 * brix_proxy_auth anonymous|forward|sss
 *
 * "anonymous" — upstream login uses no credentials (default).
 * "forward"   — forward the client's WLCG bearer token to upstream on kXR_authmore.
 * "sss"       — build an SSS credential from conf->sss_keys[0] when upstream
 *               requests SSS authentication via kXR_authmore.
 */
char *
brix_conf_set_proxy_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr)
{
    ngx_stream_brix_srv_conf_t *conf = conf_ptr;
    ngx_str_t                    *value;

    (void) cmd;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "anonymous") == 0) {
        conf->proxy.auth = BRIX_PROXY_AUTH_ANONYMOUS;
    } else if (ngx_strcmp(value[1].data, "forward") == 0) {
        conf->proxy.auth = BRIX_PROXY_AUTH_FORWARD;
    } else if (ngx_strcmp(value[1].data, "sss") == 0) {
        conf->proxy.auth = BRIX_PROXY_AUTH_SSS;
    } else if (ngx_strcmp(value[1].data, "gsi") == 0) {
        conf->proxy.auth = BRIX_PROXY_AUTH_GSI;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_proxy_auth: invalid value \"%V\"; "
            "use anonymous, forward, sss, or gsi", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
 * brix_proxy_login_user anonymous|passthrough|fixed:<name>
 *
 * Controls the username placed in the upstream kXR_login frame:
 *
 *   anonymous     — always send "xrd" (default, preserves prior behaviour)
 *   passthrough   — copy the client's authenticated username (from kXR_login),
 *                   truncated to 8 bytes if necessary.  Falls back to "xrd" for
 *                   anonymous client sessions.
 *   fixed:<name>  — always send the literal <name> (1–8 characters)
 */
char *
brix_conf_set_proxy_login_user(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf_ptr)
{
    ngx_stream_brix_srv_conf_t *conf = conf_ptr;
    ngx_str_t                    *value;

    (void) cmd;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "anonymous") == 0) {
        conf->proxy.login_user = BRIX_PROXY_LOGIN_ANONYMOUS;

    } else if (ngx_strcmp(value[1].data, "passthrough") == 0) {
        conf->proxy.login_user = BRIX_PROXY_LOGIN_PASSTHROUGH;

    } else if (value[1].len >= 7
               && ngx_strncmp(value[1].data, "fixed:", 6) == 0)
    {
        size_t nlen = value[1].len - 6;
        if (nlen == 0 || nlen > 8) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_proxy_login_user: fixed name must be 1-8 characters");
            return NGX_CONF_ERROR;
        }
        conf->proxy.login_user = BRIX_PROXY_LOGIN_FIXED;
        ngx_memcpy(conf->proxy.login_user_name, value[1].data + 6, nlen);
        conf->proxy.login_user_name[nlen] = '\0';

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_proxy_login_user: invalid value \"%V\"; "
            "use anonymous, passthrough, or fixed:<name>", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
 * brix_proxy_path_rewrite "/strip-prefix" "/add-prefix"
 *
 * Strip the leading prefix from every outbound path-bearing opcode and
 * prepend add-prefix.  If a path does not start with strip-prefix it is
 * forwarded unchanged.
 */
char *
brix_conf_set_proxy_path_rewrite(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf_ptr)
{
    ngx_stream_brix_srv_conf_t *conf = conf_ptr;
    ngx_str_t                    *value;

    (void) cmd;

    value = cf->args->elts;

    conf->proxy.path_strip = value[1];
    conf->proxy.path_add   = value[2];

    return NGX_CONF_OK;
}
