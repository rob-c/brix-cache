#include "core/config/config.h"

#include <stdlib.h>
#include <string.h>
#include "core/compat/alloc_guard.h"
#include "core/compat/str_dup.h"
#include "core/compat/cstr.h"

/* ---- Split an upstream address into host + validated port ----
 *
 * WHAT: Parses a null-terminated upstream address copy into its host and port
 *   components, supporting two formats: an IPv6 literal "[addr]:port" (detected
 *   by a leading '[', split on ']' then the following ':') or a
 *   "hostname:port" / "IPv4:port" form (split on the LAST ':' via strrchr).
 *   Duplicates the host bytes into xcf->upstream_host via brix_pstrdupz(), parses
 *   the port digits with strtol(), and validates 1 <= port <= 65535 with no
 *   trailing non-digit characters. On success writes the parsed port into
 *   *port_out and returns NGX_OK. On any malformed address, missing port, host
 *   allocation failure, or out-of-range port it logs an emerg-level message
 *   (referencing raw, the original directive token) and returns NGX_ERROR
 *   without touching *port_out.
 *
 * WHY: Upstream directives commonly use "[::1]:1094" for IPv6 loopback, which
 *   needs bracket-based splitting rather than a naive colon split; the strrchr
 *   split on the last colon keeps the non-IPv6 path tolerant of colons in the
 *   host portion. Isolating the parse+validate logic keeps the directive setter
 *   flat and makes the accept/reject decision independently reviewable. Port
 *   range 1-65535 rejects zero, negative, and above-range values so nginx never
 *   starts with an upstream address that would fail every connection.
 *
 * HOW:
 *   1. If the address begins with '[', locate the closing ']'; require it to be
 *      immediately followed by ':', else log "invalid address" and fail.
 *   2. Duplicate the bytes between '[' and ']' as the host; parse the port from
 *      two characters past ']' (skipping "]:").
 *   3. Otherwise locate the last ':'; if absent log "missing port" and fail.
 *   4. Duplicate the bytes before that ':' as the host; parse the port from one
 *      character past it.
 *   5. Reject a trailing non-digit (endp not at the terminator) or a port
 *      outside 1-65535 with an "invalid port" message.
 *   6. Store the port in *port_out and return NGX_OK.
 */
static ngx_int_t
brix_upstream_parse_host_port(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf,
    char *addr_copy, ngx_str_t *raw, long *port_out)
{
    char *endp;
    long  pnum;

    if (addr_copy[0] == '[') {
        /* IPv6 literal [addr]:port */
        char *rb = strchr(addr_copy, ']');
        if (rb == NULL || *(rb + 1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_upstream: invalid address \"%V\"", raw);
            return NGX_ERROR;
        }
        size_t hostlen = (size_t)(rb - addr_copy - 1);
        if (brix_pstrdupz(cf->pool, &xcf->upstream_host,
                            (u_char *) addr_copy + 1, hostlen) != NGX_OK) {
            return NGX_ERROR;
        }
        pnum = strtol(rb + 2, &endp, 10);
    } else {
        /* hostname:port or IPv4:port - split on last colon */
        char *colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_upstream: missing port in \"%V\"", raw);
            return NGX_ERROR;
        }
        size_t hostlen = (size_t)(colon - addr_copy);
        if (brix_pstrdupz(cf->pool, &xcf->upstream_host,
                            (u_char *) addr_copy, hostlen) != NGX_OK) {
            return NGX_ERROR;
        }
        pnum = strtol(colon + 1, &endp, 10);
    }

    if (*endp != '\0' || pnum <= 0 || pnum > BRIX_MAX_PORT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_upstream: invalid port in \"%V\"", raw);
        return NGX_ERROR;
    }

    *port_out = pnum;
    return NGX_OK;
}

/*
 * brix_upstream_preresolve — register the redirector as a runtime DNS target.
 *
 * WHAT: Hands "host:port" to the phase-116 target registry and publishes the
 *   registry-owned ngx_addr_t as xcf->upstream_addr.  An IP literal is final
 *   at once; a hostname stays socklen == 0 until the worker resolves it.
 * WHY: A redirector whose name does not resolve at `nginx -t` must not stop
 *   the server (I-DNS-1), and the answer must follow the visible resolv.conf
 *   for the process lifetime — including after the redirector moves.
 * HOW: brix_dns_target_register(); start.c reads the target round-robin via
 *   brix_dns_target_next() and never touches libc DNS on the event loop.
 */
static ngx_int_t
brix_upstream_preresolve(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
{
    ngx_str_t  host;

    host.data = xcf->upstream_host.data;
    host.len = ngx_strlen(xcf->upstream_host.data);
    xcf->upstream_dns = brix_dns_target_register(cf, "brix_upstream", &host,
                                                 (in_port_t) xcf->upstream_port,
                                                 BRIX_AF_AUTO, SOCK_STREAM,
                                                 &xcf->common.dns);
    if (xcf->upstream_dns == NULL) {
        return NGX_ERROR;
    }
    xcf->upstream_addr = &xcf->upstream_dns->addr;
    return NGX_OK;
}

/* ---- brix_upstream directive setter ----
 *
 * WHAT: nginx config-directive handler for the upstream redirector address. Copies
 *   the directive argument, splits and validates it into xcf->upstream_host and
 *   xcf->upstream_port, pre-resolves the host into xcf->upstream_addr, logs a
 *   notice confirming the configured target, and returns NGX_CONF_OK. Returns
 *   NGX_CONF_ERROR (with an emerg-level message already emitted) if the argument
 *   cannot be duplicated or fails host/port parsing.
 *
 * WHY: This is the single entry point nginx invokes when it encounters the
 *   directive. Configuration parsing runs once at startup with no concurrent
 *   access, so all allocations come from cf->pool and are freed with the config
 *   lifecycle. Delegating parse/validate and pre-resolution to helpers keeps this
 *   orchestrator a flat, reviewable sequence.
 *
 * HOW:
 *   1. Duplicate the directive value (value[1]) into a null-terminated copy;
 *      fail on allocation error.
 *   2. Parse and validate host + port via brix_upstream_parse_host_port(); fail
 *      if it rejects the address.
 *   3. Store the validated port, then pre-resolve the host address.
 *   4. Log the configured target at notice level and return NGX_CONF_OK.
 */
char *
brix_conf_set_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                  *value;
    char                       *addr_copy;
    long                        pnum = 0;

    value = cf->args->elts;
    (void) cmd;

    addr_copy = brix_pstrdup_z(cf->pool, &value[1]);
    if (addr_copy == NULL) {
        return NGX_CONF_ERROR;
    }

    if (brix_upstream_parse_host_port(cf, xcf, addr_copy, &value[1], &pnum)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    xcf->upstream_port = (uint16_t) pnum;

    /* phase-116: register the redirector as a runtime DNS target; request
     * handlers never call getaddrinfo() on the event-loop thread. */
    if (brix_upstream_preresolve(cf, xcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: upstream redirector: %s:%d",
        (char *) xcf->upstream_host.data, (int) xcf->upstream_port);

    return NGX_CONF_OK;
}
