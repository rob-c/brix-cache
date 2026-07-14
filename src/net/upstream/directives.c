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

    if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_upstream: invalid port in \"%V\"", raw);
        return NGX_ERROR;
    }

    *port_out = pnum;
    return NGX_OK;
}

/* ---- Pre-resolve the upstream host at configuration time ----
 *
 * WHAT: Attempts to resolve xcf->upstream_host:xcf->upstream_port once during
 *   config parsing and, on success, caches a copy of the first resolved
 *   ngx_addr_t (sockaddr bytes, socklen, name) in xcf->upstream_addr. Resolution
 *   or allocation failure is non-fatal: it leaves xcf->upstream_addr NULL and
 *   emits a warn-level message. Returns nothing.
 *
 * WHY: Resolving the upstream once at startup keeps request handlers off
 *   getaddrinfo() on the event-loop thread; start.c falls back to a per-request
 *   lookup only when upstream_addr is NULL, so a failed pre-resolve must degrade
 *   gracefully rather than abort startup.
 *
 * HOW:
 *   1. Format "host:port" into a stack buffer and populate an ngx_url_t.
 *   2. Call ngx_parse_url(); require success with at least one non-NULL address.
 *   3. Allocate an ngx_addr_t and a copy of the first sockaddr from cf->pool;
 *      copy sockaddr bytes, socklen, and name, then publish it as upstream_addr.
 *   4. If upstream_addr remains NULL (parse or allocation failed), log a
 *      warn-level "could not pre-resolve" notice.
 */
static void
brix_upstream_preresolve(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *xcf)
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

    /*
     * Resolve the upstream hostname once at configuration time so that
     * request handlers never call getaddrinfo() on the event-loop thread.
     * Resolution failure is non-fatal: start.c falls back to per-request
     * getaddrinfo() when upstream_addr is NULL.
     */
    brix_upstream_preresolve(cf, xcf);

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: upstream redirector: %s:%d",
        (char *) xcf->upstream_host.data, (int) xcf->upstream_port);

    return NGX_CONF_OK;
}
