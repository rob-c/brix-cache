/*
 * manager_map.c — the `brix_manager_map` directive (CMS manager mode).
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include "core/compat/cstr.h"

/* ---- Store a copied, NUL-terminated host into a manager-map entry ----
 *
 * WHAT: Allocates hostlen+1 bytes from cf->pool, copies hostlen bytes from
 * src, NUL-terminates, and records the length in entry->host.  Returns NGX_OK
 * on success, or NGX_ERROR if the pool allocation fails (no log emitted — the
 * historical behaviour returns the error silently).
 *
 * WHY: Both endpoint forms (IPv6 literal and host:port) extract a host
 * substring of differing bounds but store it identically; factoring the copy
 * keeps that storage step in one place with no behavioural drift.
 *
 * HOW:
 *   1. ngx_pnalloc(hostlen + 1); on NULL return NGX_ERROR.
 *   2. ngx_memcpy hostlen bytes from src and write a trailing NUL.
 *   3. Set entry->host.len = hostlen and return NGX_OK.
 */
static ngx_int_t
brix_manager_map_store_host(ngx_conf_t *cf, brix_manager_map_t *entry,
    const char *src, size_t hostlen)
{
    entry->host.data = ngx_pnalloc(cf->pool, hostlen + 1);
    if (entry->host.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(entry->host.data, src, hostlen);
    entry->host.data[hostlen] = '\0';
    entry->host.len = hostlen;
    return NGX_OK;
}

/* ---- Parse and validate a decimal port string into entry->port ----
 *
 * WHAT: Parses port_str as base-10 into a port number, requiring a fully
 * consumed string and a value in 1..65535.  On success stores the value in
 * *out_port and returns NGX_OK; on any parse/range failure emits the emerg
 * "invalid port" diagnostic (naming the original directive argument arg) and
 * returns NGX_ERROR.
 *
 * WHY: The two endpoint forms both terminate in a colon-delimited port with
 * identical validation and identical error text; one helper guarantees the
 * bounds check and message stay identical across both branches.
 *
 * HOW:
 *   1. strtol(port_str, &endp, 10).
 *   2. Reject trailing garbage (*endp != '\0'), non-positive, or > 65535.
 *   3. On rejection, emerg-log against arg and return NGX_ERROR.
 *   4. Otherwise cast to uint16_t, store in *out_port, return NGX_OK.
 */
static ngx_int_t
brix_manager_map_parse_port(ngx_conf_t *cf, const char *port_str,
    ngx_str_t *arg, uint16_t *out_port)
{
    char *endp;
    long  pnum;

    pnum = strtol(port_str, &endp, 10);
    if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_manager_map: invalid port in \"%V\"", arg);
        return NGX_ERROR;
    }
    *out_port = (uint16_t) pnum;
    return NGX_OK;
}

/* ---- Parse an IPv6-literal endpoint [addr]:port into a map entry ----
 *
 * WHAT: Parses the bracketed IPv6 literal form (addr_copy[0] == '['), storing
 * the bracket-enclosed host and the trailing port into entry.  Returns NGX_OK
 * on success, or NGX_ERROR (emerg-logged for malformed bracket/port; silent
 * for allocation failure) naming arg in diagnostics.
 *
 * WHY: The IPv6 grammar differs from the plain host:port grammar — it splits
 * on the closing bracket and requires a ':' immediately after it — so it needs
 * its own bounds computation before reusing the shared host/port storage.
 *
 * HOW:
 *   1. Locate ']' with strchr; reject a missing/empty ("[]") host.
 *   2. Require the byte after ']' to be ':', else "missing port".
 *   3. host = bytes between '[' and ']'; store via store_host.
 *   4. Parse the port starting two bytes past ']' (skip "]:").
 */
static ngx_int_t
brix_manager_map_parse_ipv6(ngx_conf_t *cf, brix_manager_map_t *entry,
    char *addr_copy, ngx_str_t *arg)
{
    char  *rb;
    size_t hostlen;

    rb = strchr(addr_copy, ']');
    if (rb == NULL || rb == addr_copy) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_manager_map: invalid IPv6 host \"%V\"", arg);
        return NGX_ERROR;
    }
    if (*(rb + 1) != ':') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_manager_map: missing port in \"%V\"", arg);
        return NGX_ERROR;
    }

    hostlen = (size_t) (rb - addr_copy - 1);
    if (brix_manager_map_store_host(cf, entry, addr_copy + 1, hostlen)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return brix_manager_map_parse_port(cf, rb + 2, arg, &entry->port);
}

/* ---- Parse an IPv4/hostname endpoint host:port into a map entry ----
 *
 * WHAT: Parses the unbracketed host:port form, splitting on the LAST colon so
 * bare IPv4 or hostnames parse correctly, and stores host/port into entry.
 * Returns NGX_OK on success, or NGX_ERROR (emerg-logged for a missing port;
 * silent for allocation failure) naming arg in diagnostics.
 *
 * WHY: Splitting on the final colon is what distinguishes this from the IPv6
 * form and keeps a hostname containing no colon (plus its port) unambiguous;
 * it must not be confused with the bracketed grammar.
 *
 * HOW:
 *   1. strrchr for the last ':'; reject its absence as "missing port".
 *   2. host = bytes before that colon; store via store_host.
 *   3. Parse the port from the byte after the colon.
 */
static ngx_int_t
brix_manager_map_parse_hostport(ngx_conf_t *cf, brix_manager_map_t *entry,
    char *addr_copy, ngx_str_t *arg)
{
    char  *colon;
    size_t hostlen;

    colon = strrchr(addr_copy, ':');
    if (colon == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_manager_map: missing port in \"%V\"", arg);
        return NGX_ERROR;
    }

    hostlen = (size_t) (colon - addr_copy);
    if (brix_manager_map_store_host(cf, entry, addr_copy, hostlen) != NGX_OK) {
        return NGX_ERROR;
    }

    return brix_manager_map_parse_port(cf, colon + 1, arg, &entry->port);
}

/* ---- Dispatch endpoint parsing by literal form ----
 *
 * WHAT: Selects the bracketed IPv6 parser when addr_copy begins with '[',
 * otherwise the host:port parser, populating entry->host and entry->port.
 * Returns the chosen parser's NGX_OK/NGX_ERROR.
 *
 * WHY: Isolating the one-byte form discriminator keeps the orchestrator flat
 * and the two grammars in separate, independently reviewable helpers.
 *
 * HOW:
 *   1. If addr_copy[0] == '[', delegate to the IPv6 parser.
 *   2. Otherwise delegate to the host:port parser.
 */
static ngx_int_t
brix_manager_map_parse_endpoint(ngx_conf_t *cf, brix_manager_map_t *entry,
    char *addr_copy, ngx_str_t *arg)
{
    if (addr_copy[0] == '[') {
        return brix_manager_map_parse_ipv6(cf, entry, addr_copy, arg);
    }
    return brix_manager_map_parse_hostport(cf, entry, addr_copy, arg);
}

/* ---- Append one prefix->endpoint entry to xcf->manager_map ----
 *
 * WHAT: Lazily creates xcf->manager_map, pushes a zeroed entry, normalises the
 * prefix (policy conventions), parses the endpoint (IPv4/hostname or
 * [IPv6]:port, port 1..65535), and logs a NOTICE.  Returns NGX_CONF_OK, or
 * NGX_CONF_ERROR (emerg-logged for user-facing failures) on any error.
 *
 * WHY: This is the `brix_manager_map <prefix> <host:port>` directive handler
 * for CMS manager mode; the endpoint parsing is delegated to helpers so this
 * stays a flat early-return orchestrator.
 *
 * HOW:
 *   1. Ensure the array exists; push and zero a fresh entry.
 *   2. Normalise value[1] into entry->prefix.
 *   3. Copy value[2] into a NUL-terminated buffer for parsing.
 *   4. Parse the endpoint into entry->host/entry->port.
 *   5. Log the configured mapping and return NGX_CONF_OK.
 */
char *
brix_conf_set_manager_map(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                  *value;
    brix_manager_map_t         *entry;
    char                       *addr_copy;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->manager_map == NULL) {
        xcf->manager_map = ngx_array_create(cf->pool, 2,
                                           sizeof(brix_manager_map_t));
        if (xcf->manager_map == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    entry = ngx_array_push(xcf->manager_map);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(entry, sizeof(*entry));

    /* Normalize and store the prefix path (policy-style) */
    if (brix_normalize_policy_path(cf->pool, &value[1], &entry->prefix) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_manager_map: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    /* Copy the host:port argument into a NUL-terminated buffer for parsing. */
    addr_copy = brix_pstrdup_z(cf->pool, &value[2]);
    if (addr_copy == NULL) {
        return NGX_CONF_ERROR;
    }

    if (brix_manager_map_parse_endpoint(cf, entry, addr_copy, &value[2])
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: manager_map configured: prefix=%s backend=%s:%d",
        (char *) entry->prefix.data, (char *) entry->host.data, (int) entry->port);

    return NGX_CONF_OK;
}
