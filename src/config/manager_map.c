/* ------------------------------------------------------------------ */
/* Section: CMS Manager Map Configuration                               */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the manager_map directive handler that configures CMS management mode backend mappings.
 *      Each entry associates a prefix path (policy-style normalization applied) with a host:port endpoint where a CMS
 *      server manages that namespace segment. Supports both IPv4/hostname and IPv6 literal [addr]:port formats with port
 *      range validation (1-65535).
 *
 * WHY: CMS management mode allows partitioning namespaces across multiple backend servers — each prefix maps to the
 *      CMS manager responsible for that path segment. Configuration parsing must handle IPv6 bracket literals carefully,
 *      validate port ranges, and normalize paths using policy conventions before storing in the manager_map array. */

/* ------------------------------------------------------------------ */
/* Section: Manager Map Directive Handler                               */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_conf_set_manager_map() parses the "manager_map" config directive creating a prefix→host:port mapping entry.
 *      The first argument is a prefix path (normalized via policy conventions); the second is a host:port endpoint. Creates
 *      or appends to the manager_map array, validates IPv6 bracket format and port range, stores normalized results in
 *      xcf->manager_map. Returns NGX_CONF_OK on success; NGX_CONF_ERROR with emerg-level log on any validation failure. */

/* ---- Function: xrootd_conf_set_manager_map() ----
 *
 * WHAT: Parses the "manager_map" config directive creating a prefix→host:port mapping entry for CMS management mode.
 *      First argument = prefix path (normalized via policy conventions); second = host:port endpoint. Creates or appends to
 *      manager_map array, validates IPv6 bracket format [addr]:port and port range 1-65535, stores normalized results in
 *      xcf->manager_map. Returns NGX_CONF_OK on success; NGX_CONF_ERROR with emerg-level log on any validation failure. */

/* ---- WHY: CMS management mode partitions namespaces across multiple backend servers — each prefix maps to the CMS manager
 *      responsible for that path segment. IPv6 literal handling requires bracket detection and parsing before colon split.
 *      Port validation prevents malformed endpoints from being stored in the registry. Path normalization ensures consistent
 *      policy-style prefixes across all entries. ---- */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include "../compat/alloc_guard.h"

char *
xrootd_conf_set_manager_map(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    xrootd_manager_map_t         *entry;
    char                         *addr_copy;
    char                         *endp;
    long                          pnum;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->manager_map == NULL) {
        xcf->manager_map = ngx_array_create(cf->pool, 2,
                                           sizeof(xrootd_manager_map_t));
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
    if (xrootd_normalize_policy_path(cf->pool, &value[1], &entry->prefix) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_manager_map: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    /* Copy the host:port argument into a NUL-terminated buffer for parsing. */
    XROOTD_PNALLOC_OR_RETURN(addr_copy, cf->pool, value[2].len + 1, NGX_CONF_ERROR);
    ngx_memcpy(addr_copy, value[2].data, value[2].len);
    addr_copy[value[2].len] = '\0';

    /* IPv6 literal form [addr]:port */
    if (addr_copy[0] == '[') {
        char *rb = strchr(addr_copy, ']');
        if (rb == NULL || rb == addr_copy) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_manager_map: invalid IPv6 host \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
        if (*(rb + 1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_manager_map: missing port in \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        size_t hostlen = (size_t) (rb - addr_copy - 1);
        entry->host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (entry->host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(entry->host.data, addr_copy + 1, hostlen);
        entry->host.data[hostlen] = '\0';
        entry->host.len = hostlen;

        pnum = strtol(rb + 2, &endp, 10);
        if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_manager_map: invalid port in \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
        entry->port = (uint16_t) pnum;

    } else {
        /* IPv4 or hostname form host:port - split on last colon. */
        char *colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_manager_map: missing port in \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        size_t hostlen = (size_t) (colon - addr_copy);
        entry->host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (entry->host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(entry->host.data, addr_copy, hostlen);
        entry->host.data[hostlen] = '\0';
        entry->host.len = hostlen;

        pnum = strtol(colon + 1, &endp, 10);
        if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_manager_map: invalid port in \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
        entry->port = (uint16_t) pnum;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: manager_map configured: prefix=%s backend=%s:%d",
        (char *) entry->prefix.data, (char *) entry->host.data, (int) entry->port);

    return NGX_CONF_OK;
}
