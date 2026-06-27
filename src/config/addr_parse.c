/*
 * src/config/addr_parse.c - Address parsing helper for configuration directives.
 *
 * WHAT: Extracts address parsing logic (host:port with optional scheme prefix)
 *       into a reusable helper function. Consolidates similar code from
 *       cache/directives.c, tpc_config.c, and upstream/directives.c.
 *
 * WHY: Multiple directives parse "host:port" style addresses with optional
 *      "root://", "roots://", or "https://" prefixes. Each implementation
 *      was similar but slightly different, leading to code duplication and
 *      maintenance overhead. Centralizing the logic ensures consistency and
 *      eliminates the duplication.
 *
 * HOW: Single function xrootd_parse_address() handles all cases:
 *      - "host:port"         → host="host", port=port
 *      - "root://host:port"  → host="host", port=port
 *      - "roots://host:port" → host="host", port=port, enable_tls=1
 *      - "https://host:port" → host="host", port=port, enable_tls=1
 *      - "[IPv6]:port"       → host="IPv6", port=port
 */

#include "../ngx_xrootd_module.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* xrootd_parse_address - Parse host:port address with optional scheme
 * WHAT: Parse an address string in the form "host:port", "root://host:port",
 *       "roots://host:port", or "https://host:port". Extracts host and port
 *       into separate buffers. Can optionally set enable_tls flag based on scheme.
 *
 * ARGS:
 *   addr_str:   Input address string (NOT null-terminated; may be part of larger buffer)
 *   addr_len:   Length of addr_str in bytes
 *   host:       Output buffer for hostname (must be at least host_len bytes)
 *   host_len:   Size of host output buffer
 *   port:       Output integer pointer (will be set to parsed port number)
 *   enable_tls: Optional output flag (NULL to ignore). Set to 1 if scheme is roots:// or https://.
 *               Otherwise unchanged.
 *
 * RETURNS:
 *   NGX_OK on successful parse.
 *   NGX_ERROR if:
 *     - Input address is malformed (missing port, invalid port number, etc.)
 *     - Host exceeds host_len bytes
 *     - Port number is out of valid range (0-65535)
 *
 * NOTES:
 *   - Removes "root://", "roots://", or "https://" prefix if present
 *   - Sets *enable_tls = 1 if scheme is "roots://" or "https://"
 *   - Supports IPv6 addresses in bracket notation: "[::1]:9090"
 *   - Does NOT null-terminate host buffer; caller must do this if needed
 *     (host_len buffer should be host.len + 1 to allow null terminator)
 */
ngx_int_t
xrootd_parse_address(const char *addr_str, size_t addr_len,
                     char *host, size_t host_len,
                     int *port, int *enable_tls)
{
    const char *data = addr_str;
    size_t      len = addr_len;
    const char *host_start = data;
    const char *colon = NULL;
    const char *rb = NULL;
    size_t      hostlen = 0;
    long        pnum = 0;
    char       *endp = NULL;

    /* Remove scheme prefix if present */
    if (len > sizeof("root://") - 1
        && strncmp(data, "root://", sizeof("root://") - 1) == 0)
    {
        data += sizeof("root://") - 1;
        len  -= sizeof("root://") - 1;
    }
    else if (len > sizeof("roots://") - 1
             && strncmp(data, "roots://", sizeof("roots://") - 1) == 0)
    {
        data += sizeof("roots://") - 1;
        len  -= sizeof("roots://") - 1;
        if (enable_tls != NULL) {
            *enable_tls = 1;
        }
    }
    else if (len > sizeof("https://") - 1
             && strncmp(data, "https://", sizeof("https://") - 1) == 0)
    {
        data += sizeof("https://") - 1;
        len  -= sizeof("https://") - 1;
        if (enable_tls != NULL) {
            *enable_tls = 1;
        }
    }

    host_start = data;

    /* Parse IPv6 address in bracket notation */
    if (data[0] == '[') {
        rb = memchr(data, ']', len);
        if (rb == NULL || rb + 1 >= data + len || *(rb + 1) != ':') {
            return NGX_ERROR;  /* Invalid IPv6 format */
        }
        hostlen = (size_t)(rb - data - 1);
        if (hostlen >= host_len) {
            return NGX_ERROR;  /* Host buffer too small */
        }
        memcpy(host, data + 1, hostlen);
        pnum = strtol(rb + 2, &endp, 10);
    }
    else {
        /* Parse regular host:port */
        colon = memrchr(data, ':', len);
        if (colon == NULL) {
            return NGX_ERROR;  /* Missing port */
        }
        hostlen = (size_t)(colon - data);
        if (hostlen >= host_len) {
            return NGX_ERROR;  /* Host buffer too small */
        }
        memcpy(host, data, hostlen);
        pnum = strtol(colon + 1, &endp, 10);
    }

    /* Validate port number */
    if (pnum <= 0 || pnum > 65535) {
        return NGX_ERROR;  /* Invalid port number */
    }

    *port = (int)pnum;
    return NGX_OK;
}
