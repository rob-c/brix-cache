/*
 * src/config/addr_parse.h - Address parsing helper declaration.
 *
 * WHAT: Declares xrootd_parse_address() for parsing "host:port" style
 *       addresses with optional scheme prefixes.
 */

#ifndef XROOTD_ADDR_PARSE_H
#define XROOTD_ADDR_PARSE_H

#include <nginx.h>
#include <ngx_core.h>

/* Parse address string in "host:port" format with optional scheme prefix.
 * Supports "root://", "roots://", and "https://" prefixes.
 * Returns NGX_OK on success, NGX_ERROR on parse failure.
 */
ngx_int_t xrootd_parse_address(const char *addr_str, size_t addr_len,
                               char *host, size_t host_len,
                               int *port, int *enable_tls);

#endif /* XROOTD_ADDR_PARSE_H */
