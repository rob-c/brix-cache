/*
 * etag.h — ETag string generation for HTTP responses.
 *
 * Shared between the WebDAV and S3 modules.  Pure C, no nginx headers.
 */

#ifndef BRIX_COMPAT_ETAG_H
#define BRIX_COMPAT_ETAG_H

#include <stddef.h>
#include <sys/types.h>
#include <time.h>

/* Pass BRIX_ETAG_WEAK to produce a RFC 7232 §2.1 weak ETag (W/"..."). */
#define BRIX_ETAG_WEAK  0x01u

/*
 * brix_http_etag_str — generate RFC 7232 ETag string from mtime + size.
 *
 * WHAT: Writes an ETag into buf formatted as "mtime-size" (strong) or W/"mtime-size" (weak).
 * WHY: HTTP conditional requests (If-None-Match/If-Match), PROPFIND ETag properties, S3 HEAD.
 * HOW: snprintf with conditional W/ prefix based on flags & BRIX_ETAG_WEAK. buf >= 48 bytes. */

void brix_http_etag_str(char *buf, size_t bufsz,
    time_t mtime, off_t size, unsigned flags);

#endif /* BRIX_COMPAT_ETAG_H */
