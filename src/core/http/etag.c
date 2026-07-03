/*
 * etag.c — ETag string generation shared by WebDAV and S3.
 *
 * WHAT: Generates RFC 7232-compliant ETag strings from resource mtime + size, with
 *       optional weak prefix (W/). Single function covering both strong and weak forms.
 *
 * WHY: HTTP conditional requests (If-None-Match / If-Match) compare resource ETags
 *      against client-held values. WebDAV PROPFIND returns ETag properties. S3 HEAD
 *      responses include ETag headers. All modules share this generator.
 *
 * HOW: snprintf("W/""%lx-%llx"" or ""%lx-%llx"" where %lx=mtime, %llx=size. Weak flag
 *      BRIX_ETAG_WEAK controls W/ prefix inclusion. Format matches xrootd XrdHttp
 *      convention for interoperability.
*/

#include "etag.h"

#include <stdio.h>

/*
 * brix_http_etag_str - generate RFC 7232-compliant ETag string from mtime and size.
 *
 * WHAT: Writes an ETag string into buf[0..bufsz-1] formatted as "mtime-size" (strong)
 *       or W/"mtime-size" (weak), using unsigned long for mtime, unsigned long long
 *       for size. Both use double-quote enclosure.
 *
 * WHY: RFC 7232 §2.3 requires ETags to be opaque validators that uniquely identify
 *      a resource version. This format (mtime + size) is the standard convention used
 *      by xrootd XrdHttp and nginx-xrootd for consistency across backends.
 *
 * HOW: snprintf with conditional W/ prefix based on flags & BRIX_ETAG_WEAK.
 */

void
brix_http_etag_str(char *buf, size_t bufsz,
    time_t mtime, off_t size, unsigned flags)
{
    if (flags & BRIX_ETAG_WEAK) {
        snprintf(buf, bufsz, "W/\"%lx-%llx\"",
                 (unsigned long) mtime, (unsigned long long) size);
    } else {
        snprintf(buf, bufsz, "\"%lx-%llx\"",
                 (unsigned long) mtime, (unsigned long long) size);
    }
}
