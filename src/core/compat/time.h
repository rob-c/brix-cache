/*
 * time.h — UTC ISO8601 timestamp formatting for XRootD, WebDAV, and S3.
 *
 * Single function: brix_format_iso8601() converts a time_t to an ISO-8601 UTC string with
 * millisecond precision fixed at zero. Used in stat responses, access logs, S3 LastModified XML,
 * and HTTP Date headers. Always UTC via gmtime_r — no timezone ambiguity.
 */

#ifndef BRIX_COMPAT_TIME_H
#define BRIX_COMPAT_TIME_H

#include <stddef.h>
#include <time.h>

/*
 * Format a UTC timestamp as an ISO-8601 value with millisecond precision fixed
 * to zero, matching the existing S3 XML LastModified representation.
 *
 * Example: 2026-05-21T14:30:00.000Z
 */
void brix_format_iso8601(time_t t, char *buf, size_t bufsz);

#endif /* BRIX_COMPAT_TIME_H */
