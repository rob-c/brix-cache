/*
 * time.c — POSIX time utilities for nginx-xrootd.
 *
 * ISO8601 formatting of file modification times, access logs, and protocol responses. All
 * functions use UTC (gmtime_r) to avoid timezone ambiguity across distributed HEP sites.
 */

#include "time.h"

#include <stdio.h>

/*
 * WHAT: Format a time_t value as an ISO8601 UTC string into caller-provided buffer.
 *
 * WHY: XRootD stat responses, access logs, and HTTP headers all need consistent timestamp
 *      formatting. ISO8601 with explicit 'Z' suffix unambiguously indicates UTC — critical for
 *      HEP sites distributed across multiple timezones where local time would cause confusion.
 *
 * HOW: gmtime_r converts t to a broken-down tm struct (thread-safe, UTC). snprintf formats
 *      as YYYY-MM-DDTHH:MM:SS.000Z with zero-padded fields. On gmtime_r failure or invalid
 *      args: buf[0]='\0' (empty string) returned.
 *
 * Parameters:
 *   t — time_t value to format (typically st_mtime from stat())
 *   buf — output buffer (must be at least 25 bytes for full ISO8601 string)
 *   bufsz — size of buf
 */
void
brix_format_iso8601(time_t t, char *buf, size_t bufsz)
{
    struct tm tm;

    if (buf == NULL || bufsz == 0) {
        return;
    }

    if (gmtime_r(&t, &tm) == NULL) {
        buf[0] = '\0';
        return;
    }

    snprintf(buf, bufsz,
             "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}
