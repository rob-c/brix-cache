/*
 * date.c - RFC 1123 HTTP date formatting.
 */

#include "webdav.h"

#include <stdio.h>
#include <time.h>

void
webdav_iso8601_date(time_t t, char *buf, size_t sz)
{
    struct tm tm;
    gmtime_r(&t, &tm);
    snprintf(buf, sz, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

void
webdav_http_date(time_t t, char *buf, size_t sz)
{
    struct tm tm;
    static const char *wday[] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    static const char *mon[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    gmtime_r(&t, &tm);
    snprintf(buf, sz, "%s, %02d %s %04d %02d:%02d:%02d GMT",
             wday[tm.tm_wday], tm.tm_mday, mon[tm.tm_mon],
             tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}
