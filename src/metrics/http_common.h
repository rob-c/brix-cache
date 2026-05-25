/*
 * http_common.h — shared HTTP status-class mapping for metrics modules.
 *
 * Both the WebDAV metrics module (webdav/metrics.c) and the S3 metrics
 * module (s3/metrics.c) need to bucket HTTP status codes into low-
 * cardinality XROOTD_HTTP_STATUS_* labels.  Defining the function as a
 * static inline here avoids a separate compilation unit while guaranteeing
 * a single authoritative implementation.
 */

#ifndef XROOTD_METRICS_HTTP_COMMON_H
#define XROOTD_METRICS_HTTP_COMMON_H

#include "metrics.h"

/*
 * xrootd_http_status_class — map an HTTP status code to the
 * low-cardinality XROOTD_HTTP_STATUS_* bucket used in Prometheus labels.
 *
 * Returns one of:
 *   XROOTD_HTTP_STATUS_1XX  — informational (100–199)
 *   XROOTD_HTTP_STATUS_2XX  — success       (200–299)
 *   XROOTD_HTTP_STATUS_3XX  — redirection   (300–399)
 *   XROOTD_HTTP_STATUS_4XX  — client error  (400–499)
 *   XROOTD_HTTP_STATUS_5XX  — server error  (500–599)
 *   XROOTD_HTTP_STATUS_OTHER — anything else (0, out-of-range, etc.)
 *
 * WHY static inline: eliminates duplicate local definitions in both
 * webdav/metrics.c and s3/metrics.c with zero link-time overhead.
 */
static inline ngx_uint_t
xrootd_http_status_class(ngx_uint_t status)
{
    if (status >= 100 && status < 200) { return XROOTD_HTTP_STATUS_1XX; }
    if (status >= 200 && status < 300) { return XROOTD_HTTP_STATUS_2XX; }
    if (status >= 300 && status < 400) { return XROOTD_HTTP_STATUS_3XX; }
    if (status >= 400 && status < 500) { return XROOTD_HTTP_STATUS_4XX; }
    if (status >= 500 && status < 600) { return XROOTD_HTTP_STATUS_5XX; }
    return XROOTD_HTTP_STATUS_OTHER;
}

#endif /* XROOTD_METRICS_HTTP_COMMON_H */
