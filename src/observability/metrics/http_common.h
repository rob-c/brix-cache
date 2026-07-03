/*
 * http_common.h — shared HTTP status-class mapping for metrics modules.
 *
 * Both the WebDAV metrics module (webdav/metrics.c) and the S3 metrics
 * module (s3/metrics.c) need to bucket HTTP status codes into low-
 * cardinality BRIX_HTTP_STATUS_* labels.  Defining the function as a
 * static inline here avoids a separate compilation unit while guaranteeing
 * a single authoritative implementation.
 */

#ifndef BRIX_METRICS_HTTP_COMMON_H
#define BRIX_METRICS_HTTP_COMMON_H

#include "metrics.h"

/*
 * brix_http_status_class — map an HTTP status code to the
 * low-cardinality BRIX_HTTP_STATUS_* bucket used in Prometheus labels.
 *
 * Returns one of:
 *   BRIX_HTTP_STATUS_1XX  — informational (100–199)
 *   BRIX_HTTP_STATUS_2XX  — success       (200–299)
 *   BRIX_HTTP_STATUS_3XX  — redirection   (300–399)
 *   BRIX_HTTP_STATUS_4XX  — client error  (400–499)
 *   BRIX_HTTP_STATUS_5XX  — server error  (500–599)
 *   BRIX_HTTP_STATUS_OTHER — anything else (0, out-of-range, etc.)
 *
 * WHY static inline: eliminates duplicate local definitions in both
 * webdav/metrics.c and s3/metrics.c with zero link-time overhead.
 */
static inline ngx_uint_t
brix_http_status_class(ngx_uint_t status)
{
    if (status >= 100 && status < 200) { return BRIX_HTTP_STATUS_1XX; }
    if (status >= 200 && status < 300) { return BRIX_HTTP_STATUS_2XX; }
    if (status >= 300 && status < 400) { return BRIX_HTTP_STATUS_3XX; }
    if (status >= 400 && status < 500) { return BRIX_HTTP_STATUS_4XX; }
    if (status >= 500 && status < 600) { return BRIX_HTTP_STATUS_5XX; }
    return BRIX_HTTP_STATUS_OTHER;
}

#endif /* BRIX_METRICS_HTTP_COMMON_H */
