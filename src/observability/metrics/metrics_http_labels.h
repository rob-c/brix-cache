/*
 * metrics/metrics_http_labels.h
 *
 * HTTP response status-class label slots, shared by every HTTP-family metrics
 * domain (WebDAV, S3).  Kept in one small header so both domain headers index
 * responses_total[...][BRIX_HTTP_NSTATUS] against the same fixed, low-cardinality
 * status buckets (INVARIANT #8: coarse class only, never a raw status code).
 */

#ifndef NGX_BRIX_METRICS_HTTP_LABELS_H
#define NGX_BRIX_METRICS_HTTP_LABELS_H

#define BRIX_HTTP_STATUS_1XX     0
#define BRIX_HTTP_STATUS_2XX     1
#define BRIX_HTTP_STATUS_3XX     2
#define BRIX_HTTP_STATUS_4XX     3
#define BRIX_HTTP_STATUS_5XX     4
#define BRIX_HTTP_STATUS_OTHER   5
#define BRIX_HTTP_NSTATUS        6

#endif /* NGX_BRIX_METRICS_HTTP_LABELS_H */
