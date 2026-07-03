/*
 * operation_table.c — S3 HTTP operation descriptor table.
 *
 * Lists every HTTP method handled by the S3 module with its metric slot and
 * capability flags.  The shared helpers in compat/protocol_caps.c use this
 * table for method-slot classification and for the S3 OPTIONS response.
 *
 * Note: S3 is a REST API, not a WebDAV surface.  There is no Allow header
 * requirement, but the table enables consistent metric slot lookup and can
 * drive future capability reporting (e.g. kXR_Qconfig for S3 features).
 */

#include "s3.h"
#include "core/compat/protocol_caps.h"
#include "observability/metrics/metrics.h"

const brix_http_operation_t brix_s3_operations[] = {
    /* name      http_method      metric_slot           access_op  flags */
    { "GET",    NGX_HTTP_GET,    BRIX_S3_METHOD_GET,    0,
      BRIX_PROTO_OP_READ },
    { "HEAD",   NGX_HTTP_HEAD,   BRIX_S3_METHOD_HEAD,   0,
      BRIX_PROTO_OP_READ },
    { "PUT",    NGX_HTTP_PUT,    BRIX_S3_METHOD_PUT,    0,
      BRIX_PROTO_OP_WRITE | BRIX_PROTO_OP_ASYNC_BODY },
    { "DELETE", NGX_HTTP_DELETE, BRIX_S3_METHOD_DELETE, 0,
      BRIX_PROTO_OP_WRITE },
    { "POST",   NGX_HTTP_POST,   BRIX_S3_METHOD_POST,   0,
      BRIX_PROTO_OP_WRITE | BRIX_PROTO_OP_ASYNC_BODY },
    { "OPTIONS", NGX_HTTP_OPTIONS, BRIX_S3_METHOD_OPTIONS, 0,
      BRIX_PROTO_OP_READ },
    /* ListObjectsV2 is a GET with ?list-type=2 query param; the handler
     * overrides the metric slot to BRIX_S3_METHOD_LIST at runtime. */
};

const ngx_uint_t brix_s3_operations_count =
    sizeof(brix_s3_operations) / sizeof(brix_s3_operations[0]);
