/*
 * operation_table.c — WebDAV HTTP operation descriptor table.
 *
 * Lists every HTTP method handled by the WebDAV module with its metric slot,
 * and capability flags.  The shared helpers in compat/protocol_caps.c use this
 * table to build Allow headers, CORS Allow-Methods strings, and for future
 * write-method detection replacing the inline switch statements.
 *
 * Ordering follows the preferred Allow header display order: safe methods
 * first, then write methods, then locking extensions.
 */

#include "webdav.h"
#include "core/compat/protocol_caps.h"
#include "observability/metrics/metrics.h"


const brix_http_operation_t brix_webdav_operations[] = {
    /* name          http_method          metric_slot                    flags */
    { "OPTIONS",  NGX_HTTP_OPTIONS,  BRIX_WEBDAV_METHOD_OPTIONS,  0,
      BRIX_PROTO_OP_READ },
    { "GET",      NGX_HTTP_GET,      BRIX_WEBDAV_METHOD_GET,      0,
      BRIX_PROTO_OP_READ },
    { "HEAD",     NGX_HTTP_HEAD,     BRIX_WEBDAV_METHOD_HEAD,     0,
      BRIX_PROTO_OP_READ },
    { "PROPFIND", NGX_HTTP_PROPFIND, BRIX_WEBDAV_METHOD_PROPFIND, 0,
      BRIX_PROTO_OP_READ | BRIX_PROTO_OP_LIST },
    { "SEARCH",   0,                BRIX_WEBDAV_METHOD_OTHER,    0,
      BRIX_PROTO_OP_READ | BRIX_PROTO_OP_LIST | BRIX_PROTO_OP_ASYNC_BODY },
    { "PUT",      NGX_HTTP_PUT,      BRIX_WEBDAV_METHOD_PUT,      0,
      BRIX_PROTO_OP_WRITE },
    { "DELETE",   NGX_HTTP_DELETE,   BRIX_WEBDAV_METHOD_DELETE,   0,
      BRIX_PROTO_OP_WRITE },
    { "MKCOL",    NGX_HTTP_MKCOL,    BRIX_WEBDAV_METHOD_MKCOL,    0,
      BRIX_PROTO_OP_WRITE },
    { "MOVE",     NGX_HTTP_MOVE,     BRIX_WEBDAV_METHOD_OTHER,    0,
      BRIX_PROTO_OP_WRITE },
    { "COPY",     NGX_HTTP_COPY,     BRIX_WEBDAV_METHOD_COPY,     0,
      BRIX_PROTO_OP_WRITE | BRIX_PROTO_OP_TPC },
    { "PROPPATCH",NGX_HTTP_PROPPATCH,BRIX_WEBDAV_METHOD_OTHER,    0,
      BRIX_PROTO_OP_WRITE | BRIX_PROTO_OP_LOCK | BRIX_PROTO_OP_ASYNC_BODY },
    { "ACL",      0,                BRIX_WEBDAV_METHOD_OTHER,    0,
      BRIX_PROTO_OP_WRITE },
    { "LOCK",     NGX_HTTP_LOCK,     BRIX_WEBDAV_METHOD_OTHER,    0,
      BRIX_PROTO_OP_LOCK },
    { "UNLOCK",   NGX_HTTP_UNLOCK,   BRIX_WEBDAV_METHOD_OTHER,    0,
      BRIX_PROTO_OP_LOCK },
};

const ngx_uint_t brix_webdav_operations_count =
    sizeof(brix_webdav_operations) / sizeof(brix_webdav_operations[0]);
