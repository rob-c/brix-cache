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
#include "metrics/metrics.h"


const xrootd_http_operation_t xrootd_webdav_operations[] = {
    /* name          http_method          metric_slot                    flags */
    { "OPTIONS",  NGX_HTTP_OPTIONS,  XROOTD_WEBDAV_METHOD_OPTIONS,  0,
      XROOTD_PROTO_OP_READ },
    { "GET",      NGX_HTTP_GET,      XROOTD_WEBDAV_METHOD_GET,      0,
      XROOTD_PROTO_OP_READ },
    { "HEAD",     NGX_HTTP_HEAD,     XROOTD_WEBDAV_METHOD_HEAD,     0,
      XROOTD_PROTO_OP_READ },
    { "PROPFIND", NGX_HTTP_PROPFIND, XROOTD_WEBDAV_METHOD_PROPFIND, 0,
      XROOTD_PROTO_OP_READ | XROOTD_PROTO_OP_LIST },
    { "SEARCH",   0,                XROOTD_WEBDAV_METHOD_OTHER,    0,
      XROOTD_PROTO_OP_READ | XROOTD_PROTO_OP_LIST | XROOTD_PROTO_OP_ASYNC_BODY },
    { "PUT",      NGX_HTTP_PUT,      XROOTD_WEBDAV_METHOD_PUT,      0,
      XROOTD_PROTO_OP_WRITE },
    { "DELETE",   NGX_HTTP_DELETE,   XROOTD_WEBDAV_METHOD_DELETE,   0,
      XROOTD_PROTO_OP_WRITE },
    { "MKCOL",    NGX_HTTP_MKCOL,    XROOTD_WEBDAV_METHOD_MKCOL,    0,
      XROOTD_PROTO_OP_WRITE },
    { "MOVE",     NGX_HTTP_MOVE,     XROOTD_WEBDAV_METHOD_OTHER,    0,
      XROOTD_PROTO_OP_WRITE },
    { "COPY",     NGX_HTTP_COPY,     XROOTD_WEBDAV_METHOD_COPY,     0,
      XROOTD_PROTO_OP_WRITE | XROOTD_PROTO_OP_TPC },
    { "PROPPATCH",NGX_HTTP_PROPPATCH,XROOTD_WEBDAV_METHOD_OTHER,    0,
      XROOTD_PROTO_OP_WRITE | XROOTD_PROTO_OP_LOCK | XROOTD_PROTO_OP_ASYNC_BODY },
    { "ACL",      0,                XROOTD_WEBDAV_METHOD_OTHER,    0,
      XROOTD_PROTO_OP_WRITE },
    { "LOCK",     NGX_HTTP_LOCK,     XROOTD_WEBDAV_METHOD_OTHER,    0,
      XROOTD_PROTO_OP_LOCK },
    { "UNLOCK",   NGX_HTTP_UNLOCK,   XROOTD_WEBDAV_METHOD_OTHER,    0,
      XROOTD_PROTO_OP_LOCK },
};

const ngx_uint_t xrootd_webdav_operations_count =
    sizeof(xrootd_webdav_operations) / sizeof(xrootd_webdav_operations[0]);
