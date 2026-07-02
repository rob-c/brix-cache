#ifndef XROOTD_CACHE_ORIGIN_S3_TRANSPORT_H
#define XROOTD_CACHE_ORIGIN_S3_TRANSPORT_H

/*
 * s3_transport.h — server-side libcurl HTTP transport for the shared S3 storage
 * driver (sd_s3), used by the read-through cache's S3 origin.
 *
 * WHAT: The module-side implementation of xrootd_s3_transport_t — one synchronous
 *       libcurl request + response accessors — so sd_s3's SigV4 / Range-GET / HEAD
 *       protocol logic runs over the server's HTTP stack exactly as it runs over
 *       the client's (client/lib/vfs_s3_transport.c) for the native tools.
 *
 * WHY:  sd_s3 was client-only because src/ had no HTTP-client substrate to inject.
 *       This is that substrate for the server: it lets the cache front an S3 origin
 *       (xrootd_cache_origin s3://…) by reusing the whole S3 driver, no protocol
 *       code duplicated.
 *
 * HOW:  Runs ONLY on the blocking cache-fill thread-pool worker (libcurl easy,
 *       synchronous), never the event loop — matching http_transport.c. Stateless
 *       (tctx unused). The Host header is forced to the bare endpoint host (no
 *       port) to match sd_s3's SigV4 canonical host.
 */

#include "fs/backend/s3/sd_s3_transport.h"

/* The singleton libcurl transport vtable. tctx is unused (pass NULL). */
extern const xrootd_s3_transport_t xrootd_s3_origin_curl_transport;

#endif /* XROOTD_CACHE_ORIGIN_S3_TRANSPORT_H */
