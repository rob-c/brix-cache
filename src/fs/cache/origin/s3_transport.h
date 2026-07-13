#ifndef BRIX_CACHE_ORIGIN_S3_TRANSPORT_H
#define BRIX_CACHE_ORIGIN_S3_TRANSPORT_H

/*
 * s3_transport.h — server-side libcurl HTTP transport for the shared S3 storage
 * driver (sd_s3), used by the read-through cache's S3 origin.
 *
 * WHAT: The module-side implementation of brix_s3_transport_t — one synchronous
 *       libcurl request + response accessors — so sd_s3's SigV4 / Range-GET / HEAD
 *       protocol logic runs over the server's HTTP stack exactly as it runs over
 *       the client's (client/lib/vfs_s3_transport.c) for the native tools.
 *
 * WHY:  sd_s3 was client-only because src/ had no HTTP-client substrate to inject.
 *       This is that substrate for the server: it lets the cache front an S3 origin
 *       (brix_cache_origin s3://…) by reusing the whole S3 driver, no protocol
 *       code duplicated.
 *
 * HOW:  Runs ONLY on the blocking cache-fill thread-pool worker (libcurl easy,
 *       synchronous), never the event loop — matching http_transport.c. Stateless
 *       (tctx unused). The Host header is forced to the bare endpoint host (no
 *       port) to match sd_s3's SigV4 canonical host.
 */

#include "fs/backend/s3/sd_s3_transport.h"

/* The singleton libcurl transport vtable.
 *
 * tctx is this transport's OPTIONAL per-request context: a NUL-terminated CA
 * file-or-dir PATH (the operator-configured trusted CA for origin TLS
 * verification), or NULL for libcurl's system CA bundle. A directory is used as
 * CURLOPT_CAPATH, a file as CURLOPT_CAINFO. TLS peer/host verification is always
 * enabled; tctx only widens which roots are trusted — it never disables the
 * check. The driver stores the CA path for the instance's lifetime and passes it
 * as tctx on every request (phase-70 https backend leg). */
extern const brix_s3_transport_t brix_s3_origin_curl_transport;

/* Promote the per-request upstream trace line from DEBUG to INFO (1) or back
 * to DEBUG-only (0). Set pre-fork from the cvmfs merge when any location has
 * brix_cvmfs_trace on, so all workers inherit it. */
void brix_origin_trace_set(int info_on);

/* Fast-fail transport bounds applied to EVERY origin request by this shared
 * curl transport (process-global operator policy; inherited across the fork,
 * matching brix_origin_trace_set). A value of 0 leaves libcurl's default:
 *   connect_ms         — CURLOPT_CONNECTTIMEOUT_MS: cap a blackholed connect.
 *   stall_secs         — CURLOPT_LOW_SPEED_TIME: seconds below the floor before
 *                        abort (the "connected but no bytes" stall).
 *   stall_bytes_per_s  — CURLOPT_LOW_SPEED_LIMIT: the throughput floor.
 *   attempt_ms         — CURLOPT_TIMEOUT_MS cap: abandon a whole connect+transfer
 *                        after this long so the fill loop retries on a fresh
 *                        connection within the client's timeout window. Wins
 *                        over the caller's per-request timeout.
 * stall_secs and stall_bytes_per_s take effect only together. */
void brix_s3_origin_timeouts_set(long connect_ms, long stall_secs,
    long stall_bytes_per_s, long attempt_ms);

/* Origin connection reuse toggle (process-global; set pre-fork from the cvmfs
 * merge). ON (default) keeps one warm keep-alive connection per fill thread and
 * reuses it — amortizes the handshake + TCP slow-start on a high-latency link.
 * OFF forces a fresh connection per request; use it when a connection-reaping
 * middlebox makes reuse time out on a stale connection. */
void brix_s3_origin_reuse_set(int reuse_on);

#endif /* BRIX_CACHE_ORIGIN_S3_TRANSPORT_H */
