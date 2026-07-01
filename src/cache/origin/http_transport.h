#ifndef XROOTD_CACHE_HTTP_TRANSPORT_H
#define XROOTD_CACHE_HTTP_TRANSPORT_H

/*
 * http_transport.h — HTTP(S)/WebDAV origin transport for the read-through cache.
 *
 * WHAT: Download a file from an http://, https://, or davs:// origin into the
 *       fill's ".part" staging file using libcurl, capturing the origin's
 *       advertised content digest (RFC 3230 Digest header, solicited with
 *       Want-Digest) so checksum-on-fill (verify.c) can validate it before the
 *       atomic publish.
 * WHY:  The cache's native origin client speaks only the XRootD wire protocol;
 *       a large class of origins (XrdHttp, dCache, Pelican origins/caches, plain
 *       object stores) are reachable only over HTTP.  Reusing libcurl — already
 *       a hard dependency for WebDAV TPC — gives TLS, redirect following, range
 *       requests, and header handling without a hand-rolled HTTP client.
 * HOW:  A single ranged GET streams the body straight to the part fd via a write
 *       callback; a header callback captures the Digest and Content-Length.
 *       Bearer auth is the configured cache credential (xrootd_cache_origin_token_file)
 *       and/or the forwarded client token (xrootd_cache_origin_forward_token,
 *       read from ctx->bearer_token).  Runs in a fill thread-pool worker.
 */

#include "../cache_internal.h"

/*
 * Download an explicit absolute URL into t->part_path. Used by the
 * Pelican transport to fetch the director object URL with redirect-following.
 * TLS verification is enabled when `url` is https. Returns 0 / -1 (t error set).
 */
int xrootd_cache_http_get_url(xrootd_cache_fill_t *t, const char *url);

#endif /* XROOTD_CACHE_HTTP_TRANSPORT_H */
