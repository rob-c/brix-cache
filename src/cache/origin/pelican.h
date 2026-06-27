#ifndef XROOTD_CACHE_PELICAN_H
#define XROOTD_CACHE_PELICAN_H

/*
 * pelican.h — Pelican-federation origin transport for the read-through cache
 *             (client/consumer role: pulling objects out of a federation).
 *
 * WHAT: Given a federation host (the xrootd_cache_origin "pelican://<fed>" host)
 *       and the client's requested logical path (namespace + object), discover
 *       the federation's Director and fetch the object into the fill's ".part"
 *       file, capturing the origin's Digest so checksum-on-fill verifies it.
 * WHY:  Pelican/OSDF is an HTTP-based data federation: data is addressed as
 *       pelican://<federation>/<namespace>/<object>, and a Director issues an
 *       HTTP 307 to the nearest cache/origin.  This lets the module act as a
 *       caching node that pulls from a Pelican federation, not just a single
 *       fixed origin.
 * HOW:  (1) GET https://<fed>/.well-known/pelican-configuration → parse
 *       "director_endpoint" (jansson).  (2) GET <director_endpoint><path> with
 *       libcurl redirect-following (xrootd_cache_http_get_url) — curl chases the
 *       Director's 307 to the chosen cache/origin and streams the body to the
 *       part file.  Runs in a fill thread-pool worker.  Registration of THIS
 *       node as a discoverable cache (the advertise/JWKS protocol) is a separate
 *       component (pelican_register.c).
 */

#include "../cache_internal.h"

/*
 * Resolve the configured Pelican federation and download t->clean_path into
 * t->part_path, populating t->origin_cks_* from the response Digest. Returns 0
 * on success (caller runs the shared commit+verify path), -1 on error (t error
 * set). Blocking; fill thread-pool worker only.
 */
int xrootd_cache_pelican_download(xrootd_cache_fill_t *t);

/*
 * Discover the Director endpoint for federation `fed_host`:`fed_port` by
 * fetching its .well-known/pelican-configuration and parsing director_endpoint
 * into out[outsz]. Returns 0 / -1 (t error set). Exposed for reuse by the
 * registration component and for unit testing.
 */
int xrootd_cache_pelican_discover(xrootd_cache_fill_t *t, const char *fed_host,
    uint16_t fed_port, char *out, size_t outsz);

#endif /* XROOTD_CACHE_PELICAN_H */
