/*
 * brixcvmfs_curl_pin.h — libcurl name resolution pinned to brix_resolve()
 * (phase-116).
 *
 * WHAT: cvmfs_curl_perform_pinned() performs one transfer, and every
 *       redirect hop of it, with the target host (and the proxy host, when
 *       one is set) resolved by the client's one DNS seam and handed to
 *       libcurl through CURLOPT_RESOLVE, so libcurl's own resolver is never
 *       consulted.
 * WHY:  CURLOPT_URL + CURLOPT_FOLLOWLOCATION are hidden resolver calls:
 *       libcurl would getaddrinfo() the URL host and every Location: hop
 *       itself, bypassing the family hint, the cache and the seam guard.
 *       Walking the redirects by hand keeps each hop's host under the same
 *       pin and the same http/https confinement as the first request.
 * HOW:  the server-side src/net/dns/curl_pin.c design, on the client seam:
 *       pin → CURLOPT_URL → on_hop → perform → CURLINFO_REDIRECT_URL, until
 *       no redirect or the cap; the pin list is unset and freed after each
 *       hop.  Lives in the brixcvmfs app because libbrix links no libcurl.
 */
#ifndef BRIXCVMFS_CURL_PIN_H
#define BRIXCVMFS_CURL_PIN_H

#include <curl/curl.h>

#define BRIXCVMFS_MAX_REDIRECTS 4

typedef struct {
    const char *proxy;                 /* CURLOPT_PROXY value already set ("" = direct) */
    long        max_redirects;         /* 0 = a redirect is a failure */
    void      (*on_hop)(void *ud);     /* per-hop reset (buffers, header watch) */
    void       *ud;
} cvmfs_curl_transfer;

/* Perform `url` on `c` (all other options already set), following up to
 * t->max_redirects hops, every host pinned.  CURLE_COULDNT_RESOLVE_HOST /
 * CURLE_COULDNT_RESOLVE_PROXY when a name has no address,
 * CURLE_TOO_MANY_REDIRECTS past the cap, else the last hop's CURLcode. */
CURLcode cvmfs_curl_perform_pinned(CURL *c, const cvmfs_curl_transfer *t,
                                   const char *url);

#endif /* BRIXCVMFS_CURL_PIN_H */
