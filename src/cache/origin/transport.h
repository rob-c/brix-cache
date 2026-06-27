#ifndef XROOTD_CACHE_ORIGIN_TRANSPORT_H
#define XROOTD_CACHE_ORIGIN_TRANSPORT_H

/*
 * transport.h — origin-transport seam for the read-through cache.
 *
 * WHAT: A small vtable that abstracts "where the cached bytes come from" so the
 *       fill engine (fetch.c / slice_fill.c) is independent of the origin's wire
 *       protocol.  Today the only driver is xroot:// (the historical
 *       origin_protocol.c functions); Phase 2 adds an HTTP(S) driver (libcurl)
 *       and Phase 3 a Pelican-federation driver layered on top of it.
 *
 * WHY:  Without a seam, adding an HTTP or Pelican origin meant forking the fill
 *       loop and the commit/verify path per protocol.  The seam keeps a single
 *       fill engine and a single checksum-on-fill integration (verify.c) that
 *       works identically for every transport: each driver only has to (a)
 *       stream a byte range to a local fd and (b) report the origin's advertised
 *       content digest.  This mirrors the storage-driver seam in
 *       src/fs/backend/sd.h.
 *
 * HOW:  xrootd_cache_origin_url_parse() classifies the configured origin /
 *       request URL into a scheme and selects the matching driver.  The fill
 *       worker calls connect → open (learn size) → read_range* → checksum →
 *       close.  All driver calls run in an nginx thread-pool worker (blocking
 *       I/O); none touch the event loop.  A driver advertises what it can do via
 *       `caps` so the engine can skip unsupported steps (e.g. an origin that
 *       cannot report a checksum yields XROOTD_CACHE_DIGEST_NONE and the
 *       best-effort verify policy commits the fill unverified).
 */

#include "../cache_internal.h"

#include <stdint.h>


/* Origin URL scheme — selects the transport driver. */
typedef enum {
    XROOTD_CACHE_SCHEME_XROOT = 0,   /* root://  / roots://  (default)         */
    XROOTD_CACHE_SCHEME_HTTP,        /* http://                                 */
    XROOTD_CACHE_SCHEME_HTTPS,       /* https://  / davs://                     */
    XROOTD_CACHE_SCHEME_PELICAN      /* pelican://  (federation discovery)      */
} xrootd_cache_scheme_e;

/* Transport capability bits (advertised by a driver in caps). */
#define XROOTD_CACHE_CAP_RANGE      (1u << 0)  /* read_range() honours offset/len */
#define XROOTD_CACHE_CAP_CHECKSUM   (1u << 1)  /* checksum() can report a digest  */
#define XROOTD_CACHE_CAP_REDIRECT   (1u << 2)  /* follows redirects (HTTP/Pelican)*/

/*
 * Parsed origin URL.  Borrowed string views point into the caller's storage
 * (the srv_conf directive or a request buffer); the parser copies nothing.
 */
typedef struct {
    xrootd_cache_scheme_e  scheme;
    int                    tls;          /* 1 when the scheme implies TLS        */
    ngx_str_t              host;
    uint16_t               port;         /* 0 ⇒ scheme default                   */
    ngx_str_t              path;         /* path component (with leading '/')     */
} xrootd_cache_origin_url_t;

/*
 * Origin-advertised content digest for one file.  alg[]/hex[] are NUL-terminated
 * lowercase; alg[0]=='\0' means the origin offered no usable checksum.
 */
typedef struct {
    char  alg[16];     /* algorithm name, e.g. "adler32", "crc32c"  */
    char  hex[129];    /* digest, lowercase hex                      */
} xrootd_cache_digest_t;

/*
 * xrootd_cache_transport_t — the driver vtable.
 *
 * Every function runs in a fill thread-pool worker and reports failures through
 * the xrootd_cache_fill_t error fields (xrootd_cache_set_error/_syserror), so the
 * fill engine only checks the int return.  `state` is an opaque per-fill driver
 * handle the driver allocates in connect() and frees in close().
 */
typedef struct {
    const char  *name;       /* "xroot" / "http" / "pelican" (for logs)        */
    uint32_t     caps;       /* XROOTD_CACHE_CAP_* bitmask                      */

    /* Establish a session to the origin for t (resolved url in *u). Returns 0 /
     * -1 (t error set). On success *state is the driver handle. */
    int  (*connect)(xrootd_cache_fill_t *t, const xrootd_cache_origin_url_t *u,
                    void **state);
    /* Open the source object for reading and learn its size into *out_size.
     * Returns 0 / -1 (t error set). */
    int  (*open)(xrootd_cache_fill_t *t, void *state, uint64_t *out_size);
    /* Stream [off, off+len) from the origin straight to dst_fd, writing *got
     * bytes (may be < len at EOF). Returns 0 / -1 (t error set). */
    int  (*read_range)(xrootd_cache_fill_t *t, void *state, uint64_t off,
                       size_t len, int dst_fd, size_t *got);
    /* Report the origin's advertised content digest into *out. Sets out->alg[0]
     * = '\0' (and returns 0) when the origin offers none. Returns 0 / -1 (t
     * error set on a hard failure; a missing digest is not a failure). */
    int  (*checksum)(xrootd_cache_fill_t *t, void *state,
                     xrootd_cache_digest_t *out);
    /* Tear down the session and free *state (idempotent; tolerates NULL). */
    void (*close)(xrootd_cache_fill_t *t, void *state);
} xrootd_cache_transport_t;


/*
 * Parse `raw` ("root://h:p//path", "https://h/path", "pelican://fed/ns/path",
 * or a bare "host:port" treated as xroot) into *out. Returns NGX_OK, or
 * NGX_ERROR on a malformed URL (nothing written). Borrowed views into `raw`.
 */
ngx_int_t xrootd_cache_origin_url_parse(const ngx_str_t *raw,
    xrootd_cache_origin_url_t *out);

/*
 * Select the transport driver for a parsed scheme. Returns a pointer to a
 * static const vtable, or NULL when no driver is compiled in for that scheme
 * (e.g. HTTP/Pelican before their phases land).
 */
const xrootd_cache_transport_t *xrootd_cache_transport_for(
    xrootd_cache_scheme_e scheme);


#endif /* XROOTD_CACHE_ORIGIN_TRANSPORT_H */
