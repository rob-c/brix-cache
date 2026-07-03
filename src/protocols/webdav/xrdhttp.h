/*
 * xrdhttp.h — XrdHttp protocol extension support for the nginx-xrootd WebDAV module.
 *
 * WHAT: Public API for the XrdHttp compatibility layer.  Covers:
 *   - Detection of XrdHttp clients via X-Xrootd-Proto header
 *   - Extraction of ?xrd.* and ?tpc.* query parameters per the XrdHttp URL dialect
 *   - Response header injection: X-Xrootd-Requuid, X-Xrootd-Status, X-Xrootd-Wait/Retry
 *   - XrdHttp redirect dialect: X-Xrootd-Redir-Host, X-Xrootd-Redir-Port, opaque passthrough
 *   - Multipart/byteranges GET for efficient vector reads (kXR_readv over HTTP)
 *   - URI-based TPC via ?tpc.src= / ?tpc.dst= query parameters
 *   - ?xrd.stats XML statistics endpoint
 *
 * WHY: The XRootD reference implementation (XrdHttp) uses these extensions so that
 * XRootD-aware HTTP clients (xrdcp --prefer-xrdhttp, ROOT TFile, davix with xrd hints)
 * get richer error diagnostics, server-side checksum hints, redirect loop prevention,
 * and high-performance vector reads.  Without this layer those clients fall back to
 * slower code paths or emit spurious errors.
 *
 * USAGE: Call xrdhttp_parse_request() once per request (in dispatch, after auth).
 * Call xrdhttp_add_response_headers() before returning from any method handler.
 * For multi-range GETs, check xrdhttp_request_is_multirange() and route to
 * xrdhttp_handle_multipart_get() instead of the standard single-range path.
 */

#ifndef BRIX_WEBDAV_XRDHTTP_H
#define BRIX_WEBDAV_XRDHTTP_H

/* nginx core headers — provide ngx_http_request_t, ngx_fd_t, ngx_int_t, etc. */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/stat.h>

/* Maximum lengths for client-supplied strings stored in request context.
 * These are intentionally small to bound per-request allocation. */
#define XRDHTTP_UUID_MAX     64   /* xrd.clnt.uuid / X-Xrootd-Requuid */
#define XRDHTTP_APP_MAX      64   /* xrd.clnt.app */
#define XRDHTTP_CKSUM_MAX    32   /* xrd.want.cksum algorithm name */
#define XRDHTTP_OPAQUE_MAX  512   /* xrd.opaque passthrough blob */
#define XRDHTTP_TPC_KEY_MAX 256   /* tpc.key security cookie */
#define XRDHTTP_TPC_URL_MAX 1024  /* tpc.src / tpc.dst URL */
#define XRDHTTP_PROTO_MAX    16   /* X-Xrootd-Proto version string */

/* Maximum number of byte ranges in a multipart GET. */
#define XRDHTTP_MAX_RANGES   64

/*
 * Per-request XrdHttp context.  Allocated lazily in xrdhttp_parse_request()
 * from r->pool on first use.  Retrieved with xrdhttp_get_ctx().
 */
typedef struct {
    /* Client identification (from X-Xrootd-Proto header). */
    unsigned   is_xrdhttp:1;          /* 1 = client sent X-Xrootd-Proto */
    unsigned   headers_injected:1;    /* 1 = xrdhttp response headers already added */
    char       proto_version[XRDHTTP_PROTO_MAX]; /* e.g. "5.2", NUL-term */

    /* ?xrd.* query parameters — logged and used for routing/metrics. */
    char       clnt_uuid[XRDHTTP_UUID_MAX];  /* xrd.clnt.uuid */
    char       clnt_app[XRDHTTP_APP_MAX];    /* xrd.clnt.app */
    char       want_cksum[XRDHTTP_CKSUM_MAX]; /* xrd.want.cksum alg */
    char       opaque[XRDHTTP_OPAQUE_MAX];   /* xrd.opaque blob */

    /* ?tpc.* parameters — alternate TPC signaling (besides headers). */
    char       tpc_src[XRDHTTP_TPC_URL_MAX]; /* tpc.src pull URL */
    char       tpc_dst[XRDHTTP_TPC_URL_MAX]; /* tpc.dst push URL */
    char       tpc_key[XRDHTTP_TPC_KEY_MAX]; /* tpc.key security cookie */
    char       tpc_token[XRDHTTP_TPC_KEY_MAX]; /* X-Xrootd-Tpc-Token */

    /* Request UUID echo — sent back in every response as X-Xrootd-Requuid. */
    char       requuid[XRDHTTP_UUID_MAX];  /* from X-Xrootd-Requuid or generated */

    /* Wait/retry — populated by handlers that need back-pressure. */
    int        wait_seconds;   /* emit X-Xrootd-Wait: <N> if > 0 */
    int        retry_seconds;  /* emit X-Xrootd-Retry: <N> if > 0 */

    /* Phase 21 Step B — streaming Digest over the response body.  Set by the
     * GET path when the client sent "Want-Digest: adler32" and the digest was
     * not already produced from the open fd.  The body filter folds each output
     * buffer into `adler` and emits "Digest: adler32=<hex>" as a trailer. */
    unsigned   compute_digest:1;  /* 1 = accumulate adler32 over the body */
    unsigned   digest_emitted:1;  /* 1 = trailer already queued */
    uint32_t   adler;             /* running adler32 (seed 1) */
} xrdhttp_req_ctx_t;

/* ---- context helpers ---- */

/*
 * Retrieve or allocate the XrdHttp per-request context from r->ctx.
 * Returns NULL on pool allocation failure.
 */
xrdhttp_req_ctx_t *xrdhttp_get_ctx(ngx_http_request_t *r);

/* ---- request parsing ---- */

/*
 * Parse all XrdHttp signals from the incoming request:
 *   - X-Xrootd-Proto → is_xrdhttp + proto_version
 *   - X-Xrootd-Requuid → requuid (echoed in response)
 *   - X-Xrootd-Tpc-Token → tpc_token
 *   - Query string → clnt_uuid, clnt_app, want_cksum, opaque, tpc_src, tpc_dst, tpc_key
 * Logs clnt_app and clnt_uuid at debug level for auditing.
 * Always succeeds (any unparseable value is silently ignored).
 */
void xrdhttp_parse_request(ngx_http_request_t *r);

/* ---- response header injection ---- */

/*
 * Inject XrdHttp response headers into r->headers_out before the caller
 * sends headers:
 *   - X-Xrootd-Requuid: <requuid>   (always if is_xrdhttp)
 *   - X-Xrootd-Status: <xrd_code>   (for non-2xx status; 0 = success)
 *   - X-Xrootd-Wait: <N>            (if ctx->wait_seconds > 0)
 *   - X-Xrootd-Retry: <N>           (if ctx->retry_seconds > 0)
 * Safe to call even when is_xrdhttp==0 — emits nothing in that case.
 * http_status is the HTTP status code about to be sent (for kXR mapping).
 */
ngx_int_t xrdhttp_add_response_headers(ngx_http_request_t *r,
                                        ngx_int_t http_status);

/* ---- redirect helpers ---- */

/*
 * Build and send an HTTP redirect response using the XrdHttp redirect dialect:
 *   - Location: <location_url>[?<opaque>] (tpc.key and xrd.opaque appended)
 *   - X-Xrootd-Redir-Host: <redir_host>  (if non-NULL)
 *   - X-Xrootd-Redir-Port: <redir_port>  (if redir_port > 0)
 *   - X-Xrootd-Requuid / X-Xrootd-Status from context
 * Sends a 307 Temporary Redirect.  Returns NGX_HTTP_TEMPORARY_REDIRECT.
 */
ngx_int_t xrdhttp_send_redirect(ngx_http_request_t *r,
                                  const char *location_url,
                                  const char *redir_host,
                                  int         redir_port);

/* ---- multipart/byteranges (vector read) ---- */

/*
 * Returns 1 if the Range header contains multiple comma-separated ranges
 * (i.e., this is a vector-read request), 0 for single-range or no-range.
 * Used in get.c to decide whether to call xrdhttp_handle_multipart_get().
 */
int xrdhttp_request_is_multirange(ngx_http_request_t *r);

/*
 * Serve a multipart/byteranges response for the already-open file fd.
 * sb must describe the file (for size bounds checking).
 * Returns standard NGX_HTTP_* codes or ngx_http_output_filter return value.
 */
ngx_int_t xrdhttp_handle_multipart_get(ngx_http_request_t *r,
                                         ngx_fd_t fd,
                                         const struct stat *sb,
                                         int fd_from_table);

/* ---- ?xrd.stats endpoint ---- */

/*
 * Detect whether this GET/HEAD request is a ?xrd.stats query (URL contains
 * "?xrd.stats" or "&xrd.stats" query parameter).
 * Returns 1 if so, 0 otherwise.
 */
int xrdhttp_request_is_stats_query(ngx_http_request_t *r);

/*
 * Generate the ?xrd.stats XML response and send it.
 * Returns standard NGX_HTTP_* codes.
 */
ngx_int_t xrdhttp_handle_stats_query(ngx_http_request_t *r);

/* ---- TPC query-parameter support ---- */

/*
 * If the request carries tpc.src or tpc.dst query parameters instead of
 * Source:/Destination: headers, synthesize the corresponding header in
 * r->headers_in so that the existing tpc.c handler sees them transparently.
 * Call after xrdhttp_parse_request() and before dispatching to tpc handler.
 */
ngx_int_t xrdhttp_inject_tpc_headers(ngx_http_request_t *r);

/* ---- checksum helpers ---- */

/*
 * If ctx->want_cksum is set, compute the checksum of fd using the requested
 * algorithm ("adler32" or "crc32") and inject a "Digest:" response header.
 * Silently skips if want_cksum is empty or fd is invalid.
 * Must be called before ngx_http_send_header().
 */
ngx_int_t xrdhttp_add_checksum_header(ngx_http_request_t *r,
                                        ngx_fd_t fd,
                                        const struct stat *sb);

/* ---- HTTP status → XRootD error code mapping ---- */

/*
 * Map an HTTP status code to the nearest XRootD wire error code for
 * inclusion in the X-Xrootd-Status response header.
 * Returns 0 for 2xx (success), a kXR_* constant otherwise.
 */
int xrdhttp_http_to_xrd_status(ngx_int_t http_status);

/*
 * Streaming Digest body filter (Phase 21 Step B).  Folds each output buffer
 * into ctx->adler when ctx->compute_digest is set; on the final buffer it
 * queues a "Digest: adler32=<hex>" trailer.  Pass-through (just calls `next`)
 * for non-XrdHttp requests or when digest accumulation is off.  Invoked by the
 * aux filter module's body-filter slot.
 */
ngx_int_t xrdhttp_digest_body_filter(ngx_http_request_t *r, ngx_chain_t *in,
    ngx_http_output_body_filter_pt next);

#endif /* BRIX_WEBDAV_XRDHTTP_H */
