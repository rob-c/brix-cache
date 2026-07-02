#ifndef XROOTD_SD_HTTP_H
#define XROOTD_SD_HTTP_H

/*
 * sd_http.h — read-only HTTP(S) source storage driver (phase-63 C-4).
 *
 * WHAT: A capability-typed SD driver (CAP_RANGE_READ only; every write/dir/xattr
 *       slot NULL) that serves open/stat/pread/fstat/close against a plain
 *       HTTP(S) endpoint — `open` HEADs the URL for the size, `pread` issues a
 *       byte-Range GET. The sibling of the S3 `sd_remote` driver minus SigV4: it
 *       is the *generic* web source for the composable stack, so an export
 *       (`xrootd_storage_backend http://host:port/base`) or a read cache can reach
 *       any HTTP origin through the SAME driver→driver fill path C-1 uses for
 *       root:// — no bespoke per-scheme libcurl in the cache.
 *
 * HOW:  The actual HTTP is performed by an INJECTED transport vtable
 *       (`xrootd_s3_transport_t`, the shared one the S3 driver uses) — the module
 *       passes the server libcurl singleton (`xrootd_s3_origin_curl_transport`),
 *       so this driver carries no libcurl dependency itself. No kernel fd ⇒ reads
 *       are memory-served. Blocking; runs on the cache-fill / AIO worker thread.
 *       Instances + objects are malloc-owned (no nginx pool), worker-safe.
 *
 * AUTH: anonymous GET by default. When `bearer_token` is set (the §14 credential
 *       block, threaded through the registry), every HEAD/GET carries
 *       `Authorization: Bearer <token>` — the WLCG / SciTokens path. (X.509/GSI to
 *       an HTTP origin is a later credential-block consumer.)
 */

#include "fs/backend/sd.h"
#include "fs/backend/s3/sd_s3_transport.h"

/* Endpoint for one HTTP source instance. Strings are copied. `base_path` is the
 * URL path prefix ("" or "/dir"); a request key "/file" is appended to it. */
typedef struct {
    const char                  *host;        /* endpoint host */
    int                          port;
    int                          tls;         /* 1 = https */
    const char                  *base_path;   /* URL path prefix ("" or "/sub") */
    const xrootd_s3_transport_t *transport;   /* injected HTTP transport */
    void                        *tctx;        /* transport context (NULL for curl) */
    int                          timeout_ms;
    const char                  *bearer_token; /* §14: Authorization: Bearer, or NULL */
} xrootd_sd_http_cfg_t;

/* Build a read-only HTTP source instance. Returns a malloc-owned instance, or NULL
 * (errno set). Destroy with xrootd_sd_http_destroy. */
xrootd_sd_instance_t *xrootd_sd_http_create(const xrootd_sd_http_cfg_t *cfg,
    ngx_log_t *log);

/* Free an instance built by xrootd_sd_http_create. NULL-safe. */
void xrootd_sd_http_destroy(xrootd_sd_instance_t *inst);

#endif /* XROOTD_SD_HTTP_H */
