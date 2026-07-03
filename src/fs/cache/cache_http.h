#ifndef BRIX_CACHE_HTTP_H
#define BRIX_CACHE_HTTP_H

/*
 * cache_http.h — public cache API for HTTP protocol handlers (WebDAV, S3).
 *
 * WHAT: Exposes the read-only cache hit-check function for use by HTTP-layer
 *       handlers (webdav/get.c, s3/object.c) without pulling in the full
 *       stream-specific cache_internal.h.
 *
 * WHY: cache_internal.h includes ngx_brix_module.h which brings in stream
 *      types. HTTP handlers only need brix_cache_file_ready() — a pure
 *      filesystem stat call that has no stream dependencies.
 *
 * Caller contract:
 *   path   — NUL-terminated absolute path to the potential cache file.
 *   return — 1: file exists and is complete (serve from cache);
 *             0: miss (fetch from origin);
 *            -1: stat error (treat as miss; errno is set).
 */
int brix_cache_file_ready(const char *path);

#endif /* BRIX_CACHE_HTTP_H */
