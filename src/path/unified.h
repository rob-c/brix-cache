#ifndef XROOTD_PATH_UNIFIED_H
#define XROOTD_PATH_UNIFIED_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <sys/stat.h>

/*
 * Unified path resolver options.
 *
 * These flags describe protocol semantics; the resolver keeps the security
 * checks identical for stream, WebDAV, and S3 callers.
 */
typedef struct {
    unsigned allow_missing_tail:1;      /* create/write: final component may be absent */
    unsigned require_directory:1;       /* caller requires resolved target to be a dir */
    unsigned allow_missing_parents:1;   /* recursive mkdir/HTTP PUT-style missing suffix */
    unsigned skip_cache_check:1;        /* reserved for future cache-aware resolution */
    unsigned is_write_operation:1;      /* write semantics for audit/logging */
    unsigned reject_symlinks:1;         /* reserved; confinement still rejects escapes */
    unsigned allow_root:1;              /* allow "/" to resolve to the export root */
} xrootd_path_opts_t;

#define XROOTD_PATH_TYPE_NOT_FOUND  ((ngx_int_t) -2)

typedef struct {
    ngx_str_t   resolved;
    ngx_int_t   type;
    ngx_uint_t  depth;
    unsigned    is_confined:1;
} xrootd_path_result_t;

typedef enum {
    XROOTD_PATH_STATUS_OK = 0,
    XROOTD_PATH_STATUS_INVALID,
    XROOTD_PATH_STATUS_NOT_FOUND,
    XROOTD_PATH_STATUS_TOO_LONG,
    XROOTD_PATH_STATUS_ERROR
} xrootd_path_status_t;

/*
 * Pool-allocating resolver matching the Phase 1 API shape.  Runtime protocol
 * adapters below use xrootd_path_resolve_cstr() to keep existing call
 * signatures and fixed output buffers unchanged.
 */
ngx_int_t xrootd_path_resolve(ngx_conf_t *cf,
    const ngx_str_t *root_canon, const ngx_str_t *req_path,
    xrootd_path_opts_t opts, xrootd_path_result_t *result, ngx_log_t *log);

ngx_int_t xrootd_path_validate(const ngx_str_t *root_canon,
    const ngx_str_t *req_path, ngx_log_t *log);

ngx_int_t xrootd_path_get_type(const ngx_str_t *resolved_path);

/*
 * Fixed-buffer resolver used by existing stream and HTTP adapters.
 * root_canon must already be a canonical absolute filesystem path.
 */
xrootd_path_status_t xrootd_path_resolve_cstr(ngx_log_t *log,
    const char *root_canon, const char *req_path, xrootd_path_opts_t opts,
    char *resolved, size_t resolvsz, xrootd_path_result_t *result);

#endif /* XROOTD_PATH_UNIFIED_H */
