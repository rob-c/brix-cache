#ifndef BRIX_PATH_UNIFIED_H
#define BRIX_PATH_UNIFIED_H

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
} brix_path_opts_t;

#define BRIX_PATH_TYPE_NOT_FOUND  ((ngx_int_t) -2)

typedef struct {
    ngx_str_t   resolved;
    ngx_int_t   type;
    ngx_uint_t  depth;
    unsigned    is_confined:1;
} brix_path_result_t;

typedef enum {
    BRIX_PATH_STATUS_OK = 0,
    BRIX_PATH_STATUS_INVALID,
    BRIX_PATH_STATUS_NOT_FOUND,
    BRIX_PATH_STATUS_TOO_LONG,
    BRIX_PATH_STATUS_ERROR
} brix_path_status_t;

/*
 * Fixed-buffer resolver used by existing stream and HTTP adapters.
 * root_canon must already be a canonical absolute filesystem path.
 */
brix_path_status_t brix_path_resolve_cstr(ngx_log_t *log,
    const char *root_canon, const char *req_path, brix_path_opts_t opts,
    char *resolved, size_t resolvsz, brix_path_result_t *result);

#endif /* BRIX_PATH_UNIFIED_H */
