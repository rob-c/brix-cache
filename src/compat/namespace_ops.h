#ifndef XROOTD_NAMESPACE_OPS_H
#define XROOTD_NAMESPACE_OPS_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * xrootd_ns_status_t — neutral status codes for filesystem mutations.
 */
typedef enum {
    XROOTD_NS_OK = 0,
    XROOTD_NS_NOT_FOUND,
    XROOTD_NS_DENIED,
    XROOTD_NS_EXISTS,
    XROOTD_NS_CONFLICT,
    XROOTD_NS_NOT_EMPTY,
    XROOTD_NS_TOO_LONG,
    XROOTD_NS_NO_SPACE,
    XROOTD_NS_IO_ERROR
} xrootd_ns_status_t;

/*
 * xrootd_ns_result_t — result of a namespace mutation.
 */
typedef struct {
    xrootd_ns_status_t status;
    int                sys_errno;
    ngx_flag_t         existed;
    ngx_flag_t         created;
    ngx_flag_t         was_dir;
} xrootd_ns_result_t;

/*
 * xrootd_ns_delete_opts_t — options for xrootd_ns_delete().
 */
typedef struct {
    ngx_flag_t recursive;
    ngx_flag_t idempotent_missing;
    ngx_flag_t require_empty_dir;
} xrootd_ns_delete_opts_t;

/*
 * xrootd_ns_copy_opts_t — options for xrootd_ns_local_copy().
 */
typedef struct {
    ngx_flag_t recursive;
    ngx_flag_t overwrite;
    ngx_flag_t overwrite_dirs;
    ngx_flag_t preserve_xattrs;
    ngx_flag_t staged_commit;
} xrootd_ns_copy_opts_t;

/*
 * Shared namespace mutation APIs.
 *
 * These operate on already-resolved, confined paths. They do not perform
 * wire path parsing or token/ACL checks; protocol handlers do those first.
 */

xrootd_ns_result_t xrootd_ns_delete(ngx_log_t *log,
    const char *root_canon, const char *path,
    const xrootd_ns_delete_opts_t *opts);

xrootd_ns_result_t xrootd_ns_mkdir(ngx_log_t *log,
    const char *root_canon, const char *path, mode_t mode,
    ngx_flag_t recursive);

xrootd_ns_result_t xrootd_ns_rename(ngx_log_t *log,
    const char *root_canon, const char *src, const char *dst,
    ngx_flag_t overwrite_dirs);

xrootd_ns_result_t xrootd_ns_local_copy(ngx_log_t *log,
    const char *root_canon, const char *src, const char *dst,
    const xrootd_ns_copy_opts_t *opts);

void xrootd_ns_copy_fattrs(ngx_log_t *log, const char *src, const char *dst);

#endif /* XROOTD_NAMESPACE_OPS_H */
