#ifndef BRIX_SHARED_FILE_SERVE_H
#define BRIX_SHARED_FILE_SERVE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "fs/vfs/vfs.h"

/* Outcome codes returned in brix_http_serve_result_t.range_result */
#define BRIX_SERVE_RANGE_FULL        0
#define BRIX_SERVE_RANGE_PARTIAL     1
#define BRIX_SERVE_RANGE_UNSATISFIED 2

/*
 * Pre-header-send hook: called after range parse and set_file_headers but
 * before brix_http_send_file_range fires.  WebDAV uses this to add
 * XrdHttp checksum/status headers.  Set to NULL to skip.
 */
typedef void (*brix_http_pre_header_fn)(ngx_http_request_t *r,
    ngx_fd_t fd, off_t file_size, void *userdata);

typedef struct {
    uint8_t                    xfer_proto;    /* BRIX_XFER_PROTO_WEBDAV / _S3 */
    const char                *op_name;       /* "GET" / "GetObject"            */
    const char                *identity;      /* caller-resolved display string  */
    unsigned                   etag_flags;    /* BRIX_ETAG_WEAK or 0           */
    ngx_flag_t                 compress;      /* phase-42: allow outbound codec  */
    brix_http_pre_header_fn  pre_header_send;
    void                      *pre_header_ud;
} brix_http_serve_opts_t;

typedef struct {
    int    range_result;   /* BRIX_SERVE_RANGE_* — for caller metric dispatch */
    off_t  bytes_sent;     /* 0 if header_only / 416 / error                    */
} brix_http_serve_result_t;

/*
 * brix_http_serve_file_ranged — shared range-parse → headers → send pipeline.
 *
 * Takes an already-open, already-stat'd vfs file handle (fh).  Closes fh
 * internally before the body send (success or error).  Callers must NOT
 * close fh after this call returns.
 *
 * result->range_result and result->bytes_sent let the caller increment
 * protocol-specific range and bytes metrics.
 *
 * Returns NGX_OK, NGX_ERROR, or an HTTP status code (416, 500).
 */
ngx_int_t brix_http_serve_file_ranged(ngx_http_request_t *r,
    brix_vfs_file_t *fh, const brix_vfs_stat_t *vst,
    const char *fs_path, const brix_http_serve_opts_t *opts,
    brix_http_serve_result_t *result);

#endif /* BRIX_SHARED_FILE_SERVE_H */
