/*
 * s3_put_internal.h - private split contract for put.c and its Phase-38 siblings.
 * Not a public API: include only from src/s3/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_S3_PUT_INTERNAL_H
#define BRIX_S3_PUT_INTERNAL_H

#include "s3.h"
#include "aws_chunked.h"
#include "tagging.h"
#include "usermeta.h"
#include "core/http/http_body.h"
#include "core/http/http_headers.h"
#include "core/compat/staged_file.h"
#include "fs/vfs/vfs.h"
#include "fs/path/path.h"
#include "observability/dashboard/dashboard_tracking.h"
#include "auth/impersonate/lifecycle.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

typedef struct {
    ngx_http_request_t   *r;
    brix_vfs_staged_t  *staged;
    size_t                len;
    ssize_t               nwritten;
    int                   io_errno;
    ngx_uint_t            body_mode;
    size_t                body_bytes;
    char                  final_path[PATH_MAX];
    char                  root_canon[PATH_MAX];
} s3_put_aio_t;

typedef struct {
    ngx_http_request_t   *r;
    brix_vfs_staged_t  *staged;
    char                  fs_path[PATH_MAX];
    char                  root_canon[PATH_MAX];
    uint64_t              expected;
    ngx_uint_t            body_mode;
    s3_chunk_trailer_t    trailer;       /* filled by the worker */
    s3_chunk_verify_t     verify;        /* W6a: per-chunk SigV4 verify ctx */
    ngx_int_t             rc;            /* decode result        */
    int                   http_status;   /* decode error status  */
    u_char                window[S3_CHUNK_READ_WINDOW];
} s3_chunk_aio_t;


/* put.c */
const char * s3_dashboard_put_op(ngx_http_request_t *r);
void s3_dashboard_identity(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, char *out, size_t outsz);

/* put_finalize.c */
ngx_int_t s3_commit_put(ngx_http_request_t *r, ngx_log_t *log, const char *root_canon, brix_vfs_staged_t *staged, const char *final_path);
int s3_put_commit_conflict(ngx_http_request_t *r);

/* put_aio.c */
void s3_put_aio_thread(void *data, ngx_log_t *log);
void s3_put_aio_done(ngx_event_t *ev);

/* put.c */
ngx_uint_t s3_put_body_mode(const brix_http_body_summary_t *summary);

/* put_finalize.c */
void s3_put_finalize_error(ngx_http_request_t *r);
void s3_put_finalize_fs_error(ngx_http_request_t *r, int saved_errno);
void s3_put_finalize_empty_ok(ngx_http_request_t *r);
void s3_put_finalize_ok(ngx_http_request_t *r, size_t body_bytes, ngx_uint_t body_mode);
void s3_put_finalize_bad_digest(ngx_http_request_t *r);
void s3_put_finalize_invalid_request(ngx_http_request_t *r);
void s3_put_finalize_codec_error(ngx_http_request_t *r, ngx_int_t status);
int s3_put_checksum_failed(ngx_http_request_t *r, const char *fs_path, const char *root_canon);
void s3_put_finalize_client_error(ngx_http_request_t *r, int status, const char *code, const char *message);

/* put_chunk.c */
void s3_chunk_finalize(ngx_http_request_t *r, const char *root_canon, const char *fs_path, brix_vfs_staged_t *staged, const s3_chunk_trailer_t *trailer, uint64_t expected, ngx_uint_t body_mode);
void s3_chunk_decode_failed(ngx_http_request_t *r, const char *root_canon, brix_vfs_staged_t *staged, int http_status);
void s3_chunk_aio_thread(void *data, ngx_log_t *log);
void s3_build_chunk_verify(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, s3_chunk_verify_t *v);
void s3_chunk_aio_done(ngx_event_t *ev);

/* put.c */
void s3_put_streaming(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf, brix_vfs_staged_t *staged, const char *fs_path, ngx_uint_t body_mode);
void s3_put_body_inner(ngx_http_request_t *r);

#endif /* BRIX_S3_PUT_INTERNAL_H */
