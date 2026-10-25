/* Shared bounded CVMFS coding input/response contract. Requires native nginx. */
#pragma once
#include "cvmfs.h"
#include "fs/vfs/vfs.h"

typedef struct {
    const char *encoding;
    const char *id_header;
    const char *vary;
    const char *log_label;
    const char *id_label;
} brix_cvmfs_coding_t;

int brix_cvmfs_coding_load(ngx_http_request_t *r, brix_vfs_file_t *file,
    brix_vfs_stat_t *metadata, size_t maximum, size_t *length,
    unsigned char **input, unsigned char **output);
ngx_int_t brix_cvmfs_coding_emit(ngx_http_request_t *r,
    const brix_cvmfs_coding_t *coding, time_t mtime, const char *id,
    unsigned char *output, size_t source_length, size_t output_length);
