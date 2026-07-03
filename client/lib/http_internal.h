/*
 * http_internal.h - private split contract for http.c and its Phase-38 siblings.
 * Not a public API: include only from client/lib/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_HTTP_INTERNAL_H
#define BRIX_HTTP_INTERNAL_H

#include "brix.h"
#include "core/compat/host_format.h"   
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define XRDC_HTTP_MAX (1u << 20)   

#define XRDC_HTTPX_MAX (8u << 20)   /* 8 MiB body ceiling for the deep-dive */
#define XRDC_XFER_BUF (1u << 16)   /* 64 KiB socket↔fd window */
#define XRDC_HDR_CAP  (1u << 14)   /* 16 KiB response-header ceiling */
typedef struct {
    brix_io *io;
    char    *lo;        /* leftover buffer (header buf) */
    size_t   lo_len;    /* valid leftover bytes */
    size_t   lo_off;    /* consumed so far */
    int      timeout_ms;
} body_src;


/* http_req.c */
ssize_t httpx_read_some(brix_io *io, void *buf, size_t n, int timeout_ms, brix_status *st);

/* http.c */
int ci_contains(const char *hay, const char *needle);
size_t dechunk(char *b, size_t len);
void httpx_parse(char *buf, size_t total, brix_http_resp *resp);

/* http_req.c */
int httpx_body_complete(const char *buf, size_t total, size_t body_off, long long clen, int chunked);
int httpx_exchange(brix_io *io, const char *host, int port, const char *method, const char *path, const char *extra_headers, const void *body, size_t blen, int timeout_ms, brix_http_resp *resp, brix_status *st);

/* http.c */
int httpx_connect(brix_io *io, const char *host, int port, int tls, int verify, const char *ca_dir, int timeout_ms, void **tls_ctx, brix_status *st);
ssize_t bsrc_read(body_src *s, void *buf, size_t n, brix_status *st);
int bsrc_getline(body_src *s, char *out, size_t outsz, brix_status *st);
int write_all_fd(int fd, const char *buf, size_t n, brix_status *st);

/* http_download.c */
int stream_clen(body_src *src, long long remaining, int out_fd, long long *written, brix_status *st);
int stream_eof(body_src *src, int out_fd, long long *written, brix_status *st);
int stream_chunked(body_src *src, int out_fd, long long *written, brix_status *st);
int read_resp_headers(brix_io *io, char *hdr, size_t hdrcap, int timeout_ms, int *status, size_t *total, size_t *body_off, brix_status *st);
int raw_header(const char *hdr, const char *name, char *out, size_t outsz);
int httpx_download_body(brix_io *io, char *hdr, size_t total, size_t body_off, int out_fd, int timeout_ms, long long *body_len, brix_status *st);
int httpx_download_exchange(brix_io *io, const char *host, int port, const char *path, const char *extra_headers, long long start_off, int out_fd, int timeout_ms, int *http_status, long long *body_len, brix_status *st);

/* http.c */
int httpx_window_ms(void);

/* http_upload.c — the body is pulled via `src(src_ctx, buf, base_off + consumed,
 * …)`, so the transport reads its source by absolute offset (no fd, no lseek). */
int httpx_upload_body(brix_io *io, brix_http_body_src_fn src, void *src_ctx, long long base_off, long long clen, brix_status *st);
int httpx_upload_response(brix_io *io, int timeout_ms, int *http_status, brix_status *st);
int httpx_upload_exchange(brix_io *io, const char *host, int port, const char *path, const char *extra_headers, brix_http_body_src_fn src, void *src_ctx, long long clen, int timeout_ms, int *http_status, brix_status *st);
long long httpx_parse_upload_offset(const char *hdr, size_t len);
int httpx_upload_chunk(brix_io *io, const char *host, int port, const char *path, const char *extra_headers, brix_http_body_src_fn src, void *src_ctx, long long off, long long chunk_len, long long total, int timeout_ms, int *status_out, long long *srv_off_out, brix_status *st);

#endif /* BRIX_HTTP_INTERNAL_H */
