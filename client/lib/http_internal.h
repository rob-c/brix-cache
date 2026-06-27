/*
 * http_internal.h - private split contract for http.c and its Phase-38 siblings.
 * Not a public API: include only from client/lib/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_HTTP_INTERNAL_H
#define XROOTD_HTTP_INTERNAL_H

#include "xrdc.h"
#include "compat/host_format.h"   
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
    xrdc_io *io;
    char    *lo;        /* leftover buffer (header buf) */
    size_t   lo_len;    /* valid leftover bytes */
    size_t   lo_off;    /* consumed so far */
    int      timeout_ms;
} body_src;


/* http_req.c */
ssize_t httpx_read_some(xrdc_io *io, void *buf, size_t n, int timeout_ms, xrdc_status *st);

/* http.c */
int ci_contains(const char *hay, const char *needle);
size_t dechunk(char *b, size_t len);
void httpx_parse(char *buf, size_t total, xrdc_http_resp *resp);

/* http_req.c */
int httpx_body_complete(const char *buf, size_t total, size_t body_off, long long clen, int chunked);
int httpx_exchange(xrdc_io *io, const char *host, int port, const char *method, const char *path, const char *extra_headers, const void *body, size_t blen, int timeout_ms, xrdc_http_resp *resp, xrdc_status *st);

/* http.c */
int httpx_connect(xrdc_io *io, const char *host, int port, int tls, int verify, const char *ca_dir, int timeout_ms, void **tls_ctx, xrdc_status *st);
ssize_t bsrc_read(body_src *s, void *buf, size_t n, xrdc_status *st);
int bsrc_getline(body_src *s, char *out, size_t outsz, xrdc_status *st);
int write_all_fd(int fd, const char *buf, size_t n, xrdc_status *st);

/* http_download.c */
int stream_clen(body_src *src, long long remaining, int out_fd, long long *written, xrdc_status *st);
int stream_eof(body_src *src, int out_fd, long long *written, xrdc_status *st);
int stream_chunked(body_src *src, int out_fd, long long *written, xrdc_status *st);
int read_resp_headers(xrdc_io *io, char *hdr, size_t hdrcap, int timeout_ms, int *status, size_t *total, size_t *body_off, xrdc_status *st);
int raw_header(const char *hdr, const char *name, char *out, size_t outsz);
int httpx_download_body(xrdc_io *io, char *hdr, size_t total, size_t body_off, int out_fd, int timeout_ms, long long *body_len, xrdc_status *st);
int httpx_download_exchange(xrdc_io *io, const char *host, int port, const char *path, const char *extra_headers, long long start_off, int out_fd, int timeout_ms, int *http_status, long long *body_len, xrdc_status *st);

/* http.c */
int httpx_window_ms(void);

/* http_upload.c */
int httpx_upload_body(xrdc_io *io, int in_fd, long long clen, xrdc_status *st);
int httpx_upload_response(xrdc_io *io, int timeout_ms, int *http_status, xrdc_status *st);
int httpx_upload_exchange(xrdc_io *io, const char *host, int port, const char *path, const char *extra_headers, int in_fd, long long clen, int timeout_ms, int *http_status, xrdc_status *st);
long long httpx_parse_upload_offset(const char *hdr, size_t len);
int httpx_upload_chunk(xrdc_io *io, const char *host, int port, const char *path, const char *extra_headers, int in_fd, long long off, long long chunk_len, long long total, int timeout_ms, int *status_out, long long *srv_off_out, xrdc_status *st);

#endif /* XROOTD_HTTP_INTERNAL_H */
