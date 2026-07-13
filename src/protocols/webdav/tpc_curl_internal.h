/*
 * tpc_curl_internal.h - private split contract for tpc_curl.c and its Phase-38 siblings.
 * Not a public API: include only from src/webdav/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_TPC_CURL_INTERNAL_H
#define BRIX_TPC_CURL_INTERNAL_H

#include "webdav.h"
#include "fs/backend/sd.h"   
#include "tpc/common/registry.h"
#include "core/compat/net_target.h"
#include "core/compat/host_format.h"  
#include <curl/curl.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
typedef struct {
    brix_pmark_conf_t *pm;
    ngx_uint_t           exp;
    ngx_uint_t           act;
    int                  peer_is_src;   
    int                  fd;            
    char                 app[32];
    ngx_log_t           *log;
    unsigned             active:1;
} webdav_tpc_pmark_rec_t;

#if defined(CURLOPT_OPENSOCKETFUNCTION) && defined(CURLOPT_CLOSESOCKETFUNCTION)
#define WEBDAV_TPC_PMARK_SOCKCB 1

#endif /* socket callbacks available */
typedef struct {
    uint64_t   transfer_id;
    ngx_log_t *log;
    int        is_push;
    off_t      last_done;
} webdav_tpc_curl_progress_t;

typedef struct {
    int                fd;
    off_t              cur_offset;   /* increments with each write */
    ngx_uint_t         stream_idx;
    tpc_ms_progress_t *progress;     /* NULL if progress tracking disabled */
} ms_stream_ctx_t;

/* webdav_tpc_ms_ctx_t — shared bundle for a parallel Range-based pull (driver +
 * pmark callback). Arrays are owned by the driver; the ctx aliases them. */
typedef struct {
    ngx_log_t                        *log;
    ngx_http_brix_webdav_loc_conf_t  *conf;
    const char                       *source_url;
    const char                       *tmp_path;
    ngx_array_t                      *transfer_headers;
    const char                       *user_cert;   /* per-user pull-leg cert (or NULL) */
    const char                       *user_key;    /* per-user pull-leg key  (or NULL) */
    ngx_uint_t                        n_streams;
    off_t                             total_size;
    int                               fd;
    CURLM                            *cm;
    CURL                            **easy;
    struct curl_slist               **hdrs;
    struct curl_slist               **resolve;
    ms_stream_ctx_t                  *write_ctx;
    tpc_ms_progress_t                *progress;
#ifdef WEBDAV_TPC_PMARK_SOCKCB
    webdav_tpc_pmark_rec_t           *pmrec;
#endif
} webdav_tpc_ms_ctx_t;

#ifndef BRIX_TPC_CONNECT_TIMEOUT_SECS
#define BRIX_TPC_CONNECT_TIMEOUT_SECS  30L
#endif
#ifdef CURLOPT_XFERINFOFUNCTION
#endif


/* tpc_curl_pmark.c */
curl_socket_t webdav_tpc_pmark_opensocket(void *clientp, curlsocktype purpose, struct curl_sockaddr *address);
int webdav_tpc_pmark_closesocket(void *clientp, curl_socket_t item);
void webdav_tpc_pmark_attach(CURL *curl, webdav_tpc_pmark_rec_t *rec, ngx_http_brix_webdav_loc_conf_t *conf, int is_push, const char *file_path, ngx_log_t *log);

/* tpc_curl_setup.c */
int tpc_curl_secure(CURL *curl, ngx_http_brix_webdav_loc_conf_t *conf, const char *url, ngx_log_t *log, struct curl_slist **resolve_out);
void tpc_curl_apply_stall_bounds(CURL *curl, ngx_http_brix_webdav_loc_conf_t *conf);
int tpc_curl_apply_conf(CURL *curl, ngx_http_brix_webdav_loc_conf_t *conf, const char *url, ngx_array_t *transfer_headers, ngx_log_t *log, const char *user_cert, const char *user_key, struct curl_slist **hdrs_out, struct curl_slist **resolve_out);
off_t tpc_curl_head_size(ngx_log_t *log, ngx_http_brix_webdav_loc_conf_t *conf, const char *url, ngx_array_t *transfer_headers, const char *user_cert, const char *user_key);

/* tpc_curl_pmark.c */
size_t ms_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);
int webdav_tpc_curl_progress(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);
ngx_int_t webdav_tpc_curl_finish(ngx_int_t rc, CURL *curl, struct curl_slist *hdrs, struct curl_slist *resolve, FILE *fp);

/* tpc_curl.c */
/* Perform one single-stream curl transfer described by @req.  @is_push selects
 * direction (1=push export->url, 0=pull url->staged temp); @log_tag is the short
 * "push"/"pull" label for log lines.  NGX_OK / NGX_HTTP_* on failure. */
ngx_int_t webdav_tpc_run_curl_core(ngx_log_t *log,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_array_t *transfer_headers,
    int is_push, const char *file_path, const char *url, const char *log_tag,
    uint64_t transfer_id, const char *user_cert, const char *user_key);
/* Tear down a curl_multi run and record the success/error metric keyed by @rc,
 * which is returned unchanged. */
ngx_int_t webdav_tpc_run_curl_multi_finish(ngx_int_t rc, CURLM *cm, CURL **easy,
    struct curl_slist **hdrs, struct curl_slist **resolve,
    ngx_uint_t n_streams, int fd);

#endif /* BRIX_TPC_CURL_INTERNAL_H */
