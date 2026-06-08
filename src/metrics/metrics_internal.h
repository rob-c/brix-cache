#ifndef NGX_XROOTD_METRICS_INTERNAL_H
#define NGX_XROOTD_METRICS_INTERNAL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "metrics.h"

/* Location config — one boolean per location. */
typedef struct {
    ngx_flag_t  enable;
} ngx_http_xrootd_metrics_loc_conf_t;

extern ngx_module_t ngx_http_xrootd_metrics_module;

/* Buffer chain writer for Prometheus text output. */
#define METRICS_BUF_SIZE  65536

typedef struct {
    ngx_pool_t   *pool;
    ngx_chain_t  *head;
    ngx_chain_t  *tail;
    u_char       *pos;   /* current write cursor in tail buffer        */
    u_char       *last;  /* one-past-end pointer for the tail buffer   */
    size_t        total; /* total bytes emitted across the whole chain */
} metrics_writer_t;

/* writer.c */
ngx_int_t  mw_init(metrics_writer_t *mw, ngx_pool_t *pool);
ngx_int_t  mw_printf(metrics_writer_t *mw, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void       mw_finish(metrics_writer_t *mw);

/* stream.c */
void  xrootd_export_prometheus_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);
void  xrootd_export_stream_cache_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);
void  xrootd_export_stream_proxy_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);
void  xrootd_export_stream_tracking_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);
void  xrootd_export_unified_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);

/* webdav.c */
void  xrootd_export_webdav_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);

/* s3.c */
void  xrootd_export_s3_metrics(metrics_writer_t *mw,
    ngx_xrootd_metrics_t *shm);

/* handler.c */
ngx_int_t  ngx_http_xrootd_metrics_handler(ngx_http_request_t *r);

/* tracking.c — per-VO traffic and unique user identity counting. */
ngx_int_t  xrootd_track_vo_activity(ngx_xrootd_metrics_t *shm, const char *vo_name,
    size_t bytes_tx, size_t bytes_rx);
ngx_int_t  xrootd_track_unique_user(ngx_xrootd_metrics_t *shm, const char *identity,
    size_t identity_len);

#endif /* NGX_XROOTD_METRICS_INTERNAL_H */
