#ifndef NGX_XROOTD_CMS_INTERNAL_H
#define NGX_XROOTD_CMS_INTERNAL_H

#include "ngx_xrootd_module.h"

/*
 * Timing and sizing constants for the CMS heartbeat client.
 *
 *   INITIAL_DELAY   — ms to wait before the first connection attempt after
 *                     the worker starts (lets nginx finish binding ports first).
 *   BACKOFF_INITIAL — ms for the first reconnect delay after a disconnect.
 *   BACKOFF_MAX     — maximum reconnect delay (60 s).
 *   CONNECT_TIMEOUT — ms before TCP connect is considered failed.
 *   HDR_LEN         — fixed-size CMS frame header (8 bytes).
 *   MAX_FRAME       — maximum CMS payload size (4096 bytes).
 *   MIN_FREE_MB     — if free space is below this threshold, report 0 (suspend).
 */
#define NGX_XROOTD_CMS_INITIAL_DELAY   1000
#define NGX_XROOTD_CMS_BACKOFF_INITIAL 6000
#define NGX_XROOTD_CMS_BACKOFF_MAX     60000
#define NGX_XROOTD_CMS_CONNECT_TIMEOUT 5000
#define NGX_XROOTD_CMS_HDR_LEN         8
#define NGX_XROOTD_CMS_MAX_FRAME       4096
#define NGX_XROOTD_CMS_MIN_FREE_MB     100

/*
 * CMS request/reply opcodes (kYR_* from the CMS protocol).
 * Numeric values are wire constants; do not renumber.
 */
#define CMS_RR_LOGIN   0    /* kYR_login: announce server identity to manager */
#define CMS_RR_LOCATE  2    /* kYR_locate: ask manager which server has a path */
#define CMS_RR_AVAIL   12   /* kYR_avail: report available files for a path */
#define CMS_RR_GONE    14   /* kYR_gone: data server path-level deregister */
#define CMS_RR_LOAD    16   /* kYR_load: periodic load/space heartbeat */
#define CMS_RR_SELECT  10   /* kYR_select: manager redirect reply (single host) */
#define CMS_RR_PING    17   /* kYR_ping: manager liveness probe */
#define CMS_RR_PONG    18   /* kYR_pong: reply to kYR_ping */
#define CMS_RR_SPACE   19   /* kYR_space: request available disk space stats */
#define CMS_RR_STATUS  22   /* kYR_status: suspend/resume traffic control */
#define CMS_RR_TRY     24   /* kYR_try: manager redirect reply (ordered list) */

/* kYR_status modifier bits */
#define CMS_ST_SUSPEND  0x01   /* stop accepting new requests */
#define CMS_ST_RESUME   0x02   /* resume accepting requests */

/*
 * CMS variable-length encoding type tags.
 * Fields in CMS frames are packed with a leading type byte followed by the
 * big-endian value.  These tags identify short (2-byte) vs int (4-byte) values.
 */
#define CMS_PT_SHORT   0x80   /* 2-byte big-endian value follows */
#define CMS_PT_INT     0xa0   /* 4-byte big-endian value follows */

/*
 * Login packet constants.
 *   VERSION       — CMS protocol version sent in kYR_login.
 *   MODE          — kYR_DataServer flag: this node exports data files.
 *   MODE_MANAGER  — kYR_Manager flag: this node also manages data servers.
 */
#define CMS_LOGIN_VERSION       3
#define CMS_LOGIN_MODE          0x00000008  /* kYR_DataServer */
#define CMS_LOGIN_MODE_MANAGER  0x00000010  /* kYR_Manager — set when manager_mode on */

/*
 * Per-manager CMS heartbeat context (one instance per CMS manager address).
 *
 * Lifetime: heap-allocated in each worker's init_process hook (each nginx
 * worker maintains its own independent CMS connection to the parent manager)
 * and freed when the worker exits.
 */
struct ngx_xrootd_cms_ctx_s {
    ngx_cycle_t                    *cycle;       /* nginx cycle (for pool, log) */
    ngx_stream_xrootd_srv_conf_t   *conf;        /* server block configuration */
    ngx_peer_connection_t           peer;        /* nginx upstream peer state */
    ngx_connection_t               *connection;  /* active TCP connection (NULL = disconnected) */
    ngx_event_t                     timer;       /* reconnect / heartbeat timer */
    ngx_msec_t                      backoff;     /* current reconnect wait (ms) */
    ngx_uint_t                      logged_in;   /* 1 after kYR_login exchange */
    uint32_t                        next_streamid; /* per-worker monotone counter;
                                                      wraps at UINT32_MAX; used as
                                                      CMS locate correlation key */
    u_char                          inbuf[NGX_XROOTD_CMS_MAX_FRAME]; /* receive accumulation buffer */
    size_t                          in_pos;      /* bytes received so far */
    size_t                          in_need;     /* bytes needed to complete the frame */
};

/* wire.c — big-endian encode/decode */
uint16_t  ngx_xrootd_cms_get16(const u_char *p);
uint32_t  ngx_xrootd_cms_get32(const u_char *p);
void      ngx_xrootd_cms_put16(u_char *p, uint16_t value);
void      ngx_xrootd_cms_put32(u_char *p, uint32_t value);
u_char   *ngx_xrootd_cms_put_short(u_char *p, uint16_t value);
u_char   *ngx_xrootd_cms_put_int(u_char *p, uint32_t value);

/* space.c — filesystem space measurement */
ngx_str_t  ngx_xrootd_cms_export_paths(ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t  ngx_xrootd_cms_stat_space(ngx_stream_xrootd_srv_conf_t *conf,
               uint32_t *total_gb, uint32_t *free_mb, uint32_t *util_pct);

/* send.c — outgoing CMS frames */
ngx_int_t  ngx_xrootd_cms_send_login(ngx_xrootd_cms_ctx_t *ctx);
ngx_int_t  ngx_xrootd_cms_send_load(ngx_xrootd_cms_ctx_t *ctx);
ngx_int_t  ngx_xrootd_cms_send_avail(ngx_xrootd_cms_ctx_t *ctx,
               uint32_t streamid);
ngx_int_t  ngx_xrootd_cms_send_pong(ngx_xrootd_cms_ctx_t *ctx,
               uint32_t streamid);
ngx_int_t  ngx_xrootd_cms_send_locate(ngx_xrootd_cms_ctx_t *ctx,
               uint32_t streamid, const char *path);
uint32_t   ngx_xrootd_cms_next_streamid(ngx_xrootd_cms_ctx_t *ctx);

/* recv.c — incoming frame read loop and dispatch */
void  ngx_xrootd_cms_read_handler(ngx_event_t *ev);

/* connect.c — TCP connection lifecycle, timer, entry point */
void  ngx_xrootd_cms_disconnect(ngx_xrootd_cms_ctx_t *ctx);
void  ngx_xrootd_cms_schedule(ngx_xrootd_cms_ctx_t *ctx, ngx_msec_t delay);
void  ngx_xrootd_cms_schedule_retry(ngx_xrootd_cms_ctx_t *ctx);

#endif /* NGX_XROOTD_CMS_INTERNAL_H */
