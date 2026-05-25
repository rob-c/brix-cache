#ifndef XROOTD_CACHE_INTERNAL_H
#define XROOTD_CACHE_INTERNAL_H

#include "../ngx_xrootd_module.h"


/*
 * Cache fill operation constants.
 *
 *   FETCH_CHUNK     — bytes requested per kXR_read call to the origin.
 *   IO_TIMEOUT      — maximum seconds for any single origin I/O call.
 *   LOCK_POLL_USEC  — poll interval (usleep) while waiting for a fetch lock.
 *   PART_SUFFIX     — suffix appended to the cache path during an in-progress
 *                     fetch; renamed away atomically on completion.
 *   LOCK_SUFFIX     — suffix appended to the cache path for the O_EXCL lock
 *                     file that serialises concurrent fetches of the same file.
 *   EVICT_LOCK_NAME — name of the directory-level eviction lock file.
 */
#define XROOTD_CACHE_FETCH_CHUNK      (1024 * 1024)
#define XROOTD_CACHE_IO_TIMEOUT       30
#define XROOTD_CACHE_LOCK_POLL_USEC   200000
#define XROOTD_CACHE_PART_SUFFIX      ".ngx-xrootd-part"
#define XROOTD_CACHE_LOCK_SUFFIX      ".ngx-xrootd-lock"
#define XROOTD_CACHE_EVICT_LOCK_NAME  ".ngx-xrootd-evict-lock"

/*
 * xrootd_cache_origin_conn_t — TCP/TLS connection to the origin XRootD server
 * for the cache-fill path.
 *
 * Lifetime: stack-allocated in xrootd_cache_fetch_origin(); closed with
 * xrootd_cache_origin_close() before the fill thread exits.  The SSL context
 * (ssl_ctx) is borrowed from conf->cache_ssl_ctx — do NOT free it here.
 */
typedef struct {
    int      fd;          /* connected socket fd; -1 when not connected */
    SSL_CTX *ssl_ctx;     /* borrowed TLS context; owned by srv_conf (not freed here) */
    SSL     *ssl;         /* per-connection TLS state; freed by xrootd_cache_origin_close */
} xrootd_cache_origin_conn_t;

/*
 * xrootd_cache_fill_t — per-request cache-fill task context.
 *
 * Heap-allocated before ngx_thread_task_post() and freed in
 * xrootd_cache_fill_done() after the result is consumed on the main thread.
 *
 * Path fields:
 *   clean_path — canonicalised client path (no leading slash ambiguity)
 *   cache_path — absolute path under cache_root where the file is stored
 *   part_path  — cache_path + PART_SUFFIX (in-progress download)
 *   lock_path  — cache_path + LOCK_SUFFIX (O_EXCL serialisation lock)
 *
 * Error fields (set by the fill thread; read on the main thread):
 *   result    — 0 = success, non-zero = error
 *   xrd_error — XRootD error code (kXR_*) to send to the client
 *   sys_errno — errno from the failing syscall (logged, not sent to client)
 *   err_msg   — human-readable description (sent as the error string)
 */
typedef struct {
    ngx_connection_t              *c;          /* client connection */
    xrootd_ctx_t                  *ctx;        /* per-connection XRootD context */
    ngx_stream_xrootd_srv_conf_t  *conf;       /* server config block */
    u_char    streamid[2];                     /* echoed back in the response */
    uint16_t  options;                         /* kXR_open options from the client */
    uint16_t  mode_bits;                       /* kXR_open mode bits */
    char      clean_path[PATH_MAX];            /* canonicalised client path */
    char      cache_path[PATH_MAX];            /* absolute cache file path */
    char      part_path[PATH_MAX];             /* in-progress download path */
    char      lock_path[PATH_MAX];             /* O_EXCL serialisation lock path */
    off_t     file_size;   /* file size from origin open (kXR_retstat); 0 = unknown */
    int       result;      /* 0 = success; non-zero = failure */
    int       xrd_error;   /* XRootD error code on failure */
    int       sys_errno;   /* errno on failure */
    char      err_msg[256]; /* human-readable error description */
} xrootd_cache_fill_t;

/*
 * xrootd_wt_flush_t — write-through close/sync task context.
 *
 * The flush worker mirrors one local file to an XRootD origin by replacing the
 * origin copy with the current local contents, then issuing truncate, sync, and
 * close on the origin handle.  Async close owns a copy of this structure in an
 * nginx thread task; sync close uses it on the stack.
 */
typedef struct {
    ngx_stream_xrootd_srv_conf_t  *conf;
    ngx_log_t                    *log;
    ngx_xrootd_srv_metrics_t      *metrics;
    char                          local_path[PATH_MAX];
    char                          origin_path[PATH_MAX];
    size_t                        bytes_flushed;
    uint16_t                      mode_bits;
    int                           result;
    int                           xrd_error;
    int                           sys_errno;
    char                          err_msg[256];
} xrootd_wt_flush_t;

void xrootd_cache_set_error(xrootd_cache_fill_t *t, int xrd_error,
    int sys_errno, const char *msg);
void xrootd_cache_set_syserror(xrootd_cache_fill_t *t, int xrd_error,
    const char *prefix);

int xrootd_cache_io_send(xrootd_cache_origin_conn_t *oc, const void *buf,
    size_t len);
int xrootd_cache_io_recv_exact(xrootd_cache_origin_conn_t *oc, void *buf,
    size_t len);
int xrootd_cache_fd_write_all(int fd, const void *buf, size_t len);

int xrootd_cache_append_suffix(char *dst, size_t dstsz, const char *path,
    const char *suffix);
int xrootd_cache_ensure_parent(const char *path);
int xrootd_cache_file_ready(const char *path);

int xrootd_cache_wait_or_lock(xrootd_cache_fill_t *t, int *owned);

void xrootd_cache_origin_close(xrootd_cache_origin_conn_t *oc);
int xrootd_cache_origin_connect(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc);
int xrootd_cache_origin_connect_addr(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const ngx_str_t *host, uint16_t port);

int xrootd_cache_read_response(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, uint16_t *status, u_char **body,
    uint32_t *dlen, uint32_t max_body);
void xrootd_cache_set_origin_error(xrootd_cache_fill_t *t, u_char *body,
    uint32_t dlen, const char *fallback);

int xrootd_cache_origin_bootstrap(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc);
int xrootd_cache_origin_open(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, u_char fhandle[XRD_FHANDLE_LEN]);
int xrootd_cache_origin_open_write(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *path, uint16_t mode_bits,
    u_char fhandle[XRD_FHANDLE_LEN]);
void xrootd_cache_origin_close_file(xrootd_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN]);
int xrootd_cache_origin_read_chunk(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    int outfd, uint64_t offset, size_t want, size_t *got);
int xrootd_cache_origin_write_chunk(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t offset, const u_char *data, size_t len);
int xrootd_cache_origin_truncate(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t length);
int xrootd_cache_origin_sync(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN]);

ngx_int_t xrootd_wt_flush_on_close(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path);
ngx_int_t xrootd_wt_flush_sync_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path,
    uint16_t fail_status);
void xrootd_wt_flush_thread(void *data, ngx_log_t *log);
void xrootd_wt_flush_done(ngx_event_t *ev);

int xrootd_cache_fetch_origin(xrootd_cache_fill_t *t);
void xrootd_cache_evict_if_needed(xrootd_cache_fill_t *t,
    const char *protect_path, ngx_log_t *log);
void xrootd_cache_fill_thread(void *data, ngx_log_t *log);
void xrootd_cache_fill_done(ngx_event_t *ev);


#endif /* XROOTD_CACHE_INTERNAL_H */
