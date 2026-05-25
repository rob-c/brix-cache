#ifndef XROOTD_AIO_H
#define XROOTD_AIO_H

#include "../ngx_xrootd_module.h"

/*
 * AIO — async file I/O via the nginx thread pool, plus response builders.
 *
 * WHY AIO?
 * nginx worker threads are single-threaded and must never block.  Calling
 * pread(2) directly would stall the event loop for the duration of the disk
 * I/O, preventing any other connection from making progress.  Instead we:
 *
 *   1. Allocate a task context struct (e.g. xrootd_read_aio_t) on the heap.
 *   2. Post an ngx_thread_task_t to the nginx thread pool.
 *   3. The thread-pool worker calls *_aio_thread() — pread/pwrite happens here.
 *   4. When done, nginx posts the *_aio_done() callback back to the main thread.
 *   5. The done callback queues the response and calls xrootd_aio_resume() to
 *      wake the connection.
 *
 * While AIO is in flight, ctx->state = XRD_ST_AIO and both read/write events
 * are disarmed.  ctx->destroyed is checked in every done callback so that a
 * callback firing after client disconnect safely discards its work.
 */

/* Build a chain of oksofar+ok bufs from a flat data buffer. */
ngx_chain_t *xrootd_build_chunked_chain(xrootd_ctx_t *ctx,
    ngx_connection_t *c, u_char *databuf, size_t data_total);

/* Build a zero-copy sendfile chain (uses ngx_buf_t with in_file=1). */
ngx_chain_t *xrootd_build_sendfile_chain(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int fd, const char *path, off_t offset,
    size_t data_total, u_char **base_out);

/* Reusable scratch buffers — avoids pool growth on busy sessions. */
u_char *xrootd_get_read_scratch(xrootd_ctx_t *ctx, ngx_connection_t *c,
    size_t need);
u_char *xrootd_get_read_header_scratch(xrootd_ctx_t *ctx,
    ngx_connection_t *c, size_t need);
u_char *xrootd_get_write_scratch(xrootd_ctx_t *ctx, ngx_connection_t *c,
    size_t need);
void xrootd_release_read_buffer(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf);

/*
 * Internal kXR_readv execution plan.
 *
 * The response buffer is laid out before any disk I/O starts:
 *   [wire segment header][segment bytes][wire segment header][segment bytes]...
 *
 * Each descriptor points into that final response buffer.  The read worker can
 * therefore pass payload_ptr directly to preadv(), avoiding a copy after I/O
 * completes while keeping the wire headers adjacent to their data.
 */
typedef struct {
    int       fd;
    int       handle_index;
    off_t     offset;
    uint32_t  read_length;
    u_char   *header_read_length_ptr;
    u_char   *payload_ptr;
} xrootd_readv_seg_desc_t;

ngx_int_t xrootd_readv_read_segments(xrootd_readv_seg_desc_t *segments,
    size_t segment_count, size_t *bytes_read_total, char *error_message,
    size_t error_message_len);

/*
 * Per-task context structs passed to the nginx thread-pool.
 * Each struct is heap-allocated before ngx_thread_task_post() and freed
 * in the done callback after the result is consumed on the main thread.
 */

typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    ngx_stream_xrootd_srv_conf_t  *conf;
    int       fd;
    int       handle_idx;
    off_t     offset;
    size_t    rlen;
    u_char   *databuf;
    u_char    streamid[2];
    ssize_t   nread;
    int       io_errno;
} xrootd_read_aio_t;

typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    ngx_stream_xrootd_srv_conf_t  *conf;
    int            fd;
    int            handle_idx;
    off_t          offset;
    const u_char  *data;
    size_t         len;
    u_char         streamid[2];
    char           path[PATH_MAX];
    int64_t        req_offset;
    ngx_uint_t     is_pgwrite;
    ssize_t        nwritten;
    int            io_errno;
    u_char        *payload_to_free;
} xrootd_write_aio_t;

typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    size_t                         segment_count;
    xrootd_readv_seg_desc_t       *segments;
    u_char                        *response_buffer;
    u_char  streamid[2];
    size_t  bytes_read_total;
    size_t  response_bytes;
    int     io_error;
    char    err_msg[64];
} xrootd_readv_aio_t;

typedef struct {
    int           fd;
    int           handle_idx;
    off_t         offset;
    const u_char *data;
    uint32_t      wlen;
} xrootd_writev_seg_desc_t;

typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    size_t                         n_segs;
    xrootd_writev_seg_desc_t      *segs;
    u_char                        *payload_buf; /* detached payload; freed by done handler */
    u_char  streamid[2];
    int     do_sync;
    size_t  bytes_total;  /* set by thread */
    int     io_error;     /* 0=ok, 1=pwrite error, 2=short write */
    char    err_msg[64];  /* set by thread on error */
} xrootd_writev_aio_t;

/*
 * xrootd_pgread_aio_t — async kXR_pgread context.
 *
 * scratch layout: [0 .. rlen-1] = flat file data read by thread;
 *                 [rlen .. rlen+out_size-1] = interleaved data+CRC written by thread.
 * The completion callback builds the chain from scratch + rlen.
 */
typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    int       fd;
    int       handle_idx;
    off_t     offset;
    size_t    rlen;       /* requested bytes; flat portion size in scratch */
    u_char   *scratch;    /* single alloc: flat data then interleaved output */
    size_t    out_size;   /* interleaved bytes written (set by thread) */
    u_char    streamid[2];
    ssize_t   nread;      /* actual pread return (set by thread) */
    int       io_errno;
} xrootd_pgread_aio_t;

/*
 * xrootd_dirlist_aio_t — async kXR_dirlist context.
 *
 * The main thread allocates a response buffer from c->pool (large block,
 * freed via ngx_pfree after drain), copies auth-checked path/algo/flags
 * into the struct, then posts to the thread pool.
 *
 * The worker thread opens the directory, iterates entries, calls
 * xrootd_dirlist_checksum_token() when kXR_dcksm is requested, and builds
 * the complete wire response (kXR_oksofar chunks + final kXR_ok frame)
 * directly into response[0..response_len).  No pool access in the thread.
 *
 * response_cap is XROOTD_DIRLIST_AIO_RESPONSE_MAX (default 4 MiB).  If the
 * listing would overflow, io_errno is set to E2BIG and a kXR_IOError is sent.
 */
#define XROOTD_DIRLIST_AIO_RESPONSE_MAX  (4 * 1024 * 1024)

typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    ngx_stream_xrootd_srv_conf_t  *conf;
    u_char      streamid[2];
    char        resolved[PATH_MAX];  /* absolute path, already auth-checked   */
    char        cksum_algo[32];      /* e.g. "adler32", "sha256"              */
    ngx_flag_t  want_stat;
    ngx_flag_t  want_cksum;
    u_char     *response;            /* ngx_palloc'd; freed after full drain  */
    size_t      response_cap;        /* = XROOTD_DIRLIST_AIO_RESPONSE_MAX     */
    size_t      response_len;        /* bytes written by thread               */
    int         io_errno;            /* 0 = success                           */
    char        err_msg[64];
} xrootd_dirlist_aio_t;

/* Resume the nginx event loop after an AIO task completes. */
ngx_flag_t xrootd_aio_restore_stream(xrootd_ctx_t *ctx,
    const u_char streamid[2]);
ngx_flag_t xrootd_aio_restore_request(xrootd_ctx_t *ctx,
    const u_char streamid[2]);
ngx_int_t xrootd_aio_post_task(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_pool_t *pool, ngx_thread_task_t *task,
    const char *fallback_log, ngx_flag_t *posted);
void xrootd_aio_resume(ngx_connection_t *c);

/* Main-thread completion callbacks (post AIO to event loop). */
void xrootd_read_aio_done(ngx_event_t *ev);
void xrootd_write_aio_done(ngx_event_t *ev);
void xrootd_writev_write_aio_done(ngx_event_t *ev);
void xrootd_readv_aio_done(ngx_event_t *ev);
void xrootd_pgread_aio_done(ngx_event_t *ev);
void xrootd_dirlist_aio_done(ngx_event_t *ev);

/* Thread-pool worker functions (run on a pool thread). */
void xrootd_read_aio_thread(void *data, ngx_log_t *log);
void xrootd_write_aio_thread(void *data, ngx_log_t *log);
void xrootd_writev_write_aio_thread(void *data, ngx_log_t *log);
void xrootd_readv_aio_thread(void *data, ngx_log_t *log);
void xrootd_pgread_aio_thread(void *data, ngx_log_t *log);
void xrootd_dirlist_aio_thread(void *data, ngx_log_t *log);

#endif /* XROOTD_AIO_H */
