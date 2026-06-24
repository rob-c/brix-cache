#ifndef XROOTD_AIO_H
#define XROOTD_AIO_H

#include "../ngx_xrootd_module.h"
#include "../compat/pgio.h"   /* xrdp_pg_bad_t — pgwrite CSE bad-page list */
#include "../fs/vfs_io_core.h"

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

#if (NGX_THREADS)
/*
 * xrootd_task_bind — wire a thread function and done callback into an
 * ngx_thread_task_t.  task->event.data must point back to task so the
 * done callback can recover it from ev->data.
 */
static ngx_inline void
xrootd_task_bind(ngx_thread_task_t *task,
    void               (*thread_fn)(void *data, ngx_log_t *log),
    ngx_event_handler_pt done_fn)
{
    task->handler       = thread_fn;
    task->event.handler = done_fn;
    task->event.data    = task;
}
#endif

/* Build a chain of oksofar+ok bufs from a flat data buffer. */
ngx_chain_t *xrootd_build_chunked_chain(xrootd_ctx_t *ctx,
    ngx_connection_t *c, u_char *databuf, size_t data_total);

/* Build one memory-backed response chunk with an explicit wire status
 * (kXR_oksofar / kXR_ok) — used by the Phase 31 windowed-read loop. */
ngx_chain_t *xrootd_build_window_chain(xrootd_ctx_t *ctx,
    ngx_connection_t *c, u_char *databuf, size_t data_total, uint16_t status);

/* Build a zero-copy sendfile chain (uses ngx_buf_t with in_file=1). */
ngx_chain_t *xrootd_build_sendfile_chain(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int fd, const char *path, off_t offset,
    size_t data_total, u_char **base_out);

/* Build the kXR_pgread response chain ([pgRead status header][encoded page
 * data]); shared by the synchronous pgread handler and the AIO completion.
 * Returns the chain head, or NULL on allocation failure (caller cleans up). */
ngx_chain_t *xrootd_build_pgread_chain(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int64_t offset, u_char *data, uint32_t out_size);

/*
 * Reusable per-connection scratch buffers — avoid pool growth on busy
 * sessions.  xrootd_get_pool_scratch() grows a single pool-anchored buffer
 * slot only when the current allocation is too small; XROOTD_GET_SCRATCH()
 * is the call-site sugar that names the ctx slot/size fields to use:
 *
 *   buf = XROOTD_GET_SCRATCH(ctx, c, read_scratch, read_scratch_size, need);
 */
u_char *xrootd_get_pool_scratch(ngx_pool_t *pool, u_char **slot,
    size_t *slot_size, size_t need);

#define XROOTD_GET_SCRATCH(ctx, c, slot_field, sz_field, need)  \
    xrootd_get_pool_scratch((c)->pool, &(ctx)->slot_field,      \
                            &(ctx)->sz_field, (need))

/* Return a response data buffer when a request completes.  NULL is a no-op.
 * If buf is one of the reusable per-connection scratch slots (read_scratch /
 * read_hdr_scratch / write_scratch) it is KEPT for reuse; any other buffer is
 * ngx_pfree'd back to c->pool.  Do not pass a raw-heap buffer not owned by the
 * pool other than those scratch slots. */
void xrootd_release_read_buffer(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf);

/* Borrow a per-in-flight data buffer from the connection read pool (rd_pool),
 * grown to >= need bytes — see xrootd_acquire_read_buffer in buffers.c.  Gives a
 * memory-backed read its own buffer so the read path can pipeline; returned to
 * the pool by xrootd_release_read_buffer when the response drains.  NULL on OOM
 * (or if the pool is unexpectedly exhausted). */
u_char *xrootd_acquire_read_buffer(xrootd_ctx_t *ctx, ngx_connection_t *c,
    size_t need);

/*
 * Shrink per-session transfer scratch buffers back to XROOTD_READ_WINDOW once a
 * large request has fully drained.  Call only between requests (state
 * XRD_ST_REQ_HEADER, nothing buffered) — see the recv loop.
 */
void xrootd_trim_scratch(xrootd_ctx_t *ctx, ngx_connection_t *c);

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
typedef xrootd_vfs_readv_seg_t xrootd_readv_seg_desc_t;

/* Execute the I/O for a built readv plan: validate every segment (rejects
 * negative offsets and offset+length overflow), coalesce adjacent same-fd
 * segments into grouped preadv() calls (<= 64 iovecs each, EINTR-retried), and
 * read straight into each descriptor's payload_ptr.  Also rewrites each
 * segment's wire header_read_length_ptr.  *bytes_read_total accumulates bytes
 * read.  segment_count must be 1..XROOTD_READV_MAXSEGS.  Returns NGX_OK, or
 * NGX_ERROR (short read past EOF, bad count, OOM, or I/O error) with a message
 * written into error_message (caller-owned, error_message_len bytes).
 * Safe to call off the main thread; touches no nginx pool or ctx state. */
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
    /* pgwrite CSE: pages that failed CRC32c in this request. When non-empty the
     * done callback sends a CSE retransmit frame instead of a plain status. */
    size_t         bad_page_count;
    xrdp_pg_bad_t  bad_pages[kXR_pgMaxEpr];
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

typedef xrootd_vfs_writev_seg_t xrootd_writev_seg_desc_t;

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
 * scratch holds the final interleaved [CRC32c(4)][data] wire output starting at
 * offset 0: the worker reads file data straight into the data gaps (no flat copy
 * region) and CRCs each page in place, so out_size <= rlen + pages*4. The
 * completion callback builds the data chain from scratch[0 .. out_size-1].
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
 * The worker thread consumes a loop-confined directory fd, iterates entries, calls
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
    int         dirfd;               /* beneath-confined directory fd         */
    ngx_flag_t  want_stat;
    ngx_flag_t  want_cksum;
    u_char     *response;            /* ngx_palloc'd; freed after full drain  */
    size_t      response_cap;        /* = XROOTD_DIRLIST_AIO_RESPONSE_MAX     */
    size_t      response_len;        /* bytes written by thread               */
    int         io_errno;            /* 0 = success                           */
    char        err_msg[64];
} xrootd_dirlist_aio_t;

/* --- Resume the nginx event loop after an AIO task completes. --- */

/* Liveness guard for a done callback: copies the saved 2-byte streamid into
 * ctx->cur_streamid so the response is built for the right request.  Returns 1
 * if the connection is still alive, 0 if ctx->destroyed (caller must then touch
 * nothing further — ctx/c may be stale). */
ngx_flag_t xrootd_aio_restore_stream(xrootd_ctx_t *ctx,
    const u_char streamid[2]);

/* Like xrootd_aio_restore_stream, but also resets state to XRD_ST_REQ_HEADER
 * (hdr_pos=0) so the recv loop can read the next request.  Use from done
 * callbacks that complete the request cycle after queuing the response.
 * Returns 1 if alive, 0 if destroyed. */
ngx_flag_t xrootd_aio_restore_request(xrootd_ctx_t *ctx,
    const u_char streamid[2]);

/* Post a pre-built task to the thread pool and set ctx->state = XRD_ST_AIO.
 * Always returns NGX_OK; the outcome is reported via *posted: 1 = queued (AIO
 * in flight), 0 = NOT queued, so the caller must fall back to synchronous I/O.
 * *posted is 0 when pool is NULL (no pool configured) or the pool queue is full
 * (logs fallback_log at WARN).  Never fails the request itself. */
ngx_int_t xrootd_aio_post_task(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_pool_t *pool, ngx_thread_task_t *task,
    const char *fallback_log, ngx_flag_t *posted);

/* Schedule the next event-loop step after a done callback has queued its
 * response: re-arms the write event if state is XRD_ST_SENDING, else the read
 * event so already-buffered pipelined requests run before the next epoll_wait.
 * No-op if the connection was destroyed; finalizes the session on schedule
 * failure. */
void xrootd_aio_resume(ngx_connection_t *c);

/* Phase 31 W2.1 — drive a windowed memory read (fill -> drain -> fill).
 * Called from the kXR_read handler to start, and from the send-completion
 * handler (src/connection/send.c) to continue once a window's chunk drains. */
void xrootd_read_window_pump(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *rconf);

/*
 * Main-thread completion callbacks (posted to the event loop via ngx_post_event
 * once the worker finishes).  Each recovers its task from ev->data, restores the
 * request context (and so must guard against ctx->destroyed), builds/queues the
 * wire response from the *_aio_t struct, frees that struct, then calls
 * xrootd_aio_resume.  ev->data is the ngx_thread_task_t whose .ctx is the typed
 * *_aio_t below.
 */
/* kXR_read completion: builds the data chain from xrootd_read_aio_t. */
void xrootd_read_aio_done(ngx_event_t *ev);
/* kXR_write completion (xrootd_write_aio_t).  Frees t->payload_to_free
 * unconditionally (even on the destroyed path) since the worker owns that
 * detached copy; a short write is reported as a hard kXR_IOError. */
void xrootd_write_aio_done(ngx_event_t *ev);
/* kXR_writev/chunked-write completion (xrootd_writev_aio_t); frees payload_buf. */
void xrootd_writev_write_aio_done(ngx_event_t *ev);
/* kXR_readv completion: emits the prebuilt response buffer (xrootd_readv_aio_t). */
void xrootd_readv_aio_done(ngx_event_t *ev);
/* kXR_pgread completion: builds the interleaved data+CRC chain (xrootd_pgread_aio_t). */
void xrootd_pgread_aio_done(ngx_event_t *ev);
/* kXR_dirlist completion: emits the prebuilt listing buffer (xrootd_dirlist_aio_t). */
void xrootd_dirlist_aio_done(ngx_event_t *ev);

/*
 * Thread-pool worker functions (run on a pool thread, NOT the main thread).
 * Each casts data to a ngx_thread_task_t and operates only on its *_aio_t fields
 * (the blocking pread/pwrite/opendir): they may use raw heap and the log, but
 * MUST NOT touch the nginx pool, ctx state, or the connection.  Results/errors
 * are stashed in the struct for the matching *_aio_done callback to consume.
 */
/* pread into xrootd_read_aio_t (sets nread / io_errno). */
void xrootd_read_aio_thread(void *data, ngx_log_t *log);
/* pwrite from xrootd_write_aio_t (sets nwritten / io_errno). */
void xrootd_write_aio_thread(void *data, ngx_log_t *log);
/* Multi-segment writev + optional fsync from xrootd_writev_aio_t. */
void xrootd_writev_write_aio_thread(void *data, ngx_log_t *log);
/* Coalesced preadv for all segments of xrootd_readv_aio_t. */
void xrootd_readv_aio_thread(void *data, ngx_log_t *log);
/* pread then per-page CRC32c interleave into xrootd_pgread_aio_t scratch. */
void xrootd_pgread_aio_thread(void *data, ngx_log_t *log);
/* opendir/iterate + optional checksum, building the full wire reply in-struct. */
void xrootd_dirlist_aio_thread(void *data, ngx_log_t *log);

#endif /* XROOTD_AIO_H */
