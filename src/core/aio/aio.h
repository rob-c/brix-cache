#ifndef BRIX_AIO_H
#define BRIX_AIO_H

#include "core/ngx_brix_module.h"
#include "core/compat/pgio.h"   /* xrdp_pg_bad_t — pgwrite CSE bad-page list */
#include "core/compat/lifecycle_timing.h"   /* brix_phase_now_ns — D-2 clock */
#include "fs/vfs/vfs_io_core.h"

/*
 * AIO — async file I/O via the nginx thread pool, plus response builders.
 *
 * WHY AIO?
 * nginx worker threads are single-threaded and must never block.  Calling
 * pread(2) directly would stall the event loop for the duration of the disk
 * I/O, preventing any other connection from making progress.  Instead we:
 *
 *   1. Allocate a task context struct (e.g. brix_read_aio_t) on the heap.
 *   2. Post an ngx_thread_task_t to the nginx thread pool.
 *   3. The thread-pool worker calls *_aio_thread() — pread/pwrite happens here.
 *   4. When done, nginx posts the *_aio_done() callback back to the main thread.
 *   5. The done callback queues the response and calls brix_aio_resume() to
 *      wake the connection.
 *
 * While AIO is in flight, ctx->state = XRD_ST_AIO and both read/write events
 * are disarmed.  ctx->destroyed is checked in every done callback so that a
 * callback firing after client disconnect safely discards its work.
 */

#if (NGX_THREADS)
/*
 * brix_task_bind — wire a thread function and done callback into an
 * ngx_thread_task_t.  task->event.data must point back to task so the
 * done callback can recover it from ev->data.
 */
static ngx_inline void
brix_task_bind(ngx_thread_task_t *task,
    void               (*thread_fn)(void *data, ngx_log_t *log),
    ngx_event_handler_pt done_fn)
{
    task->handler       = thread_fn;
    task->event.handler = done_fn;
    task->event.data    = task;
}
#endif

/*
 * brix_aio_metric_done — phase-56 D-2: file the op-latency histogram sample
 * for a completed stream data-plane op (kXR_read/pgread/readv → READ,
 * kXR_write/pgwrite/writev → WRITE).
 *
 * HISTOGRAM ONLY (brix_metric_op_latency): the stream plane's io_ops_total and
 * io_bytes_{read,written} already reach the exporter via the legacy per-port
 * fold in unified_export_io.c — which also covers the non-AIO paths (sendfile
 * reads, inline fallbacks) — so booking them again here would double-count.
 * The latency series is the one thing the AIO plane never emitted; its count
 * is therefore the AIO-sampled subset of ops, not io_ops_total.
 *
 * start_ns is stamped at task-post time and consumed here in the done
 * callback — both run on the event-loop thread, so the timestamp needs no
 * synchronization; the worker never touches it.  Errored completions file too
 * (parity with the VFS inline observer, whose histogram includes error ops).
 * Low-cardinality labels only (proto=stream, op) per INVARIANT #8.
 */
static ngx_inline void
brix_aio_metric_done(uint64_t start_ns, brix_metric_op_t op)
{
    uint64_t  now_ns = brix_phase_now_ns();

    brix_metric_op_latency(BRIX_PROTO_ROOT, op,
        (now_ns > start_ns) ? (ngx_msec_t) ((now_ns - start_ns) / 1000ull)
                            : 0);
}

/* Build a chain of oksofar+ok bufs from a flat data buffer. */
ngx_chain_t *brix_build_chunked_chain(brix_ctx_t *ctx,
    ngx_connection_t *c, u_char *databuf, size_t data_total);

/* Build one memory-backed response chunk with an explicit wire status
 * (kXR_oksofar / kXR_ok) — used by the Phase 31 windowed-read loop. */
ngx_chain_t *brix_build_window_chain(brix_ctx_t *ctx,
    ngx_connection_t *c, u_char *databuf, size_t data_total, uint16_t status);

/* Build one bounded fragment of a single logical response body.  The first
 * fragment carries the response header whose dlen advertises body_total;
 * later fragments are raw body bytes and carry no additional wire header. */
ngx_chain_t *brix_build_body_fragment_chain(brix_ctx_t *ctx,
    ngx_connection_t *c, u_char *databuf, size_t fragment_size,
    size_t body_total, ngx_flag_t first);

/* Build a zero-copy sendfile chain (uses ngx_buf_t with in_file=1). */
ngx_chain_t *brix_build_sendfile_chain(brix_ctx_t *ctx,
    ngx_connection_t *c, int fd, const char *path, off_t offset,
    size_t data_total, u_char **base_out);

/* Build the kXR_pgread response chain ([pgRead status header][encoded page
 * data]); shared by the synchronous pgread handler and the AIO completion.
 * Returns the chain head, or NULL on allocation failure (caller cleans up). */
ngx_chain_t *brix_build_pgread_chain(brix_ctx_t *ctx,
    ngx_connection_t *c, int64_t offset, u_char *data, uint32_t out_size);

/*
 * Reusable per-connection scratch buffers — avoid pool growth on busy
 * sessions.  brix_get_pool_scratch() grows a single pool-anchored buffer
 * slot only when the current allocation is too small; BRIX_GET_SCRATCH()
 * is the call-site sugar that names the ctx slot/size fields to use:
 *
 *   buf = BRIX_GET_SCRATCH(ctx, c, read_scratch, read_scratch_size, need);
 */
u_char *brix_get_pool_scratch(ngx_pool_t *pool, u_char **slot,
    size_t *slot_size, size_t need);

/* The ##_hot paste marks the slot used-since-last-trim (see brix_trim_scratch:
 * only a slot idle for a whole trim cycle is shrunk — a streaming transfer
 * keeps its buffer warm instead of paying a free + mmap + fault cycle per
 * request).  Every BRIX_GET_SCRATCH slot therefore carries a <name>_hot bit. */
#define BRIX_GET_SCRATCH(ctx, c, slot_field, sz_field, need)  \
    ((ctx)->slot_field##_hot = 1,                             \
     brix_get_pool_scratch((c)->pool, &(ctx)->slot_field,     \
                             &(ctx)->sz_field, (need)))

/* Return a response data buffer when a request completes.  NULL is a no-op.
 * If buf is one of the reusable per-connection scratch slots (read_scratch /
 * read_hdr_scratch / write_scratch) it is KEPT for reuse; any other buffer is
 * ngx_pfree'd back to c->pool.  Do not pass a raw-heap buffer not owned by the
 * pool other than those scratch slots. */
void brix_release_read_buffer(brix_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf);

/* Borrow a per-in-flight data buffer from the connection read pool (rd_pool),
 * grown to >= need bytes — see brix_acquire_read_buffer in buffers.c.  Gives a
 * memory-backed read its own buffer so the read path can pipeline; returned to
 * the pool by brix_release_read_buffer when the response drains.  NULL on OOM
 * (or if the pool is unexpectedly exhausted). */
u_char *brix_acquire_read_buffer(brix_ctx_t *ctx, ngx_connection_t *c,
    size_t need);

/*
 * Shrink per-session transfer scratch buffers back to BRIX_READ_WINDOW once a
 * large request has fully drained.  Call only between requests (state
 * XRD_ST_REQ_HEADER, nothing buffered) — see the recv loop.
 */
void brix_trim_scratch(brix_ctx_t *ctx, ngx_connection_t *c);

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
typedef brix_vfs_readv_seg_t brix_readv_seg_desc_t;

/* Execute the I/O for a built readv plan: validate every segment (rejects
 * negative offsets and offset+length overflow), coalesce adjacent same-fd
 * segments into grouped preadv() calls (<= 64 iovecs each, EINTR-retried), and
 * read straight into each descriptor's payload_ptr.  Also rewrites each
 * segment's wire header_read_length_ptr.  *bytes_read_total accumulates bytes
 * read.  segment_count must be 1..BRIX_READV_MAXSEGS.  Returns NGX_OK, or
 * NGX_ERROR (short read past EOF, bad count, OOM, or I/O error) with a message
 * written into error_message (caller-owned, error_message_len bytes).
 * Safe to call off the main thread; touches no nginx pool or ctx state. */
ngx_int_t brix_readv_read_segments(brix_readv_seg_desc_t *segments,
    size_t segment_count, size_t *bytes_read_total, char *error_message,
    size_t error_message_len);

/*
 * Per-task context structs passed to the nginx thread-pool.
 * Each struct is heap-allocated before ngx_thread_task_post() and freed
 * in the done callback after the result is consumed on the main thread.
 */

typedef struct {
    ngx_connection_t              *c;
    brix_ctx_t                  *ctx;
    ngx_stream_brix_srv_conf_t  *conf;
    int       fd;
    int       handle_idx;
    off_t     offset;
    size_t    rlen;
    u_char   *databuf;
    u_char    streamid[2];
    ssize_t   nread;
    int       io_errno;
    void     *csi;        /* phase-59 W2: brix_csi_t* or NULL (verify on read) */
    brix_sd_obj_t obj;  /* Layer 3: driver obj (driver==NULL ⇒ POSIX-wrap fd) */
    uint64_t  start_ns;   /* phase-56 D-2: stamped at post, read in done      */
    unsigned  counted:1;  /* phase-32 WS3: single-shot read counted in
                           * rd.aio_inflight (0 for the windowed task, which
                           * self-serializes on win_active and is never
                           * pipelined) — gates the concurrent-read teardown */
    unsigned  pg:1;       /* windowed kXR_pgread: the worker runs the in-place
                           * encode+CRC (BRIX_VFS_IO_PGREAD) into databuf and
                           * fills out_size (see pgread_window.c) */
    size_t    out_size;   /* pg only: encoded wire bytes ([CRC][page] units) */
} brix_read_aio_t;

typedef struct {
    ngx_connection_t              *c;
    brix_ctx_t                  *ctx;
    ngx_stream_brix_srv_conf_t  *conf;
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
    void          *csi;        /* phase-59 W2: brix_csi_t* or NULL (tag update) */
    brix_sd_obj_t obj;       /* Layer 3: driver obj (driver==NULL ⇒ POSIX fd) */
    uint64_t       start_ns;   /* phase-56 D-2: stamped at post, read in done  */
} brix_write_aio_t;

typedef struct {
    ngx_connection_t              *c;
    brix_ctx_t                  *ctx;
    size_t                         segment_count;
    brix_readv_seg_desc_t       *segments;
    u_char                        *response_buffer;
    u_char  streamid[2];
    size_t  bytes_read_total;
    size_t  response_bytes;
    int     io_error;
    char    err_msg[64];
    uint64_t start_ns;    /* phase-56 D-2: stamped at post, read in done */
} brix_readv_aio_t;

typedef brix_vfs_writev_seg_t brix_writev_seg_desc_t;

typedef struct {
    ngx_connection_t              *c;
    brix_ctx_t                  *ctx;
    size_t                         n_segs;
    brix_writev_seg_desc_t      *segs;
    u_char                        *payload_buf; /* detached payload; freed by done handler */
    u_char  streamid[2];
    int     do_sync;
    size_t  bytes_total;  /* set by thread */
    int     io_error;     /* 0=ok, 1=pwrite error, 2=short write */
    char    err_msg[64];  /* set by thread on error */
    uint64_t start_ns;    /* phase-56 D-2: stamped at post, read in done */
} brix_writev_aio_t;

/*
 * brix_pgread_aio_t — async kXR_pgread context.
 *
 * scratch holds the final interleaved [CRC32c(4)][data] wire output starting at
 * offset 0: the worker reads file data straight into the data gaps (no flat copy
 * region) and CRCs each page in place, so out_size <= rlen + pages*4. The
 * completion callback builds the data chain from scratch[0 .. out_size-1].
 */
typedef struct {
    ngx_connection_t              *c;
    brix_ctx_t                  *ctx;
    int       fd;
    int       handle_idx;
    off_t     offset;
    size_t    rlen;       /* requested bytes; flat portion size in scratch */
    u_char   *scratch;    /* single alloc: flat data then interleaved output */
    size_t    out_size;   /* interleaved bytes written (set by thread) */
    u_char    streamid[2];
    ssize_t   nread;      /* actual pread return (set by thread) */
    int       io_errno;
    brix_sd_obj_t obj;  /* Layer 3: driver obj (driver==NULL ⇒ POSIX-wrap fd) */
    uint64_t  start_ns;   /* phase-56 D-2: stamped at post, read in done      */
    unsigned  counted:1;  /* pipelined-pgread parity with brix_read_aio_t:
                           * counted in rd.aio_inflight while a worker thread
                           * owns this task's rd_pool buffer — gates the
                           * concurrent-read teardown deferral */

    /* §1.1 offload-AIO: when sec_c is non-NULL the reply rides this bound
     * same-worker secondary — scratch points 32 bytes into the SECONDARY's
     * rd_pool slot (the frame is [pgRead status | encoded pages], contiguous),
     * and the task is counted in BOTH connections' rd.aio_inflight so either
     * side's teardown defers while a worker thread owns the buffer. */
    ngx_connection_t *sec_c;
    brix_ctx_t       *sec_ctx;
    unsigned          sec_counted:1;

    /* §1.2 pool-send: the worker thread itself sends the finished
     * [status|pages] frame on the SECONDARY's cleartext socket, so the socket
     * copy runs on a pool core instead of the (single) event-loop core.
     * pool_send is decided at post time (secondary ring idle + no TLS); the
     * thread records what reached the wire; the done epilogue disposes of the
     * buffer, the send token, and any unsent tail accordingly. */
    unsigned  pool_send:1;       /* thread may send the frame itself         */
    unsigned  pool_sent_all:1;   /* thread: the full frame hit the socket    */
    unsigned  pool_token_held:1; /* thread: partial send — token kept for the
                                  * done handler's front-of-ring park        */
    size_t    pool_sent;         /* bytes of [status|pages] already sent     */
    int       pool_send_errno;   /* hard send()/socket errno (0 = none)      */
    unsigned  pool_chunked:1;    /* §1.3 the thread streamed the reply as N
                                  * kXR_PartialResult chunk frames laid out
                                  * back-to-back in the slot buffer          */
    unsigned  chunk_error:1;     /* read error AFTER ≥1 partial frame was
                                  * committed — the terminating kXR_error
                                  * must ride the SECONDARY under the
                                  * request sid, never the control stream   */
    size_t    pool_image_len;    /* total wire-image bytes built in the slot
                                  * (all chunk frames; classic = hdr+enc)   */
    ngx_uint_t pool_frames;      /* wire frames inside that image           */
} brix_pgread_aio_t;

/*
 * brix_rd_slot_aio_u — sizing union for a rd_pool slot's one-time task
 * allocation.  A slot's buffer serves whichever pipelined read opcode
 * (kXR_read or kXR_pgread) acquired it, one request at a time, and the task is
 * re-bound at every post — so the single per-slot task context must be sized
 * for the larger of the two.  Both post sites allocate sizeof(this union).
 */
typedef union {
    brix_read_aio_t   read;
    brix_pgread_aio_t pgread;
} brix_rd_slot_aio_u;

/*
 * brix_dirlist_aio_t — async kXR_dirlist context.
 *
 * The main thread allocates a response buffer from c->pool (large block,
 * freed via ngx_pfree after drain), copies auth-checked path/algo/flags
 * into the struct, then posts to the thread pool.
 *
 * The worker thread consumes a loop-confined directory fd, iterates entries, calls
 * brix_dirlist_checksum_token() when kXR_dcksm is requested, and builds
 * the complete wire response (kXR_oksofar chunks + final kXR_ok frame)
 * directly into response[0..response_len).  No pool access in the thread.
 *
 * response_cap is BRIX_DIRLIST_AIO_RESPONSE_MAX (default 4 MiB).  If the
 * listing would overflow, io_errno is set to E2BIG and a kXR_IOError is sent.
 */
#define BRIX_DIRLIST_AIO_RESPONSE_MAX  (4 * 1024 * 1024)

/* §1.3 chunked pgread streaming: file bytes per kXR_PartialResult chunk on
 * the pool-send path.  Sized so the client starts verifying pages while the
 * pool thread reads the next chunk (the reference server streams ~1.4 MiB
 * partials); must be a multiple of kXR_pgPageSZ.  Shared with the offload
 * producer (pgread.c), whose buffer sizing adds one status header per chunk. */
#define BRIX_PGREAD_STREAM_CHUNK  ((size_t) (1024 * 1024))

typedef struct {
    ngx_connection_t              *c;
    brix_ctx_t                  *ctx;
    ngx_stream_brix_srv_conf_t  *conf;
    u_char      streamid[2];
    char        resolved[PATH_MAX];  /* absolute path, already auth-checked   */
    char        cksum_algo[32];      /* e.g. "adler32", "sha256"              */
    int         dirfd;               /* beneath-confined directory fd         */
    ngx_flag_t  want_stat;
    ngx_flag_t  want_cksum;
    /* Phase-105: the endpoint's write posture, snapshotted at post time — the
     * dcksm worker persists digests as xattrs on the export object. */
    brix_vfs_mutation_policy_t mutation_policy;
    u_char     *response;            /* ngx_palloc'd; freed after full drain  */
    size_t      response_cap;        /* = BRIX_DIRLIST_AIO_RESPONSE_MAX     */
    size_t      response_len;        /* bytes written by thread               */
    int         io_errno;            /* 0 = success                           */
    char        err_msg[64];
} brix_dirlist_aio_t;

/* --- Resume the nginx event loop after an AIO task completes. --- */

/* Liveness guard for a done callback: copies the saved 2-byte streamid into
 * ctx->recv.cur_streamid so the response is built for the right request.  Returns 1
 * if the connection is still alive, 0 if ctx->destroyed (caller must then touch
 * nothing further — ctx/c may be stale). */
ngx_flag_t brix_aio_restore_stream(brix_ctx_t *ctx,
    const u_char streamid[2]);

/* Like brix_aio_restore_stream, but also resets state to XRD_ST_REQ_HEADER
 * (hdr_pos=0) so the recv loop can read the next request.  Use from done
 * callbacks that complete the request cycle after queuing the response.
 * Returns 1 if alive, 0 if destroyed. */
ngx_flag_t brix_aio_restore_request(brix_ctx_t *ctx,
    const u_char streamid[2]);

/* Post a pre-built task to the thread pool and set ctx->state = XRD_ST_AIO.
 * Always returns NGX_OK; the outcome is reported via *posted: 1 = queued (AIO
 * in flight), 0 = NOT queued, so the caller must fall back to synchronous I/O.
 * *posted is 0 when pool is NULL (no pool configured) or the pool queue is full
 * (logs fallback_log at WARN).  Never fails the request itself. */
ngx_int_t brix_aio_post_task(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_thread_pool_t *pool, ngx_thread_task_t *task,
    const char *fallback_log, ngx_flag_t *posted);

/* Schedule the next event-loop step after a done callback has queued its
 * response: re-arms the write event if state is XRD_ST_SENDING, else the read
 * event so already-buffered pipelined requests run before the next epoll_wait.
 * No-op if the connection was destroyed; finalizes the session on schedule
 * failure. */
void brix_aio_resume(ngx_connection_t *c);

/* Phase 31 W2.1 — drive a windowed memory read (fill -> drain -> fill).
 * Called from the kXR_read handler to start, and from the send-completion
 * handler (src/connection/send.c) to continue once a window's chunk drains. */
void brix_read_window_pump(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf);

/* Round 12 (reads_window.c ↔ reads.c seam): _emit_step posts the next
 * window's read-ahead, emits the current window, and swaps the double
 * buffers; _park_or_resume handles a dead train with a read-ahead still on a
 * worker (park in XRD_ST_AIO until its completion discards itself) vs. an
 * immediate resume.  Called from the windowed completion halves in reads.c. */
ngx_int_t brix_read_window_emit_step(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, ssize_t nread, size_t out_size,
    int io_errno);
void brix_read_window_park_or_resume(brix_ctx_t *ctx, ngx_connection_t *c);

/* Windowed kXR_pgread (primary-path streaming — pgread_window.c).  The shared
 * window pump drives these when ctx->rd.win_pgread is set: _want cuts the next
 * window's data length on the absolute 4 KiB page grid, _scratch sizes the
 * frame buffer ([32-byte status header][gapped [CRC][page] wire data]), and
 * _emit stamps the kXR_status partial/final header ahead of the encoded bytes
 * and queues the contiguous frame. */
size_t brix_pgread_window_want(off_t cur, size_t left);
size_t brix_pgread_window_scratch(off_t cur, size_t want);
ngx_int_t brix_pgread_window_emit(brix_ctx_t *ctx, ngx_connection_t *c,
    ssize_t nread, size_t out_size, int io_errno);
/* _try_warm: preadv2(RWF_NOWAIT) read+encode+CRC of one window inline on the
 * event loop — a resident window skips the thread-pool round-trip entirely
 * (the train self-serializes, so the pool buys no overlap per window).  Hit:
 * returns 1 with *nread and *out_size set and backend bytes charged; miss: 0,
 * outputs untouched, caller posts to the pool as usual. */
ngx_flag_t brix_pgread_window_try_warm(brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *rconf, u_char *datap, size_t want,
    ssize_t *nread, size_t *out_size);

/*
 * Main-thread completion callbacks (posted to the event loop via ngx_post_event
 * once the worker finishes).  Each recovers its task from ev->data, restores the
 * request context (and so must guard against ctx->destroyed), builds/queues the
 * wire response from the *_aio_t struct, frees that struct, then calls
 * brix_aio_resume.  ev->data is the ngx_thread_task_t whose .ctx is the typed
 * *_aio_t below.
 */
/* kXR_read completion: builds the data chain from brix_read_aio_t. */
void brix_read_aio_done(ngx_event_t *ev);

/*
 * Failed-read forensics (fast-lane ESPIPE/EBADF watch item): classify what an
 * fd refers to right now ("regular"/"socket"/"fifo"/"dir"/"other", or "stale"
 * when fstat fails), and the one-line failure logger the buffered/windowed/AIO
 * read error paths call with the request geometry + worker errno.
 */
const char *brix_fd_kind(int fd);
void brix_read_io_failure_log(ngx_log_t *log, const char *who, int fd,
    off_t offset, size_t rlen, int io_errno);
/* kXR_write completion (brix_write_aio_t).  Frees t->payload_to_free
 * unconditionally (even on the destroyed path) since the worker owns that
 * detached copy; a short write is reported as a hard kXR_IOError. */
void brix_write_aio_done(ngx_event_t *ev);
/* kXR_writev/chunked-write completion (brix_writev_aio_t); frees payload_buf. */
void brix_writev_write_aio_done(ngx_event_t *ev);
/* kXR_readv completion: emits the prebuilt response buffer (brix_readv_aio_t). */
void brix_readv_aio_done(ngx_event_t *ev);
/* kXR_pgread completion: builds the interleaved data+CRC chain (brix_pgread_aio_t). */
void brix_pgread_aio_done(ngx_event_t *ev);
/* kXR_dirlist completion: emits the prebuilt listing buffer (brix_dirlist_aio_t). */
void brix_dirlist_aio_done(ngx_event_t *ev);

/*
 * Thread-pool worker functions (run on a pool thread, NOT the main thread).
 * Each casts data to a ngx_thread_task_t and operates only on its *_aio_t fields
 * (the blocking pread/pwrite/opendir): they may use raw heap and the log, but
 * MUST NOT touch the nginx pool, ctx state, or the connection.  Results/errors
 * are stashed in the struct for the matching *_aio_done callback to consume.
 */
/* pread into brix_read_aio_t (sets nread / io_errno). */
void brix_read_aio_thread(void *data, ngx_log_t *log);
/* pwrite from brix_write_aio_t (sets nwritten / io_errno). */
void brix_write_aio_thread(void *data, ngx_log_t *log);
/* Multi-segment writev + optional fsync from brix_writev_aio_t. */
void brix_writev_write_aio_thread(void *data, ngx_log_t *log);
/* Coalesced preadv for all segments of brix_readv_aio_t. */
void brix_readv_aio_thread(void *data, ngx_log_t *log);
/* pread then per-page CRC32c interleave into brix_pgread_aio_t scratch. */
void brix_pgread_aio_thread(void *data, ngx_log_t *log);
/* CRC-only pgread half for the io_uring hybrid (P44-B): the ring already
 * scattered nread bytes into the gapped scratch; this pass just fills the
 * per-page CRC32c gaps (never on the event thread, R-07). */
void brix_pgread_aio_crc_thread(void *data, ngx_log_t *log);
/* opendir/iterate + optional checksum, building the full wire reply in-struct. */
void brix_dirlist_aio_thread(void *data, ngx_log_t *log);

#endif /* BRIX_AIO_H */
