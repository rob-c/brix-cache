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
    /* Phase 26 slice fill: when slice_len > 0 the worker fetches only the
     * window [slice_start, slice_start+slice_len) (clamped to file_size) and
     * cache_path/part_path/lock_path point at the per-slice files.
     * file_cache_path is the whole-file cache path used for the shared
     * .__xrds.meta sidecar.  slice_len == 0 keeps the historical whole-file
     * fill behaviour. */
    off_t     slice_start;
    off_t     slice_len;
    char      file_cache_path[PATH_MAX];
    /* Phase 26 read-resume: the original kXR_read params, so the slice fill
     * done callback can re-enter the read handler after a slice lands. */
    int       slice_read_idx;
    off_t     slice_read_offset;
    size_t    slice_read_rlen;
    /* Checksum-on-fill (verify.c): the origin's advertised content digest,
     * populated after a successful download (kXR_Qcksum for the xroot origin;
     * a Digest header for the HTTP/Pelican origins). Empty alg ⇒ origin offered
     * none; the verify policy then decides commit-unverified vs fail. */
    char      origin_cks_alg[16];
    char      origin_cks_hex[129];
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

/* Record a fill failure into t: sets t->result=NGX_ERROR, stores xrd_error
 * (kXR_* sent to client) and sys_errno (logged only); msg is copied into
 * t->err_msg (truncated to 255 chars), defaulting to "cache fill failed" when
 * NULL/empty. msg is borrowed (copied), not retained. */
void xrootd_cache_set_error(xrootd_cache_fill_t *t, int xrd_error,
    int sys_errno, const char *msg);
/* Like xrootd_cache_set_error but captures the current errno: formats
 * "<prefix>: <strerror(errno)>" as the message and records errno as sys_errno.
 * Call immediately after the failing syscall; errno is read at entry. */
void xrootd_cache_set_syserror(xrootd_cache_fill_t *t, int xrd_error,
    const char *prefix);

/* Blocking send of exactly len bytes to the origin (TLS via oc->ssl when set,
 * else plain TCP). Loops over partial writes / SSL_WANT_*, retries EINTR.
 * Thread-pool context only (never the event loop). Returns 0 on success, -1
 * on error with errno set (EIO on SSL fault, EPIPE on 0-byte TCP write). */
int xrootd_cache_io_send(xrootd_cache_origin_conn_t *oc, const void *buf,
    size_t len);
/* Blocking receive of EXACTLY len bytes from the origin into buf (loops until
 * full; partial reads accumulate). Returns 0 on success, -1 on error with errno
 * set (EIO on SSL fault, ECONNRESET on peer EOF before len). Thread-pool only. */
int xrootd_cache_io_recv_exact(xrootd_cache_origin_conn_t *oc, void *buf,
    size_t len);
/* Write all len bytes to a local fd, looping over short writes and retrying
 * EINTR. Returns 0 on success, -1 on error (errno set; a 0-byte write is -1). */
int xrootd_cache_fd_write_all(int fd, const void *buf, size_t len, off_t offset);

/* Build "<path><suffix>" into dst (size dstsz). Returns 0 on success, -1 on
 * truncation/encoding error (dst contents then unspecified). */
int xrootd_cache_append_suffix(char *dst, size_t dstsz, const char *path,
    const char *suffix);
/* Recursively create the parent directory of path (mode 0755). No-op when the
 * parent is "/" or has no slash. Returns 0 on success or if it already exists,
 * -1 on error (errno set; ENAMETOOLONG if path exceeds PATH_MAX). */
int xrootd_cache_ensure_parent(const char *path);
/* Three-state probe of a cache path: 1 = exists and is a regular file (hit),
 * 0 = does not exist (ENOENT — treat as miss), -1 = stat error or exists but
 * is not a regular file (errno set: EISDIR for a dir, else EINVAL/syscall errno). */
int xrootd_cache_file_ready(const char *path);

/* Either wait for another worker's fill to land or claim ownership of this one.
 * Returns 0 with *owned=0 when t->cache_path appeared (someone else filled it),
 * or 0 with *owned=1 when this caller won the O_EXCL lock at t->lock_path (caller
 * must fetch then unlink the lock). Returns -1 on error or after
 * conf->cache_lock_timeout seconds (sets t error: kXR_FileLocked on timeout).
 * Blocks the thread, polling every XROOTD_CACHE_LOCK_POLL_USEC us. */
int xrootd_cache_wait_or_lock(xrootd_cache_fill_t *t, int *owned);

/* Tear down an origin connection: SSL_shutdown+free, free ssl_ctx, close fd,
 * and reset all three fields. Idempotent (skips NULL/-1 members); safe to call
 * on a partially-constructed oc and on every error path. */
void xrootd_cache_origin_close(xrootd_cache_origin_conn_t *oc);
/* Connect to the configured origin (t->conf->cache_origin_host/port); thin
 * wrapper over xrootd_cache_origin_connect_addr. Returns 0 (connected, TLS done
 * if cache_origin_tls), -1 on error (t error set). */
int xrootd_cache_origin_connect(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc);
/* DNS-resolve host/port, connect (non-blocking with XROOTD_CACHE_IO_TIMEOUT-s
 * poll timeout, trying every addrinfo), set SO_RCV/SNDTIMEO, then handshake TLS
 * with peer verification when cache_origin_tls is set (trusted_ca or system CAs;
 * SNI = host). On success oc is fully populated; on failure (returns -1, t error
 * set) oc may hold a live fd/ssl — caller must xrootd_cache_origin_close it. */
int xrootd_cache_origin_connect_addr(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const ngx_str_t *host, uint16_t port);

/* Read one XRootD ServerResponseHdr plus its body. On success returns 0 and
 * sets *status, *dlen, and *body: *body is malloc'd (dlen+1, NUL-terminated)
 * and OWNED BY THE CALLER (free() it) when dlen>0, else NULL. Rejects dlen>
 * max_body (anti-OOM). Returns -1 on wire/alloc error (t error set, *body NULL). */
int xrootd_cache_read_response(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, uint16_t *status, u_char **body,
    uint32_t *dlen, uint32_t max_body);
/* Translate a kXR_error response body into t's error fields, preserving the
 * origin's own kXR code (first 4 bytes, big-endian) and message (rest, capped at
 * 255 chars). Falls back to kXR_ServerError + the fallback string when body is
 * NULL or shorter than 4 bytes. body is borrowed (not freed). */
void xrootd_cache_set_origin_error(xrootd_cache_fill_t *t, u_char *body,
    uint32_t dlen, const char *fallback);

/* Drive the full session bootstrap on a connected oc: handshake → kXR_protocol
 * negotiation → anonymous kXR_login (user "xrd"). Fails with kXR_TLSRequired if
 * the origin demands TLS but cache_origin_tls is off, kXR_AuthFailed if it
 * requires credentials. Returns 0 ready-for-requests, -1 on failure (t error set). */
int xrootd_cache_origin_bootstrap(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc);
/* kXR_open (read|retstat) on t->clean_path. Copies the file handle into fhandle
 * (XRD_FHANDLE_LEN bytes, caller-provided) and parses the retstat string to set
 * t->file_size when present. A redirect response is rejected as kXR_Unsupported
 * (origin must be a data server). Returns 0 on success, -1 on error (t error set). */
int xrootd_cache_origin_open(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, u_char fhandle[XRD_FHANDLE_LEN]);
/* kXR_query/kXR_Qcksum on t->clean_path (path-based). Writes the origin's
 * advertised "<algo> <hexvalue>" digest into alg_out[alg_sz]/hex_out[hex_sz]
 * (both emptied when the origin has no checksum). BEST-EFFORT: any wire/parse
 * failure or kXR_error leaves the outputs empty, restores t's error triple, and
 * returns 0 — a checksum query must never fail an already-complete fill. Used by
 * checksum-on-fill verification (verify.c). */
int xrootd_cache_origin_query_checksum(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, char *alg_out, size_t alg_sz,
    char *hex_out, size_t hex_sz);
/* kXR_open (update|delete|mkpath) on the borrowed absolute origin path for
 * write-through: truncates the destination and creates missing parents. mode_bits
 * applies to a newly created file (0644 when 0). Fills fhandle (caller-provided).
 * Returns 0 on success, -1 on error/redirect (t error set; kXR_ArgInvalid if path
 * is NULL/empty). */
int xrootd_cache_origin_open_write(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *path, uint16_t mode_bits,
    u_char fhandle[XRD_FHANDLE_LEN]);
/* kXR_close for fhandle; best-effort — send/response errors are ignored (the
 * fetched data is already on disk). No return value, no t error set. */
void xrootd_cache_origin_close_file(xrootd_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN]);
/* kXR_read of up to `want` bytes at `offset`, streaming each kXR_ok/kXR_oksofar
 * payload straight to outfd via xrootd_cache_fd_write_all; loops until the final
 * kXR_ok. Sets *got to bytes written (may be < want at EOF; never > want — over-
 * reads are rejected as kXR_ServerError). Returns 0 on success, -1 on error
 * (t error set). */
/* Reads `want` bytes from the origin at `read_off` and writes them into outfd at
 * `dst_off` (+ progress). The two offsets are decoupled: the whole-file fetch
 * passes dst_off==read_off (absolute), while a slice fill reads at an absolute
 * origin offset but writes into a 0-relative per-slice file (dst_off==0-based). */
int xrootd_cache_origin_read_chunk(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    int outfd, uint64_t read_off, uint64_t dst_off, size_t want, size_t *got);
/* kXR_write of len bytes from data at offset (write-through). Requires a kXR_ok
 * reply with zero data length. len>INT32_MAX is rejected (kXR_ArgTooLong).
 * Returns 0 on success, -1 on error (t error set). */
int xrootd_cache_origin_write_chunk(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t offset, const u_char *data, size_t len);
/* kXR_truncate the origin file to `length` bytes. Returns 0 on success, -1 on
 * error (t error set). */
int xrootd_cache_origin_truncate(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t length);
/* kXR_sync to flush origin buffers to stable storage (write-through, before
 * close). Returns 0 on success, -1 on error (t error set). */
int xrootd_cache_origin_sync(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN]);

/* Write-through flush entry at kXR_close for handle idx: dispatches async (nginx
 * thread pool, sets ctx->files[idx].wt_flush_pending and returns immediately) when
 * wt_mode==ASYNC and a pool exists, else runs synchronously. Falls back to sync on
 * post failure. local_path may be NULL (uses the handle's recorded path). Always
 * returns NGX_OK (errors are logged, not propagated to the close reply). */
ngx_int_t xrootd_wt_flush_on_close(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path);
/* Synchronous write-through flush for handle idx (used by kXR_sync and the sync
 * close path): blocks mirroring the local file to the origin. On success clears
 * the dirty markers. When fail_status != 0, a failure sends that kXR_* error to
 * the client (and is the return of xrootd_send_error); when 0, failures are only
 * logged. Returns NGX_OK when there was nothing dirty (NGX_DECLINED internally)
 * or on logged failure. */
ngx_int_t xrootd_wt_flush_sync_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path,
    uint16_t fail_status);
/* Thread-pool worker for async write-through: runs the blocking flush on the
 * xrootd_wt_flush_t in `data`. Result is reported via the task struct. */
void xrootd_wt_flush_thread(void *data, ngx_log_t *log);
/* Event-loop completion callback for the async write-through task: updates
 * metrics, logs success/failure, and frees the ngx_thread_task (which owns the
 * embedded wt copy). */
void xrootd_wt_flush_done(ngx_event_t *ev);

/* Thread-pool fetch of the WHOLE file from origin into t->part_path, then atomic
 * rename to t->cache_path and write the metadata sidecar. Applies the admission
 * filter (cache_max_file_size vs cache_include_regex). Returns 0 on success,
 * -1 on error (t error set), 1 when admission declined (sets t->result=NGX_DECLINED
 * so the caller redirects the client to the origin). */
int xrootd_cache_fetch_origin(xrootd_cache_fill_t *t);
/* Two-pass LRU eviction when cache filesystem occupancy exceeds
 * conf->cache_eviction_threshold (ppm); no-op if cache disabled or threshold 0.
 * protect_path (the file being filled) is never evicted. Takes a directory-level
 * evict lock. Thread-pool context only. No return value (errors counted in metrics). */
void xrootd_cache_evict_if_needed(xrootd_cache_fill_t *t,
    const char *protect_path, ngx_log_t *log);
/* Thread-pool worker for a whole-file fill: ensure parent dir → evict → wait/lock
 * → skip if already present → fetch origin → evict → release lock. Records the
 * outcome (incl. NGX_DECLINED) in the xrootd_cache_fill_t at `data` for the done
 * callback; never sends a client response itself. */
void xrootd_cache_fill_thread(void *data, ngx_log_t *log);
/* Event-loop completion callback after a whole-file fill: restores the suspended
 * request, then redirects (NGX_DECLINED), sends a kXR_error (failure), or opens
 * the freshly cached file and resumes the client's AIO read (success). */
void xrootd_cache_fill_done(ngx_event_t *ev);

/* Phase 26 slice fill (slice_fill.c). */
/* Fetch ONE byte window [slice_start, slice_start+slice_len) (clamped to file
 * size) into t->part_path, atomically rename to the per-slice t->cache_path, and
 * validate/refresh the shared whole-file meta sidecar (evicting sibling slices on
 * an origin size change). Returns 0 on success, -1 on error (t error set);
 * admission decline (1) never occurs for slices. */
int  xrootd_cache_slice_fetch_origin(xrootd_cache_fill_t *t);
/* Thread-pool worker for a slice fill: ensure parent → wait/lock → skip if the
 * slice is already present → fetch the window → release lock. Fire-and-forget:
 * the client was already answered with kXR_wait, so there is no done callback. */
void xrootd_cache_slice_fill_thread(void *data, ngx_log_t *log);


#endif /* XROOTD_CACHE_INTERNAL_H */
