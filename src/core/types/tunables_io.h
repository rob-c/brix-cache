/* Connection I/O windows, payload limits, and queue sizing.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

/*
 * Read sizing.
 *
 * BRIX_READ_MAX is the per-vector element cap used when normalising
 * client readv requests.  Large contiguous reads may still return up to
 * BRIX_READ_REQUEST_MAX, but the response is split into larger 32 MiB
 * wire chunks so cleartext sendfile responses need fewer header/file
 * boundaries and therefore fewer writev/sendfile calls.
 *
 * BRIX_READ_CHUNK_MAX — phase-33 P3-B1 (sendfile-span).  The XRootD wire
 * interleaves a kXR response header between successive wire chunks, so a
 * single sendfile(2) cannot span two chunks: this constant is the largest
 * contiguous span one sendfile can move.  Raising it 16→32 MiB halves the
 * header interleave (and sendfile/writev syscalls) for a maximum-size
 * BRIX_READ_REQUEST_MAX (64 MiB) request — a throughput-only geometry
 * change: reads are byte-identical, only the framing coarsens.  It is NOT
 * pushed to the full 64 MiB request cap so a single sendfile still cannot
 * monopolise the worker for a whole request (event-loop fairness).  Only
 * the cleartext/kTLS sendfile path is affected — the userspace-TLS and
 * buffered paths stream through BRIX_READ_WINDOW-sized slices regardless.
 */
#define BRIX_READ_MAX          (4 * 1024 * 1024)
#define BRIX_READ_CHUNK_MAX    (32 * 1024 * 1024)
#define BRIX_READ_REQUEST_MAX  (64 * 1024 * 1024)

/*
 * Small-read sendfile floor.  A [memory header][in_file body] chain makes
 * ngx_linux_sendfile_chain bracket every response with four setsockopt(2)
 * calls (TCP_NODELAY off, TCP_CORK on ... CORK off, NODELAY on) around the
 * writev+sendfile pair — six syscalls to move a 1 KiB frame.  Below this
 * floor a kXR_read takes the memory path instead: one preadv2 (warm-cache
 * probe) plus one writev of [hdr|data], zero setsockopts, and the copy cost
 * of so few bytes is far below the setsockopt bracket it saves.  At and above
 * the floor zero-copy sendfile wins and keeps the bracket.
 */
#define BRIX_READ_SENDFILE_MIN (32 * 1024)

/*
 * Post-auth request read-ahead stash.  Reading exact frame sizes makes every
 * metadata request cost four socket syscalls (header recv, payload recv, and
 * an ioctl(FIONREAD) after each exact fill inside ngx_unix_recv); asking for
 * this much instead pulls a whole small request — usually header AND payload,
 * often several pipelined requests — in ONE partial recv that nginx never
 * follows with an ioctl.  Reads at least this large bypass the stash and go
 * straight to the destination buffer (bulk write payloads must not pay a
 * bounce copy).  Sized to hold any metadata request (paths cap at PATH_MAX)
 * while staying a trivial per-connection allocation.
 */
#define BRIX_RECV_STASH_SIZE (8 * 1024)

/*
 * io_uring maximum submission queue depth.
 * Upper bound for uring ring depth to prevent excessive memory allocation.
 * 4096 entries is the practical maximum for most workloads.
 */
#define BRIX_URING_MAX_DEPTH       4096

/*
 * Memory-budget streaming (Phase 31).
 *
 * BRIX_READ_WINDOW caps the *resident heap* a single in-flight read may hold
 * at once, independently of the logical request size.  A 64 MiB TLS read (which
 * cannot use sendfile) is served as a sequence of fill -> encrypt -> drain
 * cycles over a buffer of at most this size, instead of buffering the whole
 * request in heap.  The wire framing (BRIX_READ_CHUNK_MAX chunks) is unchanged
 * — only the in-memory slice shrinks.
 *
 * BRIX_SCRATCH_TRIM_THRESHOLD is the high-water mark above which a per-session
 * reusable scratch buffer is shrunk back to BRIX_READ_WINDOW once a request
 * has fully drained.  Hysteresis (2x window) avoids realloc thrash on sessions
 * that legitimately oscillate around the window size, and the trim is hot-
 * deferred (brix_trim_scratch): a buffer used since the previous pass is kept
 * warm for one more cycle so streaming transfers never free/realloc per
 * request (equal-size churn made glibc mmap/munmap the block every request).
 *
 * BRIX_CONN_XFER_HEAP_MAX bounds the combined size of one connection's
 * transfer scratch buffers (read_scratch + read_hdr_scratch + write_scratch +
 * payload_buf).  With the read/write windows in place this ceiling is normally
 * never reached; it is the per-connection backstop that turns a runaway buffer
 * into a clean kXR_NoMemory rather than unbounded growth.
 */
#define BRIX_READ_WINDOW             (2 * 1024 * 1024)
#define BRIX_SCRATCH_TRIM_THRESHOLD  (2 * BRIX_READ_WINDOW)
#define BRIX_CONN_XFER_HEAP_MAX      (4 * BRIX_READ_WINDOW)

/*
 * Optional io_uring disk-I/O backend (Phase 44).
 *
 * The backend is a third AIO dispatch tier (io_uring -> thread pool -> inline
 * sync) selected per server block by `brix_io_uring on|off|auto`.  These are
 * compile-time, header-only constants; the runtime verdict is decided by the
 * authoritative opcode probe in src/aio/uring.c, never by parsing `uname`.
 *
 * Mode enum (stored in ngx_stream_brix_srv_conf_t.io_uring, set via an
 * ngx_conf_enum_t slot):
 *   OFF  = never use io_uring (thread pool / inline only)
 *   ON   = require io_uring — startup FAILS if it is not compiled in or the
 *          runtime probe fails (see §32 fail-fast; brix_uring_validate_conf)
 *   AUTO = enable iff the probe passes this process, else silent fallback
 *
 * QUEUE_DEPTH is the per-worker ring's SQ/CQ entry count = the ceiling on
 * concurrent in-flight SQEs.  Each read submits one SQE (windowed reads stream
 * as one contiguous IORING_OP_READ per wire chunk), so depth tracks connection
 * concurrency, not request size; get_sqe -> NULL simply falls back to the pool.
 *
 * The MIN_KERNEL_* values are a fast pre-filter only (5.6 = reliable
 * register_eventfd for the completion bridge); RESTRICT_KERNEL_MINOR (5.10) is
 * where io_uring_register_restrictions() becomes available (best-effort).
 */
#define BRIX_IO_URING_OFF                   0
#define BRIX_IO_URING_ON                    1
#define BRIX_IO_URING_AUTO                  2

#define BRIX_IO_URING_QUEUE_DEPTH           256
#define BRIX_IO_URING_MIN_KERNEL_MAJOR      5
#define BRIX_IO_URING_MIN_KERNEL_MINOR      6
#define BRIX_IO_URING_RESTRICT_KERNEL_MINOR 10

/*
 * Output-queue depth (Phase 29 pipelining; runtime-configurable).
 *
 * The per-connection output ring (brix_ctx_t.out_ring) and read-buffer pool
 * (rd_pool) are heap-allocated at connection time to ctx->out.pipeline_depth — the
 * number of in-flight responses that may be outstanding before the recv loop
 * applies backpressure.  Each slot owns one in-flight response's send state
 * (flat-buffer tail, chain tail, reusable header/data/file chain structs), so a
 * DEEPER pipeline absorbs more wire latency/jitter (packet reordering, high-BDP
 * links) — a momentarily-slow drain no longer empties the in-flight window and
 * stalls the recv->process->send loop — at a per-slot memory cost.
 *
 * Set via `brix_pipeline_depth N`; merged/clamped to [MIN, MAX].  Sizing the
 * rings to the configured depth keeps a small default cheap while leaving a large
 * value available for lossy/jittery WANs.  Was a fixed #define of 4 (Phase 29/32).
 */
#define BRIX_PIPELINE_DEPTH_DEFAULT  8
#define BRIX_PIPELINE_DEPTH_MIN      1
#define BRIX_PIPELINE_DEPTH_MAX      64

/*
 * Per-slot wire-header capacity (Phase 32 WS2).  A multi-chunk sendfile read
 * emits one XRD_RESPONSE_HDR_LEN header per 32 MiB wire chunk (phase-33 P3-B1);
 * the worst case is BRIX_READ_REQUEST_MAX/BRIX_READ_CHUNK_MAX chunks (= 2 → 16
 * bytes).  Sizing
 * the per-slot header buffer to this lets a multi-chunk response keep its headers
 * in its own slot (not the shared read_hdr_scratch), so multiple multi-chunk
 * reads can be pipelined without their headers aliasing.
 */
#define BRIX_SLOT_HDR_MAX \
    (((BRIX_READ_REQUEST_MAX + BRIX_READ_CHUNK_MAX - 1) \
      / BRIX_READ_CHUNK_MAX) * XRD_RESPONSE_HDR_LEN)

/* Maximum simultaneously open files per connection. */
#define BRIX_MAX_FILES     16

/* Maximum path length accepted from a client (alias for BRIX_PATH_MAX). */
#define BRIX_MAX_PATH      BRIX_PATH_MAX

/*
 * Maximum path component depth before rejecting the request.
 * Prevents CPU exhaustion from excessive symlink traversal chains and deep
 * directory nesting — rejects paths with more than this many components
 * before expensive realpath(3) / lstat() operations begin.
 */
#define BRIX_MAX_WALK_DEPTH  32

/*
 * Maximum write payload per request.  xrdcp v5 uses 8 MiB chunks by default;
 * each pgwrite payload adds 4-byte CRC per 4096-byte page (~0.1% overhead).
 * Cap at 16 MiB to handle non-default chunk sizes with headroom.
 */
#define BRIX_MAX_WRITE_PAYLOAD  (16 * 1024 * 1024)

/*
 * Streaming large plain kXR_write.  A single kXR_write whose dlen exceeds
 * BRIX_WRITE_STREAM_CHUNK is delivered to the file / staged writer in bounded
 * BRIX_WRITE_STREAM_CHUNK-sized installments instead of being buffered whole,
 * so a client that sends one very large write (e.g. go-hep's 64 MiB inline
 * WriteAtContext) is accepted with memory bounded to one chunk rather than the
 * whole payload.  BRIX_MAX_WRITE_STREAM is the absolute per-write ceiling (a
 * sanity bound on the dlen field, still well below the 4 GiB the wire allows) so
 * a hostile dlen is rejected before streaming begins; the buffered fast path for
 * writes <= BRIX_WRITE_STREAM_CHUNK is unchanged and still capped at
 * BRIX_MAX_WRITE_PAYLOAD.  pgwrite/writev/chkpoint keep the 16 MiB cap — they
 * carry per-page CRC / descriptor structure that the chunk streamer does not
 * split, and stock clients already chunk them below the cap.
 */
#define BRIX_WRITE_STREAM_CHUNK  (8 * 1024 * 1024)
#define BRIX_MAX_WRITE_STREAM    (1024u * 1024u * 1024u)

/*
 * Maximum kXR_prepare payload.  XrdCl sends a newline-separated list of paths;
 * allow a moderately sized batch without growing the payload receive buffer.
 */
#define BRIX_MAX_PREPARE_PAYLOAD  (64 * 1024)

/*
 * Maximum kXR_auth payload.  GSI certificate chains with VOMS attribute
 * certificates can reach 8–10 KB depending on the CA chain depth.
 */
#define BRIX_MAX_AUTH_PAYLOAD   (32 * 1024)

/* TCP receive buffer — sized to hold the largest expected request. */
#define BRIX_RECV_BUF      (BRIX_MAX_PATH + XRD_REQUEST_HDR_LEN + 64)

/*
 * Maximum immediate send_chain continuations before yielding through nginx's
 * posted-event queue.  Keeps large sendfile responses moving without
 * starving other ready connections.
 */
#define BRIX_SEND_CHAIN_SPIN_MAX  16

/*
 * Maximum kXR_auth attempts per connection before the connection is rejected.
 * Counts every non-certreq auth round that does not succeed.  Protects against
 * brute-force and CPU-amplification attacks via GSI/token/SSS processing.
 * A legitimate GSI client uses 2 rounds per attempt (certreq + cert), so 10
 * allows 5 full retry cycles before lockout.
 */
#define BRIX_MAX_AUTH_ATTEMPTS 10

/*
 * Maximum bytes allocated from the nginx connection pool (c->pool) over the
 * lifetime of a single XRootD connection.  Repeated kXR_dirlist calls each
 * commit ~65 KB permanently to the pool; a sustained flood would otherwise
 * exhaust worker heap.  64 MB allows ~1000 dirlist calls or equivalent
 * per-connection pool growth before the connection is closed with kXR_NoMemory.
 */
#define BRIX_MAX_CONN_POOL_BYTES  (64 * 1024 * 1024)

/*
 * Maximum delay cap for client wait (seconds).
 * Analog of ofs.maxdelay — caps how long client may be told to wait.
 * 60 seconds prevents excessive client-side delays while allowing retries.
 */
#define BRIX_MAX_DELAY_DEFAULT_SEC             60

/*
 * Standard timeout values used across subsystems.
 * All values in milliseconds for consistency.
 */
#define BRIX_FILL_BACKOFF_CAP_MS               8000   /* Cache fill backoff cap */
#define BRIX_DASHBOARD_IDLE_THRESHOLD_MS       5000   /* Idle session threshold */
#define BRIX_DASHBOARD_STALLED_THRESHOLD_MS    60000  /* Stalled request threshold */
#define BRIX_DASHBOARD_CLUSTER_STALE_MS        90000  /* Cluster info staleness */
#define BRIX_DASHBOARD_SESSION_TTL_SEC         28800  /* Session TTL (8 hours) */
#define BRIX_GSIFTP_TIMEOUT_DEFAULT_MS         30000  /* GSI FTP timeout */
