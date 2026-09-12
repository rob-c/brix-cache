#ifndef BRIX_TYPES_TUNABLES_H
#define BRIX_TYPES_TUNABLES_H

#include "core/compat/path.h"

/* ---- File: tunables.h — Compile-time size limits, auth constants, metric macros ----
 *
 * PURPOSE:
 *   Defines all compile-time tunable constants for nginx-xrootd.
 *   Prevents runtime allocation growth from unbounded client requests.
 *
 * WHAT (Constants Defined):
 *   Read Sizing:
 *   - BRIX_READ_MAX: 4 MiB per-vector element cap (normalizes client readv)
 *   - BRIX_READ_CHUNK_MAX: 32 MiB wire chunk size (reduces sendfile boundaries)
 *   - BRIX_READ_REQUEST_MAX: 64 MiB max per-request read
 *
 *   Connection Limits:
 *   - BRIX_MAX_FILES: 16 open files per connection
 *   - BRIX_MAX_PATH: Max path length (alias for BRIX_PATH_MAX)
 *   - BRIX_MAX_WALK_DEPTH: 32 path components (prevents symlink CPU exhaustion)
 *   - BRIX_MAX_CONN_POOL_BYTES: 64 MB pool lifetime cap (~1000 dirlist calls)
 *
 *   Payload Limits:
 *   - BRIX_MAX_WRITE_PAYLOAD: 16 MiB (handles xrdcp v5 8 MiB chunks + CRC)
 *   - BRIX_MAX_PREPARE_PAYLOAD: 64 KB (newline-separated path batch)
 *   - BRIX_MAX_AUTH_PAYLOAD: 32 KB (GSI cert chains with VOMS 8-10 KB)
 *
 *   TCP/Send Behavior:
 *   - BRIX_RECV_BUF: MAX_PATH + header + 64 (largest expected request)
 *   - BRIX_SEND_CHAIN_SPIN_MAX: 16 immediate continuations before yield
 *
 *   Auth Protection:
 *   - BRIX_MAX_AUTH_ATTEMPTS: 10 rounds (GSI = 2 rounds/attempt, so 5 retries)
 *   - BRIX_TOKEN_CLOCK_SKEW_SECS: 30 seconds (WLCG Token Profile recommendation)
 *
 *   Auth Modes:
 *   - BRIX_AUTH_NONE=0, BRIX_AUTH_GSI=1, BRIX_AUTH_TOKEN=2
 *   - BRIX_AUTH_BOTH=3, BRIX_AUTH_SSS=4
 *
 *   SSS Constants:
 *   - BRIX_SSS_KEY_MAX: 128 bytes, BRIX_SSS_NAME_MAX: 192 chars
 *   - BRIX_SSS_USER_MAX: 128 chars, BRIX_SSS_GROUP_MAX: 64 chars
 *   - SSS_OPT flags: ALLUSR/ANYUSR/ANYGRP/USRGRP/NOIPCK
 *
 *   Metric Macros:
 *   - BRIX_OP_OK/OP_ERR: Atomic fetch_add to op_ok/op_err arrays
 *   - BRIX_RETURN_OK/RETURN_ERR: Collapse log+metric+send pattern
 *
 * WHY (Design Rationale):
 *   - Read sizing: 32 MiB chunks reduce sendfile boundaries; 4 MiB cap normalizes readv
 *   - File limit 16: Prevents excessive fd consumption per connection
 *   - Walk depth 32: Rejects deep symlink chains before expensive syscalls
 *   - Pool cap 64 MB: Allows sustained dirlist without heap exhaustion
 *   - Write payload 16 MiB: Handles non-default xrdcp chunks with CRC headroom
 *   - Auth attempts 10: Protects brute-force while allowing 5 full GSI retry cycles
 *   - Clock skew 30s: Accommodates NTP drift per WLCG recommendation
 *   - Send spin 16: Keeps large responses moving without starving connections
 *   - Metric macros: Conditional on ctx->metrics — zero overhead when disabled
 *
 * HOW (Struct Layout):
 *   1. Include: compat/path.h
 *   2. Read sizing: READ_MAX/READ_CHUNK_MAX/READ_REQUEST_MAX (lines 22-24)
 *   3. Connection limits: MAX_FILES/MAX_PATH/MAX_WALK_DEPTH (lines 27-38)
 *   4. Payload limits: MAX_WRITE_PAYLOAD/MAX_PREPARE_PAYLOAD/MAX_AUTH_PAYLOAD (45-57)
 *   5. TCP buffer: RECV_BUF (line 60)
 *   6. Send spin: MAX_CHAIN_SPIN_MAX (line 67)
 *   7. Auth attempts: MAX_AUTH_ATTEMPTS (line 76)
 *   8. Pool bytes: MAX_CONN_POOL_BYTES (line 85)
 *   9. Clock skew: TOKEN_CLOCK_SKEW_SECS (line 94)
 *   10. Auth modes: NONE/GSI/TOKEN/BOTH/SSS (lines 97-101)
 *   11. SSS constants + OPT flags (lines 104-113)
 *   12. OpOK/OpErr atomic macros (lines 116-124)
 *   13. ReturnOK/ReturnErr collapse macros (lines 132-146)
 */

/*
 * Compile-time size limits, auth-mode constants, and per-operation metric macros.
 *
 * Included by ngx_brix_module.h after the nginx, OpenSSL, protocol, and
 * metrics headers have been pulled in.  Do not include this file directly
 * unless those headers precede it.
 */

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

/* BRIX_TPC_HOPS_MAX caps brix_tpc_max_hops: how many kXR_redirect hops the
 * native TPC pull may follow from the client-named source before the transfer
 * fails (F7). Bounds a redirect ring or a manager ping-pong. */
#define BRIX_TPC_HOPS_MAX            16

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
 * seccomp-BPF worker syscall filter (hyper-hardening-plan §D-3).
 *
 * A per-worker syscall allowlist installed at the tail of init_process, after
 * every setup syscall has run, so only the steady-state serving set must be
 * enumerated.  Mode enum (stored in ngx_stream_brix_srv_conf_t.seccomp, set via
 * an ngx_conf_enum_t slot; the strictest value across enabled server blocks wins
 * for the process):
 *   OFF     = no filter installed (default — strictly opt-in).
 *   AUDIT   = filter loaded with a log-only default action: allowlisted syscalls
 *             run silently, everything else is ALLOWED but logged to the kernel
 *             audit log (SECCOMP … audit records).  Converges the set risk-free.
 *   ENFORCE = allowlisted syscalls run; the named-dangerous set (execve/execveat/
 *             ptrace/process_vm_*) is KILLED; any other non-allowlisted syscall
 *             fails EPERM (fail-safe: a missed entry degrades one call, it does
 *             not crash the worker).
 *
 * Requires a build with libseccomp (config sets -DBRIX_HAVE_SECCOMP); without it
 * AUDIT/ENFORCE fail closed at init (the worker refuses to run rather than serve
 * unfiltered while the operator believes it is filtered).
 */
#define BRIX_SECCOMP_OFF                    0
#define BRIX_SECCOMP_AUDIT                  1
#define BRIX_SECCOMP_ENFORCE                2

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

/*
 * Phase 33 C4 — rate-limit key memoization.
 *
 * Number of leading rate-limit rules whose computed key string the stream
 * dispatch gate caches per connection (brix_ctx_t.rl_key_cache).  Identity-
 * stable rules (VO / ISSUER / IP / DN) produce a connection-constant key, so the
 * per-read re-hash in brix_rl_stream_gate is wasted work; caching the first
 * few rules' keys removes it from the read hot path.  VOLUME rules are path-
 * dependent and are never cached; rules at index >= this bound recompute as
 * before.  8 covers any realistic per-server rule count with negligible ctx cost.
 */
#define BRIX_RL_RULE_CACHE_MAX       8

/*
 * Phase 33 — GSI ephemeral DH key pool (src/gsi/keypool.c).
 *
 * Per-worker warm pool of pre-generated ffdhe2048 keys so kXGC_certreq never runs
 * keygen on the nginx event thread under a concurrent handshake burst.  The target
 * warm count (SIZE_DEFAULT, runtime-tunable via brix_gsi_keypool_size) is the
 * refill ceiling, sized to cover a worst-case concurrent-handshake burst; when the
 * pool falls to half the target an off-thread refill of REFILL_BATCH keys is
 * scheduled.  Each key is ~1-2 KB → target keys ≈ 100-130 KB per worker.
 *
 * SEED_DEFAULT keys are generated synchronously at worker start (brix_gsi_
 * keypool_seed); the remainder up to the target fills OFF the event thread so boot
 * is not blocked on ~target keygens (was the dominant per-worker startup cost). CAP
 * bounds the static ring so the target directive cannot be set unboundedly high.
 */
#define BRIX_GSI_KEYPOOL_CAP           256   /* static ring capacity (ceiling) */
#define BRIX_GSI_KEYPOOL_SIZE_DEFAULT  64    /* default warm/refill target     */
#define BRIX_GSI_KEYPOOL_SEED_DEFAULT  4     /* default synchronous boot seed  */
#define BRIX_GSI_KEYPOOL_REFILL_BATCH  32

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
 * Clock-skew tolerance for JWT nbf/exp validation.
 * Even with NTP, production systems commonly drift 1–5 seconds.  The WLCG
 * Token Profile recommends that servers accept a small grace window so that
 * freshly-issued tokens are not rejected by a server whose clock lags slightly.
 * 30 seconds is generous enough for any reasonable NTP configuration.
 */
#define BRIX_TOKEN_CLOCK_SKEW_SECS  30

/* ---- Timeout constants (runtime-configurable defaults) ---- */

/*
 * WebDAV lock timeout default.
 * RFC 4918 recommends 1 hour as the default lock lifetime.  Clients may
 * request shorter or longer timeouts, but this is the default when not
 * specified.  Makes timeout configurable via future directive.
 */
#define BRIX_WEBDAV_LOCK_TIMEOUT_DEFAULT       3600

/*
 * DNS healthcheck timeout (milliseconds).
 * Time to wait for DNS resolver answer before marking unhealthy.
 * 5 seconds balances reliability (allows retry) against fast failover.
 */
#define BRIX_DNS_HC_TIMEOUT_DEFAULT_MS         5000

/*
 * CMS filesystem exec timeout (milliseconds).
 * Maximum time allowed for brix_cms_fsxeq program execution before kill.
 * 10 seconds allows most filesystem operations while preventing hangs.
 */
#define BRIX_CMS_FSXEQ_TIMEOUT_DEFAULT_MS      10000

/*
 * CMS read timeout (milliseconds).
 * Maximum time to wait for CMS manager answer before fallback.
 * Formula: max(3×heartbeat_interval, 90s) — 90s is the floor.
 */
#define BRIX_CMS_READ_TIMEOUT_DEFAULT_MS       90000

/*
 * Proxy connection timeout (milliseconds).
 * Time allowed for TCP connect to upstream before failure.
 * 10 seconds allows for network latency while failing fast.
 */
#define BRIX_PROXY_CONNECT_TIMEOUT_DEFAULT_MS  10000

/*
 * Proxy read timeout (milliseconds).
 * Maximum time between upstream response bytes before timeout.
 * 60 seconds allows for slow upstreams without hanging indefinitely.
 */
#define BRIX_PROXY_READ_TIMEOUT_DEFAULT_MS     60000

/*
 * Proxy write timeout (milliseconds).
 * Maximum time to send request to upstream before timeout.
 * 60 seconds matches read timeout for symmetry.
 */
#define BRIX_PROXY_WRITE_TIMEOUT_DEFAULT_MS    60000

/* ---- Proxy buffer and sizing constants ---- */

/*
 * Maximum port number (TCP/UDP port range: 1-65535).
 * Used for port validation in proxy upstream configuration.
 */
#define BRIX_MAX_PORT                          65535

/*
 * Retry buffer threshold for proxy requests (128 KB).
 * Requests smaller than this use retry buffer; larger requests stream directly.
 * Balances memory usage against retry capability.
 */
#define BRIX_PROXY_RETRY_BUFFER_MAX            (128 * 1024)

/*
 * Maximum hostname length for proxy upstream (256 bytes).
 * Accommodates FQDNs with subdomains while bounding allocation.
 */
#define BRIX_PROXY_MAX_HOST_LEN                256

/*
 * Proxy pool size for upstream connections (512 bytes).
 * Small pool for per-connection upstream state allocation.
 */
#define BRIX_PROXY_POOL_SIZE                   512

/*
 * Audit log buffer size (1024 bytes).
 * Sufficient for single-line audit entries with host/path info.
 */
#define BRIX_PROXY_AUDIT_BUF_SIZE              1024

/*
 * Cache lock timeout (seconds).
 * Stampede prevention: maximum time a cache fill lock is held.
 * 300 seconds (5 minutes) allows slow fills while preventing deadlocks.
 */
#define BRIX_CACHE_LOCK_TIMEOUT_DEFAULT_SEC    300

/*
 * Maximum delay cap for client wait (seconds).
 * Analog of ofs.maxdelay — caps how long client may be told to wait.
 * 60 seconds prevents excessive client-side delays while allowing retries.
 */
#define BRIX_MAX_DELAY_DEFAULT_SEC             60

/* ---- Size constants ---- */

/*
 * Maximum bearer token size (bytes).
 * WLCG SciTokens typically 2–4 KB; 4 KB accommodates future extensions.
 * Prevents unbounded allocation from malicious oversized token claims.
 */
#define BRIX_BEARER_TOKEN_MAX                  4096

/*
 * Maximum macaroon path caveats.
 * Prevents path traversal attack via excessive caveat chains.
 * 8 allows reasonable delegation depth while bounding verification cost.
 */
#define BRIX_MACAROON_PATH_CAVEATS_MAX         8

/* ---- Authentication mode constants ---- */
#define BRIX_AUTH_NONE   0   /* no authentication required (anonymous) */
#define BRIX_AUTH_GSI    1   /* GSI/x509 authentication required       */
#define BRIX_AUTH_TOKEN  2   /* Bearer token (JWT/WLCG) authentication */
#define BRIX_AUTH_BOTH   3   /* Accept either GSI or token auth        */
#define BRIX_AUTH_SSS    4   /* XRootD Simple Shared Secret auth       */
#define BRIX_AUTH_UNIX   5   /* XRootD unix auth (self-asserted local) */
#define BRIX_AUTH_KRB5   6   /* XRootD Kerberos 5 auth                 */
#define BRIX_AUTH_HOST   7   /* XRootD host auth (reverse-DNS allowlist) */
#define BRIX_AUTH_PWD    8   /* XRootD pwd auth (XrdSecpwd password, opt-in) */

/* ---- GSI signed-DH policy (phase-48; brix_gsi_signed_dh directive) ---- */
#define BRIX_GSI_SDH_OFF      0  /* always unsigned DH (default, universal)  */
#define BRIX_GSI_SDH_AUTO     1  /* signed DH for clients advertising >=10400 */
#define BRIX_GSI_SDH_REQUIRE  2  /* signed DH only; reject <10400 clients     */

/* XrdSecgsi version at/after which the RSA-signed-DH wire variant applies
 * (XrdSecgsiVersDHsigned in the reference implementation). */
#define BRIX_GSI_VERS_DHSIGNED 10400

/* ---- SSS constants ---- */
#define BRIX_SSS_KEY_MAX   128
#define BRIX_SSS_NAME_MAX  192
#define BRIX_SSS_USER_MAX  128
#define BRIX_SSS_GROUP_MAX 64

#define BRIX_SSS_OPT_ALLUSR  0x01
#define BRIX_SSS_OPT_ANYUSR  0x02
#define BRIX_SSS_OPT_ANYGRP  0x04
#define BRIX_SSS_OPT_USRGRP  0x08
#define BRIX_SSS_OPT_NOIPCK  0x10

/* Increment a per-operation metric counter.  No-op when metrics are disabled. */
#define BRIX_OP_OK(ctx, op)  \
    do { if ((ctx)->metrics) { \
        ngx_atomic_fetch_add(&(ctx)->metrics->op_ok[(op)], 1); \
    } } while (0)

#define BRIX_OP_ERR(ctx, op) \
    do { if ((ctx)->metrics) { \
        ngx_atomic_fetch_add(&(ctx)->metrics->op_err[(op)], 1); \
    } } while (0)

/*
 * Collapse the common three-line pattern into a single macro call.
 * Use only when brix_send_ok sends no body (NULL, 0).
 * Handlers that return a body (read data, pgwrite status, query results)
 * must keep the three lines explicit.
 */
#define BRIX_RETURN_OK(ctx, c, op, verb, path, detail, bytes)         \
    do {                                                                  \
        brix_log_access((ctx), (c), (verb), (path), (detail),         \
                          1, kXR_ok, NULL, (bytes));                     \
        BRIX_OP_OK((ctx), (op));                                       \
        return brix_send_ok((ctx), (c), NULL, 0);                      \
    } while (0)

#define BRIX_RETURN_ERR(ctx, c, op, verb, path, detail, code, msg)    \
    do {                                                                  \
        brix_log_access((ctx), (c), (verb), (path), (detail),         \
                          0, (code), (msg), 0);                          \
        BRIX_OP_ERR((ctx), (op));                                      \
        return brix_send_error((ctx), (c), (code), (msg));             \
    } while (0)

/*
 * Collapse: log_access + BRIX_OP_OK + return send_redirect.
 * Used wherever the outcome is a successful redirect (locate, manager, etc.)
 */
#define BRIX_RETURN_REDIR(ctx, c, op, verb, path, detail, host, port)  \
    do {                                                                  \
        brix_log_access((ctx), (c), (verb), (path), (detail),         \
                          1, kXR_ok, NULL, 0);                           \
        BRIX_OP_OK((ctx), (op));                                        \
        return brix_send_redirect((ctx), (c), (host), (port));         \
    } while (0)

/*
 * Selection answer (phase-115 W2.1): like BRIX_RETURN_REDIR but the answer is
 * the manager's `brix_cms_response` policy — kXR_redirect (default) or pin the
 * session to the selected server and proxy.  Use at dynamic selection sites
 * (registry / caches / stage); static manager_map redirects keep RETURN_REDIR.
 */
#define BRIX_RETURN_SELECTED(ctx, c, conf, op, verb, path, detail, host, port) \
    do {                                                                  \
        brix_log_access((ctx), (c), (verb), (path), (detail),         \
                          1, kXR_ok, NULL, 0);                           \
        BRIX_OP_OK((ctx), (op));                                        \
        return brix_cms_answer_selected((ctx), (c), (conf), (host), (port)); \
    } while (0)

/*
 * Collapse: log_access + BRIX_OP_ERR + *rc=send_error + return 0.
 * Used in helper functions (validate_handle, parse_op_path, etc.) that
 * signal failure to callers via an out-parameter and return int 0.
 */
#define BRIX_BAIL_ERR(ctx, c, op, verb, path, detail, code, msg, rc)   \
    do {                                                                  \
        brix_log_access((ctx), (c), (verb), (path), (detail),         \
                          0, (code), (msg), 0);                          \
        BRIX_OP_ERR((ctx), (op));                                      \
        *(rc) = brix_send_error((ctx), (c), (code), (msg));            \
        return 0;                                                         \
    } while (0)

#endif /* BRIX_TYPES_TUNABLES_H */
