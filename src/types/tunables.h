#ifndef XROOTD_TYPES_TUNABLES_H
#define XROOTD_TYPES_TUNABLES_H

#include "compat/path.h"

/* ---- File: tunables.h — Compile-time size limits, auth constants, metric macros ----
 *
 * WHAT: Defines all compile-time tunable constants for nginx-xrootd: read sizing (XROOTD_READ_MAX 4 MiB per-vector element cap for normalising client readv requests; XROOTD_READ_CHUNK_MAX 16 MiB wire chunk size splitting large contiguous reads into fewer sendfile boundaries; XROOTD_READ_REQUEST_MAX 64 MiB max per-request read returning larger chunks), connection limits (XROOTD_MAX_FILES 16 simultaneously open files per connection, XROOTD_MAX_PATH alias for XROOTD_PATH_MAX max accepted path length, XROOTD_MAX_WALK_DEPTH 32 path component depth rejecting before expensive realpath/lstat to prevent CPU exhaustion from symlink traversal chains, XROOTD_MAX_CONN_POOL_BYTES 64 MB nginx connection pool lifetime cap preventing dirlist flood exhaustion — ~1000 calls exhausts worker heap), payload limits (XROOTD_MAX_WRITE_PAYLOAD 16 MiB per-write request handling non-default xrdcp v5 8 MiB chunks with pgwrite 4-byte CRC per 4096 page overhead; XROOTD_MAX_PREPARE_PAYLOAD 64 KB newline-separated path batch; XROOTD_MAX_AUTH_PAYLOAD 32 KB GSI cert chains with VOMS attribute certs reaching 8-10 KB), TCP buffer (XROOTD_RECV_BUF sized to hold largest expected request = MAX_PATH + header + 64), send behavior (XROOTD_SEND_CHAIN_SPIN_MAX 16 immediate continuations before yielding through posted-event queue keeping large responses moving without starving other connections), auth protection (XROOTD_MAX_AUTH_ATTEMPTS 10 non-certreq auth rounds per connection — legitimate GSI client uses 2 rounds per attempt so 10 allows 5 full retry cycles, protects against brute-force/CPU-amplification attacks via GSI/token/SSS processing), token validation (XROOTD_TOKEN_CLOCK_SKEW_SECS 30 seconds JWT nbf/exp grace window accepting freshly-issued tokens despite server clock lag per WLCG Token Profile recommendation), authentication modes (XROOTD_AUTH_NONE=0 anonymous, XROOTD_AUTH_GSI=1 GSI/x509 required, XROOTD_AUTH_TOKEN=2 bearer token JWT/WLCG required, XROOTD_AUTH_BOTH=3 accept either, XROOTD_AUTH_SSS=4 Simple Shared Secret), SSS constants (XROOTD_SSS_KEY_MAX 128 key bytes, XROOTD_SSS_NAME_MAX 192 name chars, XROOTD_SSS_USER_MAX 128 user chars, XROOTD_SSS_GROUP_MAX 64 group chars, SSS_OPT flags ALLUSR/ANYUSR/ANYGRP/USRGRP/NOIPCK), per-operation metric macros (XROOTD_OP_OK/OP_ERR atomic fetch_add to metrics op_ok/op_err arrays when metrics configured — no-op when disabled), response collapse macros (XROOTD_RETURN_OK combines access log + OpOK + send_ok NULL 0 for no-body responses; XROOTD_RETURN_ERR combines access log + OpErr + send_error for error paths with code/msg).
 *
 * WHY: Compile-time constants prevent runtime allocation growth from unbounded client requests. Read sizing balances wire efficiency (16 MiB chunks reduce sendfile boundaries) against per-vector element cap (4 MiB normalises readv). File limit 16 prevents excessive fd consumption per connection. Walk depth 32 rejects deep symlink chains before expensive syscalls. Pool byte cap 64 MB allows sustained dirlist calls without heap exhaustion — connection closed with kXR_NoMemory on breach. Write payload 16 MiB handles non-default xrdcp chunk sizes with CRC overhead headroom. Auth attempts 10 protects against brute-force while allowing legitimate retry cycles (certreq + cert = 2 rounds per attempt). Clock skew 30 seconds accommodates NTP drift per WLCG recommendation. Send chain spin 16 keeps large sendfile responses moving without starving other ready connections via nginx posted-event queue yield. Metric macros conditional on ctx->metrics pointer — no overhead when metrics disabled. Return macros collapse common three-line pattern (log + metric + send) into single call for no-body success/error paths; handlers returning bodies keep explicit lines.
 *
 * HOW: Struct layout — includes compat/path.h → read sizing defines READ_MAX/READ_CHUNK_MAX/READ_REQUEST_MAX (lines 22-24) → connection limits MAX_FILES/MAX_PATH/MAX_WALK_DEPTH (lines 27-38) → payload limits MAX_WRITE_PAYLOAD/MAX_PREPARE_PAYLOAD/MAX_AUTH_PAYLOAD (lines 45-57) → TCP buffer RECV_BUF (line 60) → send spin MAX_CHAIN_SPIN_MAX (line 67) → auth attempts MAX_AUTH_ATTEMPTS (line 76) → pool bytes MAX_CONN_POOL_BYTES (line 85) → clock skew TOKEN_CLOCK_SKEW_SECS (line 94) → auth mode constants NONE/GSI/TOKEN/BOTH/SSS (lines 97-101) → SSS size constants + OPT flags (lines 104-113) → OpOK/OpErr atomic macros (lines 116-124) → ReturnOK/ReturnErr collapse macros (lines 132-146). */

/*
 * Compile-time size limits, auth-mode constants, and per-operation metric macros.
 *
 * Included by ngx_xrootd_module.h after the nginx, OpenSSL, protocol, and
 * metrics headers have been pulled in.  Do not include this file directly
 * unless those headers precede it.
 */

/*
 * Read sizing.
 *
 * XROOTD_READ_MAX is the per-vector element cap used when normalising
 * client readv requests.  Large contiguous reads may still return up to
 * XROOTD_READ_REQUEST_MAX, but the response is split into larger 16 MiB
 * wire chunks so cleartext sendfile responses need fewer header/file
 * boundaries and therefore fewer writev/sendfile calls.
 */
#define XROOTD_READ_MAX          (4 * 1024 * 1024)
#define XROOTD_READ_CHUNK_MAX    (16 * 1024 * 1024)
#define XROOTD_READ_REQUEST_MAX  (64 * 1024 * 1024)

/*
 * Memory-budget streaming (Phase 31).
 *
 * XROOTD_READ_WINDOW caps the *resident heap* a single in-flight read may hold
 * at once, independently of the logical request size.  A 64 MiB TLS read (which
 * cannot use sendfile) is served as a sequence of fill -> encrypt -> drain
 * cycles over a buffer of at most this size, instead of buffering the whole
 * request in heap.  The wire framing (XROOTD_READ_CHUNK_MAX chunks) is unchanged
 * — only the in-memory slice shrinks.
 *
 * XROOTD_SCRATCH_TRIM_THRESHOLD is the high-water mark above which a per-session
 * reusable scratch buffer is shrunk back to XROOTD_READ_WINDOW once a request
 * has fully drained.  Hysteresis (2x window) avoids realloc thrash on sessions
 * that legitimately oscillate around the window size.
 *
 * XROOTD_CONN_XFER_HEAP_MAX bounds the combined size of one connection's
 * transfer scratch buffers (read_scratch + read_hdr_scratch + write_scratch +
 * payload_buf).  With the read/write windows in place this ceiling is normally
 * never reached; it is the per-connection backstop that turns a runaway buffer
 * into a clean kXR_NoMemory rather than unbounded growth.
 */
#define XROOTD_READ_WINDOW             (2 * 1024 * 1024)
#define XROOTD_SCRATCH_TRIM_THRESHOLD  (2 * XROOTD_READ_WINDOW)
#define XROOTD_CONN_XFER_HEAP_MAX      (4 * XROOTD_READ_WINDOW)

/*
 * Optional io_uring disk-I/O backend (Phase 44).
 *
 * The backend is a third AIO dispatch tier (io_uring -> thread pool -> inline
 * sync) selected per server block by `xrootd_io_uring on|off|auto`.  These are
 * compile-time, header-only constants; the runtime verdict is decided by the
 * authoritative opcode probe in src/aio/uring.c, never by parsing `uname`.
 *
 * Mode enum (stored in ngx_stream_xrootd_srv_conf_t.io_uring, set via an
 * ngx_conf_enum_t slot):
 *   OFF  = never use io_uring (thread pool / inline only)
 *   ON   = require io_uring — startup FAILS if it is not compiled in or the
 *          runtime probe fails (see §32 fail-fast; xrootd_uring_validate_conf)
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
#define XROOTD_IO_URING_OFF                   0
#define XROOTD_IO_URING_ON                    1
#define XROOTD_IO_URING_AUTO                  2

#define XROOTD_IO_URING_QUEUE_DEPTH           256
#define XROOTD_IO_URING_MIN_KERNEL_MAJOR      5
#define XROOTD_IO_URING_MIN_KERNEL_MINOR      6
#define XROOTD_IO_URING_RESTRICT_KERNEL_MINOR 10

/*
 * Output-queue depth (Phase 29 pipelining; runtime-configurable).
 *
 * The per-connection output ring (xrootd_ctx_t.out_ring) and read-buffer pool
 * (rd_pool) are heap-allocated at connection time to ctx->pipeline_depth — the
 * number of in-flight responses that may be outstanding before the recv loop
 * applies backpressure.  Each slot owns one in-flight response's send state
 * (flat-buffer tail, chain tail, reusable header/data/file chain structs), so a
 * DEEPER pipeline absorbs more wire latency/jitter (packet reordering, high-BDP
 * links) — a momentarily-slow drain no longer empties the in-flight window and
 * stalls the recv->process->send loop — at a per-slot memory cost.
 *
 * Set via `xrootd_pipeline_depth N`; merged/clamped to [MIN, MAX].  Sizing the
 * rings to the configured depth keeps a small default cheap while leaving a large
 * value available for lossy/jittery WANs.  Was a fixed #define of 4 (Phase 29/32).
 */
#define XROOTD_PIPELINE_DEPTH_DEFAULT  8
#define XROOTD_PIPELINE_DEPTH_MIN      1
#define XROOTD_PIPELINE_DEPTH_MAX      64

/*
 * Per-slot wire-header capacity (Phase 32 WS2).  A multi-chunk sendfile read
 * emits one XRD_RESPONSE_HDR_LEN header per 16 MiB wire chunk; the worst case is
 * XROOTD_READ_REQUEST_MAX/XROOTD_READ_CHUNK_MAX chunks (= 4 → 32 bytes).  Sizing
 * the per-slot header buffer to this lets a multi-chunk response keep its headers
 * in its own slot (not the shared read_hdr_scratch), so multiple multi-chunk
 * reads can be pipelined without their headers aliasing.
 */
#define XROOTD_SLOT_HDR_MAX \
    (((XROOTD_READ_REQUEST_MAX + XROOTD_READ_CHUNK_MAX - 1) \
      / XROOTD_READ_CHUNK_MAX) * XRD_RESPONSE_HDR_LEN)

/*
 * Phase 33 C4 — rate-limit key memoization.
 *
 * Number of leading rate-limit rules whose computed key string the stream
 * dispatch gate caches per connection (xrootd_ctx_t.rl_key_cache).  Identity-
 * stable rules (VO / ISSUER / IP / DN) produce a connection-constant key, so the
 * per-read re-hash in xrootd_rl_stream_gate is wasted work; caching the first
 * few rules' keys removes it from the read hot path.  VOLUME rules are path-
 * dependent and are never cached; rules at index >= this bound recompute as
 * before.  8 covers any realistic per-server rule count with negligible ctx cost.
 */
#define XROOTD_RL_RULE_CACHE_MAX       8

/*
 * Phase 33 — GSI ephemeral DH key pool (src/gsi/keypool.c).
 *
 * Per-worker warm pool of pre-generated ffdhe2048 keys so kXGC_certreq never runs
 * keygen on the nginx event thread under a concurrent handshake burst.  The target
 * warm count (SIZE_DEFAULT, runtime-tunable via xrootd_gsi_keypool_size) is the
 * refill ceiling, sized to cover a worst-case concurrent-handshake burst; when the
 * pool falls to half the target an off-thread refill of REFILL_BATCH keys is
 * scheduled.  Each key is ~1-2 KB → target keys ≈ 100-130 KB per worker.
 *
 * SEED_DEFAULT keys are generated synchronously at worker start (xrootd_gsi_
 * keypool_seed); the remainder up to the target fills OFF the event thread so boot
 * is not blocked on ~target keygens (was the dominant per-worker startup cost). CAP
 * bounds the static ring so the target directive cannot be set unboundedly high.
 */
#define XROOTD_GSI_KEYPOOL_CAP           256   /* static ring capacity (ceiling) */
#define XROOTD_GSI_KEYPOOL_SIZE_DEFAULT  64    /* default warm/refill target     */
#define XROOTD_GSI_KEYPOOL_SEED_DEFAULT  4     /* default synchronous boot seed  */
#define XROOTD_GSI_KEYPOOL_REFILL_BATCH  32

/* Maximum simultaneously open files per connection. */
#define XROOTD_MAX_FILES     16

/* Maximum path length accepted from a client (alias for XROOTD_PATH_MAX). */
#define XROOTD_MAX_PATH      XROOTD_PATH_MAX

/*
 * Maximum path component depth before rejecting the request.
 * Prevents CPU exhaustion from excessive symlink traversal chains and deep
 * directory nesting — rejects paths with more than this many components
 * before expensive realpath(3) / lstat() operations begin.
 */
#define XROOTD_MAX_WALK_DEPTH  32

/*
 * Maximum write payload per request.  xrdcp v5 uses 8 MiB chunks by default;
 * each pgwrite payload adds 4-byte CRC per 4096-byte page (~0.1% overhead).
 * Cap at 16 MiB to handle non-default chunk sizes with headroom.
 */
#define XROOTD_MAX_WRITE_PAYLOAD  (16 * 1024 * 1024)

/*
 * Maximum kXR_prepare payload.  XrdCl sends a newline-separated list of paths;
 * allow a moderately sized batch without growing the payload receive buffer.
 */
#define XROOTD_MAX_PREPARE_PAYLOAD  (64 * 1024)

/*
 * Maximum kXR_auth payload.  GSI certificate chains with VOMS attribute
 * certificates can reach 8–10 KB depending on the CA chain depth.
 */
#define XROOTD_MAX_AUTH_PAYLOAD   (32 * 1024)

/* TCP receive buffer — sized to hold the largest expected request. */
#define XROOTD_RECV_BUF      (XROOTD_MAX_PATH + XRD_REQUEST_HDR_LEN + 64)

/*
 * Maximum immediate send_chain continuations before yielding through nginx's
 * posted-event queue.  Keeps large sendfile responses moving without
 * starving other ready connections.
 */
#define XROOTD_SEND_CHAIN_SPIN_MAX  16

/*
 * Maximum kXR_auth attempts per connection before the connection is rejected.
 * Counts every non-certreq auth round that does not succeed.  Protects against
 * brute-force and CPU-amplification attacks via GSI/token/SSS processing.
 * A legitimate GSI client uses 2 rounds per attempt (certreq + cert), so 10
 * allows 5 full retry cycles before lockout.
 */
#define XROOTD_MAX_AUTH_ATTEMPTS 10

/*
 * Maximum bytes allocated from the nginx connection pool (c->pool) over the
 * lifetime of a single XRootD connection.  Repeated kXR_dirlist calls each
 * commit ~65 KB permanently to the pool; a sustained flood would otherwise
 * exhaust worker heap.  64 MB allows ~1000 dirlist calls or equivalent
 * per-connection pool growth before the connection is closed with kXR_NoMemory.
 */
#define XROOTD_MAX_CONN_POOL_BYTES  (64 * 1024 * 1024)

/*
 * Clock-skew tolerance for JWT nbf/exp validation.
 * Even with NTP, production systems commonly drift 1–5 seconds.  The WLCG
 * Token Profile recommends that servers accept a small grace window so that
 * freshly-issued tokens are not rejected by a server whose clock lags slightly.
 * 30 seconds is generous enough for any reasonable NTP configuration.
 */
#define XROOTD_TOKEN_CLOCK_SKEW_SECS  30

/* ---- Authentication mode constants ---- */
#define XROOTD_AUTH_NONE   0   /* no authentication required (anonymous) */
#define XROOTD_AUTH_GSI    1   /* GSI/x509 authentication required       */
#define XROOTD_AUTH_TOKEN  2   /* Bearer token (JWT/WLCG) authentication */
#define XROOTD_AUTH_BOTH   3   /* Accept either GSI or token auth        */
#define XROOTD_AUTH_SSS    4   /* XRootD Simple Shared Secret auth       */
#define XROOTD_AUTH_UNIX   5   /* XRootD unix auth (self-asserted local) */
#define XROOTD_AUTH_KRB5   6   /* XRootD Kerberos 5 auth                 */
#define XROOTD_AUTH_HOST   7   /* XRootD host auth (reverse-DNS allowlist) */
#define XROOTD_AUTH_PWD    8   /* XRootD pwd auth (XrdSecpwd password, opt-in) */

/* ---- GSI signed-DH policy (phase-48; xrootd_gsi_signed_dh directive) ---- */
#define XROOTD_GSI_SDH_OFF      0  /* always unsigned DH (default, universal)  */
#define XROOTD_GSI_SDH_AUTO     1  /* signed DH for clients advertising >=10400 */
#define XROOTD_GSI_SDH_REQUIRE  2  /* signed DH only; reject <10400 clients     */

/* XrdSecgsi version at/after which the RSA-signed-DH wire variant applies
 * (XrdSecgsiVersDHsigned in the reference implementation). */
#define XROOTD_GSI_VERS_DHSIGNED 10400

/* ---- SSS constants ---- */
#define XROOTD_SSS_KEY_MAX   128
#define XROOTD_SSS_NAME_MAX  192
#define XROOTD_SSS_USER_MAX  128
#define XROOTD_SSS_GROUP_MAX 64

#define XROOTD_SSS_OPT_ALLUSR  0x01
#define XROOTD_SSS_OPT_ANYUSR  0x02
#define XROOTD_SSS_OPT_ANYGRP  0x04
#define XROOTD_SSS_OPT_USRGRP  0x08
#define XROOTD_SSS_OPT_NOIPCK  0x10

/* Increment a per-operation metric counter.  No-op when metrics are disabled. */
#define XROOTD_OP_OK(ctx, op)  \
    do { if ((ctx)->metrics) { \
        ngx_atomic_fetch_add(&(ctx)->metrics->op_ok[(op)], 1); \
    } } while (0)

#define XROOTD_OP_ERR(ctx, op) \
    do { if ((ctx)->metrics) { \
        ngx_atomic_fetch_add(&(ctx)->metrics->op_err[(op)], 1); \
    } } while (0)

/*
 * Collapse the common three-line pattern into a single macro call.
 * Use only when xrootd_send_ok sends no body (NULL, 0).
 * Handlers that return a body (read data, pgwrite status, query results)
 * must keep the three lines explicit.
 */
#define XROOTD_RETURN_OK(ctx, c, op, verb, path, detail, bytes)         \
    do {                                                                  \
        xrootd_log_access((ctx), (c), (verb), (path), (detail),         \
                          1, kXR_ok, NULL, (bytes));                     \
        XROOTD_OP_OK((ctx), (op));                                       \
        return xrootd_send_ok((ctx), (c), NULL, 0);                      \
    } while (0)

#define XROOTD_RETURN_ERR(ctx, c, op, verb, path, detail, code, msg)    \
    do {                                                                  \
        xrootd_log_access((ctx), (c), (verb), (path), (detail),         \
                          0, (code), (msg), 0);                          \
        XROOTD_OP_ERR((ctx), (op));                                      \
        return xrootd_send_error((ctx), (c), (code), (msg));             \
    } while (0)

/*
 * Collapse: log_access + XROOTD_OP_OK + return send_redirect.
 * Used wherever the outcome is a successful redirect (locate, manager, etc.)
 */
#define XROOTD_RETURN_REDIR(ctx, c, op, verb, path, detail, host, port)  \
    do {                                                                  \
        xrootd_log_access((ctx), (c), (verb), (path), (detail),         \
                          1, kXR_ok, NULL, 0);                           \
        XROOTD_OP_OK((ctx), (op));                                        \
        return xrootd_send_redirect((ctx), (c), (host), (port));         \
    } while (0)

/*
 * Collapse: log_access + XROOTD_OP_ERR + *rc=send_error + return 0.
 * Used in helper functions (validate_handle, parse_op_path, etc.) that
 * signal failure to callers via an out-parameter and return int 0.
 */
#define XROOTD_BAIL_ERR(ctx, c, op, verb, path, detail, code, msg, rc)   \
    do {                                                                  \
        xrootd_log_access((ctx), (c), (verb), (path), (detail),         \
                          0, (code), (msg), 0);                          \
        XROOTD_OP_ERR((ctx), (op));                                      \
        *(rc) = xrootd_send_error((ctx), (c), (code), (msg));            \
        return 0;                                                         \
    } while (0)

#endif /* XROOTD_TYPES_TUNABLES_H */
