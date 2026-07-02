/*
 * mirror.h — Phase 24 traffic-mirroring shared config layer.
 *
 * WHAT: Protocol-agnostic configuration types shared by the HTTP/WebDAV mirror
 * (src/mirror/http_mirror.c) and the XRootD stream mirror
 * (src/mirror/stream_mirror.c).  A mirror sends a fire-and-forget copy of a
 * qualifying READ request to one or more shadow backends after the primary
 * request has already been answered; the shadow response is read, its status
 * compared against the primary, and any divergence counted.  The client never
 * sees the shadow response and is never delayed by it.
 *
 * WHY: Both surfaces need the same knobs — target list, sampling rate, a
 * method/opcode filter, auth-stripping, divergence logging, and a timeout — so
 * the operator-facing directives (xrootd_mirror_sample, _strip_auth, etc.) are
 * defined once and reused.  This header carries no HTTP- or stream-specific
 * types so it can be included from either module without pulling in ngx_http.
 *
 * HOW: xrootd_mirror_conf_t is embedded in both the WebDAV location conf and
 * the stream server conf.  Targets are resolved at configuration time into
 * xrootd_mirror_target_t (host/port/ssl + a pre-resolved sockaddr).  Sampling
 * is a per-request PRNG draw — sufficient for HEP traffic volumes, no reservoir
 * sampler needed.
 */
#ifndef XROOTD_MIRROR_H
#define XROOTD_MIRROR_H

#include <ngx_config.h>
#include <ngx_core.h>

#define XROOTD_MIRROR_MAX_TARGETS  4   /* up to 4 shadow backends per context */

/* ---- HTTP/WebDAV method bitmask (xrootd_mirror_methods) ---- */
#define XROOTD_MIRROR_M_GET       (1u << 0)
#define XROOTD_MIRROR_M_HEAD      (1u << 1)
#define XROOTD_MIRROR_M_PROPFIND  (1u << 2)
#define XROOTD_MIRROR_M_OPTIONS   (1u << 3)
/* Write methods (Phase 24 write mirroring).  Only honoured when
 * xrootd_mirror_writes is on AND the method is listed in xrootd_mirror_methods.
 * Deliberately absent from M_DEFAULT so they are never mirrored implicitly. */
#define XROOTD_MIRROR_M_PUT       (1u << 4)
#define XROOTD_MIRROR_M_DELETE    (1u << 5)
#define XROOTD_MIRROR_M_MKCOL     (1u << 6)
#define XROOTD_MIRROR_M_MOVE      (1u << 7)
#define XROOTD_MIRROR_M_COPY      (1u << 8)
#define XROOTD_MIRROR_M_WRITE_ALL (XROOTD_MIRROR_M_PUT     \
                                  | XROOTD_MIRROR_M_DELETE  \
                                  | XROOTD_MIRROR_M_MKCOL   \
                                  | XROOTD_MIRROR_M_MOVE    \
                                  | XROOTD_MIRROR_M_COPY)
#define XROOTD_MIRROR_M_DEFAULT   (XROOTD_MIRROR_M_GET     \
                                  | XROOTD_MIRROR_M_HEAD    \
                                  | XROOTD_MIRROR_M_PROPFIND)

/* ---- XRootD opcode bitmask (xrootd_mirror_opcodes) ----
 * Only stateless, path-bearing read opcodes are meaningful to replay against a
 * shadow: a kXR_read carries a file handle issued by the PRIMARY's kXR_open and
 * is meaningless on a server that never saw that open.  The default set is the
 * stateless ones; read/readv are selectable but best-effort. */
#define XROOTD_MIRROR_OP_STAT     (1u << 0)
#define XROOTD_MIRROR_OP_LOCATE   (1u << 1)
#define XROOTD_MIRROR_OP_OPEN     (1u << 2)   /* read opens only */
#define XROOTD_MIRROR_OP_READ     (1u << 3)
#define XROOTD_MIRROR_OP_READV    (1u << 4)
#define XROOTD_MIRROR_OP_DIRLIST  (1u << 5)
#define XROOTD_MIRROR_OP_STATX    (1u << 6)
#define XROOTD_MIRROR_OP_QUERY    (1u << 7)
/* Write opcodes (Phase 24 write mirroring).  MKDIR/RM/RMDIR/MV/TRUNCATE/CHMOD are
 * self-contained, path-based metadata mutations replayable by the stateless
 * one-shot mirror (W1).  WRITE covers the stateful open(write)->write->close data
 * session driven by the dedicated write-mirror (W3).  All are gated by
 * xrootd_mirror_writes and are deliberately EXCLUDED from OP_DEFAULT/OP_ALL so a
 * write op must be BOTH explicitly listed in xrootd_mirror_opcodes AND have
 * xrootd_mirror_writes on (two independent guards). */
#define XROOTD_MIRROR_OP_MKDIR    (1u << 8)
#define XROOTD_MIRROR_OP_RM       (1u << 9)
#define XROOTD_MIRROR_OP_RMDIR    (1u << 10)
#define XROOTD_MIRROR_OP_MV       (1u << 11)
#define XROOTD_MIRROR_OP_TRUNCATE (1u << 12)
#define XROOTD_MIRROR_OP_CHMOD    (1u << 13)
#define XROOTD_MIRROR_OP_WRITE    (1u << 14)
#define XROOTD_MIRROR_OP_WRITE_ALL (XROOTD_MIRROR_OP_MKDIR    \
                                  | XROOTD_MIRROR_OP_RM        \
                                  | XROOTD_MIRROR_OP_RMDIR     \
                                  | XROOTD_MIRROR_OP_MV        \
                                  | XROOTD_MIRROR_OP_TRUNCATE  \
                                  | XROOTD_MIRROR_OP_CHMOD     \
                                  | XROOTD_MIRROR_OP_WRITE)
#define XROOTD_MIRROR_OP_DEFAULT  (XROOTD_MIRROR_OP_STAT    \
                                  | XROOTD_MIRROR_OP_LOCATE  \
                                  | XROOTD_MIRROR_OP_OPEN    \
                                  | XROOTD_MIRROR_OP_DIRLIST \
                                  | XROOTD_MIRROR_OP_STATX)

/* Every mirrorable opcode.  This is the DEFAULT mask when mirroring is enabled
 * but no xrootd_mirror_opcodes is given: mirror everything, and let the operator
 * de-select with xrootd_mirror_exclude_opcodes.  read/readv stay in the set but
 * are skipped at replay time as non-self-contained (see
 * xrootd_mirror_request_replayable); query/Qcksum replays with graceful
 * "unsupported" handling. */
#define XROOTD_MIRROR_OP_ALL      (XROOTD_MIRROR_OP_STAT    \
                                  | XROOTD_MIRROR_OP_LOCATE  \
                                  | XROOTD_MIRROR_OP_OPEN    \
                                  | XROOTD_MIRROR_OP_READ    \
                                  | XROOTD_MIRROR_OP_READV   \
                                  | XROOTD_MIRROR_OP_DIRLIST \
                                  | XROOTD_MIRROR_OP_STATX   \
                                  | XROOTD_MIRROR_OP_QUERY)

/* One resolved shadow backend. */
typedef struct {
    ngx_str_t                url;       /* original directive value (display) */
    ngx_str_t                host;      /* hostname — Host: header / SNI / log */
    uint16_t                 port;
    ngx_uint_t               ssl;       /* 1 = TLS (https / future stream TLS) */
    ngx_str_t                url_base;  /* "scheme://host[:port]" (HTTP only) */
    struct sockaddr_storage  sockaddr;  /* pre-resolved at config time */
    socklen_t                socklen;
} xrootd_mirror_target_t;

/* Shared mirror configuration block (embedded in both surfaces' conf). */
typedef struct {
    ngx_flag_t   enabled;      /* derived: targets configured */
    ngx_array_t *targets;      /* xrootd_mirror_target_t[] (<= MAX_TARGETS) */
    ngx_uint_t   sample_pct;   /* 1–100; 100 = mirror everything, 0 = none */
    ngx_uint_t   method_mask;  /* XROOTD_MIRROR_M_*  (HTTP surface) */
    ngx_uint_t   opcode_mask;  /* XROOTD_MIRROR_OP_* allowed (stream surface);
                                  default XROOTD_MIRROR_OP_ALL */
    ngx_uint_t   opcode_exclude_mask; /* XROOTD_MIRROR_OP_* de-selected
                                         (xrootd_mirror_exclude_opcodes) */
    ngx_flag_t   strip_auth;   /* 1 = remove credentials before forwarding */
    ngx_flag_t   log_diverge;  /* 1 = NGX_LOG_NOTICE on status divergence */
    ngx_msec_t   timeout_ms;   /* shadow connection/read timeout */
    ngx_str_t    token;        /* optional Bearer token to inject (HTTP) */
    ngx_flag_t   mirror_writes;/* [xrootd_mirror_writes] 1 = replay write ops to an
                                * ISOLATED shadow namespace.  Off by default; the
                                * shadow MUST NOT share the primary's backing store
                                * (replayed writes would corrupt it). */
} xrootd_mirror_conf_t;

/*
 * Per-request sampling decision.  ngx_random() is seeded per worker; a plain
 * modulo draw is adequate for traffic sampling (no cryptographic uniformity
 * needed).  pct==100 short-circuits to always-on so a fully-sampled config
 * never calls the PRNG.
 */
static ngx_inline ngx_uint_t
xrootd_mirror_should_sample(ngx_uint_t sample_pct)
{
    if (sample_pct >= 100) { return 1; }
    if (sample_pct == 0)   { return 0; }
    return (ngx_uint_t) (ngx_random() % 100) < sample_pct;
}

/* Map an HTTP status (or kXR-derived pseudo-status) to its class digit 1..5. */
static ngx_inline ngx_uint_t
xrootd_mirror_status_class(ngx_uint_t status)
{
    return status / 100;
}

#endif /* XROOTD_MIRROR_H */
