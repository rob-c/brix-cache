#ifndef BRIX_TYPES_TUNABLES_H
#define BRIX_TYPES_TUNABLES_H

#include "core/compat/path.h"

/* Stringification macro for compile-time constants */
#define BRIX_STRINGIFY_HELPER(x)  #x
#define BRIX_STRINGIFY(x)         BRIX_STRINGIFY_HELPER(x)

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
 *   Protocol Constants:
 *   - BRIX_QCONFIG_RESP_MAX: 512 bytes (kXR_Qconfig response buffer)
 *   - BRIX_QCONFIG_KEY_MAX: 128 bytes (kXR_Qconfig key token buffer)
 *   - BRIX_QSPACE_RESP_MAX: 256 bytes (kXR_Qspace/QFSinfo response buffer)
 *   - BRIX_CHKPT_EXT_LEN: 4 bytes (".ckp" extension length)
 *   - BRIX_CHKPT_EXT_NUL: 5 bytes (".ckp" with null terminator)
 *   - BRIX_CHKPT_MODE: 0600 (checkpoint file permissions)
 *   - BRIX_CHKPT_SIZE_MAX: 0xFFFFFFFF (UINT32_MAX for wire protocol)
 *   - BRIX_TPC_TOKEN_MAX: 65536 bytes (TPC delegated token buffer)
 *   - BRIX_TPC_TOKEN_ERR_MAX: 256 bytes (TPC token error message buffer)
 *   - BRIX_TPC_PREFIX_LEN: 4 bytes ("tpc." prefix length)
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
 * Buffer size constants for various subsystems.
 *
 * BRIX_METER_BUF_SIZE: 8 KB buffer for CMS metering/formatting
 * BRIX_CMS_ERR_BUF_SIZE: 256 bytes for CMS error messages
 * BRIX_IP_STR_LEN: 64 bytes for IP address string representation
 * BRIX_XML_BUF_SIZE: 2 KB for XML parsing buffers
 * BRIX_PID_BUF_SIZE: 1 KB for process ID string formatting
 * BRIX_SHA256_LEN: 32 bytes (256-bit hash output)
 * BRIX_PATH_BUF_SIZE: 1 KB for temporary path buffers (smaller than PATH_MAX)
 */
#define BRIX_METER_BUF_SIZE        8192
#define BRIX_CMS_ERR_BUF_SIZE      256
#define BRIX_IP_STR_LEN            64
#define BRIX_XML_BUF_SIZE          2048
#define BRIX_PID_BUF_SIZE          1024
#define BRIX_SHA256_LEN            32
#define BRIX_PATH_BUF_SIZE         1024

/*
 * Additional buffer size constants for filesystem and cache operations.
 *
 * BRIX_SMALL_BUF_SIZE: 256 bytes for small temporary buffers
 * BRIX_MEDIUM_BUF_SIZE: 1024 bytes for medium buffers (paths, hostnames)
 * BRIX_LARGE_BUF_SIZE: 2048 bytes for larger temporary buffers
 * BRIX_XLARGE_BUF_SIZE: 4096 bytes for response buffers
 * BRIX_HUGE_BUF_SIZE: 65536 bytes for large I/O operations
 * BRIX_QBUF_SIZE: 64 bytes for small query buffers
 */
#define BRIX_SMALL_BUF_SIZE        256
#define BRIX_MEDIUM_BUF_SIZE       1024
#define BRIX_LARGE_BUF_SIZE        2048
#define BRIX_XLARGE_BUF_SIZE       4096
#define BRIX_HUGE_BUF_SIZE         65536

/*
 * Metrics histogram bucket bounds for latency measurements.
 *
 * BRIX_LATENCY_BOUND_*: Histogram bucket upper bounds in microseconds.
 *                       Follows Prometheus convention: 1ms, 5ms, 10ms, 50ms,
 *                       100ms, 500ms, 1s, 5s, 10s, +Inf (9 buckets total).
 *                       Stored in µs, exported in seconds (%.6f format).
 * BRIX_LATENCY_BOUNDS_COUNT: Number of finite buckets (excludes +Inf)
 * BRIX_IO_LATENCY_BUCKETS: Total histogram slots including +Inf slot
 *
 * WHY: Named constants make histogram configuration explicit and auditable.
 *      Operators can adjust latency sensitivity without hunting magic numbers.
 *      Matches brix_cvmfs_upstream_fill_duration_seconds and
 *      brix_frm_stage_latency_seconds conventions (seconds unit, cumulative le).
 */
#define BRIX_LATENCY_BOUND_1MS       1000
#define BRIX_LATENCY_BOUND_5MS       5000
#define BRIX_LATENCY_BOUND_10MS      10000
#define BRIX_LATENCY_BOUND_50MS      50000
#define BRIX_LATENCY_BOUND_100MS     100000
#define BRIX_LATENCY_BOUND_500MS     500000
#define BRIX_LATENCY_BOUND_1S        1000000
#define BRIX_LATENCY_BOUND_5S        5000000
#define BRIX_LATENCY_BOUND_10S       10000000
#define BRIX_LATENCY_BOUNDS_COUNT    9
#define BRIX_IO_LATENCY_BUCKETS      (BRIX_LATENCY_BOUNDS_COUNT + 1)

/* ---- Filesystem Constants ---- */

/*
 * VFS backend configuration buffer sizes.
 * Used for parsing backend configuration strings (Ceph, S3, HTTP, GSI FTP).
 * BRIX_VFS_CEPH_CONF_BUF: 1024 bytes for Ceph configuration
 * BRIX_VFS_PATH_BUF: 1024 bytes for path buffers
 * BRIX_VFS_HOST_BUF: 256 bytes for hostname buffers
 * BRIX_VFS_POOL_BUF: 256 bytes for pool name buffers
 * BRIX_VFS_META_BUF: 256 bytes for metadata buffers
 * BRIX_VFS_DATA_BUF: 256 bytes for data path buffers
 * BRIX_VFS_QUERY_BUF: 64 bytes for query parameter buffers
 */
#define BRIX_VFS_CEPH_CONF_BUF             1024
#define BRIX_VFS_PATH_BUF                  1024
#define BRIX_VFS_HOST_BUF                  256
#define BRIX_VFS_POOL_BUF                  256
#define BRIX_VFS_META_BUF                  256
#define BRIX_VFS_DATA_BUF                  256
#define BRIX_VFS_QUERY_BUF                 64

/*
 * CephFS backend timing constants.
 * Used for retry backoff and timeout operations.
 * BRIX_CEPHFS_RO_BACKOFF_BASE_US: 2000μs base backoff (exponential)
 * BRIX_CEPHFS_RO_BACKOFF_MAX_US: 50000μs maximum backoff cap (50ms)
 */
#define BRIX_CEPHFS_RO_BACKOFF_BASE_US       2000
#define BRIX_CEPHFS_RO_BACKOFF_MAX_US        50000

/*
 * File permission constants for VFS operations.
 * Standard POSIX permissions used throughout filesystem layer.
 */
#define BRIX_VFS_DIR_PERM_DEFAULT          0755  /* Default directory permissions */
#define BRIX_VFS_FILE_PERM_DEFAULT         0644  /* Default file permissions */
#define BRIX_VFS_DIR_PERM_RESTRICTED       0700  /* Restricted directory (user-only) */
#define BRIX_VFS_FILE_PERM_RESTRICTED      0600  /* Restricted file (user-only) */
#define BRIX_VFS_DIR_PERM_GROUP            0770  /* Group-shared directory */
#define BRIX_VFS_FILE_PERM_GROUP           0660  /* Group-shared file */
#define BRIX_VFS_MODE_MASK                 0777  /* Permission bits mask */

/*
 * VFS buffer size constants for various operations.
 * Buffer capacities for VFS I/O and data transfer.
 */
#define BRIX_VFS_WRITER_CHUNK_SIZE         65536  /* VFS writer chunk size */
#define BRIX_VFS_IO_CHUNK_SIZE             65536  /* General VFS I/O chunk */
#define BRIX_VFS_AUTH_LINE_BUF             1024   /* Auth credential line buffer */
#define BRIX_VFS_CRED_X509_BUF             2048   /* X.509 credential buffer */
#define BRIX_VFS_CRED_BEARER_BUF           4096   /* Bearer token buffer */
#define BRIX_VFS_CRED_KEYTAB_BUF           1024   /* Keytab credential buffer */
#define BRIX_VFS_CRED_CCACHE_BUF           1024   /* Credential cache buffer */
#define BRIX_VFS_CRED_SSS_KEYTAB_BUF       1024   /* SSS keytab buffer */
#define BRIX_VFS_MANIFEST_BUF              65536  /* Manifest buffer size */
#define BRIX_VFS_FRM_CANDIDATES_MAX        65536  /* FRM purge candidates max */
#define BRIX_VFS_ZIP_COMMENT_MAX           65535  /* ZIP comment max length */
#define BRIX_VFS_ZIP_IO_CHUNK              65536  /* ZIP I/O chunk size */

/*
 * VFS timeout constants (milliseconds).
 * Timeout values for VFS backend operations.
 */
#define BRIX_GSIFTP_BACKEND_TIMEOUT_MS     30000  /* GSI FTP backend timeout */
#define BRIX_VFS_S3_TIMEOUT_DEFAULT_MS     60000  /* S3 backend default timeout */
#define BRIX_VFS_TIMEOUT_DEFAULT_MS        60000  /* General VFS timeout default */

/*
 * VFS port and validation constants.
 * Port range limits and validation thresholds.
 */
#define BRIX_VFS_PORT_MIN                  1      /* Minimum valid port */
#define BRIX_VFS_PORT_MAX                  65535  /* Maximum valid port */
#define BRIX_VFS_PORT_GSIFTP_DEFAULT       2811   /* Default GSI FTP port */
#define BRIX_VFS_PORT_GSIFTP_UNPRIV        21     /* Unprivileged GSI FTP port */
#define BRIX_VFS_PORT_S3_DEFAULT           7480   /* Default S3 port (radosgw) */

/*
 * VFS time conversion constants.
 * Constants for time unit conversions in VFS operations.
 */
#define BRIX_VFS_NSEC_PER_SEC              1000000000ULL  /* Nanoseconds per second */
#define BRIX_VFS_NSEC_PER_MSEC             1000000L       /* Nanoseconds per millisecond */
#define BRIX_VFS_USEC_PER_SEC              1000000        /* Microseconds per second */
#define BRIX_VFS_OCCUPANCY_PPM_MAX         1000000        /* Max occupancy (parts per million) */

/*
 * VFS rate and calculation constants.
 * Constants used in rate calculations and occupancy tracking.
 */
#define BRIX_VFS_RATE_BPS_DIVISOR          1000000000ULL  /* Rate calculation divisor */

/*
 * VFS buffer size constants.
 * Buffer capacities for VFS operations and data transfer.
 */
#define BRIX_VFS_CORE_BUF_SIZE             (256 * 1024)   /* VFS core transfer buffer */
#define BRIX_VFS_AUTH_LINE_BUF_SIZE        1024           /* Auth credential line buffer */
#define BRIX_VFS_CRED_BUF_SIZE             2048           /* General credential buffer */
#define BRIX_VFS_PROXY_PEM_BUF_SIZE        2048           /* Proxy PEM credential buffer */
#define BRIX_VFS_X509_PROXY_BUF_SIZE       2048           /* X.509 proxy credential buffer */
#define BRIX_VFS_TGT_CCACHE_BUF_SIZE       1024           /* TGT credential cache buffer */
#define BRIX_VFS_KEYTAB_BUF_SIZE           1024           /* Keytab credential buffer */

/*
 * VFS path and canon buffer sizes.
 * Buffer sizes for path manipulation and canonicalization.
 */
#define BRIX_VFS_CANON_PATH_BUF_SIZE       1024           /* Canonical path buffer */
#define BRIX_VFS_SITE_N2N_BUF_SIZE         1024           /* Site name-to-name buffer */

/*
 * VFS backend configuration buffer sizes.
 * Buffer sizes for backend configuration and URL construction.
 */
#define BRIX_VFS_S3_STACK_BUF_SIZE         1024           /* S3 transport stack buffer */
#define BRIX_VFS_S3_SAFE_BUF_SIZE          1024           /* S3 safe URL buffer */
#define BRIX_VFS_S3_URL_BUF_SIZE           2048           /* S3 full URL buffer */
#define BRIX_VFS_S3_CANON_BUF_SIZE         8192           /* S3 canonical request buffer */
#define BRIX_VFS_S3_EMIT_BUF_SIZE          2112           /* S3 emit buffer */
#define BRIX_VFS_S3_AUTH_HDRS_BUF_SIZE     4096           /* S3 auth headers buffer */
#define BRIX_VFS_S3_SESSION_TOKEN_BUF_SIZE 2048           /* S3 session token buffer */
#define BRIX_VFS_S3_DOC_BUF_SIZE           (64 * 1024)    /* S3 XML document buffer */
#define BRIX_VFS_S3_AUTHZ_BUF_SIZE         2200           /* S3 authorization buffer */
#define BRIX_VFS_S3_JWT_BUF_SIZE           3072           /* S3 JWT buffer */

/*
 * VFS backend I/O buffer sizes.
 * Buffer sizes for backend read/write operations.
 */
#define BRIX_VFS_S3_PREAD_MAX              (7LL * 1024 * 1024)  /* S3 max pread size */
#define BRIX_VFS_S3_PUT_BUF_INIT           (64 * 1024)    /* S3 PUT initial buffer */
#define BRIX_VFS_S3_KEY_MAX                4096           /* S3 max key length */
#define BRIX_VFS_S3_LIST_QS_CAP            4096           /* S3 list query string cap */
#define BRIX_VFS_S3_LIST_MAX_KEYS          1000           /* S3 list max keys per page */

/*
 * VFS origin protocol buffer sizes.
 * Buffer sizes for origin protocol operations.
 */
#define BRIX_VFS_ORIGIN_FATTR_SEND_BUF     65536          /* Origin fattr send buffer */
#define BRIX_VFS_ORIGIN_PREAD_DATA_MAX     4096           /* Origin pgread data unit */
#define BRIX_VFS_ORIGIN_PREAD_CRC_SIZE     4              /* Origin pgread CRC size */

/*
 * VFS cache buffer sizes.
 * Buffer sizes for cache operations.
 */
#define BRIX_VFS_CACHE_AUTH_LINE_BUF_SIZE  1024           /* Cache auth line buffer */
#define BRIX_VFS_CACHE_CRED_BUF_SIZE       2048           /* Cache credential buffer */
#define BRIX_VFS_CACHE_PELICAN_REG_BUF     (64 * 1024)    /* Pelican registration buffer */
#define BRIX_VFS_CACHE_BACKOFF_CAP_MS      8000           /* Fill backoff cap (ms) */
#define BRIX_VFS_CACHE_CINFO_L1_ENTRIES    4096           /* Cache info L1 default entries */

/*
 * VFS metadata buffer sizes.
 * Buffer sizes for extended metadata operations.
 */
#define BRIX_VFS_XMETA_CARRIER_CAP_INIT    (64 * 1024)    /* Xmeta carrier initial cap */
#define BRIX_VFS_XMETA_UCRED_BUF_SIZE      4096           /* User credential buffer */

/*
 * VFS backend S3 signing buffer sizes.
 * Buffer sizes for S3 signature calculation.
 */
#define BRIX_VFS_S3_SIGN_CANON_BUF_SIZE    8192           /* S3 signing canonical request */
#define BRIX_VFS_S3_SIGN_SCOPE_BUF_SIZE    160            /* S3 signing scope buffer */
#define BRIX_VFS_S3_SIGN_ENC_URI_BUF_SIZE  2048           /* S3 signing encoded URI */

/*
 * VFS time conversion constants.
 * Constants for time unit conversions in VFS operations.
 */
#define BRIX_VFS_SECS_PER_DAY              86400          /* Seconds per day */
#define BRIX_VFS_SECS_PER_HOUR             3600           /* Seconds per hour */
#define BRIX_VFS_SECS_PER_MIN              60             /* Seconds per minute */
#define BRIX_VFS_MSEC_PER_SEC              1000           /* Milliseconds per second */
#define BRIX_VFS_NSEC_PER_USEC             1000           /* Nanoseconds per microsecond */

/*
 * VFS size multiplier constants.
 * Multipliers for size calculations.
 */
#define BRIX_VFS_KILOBYTE                  1024           /* 1 KB in bytes */
#define BRIX_VFS_MEGABYTE                  (1024 * 1024)  /* 1 MB in bytes */
#define BRIX_VFS_GIGABYTE                  (1024 * 1024 * 1024)  /* 1 GB in bytes */

/*
 * Filesystem backend timeout constants (milliseconds).
 * Timeout values for various backend operations.
 */

/* ---- Observability Constants ---- */

/*
 * Metrics buffer and export sizes.
 * Buffer capacities for metrics collection and Prometheus export.
 */
#define BRIX_METRICS_BUF_SIZE              65536  /* Main metrics buffer */
#define BRIX_METRICS_HEALTH_BUF          2048   /* Health check response buffer */
#define BRIX_METRICS_CONFIG_BUF            4096   /* Metrics config buffer */
#define BRIX_METRICS_ACCESS_LOG_PATH_BUF   1024   /* Access log path buffer */

/*
 * Metrics histogram bucket boundaries (microseconds).
 * Time-based buckets for latency histograms in unified metrics.
 * Covers sub-millisecond to 5-second range with logarithmic distribution.
 */
#define BRIX_METRICS_LATENCY_BUCKETS_US_COUNT  10
#define BRIX_METRICS_LATENCY_BUCKET_1_US       1000      /* 1 ms */
#define BRIX_METRICS_LATENCY_BUCKET_2_US       5000      /* 5 ms */
#define BRIX_METRICS_LATENCY_BUCKET_3_US       10000     /* 10 ms */
#define BRIX_METRICS_LATENCY_BUCKET_4_US       50000     /* 50 ms */
#define BRIX_METRICS_LATENCY_BUCKET_5_US       100000    /* 100 ms */
#define BRIX_METRICS_LATENCY_BUCKET_6_US       500000    /* 500 ms */
#define BRIX_METRICS_LATENCY_BUCKET_7_US       1000000   /* 1 second */
#define BRIX_METRICS_LATENCY_BUCKET_8_US       5000000   /* 5 seconds */

/*
 * CVMFS metrics histogram buckets (milliseconds).
 * Specialized buckets for CVMFS operation latency tracking.
 * Covers 5ms to 10s range appropriate for CVMFS operations.
 */
#define BRIX_CVMFS_BUCKET_COUNT            6
#define BRIX_CVMFS_BUCKET_1_MS             5       /* 5 ms */
#define BRIX_CVMFS_BUCKET_2_MS             25      /* 25 ms */
#define BRIX_CVMFS_BUCKET_3_MS             100     /* 100 ms */
#define BRIX_CVMFS_BUCKET_4_MS             500     /* 500 ms */
#define BRIX_CVMFS_BUCKET_5_MS             2000    /* 2 seconds */
#define BRIX_CVMFS_BUCKET_6_MS             10000   /* 10 seconds */
#define BRIX_CVMFS_QOS_TOKEN_DECREMENT     1000    /* QoS token decrement per fill */

/*
 * FRM (File Registry Manager) metrics histogram buckets (seconds).
 * Buckets for FRM operation latency tracking.
 * Covers 1s to 1 hour range for long-running FRM operations.
 */
#define BRIX_FRM_BUCKET_COUNT              8
#define BRIX_FRM_BUCKET_1_SEC              1       /* 1 second */
#define BRIX_FRM_BUCKET_2_SEC              10      /* 10 seconds */
#define BRIX_FRM_BUCKET_3_SEC              30      /* 30 seconds */
#define BRIX_FRM_BUCKET_4_SEC              60      /* 1 minute */
#define BRIX_FRM_BUCKET_5_SEC              300     /* 5 minutes */
#define BRIX_FRM_BUCKET_6_SEC              1800    /* 30 minutes */
#define BRIX_FRM_BUCKET_7_SEC              3600    /* 1 hour */

/*
 * Dashboard rate limiting constants.
 * Requests per minute limits for dashboard API endpoints.
 */
#define BRIX_DASHBOARD_READ_RL_PM          1200   /* Read requests per minute */
#define BRIX_DASHBOARD_WRITE_RL_PM         120    /* Write requests per minute */

/*
 * Dashboard scan and cluster limits.
 * Bounds for filesystem scan operations and cluster tracking.
 */
#define BRIX_DASHBOARD_SCAN_MAX_FILES      100000  /* Max files in scan */
#define BRIX_DASHBOARD_CLUSTER_MAX         256     /* Max cluster nodes tracked */

/*
 * CMS subsystem constants.
 *
 * BRIX_CMS_POOL_SIZE: 4 KB memory pool for CMS task allocation
 * BRIX_CMS_RESPAWN_DELAY_MS: 5 second backoff for monitor respawn
 * BRIX_CMS_PATHZ_BUF: 1 KB path buffer for state operations
 * BRIX_CMS_PAYLOAD_BUF: 1280 bytes for CMS payload buffers
 * BRIX_CMS_IP_HASH_INIT: 5381 DJB2 hash initialization constant
 * BRIX_BYTES_PER_GB: 1073741824 bytes in a gibibyte (2^30)
 * BRIX_BYTES_PER_MB: 1048576 bytes in a mebibyte (2^20)
 * BRIX_PCT_MAX: 1000 maximum percentage value (monitor scale, 0-1000)
 * BRIX_PCT_SCALE: 100 multiplier for percentage calculations
 * BRIX_FREE_MB_MAX: 2147483647 maximum free MB value (INT32_MAX, prevents overflow)
 * BRIX_FREE_MB_BITS: 31 bit threshold for overflow check
 * BRIX_BYTES_TO_MB_SHIFT: 20 bit shift for bytes→MB conversion (2^20)
 * BRIX_MONITOR_PCT_MAX: 1000 maximum monitor percentage value (CMS meter scale)
 */
#define BRIX_CMS_POOL_SIZE         4096
#define BRIX_CMS_RESPAWN_DELAY_MS  5000
#define BRIX_CMS_PATHZ_BUF         1024
#define BRIX_CMS_PAYLOAD_BUF       1280
#define BRIX_CMS_IP_HASH_INIT      5381
#define BRIX_BYTES_PER_GB          1073741824ULL
#define BRIX_BYTES_PER_MB          1048576ULL

/*
 * io_uring maximum submission queue depth.
 * Upper bound for uring ring depth to prevent excessive memory allocation.
 * 4096 entries is the practical maximum for most workloads.
 */
#define BRIX_URING_MAX_DEPTH       4096

/*
 * Extended metadata (xmeta) initialization chunk size.
 * Default allocation size for xmeta structures in bytes (1 MB).
 * Balances memory efficiency against allocation overhead.
 */
#define BRIX_XMETA_INIT_SIZE       (BRIX_BYTES_PER_MB)

#define BRIX_PCT_MAX               1000
#define BRIX_PCT_SCALE             100
#define BRIX_FREE_MB_MAX           2147483647LL
#define BRIX_FREE_MB_BITS          31
#define BRIX_BYTES_TO_MB_SHIFT     20
#define BRIX_QBUF_SIZE             64

/*
 * Additional CMS timing and conversion constants.
 *
 * BRIX_CMS_BACKOFF_MULTIPLIER: 10000 multiplier for max backoff calculation
 * BRIX_CMS_NS_TO_MS_DIVISOR: 1000000 divisor for nanoseconds→milliseconds conversion
 * BRIX_CMS_SEC_TO_MS_MULTIPLIER: 1000 multiplier for seconds→milliseconds conversion
 * BRIX_CMS_BLACKLIST_DURATION_MS: 86400000ms (24 hours) default blacklist duration
 * BRIX_CMS_MIN_INTERVAL_MS: 1000ms minimum interval floor
 * BRIX_CMS_MONITOR_PCT_THRESHOLD: 1000 maximum monitor percentage value
 * BRIX_CMS_SSS_LIFETIME_SECS: 3600 seconds (1 hour) SSS credential lifetime
 */
#define BRIX_CMS_BACKOFF_MULTIPLIER      10000
#define BRIX_CMS_NS_TO_MS_DIVISOR        1000000
#define BRIX_CMS_SEC_TO_MS_MULTIPLIER    1000
#define BRIX_CMS_BLACKLIST_DURATION_MS   86400000
#define BRIX_CMS_MIN_INTERVAL_MS         1000
#define BRIX_CMS_MONITOR_PCT_THRESHOLD   1000
#define BRIX_CMS_SSS_LIFETIME_SECS       3600

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
 * Additional DNS timing and conversion constants.
 *
 * BRIX_DNS_US_TO_MS_DIVISOR: 1000 divisor for microseconds→milliseconds conversion
 * BRIX_DNS_PORT_MAX: 65535 maximum valid port number (16-bit)
 * BRIX_DNS_DEADLINE_MIN_MS: 5000ms minimum deadline for DNS operations
 * BRIX_DNS_DEADLINE_MAX_MS: 60000ms maximum deadline for DNS operations
 * BRIX_DNS_TIMEOUT_FLOOR_MS: 1000ms minimum timeout floor
 * BRIX_DNS_NS_PER_MS: 1000000 nanoseconds per millisecond
 * BRIX_DNS_NS_PER_SEC: 1000000000 nanoseconds per second
 * BRIX_DNS_RESOLV_READ_MAX: 65536 bytes maximum /etc/resolv.conf read size
 */
#define BRIX_DNS_US_TO_MS_DIVISOR        1000
#define BRIX_DNS_PORT_MAX                65535
#define BRIX_DNS_DEADLINE_MIN_MS         5000
#define BRIX_DNS_DEADLINE_MAX_MS         60000
#define BRIX_DNS_TIMEOUT_FLOOR_MS        1000
#define BRIX_DNS_NS_PER_MS               1000000L
#define BRIX_DNS_NS_PER_SEC              1000000000L
#define BRIX_DNS_RESOLV_READ_MAX         (64 * 1024)

/* ---- XRootD ROOT protocol constants ---- */

/*
 * XRootD page size for paged I/O (kXR_pgread/kXR_pgwrite).
 * Standard XRootD page size is 4096 bytes. Used for CRC32c framed I/O.
 * Per AGENTS.md INVARIANT #1: pgread/pgwrite → kXR_status(4007) + per-page CRC32c
 */
#define BRIX_ROOT_PAGE_SIZE                    4096

/*
 * XRootD page checksum size (CRC32c).
 * Each page in paged I/O carries a 4-byte CRC32c checksum.
 */
#define BRIX_ROOT_PAGE_CKSIZE                  4

/*
 * XRootD page record size (data + checksum).
 * Total size of one paged I/O record: 4096 bytes data + 4 bytes CRC32c = 4100 bytes.
 */
#define BRIX_ROOT_PAGE_RECORD_SIZE             4100

/*
 * XRootD probe path buffer size.
 * Stack buffer for path probing during connection validation.
 */
#define BRIX_ROOT_PROBE_PATH_SIZE              1024

/*
 * XRootD locate manager list buffer size.
 * Buffer for endpoint list formatting in kXR_locate responses.
 */
#define BRIX_ROOT_LOCATE_LIST_BUF_SIZE         2048

/*
 * XRootD relay line buffer size.
 * Buffer for relay command/response line processing.
 */
#define BRIX_ROOT_RELAY_LINE_BUF_SIZE          1280

/*
 * XRootD stat conversion divisor (bytes to KB).
 * Used to convert byte counts to kilobytes in kXR_query stats responses.
 * 1024 = 1 KB
 */
#define BRIX_ROOT_BYTES_TO_KB                  1024

/*
 * XRootD stat conversion divisor (bytes to MB).
 * Used to convert byte counts to megabytes in kXR_stat responses.
 * 1048576 = 1024 * 1024 = 1 MB
 */
#define BRIX_ROOT_BYTES_TO_MB                  1048576

/*
 * XRootD milliseconds to seconds conversion divisor.
 * Used to convert millisecond timestamps to seconds.
 */
#define BRIX_ROOT_MS_TO_SEC                    1000

/*
 * XRootD default file descriptor limit for query operations.
 * Used when RLIMIT_NOFILE is unavailable or invalid.
 */
#define BRIX_ROOT_DEFAULT_MAX_FD               1024

/*
 * XRootD directory list chunk capacity.
 * Maximum bytes per dirlist chunk to control memory usage.
 */
#define BRIX_ROOT_DIRLIST_CHUNK_SIZE           65536

/*
 * Default XRootD root protocol port number.
 * IANA-assigned port for XRootD file access protocol.
 * Used when port is not specified in root:// URLs.
 */
#define BRIX_ROOT_DEFAULT_PORT                 1094

/*
 * XRootD protocol version for GSI signed DH requirement.
 * Clients advertising version >= 10400 support signed DH handshake.
 */
#define BRIX_ROOT_GSI_SIGNED_DH_MIN_VERSION    10400

/* ---- XRootD ROOT protocol - file attribute constants ---- */

/*
 * XRootD maximum file attribute name length.
 * Derived from: 255 (XATTR_NAME_MAX) - 7 (len("user.")) = 248 bytes.
 * This is the maximum length for xattr names in the "user." namespace on ext4/xfs.
 */
#define BRIX_ROOT_FATTR_NAME_MAX               248

/*
 * XRootD maximum file attribute value length.
 * 64 KiB cap matches ext4/xfs stock xattr value limits.
 * Used in kXR_query config responses for filesystem capability reporting.
 */
#define BRIX_ROOT_FATTR_VALUE_MAX              65536

/*
 * XRootD compression buffer slack.
 * Additional buffer space for compression overhead (worst-case expansion).
 * Formula: plain + (plain / 2) + BRIX_ROOT_COMPRESS_SLACK
 */
#define BRIX_ROOT_COMPRESS_SLACK               4096

/*
 * XRootD fattr list buffer slack.
 * Additional space to absorb attribute names added between stat and list.
 */
#define BRIX_ROOT_FATTR_LIST_SLACK             4096

/* ---- XRootD ROOT protocol - timeout constants ---- */

/*
 * XRootD write cache validity timeout (milliseconds).
 * Cached write metadata is considered valid for 5 seconds before re-validation.
 * Balances performance (avoiding stat() calls) with consistency.
 */
#define BRIX_ROOT_WRITE_CACHE_VALIDITY_MS      5000

/*
 * XRootD seconds-to-milliseconds conversion factor.
 * Used for admin socket and other timeout conversions.
 */
#define BRIX_ROOT_MS_PER_SEC                   1000

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
 * CMS send timeout (milliseconds).
 * Maximum time to wait for CMS send operation before failure.
 * 10 seconds provides reasonable timeout for network operations.
 */
#define BRIX_CMS_SEND_TIMEOUT_DEFAULT_MS       10000

/*
 * CMS locate timeout (milliseconds).
 * Maximum time to wait for CMS locate operation before failure.
 * 5 seconds allows for fast failure on missing files.
 */
#define BRIX_CMS_LOCATE_TIMEOUT_DEFAULT_MS     5000

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

/* ---- Additional timeout constants (runtime-configurable defaults) ---- */

/*
 * WebDAV lock timeout maximum (seconds).
 * RFC 4918 recommends 1 hour as the default lock lifetime.  Clients may
 * request shorter or longer timeouts, but this is the maximum allowed.
 * Prevents clients from requesting excessively long locks that could block resources.
 */
#define BRIX_WEBDAV_LOCK_TIMEOUT_MAX           3600

/*
 * CMS read timeout maximum (milliseconds).
 * Maximum time to wait for CMS manager answer before fallback.
 * 90 seconds is the floor — allows for slow storage + network latency.
 * Exceeding this suggests a hung backend or network partition.
 */
#define BRIX_CMS_READ_TIMEOUT_MAX_MS           90000

/* ---- CMS Port and Network Constants ---- */

/*
 * Maximum valid port number (16-bit).
 * Used for port validation in CMS admin and blacklist parsing.
 * Matches TCP/UDP port range limit (0-65535).
 */
#define BRIX_CMS_MAX_PORT                        65535

/*
 * Default XRootD CMS port.
 * Standard port for XRootD Cluster Management System.
 * Used as default when no port is specified in host:port specs.
 */
#define BRIX_CMS_DEFAULT_PORT                    1094

/* ---- CMS Buffer Size Constants ---- */

/*
 * CMS admin target hostname buffer size (bytes).
 * Accommodates FQDNs with subdomains while bounding stack allocation.
 * 256 bytes allows for very long hostnames with safety margin.
 */
#define BRIX_CMS_ADMIN_HOST_BUF                  256

/*
 * CMS frame state path buffer size (bytes).
 * Maximum path length for CMS state probe operations.
 * 1024 bytes accommodates deep directory hierarchies.
 */
#define BRIX_CMS_STATE_PATH_BUF                  1024

/*
 * CMS frame state safe log buffer size (bytes).
 * Sanitized path buffer for log output (escapes special chars).
 * 256 bytes sufficient for truncated path representation.
 */
#define BRIX_CMS_STATE_SAFE_BUF                  256

/*
 * CMS login payload buffer size (bytes).
 * Wire format payload for kYR_login frames.
 * 1280 bytes accommodates SID, paths, ifList, envCGI fields.
 */
#define BRIX_CMS_LOGIN_PAYLOAD_BUF               1280

/*
 * CMS SID (server identity) buffer size (bytes).
 * Format: "<hostname>:<port>" — typically <100 bytes.
 * 256 bytes provides generous margin for long hostnames.
 */
#define BRIX_CMS_SID_BUF                         256

/*
 * CMS path list buffer size (bytes).
 * Newline-separated "<type> <path>" entries for login.
 * 640 bytes accommodates multiple export paths.
 */
#define BRIX_CMS_PATH_LIST_BUF                   640

/*
 * CMS environment CGI buffer size (bytes).
 * Carries "vnid=<id>" when configured.
 * 80 bytes sufficient for typical VNID strings.
 */
#define BRIX_CMS_ENV_CGI_BUF                     80

/*
 * CMS host identity buffer size (bytes).
 * gethostname() result for server identification.
 * 200 bytes accommodates long hostnames with safety margin.
 */
#define BRIX_CMS_HOST_ID_BUF                     200

/*
 * FSXEQ captured stdout buffer size (bytes).
 * Operator-facing log output from filesystem exec programs.
 * 256 bytes captures first ~40 lines of output.
 */
#define BRIX_CMS_FSXEQ_OUT_BUF                   256

/* ---- CMS Hash and Limit Constants ---- */

/*
 * DJB2 hash initial value for IP tracking.
 * Classic string hash algorithm constant (djb2-xor variant).
 * Used in brix_cms_ip_hash() for connection limiting.
 */
#define BRIX_CMS_IP_HASH_INIT                    5381

/*
 * Minimum interval between connection count checks (milliseconds).
 * Rate limiting for per-IP connection tracking.
 * 1000ms = 1 second prevents rapid count updates.
 */
#define BRIX_CMS_IP_CHECK_INTERVAL_MS            1000

/*
 * Maximum CMS server connections (global).
 * Prevents excessive connection consumption.
 * 4096 allows for large cluster deployments.
 */
#define BRIX_CMS_MAX_CONNECTIONS                 4096

/*
 * Maximum CMS connections per IP address.
 * Prevents single host from monopolizing server connections.
 * 256 allows for multi-process clients on same host.
 */
#define BRIX_CMS_MAX_CONNECTIONS_PER_IP          256

/*
 * FSXEQ mode bits display mask (octal).
 * Shows full permission bits (setuid/setgid/sticky + rwx).
 * 07777 = all permission and special bits.
 */
#define BRIX_CMS_MODE_BITS_MASK                  07777

/*
 * CMS file and directory permission constants (octal).
 *
 * BRIX_CMS_DIR_PERM: 0755 — default directory permissions (rwxr-xr-x)
 * BRIX_CMS_FILE_PERM: 0644 — default file permissions (rw-r--r--)
 * BRIX_CMS_PRIVATE_PERM: 0600 — private file permissions (rw-------)
 * BRIX_CMS_RESTRICTED_PERM: 0640 — restricted file permissions (rw-r-----)
 *
 * WHY: CMS management files and directories need consistent permissions.
 * Private files (credentials, keys) use 0600; shared configs use 0640/0644.
 */
#define BRIX_CMS_DIR_PERM          0755
#define BRIX_CMS_FILE_PERM         0644
#define BRIX_CMS_PRIVATE_PERM      0600
#define BRIX_CMS_RESTRICTED_PERM   0640

/*
 * CMS maximum frame payload size (4096 bytes).
 * Maximum payload that fits in a single CMS frame.
 * Used for frame I/O validation and buffer allocation.
 */
#define BRIX_CMS_MAX_FRAME         4096

/*
 * Admin socket pool size (2048 bytes).
 * Memory pool size for admin command connection handling.
 * Sufficient for command parsing and response buffering.
 */
#define BRIX_ADMIN_POOL_SIZE       2048

/* ---- VFS Backend Timeout Constants ---- */

/*
 * VFS backend busy timeout (milliseconds).
 * Default timeout when backend reports "busy" — triggers retry or failover.
 * 5 seconds allows for network round-trip + backend processing + response.
 * Used in VFS backend registry and tier configuration.
 */
#define BRIX_VFS_BUSY_TIMEOUT_DEFAULT_MS       5000

/*
 * GSI-FTP operation timeout (milliseconds).
 * Default timeout for GridFTP control and data channel operations.
 * 30 seconds allows for authentication handshake + data channel setup.
 * Longer operations (multi-GB transfers) use progress-based timeouts.
 */
#define BRIX_GSIFTP_TIMEOUT_DEFAULT_MS         30000

/*
 * S3 operation timeout (milliseconds).
 * Default timeout for S3 API operations (PUT, GET, LIST, etc.).
 * 300 seconds (5 minutes) allows for multi-GB object transfers with retry.
 * Individual API calls (HEAD, LIST) complete much faster.
 */
#define BRIX_S3_TIMEOUT_DEFAULT_MS             300000

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
 * Default XRootD port number (1094).
 * Standard port for XRootD protocol communication.
 * Used when port is not explicitly specified in upstream configuration.
 */
#define BRIX_PROXY_DEFAULT_PORT                1094

/*
 * Proxy audit line buffer size (1280 bytes).
 * Maximum length for formatted audit log lines.
 * Accommodates full request/response metadata with path and session info.
 */
#define BRIX_PROXY_AUDIT_LINE_BUF              1280

/*
 * Maximum bearer token size for proxy upstream auth (65536 bytes).
 * JWT tokens with claims typically 2-4 KB; 64 KB provides 16x headroom.
 * Prevents buffer overflow on malformed or malicious oversized tokens.
 */
#define BRIX_PROXY_BEARER_TOKEN_MAX            65536

/*
 * Proxy keepalive default interval (15000 ms = 15 seconds).
 * Controls how long idle pooled connections are kept alive.
 * 15 seconds balances connection reuse against resource consumption.
 * Shorter intervals free resources faster; longer improves reuse.
 */
#define BRIX_PROXY_KEEPALIVE_INTERVAL_DEFAULT_MS  15000

/*
 * Health check pool size (1024 bytes).
 * Used for temporary allocations during health check operations.
 * Sized to hold health check context, host strings, and small buffers.
 * 1 KB is sufficient for typical health check metadata.
 */
#define BRIX_HC_POOL_SIZE                      1024

/*
 * Registry opaque buffer size (1024 bytes).
 * Used for opaque data storage in registry selection operations.
 * Accommodates typical registry metadata and selection criteria.
 */
#define BRIX_REGISTRY_OPAQUE_BUF_SIZE          1024

/*
 * Load percentage divisor (10000).
 * Used in weighted load calculations for registry selection.
 * Provides 0.01% precision in load percentage computations.
 * Example: metric * weight * load_pct / 10000
 */
#define BRIX_LOAD_PCT_DIVISOR                  10000

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
 * Maximum base64url-encoded input size (bytes).
 * JWT tokens with claims typically 2-4 KB encoded; 8 KB provides 2x headroom.
 * Prevents buffer overflow on malformed or malicious oversized inputs.
 * Decoded output will be ~6 KB (base64 expands by 4/3).
 */
#define BRIX_B64_DECODE_MAX                  8192

/*
 * Maximum JWKS (JSON Web Key Set) file size (bytes).
 * Typical JWKS with 10-20 keys is 5-15 KB; 64 KB allows for large key sets.
 * Prevents DoS via oversized JWKS files (memory exhaustion, parse time).
 * If more than 20 keys needed, consider key rotation or multiple JWKS endpoints.
 */
#define BRIX_JWKS_FILE_MAX                   65536

/*
 * Maximum bearer token size (bytes).
 * WLCG SciTokens typically 2-4 KB; 4 KB accommodates future extensions.
 * Prevents unbounded allocation from malicious oversized token claims.
 */
#define BRIX_BEARER_TOKEN_MAX                  4096

/*
 * Maximum macaroon path caveats.
 * Prevents path traversal attack via excessive caveat chains.
 * 8 allows reasonable delegation depth while bounding verification cost.
 */
#define BRIX_MACAROON_PATH_CAVEATS_MAX         8

/* ---- Protocol constants ---- */

/*
 * kXR_Qconfig response buffer size (bytes).
 * Reference XRootD uses 512 bytes for capability query responses.
 * Supports ~20 key=value lines at typical lengths.
 */
#define BRIX_QCONFIG_RESP_MAX                  512

/*
 * kXR_Qconfig key token buffer size (bytes).
 * Maximum length for a single capability key token.
 * 128 bytes accommodates extended key names with margin.
 */
#define BRIX_QCONFIG_KEY_MAX                   128

/*
 * kXR_Qspace/QFSinfo response buffer size (bytes).
 * Reference XRootD uses 256 bytes for space query responses.
 * Format: "oss.cgroup=...&oss.space=..." (typically <200 bytes).
 */
#define BRIX_QSPACE_RESP_MAX                   256

/*
 * Checkpoint file extension length (bytes).
 * ".ckp" suffix appended to original path for checkpoint snapshots.
 * Used in ckp_begin() for path construction.
 */
#define BRIX_CHKPT_EXT_LEN                     4

/*
 * Checkpoint file extension with null terminator (bytes).
 * ".ckp\0" = 5 bytes total for memcpy with null termination.
 */
#define BRIX_CHKPT_EXT_NUL                     5

/*
 * Checkpoint file permissions (octal).
 * 0600 = owner read/write only, no group/other access.
 * Checkpoint files contain tentative writes; restrict to process owner.
 */
#define BRIX_CHKPT_MODE                        0600

/*
 * Maximum checkpoint size for wire protocol (uint32_t limit).
 * Wire protocol uses 32-bit field for maxCkpSize; clamp to UINT32_MAX.
 * Used in ckp_query() to prevent overflow when advertising capacity.
 */
#define BRIX_CHKPT_SIZE_MAX                    0xFFFFFFFFu

/*
 * TPC delegated token buffer size (bytes).
 * OAuth2/OIDC access tokens typically 1-4 KB; 64 KB provides 16x headroom.
 * Prevents buffer overflow on malformed or malicious oversized tokens.
 */
#define BRIX_TPC_TOKEN_MAX                     65536

/*
 * TPC token error message buffer size (bytes).
 * Error messages from oidc-agent/curl subprocesses typically <128 bytes.
 * 256 bytes provides 2x headroom for verbose error output.
 */
#define BRIX_TPC_TOKEN_ERR_MAX                 256

/*
 * TPC opaque parameter prefix length (bytes).
 * "tpc." prefix identifies TPC-specific query parameters.
 * Used in tpc_parse_token() for key matching.
 */
#define BRIX_TPC_PREFIX_LEN                    4

/*
 * TPC authority buffer size (bytes).
 * Maximum size for host[:port] authority string during URL decomposition.
 * Supports IPv6 bracket notation [::1]:port with room for 256-char hostnames.
 * Used in tpc_parse_src_spec() for temporary authority parsing buffer.
 */
#define BRIX_TPC_AUTHORITY_BUF_SIZE            320

/*
 * TPC key length constants for recognized parameters.
 * These are the bare key lengths after stripping "tpc." prefix.
 * Used in tpc_parse_token() for key matching validation.
 */
#define BRIX_TPC_KEY_LEN_SHORT                 3   /* src, dst, key, lfn, org */
#define BRIX_TPC_KEY_LEN_STAGE                 5   /* stage */
#define BRIX_TPC_KEY_LEN_TOKEN_MODE           10   /* token_mode */

/*
 * TPC minimum key length for valid "tpc.*" parameters.
 * Must be at least 5 chars: "tpc." (4) + at least 1 char for key name.
 * Used in tpc_parse_token() to reject malformed keys.
 */
#define BRIX_TPC_KEY_LEN_MIN                   5

/* ---- TPC token exchange constants ---- */

/*
 * TPC RFC 8693 token exchange body buffer size (bytes).
 * Form-urlencoded body: grant_type + subject_token (JWT, ~1-3 KB) + resource
 * + audience + scope. Typical total 1.5-2 KB; 4 KB provides 2x headroom.
 * Used in tpc_rfc8693_stage_body() for temporary body formatting.
 */
#define BRIX_TPC_TOKEN_BODY_BUF_SIZE           4096

/*
 * TPC token exchange curl argv array size.
 * curl command line: curl -s -S -f -X POST -H Content-Type [-u auth] -d @file
 * -- endpoint_url NULL. Maximum 13 arguments including optional basic auth.
 * Used in tpc_rfc8693_build_argv() for curl invocation array.
 */
#define BRIX_TPC_TOKEN_CURL_ARGV_MAX           16

/*
 * TPC OIDC socket path buffer size (bytes).
 * Default: /run/user/1000/oidc/oidc_agent.sock (36 chars).
 * 256 bytes supports custom XDG_RUNTIME_DIR paths with long usernames.
 * Used in tpc_oidc_child_run() for socket path construction.
 */
#define BRIX_TPC_TOKEN_OIDC_SOCK_BUF_SIZE      256

/*
 * TPC OIDC environment variable buffer size (bytes).
 * Format: "VAR=value" where value can be long path (HOME, XDG_RUNTIME_DIR).
 * 280 bytes: 20 chars for "VAR=" + 256 chars for path value + 4 padding.
 * Used in tpc_oidc_exec_fallback() for environment variable construction.
 */
#define BRIX_TPC_TOKEN_ENV_BUF_SIZE            280

/* ---- TPC timeout constants ---- */

/*
 * TPC I/O timeout (seconds).
 * SO_RCVTIMEO/SO_SNDTIMEO for TPC socket read/write operations.
 * 60 seconds provides headroom for high-latency WAN transfers while
 * preventing indefinite hangs on unresponsive peers.
 * Used in tpc_set_rcvtimeo() and TPC socket setup.
 */
#define BRIX_TPC_IO_TIMEOUT_SEC                60

/*
 * TPC connect timeout (seconds).
 * poll() timeout for non-blocking connect() during TPC session establishment.
 * 5 seconds allows for network latency while failing fast on unreachable hosts.
 * Used in brix_tpc_connect() for parallel connection attempts.
 */
#define BRIX_TPC_CONNECT_TIMEOUT_SEC           5

/* ---- TPC buffer size constants ---- */

/*
 * TPC bearer token buffer size (bytes).
 * Stack cap for a single JWT read from bearer file.
 * OAuth2/OIDC tokens typically 1-4 KB; 64 KB provides 16x headroom.
 * Prevents buffer overflow on malformed or malicious oversized tokens.
 * Used in gsi_outbound_certreq.c for token read operations.
 */
#define BRIX_TPC_BEARER_MAX                    65536

/*
 * TPC GSI auth body maximum size (bytes).
 * Shared upper bound on decoded GSI authentication body.
 * 256 KB accommodates large credential chains while preventing DoS.
 * Used in gsi_outbound_common.c for GSI auth body validation.
 */
#define BRIX_TPC_GSI_MAX_BODY                  262144

/* ---- ES256 signature constants ---- */

/*
 * ES256 (ECDSA P-256) signature component size (bytes).
 * IEEE P1363 format: raw r||s, each component is 32 bytes.
 * Total signature size is 64 bytes (BRIX_ES256_SIG_COMPONENT * 2).
 * Used for JWT ES256 signature validation in brix_token_verify_es256().
 */
#define BRIX_ES256_SIG_COMPONENT               32

/*
 * ES256 (ECDSA P-256) total signature size (bytes).
 * IEEE P1363 format: r (32 bytes) || s (32 bytes) = 64 bytes total.
 * Used for signature length validation before BN_bin2bn conversion.
 */
#define BRIX_ES256_SIG_SIZE                    64

/* ---- Core utility constants ---- */

/*
 * Core filesystem usage PPM (parts per million) multiplier.
 * Used in brix_fs_usage_calc() for occupancy percentage calculation.
 * Formula: (occupancy_bytes / total_bytes) * 1000000 = PPM value.
 * Provides 6 decimal places of precision for fractional percentages.
 */
#define BRIX_CORE_FS_USAGE_PPM                 1000000

/*
 * Core ISO-8601 timestamp buffer size (bytes).
 * Format: "YYYY-MM-DDTHH:MM:SS.mmmZ" = 24 chars + NUL terminator.
 * Used in brix_format_iso8601() for UTC timestamp formatting.
 * Supports millisecond precision for XRootD, WebDAV, and S3 protocols.
 */
#define BRIX_CORE_ISO8601_BUF_SIZE             25

/*
 * Core hex encoding buffer size multiplier.
 * Each byte encodes to 2 hex characters (e.g., 0xFF → "ff").
 * Used in brix_hex_encode() for checksum/digest formatting.
 * Buffer must be at least (input_len * 2) + 1 for NUL terminator.
 */
#define BRIX_CORE_HEX_ENCODE_MULTIPLIER        2

/*
 * Core range vector parsing buffer size (bytes).
 * Maximum size for comma-separated byte range specifications.
 * HTTP Range header format: "bytes=0-499,500-999,..."
 * 4 KB supports ~100 range entries with typical formatting.
 * Used in brix_parse_range_vector() for HTTP Range header parsing.
 */
#define BRIX_CORE_RANGE_VECTOR_BUF_SIZE        4096

/*
 * Core lifecycle timing buffer size (bytes).
 * Format: "component=Nus" for timing measurements.
 * 64 bytes supports component names up to ~50 chars + numeric value.
 * Used in brix_lifecycle_record() for init/process timing reports.
 */
#define BRIX_CORE_LIFECYCLE_TIMING_BUF_SIZE    64

/*
 * Core URI encoding buffer size (bytes).
 * Maximum size for percent-encoded URI components.
 * Worst case: every byte encodes to 3 chars (%XX).
 * 8 KB supports original strings up to ~2.7 KB.
 * Used in brix_uri_encode() for URL-safe path encoding.
 */
#define BRIX_CORE_URI_ENCODE_BUF_SIZE          8192

/* ---- Core time conversion constants ---- */

/*
 * Nanoseconds per second.
 * Used in brix_phase_now_ns() for timespec → nanosecond conversion.
 * 1 second = 1,000,000,000 nanoseconds (10^9).
 */
#define BRIX_CORE_NSEC_PER_SEC                 1000000000ULL

/*
 * Nanoseconds per microsecond.
 * Used in us_since() for nanosecond → microsecond conversion.
 * 1 microsecond = 1,000 nanoseconds (10^3).
 */
#define BRIX_CORE_NSEC_PER_USEC                1000ULL

/* ---- Permission mask constants ---- */

/*
 * Unix permission mask for chmod/fchmod operations.
 * Masks off the high 4 bits (setuid/setgid/sticky) to get low 12 bits.
 * Used in brix_apply_child_mode() to extract permission bits from mode_t.
 * Octal 07777 = binary 111 111 111 111 (12 bits for rwxrwxrwx+sticky).
 */
#define BRIX_PERM_MASK                         07777

/*
 * Maximum S3 list objects max-keys parameter.
 * AWS S3 API maximum is 1000; this matches the service limit.
 * Pagination (continuation token) handles larger result sets.
 * Keeping at 1000 minimizes API calls while respecting service  (prevents throttling).
 */
#define BRIX_S3_LIST_MAX_KEYS                  1000

/* ---- S3 STS (Security Token Service) constants ---- */

/*
 * STS credential lifetime bounds (AWS STS API constraints).
 * AssumeRole returns credentials valid for [900, 43200] seconds.
 * Values outside this range are clamped to the valid window.
 */
#define BRIX_S3_STS_MIN_LIFETIME_SECS          900     /* 15 minutes (AWS minimum) */
#define BRIX_S3_STS_MAX_LIFETIME_SECS          43200   /* 12 hours (AWS maximum) */

/* ---- File permission constants ---- */

/*
 * Standard Unix file permission modes.
 * These constants ensure consistent permission usage across the codebase.
 */
#define BRIX_PERM_PRIVATE                      0600  /* Owner read/write only (credentials, keys) */
#define BRIX_PERM_RESTRICTED                   0700  /* Owner full access (private directories) */
#define BRIX_PERM_FILE_DEFAULT                 0644  /* Owner rw, others r (public files) */
#define BRIX_PERM_DIR_DEFAULT                  0755  /* Owner rwx, others rx (public dirs) */
#define BRIX_PERM_EXEC_DEFAULT                 0755  /* Executable files */

/* ---- Parts-per-million (PPM) constants ---- */

/*
 * PPM (parts per million) multiplier for occupancy/ratio calculations.
 * Used in cache eviction, filesystem usage, and metric calculations.
 * 1000000 = 1,000,000 = 10^6 (1 million parts)
 */
#define BRIX_PPM_MULTIPLIER                    1000000

/* ---- Time conversion constants ---- */

/*
 * Milliseconds per second.
 * Used for time conversion in dashboard, metrics, and timeout calculations.
 */
#define BRIX_MSEC_PER_SEC                      1000

/* ---- Dashboard and API limits ---- */

/*
 * Maximum entries in dashboard file listings.
 * Prevents unbounded JSON responses and browser hangs.
 * 10000 entries provides comprehensive view while bounding response size.
 */
#define BRIX_DASHBOARD_FILES_MAX               10000

/* ---- Observability Metrics Constants ---- */

/*
 * Metrics export buffer size (bytes).
 * Sized to hold complete Prometheus-format metric families without fragmentation.
 * 64 KB accommodates large metric families with multiple label combinations.
 */
#define BRIX_METRICS_EXPORT_BUF_SIZE           65536

/*
 * Metrics stream cache capacity (bytes).
 * Maximum memory for in-flight metric stream buffering.
 * 2 MB allows for high-throughput streaming without backpressure.
 */
#define BRIX_METRICS_STREAM_CACHE_SIZE         (2 * 1024 * 1024)

/*
 * Metrics occupancy threshold (parts per million).
 * Cache eviction triggers when occupancy exceeds this threshold.
 * 800000 ppm = 80% utilization threshold.
 */
#define BRIX_METRICS_OCCUPANCY_THRESHOLD_PPM   800000

/*
 * Access log timer interval (milliseconds).
 * Periodic flush interval for access log buffering.
 * 1000 ms = 1 second flush interval for timely log delivery.
 */
#define BRIX_ACCESS_LOG_TIMER_MS               1000

/*
 * Metrics histogram bucket count.
 * Standard Prometheus-style histogram buckets for latency tracking.
 * 8 buckets: 1, 10, 30, 60, 300, 1800, 3600, +Inf seconds.
 */
#define BRIX_METRICS_HISTOGRAM_BUCKETS         8

/* ---- Dashboard Configuration Constants ---- */

/*
 * Dashboard authentication secret maximum length (bytes).
 * Accommodates strong passwords and API keys with safety margin.
 * 4096 bytes allows for very long secrets while bounding allocation.
 */
#define BRIX_DASHBOARD_SECRET_MAX              4096

/*
 * Dashboard admin request body maximum (bytes).
 * Limits configuration upload and admin API payload sizes.
 * 64 KB accommodates complex configs while preventing abuse.
 */
#define BRIX_DASHBOARD_ADMIN_MAX_BODY          65536

/*
 * Dashboard session rate limit (requests per second).
 * Per-session request rate for API endpoints.
 * 100 requests/sec allows interactive use without abuse.
 */
#define BRIX_DASHBOARD_SESSION_RATE_LIMIT      100

/*
 * Dashboard password buffer size (bytes).
 * Maximum password length for authentication.
 * 1024 bytes accommodates very long passwords while bounding stack allocation.
 */
#define BRIX_DASHBOARD_PASSWORD_BUF            1025

/*
 * Dashboard CSS/JS inline buffer size (bytes).
 * Maximum size for inline stylesheet and script content.
 * 4096 bytes accommodates typical dashboard styling.
 */
#define BRIX_DASHBOARD_INLINE_STYLE_MAX        4096

/* ---- PMark (Packet Marking) Constants ---- */

/*
 * PMark flow label experiment range maximum.
 * Valid experiment IDs are 1-1023 (10-bit range).
 * Activity codes are 1-63 (6-bit range).
 */
#define BRIX_PMARK_EXPERIMENT_MAX              1023
#define BRIX_PMARK_ACTIVITY_MAX                63

/*
 * PMark flow label port range.
 * Valid flow label ports are 65-65535.
 * Ports below 65 are reserved for well-known services.
 */
#define BRIX_PMARK_PORT_MIN                    65
#define BRIX_PMARK_PORT_MAX                    65535

/*
 * PMark firefly echo interval (microseconds).
 * Default interval for firefly collector heartbeat.
 * 30000 us = 30 ms provides responsive monitoring without overhead.
 */
#define BRIX_PMARK_FIREFLY_ECHO_INTERVAL_US    30000

/*
 * PMark socket stats buffer size (bytes).
 * Buffer for ISO8601 timestamp formatting.
 * 64 bytes accommodates full timestamp with timezone.
 */
#define BRIX_PMARK_TIMESTAMP_BUF               64

/*
 * PMark mapping path buffer size (bytes).
 * Maximum path length for flow label mapping operations.
 * 1024 bytes accommodates deep directory hierarchies.
 */
#define BRIX_PMARK_PATH_BUF                    1024

/*
 * PMark firefly transmit buffer size (bytes).
 * Buffer for firefly protocol messages.
 * 1280 bytes accommodates IPv6 MTU minus headers.
 */
#define BRIX_PMARK_FIREFLY_TX_BUF              1280

/*
 * Maximum weight value for proxy load balancing.
 * Clamped to 1000 to prevent overflow in weighted calculations.
 */
#define BRIX_PROXY_WEIGHT_MAX                  1000

/* ---- Timeout constants (milliseconds) ---- */

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

/* ---- Auth Buffer Size Constants ---- */

/*
 * Auth gate cache key buffer size (bytes).
 * Sized to hold: "aop" + IP (64) + "/" + resolved + "/" + reqpath + "/" +
 * DN + "/" + VO + "/" + scope + padding.
 * PATH_MAX + PATH_MAX covers worst-case path + resolved hostname.
 * 512 + 512 covers DN + VO list (typical: <100 bytes each).
 * 1024 covers scope claims (JWT/WLCG tokens can be large).
 */
#define BRIX_AUTH_GATE_KEY_BUF_SIZE            4096

/*
 * Auth audit buffer size (bytes).
 * Buffer for audit log formatting during authentication decisions.
 * Holds timestamp, identity, operation, path, and decision details.
 * 2 KB provides headroom for long DN/VO strings.
 */
#define BRIX_AUTH_AUDIT_BUF_SIZE               2048

/*
 * DN (Distinguished Name) buffer size (bytes).
 * X.509 certificate subject/issuer DN maximum length.
 * Typical DN: 100-300 bytes; 1024 provides 3-10x headroom.
 * Used in GSI/Kerberos authentication flows.
 */
#define BRIX_AUTH_DN_BUF_SIZE                  1024

/*
 * VO (Virtual Organization) list buffer size (bytes).
 * Holds comma-separated VO list from VOMS proxy.
 * Typical: 1-5 VOs at 20-50 bytes each; 512 provides 2-5x headroom.
 */
#define BRIX_AUTH_VO_BUF_SIZE                  512

/*
 * Auth cache key hash buffer size (bytes).
 * Temporary buffer for SHA-256 hash computation during cache key generation.
 * Must accommodate all key components before hashing.
 */
#define BRIX_AUTH_CACHE_KEY_BUF_SIZE           (3 + 64 + 1 + PATH_MAX + PATH_MAX + 512 + 512 + 1024 + 8)

/* ---- Auth ACC (Access Control Cache) Constants ---- */

/*
 * ACC GID cache lifetime default (seconds).
 * Default TTL for group membership cache entries.
 * 43200 seconds = 12 hours (balances freshness vs. lookup overhead).
 */
#define BRIX_ACC_GIDLIFETIME_DEFAULT           43200

/*
 * ACC audit buffer sizes (bytes).
 * Buffers for audit logging in access control decisions.
 * 256 bytes for identity/host, 1024 bytes for path.
 */
#define BRIX_ACC_AUDIT_ID_BUF_SIZE             256
#define BRIX_ACC_AUDIT_HOST_BUF_SIZE           256
#define BRIX_ACC_AUDIT_PATH_BUF_SIZE           1024

/* ---- Auth IDMAP Constants ---- */

/*
 * IDMAP denylist buffer sizes (bytes).
 * Buffers for user/group denylist file parsing.
 * 1024 bytes per line handles typical entries with comments.
 */
#define BRIX_IDMAP_DENYLIST_LINE_BUF_SIZE      1024

/* ---- Auth Timeout Constants ---- */

/*
 * Auth cache TTL multiplier (milliseconds per second).
 * Converts configured TTL (seconds) to nginx timer units (milliseconds).
 * Standard conversion factor: 1 second = 1000 milliseconds.
 */
#define BRIX_AUTH_CACHE_TTL_MS_PER_SEC         1000

/*
 * Token buffer sizes for JWT/Macaroon processing.
 *
 * BRIX_TOKEN_SUB_BUF_SIZE: 512 bytes for subject claims
 * BRIX_TOKEN_ISS_BUF_SIZE: 512 bytes for issuer claims
 * BRIX_TOKEN_SCOPE_BUF_SIZE: 1024 bytes for scope claims
 * BRIX_TOKEN_GROUPS_BUF_SIZE: 512 bytes for groups claims
 * BRIX_TOKEN_HDR_JSON_BUF_SIZE: 2048 bytes for JWT header JSON
 * BRIX_TOKEN_MACAROON_SCOPE_BUF_SIZE: 1024 bytes for Macaroon scope
 * BRIX_TOKEN_MACAROON_PATH_CAV_BUF_SIZE: 1024 bytes for Macaroon path caveat
 * BRIX_TOKEN_FP_BUF_SIZE: 32 bytes for SHA-256 fingerprint
 * BRIX_TOKEN_AUD_BUF_SIZE: 512 bytes for audience claim
 * BRIX_TOKEN_ERR_BUF_SIZE: 256 bytes for token error messages
 * BRIX_TOKEN_INI_LINE_BUF_SIZE: 1024 bytes for INI file line parsing
 * BRIX_TOKEN_ISSUER_BUF_SIZE: 128 bytes for issuer registry buffer
 * BRIX_TOKEN_SIG_B64_BUF_SIZE: 128 bytes for base64-encoded signature
 */
#define BRIX_TOKEN_SUB_BUF_SIZE                512
#define BRIX_TOKEN_ISS_BUF_SIZE                512
#define BRIX_TOKEN_SCOPE_BUF_SIZE              1024
#define BRIX_TOKEN_GROUPS_BUF_SIZE             512
#define BRIX_TOKEN_HDR_JSON_BUF_SIZE           2048
#define BRIX_TOKEN_MACAROON_SCOPE_BUF_SIZE     1024
#define BRIX_TOKEN_MACAROON_PATH_CAV_BUF_SIZE  1024
#define BRIX_TOKEN_FP_BUF_SIZE                 32
#define BRIX_TOKEN_AUD_BUF_SIZE                512
#define BRIX_TOKEN_ERR_BUF_SIZE                256
#define BRIX_TOKEN_INI_LINE_BUF_SIZE           1024
#define BRIX_TOKEN_ISSUER_BUF_SIZE             128
#define BRIX_TOKEN_SIG_B64_BUF_SIZE            128

/* ---- Auth Permission Constants ---- */

/*
 * Permission and special bits mask (octal).
 * Masks file mode to show only permission bits (rwx) and special bits
 * (setuid, setgid, sticky). Used in policy enforcement and logging.
 * 07777 = 07000 (special) | 00777 (permission)
 */
#define BRIX_PERM_MASK                         07777

/* ---- Auth Database Constants ---- */

/*
 * Maximum auth database file size (bytes).
 * Prevents unbounded memory allocation when parsing authdb files.
 * 1 MB allows for thousands of entries while bounding resource usage.
 */
#define BRIX_AUTHDB_MAX_FILE_SIZE              1048576

/* ---- GSI/DH Constants ---- */

/*
 * GSI certificate response buffer size (bytes).
 * Buffer for building certificate response messages in GSI handshake.
 * Must accommodate certificate chain + DH public key + signatures.
 * 16 KB handles typical certificate chains with room for growth.
 */
#define BRIX_GSI_CERT_RESP_BUF_SIZE            16384

/*
 * GSI signature buffer size (bytes).
 * Buffer for RSA/ECDSA signatures during GSI handshake.
 * RSA-4096 signature = 512 bytes; 1024 provides 2x headroom.
 */
#define BRIX_GSI_SIG_BUF_SIZE                  1024

/*
 * GSI RSA public exponent (65537 = 0x10001).
 * Standard RSA exponent providing good security/performance balance.
 * Used for key generation in proxy certificate requests.
 */
#define BRIX_GSI_RSA_EXPONENT                  65537

/*
 * GSI DH public key buffer size (bytes).
 * Buffer for Diffie-Hellman public key exchange.
 * ffdhe2048 = 256 bytes; 4096 provides 16x headroom for future groups.
 */
#define BRIX_GSI_DH_PUB_BUF_SIZE               4096

/*
 * OCSP (Online Certificate Status Protocol) constants.
 *
 * BRIX_OCSP_MAX_RESPONSE_BYTES: Maximum OCSP response size (64 KB)
 * BRIX_OCSP_NONCE_SIZE: OCSP nonce size in bytes (16 bytes per RFC 6960)
 */
#define BRIX_OCSP_MAX_RESPONSE_BYTES           (64 * 1024)
#define BRIX_OCSP_NONCE_SIZE                   16

/*
 * Crypto key strength minimums per IGTF security policy.
 * BRIX_CRYPTO_RSA_MIN_BITS: Minimum RSA key size (2048 bits)
 * BRIX_CRYPTO_DSA_MIN_BITS: Minimum DSA key size (2048 bits)
 * BRIX_CRYPTO_EC_MIN_BITS: Minimum EC key size (256 bits for P-256)
 */
#define BRIX_CRYPTO_RSA_MIN_BITS               2048
#define BRIX_CRYPTO_DSA_MIN_BITS               2048
#define BRIX_CRYPTO_EC_MIN_BITS                256

/*
 * PWD authentication constants.
 * BRIX_PWD_PATH_BUF_SIZE: Buffer for password file path (1024 bytes)
 * BRIX_PWD_PBKDF2_ITERATIONS: PBKDF2-HMAC-SHA1 iterations (10000)
 * BRIX_PWD_HASH_OUTPUT_SIZE: PBKDF2 output size in bytes (24)
 */
#define BRIX_PWD_PATH_BUF_SIZE                 1024
#define BRIX_PWD_PBKDF2_ITERATIONS             10000
#define BRIX_PWD_HASH_OUTPUT_SIZE              24

/*
 * Kerberos authentication constants.
 * BRIX_KRB5_CNAME_BUF_SIZE: Buffer for Kerberos client name (1024 bytes)
 */
#define BRIX_KRB5_CNAME_BUF_SIZE               1024

/*
 * GSI proxy delegation signed request tag buffer size (bytes).
 * Holds signed delegation request during proxy delegation handshake.
 * 1024 bytes handles typical proxy certification requests.
 */
#define BRIX_GSI_DELEGATION_TAG_BUF_SIZE       1024

/* ---- Token Authentication Constants ---- */

/*
 * Maximum Bearer token size (bytes).
 * JWT/WLCG tokens typically 500-2000 bytes; 4096 provides 2-8x headroom.
 * Enforced during token extraction from Authorization header.
 */
#define BRIX_BEARER_TOKEN_MAX                  4096

/*
 * JWKS (JSON Web Key Set) file size maximum (bytes).
 * JWKS files contain public keys for token verification.
 * Typical: 2-10 KB; 64 KB allows for large key rotations.
 */
#define BRIX_JWKS_FILE_MAX                     65536

/*
 * Base64 URL decode buffer maximum (bytes).
 * Temporary buffer for base64url decoding of JWT components.
 * 8 KB handles large JWT claims sets.
 */
#define BRIX_B64_DECODE_MAX                    8192

/* ---- GSI signed-DH policy (phase-48; brix_gsi_signed_dh directive) ---- */
#define BRIX_GSI_SDH_OFF      0  /* always unsigned DH (default, universal)  */
#define BRIX_GSI_SDH_AUTO     1  /* signed DH for clients advertising >=10400 */
#define BRIX_GSI_SDH_REQUIRE  2  /* signed DH only; reject <10400 clients     */

/* XrdSecgsi version at/after which the RSA-signed-DH wire variant applies
 * (XrdSecgsiVersDHsigned in the reference implementation). */
#define BRIX_GSI_VERS_DHSIGNED 10400

/* ---- SSS (Simple Shared Secret) Constants ---- */

/*
 * SSS configuration line buffer size (bytes).
 * Used for parsing SSS keytab configuration files.
 * 4096 bytes handles typical keytab entries with headroom.
 */
#define BRIX_SSS_CONFIG_LINE_BUF_SIZE          4096

/* ---- GSSAPI Constants ---- */

/*
 * GSSAPI read buffer size (bytes).
 * Used for GSSAPI token exchange and context establishment.
 * 16384 bytes (16 KB) handles typical GSSAPI tokens with headroom.
 */
#define BRIX_GSSAPI_READ_BUF_SIZE              16384

/* ---- Impersonation Broker Constants ---- */

/*
 * Impersonation broker maximum concurrent connections.
 * Limits simultaneous broker client connections to prevent resource exhaustion.
 * 1024 connections provides headroom for high-concurrency workloads.
 */
#define BRIX_IMP_BROKER_MAXCONN                1024

/*
 * Impersonation broker socket path buffer size (bytes).
 * Accommodates Unix domain socket paths for broker communication.
 * 256 bytes handles typical socket paths with headroom.
 */
#define BRIX_IMP_SOCK_PATH_BUF_SIZE            256

/*
 * Impersonation broker root path buffer size (bytes).
 * Buffer for broker root directory path construction.
 * 1024 bytes handles deep directory structures.
 */
#define BRIX_IMP_ROOT_PATH_BUF_SIZE            1024

/* ---- GSI RSA key generation constants ---- */

/*
 * GSI proxy certificate RSA key minimum bits.
 * RFC 3828 and XRootD security policy require 2048-bit minimum for proxy certs.
 * Used in EVP_PKEY_CTX_set_rsa_keygen_bits() for proxy key generation.
 * Larger keys (3072, 4096) supported but 2048 balances security/performance.
 */
#define BRIX_GSI_PROXY_KEY_BITS          2048

/*
 * RSA public exponent for key generation.
 * 65537 (0x10001) is the standard RSA public exponent per PKCS#1 v2.1.
 * Chosen for efficient encryption operations while maintaining security.
 * Used in EVP_PKEY_CTX_set_rsa_keygen_pubexp() for proxy key generation.
 */
#define BRIX_RSA_PUBLIC_EXPONENT         65537

/*
 * GSI buffer sizes for DN/EEC parsing.
 * BRIX_GSI_DN_BUF_SIZE: 1024 bytes for Distinguished Name strings
 * BRIX_GSI_EEC_BUF_SIZE: 1024 bytes for EEC (End Entity Certificate) strings
 */
#define BRIX_GSI_DN_BUF_SIZE                 1024
#define BRIX_GSI_EEC_BUF_SIZE                1024

/*
 * GSI DH (Diffie-Hellman) key sizes.
 * BRIX_GSI_DH_FFDHE2048: 2048-bit finite field DH group (ffdhe2048)
 * BRIX_GSI_DH_FFDHE3072: 3072-bit finite field DH group (ffdhe3072)
 * BRIX_GSI_DH_FIXED_SIZE: Fixed 3072-bit DH params size in bytes
 */
#define BRIX_GSI_DH_FFDHE2048_BITS           2048
#define BRIX_GSI_DH_FFDHE3072_BITS           3072
#define BRIX_GSI_DH_FIXED_SIZE               3072

/*
 * GSI serial number buffer size.
 * Buffer for certificate serial number formatting (8 bytes hex + null terminator).
 */
#define BRIX_GSI_SERIAL_BUF_SIZE             17

/*
 * GSI time conversion constants.
 * BRIX_GSI_SECS_PER_DAY: Seconds per day (86400) for proxy lifetime calculations
 */
#define BRIX_GSI_SECS_PER_DAY                86400

/* ---- SSS constants ---- */
#define BRIX_SSS_KEY_MAX   128
#define BRIX_SSS_NAME_MAX  192

/* ---- ROOT Protocol Constants ---- */

/* ---- XRootD Protocol Constants ---- */

/*
 * XRootD protocol handshake constant (ROOTD_PQ).
 * Value 2012 (0x7DC) identifies valid XRootD protocol client in handshake.
 * Used in ClientInitHandShake.fifth = htonl(2012) for protocol validation.
 * Reference: src/protocols/root/protocol/opcodes.h:15
 */
#define BRIX_XRD_PROTOCOL_ID             2012

/*
 * XRootD handshake fourth field constant.
 * ClientInitHandShake.fourth = htonl(4) validates protocol compatibility.
 * Part of the 20-byte initial handshake structure.
 */
#define BRIX_XRD_HANDSHAKE_FOURTH        4

/*
 * XRootD response status codes.
 * These define the server response type for all operations.
 */

/* kXR_ok (0) — request succeeded, body carries result data */
#define BRIX_XRD_STATUS_OK               0

/* kXR_oksofar (4000) — partial result, more response frames follow */
#define BRIX_XRD_STATUS_OKSOFAR          4000

/* kXR_attn (4001) — unsolicited server push notification */
#define BRIX_XRD_STATUS_ATTN             4001

/* kXR_authmore (4002) — authentication needs another round-trip */
#define BRIX_XRD_STATUS_AUTHMORE         4002

/* kXR_error (4003) — request failed, body = errnum[4] + errmsg */
#define BRIX_XRD_STATUS_ERROR            4003

/* kXR_redirect (4004) — client should retry at different server */
#define BRIX_XRD_STATUS_REDIRECT         4004

/* kXR_wait (4005) — try again after N seconds (body carries wait time) */
#define BRIX_XRD_STATUS_WAIT             4005

/* kXR_waitresp (4006) — async result coming in future kXR_attn frame */
#define BRIX_XRD_STATUS_WAITRESP         4006

/* kXR_status (4007) — extended response with CRC32c (pgread/pgwrite) */
#define BRIX_XRD_STATUS                  4007

/*
 * XRootD request opcodes (client → server).
 * See src/protocols/root/protocol/opcodes.h for complete list.
 */

/* kXR_auth (3000) — authentication credential exchange */
#define BRIX_XRD_OPCODE_AUTH             3000

/* kXR_query (3001) — server/file information query */
#define BRIX_XRD_OPCODE_QUERY            3001

/* kXR_chmod (3002) — change file permission bits */
#define BRIX_XRD_OPCODE_CHMOD            3002

/* kXR_close (3003) — close an open file handle */
#define BRIX_XRD_OPCODE_CLOSE            3003

/* kXR_dirlist (3004) — list directory entries */
#define BRIX_XRD_OPCODE_DIRLIST          3004

/* kXR_protocol (3006) — protocol version negotiation */
#define BRIX_XRD_OPCODE_PROTOCOL         3006

/* kXR_login (3007) — session login with username */
#define BRIX_XRD_OPCODE_LOGIN            3007

/* kXR_open (3010) — open a file for I/O */
#define BRIX_XRD_OPCODE_OPEN             3010

/* kXR_ping (3011) — liveness check (no payload) */
#define BRIX_XRD_OPCODE_PING             3011

/* kXR_read (3013) — read bytes from open file handle */
#define BRIX_XRD_OPCODE_READ             3013

/* kXR_stat (3017) — stat a path or open handle */
#define BRIX_XRD_OPCODE_STAT             3017

/* kXR_prepare (3021) — stage files from tape */
#define BRIX_XRD_OPCODE_PREPARE          3021

/* kXR_pgwrite (3026) — paged write with per-page CRC32c */
#define BRIX_XRD_OPCODE_PGWRITE          3026

/* kXR_pgread (3030) — paged read with per-page CRC32c */
#define BRIX_XRD_OPCODE_PGREAD           3030

/*
 * XRootD server type constants.
 * Used in ServerInitHandShake.msgval to identify server role.
 */

/* kXR_LBalServer (0) — load-balancer/redirector (does not serve files) */
#define BRIX_XRD_SERVER_LB               0

/* kXR_DataServer (1) — data server (serves files) */
#define BRIX_XRD_SERVER_DATA             1

/*
 * XRootD protocol response type codes.
 * Used in ServerResponseBody_Status.resptype field.
 */

/* kXR_FinalResult (0) — this is the final response */
#define BRIX_XRD_RESP_FINAL              0

/* kXR_PartialResult (1) — more response data follows */
#define BRIX_XRD_RESP_PARTIAL            1

/*
 * XRootD expect codes for protocol negotiation.
 * Used in ClientProtocolRequest.expect field.
 */

/* kXR_ExpLogin (0x03) — client expects login response */
#define BRIX_XRD_EXPECT_LOGIN            0x03

/*
 * Minimum ROOT protocol version supporting signed DH handshake.
 * Clients advertising version >= this value must use signed DH variant.
 * Matches XrdSecgsiVersDHsigned in the reference implementation.
 */
#define BRIX_ROOT_MIN_SIGNED_DH_VERSION    10400

/*
 * Default ROOT session timeout (milliseconds).
 * Sessions inactive for this duration are eligible for cleanup.
 * 300 seconds (5 minutes) balances resource usage with client retry patterns.
 */
#define BRIX_ROOT_SESSION_TIMEOUT_MS       300000

/*
 * Maximum ROOT query result size (bytes).
 * Caps CMS query responses to prevent unbounded memory allocation.
 * Typical directory listings are 10-100 KB; 1 MB provides 10x headroom.
 */
#define BRIX_ROOT_MAX_QUERY_SIZE           1048576

/*
 * ROOT fattr cache entry TTL (seconds).
 * File attribute cache validity period before revalidation required.
 * 60 seconds provides good performance while ensuring freshness.
 */
#define BRIX_ROOT_FATTR_TTL_SEC            60

/*
 * Minimum ROOT protocol version supporting signed DH handshake.
 * Clients advertising version >= this value must use signed DH variant.
 * Matches XrdSecgsiVersDHsigned in the reference implementation.
 */
#define BRIX_ROOT_MIN_SIGNED_DH_VERSION    10400

/*
 * Default ROOT session timeout (milliseconds).
 * Sessions inactive for this duration are eligible for cleanup.
 * 300 seconds (5 minutes) balances resource usage with client retry patterns.
 */
#define BRIX_ROOT_SESSION_TIMEOUT_MS       300000

/*
 * Maximum ROOT query result size (bytes).
 * Caps CMS query responses to prevent unbounded memory allocation.
 * Typical directory listings are 10-100 KB; 1 MB provides 10x headroom.
 */
#define BRIX_ROOT_MAX_QUERY_SIZE           1048576

/*
 * ROOT fattr cache entry TTL (seconds).
 * File attribute cache validity period before revalidation required.
 * 60 seconds provides good performance while ensuring freshness.
 */
#define BRIX_ROOT_FATTR_TTL_SEC            60

/*
 * ROOT protocol permission mask for mkdir/create operations.
 * Masks off the high 4 bits (setuid/setgid/sticky) to get low 12 bits.
 * Used to extract permission bits from mode_t in mkdir handlers.
 * Octal 07777 = binary 111 111 111 111 (12 bits for rwxrwxrwx+sticky).
 */
#define BRIX_ROOT_PERM_MASK                07777

/*
 * ROOT protocol default directory creation mode.
 * Used when client sends mode=0 in mkdir request.
 * 0755 provides standard directory permissions (rwxr-xr-x).
 */
#define BRIX_ROOT_DEFAULT_DIR_MODE         0755

/*
 * ROOT protocol default file creation mode.
 * Used when client sends mode=0 in open/create request.
 * 0644 provides standard file permissions (rw-r--r--).
 */
#define BRIX_ROOT_DEFAULT_FILE_MODE        0644

/*
 * ROOT protocol private file mode for checkpoint/lock files.
 * Used for temporary files requiring restricted access.
 * 0600 provides owner-only read/write permissions.
 */
#define BRIX_ROOT_PRIVATE_FILE_MODE        0600

/* ---- WebDAV Protocol Constants ---- */

/*
 * WebDAV lock timeout maximum (seconds).
 * RFC 4918 §14.9.4 recommends 3600 seconds (1 hour) as reasonable maximum.
 * Prevents resource exhaustion from abandoned locks.
 */
#define BRIX_WEBDAV_LOCK_TIMEOUT_MAX_SEC   3600

/*
 * WebDAV depth header maximum value.
 * RFC 4918 defines Depth: 0, 1, or infinity. Internal representation uses 0, 1, 2.
 * Value 2 represents "infinity" for internal processing.
 */
#define BRIX_WEBDAV_DEPTH_INFINITY         2

/*
 * WebDAV XML property request buffer size (bytes).
 * Typical PROPFIND requests are 1-4 KB; 8 KB provides 2x headroom.
 * Prevents buffer overflow on malformed or malicious oversized requests.
 */
#define BRIX_WEBDAV_XML_PROP_BUF_SIZE      8192

/*
 * WebDAV COPY/MOVE buffer size (bytes).
 * Used for chunked file copy operations.
 * 64 KB balances memory usage with I/O efficiency.
 */
#define BRIX_WEBDAV_COPY_BUF_SIZE          65536

/*
 * WebDAV HTTP status code for Multi-Status response.
 * RFC 4918 §11.1 defines 207 Multi-Status for PROPFIND/PROPPATCH responses.
 */
#define BRIX_WEBDAV_HTTP_MULTI_STATUS      207

/*
 * WebDAV HTTP status code for Locked.
 * RFC 4918 §11.8 defines 423 Locked when resource is locked.
 */
#define BRIX_WEBDAV_HTTP_LOCKED            423

/*
 * WebDAV HTTP status code for Insufficient Storage.
 * RFC 4918 §11.5 defines 507 Insufficient Storage.
 */
#define BRIX_WEBDAV_HTTP_INSUFF_STORAGE    507

/* ---- WebDAV GSI/TLS Authentication Constants ---- */

/*
 * WebDAV TLS auth cache DN buffer size (bytes).
 * Stores verified X.509 subject DN from client certificate.
 * Typical DN is 64-256 bytes; 1024 provides 4x headroom for long DNs.
 * Used in ngx_http_brix_webdav_tls_auth_cache_t.dn field.
 */
#define BRIX_WEBDAV_TLS_DN_BUF               1024

/*
 * WebDAV VOMS primary VO buffer size (bytes).
 * Stores primary Virtual Organization name from VOMS extension.
 * Typical VO names are 32-128 bytes; 256 provides 2x headroom.
 * Used in webdav_extract_and_set_voms_identity() primary_vo field.
 */
#define BRIX_WEBDAV_VOMS_PRIMARY_VO_BUF      256

/*
 * WebDAV VOMS VO list buffer size (bytes).
 * Stores slash-separated list of VO memberships from VOMS extension.
 * Typical VO lists are 128-512 bytes; 1024 provides 2x headroom.
 * Used in webdav_extract_and_set_voms_identity() vo_list field.
 */
#define BRIX_WEBDAV_VOMS_LIST_BUF            1024

/*
 * WebDAV VOMS FQAN list buffer size (bytes).
 * Stores slash-separated Fully Qualified Attribute Names from VOMS.
 * FQAN lists can be longer than VO lists; 1024 provides adequate margin.
 * Used in webdav_extract_and_set_voms_identity() fqan_list field.
 */
#define BRIX_WEBDAV_VOMS_FQAN_LIST_BUF       1024

/*
 * WebDAV GSI auth log DN buffer size (bytes).
 * Sanitized DN string for operator-facing log messages.
 * Matches BRIX_WEBDAV_TLS_DN_BUF for consistency (1024 bytes).
 * Used in webdav_finish_verified_cert() dn_log field.
 */
#define BRIX_WEBDAV_GSI_LOG_DN_BUF           1024

/*
 * WebDAV protocol permission mask for mkdir/create operations.
 * Masks off the high 4 bits (setuid/setgid/sticky) to get low 12 bits.
 * Used to extract permission bits from mode_t in mkdir handlers.
 * Octal 07777 = binary 111 111 111 111 (12 bits for rwxrwxrwx+sticky).
 */
#define BRIX_WEBDAV_PERM_MASK                07777

/*
 * WebDAV protocol default directory creation mode.
 * Used when no mode is specified in MKCOL request.
 * 0755 provides standard directory permissions (rwxr-xr-x).
 */
#define BRIX_WEBDAV_DEFAULT_DIR_MODE         0755

/*
 * WebDAV protocol default file creation mode.
 * Used when no mode is specified in PUT/MKCOL requests.
 * 0644 provides standard file permissions (rw-r--r--).
 */
#define BRIX_WEBDAV_DEFAULT_FILE_MODE        0644

/*
 * WebDAV protocol private file mode for TPC/temporary files.
 * Used for temporary files requiring restricted access.
 * 0600 provides owner-only read/write permissions.
 */
#define BRIX_WEBDAV_PRIVATE_FILE_MODE        0600

/* ---- S3 Protocol Constants ---- */

/*
 * S3 multipart upload maximum part number.
 * AWS S3 API allows part numbers 1-10000.
 * Enforced in uploadPart, uploadPartCopy, and listParts operations.
 */
#define BRIX_S3_MAX_PART_NUMBER            10000

/*
 * S3 multipart upload minimum part size (bytes).
 * AWS S3 requires minimum 5 MB per part (except last part).
 * Enforced in uploadPart and uploadPartCopy operations.
 */
#define BRIX_S3_MIN_PART_SIZE              5242880

/*
 * S3 multipart upload maximum parts per upload.
 * AWS S3 allows maximum 10000 parts per multipart upload.
 * With 5 MB minimum part size, supports objects up to 50 GB.
 */
#define BRIX_S3_MAX_PARTS_PER_UPLOAD       10000

/*
 * S3 signature version 4 maximum credential scope length (bytes).
 * Scope format: "<date>/<region>/<service>/aws4_request".
 * Typical scope is 40-60 bytes; 256 provides 4x headroom.
 */
#define BRIX_S3_SIGV4_SCOPE_MAX            256

/*
 * S3 signature version 4 maximum canonical request size (bytes).
 * Canonical request includes method, URI, query, headers, payload hash.
 * Typical size is 500-2000 bytes; 8 KB provides 4x headroom.
 */
#define BRIX_S3_SIGV4_CANONICAL_MAX        8192

/*
 * S3 signature version 4 maximum string-to-sign size (bytes).
 * String-to-sign includes algorithm, timestamp, scope, canonical hash.
 * Fixed format is typically 200-300 bytes; 4 KB provides ample headroom.
 */
#define BRIX_S3_SIGV4_STRING_TO_SIGN_MAX   4096

/*
 * S3 ISO 8601 timestamp buffer size (bytes).
 * Format: "YYYY-MM-DDTHH:MM:SS.fffZ" = 24 characters + null terminator.
 * 32 bytes provides comfortable margin.
 */
#define BRIX_S3_ISO8601_BUF_SIZE           32

/*
 * S3 ETag buffer size (bytes).
 * ETag format: "<hex-md5>" or "<hex-md5>-<part-count>".
 * MD5 is 32 hex chars; with quotes and part count, max is ~40 bytes.
 * 64 bytes provides 1.6x headroom.
 */
#define BRIX_S3_ETAG_BUF_SIZE              64

/*
 * S3 bucket name maximum length (bytes).
 * AWS S3 allows 3-63 characters for bucket names.
 * 64 bytes matches the limit plus null terminator.
 */
#define BRIX_S3_BUCKET_NAME_MAX            64

/*
 * S3 object key maximum length (bytes).
 * AWS S3 allows object keys up to 1024 bytes.
 * Matches AWS service limit exactly.
 */
#define BRIX_S3_OBJECT_KEY_MAX             1024

/*
 * S3 CORS preflight cache max-age (seconds).
 * RFC 6454 recommends 86400 seconds (24 hours) for CORS preflight caching.
 * Reduces preflight request overhead for repeated cross-origin requests.
 */
#define BRIX_S3_CORS_MAX_AGE_SEC           86400

/*
 * S3 SigV4 signature expiration maximum (seconds).
 * AWS SigV4 allows signatures valid for up to 7 days (604800 seconds).
 * Enforced in auth_sigv4_parse.c during signature validation.
 */
#define BRIX_S3_SIGV4_EXPIRY_MAX_SEC       604800

/*
 * S3 multipart copy buffer size (bytes).
 * Used for server-side copy operations in uploadPartCopy.
 * 64 KB balances memory usage with I/O efficiency.
 */
#define BRIX_S3_COPY_BUF_SIZE              65536

/*
 * S3 XML tag buffer size (bytes).
 * Used for XML parsing in tagging, user metadata operations.
 * Typical XML tags are 64-256 bytes; 2 KB provides 8x headroom.
 */
#define BRIX_S3_XML_TAG_BUF_SIZE           2048

/*
 * S3 SigV4 credential buffer size (bytes).
 * Used for parsing AWS credential strings in auth_sigv4_parse.c.
 * Format: AKID/DATE/REGION/s3/aws4_request (max ~128 bytes).
 */
#define BRIX_S3_CREDENTIAL_BUF_SIZE        256

/*
 * S3 SigV4 signed headers buffer size (bytes).
 * Used for storing signed headers list in auth_sigv4_verify.c.
 * Typical headers: host;x-amz-content-sha256;x-amz-date (~64 bytes).
 */
#define BRIX_S3_SIGNED_HEADERS_BUF_SIZE    256

/*
 * S3 SigV4 header skew tolerance (seconds).
 * AWS SigV4 requires request time within +/-900 seconds (15 minutes) of server time.
 * Used in auth_sigv4_verify_time.c for clock skew validation.
 */
#define BRIX_S3_SIGV4_HEADER_SKEW_SEC      900

/*
 * S3 SigV4 future skew tolerance (seconds).
 * Prevents future-dated requests beyond 900 seconds (15 minutes).
 * Used in auth_sigv4_verify_time.c for future date rejection.
 */
#define BRIX_S3_SIGV4_FUTURE_SKEW_SEC      900

/*
 * S3 canonical query string buffer size (bytes).
 * Used in auth_sigv4_verify_crypto.c for query string canonicalization.
 * Typical query strings are 256-512 bytes; 2 KB provides 4x headroom.
 */
#define BRIX_S3_CANONICAL_QUERY_BUF_SIZE   2048

/*
 * S3 canonical headers buffer size (bytes).
 * Used in auth_sigv4_verify_crypto.c for headers canonicalization.
 * Typical headers are 512-1024 bytes; 2 KB provides 2x headroom.
 */
#define BRIX_S3_CANONICAL_HEADERS_BUF_SIZE 2048

/*
 * S3 header name buffer size (bytes).
 * Used in auth_sigv4_canonical.c for header name extraction.
 * HTTP headers are typically 16-64 bytes; 256 bytes provides 4x headroom.
 */
#define BRIX_S3_HEADER_NAME_BUF_SIZE       256

/*
 * S3 header value buffer size (bytes).
 * Used in auth_sigv4_canonical.c for header value extraction.
 * HTTP header values are typically 64-256 bytes; 1 KB provides 4x headroom.
 */
#define BRIX_S3_HEADER_VALUE_BUF_SIZE      1024

/*
 * S3 ISO 8601 timestamp buffer size (bytes).
 * Used for parsing/generating ISO 8601 timestamps in auth operations.
 * Format: YYYYMMDDTHHMMSSZ (16 bytes) or full with timezone (32 bytes).
 */
#define BRIX_S3_ISO8601_BUF_SIZE           32

/*
 * S3 year base for Unix time conversion.
 * Used in auth_sigv4_verify_time.c for date parsing (year - 1900).
 */
#define BRIX_S3_UNIX_YEAR_BASE             1900

/*
 * S3 STS (Security Token Service) constants.
 *
 * BRIX_STS_TTL_MIN_SEC: Minimum credential lifetime (900 seconds = 15 minutes)
 * BRIX_STS_TTL_MAX_SEC: Maximum credential lifetime (43200 seconds = 12 hours)
 * BRIX_STS_TTL_DEFAULT_SEC: Default credential lifetime (3600 seconds = 1 hour)
 * BRIX_STS_BODY_BUF_SIZE: Buffer for STS request body (1024 bytes)
 * BRIX_STS_AUTHZ_BUF_SIZE: Buffer for STS authorization header (1024 bytes)
 * BRIX_STS_ACTION_QS_BUF_SIZE: Buffer for STS action query string (2048 bytes)
 * BRIX_STS_SIGNED_QS_BUF_SIZE: Buffer for STS signed query string (2560 bytes)
 * BRIX_STS_SESSION_BUF_SIZE: Buffer for STS session token (8192 bytes)
 * BRIX_STS_URL_BUF_SIZE: Buffer for STS request URL (3072 bytes)
 * BRIX_STS_HTTP_LINE_BUF_SIZE: Buffer for HTTP response line parsing (1200 bytes)
 * BRIX_STS_CANONICAL_BUF_SIZE: Buffer for canonical request (4096 bytes)
 */
#define BRIX_STS_TTL_MIN_SEC                 900
#define BRIX_STS_TTL_MAX_SEC                 43200
#define BRIX_STS_TTL_DEFAULT_SEC             3600
#define BRIX_STS_BODY_BUF_SIZE               1024
#define BRIX_STS_AUTHZ_BUF_SIZE              1024
#define BRIX_STS_ACTION_QS_BUF_SIZE          2048
#define BRIX_STS_SIGNED_QS_BUF_SIZE          2560
#define BRIX_STS_SESSION_BUF_SIZE            8192
#define BRIX_STS_URL_BUF_SIZE                3072
#define BRIX_STS_HTTP_LINE_BUF_SIZE          1200
#define BRIX_STS_CANONICAL_BUF_SIZE          4096

/*
 * GridFTP/FTP protocol constants.
 *
 * BRIX_FTP_PORT_MAX: 65535 (maximum valid TCP port number)
 * BRIX_FTP_NAME_BUF_SIZE: 256 bytes (buffer for FTP name/identifier)
 * BRIX_FTP_BEARER_BUF_SIZE: 4096 bytes (buffer for FTP bearer token)
 */
#define BRIX_FTP_PORT_MAX                  65535
#define BRIX_FTP_NAME_BUF_SIZE             256
#define BRIX_FTP_BEARER_BUF_SIZE           4096

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

/* ---- XRootD Protocol Constants ---- */

/*
 * XRootD protocol version for unsigned DH (default, universally compatible).
 * Used when client does not advertise version or uses legacy protocol.
 * All clients support this baseline version.
 */
#define BRIX_ROOT_PROTO_UNSIGNED               10000

/*
 * XRootD protocol version threshold for RSA-signed DH.
 * Clients advertising >= 10400 support signed DH for enhanced security.
 * Used in login handshake to negotiate DH variant (auto mode).
 */
#define BRIX_ROOT_PROTO_DHSIGNED_THRESHOLD   10400

/*
 * XRootD protocol version for signed DH with explicit requirement.
 * Used when server requires signed DH and rejects legacy clients.
 * Provides man-in-the-middle protection for DH key exchange.
 */
#define BRIX_ROOT_PROTO_DHSIGNED_REQUIRED    10600

/*
 * XRootD protocol version for password auth capability.
 * Clients advertising >= 10100 support XrdSecpwd authentication.
 * Opt-in feature for environments requiring password-based auth.
 */
#define BRIX_ROOT_PROTO_PWD_AUTH             10100

/*
 * Default login parameters buffer size (bytes).
 * Accommodates full parameter string: "&P=<auth>,v:<version>,c:<crypto>"
 * Typical: "&P=pwd,v:10100,c:ssl" = 19 bytes; 1024 provides 50x headroom.
 */
#define BRIX_ROOT_LOGIN_PARM_BUF             1024

/*
 * XRootD fattr recursive xattr list buffer (bytes).
 * Used for extended attribute enumeration on directories.
 * 8 KB accommodates typical directory with 50-100 xattrs.
 */
#define BRIX_ROOT_FATTR_XLIST_BUF            8192

/*
 * XRootD fattr response capacity (bytes).
 * Maximum buffer for recursive attribute list responses.
 * 256 KB accommodates deep directory trees with many xattrs.
 */
#define BRIX_ROOT_FATTR_RESP_CAP             (256 * 1024)

/*
 * XRootD fattr path slack buffer (bytes).
 * Extra space for names added between size query and retrieval.
 * 4 KB prevents reallocation during concurrent modifications.
 */
#define BRIX_ROOT_FATTR_PATH_SLACK           4096

/*
 * XRootD fattr value buffer size (bytes).
 * Maximum size for individual xattr value during enumeration.
 * 4 KB accommodates most xattr values (ACLs, capabilities, etc.).
 */
#define BRIX_ROOT_FATTR_VAL_BUF              4096

/*
 * XRootD async action code: attention frame (server push).
 * Used for kXR_attn frames carrying async notifications.
 * See XProtocol.hh for async frame format specification.
 */
#define BRIX_ROOT_ATTN_FRAME                 4001

/*
 * XRootD async action code: unsolicited message notification.
 * Server-initiated text messages to clients (status, warnings).
 * Deprecated in favor of asynresp for structured notifications.
 */
#define BRIX_ROOT_ASYNCMS                    5002

/*
 * XRootD async action code: deferred response delivery.
 * Used after kXR_waitresp to deliver delayed operation results.
 * Primary mechanism for long-running operation completion.
 */
#define BRIX_ROOT_ASYNCRESP                  5008

/*
 * XRootD async action code: abort notification (deprecated).
 * Legacy code 5000 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNCAB                    5000

/*
 * XRootD async action code: disconnect notification (deprecated).
 * Legacy code 5001 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNCDI                    5001

/*
 * XRootD async action code: read notification (deprecated).
 * Legacy code 5003 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNC_RD                   5003

/*
 * XRootD async action code: write notification (deprecated).
 * Legacy code 5004 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNC_WT                   5004

/*
 * XRootD async action code: availability notification (deprecated).
 * Legacy code 5005 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNC_AV                   5005

/*
 * XRootD async action code: unavailability notification (deprecated).
 * Legacy code 5006 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNC_UNAV                 5006

/*
 * XRootD async action code: go notification (deprecated).
 * Legacy code 5007 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNC_GO                   5007

/*
 * XRootD first request opcode base (3000).
 * All standard opcodes are offset from this base.
 * Used for opcode normalization and dispatch table indexing.
 */
#define BRIX_ROOT_OPCODE_BASE                3000

/*
 * XRootD query opcode (kXR_query = 2012).
 * Used for CMS queries, checksums, and metadata operations.
 * Legacy opcode predates the 3000+ range.
 */
#define BRIX_ROOT_QUERY_OPCODE               2012

/*
 * Adler-32 checksum buffer size (bytes).
 * Read buffer for RFC 3309 Adler-32 computation via pread() loop.
 * 64 KB provides optimal throughput for sequential file reads.
 */
#define BRIX_ROOT_ADLER_BUF                  65536

/*
 * Adler-32 checksum modulus (RFC 3309).
 * Prime modulus for Adler-32 accumulator (A and B values).
 * Must be applied after each byte to prevent overflow.
 */
#define BRIX_ROOT_ADLER_MOD                  65521

/*
 * ZIP inflate scratch buffer (bytes).
 * Temporary buffer for RFC 1951 deflate decompression.
 * 64 KB matches typical ZIP member compression window.
 */
#define BRIX_ROOT_ZIP_INFL_BUF               (64 * 1024)

/*
 * ZIP member maximum size (bytes).
 * Default cap for uncompressed ZIP member extraction.
 * 16 MB prevents memory exhaustion on malicious archives.
 */
#define BRIX_ROOT_ZIP_MEMBER_MAX             (16 * 1024 * 1024)

/*
 * Session duration conversion factor (ms to seconds).
 * Used in disconnect reporting for throughput calculations.
 * Floating-point division for precise rate computation.
 */
#define BRIX_ROOT_MS_TO_SEC_FACTOR           1000.0

/*
 * Mirror/replication subsystem constants.
 *
 * BRIX_MIRROR_DEFAULT_PORT: 1094 default XRootD port for mirror connections
 * BRIX_MIRROR_POOL_SIZE: 2048 bytes pool size for mirror task allocation
 * BRIX_MIRROR_TIMEOUT_DEFAULT_MS: 5000ms default timeout for mirror operations
 */
#define BRIX_MIRROR_DEFAULT_PORT             1094
#define BRIX_MIRROR_POOL_SIZE                2048
#define BRIX_MIRROR_TIMEOUT_DEFAULT_MS       5000

/*
 * Maximum macaroon path caveats.
 * Prevents path traversal attack via excessive caveat chains.
 * 8 allows reasonable delegation depth while bounding verification cost.
 */
#define BRIX_ROOT_MACAROON_PATH_CAVEATS_MAX  8

/* ============================================================================ */
/* IPv6 Flow Label Constants (SciTags Phase 34)                                */
/* ============================================================================ */

/*
 * IPv6 Flow Label field structure (20 bits, network byte order).
 * Used for SciTags network marking so routers/NRENs can classify traffic.
 * This is the per-packet technique complementing firefly (per-flow reporting).
 *
 * Flow Label Layout (20 bits, low bits of uint32_t):
 *   Bits 0-5:   Activity code (6 bits, 64 activities)
 *   Bits 6-15:  Experiment ID (10 bits, 1024 experiments)
 *   Bits 16-19: Entropy bits (4 bits, ECMP hash differentiation)
 *
 * Reference: SciTags2 Network Marking Phase 34 Specification §4
 * XRootD counterpart: XrdNetPMarkCfg.cc:240-248 (declared but not implemented)
 */

/*
 * Flow Label bit positions and masks.
 * BRIX_IPV6_FL_MASK: 20-bit field mask (0x000FFFFF)
 * BRIX_IPV6_FL_ENTROPY_MASK: Entropy bit positions (bits 0,1,8,18,19)
 * BRIX_IPV6_FL_ACTIVITY_BITS: Number of activity bits (6)
 * BRIX_IPV6_FL_ACTIVITY_MASK: Activity field mask (0x3F)
 * BRIX_IPV6_FL_EXP_SHIFT: Experiment ID shift (6 bits)
 * BRIX_IPV6_FL_EXP_MASK: Experiment field mask (0x3FF)
 */
#define BRIX_IPV6_FL_MASK              0x000FFFFFu   /* 20-bit flow label field */
#define BRIX_IPV6_FL_ENTROPY_MASK      0x000C0103u   /* E bits 0,1,8,18,19      */
#define BRIX_IPV6_FL_ACTIVITY_BITS     6             /* low 6 bits = activity   */
#define BRIX_IPV6_FL_ACTIVITY_MASK     0x3F          /* activity mask           */
#define BRIX_IPV6_FL_EXP_SHIFT         6             /* exp starts at bit 6     */
#define BRIX_IPV6_FL_EXP_MASK          0x3FF         /* 10-bit experiment mask  */

/*
 * IPv6 socket options for flow label management (Linux-specific).
 * These are normally in <linux/in6.h> but we define them here to avoid
 * header conflicts with <netinet/in.h>.
 *
 * BRIX_IPV6_FLOWLABEL_MGR: Socket option to manage flow labels (32)
 * BRIX_IPV6_FLOWINFO_SEND: Socket option to enable flow info in headers (33)
 * BRIX_IPV6_FL_A_GET: Action to get/retrieve a flow label (0)
 * BRIX_IPV6_FL_F_CREATE: Flag to create new flow label entry (1)
 * BRIX_IPV6_FL_S_EXCL: Share mode exclusive (1)
 */
#define BRIX_IPV6_FLOWLABEL_MGR        32            /* manage flow labels      */
#define BRIX_IPV6_FLOWINFO_SEND        33            /* send flowinfo in hdr    */
#define BRIX_IPV6_FL_A_GET             0             /* get/retrieve action     */
#define BRIX_IPV6_FL_F_CREATE          1             /* create flag             */
#define BRIX_IPV6_FL_S_EXCL            1             /* exclusive share mode    */

/*
 * Flow label encoding helper macro.
 * Encodes experiment ID and activity code into 20-bit flow label.
 * Usage: BRIX_IPV6_FL_ENCODE(exp, act) → uint32_t label
 *
 * Parameters:
 *   exp: Experiment ID (0-1023, 10 bits)
 *   act: Activity code (0-63, 6 bits)
 *
 * Returns: Encoded flow label (bits 6-15 = exp, bits 0-5 = act)
 *
 * Example:
 *   uint32_t label = BRIX_IPV6_FL_ENCODE(42, 1);  // exp=42, act=write
 */
#define BRIX_IPV6_FL_ENCODE(exp, act)  (((exp) & BRIX_IPV6_FL_EXP_MASK) << BRIX_IPV6_FL_ACTIVITY_BITS | ((act) & BRIX_IPV6_FL_ACTIVITY_MASK))

/*
 * Flow label range constants (SciTags2 specification).
 * These define the valid ranges for experiment IDs and activity codes.
 *
 * BRIX_IPV6_FLOW_MIN: Minimum valid flow value (65)
 * BRIX_IPV6_FLOW_MAX: Maximum valid flow value (65535, 16-bit space)
 * BRIX_IPV6_EXP_MIN: Minimum experiment ID (1)
 * BRIX_IPV6_EXP_MAX: Maximum experiment ID (1023, 10 bits)
 * BRIX_IPV6_ACT_MIN: Minimum activity code (1)
 * BRIX_IPV6_ACT_MAX: Maximum activity code (63, 6 bits)
 */
#define BRIX_IPV6_FLOW_MIN             65            /* smallest valid flow     */
#define BRIX_IPV6_FLOW_MAX             65535         /* 16-bit flow-id space    */
#define BRIX_IPV6_EXP_MIN              1             /* minimum experiment ID   */
#define BRIX_IPV6_EXP_MAX              1023          /* 10-bit experiment space */
#define BRIX_IPV6_ACT_MIN              1             /* minimum activity code   */
#define BRIX_IPV6_ACT_MAX              63            /* 6-bit activity space    */

/*
 * Activity code constants (SciTags2 standard activities).
 * These map to common data transfer operations.
 *
 * BRIX_IPV6_ACT_READ:  Client reads data (http-get, server is source)
 * BRIX_IPV6_ACT_WRITE: Client writes data (http-put, client is source)
 * BRIX_IPV6_ACT_TPC:   Third-party copy (outbound TPC)
 */
#define BRIX_IPV6_ACT_READ             0             /* client read (get)       */
#define BRIX_IPV6_ACT_WRITE            1             /* client write (put)      */
#define BRIX_IPV6_ACT_TPC              2             /* third-party copy        */

/*
 * Experiment ID constants (predefined experiment categories).
 * These categorize flows by their purpose or routing domain.
 *
 * BRIX_IPV6_EXP_DEFAULT: Default experiment (0)
 * BRIX_IPV6_EXP_PATH:    Path-based experiment (1)
 * BRIX_IPV6_EXP_VO:      Virtual Organization experiment (2)
 */
#define BRIX_IPV6_EXP_DEFAULT          0             /* default experiment      */
#define BRIX_IPV6_EXP_PATH             1             /* path-based experiment   */
#define BRIX_IPV6_EXP_VO               2             /* VO-based experiment     */

/*
 * Firefly collector UDP port (out-of-band flow reporting).
 * Complements the in-band flow label marking.
 *
 * BRIX_PMARK_FF_PORT: Default firefly collector port (10514)
 * This is the standard port for SciTags firefly UDP telemetry.
 */
#define BRIX_PMARK_FF_PORT             10514         /* firefly collector UDP   */

/*
 * ============================================================================
 * CONFIG CONSTANTS - Configuration parsing and runtime server setup
 * ============================================================================
 */

/*
 * Timeout constants (milliseconds unless noted).
 * Used throughout src/core/config/ for timer initialization and validation.
 *
 * BRIX_CONFIG_CRL_RELOAD_DEFAULT_SEC: Default CRL reload interval (3600 sec = 1 hour)
 * BRIX_CONFIG_CRL_RELOAD_MIN_SEC: Minimum CRL reload interval (60 sec)
 * BRIX_CONFIG_FRM_PURGE_TICK_MS: Default FRM purge timer tick (5000 ms)
 * BRIX_CONFIG_FRM_PURGE_DELAY_MIN_MS: Minimum delay before first purge (1000 ms)
 * BRIX_CONFIG_STAGE_RETRY_SWEEP_SEC: Stage retry sweep interval (derived from period/1000)
 * BRIX_CONFIG_HEALTH_CHECK_INTERVAL_MS: Default health check interval (30000 ms)
 * BRIX_CONFIG_HEALTH_CHECK_TIMEOUT_MS: Default health check timeout (5000 ms)
 * BRIX_CONFIG_HEALTH_CHECK_BLACKLIST_MS: Health check blacklist duration (60000 ms)
 * BRIX_CONFIG_CMS_PERF_INTERVAL_MS: CMS performance sampling interval (30000 ms)
 * BRIX_CONFIG_CMS_ALTDS_INTERVAL_MS: CMS AltDS reporting interval (10000 ms)
 * BRIX_CONFIG_TPC_MAX_TRANSFER_SECS: Maximum TPC transfer duration (86400 sec = 24 hours)
 */
#define BRIX_CONFIG_CRL_RELOAD_DEFAULT_SEC     3600          /* 1 hour CRL reload     */
#define BRIX_CONFIG_CRL_RELOAD_MIN_SEC         60            /* minimum CRL reload    */
#define BRIX_CONFIG_FRM_PURGE_TICK_MS          5000          /* FRM purge timer tick  */
#define BRIX_CONFIG_FRM_PURGE_DELAY_MIN_MS     1000          /* first purge delay     */
#define BRIX_CONFIG_STAGE_RETRY_SWEEP_SEC      1             /* retry sweep interval  */
#define BRIX_CONFIG_HEALTH_CHECK_INTERVAL_MS   30000         /* HC interval default   */
#define BRIX_CONFIG_HEALTH_CHECK_TIMEOUT_MS    5000          /* HC timeout default    */
#define BRIX_CONFIG_HEALTH_CHECK_BLACKLIST_MS  60000         /* HC blacklist default  */
#define BRIX_CONFIG_CMS_PERF_INTERVAL_MS       30000         /* CMS perf sampling     */
#define BRIX_CONFIG_CMS_ALTDS_INTERVAL_MS      10000         /* CMS AltDS reporting   */
#define BRIX_CONFIG_TPC_MAX_TRANSFER_SECS      86400         /* 24h max TPC transfer  */

/*
 * Buffer size constants for configuration parsing.
 * Used for temporary path buffers, bearer tokens, and line buffers.
 *
 * BRIX_CONFIG_BEARER_BUF_SIZE: Buffer for bearer token loading (4096 bytes)
 * BRIX_CONFIG_PATH_BUF_SIZE: Temporary path buffer (1024 bytes)
 * BRIX_CONFIG_LINE_BUF_SIZE: Configuration line buffer (1024 bytes)
 * BRIX_CONFIG_BACKEND_PATH_SIZE: Backend path buffer (4096 bytes)
 */
#define BRIX_CONFIG_BEARER_BUF_SIZE            4096          /* bearer token buffer   */
#define BRIX_CONFIG_PATH_BUF_SIZE              1024          /* temp path buffer      */
#define BRIX_CONFIG_LINE_BUF_SIZE              1024          /* config line buffer    */
#define BRIX_CONFIG_BACKEND_PATH_SIZE          4096          /* backend path buffer   */

/*
 * Limit and threshold constants.
 * Used for validation and caps in configuration processing.
 *
 * BRIX_CONFIG_PORT_MIN: Minimum valid port number (1)
 * BRIX_CONFIG_PORT_MAX: Maximum valid port number (65535)
 * BRIX_CONFIG_PPM_MAX: Maximum parts-per-million value (1000000)
 * BRIX_CONFIG_CACHE_SIZE_CAP: Maximum cache size cap (8*1024*1024 = 8 MB)
 * BRIX_CONFIG_SIZE_MIN_CAP: Minimum size capability (1024*1024 = 1 MB)
 * BRIX_CONFIG_EVICTION_THRESHOLD_MAX: Maximum eviction threshold (1000000 ppm)
 * BRIX_CONFIG_WATERMARK_MAX: Maximum watermark threshold (1000000 ppm)
 * BRIX_CONFIG_CACHE_PREFETCH_DEFAULT: Default cache prefetch window (8*1024*1024)
 */
#define BRIX_CONFIG_PORT_MIN                   1             /* minimum port          */
#define BRIX_CONFIG_PORT_MAX                   65535         /* maximum port          */
#define BRIX_CONFIG_PPM_MAX                    1000000       /* 100% in ppm           */
#define BRIX_CONFIG_CACHE_SIZE_CAP             (8*1024*1024) /* 8 MB cache cap        */
#define BRIX_CONFIG_SIZE_MIN_CAP               (1024*1024)   /* 1 MB min cap          */
#define BRIX_CONFIG_EVICTION_THRESHOLD_MAX     1000000       /* max eviction ppm      */
#define BRIX_CONFIG_WATERMARK_MAX              1000000       /* max watermark ppm     */
#define BRIX_CONFIG_CACHE_PREFETCH_DEFAULT     (8*1024*1024) /* 8 MB prefetch default */

/*
 * Permission constants for directory/file creation.
 * Used in mkdir/at and open/at calls throughout config processing.
 *
 * BRIX_CONFIG_PERM_PRIVATE: Private directory/file (0700)
 * BRIX_CONFIG_PERM_TRAVERSE: Traverse-only directory (0711)
 * BRIX_CONFIG_PERM_PUBLIC: Public directory (0755)
 * BRIX_CONFIG_PERM_FILE: Standard file permissions (0644)
 * BRIX_CONFIG_PERM_RESTRICTED: Restricted file (0600)
 */
#define BRIX_CONFIG_PERM_PRIVATE               0700          /* private dir/file      */
#define BRIX_CONFIG_PERM_TRAVERSE              0711          /* traverse-only dir     */
#define BRIX_CONFIG_PERM_PUBLIC                0755          /* public directory      */
#define BRIX_CONFIG_PERM_FILE                  0644          /* standard file         */
#define BRIX_CONFIG_PERM_RESTRICTED            0600          /* restricted file       */

/*
 * ============================================================================
 * SHARED CONSTANTS - Shared library utilities (shared/ directory)
 * ============================================================================
 */

/*
 * Buffer sizes for shared utilities.
 * Used in shared/net/, shared/cache/, shared/oci/, shared/cvmfs/.
 *
 * BRIX_SHARED_PROXY_BUF_SIZE: Proxy environment buffer (1024 bytes)
 * BRIX_SHARED_PROXY_RESP_SIZE: Proxy connect response buffer (2048 bytes)
 * BRIX_SHARED_TAR_PATH_SIZE: TAR entry path buffer (4096 bytes)
 * BRIX_SHARED_TAR_LINK_SIZE: TAR linkname buffer (4096 bytes)
 * BRIX_SHARED_OCI_COPYBUF_SIZE: OCI copy buffer (64*1024 = 64 KB)
 * BRIX_SHARED_STARGZ_IOBUF_SIZE: Stargz I/O buffer (64*1024 = 64 KB)
 * BRIX_SHARED_STARGZ_TOC_CAP0: Initial stargz TOC capacity (64*1024 = 64 KB)
 * BRIX_SHARED_FLATTEN_COMPS_MAX: Maximum path components (2048)
 * BRIX_SHARED_FLATTEN_ENTRIES_DEFAULT: Default flatten entries (1024*1024 = 1M)
 */
#define BRIX_SHARED_PROXY_BUF_SIZE             1024          /* proxy env buffer      */
#define BRIX_SHARED_PROXY_RESP_SIZE            2048          /* proxy response buffer */
#define BRIX_SHARED_TAR_PATH_SIZE              4096          /* TAR path buffer       */
#define BRIX_SHARED_TAR_LINK_SIZE              4096          /* TAR linkname buffer   */
#define BRIX_SHARED_OCI_COPYBUF_SIZE           (64*1024)     /* 64 KB OCI copy buf    */
#define BRIX_SHARED_STARGZ_IOBUF_SIZE          (64*1024)     /* 64 KB stargz I/O buf  */
#define BRIX_SHARED_STARGZ_TOC_CAP0            (64*1024)     /* 64 KB initial TOC cap */
#define BRIX_SHARED_FLATTEN_COMPS_MAX          2048          /* max path components   */
#define BRIX_SHARED_FLATTEN_ENTRIES_DEFAULT    (1024*1024)   /* 1M default entries    */

/*
 * CAS (Content-Addressable Storage) constants.
 * Used in shared/cache/cas_*.c for hash tables and file operations.
 *
 * BRIX_SHARED_CAS_FSYNC_BATCH: FSync batch size (8*1024*1024 = 8 MB)
 * BRIX_SHARED_CAS_HASH_SEED: FNV-1a hash seed (1469598103934665603ull)
 * BRIX_SHARED_CAS_HASH_PRIME: FNV-1a hash prime (1099511628211ull)
 * BRIX_SHARED_CAS_INIT_TAB_CAP: Initial hash table capacity (1024)
 * BRIX_SHARED_CAS_INIT_KEYS_CAP: Initial keys capacity (65536)
 * BRIX_SHARED_CAS_GC_CAP0: Initial GC capacity (1024)
 */
#define BRIX_SHARED_CAS_FSYNC_BATCH            (8L*1024*1024) /* 8 MB fsync batch     */
#define BRIX_SHARED_CAS_HASH_SEED              1469598103934665603ull /* FNV-1a seed  */
#define BRIX_SHARED_CAS_HASH_PRIME             1099511628211ull     /* FNV-1a prime   */
#define BRIX_SHARED_CAS_INIT_TAB_CAP           1024          /* initial table cap     */
#define BRIX_SHARED_CAS_INIT_KEYS_CAP          65536         /* initial keys cap      */
#define BRIX_SHARED_CAS_GC_CAP0                1024          /* initial GC cap        */

/*
 * Permission constants for shared operations.
 * Used in shared/cache/, shared/oci/ for file/directory creation.
 *
 * BRIX_SHARED_PERM_PRIVATE: Private file (0600)
 * BRIX_SHARED_PERM_FILE: Standard file (0644)
 * BRIX_SHARED_PERM_DIR: Standard directory (0755)
 * BRIX_SHARED_PERM_DIR_TRAVERSE: Traverse directory (0711)
 */
#define BRIX_SHARED_PERM_PRIVATE               0600          /* private file          */
#define BRIX_SHARED_PERM_FILE                  0644          /* standard file         */
#define BRIX_SHARED_PERM_DIR                   0755          /* standard directory    */
#define BRIX_SHARED_PERM_DIR_TRAVERSE          0711          /* traverse directory    */

/*
 * Limit constants for shared operations.
 *
 * BRIX_SHARED_PORT_MAX: Maximum port number (65535)
 * BRIX_SHARED_TAR_PATH_MAX: Maximum TAR path length (4095 bytes)
 * BRIX_SHARED_HEX_BUFFER_SIZE: Hex encoding buffer (64 bytes for SHA256)
 */
#define BRIX_SHARED_PORT_MAX                   65535         /* maximum port          */
#define BRIX_SHARED_TAR_PATH_MAX               4095          /* max TAR path length   */
#define BRIX_SHARED_HEX_BUFFER_SIZE            64            /* hex encoding buffer   */

/* ---- WebDAV Buffer Size Constants ---- */

/*
 * WebDAV macaroon endpoint OAuth2 body max (bytes).
 * Maximum request body size for OAuth2 token exchange endpoint.
 * 64 KB accommodates typical OAuth2 assertion payloads.
 */
#define BRIX_WEBDAV_MACAROON_OAUTH2_BODY_MAX  65536

/*
 * WebDAV macaroon endpoint request body max (bytes).
 * Maximum request body size for macaroon request endpoint.
 * 16 KB is sufficient for typical macaroon requests.
 */
#define BRIX_WEBDAV_MACAROON_REQUEST_BODY_MAX  16384

/*
 * WebDAV proppatch body max (bytes).
 * Maximum PROPPATCH request body size.
 * 64 KB accommodates large property updates.
 */
#define BRIX_WEBDAV_PROPPATCH_BODY_MAX  65536

/*
 * WebDAV dead property list max (bytes).
 * Maximum size for dead property list responses.
 * 64 KB provides margin for large property sets.
 */
#define BRIX_WEBDAV_DEAD_PROP_LIST_MAX    65536

/*
 * WebDAV PROPFIND body max (bytes).
 * Maximum PROPFIND request body size.
 * 64 KB accommodates complex property queries.
 */
#define BRIX_WEBDAV_PROPFIND_BODY_MAX  65536

/*
 * WebDAV SEARCH body max (bytes).
 * Maximum SEARCH request body size.
 * 64 KB accommodates complex search queries.
 */
#define BRIX_WEBDAV_SEARCH_BODY_MAX       65536

/*
 * WebDAV TPC digest max (bytes).
 * Maximum size for TPC digest header values.
 * 256 bytes accommodates algorithm names plus hex digests.
 */
#define BRIX_WEBDAV_TPC_DIGEST_MAX  256

/*
 * WebDAV XRDHTTP stats buffer max (bytes).
 * Buffer size for XRDHTTP statistics output.
 * 4 KB accommodates typical stats summaries.
 */
#define BRIX_WEBDAV_XRDHTTP_STATS_BUF_MAX  4096

/*
 * WebDAV TPC credential token max (bytes).
 * Maximum token length for TPC credential exchange.
 * 4 KB accommodates typical OAuth2/JWT tokens.
 */
#define BRIX_WEBDAV_TPC_CRED_TOKEN_MAX  4096

/*
 * WebDAV tape REST path max (bytes).
 * Maximum path length for tape REST operations.
 * 4 KB accommodates deep directory hierarchies.
 */
#define BRIX_WEBDAV_TAPE_PATH_MAX       4096

/*
 * WebDAV delegation temp path buffer (bytes).
 * Buffer for delegation temporary file paths.
 * 1024 bytes accommodates typical temp directory paths.
 */
#define BRIX_WEBDAV_DELEG_PATH_BUF      1024

/*
 * WebDAV dispatch CGI path buffer (bytes).
 * Buffer for CGI script paths in dispatch.
 * 512 bytes sufficient for typical CGI paths.
 */
#define BRIX_WEBDAV_CGI_PATH_BUF        512

/* ---- Config Module Timeout Constants ---- */

/*
 * Health check timeout constants (milliseconds).
 * Used in server_conf_merge_cluster.c for cluster health monitoring.
 *
 * BRIX_CONFIG_HC_INTERVAL_MS: Health check interval (30000 ms = 30s)
 * BRIX_CONFIG_HC_TIMEOUT_MS: Health check timeout (5000 ms = 5s)
 * BRIX_CONFIG_HC_BLACKLIST_MS: Health check blacklist duration (60000 ms = 60s)
 */
#define BRIX_CONFIG_HC_INTERVAL_MS       30000         /* HC interval default     */
#define BRIX_CONFIG_HC_TIMEOUT_MS        5000          /* HC timeout default      */
#define BRIX_CONFIG_HC_BLACKLIST_MS      60000         /* HC blacklist duration   */

/*
 * CMS performance and AltDS reporting intervals (milliseconds).
 * Used in server_conf_merge_cluster.c for CMS monitoring.
 *
 * BRIX_CONFIG_CMS_PERF_INTERVAL_MS: CMS performance sampling (30000 ms = 30s)
 * BRIX_CONFIG_CMS_ALTDS_INTERVAL_MS: CMS AltDS reporting (10000 ms = 10s)
 * BRIX_CONFIG_CMS_FSXEQ_TIMEOUT_MS: CMS FSXEQ timeout (10000 ms = 10s)
 */
#define BRIX_CONFIG_CMS_PERF_INTERVAL_MS 30000         /* CMS perf sampling       */
#define BRIX_CONFIG_CMS_ALTDS_INTERVAL_MS 10000        /* CMS AltDS reporting     */
#define BRIX_CONFIG_CMS_FSXEQ_TIMEOUT_MS 10000         /* CMS FSXEQ timeout       */

/*
 * Proxy module timeout constants (milliseconds).
 * Used in server_conf_merge_proxy_net.c for proxy connections.
 *
 * BRIX_CONFIG_PROXY_CONNECT_TIMEOUT_MS: Proxy connect timeout (10000 ms = 10s)
 * BRIX_CONFIG_PROXY_READ_TIMEOUT_MS: Proxy read timeout (60000 ms = 60s)
 * BRIX_CONFIG_PROXY_WRITE_TIMEOUT_MS: Proxy write timeout (60000 ms = 60s)
 * BRIX_CONFIG_PROXY_KEEPALIVE_INTERVAL_MS: Proxy keepalive (15000 ms = 15s)
 */
#define BRIX_CONFIG_PROXY_CONNECT_TIMEOUT_MS    10000    /* proxy connect timeout   */
#define BRIX_CONFIG_PROXY_READ_TIMEOUT_MS       60000    /* proxy read timeout      */
#define BRIX_CONFIG_PROXY_WRITE_TIMEOUT_MS      60000    /* proxy write timeout     */
#define BRIX_CONFIG_PROXY_KEEPALIVE_INTERVAL_MS 15000    /* proxy keepalive         */

/*
 * TPC max transfer duration (seconds).
 * Used in server_conf_merge_cluster.c for TPC transfer limits.
 *
 * BRIX_CONFIG_TPC_MAX_TRANSFER_SECS: Maximum TPC transfer (86400 = 24 hours)
 */
#define BRIX_CONFIG_TPC_MAX_TRANSFER_SECS  86400         /* 24h max TPC transfer    */

/* ---- Config Module Buffer Size Constants ---- */

/*
 * Config module buffer sizes (bytes).
 * Used in runtime_server_backend*.c for path and line buffers.
 *
 * BRIX_CONFIG_BACKEND_PATH_BUF_SIZE: Backend path buffer (4096 bytes)
 * BRIX_CONFIG_BACKEND_LINE_BUF_SIZE: Backend line buffer (1024 bytes)
 * BRIX_CONFIG_CACHE_PATH_BUF_SIZE: Cache path buffer (1024 bytes)
 */
#define BRIX_CONFIG_BACKEND_PATH_BUF_SIZE  4096          /* backend path buffer     */
#define BRIX_CONFIG_BACKEND_LINE_BUF_SIZE  1024          /* backend line buffer     */
#define BRIX_CONFIG_CACHE_PATH_BUF_SIZE    1024          /* cache path buffer       */

/*
 * Config module size limits (bytes).
 * Used in server_conf_merge_storage.c for cache and stage limits.
 *
 * BRIX_CONFIG_CACHE_SIZE_CAP: Cache size cap (8*1024*1024 = 8 MB)
 * BRIX_CONFIG_SIZE_MIN_CAP: Minimum size cap (1024*1024 = 1 MB)
 * BRIX_CONFIG_CACHE_PREFETCH_WINDOW_MAX: Max prefetch window (8*1024*1024 = 8 MB)
 * BRIX_CONFIG_ZIP_STAGE_MAX_BYTES: Zip stage max (512*1024*1024 = 512 MB)
 * BRIX_CONFIG_CACHE_WT_STAGE_HIGH_WATERMARK: Cache high watermark (900000)
 */
#define BRIX_CONFIG_CACHE_SIZE_CAP           (8*1024*1024)  /* 8 MB cache cap        */
#define BRIX_CONFIG_SIZE_MIN_CAP             (1024*1024)    /* 1 MB min cap          */
#define BRIX_CONFIG_CACHE_PREFETCH_WINDOW_MAX (8*1024*1024) /* 8 MB prefetch max     */
#define BRIX_CONFIG_ZIP_CD_MAX_BYTES         (16*1024*1024) /* 16 MB zip CD max      */
#define BRIX_CONFIG_ZIP_STAGE_MAX_BYTES      (512*1024*1024) /* 512 MB zip stage     */
#define BRIX_CONFIG_CACHE_WT_STAGE_HIGH_WM   900000         /* high watermark        */
#define BRIX_CONFIG_CACHE_WT_STAGE_HYSTERESIS 50000         /* hysteresis (5%)       */

/*
 * Config module checksum scan limits.
 * Used in server_conf_merge_cluster.c for checksum scanning.
 *
 * BRIX_CONFIG_CKSCAN_MAX_FILES: Maximum files to scan (100000)
 */
#define BRIX_CONFIG_CKSCAN_MAX_FILES         100000        /* max ckscan files      */

/*
 * Config module stage retry permissions.
 * Used in process_stage_retry.c for queue directory creation.
 *
 * BRIX_CONFIG_STAGE_RETRY_QUEUE_PERM: Stage retry queue permission (0700)
 */
#define BRIX_CONFIG_STAGE_RETRY_QUEUE_PERM   0700          /* retry queue perm      */

/* ---- Shared Module Additional Constants ---- */

/*
 * Shared OCI module constants.
 * Used in shared/oci C files for OCI operations.
 *
 * BRIX_SHARED_OCI_FLATTEN_COPYBUF_SIZE: OCI flatten copy buffer (64*1024 = 64 KB)
 * BRIX_SHARED_OCI_FLATTEN_MAX_PATH: OCI flatten max path (4096 bytes)
 * BRIX_SHARED_OCI_STARGZ_PATH_BUF: Stargz path buffer (1100 bytes)
 * BRIX_SHARED_OCI_TAR_MODE_MASK: TAR mode mask (07777)
 */
#define BRIX_SHARED_OCI_FLATTEN_COPYBUF_SIZE (64*1024)     /* 64 KB flatten copybuf */
#define BRIX_SHARED_OCI_FLATTEN_MAX_PATH     4096          /* max flatten path      */
#define BRIX_SHARED_OCI_STARGZ_PATH_BUF      1100          /* stargz path buffer    */
#define BRIX_SHARED_OCI_TAR_MODE_MASK        07777         /* TAR mode mask         */

/*
 * Shared CAS module file permissions.
 * Used in shared/cache/cas_*.c for file creation.
 *
 * BRIX_SHARED_CAS_FILE_PERM: CAS file permission (0644)
 * BRIX_SHARED_CAS_TMP_PERM: CAS temp file permission (0644)
 * BRIX_SHARED_CAS_DIR_PERM: CAS directory permission (0755)
 * BRIX_SHARED_CAS_PACK_DIR_PERM: CAS pack directory permission (0755)
 * BRIX_SHARED_CAS_PRIVATE_PERM: CAS private file permission (0600)
 */
#define BRIX_SHARED_CAS_FILE_PERM            0644          /* CAS file perm         */
#define BRIX_SHARED_CAS_TMP_PERM             0644          /* CAS temp perm         */
#define BRIX_SHARED_CAS_DIR_PERM             0755          /* CAS directory perm    */
#define BRIX_SHARED_CAS_PACK_DIR_PERM        0755          /* CAS pack dir perm     */
#define BRIX_SHARED_CAS_PRIVATE_PERM         0600          /* CAS private perm      */

/* ---- Client Module Constants ---- */

/*
 * Client module buffer sizes (bytes).
 * Used in client/ for test and utility buffers.
 *
 * BRIX_CLIENT_TEST_BUF_SIZE: Client test buffer (8192 bytes)
 * BRIX_CLIENT_TEST_URL_BUF_SIZE: Client test URL buffer (8300 bytes)
 */
#define BRIX_CLIENT_TEST_BUF_SIZE            8192          /* test buffer size      */
#define BRIX_CLIENT_TEST_URL_BUF_SIZE        8300          /* test URL buffer       */

/*
 * Client FTP module constants.
 * Used in client/tests/c/ftp_client_unit.c for FTP operations.
 *
 * BRIX_CLIENT_FTP_DEFAULT_PORT: FTP default port (2811 - GridFTP)
 * BRIX_CLIENT_FTP_DATA_PORT_MIN: FTP data port minimum (1024)
 * BRIX_CLIENT_FTP_DATA_PORT_MAX: FTP data port maximum (65535)
 */
#define BRIX_CLIENT_FTP_DEFAULT_PORT         2811          /* GridFTP port          */
#define BRIX_CLIENT_FTP_DATA_PORT_MIN        1024          /* data port minimum     */
#define BRIX_CLIENT_FTP_DATA_PORT_MAX        65535         /* data port maximum     */

/*
 * WebDAV redirect canonical path buffer (bytes).
 * Buffer for canonicalized redirect paths.
 * 4096 bytes accommodates complex redirect scenarios.
 */
#define BRIX_WEBDAV_REDIRECT_CANON_BUF  4096

/*
 * WebDAV redirect user/VO buffer (bytes).
 * Buffer for user and VO strings in redirects.
 * 1024 bytes each accommodates typical identifiers.
 */
#define BRIX_WEBDAV_REDIRECT_ID_BUF     1024

/*
 * WebDAV TPC credential body buffer (bytes).
 * Stack buffer for TPC credential body.
 * 2048 bytes accommodates typical credential payloads.
 */
#define BRIX_WEBDAV_TPC_CRED_BODY_BUF   2048

/* ---- WebDAV Timeout Constants ---- */

/*
 * WebDAV macaroon expiry default (seconds).
 * Default expiry for macaroon tokens when not specified.
 * 1 hour (3600s) is the RFC 4918 recommended default.
 */
#define BRIX_WEBDAV_MACAROON_EXPIRY_DEFAULT  3600

/*
 * WebDAV macaroon expiry maximum (seconds).
 * Maximum allowed macaroon token expiry.
 * 30 days (2,592,000s) prevents excessive token lifetimes.
 */
#define BRIX_WEBDAV_MACAROON_EXPIRY_MAX  (86400L * 30)

/*
 * WebDAV introspect TTL multiplier.
 * Multiplier to convert introspect TTL to milliseconds.
 * 1000 converts seconds to milliseconds.
 */
#define BRIX_WEBDAV_INTROSPECT_TTL_MULT  1000

/*
 * WebDAV TPC low speed default (bytes).
 * Default low-speed threshold for TPC transfers.
 * 1024 bytes/second triggers low-speed timeout.
 */
#define BRIX_WEBDAV_TPC_LOW_SPEED_DEFAULT  1024

/*
 * WebDAV TPC 2GB limit check.
 * Threshold for 2GB file size special handling.
 * Used to detect files exceeding 32-bit offset range.
 */
#define BRIX_WEBDAV_TPC_2GB_LIMIT  (2LL * 1024 * 1024 * 1024)

/* ---- WebDAV Pool Allocation Constants ---- */

/*
 * WebDAV walk offload pool size (bytes).
 * nginx pool size for walk offload operations.
 * 4096 bytes is efficient for walk metadata.
 */
#define BRIX_WEBDAV_WALK_POOL_SIZE    4096

/*
 * WebDAV proxy pool base size (bytes).
 * Base pool size for proxy operations.
 * 512 bytes is minimal for proxy metadata.
 */
#define BRIX_WEBDAV_PROXY_POOL_BASE   512

/* ---- OCI (Open Container Initiative) Constants ---- */

/* ---- OCI Buffer Size Constants ---- */

/*
 * OCI delegation challenge buffer (bytes).
 * Buffer for OCI delegation challenge strings.
 * 256 bytes accommodates typical challenge responses.
 */
#define BRIX_OCI_DELEG_CHAL_BUF     256

/*
 * OCI delegation scope buffer (bytes).
 * Buffer for OCI delegation scope strings.
 * 512 bytes accommodates complex scope specifications.
 */
#define BRIX_OCI_DELEG_SCOPE_BUF    512

/*
 * OCI error buffer (bytes).
 * Buffer for OCI error message formatting.
 * 256 bytes accommodates typical error messages.
 */
#define BRIX_OCI_ERROR_BUF          256

/*
 * OCI GC (garbage collection) error buffer (bytes).
 * Buffer for GC error reporting.
 * 256 bytes sufficient for error context.
 */
#define BRIX_OCI_GC_ERROR_BUF       256

/*
 * OCI registry principal buffer (bytes).
 * Buffer for registry principal identifiers.
 * 256 bytes accommodates typical principal names.
 */
#define BRIX_OCI_REGISTRY_PRINCIPAL_BUF  256

/*
 * OCI tags challenge buffer (bytes).
 * Buffer for tags API challenge strings.
 * 1024 bytes accommodates complex challenge data.
 */
#define BRIX_OCI_TAGS_CHAL_BUF    1024

/*
 * OCI token cache key buffer (bytes).
 * Buffer for token cache key construction.
 * 1024+33 bytes: 1024 for components + 33 for formatting.
 */
#define BRIX_OCI_TOKEN_CACHE_KEY_BUF  (1024 + 33)

/*
 * OCI token cache scope buffer (bytes).
 * Buffer for token scope strings.
 * 1024 bytes accommodates complex scope specifications.
 */
#define BRIX_OCI_TOKEN_CACHE_SCOPE_BUF  1024

/*
 * OCI upstream auth host buffer (bytes).
 * Buffer for upstream registry host strings.
 * 256 bytes accommodates FQDNs with subdomains.
 */
#define BRIX_OCI_UPSTREAM_HOST_BUF  256

/*
 * OCI upstream auth error buffer (bytes).
 * Buffer for upstream auth error messages.
 * 256 bytes sufficient for error reporting.
 */
#define BRIX_OCI_UPSTREAM_ERROR_BUF  256

/* ---- OCI Timeout Constants ---- */

/*
 * OCI delegation challenge TTL (milliseconds).
 * Time-to-live for delegation challenges.
 * 1 hour (3,600,000ms) allows time for client proof generation.
 */
#define BRIX_OCI_DELEG_CHAL_TTL_MS  (3600 * 1000)

/*
 * OCI proof TTL multiplier.
 * Multiplier to convert proof TTL to milliseconds.
 * 1000 converts seconds to milliseconds.
 */
#define BRIX_OCI_PROOF_TTL_MULT   1000

/* ---- OCI Size Limit Constants ---- */

/*
 * OCI manifest max size (bytes).
 * Maximum size for OCI manifest documents.
 * 4 MB accommodates large manifests with many layers.
 */
#define BRIX_OCI_MANIFEST_MAX      (4 * 1024 * 1024)

/*
 * OCI referrers body max (bytes).
 * Maximum size for referrers API response bodies.
 * 256 KB accommodates typical referrer lists.
 */
#define BRIX_OCI_REFERRERS_BODY_MAX  (256 * 1024)

/*
 * OCI tags max size (bytes).
 * Maximum size for tags API responses.
 * 64 KB accommodates repositories with many tags.
 */
#define BRIX_OCI_TAGS_MAX  (64 * 1024)

/*
 * OCI tags response max (bytes).
 * Maximum size for tags list responses.
 * 256 KB provides margin for large tag lists.
 */
#define BRIX_OCI_TAGS_RESP_MAX     (256 * 1024)

/* ---- OCI Permission Constants ---- */

/*
 * OCI store directory mode.
 * Permissions for OCI store directories.
 * 0700 = owner rwx only (private store).
 */
#define BRIX_OCI_STORE_DIR_MODE   0700

/*
 * OCI store I/O chunk size (bytes).
 * I/O buffer size for store read/write operations.
 * 64 KB balances memory usage with throughput.
 */
#define BRIX_OCI_STORE_IO_CHUNK   (64 * 1024)

/*
 * OCI upload session mode.
 * Permissions for upload session files.
 * 0700 = owner rwx only (private sessions).
 */
#define BRIX_OCI_UPLOAD_SESSION_MODE  0700

/* ---- OCI Key/Value Constants ---- */

/*
 * OCI mirror KV value size (bytes).
 * Value size for mirror location KV store.
 * 4096 bytes accommodates mirror metadata.
 */
#define BRIX_OCI_MIRROR_KV_VAL_SIZE  4096

/* ---- ISO-8601 Duration Constants ---- */

/*
 * Seconds per day (for ISO-8601 duration parsing).
 * Used in macaroon endpoint duration calculations.
 * 86400 = 24 * 60 * 60
 */
#define BRIX_ISO8601_SECS_PER_DAY  86400

/*
 * Seconds per hour (for ISO-8601 duration parsing).
 * Used in macaroon endpoint duration calculations.
 * 3600 = 60 * 60
 */
#define BRIX_ISO8601_SECS_PER_HOUR  3600

/* ---- Quality Value Constants (RFC 7231) ---- */

/*
 * HTTP quality value scale (RFC 7231).
 * q-values are 0..1 with 3 decimals, scaled to 0..1000.
 * Used in content-type preference parsing.
 */
#define BRIX_HTTP_Q_SCALE  1000

/*
 * Default HTTP quality value (1.0).
 * Used when q-value is absent in Accept headers.
 * Scaled to 1000 for integer arithmetic.
 */
#define BRIX_HTTP_Q_DEFAULT  1000

/*
 * Maximum HTTP quality value (1.0).
 * Caps q-values at 1.0 even if malformed input exceeds.
 * Scaled to 1000 for integer arithmetic.
 */
#define BRIX_HTTP_Q_MAX  1000

/* ---- OIDC Agent Socket Path ---- */

/*
 * OIDC agent socket default path.
 * Default location for oidc-agent Unix socket.
 * Used when no explicit socket path is configured.
 */
#define BRIX_OIDC_AGENT_SOCKET_PATH  "/run/user/1000/oidc/oidc_agent.sock"

/* ---- Curl Multi Wait Timeout ---- */

/*
 * Curl multi wait timeout (milliseconds).
 * Timeout for curl_multi_wait() in TPC curl integration.
 * 1000ms (1 second) balances responsiveness with efficiency.
 */
#define BRIX_CURL_MULTI_WAIT_TIMEOUT_MS  1000

/* ---- Buffer Size Constants ---- */

/*
 * Admin Unix socket connection pool size (bytes).
 * Pool size for admin Unix socket connections.
 * 2048 bytes provides adequate space for admin commands.
 */
#define BRIX_ADMIN_POOL_SIZE  2048

/*
 * Rate limit stream path buffer size.
 * Path buffer for rate limit stream operations.
 * 1024 bytes accommodates typical filesystem paths.
 */
#define BRIX_RL_STREAM_PATH_BUF  1024

/*
 * Registry health check entry buffer size.
 * Buffer for health check entry formatting.
 * 300 bytes accommodates typical host:port entries.
 */
#define BRIX_REGISTRY_HEALTH_ENTRY_BUF  300

/*
 * Registry health check hostport buffer size.
 * Buffer for host:port formatting (host[256] + "[]" + ":65535" + NUL).
 * 288 bytes = 256 (host) + 2 (brackets) + 6 (":65535") + 1 (NUL) + padding.
 */
#define BRIX_REGISTRY_HEALTH_HOSTPORT_BUF  288

/*
 * CMS server handler IP buffer size.
 * Buffer for peer IP string representation.
 * 64 bytes accommodates IPv6 addresses with padding.
 */
#define BRIX_CMS_HANDLER_IP_BUF  64

/*
 * Tape stage configuration path buffer size.
 * Path buffer for tape stage configuration.
 * 4096 bytes matches PATH_MAX for full path support.
 */
#define BRIX_TAPE_STAGE_PATH_BUF  4096

/*
 * Tape stage runtime configuration line buffer size.
 * Line buffer for reading runtime configuration.
 * 1024 bytes accommodates typical configuration lines.
 */
#define BRIX_TAPE_STAGE_LINE_BUF  1024

/*
 * Rate limit reservation name buffer size.
 * Buffer for rate limit reservation names.
 * 64 bytes accommodates typical reservation identifiers.
 */
#define BRIX_RL_RESERVATION_NAME_BUF  64

/*
 * Redirect cache path buffer size.
 * Path buffer for redirect cache entries.
 * 256 bytes accommodates typical redirect paths.
 */
#define BRIX_REDIR_CACHE_PATH_BUF  256

/*
 * Redirect cache host buffer size.
 * Host buffer for redirect cache entries.
 * 128 bytes accommodates typical hostnames.
 */
#define BRIX_REDIR_CACHE_HOST_BUF  128

/*
 * CMS server send payload buffer size.
 * Buffer for CMS server send payload construction.
 * 256 bytes + 3 bytes for payload header.
 */
#define BRIX_CMS_SEND_PAYLOAD_BUF  259

/* ---- File Permission Constants ---- */

/*
 * Default CMS node file mode.
 * File mode for regular files created by CMS.
 * 0644 = owner rw, group r, others r.
 */
#define BRIX_CMS_FILE_MODE  0644

/*
 * Default CMS node directory mode.
 * Directory mode for directories created by CMS.
 * 0755 = owner rwx, group rx, others rx.
 */
#define BRIX_CMS_DIR_MODE  0755

/*
 * Staged file default mode.
 * Mode for staged files before commit.
 * 0600 = owner rw only (private during staging).
 */
#define BRIX_STAGE_FILE_MODE  0600

/*
 * Credential staging directory mode.
 * Mode for credential staging directories.
 * 0700 = owner rwx only (private tmpfs directory).
 */
#define BRIX_CRED_STAGE_DIR_MODE  0700

/* ---- Port and Protocol Constants ---- */

/*
 * Default IANA CMS server port.
 * IANA-assigned port for CMS management (distinct from XRootD CMS).
 */
#define BRIX_IANA_CMS_DEFAULT_PORT  1213

/*
 * Default XRootD port.
 * IANA-assigned port for XRootD services.
 */
#define BRIX_XRD_DEFAULT_PORT  1094

/*
 * Maximum valid port number.
 * Upper bound for TCP/UDP port validation.
 */
#define BRIX_MAX_PORT_NUM  65535

/* ---- Time and Rate Constants ---- */

/*
 * Nanoseconds per second.
 * Conversion factor for time calculations.
 */
#define BRIX_NSEC_PER_SEC  1000000000ULL

/*
 * Rate limit unit scale factor.
 * Rate limits stored ×1000 for sub-millisecond precision.
 */
#define BRIX_RATE_LIMIT_SCALE  1000

/*
 * Registry selection weight divisor.
 * Divisor for weighted metric calculations.
 */
#define BRIX_REGISTRY_WEIGHT_DIVISOR  10000

/* ---- Tape Stage TTL Constants ---- */

/*
 * Default tape stage TTL (milliseconds).
 * Time-to-live for staged tape data.
 * 600000ms = 10 minutes.
 */
#define BRIX_TAPE_STAGE_TTL_DEFAULT_MS  600000

/*
 * Default tape stage reap interval (milliseconds).
 * Interval for reaping expired staged data.
 * 300000ms = 5 minutes.
 */
#define BRIX_TAPE_STAGE_REAP_INTERVAL_MS  300000

/* ---- Checksum Algorithm Constants ---- */

/*
 * Adler-32 modulus.
 * Modulus used in Adler-32 checksum calculation.
 */
#define BRIX_ADLER_MOD  65521

/* ---- Hash Algorithm Constants ---- */

/*
 * DJB2 hash initial value.
 * Standard initialization constant for djb2 hash algorithm.
 * Used in various hash table implementations throughout the codebase.
 */
#define BRIX_HASH_DJB2_INIT  5381

/*
 * FNV-1a 64-bit offset basis.
 * Initial hash value for FNV-1a 64-bit hash.
 */
#define BRIX_FNV1A_64_OFFSET  1469598103934665603ULL

/*
 * FNV-1a 64-bit prime.
 * Multiplicative factor for FNV-1a 64-bit hash.
 */
#define BRIX_FNV1A_64_PRIME  1099511628211ULL

/* ---- Security Policy Constants ---- */

/*
 * Minimum RSA/DSA key size (bits).
 * IGTF floor for acceptable public key strength.
 */
#define BRIX_MIN_RSA_KEY_BITS  2048

/*
 * Minimum DSA key size (bits).
 * IGTF floor for acceptable DSA key strength.
 */
#define BRIX_MIN_DSA_KEY_BITS  2048

/* ---- GSI Protocol Constants ---- */

/*
 * GSI certificate request message code.
 * kXGC_certreq = 1000 in XRootD GSI protocol.
 */
#define BRIX_GSI_CERTREQ_CODE  1000

/*
 * GSI certificate response message code.
 * kXGS_cert = 2001 in XRootD GSI protocol.
 */
#define BRIX_GSI_CERT_CODE  2001

/*
 * GSI signed-DH minimum client version.
 * Clients >= 10400 support signed DH handshake.
 */
#define BRIX_GSI_SIGNED_DH_MIN_VERSION  10400

/*
 * GSI authmore response code.
 * kXR_authmore = 4002 in XRootD protocol.
 */
#define BRIX_GSI_AUTHMORE_CODE  4002

/* ---- S3 STS API Constants ---- */

/*
 * S3 STS API version string.
 * Version parameter for STS AssumeRole requests.
 */
#define BRIX_S3_STS_VERSION  "2011-06-15"

/* ---- HTTP Guard Constants ---- */

/*
 * HTTP guard timestamp buffer size.
 * Buffer for ISO-8601 timestamp formatting.
 * Size: "YYYY-MM-DDThh:mm:ss+00:00" = 25 bytes + NUL.
 */
#define BRIX_HTTPGUARD_TS_BUF  26

/* ---- Nginx Version Check ---- */

/*
 * Nginx version threshold for directive flags.
 * NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1234 available in newer versions.
 */
#define BRIX_NGINX_STREAM_CONF_VERSION  1023000

/* ---- Maximum Frame Constants ---- */

/*
 * Maximum CMS frame payload size.
 * Maximum payload for CMS frame operations.
 */
#define BRIX_CMS_MAX_FRAME_PAYLOAD  4096

/* ---- Monitor Value Constants ---- */

/*
 * Maximum valid monitor value.
 * Monitor values are percentages; >1000 indicates garbled input.
 */
#define BRIX_MONITOR_VALUE_MAX  1000

/* ---- Connection Pool Constants ---- */

/*
 * Maximum CMS connections per server.
 * Default cap on accepted CMS connections.
 */
#define BRIX_CMS_MAX_CONNECTIONS_DEFAULT  4096

/* ---- Advertisement Interval ---- */

/*
 * Default advertisement interval (milliseconds).
 * Interval for server advertisement broadcasts.
 * 60000ms = 1 minute.
 */
#define BRIX_ADVERTISE_INTERVAL_DEFAULT_MS  60000

/* ---- Redirection TTL ---- */

/*
 * Default redirection TTL (milliseconds).
 * Time-to-live for cached redirections.
 * 30000ms = 30 seconds.
 */
#define BRIX_REDIR_TTL_DEFAULT_MS  30000

/* ---- Occupancy Precision ---- */

/*
 * Occupancy calculation precision multiplier.
 * Used for precise occupancy percentage calculations.
 */
#define BRIX_OCCUPANCY_PRECISION  1000000

/* ---- Days per Second ---- */

/*
 * Seconds per day.
 * Used in S3 backend date calculations.
 */
#define BRIX_SECS_PER_DAY  86400

/* ---- ISO-8601 Buffer Size ---- */

/*
 * ISO-8601 timestamp buffer size.
 * Buffer size for full ISO-8601 timestamp with milliseconds.
 * Format: "YYYY-MM-DDThh:mm:ss.mmmZ" = 24 bytes + NUL.
 */
#define BRIX_ISO8601_BUF_SIZE  25

/* ---- Year/Month Adjustment ---- */

/*
 * Unix epoch year offset.
 * Adjustment for tm_year to calendar year.
 */
#define BRIX_UNIX_EPOCH_YEAR  1900

/* ---- Unicode Base64url Alphabet ---- */

/*
 * Base64url encoding alphabet.
 * Standard RFC 4648 base64url character set.
 */
#define BRIX_BASE64URL_ALPHABET  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

/* ---- Hexadecimal Alphabet ---- */

/*
 * Lowercase hexadecimal alphabet.
 * Used for hex encoding operations.
 */
#define BRIX_HEX_ALPHABET_LOWER  "0123456789abcdef"

/*
 * Uppercase hexadecimal alphabet.
 * Used for hex encoding operations.
 */
#define BRIX_HEX_ALPHABET_UPPER  "0123456789ABCDEF"

/* ---- Windows Build Number Constants ---- */

/* Windows 11 24H2 build number */
#define BRIX_WIN11_24H2_BUILD  26100

/* Windows Server 2022 build number */
#define BRIX_WIN_SERVER_2022_BUILD  20348

/* Windows 10 1809 build number */
#define BRIX_WIN10_1809_BUILD  17763

/* Windows 11 21H2 build number */
#define BRIX_WIN11_21H2_BUILD  22000

/* Windows 11 22H2 build number */
#define BRIX_WIN11_22H2_BUILD  22621

/* Windows 10 21H2 build number */
#define BRIX_WIN10_21H2_BUILD  19044

/* Windows 10 21H1 build number */
#define BRIX_WIN10_21H1_BUILD  19043

/* Windows 10 20H2 build number */
#define BRIX_WIN10_20H2_BUILD  19042

/* Windows 10 2004 build number */
#define BRIX_WIN10_2004_BUILD  19041

/* ---- URI Unreserved Characters (RFC 3986) ---- */

/*
 * URI unreserved characters.
 * RFC 3986 unreserved character set for URI encoding.
 */
#define BRIX_URI_UNRESERVED  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

/* ---- WebDAV Additional Constants ---- */

/*
 * WebDAV XRootD HTTPS default port.
 * Default port for XRootD-over-HTTPS (xrdhttp) connections.
 * 8443 is the standard alternative HTTPS port for XRootD services.
 */
#define BRIX_WEBDAV_XRDHTTP_HTTPS_PORT  8443

/*
 * WebDAV TPC marker URL buffer size (bytes).
 * Buffer size for TPC marker URL storage in internal structures.
 * 4096 bytes accommodates typical marker service URLs with query params.
 */
#define BRIX_WEBDAV_TPC_MARKER_URL_BUF  4096

/*
 * WebDAV PUT/COPY buffer size (bytes).
 * Buffer size for WebDAV PUT and COPY operations.
 * 1 MB is efficient for streaming large file transfers.
 */
#define BRIX_WEBDAV_PUT_COPY_BUFSZ  (1024 * 1024)

/*
 * WebDAV PUT/COPY chunk size (bytes).
 * Chunk size for large WebDAV PUT and COPY operations.
 * 16 MB chunks balance memory usage with transfer efficiency.
 */
#define BRIX_WEBDAV_PUT_COPY_CHUNK  (16 * 1024 * 1024)

/*
 * WebDAV redirect canonicalization buffer (bytes).
 * Buffer size for URL canonicalization in redirect operations.
 * 4096 bytes handles typical redirect URLs with query parameters.
 */
#define BRIX_WEBDAV_REDIRECT_CANON_BUF  4096

/*
 * WebDAV redirect ID buffer (bytes).
 * Buffer size for redirect operation identifiers.
 * 1024 bytes is sufficient for redirect tracking IDs.
 */
#define BRIX_WEBDAV_REDIRECT_ID_BUF  1024

/*
 * WebDAV macaroon endpoint path buffer (bytes).
 * Buffer size for macaroon caveat path extraction.
 * 1024 bytes handles typical API endpoint paths.
 */
#define BRIX_WEBDAV_MACAROON_PATH_BUF  1024

/*
 * WebDAV escape URI buffer multiplier.
 * Multiplier for URI buffer sizing (6x for URL encoding overhead).
 * Base size * 6 + 8 accommodates worst-case URL encoding expansion.
 */
#define BRIX_WEBDAV_ESC_URI_MULT  6
#define BRIX_WEBDAV_ESC_URI_EXTRA  8

/* ---- OCI (Open Container Initiative) Additional Constants ---- */

/*
 * OCI store I/O chunk size (bytes).
 * Chunk size for OCI store read/write operations.
 * 64 KB balances I/O efficiency with memory usage.
 */
#define BRIX_OCI_STORE_IO_CHUNK  (64 * 1024)

/*
 * OCI mirror password file mode mask (octal).
 * Permission mask for OCI mirror password files.
 * 07777 used for validation checking (must be 0600 or 0400).
 */
#define BRIX_OCI_MIRROR_PWFILE_MODE_MASK  07777

/* ---- S3 (Amazon Simple Storage Service) Constants ---- */

/*
 * S3 multipart part number range maximum.
 * S3 allows part numbers from 1 to 10000 for multipart uploads.
 * Used for validation in part number parsing.
 */
#define BRIX_S3_PART_NUMBER_MAX  10000

/*
 * S3 user metadata KV buffer size (bytes).
 * Buffer size for S3 user metadata key-value pairs.
 * 2048 bytes accommodates typical user metadata sizes.
 */
#define BRIX_S3_USERMETA_KV_BUF  2048

/*
 * S3 handler host buffer size (bytes).
 * Buffer size for S3 handler hostname storage.
 * 64 bytes is sufficient for typical S3 endpoint hostnames.
 */
#define BRIX_S3_HANDLER_HOST_BUF  64

/*
 * S3 handler path buffer size (bytes).
 * Buffer size for S3 handler path storage.
 * 1024 bytes handles typical S3 object key paths.
 */
#define BRIX_S3_HANDLER_PATH_BUF  1024

/*
 * S3 handler CGI buffer size (bytes).
 * Buffer size for S3 handler CGI parameter storage.
 * 512 bytes is sufficient for typical CGI parameters.
 */
#define BRIX_S3_HANDLER_CGI_BUF  512

/*
 * S3 handler temporary path buffer size (bytes).
 * Buffer size for S3 handler temporary path construction.
 * 2048 bytes handles temp path construction with prefixes.
 */
#define BRIX_S3_HANDLER_TMP_PATH_BUF  2048

/*
 * S3 list walk entry array size.
 * Maximum number of entries cached per list walk request.
 * 65536 entries (~273 MB) handles large bucket listings efficiently.
 */
#define BRIX_S3_LIST_WALK_ENTRY_MAX  65536

/*
 * S3 list walk key inline size (bytes).
 * Inline key storage size per list walk entry.
 * 4096 bytes accommodates typical S3 object key lengths.
 */
#define BRIX_S3_LIST_WALK_KEY_BUF  4096

/*
 * S3 conditional header value buffer (bytes).
 * Buffer size for S3 conditional header parsing.
 * 1024 bytes handles typical ETag/Last-Modified values.
 */
#define BRIX_S3_CONDITIONAL_VAL_BUF  1024

/*
 * S3 multipart complete list parts line buffer (bytes).
 * Buffer size for parsing multipart upload part entries.
 * 1024 bytes handles typical XML part entry lines.
 */
#define BRIX_S3_MULTIPART_LIST_LINE_BUF  1024

/*
 * S3 ISO-8601 date parsing era constant.
 * Days per 400-year era in Gregorian calendar.
 * 146097 = exact days in 400 Gregorian years.
 */
#define BRIX_S3_ISO8601_ERA_DAYS  146097

/*
 * S3 ISO-8601 date parsing epoch anchor.
 * Day offset to align era calculation with Unix epoch.
 * 719468 = days from year 0 to Unix epoch (1970-01-01).
 */
#define BRIX_S3_ISO8601_EPOCH_ANCHOR  719468

/*
 * S3 post policy year minimum.
 * Minimum valid year for S3 post policy expiration dates.
 * 1970 = Unix epoch year (dates before are invalid).
 */
#define BRIX_S3_POST_POLICY_YEAR_MIN  1970

/*
 * S3 staging directory mode (octal).
 * Permission mode for S3 multipart upload staging directories.
 * 0700 ensures upload isolation between concurrent uploads.
 */
#define BRIX_S3_STAGING_DIR_MODE  0700

/*
 * S3 final temporary file mode (octal).
 * Permission mode for S3 final temporary files.
 * 0644 allows owner write, group/world read after completion.
 */
#define BRIX_S3_FINAL_TMP_MODE  0644

/*
 * S3 object file mode (octal).
 * Permission mode for completed S3 objects.
 * 0600 ensures only owner can access stored objects.
 */
#define BRIX_S3_OBJECT_MODE  0600

/*
 * S3 seconds per day constant.
 * Used in S3 expiration and lifecycle calculations.
 * 86400 = 24 * 60 * 60 seconds per day.
 */
#define BRIX_S3_SECS_PER_DAY  86400

/*
 * S3 seconds per hour constant.
 * Used in S3 timeout and expiration calculations.
 * 3600 = 60 * 60 seconds per hour.
 */
#define BRIX_S3_SECS_PER_HOUR  3600

/*
 * S3 seconds per week constant (7 days).
 * Used in S3 presigned URL expiration (max 7 days).
 * 604800 = 7 * 24 * 60 * 60 seconds.
 */
#define BRIX_S3_SECS_PER_WEEK  604800

/* ---- GFAL (Grid File Access Library) Constants ---- */

/*
 * GFAL GridFTP timeout default (milliseconds).
 * Default timeout for GFAL GridFTP operations.
 * 300000ms (5 minutes) balances reliability with responsiveness.
 */
#define BRIX_GFAL_GRIDFTP_TIMEOUT_DEFAULT_MS  300000

/*
 * GFAL buffer size (bytes).
 * Default buffer size for GFAL read/write operations.
 * 65536 bytes (64 KB) is efficient for GridFTP transfers.
 */
#define BRIX_GFAL_BUF_SIZE  65536

/*
 * GFAL path buffer size (bytes).
 * Buffer size for GFAL path operations.
 * 4096 bytes handles typical GridFTP path lengths.
 */
#define BRIX_GFAL_PATH_BUF  4096

/* ---- Common Permission Constants ---- */

/*
 * Permission mask for validation (octal).
 * Full permission mask for mode validation operations.
 * 07777 = all permission bits (user/group/other + setuid/setgid/sticky).
 */
#define BRIX_PERM_MASK_FULL  07777

/*
 * Private file permission mode (octal).
 * Most restrictive mode for private files.
 * 0600 = owner read/write only.
 */
#define BRIX_PERM_PRIVATE  0600

/*
 * Restricted directory permission mode (octal).
 * Restrictive mode for service-owned directories.
 * 0700 = owner read/write/execute only.
 */
#define BRIX_PERM_RESTRICTED  0700

/*
 * Standard directory permission mode (octal).
 * Typical mode for shared directories.
 * 0755 = owner rwx, group/other rx.
 */
#define BRIX_PERM_DIR_STANDARD  0755

/*
 * Standard file permission mode (octal).
 * Typical mode for shared files.
 * 0644 = owner rw, group/other r.
 */
#define BRIX_PERM_FILE_STANDARD  0644

/*
 * Additional permission modes for specific use cases.
 */
#define BRIX_PERM_OWNER_ONLY     0600  /* Private files (credentials, temp files) */
#define BRIX_PERM_GROUP_SHARED   0660  /* Group-readable files */
#define BRIX_PERM_DIR_PRIVATE    0700  /* Private directories (credential stores) */
#define BRIX_PERM_MASK_BASE      0777  /* Standard permission mask */

/*
 * Network port constants.
 */
#define BRIX_PORT_XROOTD_DEFAULT    1094  /* Default XRootD port */
#define BRIX_PORT_XROOTD_SECURE     1095  /* Secure XRootD port */
#define BRIX_PORT_HTTP_DEFAULT      80    /* Standard HTTP port */
#define BRIX_PORT_HTTPS_DEFAULT     443   /* Standard HTTPS port */
#define BRIX_PORT_HTTPS_ALT         8443  /* Alternative HTTPS port (WebDAV) */
#define BRIX_PORT_HTTP_ALT          8080  /* Alternative HTTP port */
#define BRIX_PORT_CVMFS_ALT         8000  /* Alternative CVMFS port */
#define BRIX_PORT_CMS_DEFAULT       1213  /* Default CMS management port */
#define BRIX_PORT_MAX               65535 /* Maximum valid port number */
#define BRIX_PORT_MIN               1     /* Minimum valid port number */

/*
 * Buffer size constants for network operations.
 */
#define BRIX_NET_HOST_BUF_SIZE      256   /* Hostname buffer size */
#define BRIX_NET_PATH_BUF_SIZE      1024  /* Network path buffer */
#define BRIX_NET_SMALL_BUF_SIZE     128   /* Small network buffer */
#define BRIX_NET_LARGE_BUF_SIZE     4096  /* Large network buffer */

/*
 * TAP protocol constants.
 * Used for XRootD TAP streaming protocol.
 */
#define BRIX_TAP_WRITEV_MAXSEGS       1024  /* Maximum writev segments */
#define BRIX_TAP_WRITEV_SEGSIZE       16    /* Segment size multiplier */
#define BRIX_TAP_WRITEV_MAX_PAYLOAD   (BRIX_TAP_WRITEV_MAXSEGS * BRIX_TAP_WRITEV_SEGSIZE)

/*
 * Timeout constants (milliseconds).
 */
#define BRIX_TIMEOUT_DEFAULT_MS         30000   /* Default 30-second timeout */
#define BRIX_TIMEOUT_SHORT_MS           5000    /* Short timeout (5 seconds) */
#define BRIX_TIMEOUT_LONG_MS            300000  /* Long timeout (5 minutes) */
#define BRIX_TIMEOUT_CONNECT_MS         10000   /* Connection timeout (10 seconds) */
#define BRIX_TIMEOUT_READ_MS            60000   /* Read timeout (60 seconds) */
#define BRIX_TIMEOUT_WRITE_MS           60000   /* Write timeout (60 seconds) */
#define BRIX_TIMEOUT_CMS_INTERVAL_MS    1000    /* CMS heartbeat interval (1 second) */

/*
 * Rate limiting constants.
 */
#define BRIX_RATE_MULTIPLIER        1000    /* Rate limit precision multiplier */
#define BRIX_RATE_PERCENT_DIVISOR   10000   /* Rate percentage calculation divisor */
#define BRIX_RATE_PERCENT_BASE      100     /* Percentage base (100%) */

/*
 * Protocol-specific constants.
 */
#define BRIX_PROTO_PAYLOAD_MAX      65535   /* Maximum protocol payload (uint16) */
#define BRIX_PROTO_FRAME_MAX        4096    /* Maximum CMS frame size */
#define BRIX_PROTO_MONITOR_MAX      1000    /* Maximum monitor value (percentage) */
#define BRIX_PROTO_AUTH_BODY_MAX    65536   /* Maximum auth body size */

/*
 * Timestamp and time-related constants.
 */
#define BRIX_TIME_MS_PER_SEC        1000    /* Milliseconds per second */
#define BRIX_TIME_US_PER_SEC        1000000 /* Microseconds per second */
#define BRIX_TIME_NS_PER_SEC        1000000000 /* Nanoseconds per second */
#define BRIX_TIME_SECS_PER_MIN      60      /* Seconds per minute */
#define BRIX_TIME_SECS_PER_HOUR     3600    /* Seconds per hour */
#define BRIX_TIME_SECS_PER_DAY      86400   /* Seconds per day */
#define BRIX_TIME_SECS_PER_WEEK     604800  /* Seconds per week */
#define BRIX_TIME_DAYS_PER_WEEK     7       /* Days per week */

/*
 * Filesystem and path constants.
 */
#define BRIX_FS_WALK_DEPTH_MAX      32      /* Maximum path walk depth */
#define BRIX_FS_OPEN_FILES_MAX      16      /* Max open files per connection */
#define BRIX_FS_STAGE_MODE_DEFAULT  0700    /* Default staging directory mode */
#define BRIX_FS_OBJECT_MODE_DEFAULT 0600    /* Default object file mode */
#define BRIX_FS_SCAN_MAX_DEPTH      1024    /* Maximum scan recursion depth */
#define BRIX_XFER_FD_DEFAULT_MAX    1024    /* Default xfer fd_max for spawn */

/*
 * Checkpoint and staging constants.
 */
#define BRIX_STAGE_EXT_LEN          4       /* Checkpoint extension length (".ckp") */
#define BRIX_STAGE_EXT_NUL          5       /* Checkpoint extension with null */
#define BRIX_STAGE_MODE             0600    /* Checkpoint file permissions */
#define BRIX_STAGE_SIZE_MAX         0xFFFFFFFF /* Maximum checkpoint size (UINT32_MAX) */

/*
 * Hex encoding constants.
 */
#define BRIX_HEX_BUF_SIZE_SMALL     64      /* Small hex buffer */
#define BRIX_HEX_BUF_SIZE_LARGE     256     /* Large hex buffer */

/*
 * Authentication and credential constants.
 */
#define BRIX_AUTH_ATTEMPTS_MAX      10      /* Maximum authentication attempts */
#define BRIX_AUTH_SKEW_SECS         30      /* Token clock skew tolerance */
#define BRIX_AUTH_TOKEN_MAX         65536   /* Maximum token size */
#define BRIX_AUTH_CERT_MODE         0600    /* Certificate file permissions */

/*
 * TPC (Third Party Copy) constants.
 */
#define BRIX_TPC_PREFIX_LEN         4       /* "tpc." prefix length */
#define BRIX_TPC_TOKEN_MAX          65536   /* Maximum TPC token size */
#define BRIX_TPC_TOKEN_ERR_MAX      256     /* TPC token error message buffer */
#define BRIX_TPC_MARKER_URL_MAX     4096    /* TPC marker URL buffer */

/*
 * S3-specific constants.
 */
#define BRIX_S3_PART_NUMBER_MAX     10000   /* Maximum S3 part number */
#define BRIX_S3_LIST_KEYS_MAX       1000    /* Maximum keys in list response */
#define BRIX_S3_LIST_ENTRY_MAX      65536   /* Maximum list walk entry size */
#define BRIX_S3_CONDITIONAL_VAL_MAX 1024    /* Conditional header value buffer */
#define BRIX_S3_MULTIPART_LINE_MAX  1024    /* Multipart list line buffer */
#define BRIX_S3_USERMETA_KV_MAX     2048    /* User metadata key-value buffer */
#define BRIX_S3_HANDLER_HOST_MAX    64      /* S3 handler host buffer */
#define BRIX_S3_HANDLER_PATH_MAX    1024    /* S3 handler path buffer */
#define BRIX_S3_HANDLER_CGI_MAX     512     /* S3 handler CGI buffer */
#define BRIX_S3_HANDLER_TMP_MAX     2048    /* S3 handler temp path buffer */
#define BRIX_S3_LIST_KEY_BUF_MAX    4096    /* S3 list walk key buffer */
#define BRIX_S3_POST_POLICY_YEAR_MIN 1970   /* Minimum policy year (Unix epoch) */
#define BRIX_S3_ISO8601_ERA_DAYS    146097  /* Days in 400-year Gregorian era */
#define BRIX_S3_ISO8601_EPOCH_ANCHOR 719468 /* Days from year 0 to Unix epoch */

/*
 * OCI-specific constants.
 */
#define BRIX_OCI_IO_CHUNK_SIZE      65536   /* OCI store I/O chunk size */
#define BRIX_OCI_PWFILE_MODE_MASK   07777   /* OCI password file mode mask */

/*
 * GFAL-specific constants.
 */
#define BRIX_GFAL_TIMEOUT_DEFAULT_MS 300000 /* GFAL GridFTP timeout (5 minutes) */
#define BRIX_GFAL_BUF_SIZE_DEFAULT   65536  /* GFAL buffer size */
#define BRIX_GFAL_PATH_BUF_SIZE      4096   /* GFAL path buffer */

/*
 * CMS-specific constants.
 */
#define BRIX_CMS_FRAME_MAX          4096    /* Maximum CMS frame payload */
#define BRIX_CMS_INTERVAL_DEFAULT   1000    /* CMS heartbeat interval (1 second) */
#define BRIX_CMS_CONN_MAX_DEFAULT   4096    /* Maximum CMS connections */
#define BRIX_CMS_CONN_PER_IP_MAX    256     /* Max connections per IP */
#define BRIX_CMS_LOGIN_TIMEOUT_MS   10000   /* CMS login timeout (10 seconds) */
#define BRIX_CMS_FSXEQ_TIMEOUT_MS   10000   /* CMS FS execute timeout */
#define BRIX_CMS_READ_TIMEOUT_MS    90000   /* CMS read timeout (90 seconds) */
#define BRIX_CMS_BLACKLIST_SEC_DEFAULT 86400 /* Default blacklist duration (24h) */

/*
 * Proxy-specific constants.
 */
#define BRIX_PROXY_CONNECT_TIMEOUT_MS 10000 /* Proxy connection timeout */
#define BRIX_PROXY_READ_TIMEOUT_MS    60000 /* Proxy read timeout */
#define BRIX_PROXY_WRITE_TIMEOUT_MS   60000 /* Proxy write timeout */
#define BRIX_PROXY_RETRY_BUF_MAX      131072 /* Proxy retry buffer (128 KB) */
#define BRIX_PROXY_AUDIT_BUF_SIZE     1024  /* Proxy audit buffer */
#define BRIX_PROXY_BEARER_MAX       65536   /* Proxy bearer token max */
#define BRIX_PROXY_UPSTREAM_BEARER_MAX 65536 /* Upstream bearer max */

/*
 * Dashboard and metrics constants.
 */
#define BRIX_DASHBOARD_LOGIN_PATH_MAX 256   /* Dashboard login path buffer */
#define BRIX_DASHBOARD_PAGE_BUF_MAX   4096  /* Dashboard page buffer */
#define BRIX_METRICS_TRACKING_BUF_MAX 1024  /* Metrics tracking buffer */

/*
 * Guard and security constants.
 */
#define BRIX_GUARD_TEST_IP_BUF      64      /* Guard test IP buffer */
#define BRIX_GUARD_TEST_PROTO_BUF   32      /* Guard test protocol buffer */
#define BRIX_GUARD_TEST_SIGNAL_BUF  64      /* Guard test signal buffer */
#define BRIX_GUARD_TEST_PATH_BUF    256     /* Guard test path buffer */

/*
 * URI encoding constants.
 */
#define BRIX_URI_UNRESERVED_CHARS   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
#define BRIX_URI_HEX_LOWER          "0123456789abcdef"
#define BRIX_URI_HEX_UPPER          "0123456789ABCDEF"
#define BRIX_URI_ENCODE_MULT        3       /* Worst-case encoding multiplier */

/*
 * Windows version build numbers.
 */
#define BRIX_WIN10_1809_BUILD       17763
#define BRIX_WIN10_2004_BUILD       19041
#define BRIX_WIN10_20H2_BUILD       19042
#define BRIX_WIN10_21H1_BUILD       19043
#define BRIX_WIN10_21H2_BUILD       19044
#define BRIX_WIN11_21H2_BUILD       22000
#define BRIX_WIN11_22H2_BUILD       22621
#define BRIX_WIN11_24H2_BUILD       26100
#define BRIX_WIN_SERVER_2022_BUILD  20348

/*
 * Collapsed redirect TTL (milliseconds).
 */
#define BRIX_COLLAPSE_REDIR_TTL_MS  30000   /* 30-second redirect cache TTL */

#endif /* BRIX_TYPES_TUNABLES_H */
