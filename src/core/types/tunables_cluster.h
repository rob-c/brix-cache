/* CMS, registry, monitoring, and cluster control defaults.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

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
 * CMS read timeout maximum (milliseconds).
 * Maximum time to wait for CMS manager answer before fallback.
 * 90 seconds is the floor — allows for slow storage + network latency.
 * Exceeding this suggests a hung backend or network partition.
 */
#define BRIX_CMS_READ_TIMEOUT_MAX_MS           90000

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
 * Rate limit unit scale factor.
 * Rate limits stored ×1000 for sub-millisecond precision.
 */
#define BRIX_RATE_LIMIT_SCALE  1000

/*
 * Registry selection weight divisor.
 * Divisor for weighted metric calculations.
 */
#define BRIX_REGISTRY_WEIGHT_DIVISOR  10000

/*
 * Maximum CMS frame payload size.
 * Maximum payload for CMS frame operations.
 */
#define BRIX_CMS_MAX_FRAME_PAYLOAD  4096

/*
 * Maximum valid monitor value.
 * Monitor values are percentages; >1000 indicates garbled input.
 */
#define BRIX_MONITOR_VALUE_MAX  1000

/*
 * Maximum CMS connections per server.
 * Default cap on accepted CMS connections.
 */
#define BRIX_CMS_MAX_CONNECTIONS_DEFAULT  4096

/*
 * Default advertisement interval (milliseconds).
 * Interval for server advertisement broadcasts.
 * 60000ms = 1 minute.
 */
#define BRIX_ADVERTISE_INTERVAL_DEFAULT_MS  60000

/*
 * Default redirection TTL (milliseconds).
 * Time-to-live for cached redirections.
 * 30000ms = 30 seconds.
 */
#define BRIX_REDIR_TTL_DEFAULT_MS  30000

/*
 * Occupancy calculation precision multiplier.
 * Used for precise occupancy percentage calculations.
 */
#define BRIX_OCCUPANCY_PRECISION  1000000

/*
 * Rate limiting constants.
 */
#define BRIX_RATE_MULTIPLIER        1000    /* Rate limit precision multiplier */
#define BRIX_RATE_PERCENT_DIVISOR   10000   /* Rate percentage calculation divisor */
#define BRIX_RATE_PERCENT_BASE      100     /* Percentage base (100%) */

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
 * Collapsed redirect TTL (milliseconds).
 */
#define BRIX_COLLAPSE_REDIR_TTL_MS  30000   /* 30-second redirect cache TTL */
