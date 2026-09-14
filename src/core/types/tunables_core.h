/* Common buffers, numeric conversions, permissions, and encoding constants.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

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
 * Cache lock timeout (seconds).
 * Stampede prevention: maximum time a cache fill lock is held.
 * 300 seconds (5 minutes) allows slow fills while preventing deadlocks.
 */
#define BRIX_CACHE_LOCK_TIMEOUT_DEFAULT_SEC    300

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

/*
 * Unix permission mask for chmod/fchmod operations.
 * Masks off the high 4 bits (setuid/setgid/sticky) to get low 12 bits.
 * Used in brix_apply_child_mode() to extract permission bits from mode_t.
 * Octal 07777 = binary 111 111 111 111 (12 bits for rwxrwxrwx+sticky).
 */
#define BRIX_PERM_MASK                         07777

/*
 * Standard Unix file permission modes.
 * These constants ensure consistent permission usage across the codebase.
 */
#define BRIX_PERM_PRIVATE                      0600  /* Owner read/write only (credentials, keys) */
#define BRIX_PERM_RESTRICTED                   0700  /* Owner full access (private directories) */
#define BRIX_PERM_FILE_DEFAULT                 0644  /* Owner rw, others r (public files) */
#define BRIX_PERM_DIR_DEFAULT                  0755  /* Owner rwx, others rx (public dirs) */
#define BRIX_PERM_EXEC_DEFAULT                 0755  /* Executable files */

/*
 * PPM (parts per million) multiplier for occupancy/ratio calculations.
 * Used in cache eviction, filesystem usage, and metric calculations.
 * 1000000 = 1,000,000 = 10^6 (1 million parts)
 */
#define BRIX_PPM_MULTIPLIER                    1000000

/*
 * Milliseconds per second.
 * Used for time conversion in dashboard, metrics, and timeout calculations.
 */
#define BRIX_MSEC_PER_SEC                      1000

/*
 * Permission and special bits mask (octal).
 * Masks file mode to show only permission bits (rwx) and special bits
 * (setuid, setgid, sticky). Used in policy enforcement and logging.
 * 07777 = 07000 (special) | 00777 (permission)
 */
#define BRIX_PERM_MASK                         07777

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

/*
 * Nanoseconds per second.
 * Conversion factor for time calculations.
 */
#define BRIX_NSEC_PER_SEC  1000000000ULL

/*
 * Adler-32 modulus.
 * Modulus used in Adler-32 checksum calculation.
 */
#define BRIX_ADLER_MOD  65521

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

/*
 * Nginx version threshold for directive flags.
 * NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1234 available in newer versions.
 */
#define BRIX_NGINX_STREAM_CONF_VERSION  1023000

/*
 * Seconds per day.
 * Used in S3 backend date calculations.
 */
#define BRIX_SECS_PER_DAY  86400

/*
 * ISO-8601 timestamp buffer size.
 * Buffer size for full ISO-8601 timestamp with milliseconds.
 * Format: "YYYY-MM-DDThh:mm:ss.mmmZ" = 24 bytes + NUL.
 */
#define BRIX_ISO8601_BUF_SIZE  25

/*
 * Unix epoch year offset.
 * Adjustment for tm_year to calendar year.
 */
#define BRIX_UNIX_EPOCH_YEAR  1900

/*
 * Base64url encoding alphabet.
 * Standard RFC 4648 base64url character set.
 */
#define BRIX_BASE64URL_ALPHABET  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

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

/*
 * URI unreserved characters.
 * RFC 3986 unreserved character set for URI encoding.
 */
#define BRIX_URI_UNRESERVED  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

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
 * Hex encoding constants.
 */
#define BRIX_HEX_BUF_SIZE_SMALL     64      /* Small hex buffer */
#define BRIX_HEX_BUF_SIZE_LARGE     256     /* Large hex buffer */

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
