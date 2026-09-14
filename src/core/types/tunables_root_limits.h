/* ROOT handler capacities, timeouts, and file-operation limits.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

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
 * Maximum macaroon path caveats.
 * Prevents path traversal attack via excessive caveat chains.
 * 8 allows reasonable delegation depth while bounding verification cost.
 */
#define BRIX_ROOT_MACAROON_PATH_CAVEATS_MAX  8
