/* Filesystem, cache, staging, and storage-backend limits.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

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
 * Staged file default mode.
 * Mode for staged files before commit.
 * 0600 = owner rw only (private during staging).
 */
#define BRIX_STAGE_FILE_MODE  0600

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
 * GFAL-specific constants.
 */
#define BRIX_GFAL_TIMEOUT_DEFAULT_MS 300000 /* GFAL GridFTP timeout (5 minutes) */
#define BRIX_GFAL_BUF_SIZE_DEFAULT   65536  /* GFAL buffer size */
#define BRIX_GFAL_PATH_BUF_SIZE      4096   /* GFAL path buffer */
