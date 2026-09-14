/* Configuration parser capacities and merged runtime defaults.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

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
