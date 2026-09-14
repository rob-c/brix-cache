/* DNS, proxy transport, network marking, and endpoint limits.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

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
 * Flow-id parsing fields and IPv6 flow-label masks.
 * The compact flow ID stores experiment and activity contiguously; packet
 * labels use the separate SciTags layout in brix_pmark_flowlabel_encode().
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

/*
 * Curl multi wait timeout (milliseconds).
 * Timeout for curl_multi_wait() in TPC curl integration.
 * 1000ms (1 second) balances responsiveness with efficiency.
 */
#define BRIX_CURL_MULTI_WAIT_TIMEOUT_MS  1000

/*
 * Default IANA CMS server port.
 * IANA-assigned port for CMS management (distinct from XRootD CMS).
 */
#define BRIX_IANA_CMS_DEFAULT_PORT  1213

/*
 * Maximum valid port number.
 * Upper bound for TCP/UDP port validation.
 */
#define BRIX_MAX_PORT_NUM  65535

/*
 * HTTP guard timestamp buffer size.
 * Buffer for ISO-8601 timestamp formatting.
 * Size: "YYYY-MM-DDThh:mm:ss+00:00" = 25 bytes + NUL.
 */
#define BRIX_HTTPGUARD_TS_BUF  26

/*
 * Network port constants.
 */
#define BRIX_PORT_ROOT_DEFAULT     1094  /* Default XRootD port */
#define BRIX_PORT_ROOT_SECURE      1095  /* Secure XRootD port */
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
 * Protocol-specific constants.
 */
#define BRIX_PROTO_PAYLOAD_MAX      65535   /* Maximum protocol payload (uint16) */
#define BRIX_PROTO_FRAME_MAX        4096    /* Maximum CMS frame size */
#define BRIX_PROTO_MONITOR_MAX      1000    /* Maximum monitor value (percentage) */
#define BRIX_PROTO_AUTH_BODY_MAX    65536   /* Maximum auth body size */

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
