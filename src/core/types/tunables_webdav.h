/* WebDAV, HTTP transfer, and delegated credential limits.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

/*
 * WebDAV lock timeout default.
 * RFC 4918 recommends 1 hour as the default lock lifetime.  Clients may
 * request shorter or longer timeouts, but this is the default when not
 * specified.  Makes timeout configurable via future directive.
 */
#define BRIX_WEBDAV_LOCK_TIMEOUT_DEFAULT       3600

/*
 * WebDAV lock timeout maximum (seconds).
 * RFC 4918 recommends 1 hour as the default lock lifetime.  Clients may
 * request shorter or longer timeouts, but this is the maximum allowed.
 * Prevents clients from requesting excessively long locks that could block resources.
 */
#define BRIX_WEBDAV_LOCK_TIMEOUT_MAX           3600

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
