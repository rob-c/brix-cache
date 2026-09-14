/* S3 protocol, signing, multipart, and STS constants.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

/*
 * S3 operation timeout (milliseconds).
 * Default timeout for S3 API operations (PUT, GET, LIST, etc.).
 * 300 seconds (5 minutes) allows for multi-GB object transfers with retry.
 * Individual API calls (HEAD, LIST) complete much faster.
 */
#define BRIX_S3_TIMEOUT_DEFAULT_MS             300000

/*
 * Maximum S3 list objects max-keys parameter.
 * AWS S3 API maximum is 1000; this matches the service limit.
 * Pagination (continuation token) handles larger result sets.
 * Keeping at 1000 minimizes API calls while respecting service  (prevents throttling).
 */
#define BRIX_S3_LIST_MAX_KEYS                  1000

/*
 * STS credential lifetime bounds (AWS STS API constraints).
 * AssumeRole returns credentials valid for [900, 43200] seconds.
 * Values outside this range are clamped to the valid window.
 */
#define BRIX_S3_STS_MIN_LIFETIME_SECS          900     /* 15 minutes (AWS minimum) */
#define BRIX_S3_STS_MAX_LIFETIME_SECS          43200   /* 12 hours (AWS maximum) */

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
 * Scratch capacity for one percent-encoded SigV4 query name or value.
 * Preserves the canonicalizer's 1024-byte buffer; credential scopes exceed
 * the separate timestamp buffer even with ordinary short access keys.
 */
#define BRIX_S3_QUERY_ENCODE_BUF_SIZE      1024

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
 * S3 STS API version string.
 * Version parameter for STS AssumeRole requests.
 */
#define BRIX_S3_STS_VERSION  "2011-06-15"

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
