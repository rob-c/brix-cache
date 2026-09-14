/* OCI registry, upload, and image-store limits.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

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

/*
 * OCI mirror KV value size (bytes).
 * Value size for mirror location KV store.
 * 4096 bytes accommodates mirror metadata.
 */
#define BRIX_OCI_MIRROR_KV_VAL_SIZE  4096

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

/*
 * OCI-specific constants.
 */
#define BRIX_OCI_IO_CHUNK_SIZE      65536   /* OCI store I/O chunk size */
#define BRIX_OCI_PWFILE_MODE_MASK   07777   /* OCI password file mode mask */
