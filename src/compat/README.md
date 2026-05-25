# compat — Cross-backend compatibility helpers

Provides shared utilities used by both the native XRootD stream path and the WebDAV/HTTP paths to ensure consistent behaviour across deployment modes. Every file in this directory is a standalone helper — no module-level state, no nginx-specific dependencies beyond `ngx_str_t` allocation.

| File | Responsibility |
|---|---|
| `async_job.c` | Generic async job submission and completion tracking via nginx thread pool |
| `async_job.h` | Async job types and prototypes |
| `checksum.c` | Checksum computation: CRC32c, MD5 for file integrity verification |
| `checksum.h` | Checksum types and prototypes |
| `copy_range.c` | `copy_file_range` wrapper with fallback to read/write loop |
| `copy_range.h` | Copy-range types and prototypes |
| `cors.c` | CORS header generation for WebDAV cross-origin requests |
| `cors.h` | CORS helper types and prototypes |
| `crc32c.c` | CRC32c polynomial computation and checksum calculation |
| `crc32c.h` | CRC32c types and prototypes |
| `crypto.c` | Shared crypto operations: HMAC-SHA256 for GSI sigver, random nonce generation |
| `crypto.h` | Crypto helper types and prototypes |
| `etag.c` | ETag computation from file metadata (size + mtime) |
| `etag.h` | ETag types and prototypes |
| `fs_usage.c` | Filesystem usage queries: disk space, inode counts via statvfs |
| `fs_usage.h` | FS-usage types and prototypes |
| `fs_walk.c` | Directory traversal for dirlist and S3 ListObjectsV2 |
| `fs_walk.h` | FS-walk types and prototypes |
| `hex.c` | Hexadecimal encoding/decoding for wire protocol byte representation |
| `hex.h` | Hex helper types and prototypes |
| `http_body.c` | HTTP response body building: chunked, content-length, streaming |
| `http_body.h` | HTTP-body types and prototypes |
| `http_conditionals.c` | HTTP conditional request handling: If-Match, If-None-Match, If-Modified-Since |
| `http_conditionals.h` | Conditional-request types and prototypes |
| `error_mapping.c` | Unified error mapping: errno→kXR-code, errno→HTTP-status, kXR_status→HTTP-status across protocol paths |
| `error_mapping.h` | Error-mapping types and prototypes (replaces http_errno.h + kxr_errno.h + result_mapper.h) |
| `http_file_response.c` | File response construction: headers, body chain, sendfile path |
| `http_file_response.h` | File-response types and prototypes |
| `http_headers.c` | HTTP header building and manipulation for all protocol paths |
| `http_headers.h` | Header helper types and prototypes |
| `http_query.c` | URL query string parsing and parameter extraction |
| `http_query.h` | Query-string types and prototypes |
| `http_xml.c` | XML response generation for S3 ListObjectsV2 and WebDAV PROPFIND |
| `http_xml.h` | XML helper types and prototypes |
| `integrity_info.c` | File integrity metadata: checksum, size, mtime extraction |
| `integrity_info.h` | Integrity-info types and prototypes |
| `io.c` | Shared I/O helpers: read/write loops, buffer management across protocols |
| `io.h` | IO helper types and prototypes |
| `kxr_errno.c` | errno-to-kXR-code mapping (ENOENT→kXR_NotFound, EACCES→kXR_NotAuthorized) |
| `kxr_errno.h` | kXR-errno-mapping types and prototypes |
| `log.c` | Structured access logging: format, write, sanitize for all protocol paths |
| `log.h` | Logging helper types and prototypes |
| `namespace_ops.c` | Namespace operations: mkdir, rename, delete across POSIX filesystem |
| `namespace_ops.h` | Namespace-ops types and prototypes |
| `net_target.c` | Network target resolution: hostname → IP for upstream connections |
| `net_target.h` | Net-target types and prototypes |
| `path.c` | Path manipulation: canonicalization, confinement checks, basename extraction |
| `path.h` | Path helper types and prototypes |
| `protocol_caps.c` | Protocol capability negotiation: what opcodes a server supports |
| `protocol_caps.h` | Protocol-caps types and prototypes |
| `range.c` | HTTP Range header parsing and byte-range validation |
| `range.h` | Range types and prototypes |
| `range_vector.c` | Multiple range parsing (bytes=0-10,20-30) and range-vector operations |
| `range_vector.h` | Range-vector types and prototypes |
| `result_mapper.c` | Response result mapping: kXR_status → HTTP status across protocol paths |
| `result_mapper.h` | Result-mapper types and prototypes |
| `shm_slots.h` | Shared-memory slot definitions for TPC key registry |
| `staged_file.c` | Staged file operations: `.part` creation, atomic rename to final name |
| `staged_file.h` | Staged-file types and prototypes |
| `time.c` | Time utilities: epoch conversion, mtime formatting for HTTP headers |
| `time.h` | Time helper types and prototypes |
| `tmp_path.c` | Temporary path generation for staged writes and cache fills |
| `tmp_path.h` | Temp-path types and prototypes |
| `uri.c` | URI parsing: scheme extraction, host/path splitting for proxy mode |
| `uri.h` | URI helper types and prototypes |
| `xml.c` | XML encoding helpers: escaping, element building for S3/WebDAV responses |
| `xml.h` | XML helper types and prototypes |
