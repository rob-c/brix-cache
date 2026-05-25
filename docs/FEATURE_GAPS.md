# nginx-xrootd Feature Gap Analysis

This document identifies incomplete features, missing corner cases, and areas requiring completion across the supported protocols (XRootD Stream, WebDAV, S3) in the `nginx-xrootd` module.

## 1. XRootD Stream Protocol

### Incomplete Features
- **Authenticated TPC Sources**: `src/tpc/bootstrap.c` identifies that authenticated source fetch/delegation is not implemented for TPC (Transfer Protocol Client). Currently, only anonymous sources are supported during the handshake frame setup.
- **Checkpoint sub-opcode implementation**: While the main `kXR_chkpoint` opcode and core sub-opcodes (begin, commit, rollback, query) are implemented and tested, complex transactional scenarios involving multiple concurrent checkpoints or recovery from partially failed checkpoints may need further hardening.

### Missing Corner Cases
- **Checkpoint Error Paths**: Validation of behavior when a checkpoint is held open across session disconnects or server restarts.

## 2. WebDAV Protocol

### Implementation Status
- **Completed - MKCOL and DELETE Native Integration**: `MKCOL` and `DELETE` are handled by native WebDAV namespace code instead of delegating to the built-in `ngx_http_dav_module`, preserving module-specific lock checks, metrics, and logging.
- **Completed - Advanced WebDAV Discovery Methods**: `SEARCH` now supports a basic RFC 5323 `DAV:basicsearch` flow for scoped namespace discovery. `ACL` discovery properties are exposed through `PROPFIND`; direct ACL mutation is rejected with a protected-property error because filesystem ACL authoring is not currently part of the module's authorization model.
- **Completed - Dead Property Storage**: `PROPPATCH` stores non-`DAV:` dead properties in `user.nginx_xrootd.webdav.*` extended attributes, rejects protected live `DAV:` properties per-property, and returns persisted dead properties from `PROPFIND`.
- **Completed - Large Collection Operation Offload**: Recursive collection `COPY` and collection `MOVE` are posted to the configured nginx thread pool so directory traversal, recursive copy, destination tree replacement, and confined rename work do not block the event-loop worker. If no thread pool is configured, handlers retain the synchronous fallback path.

### Missing Corner Cases
- No open WebDAV Section 2 corner cases are currently tracked in this document.

## 3. S3 Protocol

### Incomplete Features
- **OPTIONS Support**: `src/s3/operation_table.c` notes that `OPTIONS` support is missing. S3 clients sometimes use `OPTIONS` for CORS pre-flight checks.
- **Batch Operations**: While `DeleteObjects` (multi-object delete) is referenced and a file `src/s3/delete_objects.c` exists, its integration in the main handler needs validation for complex error reporting.
- **POST Object (Browser Uploads)**: Support for S3 `POST` (form-based uploads) is minimal compared to the `PUT` implementation.

### Missing Corner Cases
- **Signature Version 4 (SigV4) Clock Skew**: Behavior when the client's clock is significantly skewed from the server's.

## 4. Security & Infrastructure

### Incomplete Features
- **HTTPS OCSP Responders**: `src/crypto/ocsp.c` explicitly states that HTTPS responders are not supported in the synchronous path. OCSP checks for certificates using HTTPS-only responders will currently fail (or rely on `soft_fail`).

---

## Implementation Proposal: S3 OPTIONS Support

### Goal
Implement the `OPTIONS` method for the S3 protocol to support CORS pre-flight requests and feature discovery.

### Implementation Strategy
1.  **Operation Table**: Add `"OPTIONS"` to the `xrootd_s3_operations` table in `src/s3/operation_table.c`.
2.  **Handler**: Update `ngx_http_s3_handler` in `src/s3/handler.c` to catch `NGX_HTTP_OPTIONS`.
3.  **Response**: Implement a standard S3 `OPTIONS` response that returns the `Allow` header and appropriate CORS headers (using `webdav_add_cors_headers` helper if compatible).

### Testing Plan
- **Test Case**: Send an `OPTIONS` request to an S3 bucket URL.
- **Verification**: Ensure the response is `200 OK` and contains the `Allow: GET, HEAD, PUT, DELETE, POST, OPTIONS` header.
- **Tools**: Use `curl -X OPTIONS -i <s3_url>`.

## Completed: WebDAV Native MKCOL/DELETE Integration

### Goal
Replace `ngx_http_dav_module` delegation for `MKCOL` and `DELETE` with native implementations to improve metric accuracy, preserve module lock checks, and reduce external dependencies.

### Implemented
1.  **Dispatch**: `src/webdav/dispatch.c` routes `MKCOL` and `DELETE` to native handlers.
2.  **Handlers**: `src/webdav/namespace.c` owns native namespace operations using confined path resolution and lock checks.
3.  **Shared Copy Metadata**: `src/compat/namespace_ops.c` preserves XRootD-mapped `user.U.*` extended attributes when WebDAV COPY requests metadata preservation.

### Test Coverage
- **Test Case**: Execute `MKCOL` on a non-existent path.
- **Verification**: Directory creation returns `201 Created`; duplicate resources return `405 Method Not Allowed`; `DELETE` preserves lock semantics and empty-directory behavior.
