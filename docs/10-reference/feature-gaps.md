# gnuBall Feature Gap Analysis

This document identifies incomplete features, missing corner cases, and areas requiring completion across the supported protocols (XRootD Stream, WebDAV, S3) in the `nginx-xrootd` module.

## 1. XRootD Stream Protocol

### Implementation Status
- **Authenticated TPC Sources**: Destination-side TPC can now use configured bearer-file credentials, GSI credentials, or delegated OAuth2/OIDC tokens (`tpc.token_mode=oidc-agent` / `token-exchange`) during outbound source authentication. The ZTN selection path treats an already-fetched delegated token as a usable credential, so delegation-only configurations do not require a static bearer file.
- **Checkpoint sub-opcode implementation**: The main `kXR_chkpoint` opcode and core sub-opcodes (begin, commit, rollback, query, and `ckpXeq`) are implemented and tested. Same-file concurrent checkpoints are rejected by exclusive `.ckp` snapshot creation.
- **Checkpoint Restart Recovery**: Worker startup scans configured export roots for abandoned `<path>.ckp` snapshots under a root-local recovery lock. Stale snapshots are restored to their original path and then removed, preserving rollback semantics for interrupted checkpoint transactions.

### Missing Corner Cases
- No open XRootD Stream Section 1 checkpoint corner cases are currently tracked in this document.

## 2. WebDAV Protocol

### Implementation Status
- **Completed - MKCOL and DELETE Native Integration**: `MKCOL` and `DELETE` are handled by native WebDAV namespace code instead of delegating to the built-in `ngx_http_dav_module`, preserving module-specific lock checks, metrics, and logging.
- **Completed - Advanced WebDAV Discovery Methods**: `SEARCH` now supports a basic RFC 5323 `DAV:basicsearch` flow for scoped namespace discovery. `ACL` discovery properties are exposed through `PROPFIND`; direct ACL mutation is rejected with a protected-property error because filesystem ACL authoring is not currently part of the module's authorization model.
- **Completed - Dead Property Storage**: `PROPPATCH` stores non-`DAV:` dead properties in `user.nginx_xrootd.webdav.*` extended attributes, rejects protected live `DAV:` properties per-property, and returns persisted dead properties from `PROPFIND`.
- **Completed - Large Collection Operation Offload**: Recursive collection `COPY` and collection `MOVE` are posted to the configured nginx thread pool so directory traversal, recursive copy, destination tree replacement, and confined rename work do not block the event-loop worker. If no thread pool is configured, handlers retain the synchronous fallback path.

### Missing Corner Cases
- No open WebDAV Section 2 corner cases are currently tracked in this document.

## 3. S3 Protocol

### Implementation Status
- **OPTIONS Support**: Implemented for S3, including the operation table, `Allow` response, unauthenticated browser preflight handling, and fixed-method metrics.
- **Batch Operations**: `DeleteObjects` is integrated in the main handler and parses the XML request body with libxml2, including entity-decoded keys, per-object XML-escaped results, path traversal reporting, and malformed XML errors.
- **Signature Version 4 (SigV4) Clock Skew**: Implemented for header-auth requests with a 15-minute skew window and for presigned URLs whose request timestamp is too far in the future.
- **POST Object (Browser Uploads)**: Implemented for browser-style `multipart/form-data` uploads to `POST /<bucket>/`, including key/file extraction, `${filename}` expansion, anonymous writable buckets, SigV4 POST policy verification for configured credentials, policy condition checks, staged confined object writes, and `200`/`201`/`204`/redirect success responses.

### Missing Corner Cases
- No open S3 clock-skew, batch-delete, or POST Object corner cases are currently tracked in this document.

## 4. Security & Infrastructure

### Implementation Status
- **HTTPS OCSP Responders**: `src/auth/crypto/ocsp.c` supports HTTPS OCSP responder URLs by wrapping the responder connection in an OpenSSL TLS client context, enabling default trust-store verification, SNI, and hostname verification before sending the OCSP request.

### Missing Corner Cases
- No open Security & Infrastructure Section 4 corner cases are currently tracked in this document.

---

## Completed: S3 OPTIONS Support

### Goal
Implement the `OPTIONS` method for the S3 protocol to support CORS pre-flight requests and feature discovery.

### Implemented
1.  **Operation Table**: Add `"OPTIONS"` to the `xrootd_s3_operations` table in `src/protocols/s3/operation_table.c`.
2.  **Handler**: Update `ngx_http_s3_handler` in `src/protocols/s3/handler.c` to catch `NGX_HTTP_OPTIONS`.
3.  **Response**: Return `200 OK`, `Allow`, and browser preflight CORS headers before SigV4 authentication.
4.  **Metrics**: Track `OPTIONS` in a fixed low-cardinality S3 method bucket.

### Test Coverage
- **Test Case**: Send `OPTIONS` and CORS preflight requests to an S3 bucket URL.
- **Verification**: Ensure the response is `200 OK`, includes `Allow: GET, HEAD, PUT, DELETE, POST, OPTIONS`, and echoes safe preflight request headers.

## Completed: WebDAV Native MKCOL/DELETE Integration

### Goal
Replace `ngx_http_dav_module` delegation for `MKCOL` and `DELETE` with native implementations to improve metric accuracy, preserve module lock checks, and reduce external dependencies.

### Implemented
1.  **Dispatch**: `src/protocols/webdav/dispatch.c` routes `MKCOL` and `DELETE` to native handlers.
2.  **Handlers**: `src/protocols/webdav/namespace.c` owns native namespace operations using confined path resolution and lock checks.
3.  **Shared Copy Metadata**: `src/core/compat/namespace_ops.c` preserves XRootD-mapped `user.U.*` extended attributes when WebDAV COPY requests metadata preservation.

### Test Coverage
- **Test Case**: Execute `MKCOL` on a non-existent path.
- **Verification**: Directory creation returns `201 Created`; duplicate resources return `405 Method Not Allowed`; `DELETE` preserves lock semantics and empty-directory behavior.
