# nginx-xrootd Protocol Unification Strategy
**Version:** 1.0
**Date:** June 5, 2026
**Status:** PROPOSAL

## 1. Introduction
The `nginx-xrootd` module supports two distinct protocol families: the binary XRootD stream protocol and the HTTP-based REST protocols (WebDAV, S3). Currently, these layers share low-level logic (like token validation) but maintain redundant implementations for high-level operations such as path resolution, I/O orchestration, and metric tracking.

This document outlines the strategy for "Deep Unification"—moving core logic into protocol-agnostic shared services to improve security, reduce technical debt, and ensure feature parity.

---

## 2. Core Unification Areas

### A. The "Universal" Path Resolver
Currently, the codebase has two primary path resolvers:
1.  **Stream Resolver (`src/path/resolve_path_variants.c`):** Integrated with `ngx_str_t`, handles `mkdirpath` logic, and logs via stream context.
2.  **HTTP/S3 Resolver (`src/compat/path.c`):** Pure C, handles `ENOENT` parent walking for PUT/COPY, and uses numeric return codes.

#### Proposed Architecture: `xrootd_path_v2`
A single resolver will be implemented in `src/path/unified.c` with the following signature:

```c
typedef struct {
    unsigned int allow_missing_tail:1; // For PUT/MKDIR
    unsigned int require_directory:1;  // For MKCOL/DIRLIST
    unsigned int skip_cache_check:1;   // For direct origin access
} xrootd_path_opts_t;

int xrootd_path_resolve(
    const char *root_canon,
    const char *req_path,
    xrootd_path_opts_t opts,
    char *resolved_out,
    size_t outsz
);
```

**Security Invariants:**
- **Double-Check Boundary:** `realpath()` followed by `strncmp()` against the root.
- **Component Sanitization:** Rejection of `\0`, `..`, and control characters *before* any syscall.
- **Depth Guard:** `xrootd_count_path_depth` to prevent CPU-exhaustion via deeply nested symbolic links.

---

### B. Identity and Authorization Unification
Identity state is currently fragmented across `xrootd_ctx_t` (Stream) and `ngx_http_xrootd_webdav_req_ctx_t` (HTTP).

#### Proposed Structure: `xrootd_identity_t`
```c
typedef struct {
    ngx_str_t  dn;             // GSI Distinguished Name
    ngx_str_t  subject;        // JWT 'sub' claim
    ngx_array_t *vo_list;      // Extracted VOMS/Groups
    ngx_array_t *scopes;       // Token write/read scopes
    unsigned int is_authenticated:1;
    unsigned int is_admin:1;
} xrootd_identity_t;
```

**Workflow Unification:**
1.  **Auth Phase:** Extract credentials (Cert/Token) and populate `xrootd_identity_t`.
2.  **Policy Phase:** Pass the identity object to `xrootd_check_vo_acl()` or `xrootd_check_authdb()`.
3.  **Result:** Authorization logic becomes 100% protocol-neutral.

---

### C. Unified VFS & I/O Orchestration
The most significant duplication exists in the I/O path. Both `src/read/read.c` and `src/webdav/get.c` independently handle:
- Read-through cache lookups.
- AIO thread-pool dispatching.
- dashboard transfer slot updates.

#### The I/O Hook Pattern
Instead of each protocol calling `pread()` or `sendfile()` directly, they should use a shared I/O dispatcher:

```mermaid
graph TD
    A[Stream: kXR_read] --> D[Shared VFS Layer]
    B[WebDAV: GET] --> D
    C[S3: GetObject] --> D
    D --> E{In Cache?}
    E -- Yes --> F[Read from Cache Root]
    E -- No --> G[Read from Origin Root]
    F --> H[Update Dashboard & Metrics]
    G --> H
    H --> I[Dispatch to AIO Threadpool]
```

---

## 3. Metric & Logging Consistency
Currently, metrics are siloed (e.g., `webdav.bytes_tx` vs `stream.bytes_tx`). 

### Proposed Unified Metric Slots
We will move to an **Op-Centric** metric model rather than a **Protocol-Centric** one.
- `xrootd_io_bytes_read` (Labeled by: `proto=[stream|webdav|s3]`)
- `xrootd_io_ops_total` (Labeled by: `op=[read|write|stat|delete]`)

This allows for a single Prometheus query to show the total throughput of the server regardless of protocol.

---

## 4. Implementation Phasing

### Phase 1: Resolver Consolidation (Week 1)
- Move `src/compat/path.c` logic into `src/path/`.
- Replace all protocol-specific resolution calls with the unified resolver.
- **Validation:** Cross-protocol test suite (`tests/run_cross_compatible_tests.sh`).

### Phase 2: Identity Abstraction (Week 2)
- Create `src/types/identity.h`.
- Refactor `src/token/` and `src/gsi/` to return the new identity struct.
- Update `src/path/acl.c` to consume identity objects.

### Phase 3: VFS Hooking (Week 3)
- Extract common I/O logic from `read.c` and `get.c`.
- Implement `src/fs/io_engine.c`.
- Ensure dashboard updates are triggered automatically by the engine.

---

## 5. Risk Assessment
| Risk | Mitigation |
|:---|:---|
| **Performance Overhead** | Use `ngx_inline` for shared helpers and avoid extra memory copies. |
| **Regression in Security** | Maintain a "Golden Test Set" of known traversal attacks that must pass before any merge. |
| **Protocol Specifics** | Keep the "Wire-to-Internal" mapping thin but separate (e.g., kXR_open flags vs HTTP Range). |

---

## 6. Conclusion
Unifying the `nginx-xrootd` architecture will transform the module from a collection of protocol handlers into a **High-Performance Filesystem Gateway**. By centralizing the path, auth, and I/O layers, we reduce the surface area for bugs and prepare the codebase for future features like `io_uring` and advanced erasure-coding backends.
