# nginx-xrootd Logical Pathways: Tier 1 & Tier 2

This document maps the architectural pathways within the `nginx-xrootd` module, categorizing them into **Tier 1** (Core Data & Security) and **Tier 2** (Clustering & Advanced Features).

```text
   TCP connect
        │
  ╔═════▼═══════════════ TIER 1: every single-node data server needs this ══════╗
  ║  handshake ─▶ protocol ─▶ login ─▶ AUTH ─▶ open ─▶ read/write/stat ─▶ close  ║
  ║  handler.c    protocol.c  login.c  gsi/    open.c   read.c            close.c ║
  ║                                    token/  │ authdb path check               ║
  ║                                    sss/    └─▶ resolve_path → confined fd     ║
  ╚════════════════════════════════════════╤═══════════════════════════════════╝
                                           │  layered on top, opt-in
  ╔════════════════════════════════════════▼═══════ TIER 2: cluster + advanced ══╗
  ║  CLUSTERING        TPC              ADVANCED I/O        MULTI-PROTOCOL        ║
  ║  cms heartbeat     native key-reg   aio thread pool     WebDAV  GET/PUT/      ║
  ║  locate/redirect   webdav curl      pgread/pgwrite CRC  s3/     PROPFIND      ║
  ║  manager mode      pull/push        readv/writev        SigV4   →  same VFS   ║
  ╚══════════════════════════════════════════════════════════════════════════════╝
        all file byte I/O converges on the VFS → POSIX data plane (src/fs/)
```

---

## 1. Tier 1 Pathways: Core Data & Security
These pathways represent the foundational functionality required for a single-node data server. They handle the essential "root://" protocol lifecycle.

### A. Handshake & Session Lifecycle
- **Entry Point**: `src/connection/handler.c`
- **Logic Flow**:
  1. `xrootd_conn_handshake_handler`: Detects protocol magic (ROOTD_PQ).
  2. `xrootd_handle_protocol`: Negotiates version and capability flags (`src/session/protocol.c`).
  3. `xrootd_handle_login`: Initial client identification (`src/session/login.c`).
  4. `xrootd_handle_endsess`: Graceful termination (`src/session/lifecycle.c`).

### B. Authentication & Authorization
- **Logic Flow**:
  1. `xrootd_handle_auth`: Dispatches to specific security plugins.
  2. **Plugins**:
     - **GSI**: X.509 proxy validation (`src/gsi/`).
     - **Token**: JWT/WLCG bearer token validation (`src/token/`).
     - **SSS**: Shared-secret authentication (`src/sss/`).
  3. `xrootd_check_authdb`: Verifies file-path permissions against `authdb` rules (`src/path/authdb.c`).

### C. Basic File I/O
- **Entry Point**: `src/handshake/dispatch_read.c` / `dispatch_write.c`
- **Logic Flow**:
  1. `xrootd_handle_open`: Resolves logical paths to physical paths using `xrootd_resolve_path`.
  2. `xrootd_handle_read` / `xrootd_handle_write`: Standard POSIX-backed I/O.
  3. `xrootd_handle_stat`: Metadata retrieval.
  4. `xrootd_handle_close`: Releases file handles and flushes caches.

---

## 2. Tier 2 Pathways: Clustering & Advanced Features
These pathways provide interoperability with larger XRootD clusters and optimize performance for high-throughput environments.

### A. Clustering & Redirection (CMS)
- **Logic Flow**:
  1. `src/cms/send.c`: Heartbeat and free-space reporting to a manager node.
  2. `xrootd_handle_locate`: Redirects clients to the actual data node (`src/read/locate.c`).
  3. `xrootd_manager_mode`: Toggles logic between a data server and a redirector.

### B. Third-Party Copy (TPC)
- **Logic Flow**:
  1. `src/tpc/launch.c`: Initiates a transfer between two remote servers.
  2. `src/tpc/key_registry.c`: Manages SHM-based authorization keys for native XRootD TPC.
  3. `src/webdav/tpc.c`: Handles HTTP-based TPC pull/push using libcurl.

### C. Advanced I/O (AIO & Page-based)
- **Logic Flow**:
  1. `src/aio/`: Offloads blocking I/O to nginx thread pools.
  2. `src/read/pgread.c` / `src/write/pgwrite.c`: Handles page-aligned transfers with in-wire CRC32c checksumming for data integrity.
  3. `src/read/readv.c` / `src/write/writev.c`: Vectorized I/O for scatter/gather operations.

### D. Multi-Protocol Gateway (WebDAV & S3)
- **Logic Flow**:
  1. `src/webdav/dispatch.c`: Maps HTTP methods (GET, PUT, PROPFIND) to XRootD filesystem operations.
  2. `src/s3/handler.c`: Implements S3 SigV4 authentication and bucket/object listing.

---

## Summary Mapping
| Feature | Tier | Main Files |
|---|---|---|
| Handshake/Login | 1 | `session/protocol.c`, `session/login.c` |
| GSI/Token Auth | 1 | `gsi/`, `token/`, `path/authdb.c` |
| Open/Read/Write | 1 | `read/open.c`, `read/read.c`, `write/write.c` |
| CMS Heartbeat | 2 | `cms/send.c`, `cms/recv.c` |
| Redirection | 2 | `read/locate.c`, `upstream/` |
| Native TPC | 2 | `tpc/key_registry.c`, `tpc/launch.c` |
| AIO / Page I/O | 2 | `aio/`, `read/pgread.c`, `write/pgwrite.c` |
| WebDAV/S3 | 2 | `webdav/`, `s3/` |
