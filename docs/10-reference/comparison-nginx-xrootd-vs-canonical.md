# nginx-xrootd vs Canonical XRootD — Feature Comparison

**Date:** 2026-05-25 (updated 2026-06-14 to correct source-verified implementation-state mismatches)
**Source:** `/home/rcurrie/HEP-x/nginx-xrootd` (nginx module) vs `/tmp/xrootd-src` (official XRootD source)

> **Current reviewer note:** this is a compact comparison. For the authoritative
> source-verified matrix, including file-level evidence and stale-claim
> corrections, use
> [source-verified-xrootd-comparison.md](source-verified-xrootd-comparison.md).

---

## 1. Opcode Coverage

### 1.1 Request Opcodes (kXR_* = 3000–3032)

| Opcode | Name | Canonical | nginx-xrootd | Status |
|---|---|---|---|---|
| kXR_auth=3000 | Authentication | ✓ | ✓ | Implemented (GSI, token, SSS) |
| kXR_query=3001 | Server/file query | ✓ | ✓ | Implemented |
| kXR_chmod=3002 | Change permissions | ✓ | ✓ | Implemented |
| kXR_close=3003 | Close file handle | ✓ | ✓ | Implemented |
| kXR_dirlist=3004 | Directory listing | ✓ | ✓ | Implemented |
| kXR_gpfile=3005 | Get/put file (legacy) | ✓ | Declared | **Not implemented** — legacy unused opcode |
| kXR_protocol=3006 | Capability negotiation/TLS | ✓ | ✓ | Implemented |
| kXR_login=3007 | Session start | ✓ | ✓ | Implemented |
| kXR_mkdir=3008 | Create directory | ✓ | ✓ | Implemented |
| kXR_mv=3009 | Rename/move | ✓ | ✓ | Implemented |
| kXR_open=3010 | Open file handle | ✓ | ✓ | Implemented |
| kXR_ping=3011 | Liveness check | ✓ | ✓ | Implemented |
| kXR_chkpoint=3012 | Checkpoint/transaction writes | ✓ | ✓ | Implemented |
| kXR_read=3013 | Read bytes | ✓ | ✓ | Implemented |
| kXR_rm=3014 | Delete file | ✓ | ✓ | Implemented |
| kXR_rmdir=3015 | Remove empty directory | ✓ | ✓ | Implemented |
| kXR_sync=3016 | fsync to disk | ✓ | ✓ | Implemented |
| kXR_stat=3017 | Stat path/handle | ✓ | ✓ | Implemented |
| kXR_set=3018 | Set config option | ✓ | ✓ | Implemented |
| kXR_write=3019 | Write bytes | ✓ | ✓ | Implemented |
| kXR_fattr=3020 | Extended attributes (xattr) | ✓ | ✓ | Implemented |
| kXR_prepare=3021 | Tape staging | ✓ | ✓ | Implemented |
| kXR_statx=3022 | Multi-path stat | ✓ | ✓ | Implemented |
| kXR_endsess=3023 | Graceful session termination | ✓ | ✓ | Implemented |
| kXR_bind=3024 | Bind secondary data channel | ✓ | ✓ | Implemented |
| kXR_readv=3025 | Scatter-gather read | ✓ | ✓ | Implemented |
| kXR_pgwrite=3026 | Paged write with CRC32c | ✓ | ✓ | Implemented |
| kXR_locate=3027 | Locate file replicas | ✓ | ✓ | Implemented |
| kXR_truncate=3028 | Truncate file | ✓ | ✓ | Implemented |
| kXR_sigver=3029 | Request-signing envelope (HMAC-SHA256) | ✓ | ✓ | Implemented (HMAC-SHA256, GSI DH key derivation, security level enforcement, replay protection) |
| kXR_pgread=3030 | Paged read with CRC32c integrity | ✓ | ✓ | Implemented |
| kXR_writev=3031 | Scatter-gather write | ✓ | ✓ | Implemented |
| kXR_clone=3032 | Server-side range copy (5.2.0) | ✓ | ✓ | Implemented |

### 1.2 Summary: 33 request opcodes declared; **32 implemented, 1 unimplemented**

- `kXR_gpfile` (3005) — legacy, unused in modern clients; falls through to kXR_Unsupported in dispatch (intentional)

### 1.3 Response Codes (kXR_* = 4000–4007)

| Code | Name | Canonical | nginx-xrootd | Status |
|---|---|---|---|---|
| kXR_ok=0 | Success | ✓ | ✓ | Implemented |
| kXR_oksofar=4000 | Partial result | ✓ | ✓ | Used for pgread/pgwrite page responses |
| kXR_attn=4001 | Unsolicited notification | ✓ | ✓ | Native server-originated generation implemented (`src/response/async.c`: `xrootd_send_attn_asyncms()`/`xrootd_send_attn_asynresp()`); proxy relay also implemented (`proxy/events_read.c`) |
| kXR_authmore=4002 | Auth needs round-trip | ✓ | ✓ | Implemented (GSI negotiation) |
| kXR_error=4003 | Request failed | ✓ | ✓ | Implemented with errno→kXR mapping |
| kXR_redirect=4004 | Redirect to another server | ✓ | ✓ | Implemented (manager mode, CMS locate, upstream proxy relay — `response/control.c`, `upstream/response.c`) |
| kXR_wait=4005 | Try again after N seconds | ✓ | ✓ | Implemented (upstream proxy retry, backpressure — `response/control.c`) |
| kXR_waitresp=4006 | Async result pending | ✓ | ✓ | Implemented (upstream async response relay — `response/control.c`, `upstream/response.c`) |
| kXR_status=4007 | Extended status with CRC32c | ✓ | ✓ | Used for pgread/pgwrite integrity responses |

### 1.4 Error Codes (kXR_* = 3000–3021) — ServerServerErrorBody.errnum

All error codes declared in `opcodes.h` and mapped via `errno → kXR_*` helpers:

| Canonical errno mapping | nginx-xrootd mapping | HTTP response |
|---|---|---|
| ENOENT → kXR_NotFound(3011) | ✓ | 404 |
| EACCES/EPERM → kXR_NotAuthorized(3010) | ✓ | 403 |
| EINVAL → kXR_ArgInvalid(3000) | ✓ | 400 |
| EIO → kXR_IOError(3007) | ✓ | 500 |
| ENOMEM → kXR_NoMemory(3008) | ✓ | 507 |

---

## 2. Protocol Version & Capability Negotiation

### Canonical XRootD (XProtocol.hh)
- Supports protocol versions: v1, v2, v3, v4, v5
- `kXR_async` flag (0x0040) — async response mode
- Async operations: kXR_asyncms(5002), kXR_asyncdi/rd/wt/av/go (5001–5007)
- Multiple capability negotiation rounds via `kXR_protocol`

### nginx-xrootd (opcodes.h)
- Advertises version **5.2.0** (`kXR_PROTOCOLVERSION = 0x00000520u`)
- Falls back to stable v3 (`kXR_PROTOCOLVERSION_3 = 0x00000300u`)
- Server type: `kXR_DataServer=1` by default; advertises `kXR_isManager` when `xrootd_manager_mode on` or `xrootd_manager_map` is configured (`session/protocol.c`)

**Status:** The active async action codes `kXR_asyncms` (5002) and `kXR_asynresp` (5008) are declared in `opcodes.h`, and `src/response/async.c` (registered in `config`) implements native server-push generation via `xrootd_send_attn_asyncms()`. The deprecated codes 5000–5007 (except 5002) return `kXR_Unsupported` per the v5 spec; unknown async requests fall through to the generic `kXR_Unsupported` path.

---

## 3. Remaining Gaps from Canonical XRootD (Intentional or Minimal Impact)

### 3.1 `kXR_gpfile` — Legacy Get/Put File
- **Canonical:** Legacy opcode (was kXR_getfile), rarely used in modern clients
- **nginx-xrootd:** Declared constant, no dispatch handler
- **Impact:** Minimal — legacy unused opcode; modern clients use kXR_open+kXR_read/kXR_write instead

### 3.2 `kXR_attn` Response (4001) — Unsolicited Notification
- **Canonical:** Server pushes unsolicited notifications to client (e.g., drain, disconnect signals)
- **nginx-xrootd:** Implemented — native `xrootd_send_attn_asyncms()` generation exists (`src/response/async.c`); proxy mode also relays upstream `kXR_attn` frames (`proxy/events_read.c`). Full coverage exists.
- **Impact:** Both native server-originated notifications and proxy relay are supported

### 3.3 Async Operations (5000–5008) — Deprecated Legacy Actions
- **Canonical:** Deprecated action codes exist for legacy async response workflows
- **nginx-xrootd:** `kXR_asyncms` (5002) and `kXR_asynresp` (5008) ARE defined in `opcodes.h`; `src/response/async.c` is registered in `config` and contains the native `xrootd_send_attn_asyncms()` implementation. The remaining deprecated action codes (5000–5007, except 5002) return `kXR_Unsupported` per the v5 spec.
- **Impact:** Active async action codes are implemented natively; deprecated codes receive the generic `kXR_Unsupported` fallback

---

## 4. Features Where nginx-xrootd is Superior to Canonical XRootD

### 4.1 Confined Path Resolution (Security)
- **Canonical:** Uses `XrdSysFilesystem` and configurable chroot paths
- **nginx-xrootd:** Uses `ngx_http_xrootd_webdav_resolve_path()` — canonical+confined path resolution in a single helper, applied before every open() call on all wire paths (INVARIANT #4 from AGENTS.md)

**Advantage:** nginx applies confined path resolution as an invariant gate on ALL operations, ensuring no path escapes the configured root. This is more uniformly enforced than canonical's per-path filesystem lookup approach.

### 4.2 Atomic Temp Write Pattern (S3 PUT + WebDAV PUT)
- **Canonical:** Direct write to target file; crash recovery via checkpoint transactions (`kXR_chkpoint`)
- **nginx-xrootd:** Writes to temp file with `O_EXCL`, then renames to final path — atomic swap

**Advantage:** nginx's O_EXCL + rename pattern prevents partial writes from being visible. If the write fails mid-stream, no corrupted data appears at the target path. Canonical uses kXR_chkpoint for transactional writes but requires explicit client checkpoint mode.

### 4.3 Mixed Body Modes (S3 PUT)
- **Canonical:** Single write mode per file handle
- **nginx-xrootd:** S3 PUT handler (`s3_put_body_handler()`) supports mixed body modes — UploadPart and regular PUT handled in same dispatch with different callback paths

**Advantage:** Unified handling for both standard PUT and multipart UploadPart operations, reducing code duplication between S3 REST and XRootD protocol paths.

### 4.4 ETag Generation via Stat
- **Canonical:** No native ETag concept (XRootD uses mtime+size as implicit version)
- **nginx-xrootd:** After successful PUT, calls `stat(final_path)` → `s3_etag()` to generate RFC-compliant S3 ETags

**Advantage:** Bridges XRootD semantics with S3 REST API expectations — clients get verifiable content hashes without extra filesystem overhead.

### 4.5 Token Scope Check (WebDAV + S3)
- **Canonical:** Uses VOMS attributes and ACL policy files for authorization
- **nginx-xrootd:** Uses `xrootd_token_check_scope(scope, path)` to verify JWT scope grants access before write operations, with global `conf->allow_write` check as pre-gate (INVARIANT #3 from AGENTS.md)

**Advantage:** Two-tier auth gate — global config + per-request token scope — provides finer-grained control than canonical's single ACL lookup. Combined with WebDAV lock checking (`webdav_check_locks()`) for MOVE/COPY/DELETE on collections.

### 4.6 Async I/O via nginx Event Loop
- **Canonical:** Uses thread pools and async I/O workers (XrdAsync)
- **nginx-xrootd:** Uses `ngx_http_read_client_request_body()` for async body reads — non-blocking event-loop model, no threads needed per request

**Advantage:** nginx's event-loop architecture handles thousands of concurrent requests with minimal memory overhead. No thread-per-request cost; async callbacks (`s3_put_body_handler()`) integrate cleanly with the event loop.

### 4.7 WebDAV TPC via curl COPY
- **Official XRootD:** HTTP-TPC is implemented by `src/XrdHttpTpc`; native root TPC is implemented separately in the XRootD stack.
- **nginx-xrootd:** WebDAV TPC uses libcurl/helper paths with Source/Credential headers (`src/webdav/tpc.c`, `tpc_curl.c`, `tpc_cred.c`, `tpc_headers.c`)

**Difference:** nginx-xrootd's WebDAV TPC is operationally tied to nginx/WebDAV
and includes module-specific hardening; it should not be presented as a feature
missing from upstream XRootD.

### 4.8 S3 SigV4 Auth Gate
- **Canonical:** No native S3 REST API support
- **nginx-xrootd:** Full S3 REST API with AWS Signature Version 4 authentication gate (`src/s3/auth.c`) — GET, PUT, List, Multipart operations

**Advantage:** nginx-xrootd adds a complete S3-compatible REST layer on top of XRootD storage — clients can access the same data via both `root://` protocol and `s3://` REST API without duplication.

### 4.9 Response Buffer Layout (TLS vs Cleartext)
- **Canonical:** Uses raw socket writes; buffer type determined by transport
- **nginx-xrootd:** Strict buffer separation — TLS: `b->memory=1` memory-backed buffers only; cleartext: file-backed + sendfile; never mixed (INVARIANT #2 from AGENTS.md)

**Advantage:** Prevents subtle bugs where TLS and cleartext buffer types are accidentally mixed, ensuring correct I/O path selection for every response.

### 4.10 Wire String Sanitization
- **Canonical:** Raw wire strings passed through
- **nginx-xrootd:** `xrootd_sanitize_log_string()` — escapes control bytes, quotes, backslashes, non-ASCII to `\xNN` before logging

**Advantage:** Prevents log injection and garbled output from malicious or binary wire data.

---

## 5. Performance Optimizations Comparison

### 5.1 Checksum Operations
| Feature | Canonical | nginx-xrootd |
|---|---|---|
| CRC32c per-page (pgread/pgwrite) | ✓ | ✓ |
| Max checksum errors per request | kXR_pgMaxEpr=128 | Declared, used in pgread/pgwrite |
| Max outstanding checksum errors | kXR_pgMaxEos=256 | Declared, used in pgread/pgwrite |
| SHA256 checksums | ✓ (via kXR_query) | ✓ (via kXR_query handler) |
| CRC64 checksums | Stock XRootD declares the name/length convention but ships no calculator | ✓ `crc64` / `crc64nvme` via `src/core/compat/crc64.c`; S3 CRC64NVME headers supported |

**Status:** nginx-xrootd is stronger here: both support per-page CRC32c
integrity and SHA256 query checksums, while nginx-xrootd additionally implements
CRC-64/XZ and CRC-64/NVME across root://, WebDAV/XrdHttp, S3, and the native
client (`docs/10-reference/crc64-checksums.md`).

### 5.2 Scatter-Gather I/O
| Feature | Canonical | nginx-xrootd |
|---|---|---|
| kXR_readv (scatter-gather read) | ✓ | ✓ |
| kXR_writev (scatter-gather write) | ✓ | ✓ |
| kXR_pgread/pgwrite (paged with CRC32c) | ✓ | ✓ |

**Status:** Parity — all scatter-gather and paged operations implemented.

### 5.3 Server-Side Transfer (TPC)
| Feature | Canonical | nginx-xrootd |
|---|---|---|
| Native root TPC | ✓ (official XRootD TPC handling in `src/XrdOfs` / `src/XrdXrootd`) | ✓ (`src/tpc/key_registry.c`, `launch.c`, `thread.c`, `io.c`, `done.c`) |
| HTTP/WebDAV TPC | ✓ (`src/XrdHttpTpc`) | ✓ (`src/webdav/tpc.c`, `tpc_curl.c`, `tpc_marker.c`, `tpc_cred.c`) |

**Status:** Both projects implement HTTP/WebDAV TPC, but with different
integration models and operational controls.

### 5.4 File Handle Management
- **Canonical:** Uses file descriptor table with opaque handles
- **nginx-xrootd:** Uses `xrootd_file_t` in `src/connection/fd_table.c`, handles mapped to 0–255 range (AGENTS.md FAQ)

**Status:** Similar — both use opaque handle tables. nginx's fixed 0–255 range provides predictable memory allocation via ngx_palloc.

### 5.5 Open Cache
- **Canonical:** Uses file descriptor caching at filesystem level
- **nginx-xrootd:** `open_cache.c` — caches open handles to avoid repeated path resolution and stat calls (INVARIANT #7: "use handle metadata; no extra path syscalls per read")

**Advantage:** nginx's open cache is tighter — avoids redundant syscall overhead by caching resolved+confined paths, not just file descriptors.

---

## 6. Architecture Comparison

### 6.1 Server Model
| Aspect | Canonical XRootD | nginx-xrootd |
|---|---|---|
| Redirector/Data server split | Yes (redirectors + data servers) | Yes — `xrootd_manager_mode on` + `xrootd_manager_map` enable full manager/redirector role (`session/protocol.c` advertises `kXR_isManager`) |
| Load balancing | Yes (kXR_locate returns replica list, kXR_redirect sends client elsewhere) | Yes — manager mode issues `kXR_redirect`/`kXR_wait`/`kXR_waitresp` via CMS locate and upstream relay (`response/control.c`, `upstream/response.c`) |
| Cluster management | CMS/cluster protocol (`src/net/cms/send.c`, `upstream/`) | Implemented — `xrootd_cms_manager` directive; `manager/registry.c`, `cms/send.c` handle LOGIN/AVAIL/PING heartbeat and multi-tier cluster topologies |

### 6.2 Auth Methods
| Method | Canonical | nginx-xrootd |
|---|---|---|
| GSI (Grid Security Infrastructure) | ✓ | ✓ (`session/gsi/parse.c`) |
| Token-based (JWT/OIDC) | ✓ | ✓ (`session/token/validate.c`) |
| SSS (Simple Session Service) | ✓ | ✓ (`session/sss/`) |
| Anonymous | ✓ | ✓ |
| VOMS attributes | ✓ | ✓ (`voms/`) |
| ACL policy files | ✓ | ✓ (`handshake/policy.c`, `path/acl.c`, `authdb.c`) |

**Status:** Parity — all auth methods implemented.

### 6.3 Protocol Lifecycle
- **Canonical:** Full lifecycle with bind/unbind, async resp, redirect chains
- **nginx-xrootd:** Simplified lifecycle: login → protocol negotiation → ops → endsess/bind

**Advantage:** nginx's simplified lifecycle reduces state complexity and memory overhead for single-server deployments.

---

## 7. WebDAV & S3 REST API

### 7.1 WebDAV
| Method | Canonical | nginx-xrootd |
|---|---|---|
| GET | ✓ (`src/XrdHttp`) | ✓ |
| PUT | ✓ (`src/XrdHttp`) | ✓ |
| MOVE | ✓ (`src/XrdHttp`) | ✓ |
| COPY | ✓ (`src/XrdHttp`) | ✓ |
| PROPFIND | ✓ (`src/XrdHttp`) | ✓ |
| LOCK | Site/plugin dependent | ✓ (`src/webdav/lock.c`) |
| HTTP/WebDAV TPC | ✓ (`src/XrdHttpTpc`) | ✓ (`src/webdav/tpc.c`) |

### 7.2 S3 REST API (Unique to nginx-xrootd)
| Operation | Canonical | nginx-xrootd |
|---|---|---|
| GET Object | ✗ | ✓ (`src/s3/get.c`) |
| PUT Object | ✗ | ✓ (`src/s3/put.c`) — atomic temp write + rename |
| List Objects | ✗ | ✓ (`src/s3/list.c`) |
| Multipart Upload | ✗ | ✓ (`src/s3/multipart.c`) |
| SigV4 Auth | ✗ | ✓ (`src/s3/auth.c`) |

**Advantage:** nginx-xrootd provides an S3-compatible REST layer in addition to
native/WebDAV storage access, enabling cloud-native clients to access HEP data
without protocol conversion.

---

## 8. Metrics & Logging

### 8.1 Metrics
- **Canonical:** Uses XrdStats for server-side metrics
- **nginx-xrootd:** `src/observability/metrics/stream.c`/`writer.c` — HTTP request counters, bytes_sent tracking via `webdav_metrics_return()` and `XROOTD_PROXY_METRIC_INC(op, status)`

**Advantage:** nginx provides HTTP-layer metrics (request counts + byte totals) in addition to protocol-level stats. Low-cardinality labels only (INVARIANT #8: no paths/bucket-names/UUIDs).

### 8.2 Logging
- **Canonical:** XrdLog with configurable log levels
- **nginx-xrootd:** nginx error_log + `xrootd_sanitize_log_string()` for wire data sanitization

**Advantage:** Wire string sanitization prevents control byte injection in logs.

---

## 9. Summary: Gap Analysis

### Missing or narrower in nginx
1. **kXR_gpfile(3005)** — Legacy unused opcode; declared but no handler; falls through to kXR_Unsupported. Minimal impact.
2. **Custom third-party security plugins** — every *standard* upstream auth
   scheme is now implemented (GSI, token, SSS, unix, krb5, macaroons, and now
   `host`/`pwd` in `src/auth/host/`+`src/auth/pwd/`); only arbitrary loadable sec plugins
   are not reproduced (no sec-plugin ABI).
3. **PSS/PFC/Ceph/OssCsi/OssArc/full XrdFrm-MSS ecosystem** — upstream remains
   broader for deployments built around those storage-backend plugins.
   (ZIP-member access is implemented in `src/zip/`.)

### Where nginx is superior
- Confined path resolution as universal invariant gate
- Atomic temp write + rename pattern for crash-safe PUTs
- Token scope + global config two-tier auth gate
- Async event-loop I/O (no thread-per-request cost)
- WebDAV TPC with nginx-specific hardening and operational controls
- S3 SigV4 REST API layer on top of XRootD storage
- Strict TLS/cleartext buffer separation invariant
- Wire string sanitization for log safety
- Open cache with resolved path deduplication

### Where official XRootD may have advantages
- Full PSS/PFC/XrdFrm/MSS and OSS plugin ecosystem
- Broader historical auth/security plugin surface
- More mature XrdHttpTpc monitoring and deployment history
- Native client libraries and federation tooling outside this server module

---

## 10. Recommendations

### ✓ Done: `kXR_sigver` handler — fully implemented
- `src/session/signing.c` — parses ClientSigverRequest, validates seqno monotonicity (replay protection), stores HMAC pending state
- `src/handshake/sigver.c` — HMAC-SHA256 verification before next dispatch; enforces `xrootd_security_level` directive
- `src/handshake/dispatch_signing.c` — routes `kXR_sigver` to handler
- GSI key derivation: `src/auth/gsi/parse_crypto_helpers.c` sets `ctx->signing_key` = SHA-256(DH shared secret), `ctx->signing_active = 1`

### ✓ Done: Manager/redirector mode
- Full two-tier and three-tier cluster topologies via `xrootd_manager_mode` + `xrootd_cms_manager`
- `kXR_redirect`, `kXR_wait`, `kXR_waitresp` all generated by `response/control.c` and relayed by `upstream/response.c`

### ✓ Done: Native `kXR_attn` generation and active async action codes
- `xrootd_send_attn()`, `xrootd_send_attn_asyncms()`, and `xrootd_send_attn_asynresp()` are declared in `src/response/async.h` and implemented in `src/response/async.c` (registered in `config`)
- Active action codes `kXR_asyncms` (5002) and `kXR_asynresp` (5008) are declared in `opcodes.h`; native generation is used by `kXR_notify` on `kXR_prepare` (`src/query/prepare.c`). Deprecated codes 5000–5007 (except 5002) return `kXR_Unsupported` per the v5 spec

### Request opcode coverage
- 32 active request opcodes have parity or module-specific behavior.
- 1 legacy opcode (`kXR_gpfile`) is intentionally unimplemented and upstream
  default data-server behavior is also unsupported for this obsolete path.
