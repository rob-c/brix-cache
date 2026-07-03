# Cross-Protocol Sharing & Expansion Analysis

**Date:** 2026-05-26  
**Scope:** BriX-Cache module — XRootD (stream), WebDAV/HTTP (http), S3 REST (http)  
**Purpose:** Identify areas where functionality can be shared or expanded across protocol implementations to reduce duplication, improve consistency, and enable new cross-protocol capabilities.

---

## Executive Summary

The BriX-Cache module implements three distinct protocols — XRootD (`root://`/`roots://`) via the stream layer, WebDAV (`davs://`/`http://`) via the HTTP layer, and S3-compatible REST via a separate HTTP location handler. Despite their protocol differences, there is significant overlap in **auth validation**, **path resolution**, **namespace operations**, **HTTP response building**, **error mapping**, **metrics infrastructure**, and **I/O helpers**.

```text
   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   PROTOCOL FRONT-ENDS
   │ STREAM root://│   │ WebDAV davs://│   │  S3  REST    │   (distinct framing
   │ opcodes·wire  │   │ HTTP methods  │   │  SigV4·XML   │    & dispatch)
   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
          │ wire-path        │ URI-decode       │ key-strip   protocol-specific
          ▼ extract          ▼                  ▼ bucket      pre-processing
   ┌──────────────────────────────────────────────────────┐
   │  SHARED CORE                                          │  src/core/compat/, src/fs/path/
   │  token validate · scope check · confined ns ops       │  src/auth/token/, src/observability/metrics/
   │  path resolve · error map (errno→kXR / →HTTP)         │
   │  HTTP file response · range · ETag · XML · fs_walk     │  ← WebDAV+S3 reuse
   │  staged-file commit · async-job guard · metrics zone   │
   └───────────────────────────┬──────────────────────────┘
                               ▼
                    VFS → POSIX storage driver (src/fs/)
   ─────────────────────────────────────────────────────────────────────────────
   reuse legend:  ███ all three protocols   ▓▓ WebDAV+S3 only   ░ stream only
   INVARIANT #6: S3 SigV4 auth stays SEPARATE — scope checks shared, auth NEVER
```

This analysis identifies:

1. **Already shared** functions used across 2+ protocols (high ROI — maintain & document)
2. **Near-shared** patterns that could be unified with minimal effort (medium ROI)
3. **Protocol-specific gaps** where one protocol has capabilities another lacks (expansion opportunities)
4. **Architecture-level consolidation** candidates for long-term refactoring

---

## 1. Already Shared — Cross-Protocol Functions

These functions are already used by multiple protocols and represent the foundation of cross-protocol sharing.

### 1.1 Token Validation & Scope Checking

| Function | File | Used By |
|---|---|---|
| `brix_token_validate()` | `src/auth/token/validate.c` | Stream (XRootD), WebDAV |
| `brix_token_check_read/write()` | `src/auth/token/scopes.c` | **Stream, WebDAV, S3** — all three protocols |

**Current state:** WLCG/JWT token validation is shared between Stream and WebDAV. Scope checking (`storage.read`, `storage.write`, `storage.create`) with prefix matching is used by ALL three protocols. This is the strongest cross-protocol sharing point.

**Boundary:** S3 must continue to treat SigV4 as distinct from WLCG token
auth. Scope-check helper reuse is acceptable, but bearer-token validation for
S3 should remain out of scope unless the project explicitly changes INVARIANT
#6 ("S3 SigV4 ≠ WLCG token — never share auth logic").

### 1.2 Confined Namespace Operations

All three protocols use the same confined filesystem operations from `src/fs/path/`:

| Function | File | Used By |
|---|---|---|
| `brix_open_confined_canon()` | `src/fs/path/resolve_confined_ops.c` | Stream, WebDAV, S3 |
| `brix_unlink_confined_canon()` | `src/fs/path/resolve_confined_ops.c` | Stream, WebDAV, S3 |
| `brix_mkdir_confined_canon()` | `src/fs/path/resolve_confined_ops.c` | Stream, WebDAV, S3 |
| `brix_rename_confined_canon()` | `src/fs/path/resolve_confined_ops.c` | Stream, WebDAV, S3 |
| `brix_link_confined_canon()` | `src/fs/path/resolve_confined_ops.c` | Stream, WebDAV, S3 |

**Current state:** All three protocols use the same confined helpers — these enforce export root boundary via `openat2(RESOLVE_BENEATH)` on Linux or parent-directory walk with `O_NOFOLLOW` as fallback. TOCTOU race closure is consistent across all paths.

### 1.3 Shared Namespace Ops (copy/delete)

| Function | File | Used By |
|---|---|---|
| `brix_ns_local_copy()` | `src/core/compat/namespace_ops.c` | WebDAV, S3 |
| `brix_ns_delete()` | `src/core/compat/namespace_ops.c` | WebDAV, S3 |

**Current state:** WebDAV and S3 both use the same namespace copy/delete helpers from `src/core/compat/`. These implement `copy_file_range` with read/write fallback for local transfers. Stream protocol has native TPC via SHM key registry (`src/tpc/`) but could also benefit from these simpler local-copy helpers for non-TPC intra-root moves.

### 1.4 HTTP Response Building (WebDAV + S3)

All three functions in `src/core/http/http_file_response.c` are shared between WebDAV and S3:

| Function | File | Used By |
|---|---|---|
| `brix_http_send_file_range()` | `src/core/http/http_file_response.c` | WebDAV GET, S3 GetObject |
| `brix_http_add_etag_header()` | `src/core/http/http_file_response.c` | WebDAV HEAD, S3 HeadObject |
| `brix_http_parse_range()` / `brix_http_parse_range_vector()` | `src/core/compat/range.c`, `range_vector.c` | WebDAV GET, S3 GetObject (Range header) |

**Current state:** WebDAV and S3 share the same HTTP file response infrastructure — both build `ngx_chain_t` of `ngx_buf_t`, use sendfile for cleartext, memory-backed buffers for TLS. ETag generation via `brix_http_etag_str()` from mtime+size is shared in `src/core/http/etag.c`.

### 1.5 XML Building (WebDAV + S3)

| Function | File | Used By |
|---|---|---|
| `brix_xml_write_text_element()` | `src/core/compat/xml.c` | WebDAV PROPFIND, S3 ListObjectsV2, S3 multipart responses |
| `brix_http_xml_error_builder()` (via XML_APPEND macros) | `src/protocols/s3/s3.h`, `src/protocols/webdav/propfind.c` | S3 error responses, WebDAV PROPFIND |

**Current state:** Both protocols share the same XML encoding helpers for escaping, element building, and error response generation.

### 1.6 Directory Walk (WebDAV + S3)

| Function | File | Used By |
|---|---|---|
| `brix_fs_walk()` / `brix_fs_walk_dir()` | `src/core/compat/fs_walk.c` | WebDAV PROPFIND, S3 ListObjectsV2 |

**Current state:** Recursive directory traversal with callback and depth tracking is shared between WebDAV (PROPFIND) and S3 (ListObjectsV2). Stream protocol uses its own dirlist handler in `src/protocols/root/dirlist/handler.c` but could benefit from this unified walk engine.

### 1.7 Error Mapping

| Function | File | Used By |
|---|---|---|
| `brix_kxr_from_errno()` | `src/core/compat/error_mapping.c` | Stream (XRootD) |
| `brix_http_errno_to_status()` | `src/core/compat/error_mapping.c` | WebDAV, S3 |
| `brix_http_map_ns_status()` / `brix_http_map_errno()` | `src/core/compat/error_mapping.c` | WebDAV, S3 |

**Current state:** Unified errno→kXR and errno→HTTP mapping consolidates three domains previously split across separate files. This is a well-designed shared layer.

### 1.8 Shared Config Preamble

All three protocol config structs embed `ngx_http_brix_shared_conf_t` at the top:

```c
typedef struct {
    ngx_flag_t          enable;             /* on/off toggle for protocol */
    ngx_str_t           root;               /* filesystem export root path */
    char                root_canon[PATH_MAX]; /* canonicalized/confined root */
    ngx_flag_t          allow_write;        /* write permission flag */
    ngx_str_t           thread_pool_name;   /* async I/O thread pool name */
    ngx_thread_pool_t  *thread_pool;        /* resolved pool handle (runtime only) */
} ngx_http_brix_shared_conf_t;
```

**Current state:** `src/core/config/shared_conf.h` provides `ngx_http_brix_shared_init()`, `ngx_http_brix_shared_merge()`, and `ngx_http_brix_shared_merge_with_root()` inline helpers that consolidate the common enable/root/allow-write/thread-pool create+merge lifecycle. Stream, WebDAV/XrdHttp, and S3 all use the shared initializer and merge helper while preserving their protocol-specific root defaults.

### 1.9 Metrics Infrastructure

| Macro | File | Used By |
|---|---|---|
| `BRIX_WEBDAV_METRIC_INC()` / `BRIX_S3_METRIC_INC()` / `BRIX_SRV_METRIC_INC()` | `src/observability/metrics/metrics_macros.h` | WebDAV, S3, Stream — all three protocols |

**Current state:** Shared-memory zone (`ngx_brix_shm_zone`) with per-protocol counter families (requests_total, responses_total, auth_total, bytes_rx_tx). All three protocols write atomic counters to the same shared memory. Prometheus exporter iterates all protocol families in `src/observability/metrics/stream.c`. Dashboard live transfer monitor reads from this same zone for cross-protocol visibility.

### 1.10 Crypto Helpers

| Function | File | Used By |
|---|---|---|
| HMAC-SHA256 (`EVP_MAC` operations) | `src/core/compat/crypto.c` | Stream (GSI sigver), S3 (SigV4 signing chain) |
| CRC32c computation | `src/core/compat/crc32c.c` | Stream (pgread/pgwrite per-page CRC), WebDAV, S3 |

**Current state:** Shared crypto operations for HMAC-SHA256 and random nonce generation are used across protocols. CRC32c is shared between stream wire framing and HTTP protocol integrity checks.

---

## 2. Near-Shared — Patterns That Could Be Unified

These patterns are structurally similar but currently implemented separately. Unification would reduce code duplication and improve consistency.

### 2.1 Path Resolution — Shared Core With Protocol Preprocessing

**Current state:** Each protocol has its own path resolution function:

| Protocol | Function | File | Input Format |
|---|---|---|---|
| Stream (XRootD) | `brix_resolve_path()` variants | `src/fs/path/resolve_path_variants.c` | Raw wire payload string |
| WebDAV | `ngx_http_brix_webdav_resolve_path()` | `src/protocols/webdav/path.c` → URL-decodes then calls `brix_http_resolve_path()` | HTTP URI (percent-encoded) |
| S3 | `s3_resolve_key()` | `src/protocols/s3/util.c` → key-strips then calls `brix_http_resolve_path()` | S3 object key + bucket prefix stripping |

**Key differences:**
- Stream: extracts path from wire payload, handles CGI suffix stripping via `brix_strip_cgi()`
- WebDAV: URL-decodes HTTP URI → calls `brix_http_resolve_path()` (shared in `src/core/compat/path.c`)
- S3: maps `s3://bucket/key` → filesystem path with bucket name as prefix, handles `$folder$` sentinel

**Implemented:** The core logic — canonicalization + confinement check — now lives behind the protocol-neutral `brix_http_resolve_path()` entry point in `src/core/compat/path.c`. Protocol-specific pre-processing (wire extraction, URI decoding, bucket stripping) remains separate, and WebDAV/S3 call the shared resolver once they have a normalized path.

**Remaining expansion:** Stream still uses its dedicated wire-path resolver variants. A future cleanup can route any already-normalized stream paths through `brix_http_resolve_path()` once the stream-specific CGI stripping and protocol error mapping are kept intact.

### 2.2 GSI Certificate Verification — Shared Verification Core

**Current state:** Two separate cert verification paths:

| Protocol | Function | File | Caching Strategy |
|---|---|---|---|
| Stream (XRootD) | `brix_handle_gsi_auth()` → parse_x509 + verify CA chain | `src/auth/gsi/auth.c`, `parse_x509.c` | Session-level — verified once per session |
| WebDAV | `webdav_verify_proxy_cert()` | `src/protocols/webdav/auth_cert.c` | Per-request with caching via `webdav_mark_req_verified()` |

**Key differences:**
- Stream: two-round DH key exchange (certreq→send_cert, cert→parse_x509), session-level verification
- WebDAV: per-request verification with mark-caching to avoid re-verifying on subsequent requests within same connection

**Implemented:** The OpenSSL `X509_STORE_CTX` setup, proxy-cert flag,
verification-depth handling, chain verification, and leaf DN extraction are
shared in `brix_gsi_verify_chain()` (`src/auth/crypto/gsi_verify.c`). Stream and
WebDAV both call this helper after their protocol-specific credential intake:
- Stream keeps the two-round DH-protected GSI wire exchange and session-level
  auth state.
- WebDAV keeps TLS peer-certificate extraction and connection/session auth
  caching.

**Remaining expansion:** VOMS extraction is now available to WebDAV via
`webdav_extract_voms_ctx()` in `src/protocols/webdav/auth_cert.c`. After any successful
GSI cert verification path (cached, nginx-verified, or manually verified),
the function calls `brix_extract_voms_info()` from `src/auth/voms/extract.c`
and populates `ctx->primary_vo` and `ctx->vo_list` in the per-request context.
A thin header `src/auth/voms/voms_http.h` exposes the extraction API without pulling
in the full stream-module umbrella header.

Configuration: add `brix_webdav_vomsdir /etc/grid-security/vomsdir;` and
`brix_webdav_voms_cert_dir /etc/grid-security/certificates;` to a WebDAV
location block. VOMS extraction is skipped when either directive is absent.

### 2.3 HTTP Body Write — Shared WebDAV/S3 Body Writer

**Current state:** WebDAV and S3 PUT both route request-body writes through
the shared body helpers in `src/core/http/http_body.c`:

| Protocol | Function | File | Buffer Handling |
|---|---|---|---|
| WebDAV | `webdav_put_body_handler()` → async callback after body read | `src/protocols/webdav/put.c` | Uses `brix_http_body_write_buf()` from `src/core/http/http_body.c` |
| S3 | `s3_put_body_handler()` → async callback after body read | `src/protocols/s3/put.c` | Uses `brix_http_body_write_to_fd()` from `src/core/http/http_body.c` |

**Key differences:**
- WebDAV: uses shared `brix_http_body_pwrite_full()` / `brix_http_body_write_buf()` helpers from `src/core/http/http_body.c`
- S3: uses `brix_http_body_write_to_fd()` so memory-backed and spooled request-body buffers follow the same write path as WebDAV

**Implemented:** S3 no longer needs a private request-body chain iterator for
normal PUT handling. The shared helper owns the buffer traversal and `write(2)`
retry behavior for both WebDAV and S3.

### 2.4 Staged File Operations

**Current state:** WebDAV and S3 now share one staged file implementation:

| Protocol | Function | File | Temp Pattern |
|---|---|---|---|
| S3 PUT | `brix_staged_open()` / `brix_staged_commit()` / `brix_staged_abort()` | `src/core/compat/staged_file.c` + used in `src/protocols/s3/put.c` | `.xrd-tmp.{pid}.{random}` |
| WebDAV PUT | `brix_staged_open()` / `brix_staged_commit()` / `brix_staged_abort()` | `src/core/compat/staged_file.c` + used in `src/protocols/webdav/put.c` | `.xrd-tmp.{pid}.{random}` |

**Key differences:**
- S3: uses shared `brix_staged_*()` helpers from `src/core/compat/staged_file.c` with 16-attempt retry loop
- WebDAV: now shares the same staged temp-open/write/rename lifecycle

**Implemented:** WebDAV PUT now uses the same staged file pattern as S3:
`brix_staged_open()`, body write, then `brix_staged_commit()` /
`brix_staged_abort()` for atomic rename with cleanup on failure. Both
protocols generate identical temp path patterns
(`fs_path.xrd-tmp.{pid}.{random}`). The handler also refreshes the WebDAV
open-file cache after the staged rename so subsequent GET/HEAD requests do not
retain the replaced inode.

### 2.5 Range Header Parsing — Already Shared, Could Expand

**Current state:** `brix_http_parse_range()` and `brix_http_parse_range_vector()` from `src/core/compat/range.c` are used by WebDAV GET and S3 GetObject for HTTP Range header parsing. Stream protocol's kXR_read does not support byte ranges (XRootD uses offset+length in wire payload).

**Expansion opportunity:** Add range support to stream kXR_read — this would enable `xrdcp` clients to request partial file downloads, matching WebDAV/S3 behavior. The shared parser infrastructure already exists; only the stream-side framing and dispatch logic needs addition.

---

## 3. Protocol-Specific Gaps — Expansion Opportunities

These are capabilities that one protocol has but others lack. Adding them would create more consistent cross-protocol behavior.

### 3.1 Read-Through Cache — Stream Only, Could Expand to HTTP

**Current state:** The read-through cache (`src/fs/cache/`) operates only on the stream (XRootD) layer:
- Anonymous `root://`/`roots://` clients trigger direct-mode cache fills from origin
- Per-file worker locks prevent concurrent fill collisions
- Write-through mirroring is implemented on kXR_sync/kXR_close

**Gap:** WebDAV GET and S3 GetObject do not use the read-through cache. HTTP clients downloading files always hit the filesystem directly, even when the file is cached locally.

**Expansion opportunity:** Add cache lookup to WebDAV GET (`src/protocols/webdav/get.c`) and S3 GetObject (`src/protocols/s3/object.c`). Before opening the file via `brix_open_confined_canon()`, check if a cached copy exists in the cache directory (same mechanism used by stream). This would:
- Reduce filesystem I/O for hot files accessed via HTTP protocols
- Improve latency for repeated downloads from browser/rucio/aws s3 clients
- Provide consistent caching behavior across all protocol entry points

**Implemented:** Read-through cache lookup is now integrated into both
WebDAV GET (`src/protocols/webdav/get.c`) and S3 GetObject (`src/protocols/s3/object.c`). When
`brix_webdav_cache_root` (WebDAV) or `brix_s3_cache_root` (S3) is
configured, each handler checks `brix_cache_file_ready()` from
`src/fs/cache/paths.c` before opening the canonical file path. On a cache hit
the handler redirects to the cached path while preserving root confinement
(the confined open uses `cache_root_canon` as the confinement root for cache
paths). The `cache_root` field is stored in `ngx_http_brix_shared_conf_t`
so it is inherited through the normal merge chain.

Configuration: add `brix_webdav_cache_root /srv/cache;` or
`brix_s3_cache_root /srv/cache;` to the respective location block.

### 3.2 Native TPC — Stream Only, Could Expand to HTTP

**Current state:** Native Third-Party Copy (`src/tpc/engine/key_registry.c`, `launch.c`, `thread.c`, `io.c`, `done.c`) operates only on the stream (XRootD) layer using SHM key registry for cross-process zero-copy transfers. WebDAV TPC uses curl COPY with Source/Credential headers (`src/protocols/webdav/tpc.c`). S3 has local copy via `brix_ns_local_copy()` but no remote TPC.

**Gap:** S3 does not support third-party copy (PUT with Content-Copy-Source header already exists as `s3_handle_copy_object()` in `src/protocols/s3/copy.c` but uses local file copy, not cross-server transfer). WebDAV TPC is curl-based; stream TPC is SHM-based — two different architectures for the same concept.

**Expansion opportunity:**
1. **S3 TPC via native TPC:** Enable S3 PUT with Content-Copy-Source header to use the native SHM key registry TPC path instead of local copy_file_range. This would allow cross-server transfers between S3 endpoints and XRootD backends.
2. **Unified TPC architecture:** Consolidate stream SHM-based TPC and WebDAV curl-based TPC into a single abstracted transfer engine that dispatches to the appropriate transport based on source/destination type (local vs remote).

**Incremental implementation:** S3 CopyObject now explicitly rejects remote
URL-style `x-amz-copy-source` values (for example `https://...` or
`root://...`) with `501 NotImplemented` and S3 error code
`NotImplemented`. This formalizes the current capability boundary while local
copy sources (`/bucket/key` or `bucket/key`) continue to use
`brix_ns_local_copy()`.

**Effort:** Medium-High — S3 TPC via native path is medium effort. Unified architecture requires redesigning `src/tpc/` to accept HTTP protocol requests and dispatch to appropriate transports.

### 3.3 WebDAV Locking — Stream Has ACL, No File Locks

**Current state:** WebDAV has full LOCK/UNLOCK support (`src/protocols/webdav/lock.c`) with file-level locking for concurrent access control. Stream (XRootD) uses VO ACL and token scope for authorization but has no per-file lock mechanism.

**Gap:** XRootD clients cannot acquire locks on files — concurrent access is controlled only by ACLs and session authentication. This means `xrdcp` clients can overwrite each other's files without coordination.

**Expansion opportunity:** Add file locking to stream protocol handlers (kXR_open, kXR_write, kXR_close). Reuse the WebDAV lock infrastructure from `src/protocols/webdav/lock.c`:
- LOCK on open → acquire advisory lock on fd
- WRITE while locked → check lock ownership before writing
- CLOSE with UNLOCK → release lock

**Effort:** Medium — integrate existing WebDAV lock helpers into stream open/write/close handlers. Add kXR_lock/kXR_unlock opcodes or use existing kXR_open flags for lock negotiation.

### 3.4 S3 WLCG Token Auth — SigV4 Only, Could Add Bearer Tokens

**Current state:** S3 uses only AWS Signature Version 4 (`src/protocols/s3/auth_sigv4_verify.c`) with HMAC-SHA256 signing chain. Anonymous mode is supported via empty access_key config. WLCG/JWT bearer tokens are NOT used for S3 auth per INVARIANT #6 ("S3 SigV4 ≠ WLCG token — never share auth logic").

**Status:** Deferred by invariant. WebDAV supports GSI certs and WLCG bearer
tokens, while S3 supports SigV4 or anonymous mode. That separation is
intentional in the current architecture.

**Allowed sharing:** Continue sharing authorization scope checks where S3
already needs path-level read/write/create decisions, but do not route S3
authentication through WebDAV or WLCG bearer-token validation.

### 3.5 Cross-Protocol Access Logging — Protocol-Tagged Shared Logs

**Current state:** Access logging remains transport-native, but both log
formats now carry protocol labels:
- Stream: `brix_access*.log` via `brix_log_access()` in
  `src/observability/accesslog/access_log.c`, with `proto=root` appended to each structured line.
- WebDAV and S3: nginx HTTP `access_log` can use the shared
  `$brix_protocol` variable from `src/core/compat/http_protocol_vars.c`, which
  resolves to `webdav`, `s3`, or `http` from the active location config.

**Implemented:** The shared test configuration writes a single
`http_access.log` using `proto=$brix_protocol` while preserving the older
per-endpoint logs for compatibility. This gives operators a non-duplicating
path to protocol-tagged HTTP logs and aligns native stream access lines with
the same `proto=` convention.

**Remaining expansion:** A future operator-facing directive could provide a
module-managed common access log path across stream and HTTP. For now, the
module exposes protocol labels and leaves file fan-in to nginx's native
`access_log` configuration, avoiding duplicate HTTP log lines.

**Effort:** Low — implemented for protocol labels. Full stream+HTTP single-file
fan-in would require an explicit directive and ownership rules for log file
opening/reload behavior.

### 3.6 Dashboard Cross-Protocol Visibility — Implemented

**Current state:** The HTTPS dashboard (`src/observability/dashboard/`) shows active
stream, WebDAV, S3, and TPC transfers in the same transfer table and exposes
per-protocol summaries in the JSON API.

**Implemented:**
- `src/observability/dashboard/http_tracking.c` tracks HTTP protocol transfers for WebDAV,
  S3, and WebDAV TPC.
- `src/observability/dashboard/api.c` emits protocol summaries for `root`, `webdav`, `s3`,
  and `tpc`.
- `src/observability/dashboard/page.c` renders protocol summary cards and a protocol filter
  for the live transfer table.

**Remaining expansion:** Add richer historical breakdowns by protocol and
operation once the dashboard history buckets have per-protocol dimensions.

---

## 4. Architecture-Level Consolidation Candidates

These are longer-term refactoring opportunities that would fundamentally improve cross-protocol consistency.

### 4.1 Unified Protocol Config Structure

**Current state:** Each protocol has its own config struct embedding `ngx_http_brix_shared_conf_t`:
- Stream: `ngx_stream_brix_srv_conf_t` (server-level) — includes VO rules, group rules, CMS map, proxy config
- WebDAV: location-level config — includes proxy upstream, CORS origins, open file cache
- S3: location-level config — includes bucket name, access key/secret key, SigV4 region

**Implemented:** The common config preamble is now actively used by all three
protocol config lifecycles:
- Stream calls `ngx_http_brix_shared_init()` in server-conf creation and
  `ngx_http_brix_shared_merge_with_root()` with root default `/`.
- WebDAV/XrdHttp calls the same shared init/merge path with root default `/`.
- S3 calls `ngx_http_brix_shared_init()` and `ngx_http_brix_shared_merge()`
  with the empty-root default expected by `brix_s3_root`.

This removes duplicated enable/root/allow-write/thread-pool merge logic and
also fixes stream thread-pool name inheritance through the same shared preamble
used by the HTTP protocols.

**Remaining consolidation candidate:** Extend the shared preamble beyond
enable/root/allow_write/thread_pool to hold additional cross-protocol fields,
where the semantics are actually common:
- Common auth mode field (`anonymous|gsi|token|sigv4`)
- Shared thread pool reference (already present)
- Common cache directory path

**Effort:** Medium — extending the struct is straightforward, but the auth and
cache semantics still differ enough that each additional field needs a protocol
compatibility check before moving it into the shared preamble.

### 4.2 Unified Dispatch Layer

**Current state:** Three separate dispatch entry points:
- Stream: `connection/handler.c` → `handshake/dispatch.c` → opcode handlers in read/, write/, etc.
- WebDAV: `webdav/dispatch.c` → method handlers in get.c, put.c, move.c, etc.
- S3: `s3/handler.c` → 11-step dispatch chain → sub-handlers in get.c, put.c, list.c, etc.

**Consolidation candidate:** Create a unified request dispatch abstraction that handles protocol-specific routing but shares common pre-processing:
- Auth gate (shared auth verification)
- Path resolution (shared path resolver from Section 2.1)
- Metrics tracking (shared metric macros)
- ACL/VO check (shared VO ACL from `src/auth/authz/acl.c`)

**Effort:** High — requires redesigning the dispatch entry point for each protocol to share a common pre-processing pipeline before delegating to protocol-specific handlers. Would reduce ~200 lines of duplicated auth+metrics+path resolution code across three protocols.

### 4.3 Shared AIO Thread Pool Infrastructure

**Current state:** All three protocols use nginx thread pools for async I/O but each configures and dispatches independently:
- Stream: `src/core/aio/read.c`, `aio/pgread.c`, `aio/write.c` — uses `conf->common.thread_pool`
- WebDAV: `src/protocols/webdav/put.c`, `src/protocols/webdav/copy.c` — uses `conf->common.thread_pool` via `ngx_thread_task_post()`
- S3: `src/protocols/s3/put.c` — uses `cf->common.thread_pool` via staged file async

**Partially implemented:** HTTP async PUT jobs now share the lifecycle guard in
`src/core/compat/async_job.c`. WebDAV and S3 threaded PUT tasks register staged-file
cleanup through `brix_async_job_set_cleanup()` and use
`brix_async_job_cleanup_once()` on async write/post-allocation failure paths.
This centralizes the double-cleanup guard while leaving protocol-specific I/O
and response finalization in each handler.

**Remaining expansion:** Stream AIO still uses `src/core/aio/` task helpers directly,
and WebDAV COPY/MOVE/TPC still post protocol-specific task structs. A future
phase can add a protocol-neutral thread-post wrapper if repeated queue-full
fallback handling continues to drift.

### 4.4 Shared HTTP Protocol Layer (WebDAV + S3)

**Current state:** WebDAV and S3 are implemented as separate nginx HTTP modules (`ngx_http_brix_webdav_module` and `ngx_http_brix_s3_module`) with independent config, dispatch, and handlers. They share ~60 functions in `src/core/compat/` but each module maintains its own entry point.

**Consolidation candidate:** Merge WebDAV and S3 into a single HTTP protocol handler that dispatches based on request URI pattern:
- `/brix/` → WebDAV (path-style DAV operations)
- `/bucket/key` → S3 (bucket-prefix matching)
- Common pre-processing pipeline for auth, path resolution, metrics

**Effort:** Medium-High — requires redesigning location configuration to support dual-mode operation. Would eliminate separate module registration and reduce config directive duplication. WebDAV and S3 handlers would share the same `ngx_http_module_t` context.

---

## 5. Implementation Priority Matrix

| Category | Opportunity | Effort | Impact | Priority |
|---|---|---|---|---|
| **Already Shared** | Document & maintain existing shared functions | Low | High | P0 — ongoing maintenance |
| Near-Shared | S3 body write → use `brix_http_body_write_to_fd()` | Done | Medium | Implemented |
| Near-Shared | WebDAV PUT staging → use `brix_staged_*()` helpers | Done | Medium | Implemented |
| Near-Shared | Unified path resolver in `src/core/compat/path.c` | Done | High | Implemented |
| Gap | Read-through cache for HTTP protocols | Done | High | Implemented |
| Gap | VOMS extraction for WebDAV auth | Done | Medium | Implemented |
| Gap | S3 WLCG bearer token auth | Deferred | Medium | Blocked by S3 auth invariant |
| Gap | Cross-protocol access logging labels | Done | Medium | Implemented |
| Gap | Dashboard cross-protocol visibility | Done | Medium | Implemented |
| Architecture | Shared HTTP async PUT lifecycle | Done | Medium | Implemented |
| Architecture | Shared protocol config preamble lifecycle | Done | Medium | Implemented |
| Architecture | Unified dispatch layer | High | Very High | P3 — major refactor |
| Architecture | WebDAV+S3 unified HTTP module | Medium-High | High | P3 — structural consolidation |
| Gap | Native TPC for S3 | Medium-High | High | P2 — transfer capability (remote URL CopyObject guarded with 501 NotImplemented) |

---

## 6. Key Invariants Affected by Consolidation

These existing invariants from AGENTS.md should be preserved or updated during consolidation:

| Invariant | Current Location | Impact of Consolidation |
|---|---|---|
| pgread/pgwrite → kXR_status(4007) framing + per-page CRC32c required | Stream only | Unchanged — stream-specific wire protocol |
| TLS: `b->memory=1` only; cleartext: file-backed+sendfile; never mix | All HTTP protocols | Preserved by shared http_file_response helpers |
| conf->allow_write checked globally before token scope | Stream, WebDAV, S3 | Already shared via `conf->common.allow_write` |
| All wire paths → resolve_path() before open() — no exceptions | Stream, WebDAV, S3 | **Enhanced** by unified resolver in Section 2.1 |
| DEL/MOVE/COPY on collections: recursively check child locks | WebDAV only | Could expand to stream via locking (Section 3.3) |
| S3 SigV4 ≠ WLCG token — never share auth logic | S3 only | Preserved — Section 3.4 is deferred by this invariant |
| Stat: use handle metadata; no extra path syscalls per read | Stream only | Unchanged — stream-specific optimization |
| Metric labels: low-cardinality only (no paths/bucket-names/UUIDs) | All protocols | Preserved by shared-memory zone design |

---

## 7. Files to Reference for Each Consolidation

### Path Resolution (Section 2.1)
- `src/fs/path/resolve_path_variants.c` — stream resolver variants
- `src/protocols/webdav/path.c` → URL-decodes then calls `brix_http_resolve_path()` — webdav wrapper
- `src/core/compat/path.c` → `brix_http_resolve_path()` — shared core logic
- `src/protocols/s3/util.c` → `s3_resolve_key()` — S3 key-to-path mapper

### Confined Ops (Section 1.2)
- `src/fs/path/resolve_confined_ops.c` — all confined helpers
- `src/protocols/webdav/webdav.h` — declarations for WebDAV callers
- `src/protocols/s3/s3.h` — declarations for S3 callers

### HTTP Response Building (Section 1.4)
- `src/core/http/http_file_response.c` — file response helpers
- `src/core/compat/range.c`, `range_vector.c` — range parsing
- `src/core/http/etag.c` — ETag generation

### Staged Files (Section 2.4)
- `src/core/compat/staged_file.c` — staged file helpers
- `src/protocols/s3/put.c` — current S3 staging usage
- `src/protocols/webdav/put.c` — current WebDAV inline staging

### Read-Through Cache (Section 3.1)
- `src/fs/cache/paths.c` — cache path resolution
- `src/fs/cache/README.md` — cache architecture overview
- `src/protocols/webdav/get.c` — target for cache integration
- `src/protocols/s3/object.c` — target for cache integration

### Token Validation (Section 1.1)
- `src/auth/token/validate.c` — shared JWT validation
- `src/auth/token/scopes.c` — scope checking
- `src/auth/gsi/token.c` — Stream token handler
- `src/protocols/webdav/auth_token.c` — WebDAV token handler

### Metrics (Section 1.9)
- `src/observability/metrics/metrics_macros.h` — shared metric macros
- `src/observability/metrics/metrics_internal.h` — shared-memory layout
- `src/observability/metrics/stream.c` — Prometheus exporter (iterates all protocols)

### Access Logging (Section 3.5)
- `src/observability/accesslog/access_log.c` — stream structured access lines with `proto=root`
- `src/core/compat/http_protocol_vars.c` — shared `$brix_protocol` HTTP variable
- `tests/configs/nginx_shared.conf` — shared `http_access.log` format with protocol labels
- `docs/08-metrics-monitoring/access-logging.md` — operator-facing log format reference

---

## 8. Testing Strategy for Consolidation Changes

For each consolidation, follow the existing 3-test pattern from AGENTS.md:
1. **Success test** — operation works as expected with new shared path
2. **Error test** — error case produces correct response via shared helper
3. **Security-neg test** — path escape / auth bypass / scope violation detected

Cross-protocol consolidation changes should also include:
4. **Cross-backend conformance** — verify behavior matches reference xrootd daemon (for stream) or XrdHttp module (for WebDAV) via `TEST_CROSS_BACKEND=nginx`
5. **Protocol parity test** — verify same operation produces equivalent results across all three protocols

---

## Appendix: Protocol Comparison Table

| Feature | Stream (XRootD) | WebDAV (HTTP/HTTPS) | S3 REST |
|---|---|---|---|
| Auth methods | Anonymous, GSI, WLCG token, SSS | Anonymous, GSI, WLCG token | SigV4, Anonymous |
| Path resolution | `brix_resolve_path()` variants | `ngx_http_brix_webdav_resolve_path()` | `s3_resolve_key()` |
| Confined ops | All helpers via `src/fs/path/` | All helpers via `src/fs/path/` | All helpers via `src/fs/path/` |
| File response | Wire framing (kXR_ok + data) | `brix_http_send_file_range()` | `brix_http_send_file_range()` |
| Range support | Offset+length in wire payload | HTTP Range header | HTTP Range header |
| TPC | SHM key registry (`src/tpc/`) | curl COPY (`src/protocols/webdav/tpc.c`) | Local copy (`brix_ns_local_copy()`) |
| Cache | Read-through (stream only) | No cache | No cache |
| Locking | ACL + scope enforcement | LOCK/UNLOCK (`src/protocols/webdav/lock.c`) | None |
| Multipart | kXR_prepare/kXR_sync pattern | WebDAV PUT with chunked upload | UploadPart + CompleteMultipartUpload |
| Metrics | Per-op counters via shared zone | Per-method counters via shared zone | Per-S3-op counters via shared zone |
| XML responses | ASCII stat body format | PROPFIND XML | ListObjectsV2, multipart XML |
| Directory sentinel | N/A (XRootD uses dirlist) | N/A (WebDAV uses MKCOL) | `.xrdcls3.dirsentinel` |
