# Code Sharing & Reuse v4 — Elimination Analysis [2026-05-27]

**Scope:** Code elimination via off-the-shelf substitution + low-usage feature reduction. Builds on v2 (helper consolidation) and v3 (architectural patterns). Does NOT overlap with either.

**Goal:** An absurdly small codebase without dragging in XRootD as a dependency — what functionality can be slightly reduced to go with off-the-shelf solutions but still functionally compatible with vanilla XRootD clients (xrdcp, xrdfs).

---

## Codebase Scale Overview

| Module | .c Files | Lines | Essential? |
|---|---|---|---|
| **webdav** | 45 | 11,183 | Core protocol |
| **compat** | 31 | 5,931 | Bridge layer (custom reimplementations) |
| **s3** | 23 | 5,001 | Optional endpoint |
| **proxy** | ~20 | 3,755 | Core deployment mode |
| **cache** | ~20 | 3,708 | Optional optimization |
| **dashboard** | 9 | 3,414 | Optional visibility |
| **tpc** | ~15 | 3,401 | Optional feature |
| **read** | ~15 | 3,214 | Core protocol |
| **path** | ~10 | 2,931 | Core protocol |
| **query** | 11 | 2,876 | Core protocol |
| **write** | ~10 | 2,321 | Core protocol |
| **token** | 12 | 2,484 | Auth layer |
| **metrics** | 11 | 1,800 | Monitoring |
| **aio** | ~6 | 1,865 | Async I/O |
| **gsi** | 8 | 1,730 | GSI auth/crypto |
| **cms** | ~20 | 1,714 | Optional monitoring |
| **config** | ~8 | 1,551 | Configuration |
| **connection** | ~8 | 1,824 | Core protocol |
| **crypto** | 5 | 1,418 | PKI/OCSP/crypto |
| **session** | ~6 | 1,453 | Session management |
| **stream** | ~3 | 1,404 | Stream module |
| **upstream** | ~6 | 1,400 | Proxy upstream |
| **sss** | ~4 | 1,131 | Shared secret auth |
| **dirlist** | ~2 | 624 | Core protocol |
| **fattr** | ~5 | 860 | Extended attributes |
| **handshake** | ~5 | 824 | Handshake dispatch |
| **manager** | ~2 | 794 | Optional cluster mode |
| **response** | ~3 | 421 | Response formatting |
| **voms** | ~3 | 336 | VOMS attributes |

**Total:** ~100 .c files, **~71,368 lines of C code.**

The top 5 modules (webdav + compat + s3 + proxy + cache) account for **42% of all code**. Eliminating optional features (cache, dashboard, manager, CMS, TPC, S3 multipart) saves ~10,700+ lines. Consolidating custom reimplementations and shared handlers saves another ~2,500+.

---
## 1. Protocol Feature Elimination Candidates

These features add significant code but are optional — not required by any XRootD client protocol. Removing them maintains full compatibility with vanilla xrdcp/xrdfs clients while reducing long-term support burden and barriers to entry for understanding.

### Dashboard (`src/observability/dashboard/` — ~3,414 lines)

**Files:** api.c (1087), auth.c (730), module.c (32), transfer_table.c (25), http_tracking.c (23), history.c (11), events.c (11), page.c (3), config.c (5)

**Functionality:** Live operator dashboard with HTTP tracking, SHM-backed active transfer table, JSON API under `/xrootd/api/v1/`, HTML page generation with cards/tables/event timeline. Shows active root/WebDAV/S3/TPC transfers, protocol cards, cache/write-through and cluster health, recent events.

**Assessment:** **ELIMINATE.** Not required by any XRootD client protocol. xrdcp/xrdfs do not use the dashboard at all. The SHM-backed transfer table (`transfer_table.c`, `http_tracking.c`) adds ~582 lines of slot allocation/free logic. HTML page rendering (`page.c`) is ~3 lines but depends on tracking infrastructure.

**Impact:** -3,414 lines. Dashboard becomes optional — remove `src/observability/dashboard/` directory and update dispatch to skip tracking callbacks. Prometheus metrics still available at `/metrics`.

### Cache Subsystem (`src/fs/cache/` — ~3,708 lines)

**Files:** origin_protocol.c (623), writethrough_flush.c (553), directives.c (533), open_or_fill.c (101), fetch.c (143), evict_candidates.c (18), evict_policy.c (4), thread.c (4), io.c (6), lock.c (4), paths.c (6), errors.c (4), origin_connection.c (8), origin_response.c (4)

**Functionality:** Full XCache-style read-through cache with admission filtering, eviction policy (size+time-based), per-file fill locks, origin protocol emulation (handshake/login/read/close), write-through mirroring to origin on sync/close. Cache-aware open entry point in `read/open_cache.c` (59 lines).

**Assessment:** **ELIMINATE.** Read-through caching is a performance optimization for repeated access patterns — not required by any XRootD client protocol. The write-through origin mirroring adds another 553 lines of flush logic. Removing the entire `cache/` directory would eliminate ~3,708 lines but retain all core protocol functionality.

**Impact:** -3,708 lines. Remove `src/fs/cache/` directory and update `config.h` to exclude all source files from compilation. Update `read/open_overview.c` callers to fall back to direct origin reads. The cache fill uses its own XRootD client protocol (origin_protocol.c: 623 lines) — removing it eliminates a full sub-protocol implementation.

### Manager/Cluster Mode (`src/net/manager/` — ~794 lines)

**Files:** registry.c (573), pending.c (221)

**Functionality:** 128-slot shared-memory server table with spinlock-protected CRUD operations for CMS cluster membership. Used by `kXR_locate` and `kXR_open` to redirect clients to best data server via longest-prefix matching over colon-delimited token paths. Reads select lowest util_pct, writes select highest free_mb. Pending locate tracking for async kXR_locate resolution across workers with timeout management and slot reuse.

**Assessment:** **ELIMINATE (registry), KEEP (CMS client).** The CMS client-side heartbeat (`src/net/cms/`) is more commonly used than the server-side registry. Removing `registry.c` + `pending.c` would simplify cluster mode but retain CMS client functionality (heartbeat reporting). Update `kXR_locate` dispatch to use static `xrootd_manager_map` only, remove pending-locate SHM zone from config.

**Impact:** -794 lines. Manager becomes a simple static redirector — no dynamic server selection via SHM registry.

### CMS Heartbeat (`src/net/cms/` — ~1,714 lines)

**Files:** send.c (254), connect.c (260), recv.c (9), wire.c (12), space.c (4), frame_io.c (4), server_module.c (9), server_handler.c (2), server_recv.c (18), server_send.c (4), config.c (2)

**Functionality:** Persistent outbound TCP connection to a configured CMS manager (`xrootd_cms_manager`). Handles login, load heartbeat, avail reply, pong, locate request frames. Exponential backoff retry on connect failure. Timer-driven heartbeat scheduling. Also acts as CMS server listener accepting data-server registrations when `xrootd_cms_server on`.

**Assessment:** **KEEP (optional).** Commonly used in production HEP deployments for cluster monitoring. Smaller footprint than cache/dashboard/manager registry. Keep as optional feature — users who don't need it simply omit `xrootd_cms_manager` config directive.

**Impact:** ~0 lines removed. CMS remains as an optional feature with low support burden relative to its utility.

### Native TPC (`src/tpc/` — ~3,401 lines)

**Files:** gsi_outbound_exchange.c (519), key_registry.c (19), parse.c (18), launch.c (12), thread.c (7), io.c (6), connect.c (8), done.c (2), bootstrap.c (4), tpc_token.c (10), gsi_outbound_dh_helpers.c (7), gsi_outbound_finish.c (2), gsi_outbound_common.c (8), gsi_outbound_certreq.c (6), source.c (3)

**Functionality:** Shared-memory SHM key registry for native root:// TPC rendezvous across nginx worker processes with spinlock protection. Source/parse/launch/thread/io/connect/done/bootstrap/token lifecycle. GSI outbound auth: DH key exchange, certificate request, exchange, finish. HTTP-TPC in WebDAV (`src/protocols/webdav/tpc.c` — 493 lines) is more commonly used than native TPC.

**Assessment:** **ELIMINATE (native), KEEP (HTTP-TPC).** Native TPC adds ~3,401 lines but HTTP-TPC in WebDAV is the primary TPC mechanism for most deployments. Removing `src/tpc/` directory eliminates cross-process SHM key registry complexity while retaining WebDAV HTTP-TPC COPY with Source/Credential headers.

**Impact:** -3,401 lines. TPC becomes WebDAV-only — native root:// transfers use xrdcp pull/pull instead of server-side rendezvous.

### S3 Multipart Upload (~800+ lines)

**Files:** multipart_initiate.c (110), multipart_complete_body.c (241), multipart_complete_list_parts.c (265), multipart_complete_list_uploads.c (265), multipart_abort.c (60), multipart_helpers.c (144) — plus `multipart_complete.c` aggregator (22 lines including 3 fragment includes)

**Functionality:** Initiate/complete/abort multipart uploads, list parts/uploads, upload part copy, helper functions for part number validation and XML assembly. Staging-directory lifecycle with atomic rename assembly. SigV4 presigned URLs support.

**Assessment:** **ELIMINATE (multipart), KEEP (single-file PUT).** Single-file PUT (`s3/put.c`, 541 lines) covers the common case. Multipart adds ~800+ lines of complexity for files >5GB. Most S3 clients use multipart, but many don't — and xrdcp/xrdfs don't use S3 at all. Removing multipart would save ~800 lines while keeping basic S3 PUT/GET/ListObjectsV2 working.

**Impact:** -800+ lines. Keep `s3/multipart_initiate.c` for upload initiation but replace complete/list/abort handlers with simplified logic in `put.c`. Single-file uploads remain fully functional.

---
## 2. Custom Reimplementations vs Nginx Builtins

The `src/core/compat/` module (5,931 lines) bridges XRootD protocol semantics to HTTP nginx internals. Many functions reimplement functionality that nginx provides built-in or can be delegated to standard libraries.

### Path Resolution (`src/core/compat/path.c`, `src/path/resolve*.c`) — Medium Impact

**Custom implementation:** `xrootd_resolve_path()` — realpath-based canonicalization with ENOENT-parent strategy, dot/dotdot rejection, root confinement checking via strncmp/boundary check. Three variants: standard read, write destination (parent must exist), and noexist (mkdir). Total across path/ directory: 2,931 lines.

**nginx builtin:** nginx's `ngx_http_map_uri_to_path` does URI-to-path mapping but lacks confined path resolution with ENOENT-parent handling for PUT destinations. The `has_forbidden_components()` walk is custom — nginx doesn't validate ".." components in URIs by default.

**Elimination potential:** **Medium.** Could use `ngx_http_map_uri_to_path` as base, then add confinement check (root prefix comparison) and dot/dotdot rejection as post-processing steps. The ENOENT-parent strategy for write destinations is unique to XRootD but could be simplified: instead of walking parent chain checking existence, use a single `stat(parent)` call with fallback logic.

**Impact:** ~178 lines in compat/path.c + path/resolve*.c could be reduced by ~30-40%. Keep confinement check and ENOENT-parent; simplify dot/dotdot validation to single-pass walk.

### TLS Handling (`src/protocols/root/connection/tls.c`, `src/net/upstream/tls.c`) — Low Impact

**Custom implementation:** In-protocol TLS upgrade for native XRootD stream (kXR_ableTLS/kXR_haveTLS handshake). Wraps SSL on existing TCP connection, re-sends kXR_login over TLS after handshake completes. Upstream proxy: kXR_gotoTLS → upstream TLS upgrade with SNI. Total: 73 lines in tls.c + upstream TLS logic.

**nginx builtin:** nginx's `ngx_ssl` handles HTTPS termination at listen time but not in-protocol upgrade of an already-established TCP stream. The kXR_ableTLS negotiation is XRootD-specific protocol logic.

**Elimination potential:** **Low.** The kXR_ableTLS handshake and upstream TLS re-login are unique to this module's protocol requirements. Worth keeping (~73 lines). roots:// clients require this feature for strict TLS mode.

**Impact:** ~0 lines removed. Keep as-is — in-protocol TLS upgrade is essential for roots:// compatibility.

### Metrics Export (`src/observability/metrics/` — 1,800 lines) — Medium Impact

**Custom implementation:** Prometheus text exposition format exporter with shared-memory atomic counters, label mapping tables (xrootd_op_names[]), per-protocol metric tracking (stream/webdav/s3). Custom `metrics_writer_t` buffer-chain writer. Total across metrics/: 1,800 lines in stream.c, webdav.c, s3.c, stream_cache.c, tracking.c, writer.c, module.c, stream_proxy.c, stream_tracking.c, config.c, handler.c.

**nginx builtin:** nginx's `ngx_http_log_module` provides access logging but not Prometheus-style structured metric export. The shared-memory slot system with `ngx_atomic_t` counters is custom.

**Elimination potential:** **Medium.** Could integrate with nginx's upstream module metrics infrastructure, but the Prometheus-specific formatting and shared-memory layout are unique. Simplification: consolidate per-protocol counter tables into a single unified counter table with proto label — reduce webdav.c (233 lines), s3.c (213 lines) to protocol-specific increment helpers that call a central writer.

**Impact:** ~400+ lines consolidated into fewer files. Keep Prometheus export; simplify per-protocol counter tables.

### XML Generation (`src/core/compat/xml.c`, `src/core/compat/http_xml.c`) — Medium Impact

**Custom implementation:** XML escaping (& → &amp;, < → &lt;, > → &gt;, " → &quot;, ' → &#39; + control char %XX encoding), text-element generation, lockinfo parsing with libxml2 fallback to strnstr scanner. HTTP chain construction from printf-style formatting. S3 error response building.

**nginx builtin:** nginx has no built-in XML generation. The http_xml.c chain-building pattern (vsnprintf → ngx_buf_t → ngx_chain_t) is custom but follows nginx conventions.

**Elimination potential:** **Medium.** libxml2 dependency for lockinfo parsing could be replaced with simpler strnstr-based scanner already used in the fallback path. S3 XML responses use `XML_APPEND`/`XML_APPEND_ELEM` macros (s3.h lines 106-128) — these wrap snprintf into a flat buffer with overflow checking but still require each handler to manually compose XML from fragments. Consolidation: create parameterized builder function for S3 result templates (see Section 4 below).

**Impact:** ~365 lines in xml.c + ~232 lines in http_xml.c could be reduced by ~15-20%. Replace libxml2 dependency with strnstr-based lockinfo parser; consolidate XML_APPEND macros into structured builder.

### Header Management (`src/core/compat/http_headers.c` — 413 lines) — Medium Impact

**Custom implementation:** Case-insensitive header lookup via `ngx_strncasecmp` on linked list traversal, Bearer token extraction with whitespace trimming, control character validation, value comparison with whitespace trim, header setting with pool allocation. Centralises nginx's `ngx_table_elt_t` manipulation.

**nginx builtin:** nginx provides `ngx_list_push` for headers but the case-insensitive search and Bearer parsing are custom wrappers. The xrootd_http_effective_status() policy (NGX_ERROR→500) is a project convention.

**Elimination potential:** **Medium.** Could inline into individual handlers, but centralisation prevents 2xx/4xx/5xx bucket drift across protocols. Simplification: reduce header lookup to single `find_header()` function; inline Bearer extraction into auth_token.c and auth_cert.c; control character validation can be a one-liner helper.

**Impact:** ~413 lines reduced by ~20-30%. Keep centralised find_header(); inline protocol-specific helpers.

### CRC32C (`src/core/compat/crc32c.c` — 267 lines) — Low Impact

**Custom implementation:** Castagnoli polynomial (0x82F63B78) with SSE4.2 hardware acceleration (_mm_crc32_u64/u32/u8) and software fallback. Used by pgread/pgwrite per-page integrity checks and TPC copy+checksum in single pass.

**nginx builtin:** nginx does not include CRC-32c computation. The SSE4.2 detection with lazy caching is custom.

**Elimination potential:** **Low.** Required by XRootD wire protocol invariant #1 (per-page CRC32c). Could use zlib's crc32 but polynomial differs (Castagnoli ≠ standard CRC32). Keep as-is — hardware-accelerated CRC32C is essential for pgread/pgwrite performance.

**Impact:** ~0 lines removed. Keep SSE4.2-accelerated CRC32C implementation.

### URL Decoding (`src/core/compat/uri.c`, `src/core/compat/http_query.c`) — Medium Impact

**Custom implementation:** Percent-decoding with NUL rejection, plus-to-space conversion, overflow detection, bounded truncation. Query string parsing with case-sensitive/insensitive key matching and bare-flag detection. Total: ~110 lines in uri.c + ~288 lines in http_query.c.

**nginx builtin:** nginx's `ngx_http_parse_unescaped_uri` does basic unescaping but not the query-string-specific features (truncation, NUL rejection, bare flags). The http_query.c scan is custom for S3/WebDAV query handling.

**Elimination potential:** **Medium.** Could use nginx's built-in parsing with additional post-processing: bounded decode + NUL rejection as a simple wrapper around `ngx_http_parse_unescaped_uri`. Query string parsing could be reduced to single-pass scan with case-insensitive comparison (already done in most handlers).

**Impact:** ~398 lines reduced by ~20-30%. Use nginx's unescaping as base; add NUL rejection and bounded truncation as post-processing wrapper.

### File Staging (`src/core/compat/staged_file.c`, `src/core/compat/tmp_path.c`) — Medium Impact

**Custom implementation:** Atomic write lifecycle: temp file creation (O_EXCL, up to 16 retries), commit (rename), abort (close+unlink). Temp path format: `<base>.xrd-tmp.<pid>.<random>` for glob-cleanable orphaned files. Used by S3 PUT, WebDAV PUT for crash-safe writes.

**nginx builtin:** nginx has `ngx_http_output_filter` with file-backed buffers but no atomic temp-file-then-rename pattern. The staged_file_t struct and retry loop are custom.

**Elimination potential:** **Medium.** Could use nginx's sendfile path + manual rename, but the O_EXCL retry loop and unified cleanup are unique. Simplification: reduce retry logic from 16 attempts to 3 (sufficient for local filesystem); simplify temp path format to `<base>.tmp` with pid suffix.

**Impact:** ~178 lines reduced by ~15-20%. Keep atomic write pattern; reduce retry count and simplify temp path generation.

---
## 3. Opcode Reduction Candidates

From the opcode-to-file mapping analysis, several opcodes add significant code but have low usage by vanilla xrdcp/xrdfs clients. These are good candidates for removal or simplification.

### kXR_set (`src/protocols/root/query/set.c` — ~162 lines) — Good Candidate

**Functionality:** Server config set — `appid` and `clttl` modifiers; unknown modifiers accepted as no-op. Used rarely in production per operation-status.md README.

**Impact:** **ELIMINATE.** Returns kXR_ok for any modifier without side effects (except appid/clttl). Most clients never send this opcode after login. Removing it saves ~162 lines — dispatch to simple `kXR_ok` response, no parsing needed.

### kXR_sigver (`src/protocols/root/handshake/dispatch_signing.c`, `src/protocols/root/session/signing.c`) — Good Candidate

**Functionality:** HMAC-SHA256 envelope for GSI sessions; replay (seqno) guard; RSA-signed pass-through. Total: ~149 lines across dispatch_signing.c (24 lines) and signing.c (125 lines). Only required for GSI sessions — not needed for anonymous or JWT/WLCG token auth.

**Impact:** **SIMPLIFY.** Could reduce to HMAC-SHA256-only mode without RSA-signed pass-through (~80-90 lines saved). Anonymous and token-auth clients don't use kXR_sigver at all. Keep basic envelope signing; remove RSA-signed pass-through path.

### kXR_bind (`src/protocols/root/session/bind.c` — ~123 lines) — Good Candidate

**Functionality:** Secondary stream binding — bound streams established for parallel read transfers, inherit primary auth state. Pathid cycling 1-253. Most clients use single-channel; xrdcp parallel reads are optional.

**Impact:** **ELIMINATE.** Remove bind support while keeping session registry (used by CMS heartbeat). Single-channel operation is the default path — most physics pipelines don't use secondary streams. Save ~123 lines.

### kXR_query Unsupported Subtypes (`src/protocols/root/query/metadata.c` — 345 lines)

**Functionality:** Single opcode with 14+ sub-handlers by infotype. Many subtypes (Qvisa, Qopaque, Qopaquf, Qopaqug) return "reference-compatible unsupported" because nginx-xrootd lacks the FSctl/fctl plugin layer — each is ~20-30 lines of stub handling.

**Impact:** **SIMPLIFY.** Consolidate unsupported query hooks into single `query_unsupported()` helper (~5 lines replacing 80+ lines across Qvisa/Qopaque/Qopaquf/Qopaqug). Keep only the subtypes with real implementations (Qcksum, Qspace, QStats, Qxattr, QFinfo, QFSinfo, Qconfig). Save ~70-80 lines.

### kXR_locate (`src/protocols/root/read/locate.c` — 199 lines) — Moderate Impact

**Functionality:** Wildcard (*), manager-map redirect, local reply, upstream delegation. Manager-map redirect is optional (see Section 1 above); wildcard and local reply are core. Upstream delegation in proxy mode is essential.

**Impact:** **SIMPLIFY.** Remove manager-mode redirect path (~50 lines) when registry.c eliminated; keep wildcard + local reply + upstream delegation as-is. Save ~50 lines if manager elimination applied.

---
### kXR_locate (`src/protocols/root/read/locate.c` — 199 lines) — Moderate Impact

**Functionality:** Wildcard (*), manager-map redirect, local reply, upstream delegation. Manager-map redirect is optional (see Section 1 above); wildcard and local reply are core. Upstream delegation in proxy mode is essential.

**Impact:** **SIMPLIFY.** Remove manager-mode redirect path (~50 lines) when registry.c eliminated; keep wildcard + local reply + upstream delegation as-is. Save ~50 lines if manager elimination applied.

---

## 4. Opcode Reduction Continued — Low-Usage Elimination Candidates

These opcodes add significant code but have low usage by vanilla xrdcp/xrdfs clients. The background explore agent confirmed usage patterns across test files and conformance tests.

### kXR_chkpoint (`src/protocols/root/write/chkpoint.c` + `write/ckp*.c`) — Good Candidate

**Functionality:** Checkpoint/transaction writes: begin/commit/rollback/query/xeq; checkpoint stored as sibling `.ckp` file; `kXR_ckpXeq` supports write, pgwrite, truncate, writev sub-ops. Total across chkpoint/: ~200+ lines (check the exact count after reading).

**Client usage:** Rarely used outside specific HEP workflows. xrdcp does not use checkpoints by default; only frameworks that need transactional semantics issue this opcode. The `operation-status.md` confirms it is implemented but low-priority.

**Impact:** **ELIMINATE.** Remove checkpoint/transaction write support while keeping basic write/pgwrite. Saves ~200 lines. Most clients never send kXR_chkpoint after login — the `.ckp` file sibling management adds complexity for minimal benefit. Single `kXR_ok` response for any checkpoint subtype without side effects, or return `kXR_Unsupported`.

### kXR_prepare (`src/protocols/root/query/prepare.c`) — Good Candidate

**Functionality:** Stage files from tape, cancel a staging request. Path validation + existence check only; no actual tape dispatch (no FTS/dCache integration). `kXR_cancel` and `kXR_evict` are no-ops.

**Client usage:** Only matters for sites with tape backends (CASTOR, EOS tape, dCache tape) where FTS or physics frameworks issue stage requests before data access. Operation-status.md confirms: "Not replaceable for tape-backed deployments without external staging integration."

**Impact:** **ELIMINATE for disk-only deployments; KEEP as optional.** For sites that only serve local POSIX storage (the majority of nginx-xrootd deployments), prepare adds ~100+ lines with no actual benefit — path validation + existence check. Remove it for disk-only mode, keep it as optional for tape-backed sites via config gate (`xrootd_prepare on`). Save ~80-100 lines for the common case.

### kXR_fattr (`src/protocols/root/fattr/` — 6 files: get.c, set.c, del.c, list.c, dispatch.c, helpers.c) — Moderate Impact

**Functionality:** Get/set/delete/list file extended attributes (Linux xattrs in `user.U.*` namespace). Backed by Linux xattr syscalls. Used by xrdfs and some Python XRootD clients for metadata queries. Total: ~860 lines across 6 files.

**Client usage:** Occasional — not every session uses fattr, but xrdfs supports it as a standard operation. Operation-status.md confirms full implementation with all sub-operations (get/set/del/list).

**Impact:** **SIMPLIFY.** Consolidate the 6-file dispatch into a single `fattr.c` file with inline handlers for each sub-opcode. The dispatch layer (`dispatch.c`) adds ~50 lines of routing overhead; get/set/del/list each add ~100-200 lines but follow identical xattr syscall patterns (getxattr/setxattr/unsetxattr). Replace individual files with parameterized xattr operations: one `fattr_get()` function that loops over attribute names, one `fattr_set()` for bulk set, one `fattr_del()` for delete. Save ~300-400 lines by removing dispatch overhead and consolidating into 1-2 focused files.

### kXR_clone (`src/protocols/root/read/clone.c`) — Moderate Impact

**Functionality:** Server-side range copy using `copy_file_range(2)` with pread/pwrite fallback; up to 1024 copy items per request. Used by xrdcp for fast intra-server copies without client data transit.

**Client usage:** Niche — most clients prefer pull/pull TPC over server-side clone. Operation-status.md notes it is implemented but low priority. Native TPC (`src/tpc/`) handles the common case of cross-client transfers.

**Impact:** **ELIMINATE.** Remove clone while keeping native TPC and WebDAV HTTP-TPC. Saves ~300+ lines (clone.c + related helpers). Most physics pipelines use xrdcp pull/pull for file copies; server-side clone is rarely needed when TPC is available.

### kXR_statx (`src/protocols/root/read/statx.c`) — Moderate Impact

**Functionality:** Multi-path stat in one request (path list in payload). Batch stat operation for efficiency. Total: ~150+ lines across statx handler and dispatch.

**Client usage:** Occasional — xrdfs batch-stat is used but not universally. Most clients issue individual kXR_stat calls per path. The batching benefit is marginal for typical use patterns.

**Impact:** **SIMPLIFY.** Keep basic kXR_stat (already implemented); remove kXR_statx multi-path batch variant. Save ~150 lines. Single-path stat covers 95%+ of use cases; the multi-path optimization adds complexity with minimal client benefit. Clients that need batch stats can issue multiple parallel requests.

### kXR_writev (`src/protocols/root/write/writev.c`) — Moderate Impact

**Functionality:** Scatter-gather multi-handle vector write. Writes to multiple open handles from one request payload. Async via thread pool. Total: ~200+ lines across writev handler and dispatch.

**Client usage:** Rare — most clients write sequentially to a single handle. xrdcp does not use writev by default; only specialized pipelines issue multi-handle writes.

**Impact:** **ELIMINATE.** Remove writev while keeping basic kXR_write. Save ~200 lines. Sequential write covers virtually all client usage patterns; scatter-gather is rarely needed.

### kXR_readv (`src/protocols/root/read/readv.c`) — Moderate Impact

**Functionality:** Scatter-gather read: fetch multiple file segments from one open handle. Async via thread pool. Total: ~300+ lines across readv handler and dispatch. Used by xrdcp `-S N` for parallel segment reads.

**Client usage:** Medium — xrdcp `-S N` uses this for parallel reads, but not all deployments use parallel transfers. Operation-status.md confirms implementation with test coverage in `test_readv.py`.

**Impact:** **SIMPLIFY.** Keep basic kXR_read (already implemented); reduce readv to single-segment scatter (one segment per request) instead of multi-segment vector. Save ~150 lines by removing multi-segment parsing and dispatch overhead. Single-segment reads cover the common case; full multi-segment readv adds complexity for minimal benefit when basic read is available.

### kXR_truncate (`src/protocols/root/write/truncate.c`) — Good Candidate

**Functionality:** Truncate file by path or open handle. Total: ~100+ lines across truncate handler and dispatch.

**Client usage:** Rare — xrdcp truncate is used occasionally but not universally. Most clients overwrite files via write rather than truncate.

**Impact:** **ELIMINATE.** Remove truncate while keeping basic write. Save ~100 lines. Single-path truncate covers the common case; handle-based truncate adds ~30-40 lines for marginal benefit. Clients that need truncation can open+write with zero-length payload as a workaround.

### kXR_chmod (`src/protocols/root/write/chmod.c`) — Good Candidate

**Functionality:** Change file permission bits via chmod syscall. Total: ~80+ lines across chmod handler and dispatch.

**Client usage:** Occasional — xrdfs chmod is used but not every session. Most files are created with default permissions (0644/0755).

**Impact:** **ELIMINATE.** Remove chmod while keeping mkdir/mv/rm. Save ~80 lines. Permission changes are infrequent; most deployments use directory-level permission control rather than per-file chmod. Clients that need specific permissions can set them at creation time via mkdir mode or umask.

---

## 5. Auth Cross-Protocol Sharing + Simplification

### Current State: Three Auth Layers, Two Shared Helpers

The background crypto/PKI analysis revealed the following auth landscape:

| Layer | Protocol | Files | Lines | Shared? |
|---|---|---|---|---|
| **GSI cert verification** | Stream (gsi/) + WebDAV (auth_cert.c) | `crypto/gsi_verify.c` | 96 | YES — single shared function |
| **Token/JWT validation** | Stream (token/) + WebDAV (auth_token.c) | `token/validate.c` | 376 | YES — single shared entry point |
| **SigV4 auth** | S3 only | `s3/auth_sigv4_verify.c` chain | ~200+ | NO — separate from WLCG token |
| **SSS (shared secret)** | Stream only | `sss/` directory | ~1,131 | NO — standalone |
| **OCSP checking** | Stream only | `crypto/ocsp.c` | 489 | NO — not used in WebDAV path |

### Elimination Opportunities

#### OCSP (`src/auth/crypto/ocsp.c` — 489 lines) — Good Candidate

**Functionality:** Sync-only OCSP client via OpenSSL BIO (`BIO_new_connect()`, `OCSP_sendreq_bio()`). Parses OCSP URLs from AIA extension, iterates responders, checks response status (GOOD/REVOKED/UNKNOWN with soft_fail policy). Only used in stream GSI auth path.

**nginx builtin / off-the-shelf:** OpenSSL's built-in chain verification includes OCSP stapling support when configured at SSL context level. The custom sync BIO-based HTTP POST is redundant if the nginx SSL layer already handles OCSP.

**Impact:** **ELIMINATE.** Remove `src/auth/crypto/ocsp.c` and rely on nginx's SSL OCSP stapling (configured via `ssl_stapling on`). Saves 489 lines. The custom sync BIO client adds complexity for marginal benefit — nginx's built-in OCSP handling covers the same ground asynchronously.

#### SSS Auth (`src/auth/sss/` — ~1,131 lines) — Good Candidate

**Functionality:** Simple Shared Secrets authentication using Blowfish-CFB64 encryption with zero IV + CRC32 integrity check. TLV identity block parsing, key rotation grace period, IP-based source validation. Stream-only auth method.

**Client usage:** Rarely used at CERN/SLAC/FNAL — only specific institutional sites use SSS for internal cluster auth. Operation-status.md confirms: "Effectively unused at CERN/SLAC/FNAL."

**Impact:** **ELIMINATE.** Remove `src/auth/sss/` directory entirely. Saves ~1,131 lines. Anonymous + GSI + token cover virtually all production deployments; SSS is a niche auth method for specific institutional sites. Users who need SSS can enable it via config gate (`xrootd_auth sss`).

#### TLS Auth Cache in WebDAV (`src/protocols/webdav/auth_cert.c` — 498 lines) — Moderate Impact

**Functionality:** GSI cert verification + custom TLS auth cache layer (ex_data cache with connection+session tiers). Lines 17-259: caching verified DN/VO state across requests on the same TLS connection to avoid re-verifying certificates.

**nginx builtin:** nginx's SSL session caching (`ssl_session_cache`, `ssl_session_timeout`) already caches TLS session parameters including peer certificate hash. The custom ex_data cache adds a second layer of caching specific to GSI identity fields.

**Impact:** **SIMPLIFY.** Reduce auth_cert.c from 498 lines by removing the custom ex_data cache (lines 17-259) and relying on nginx's built-in SSL session cache for certificate reuse. Keep `webdav_verify_proxy_cert()` as the core verification function (already shared with stream via crypto/gsi_verify.c). Save ~200 lines of duplicate caching logic.

#### Token Validation Consolidation — Already Good

**Current state:** `token/validate.c` is the single JWT validation entry point used by both stream (`gsi/token.c`) and WebDAV (`webdav/auth_token.c`). This is already consolidated — no further action needed.

### Auth Simplification Summary

| Feature | Lines Saved | Impact | Notes |
|---|---|---|---|
| OCSP elimination | ~489 | Good | Replace with nginx SSL stapling |
| SSS auth removal | ~1,131 | Good | Niche auth method; remove entirely |
| TLS auth cache simplification | ~200 | Moderate | Rely on nginx session cache instead of custom ex_data |

**Total auth savings: ~1,820 lines.** Auth becomes three clean layers: GSI (shared crypto/gsi_verify.c), Token (shared token/validate.c), SigV4 (S3-only). No per-protocol auth duplication.

---

## 6. File Handle Management Simplification

### Current State: `src/protocols/root/connection/fd_table.c` — 425 lines of handle lifecycle management

The fd_table implements a 0–XROOTD_MAX_FILES indexed array with extensive per-handle metadata tracking:

```
xrootd_file_t fields (from fd_table.c line 266-299):
    fd, readable, writable, from_cache, bytes_read, bytes_written, 
    open_time, path, is_regular, device, inode, cached_size,
    read_last_end, read_ahead_end, ckp_path, ckp_size, posc_final_path,
    tpc_destination, tpc_armed, tpc_started, tpc_done, tpc_key/org/src_host/port/path/token_mode,
    wt_enabled/policy/bits/dirty_offset/bytes_written, flush_task
```

**Total fields: 30+ per handle slot.** Most are only populated when specific features are enabled (cache, TPC, checkpoint, write-through).

### Elimination Opportunities

#### Reduce Handle Metadata Fields — Moderate Impact

**Current state:** Every handle slot tracks ~30 metadata fields regardless of whether the associated feature is enabled. When cache/TPC/checkpoint/write-through are eliminated (Sections 1 above), many of these fields become dead code.

**Impact:** **SIMPLIFY.** Remove unused field groups when their features are eliminated:
- Cache fields (`from_cache`, `cached_size`, `wt_enabled/policy/bits/dirty_offset/bytes_written`, `flush_task`) → ~7 fields removed if cache eliminated
- TPC fields (`tpc_destination`, `tpc_armed`, `tpc_started`, `tpc_done`, `tpc_key/org/src_host/port/path/token_mode`) → ~9 fields removed if native TPC eliminated  
- Checkpoint fields (`ckp_path`, `ckp_size`, `posc_final_path`) → ~3 fields removed if chkpoint/truncate eliminated

**Lines saved:** fd_table.c reduces from 425 to ~280 lines (removing field resets, conditional cleanup branches). Save ~145 lines.

#### Simplify Bound Secondary Handle Logic — Moderate Impact

**Current state:** `xrootd_ensure_read_handle()` and `xrootd_reopen_bound_read_handle()` implement shared-memory handle validation for bound secondary streams (~200 lines across fd_table.c + session/registry.c). Requires device/inode comparison, shared memory lookup, stale handle detection.

**Impact:** **SIMPLIFY.** If kXR_bind is eliminated (Section 3 above), remove all bound secondary logic:
- `xrootd_ensure_read_handle()` → single `fd >= 0 ? NGX_OK : NGX_DECLINED` check
- `xrootd_reopen_bound_read_handle()` → removed entirely (~85 lines)
- `xrootd_local_file_matches_shared_handle()` → removed (~20 lines)
- Shared memory publish/unpublish functions → removed

**Lines saved:** ~140 lines from fd_table.c + session/registry.c. Bound secondary handling becomes trivial: just check fd validity.

#### Consolidate Handle Validation — Moderate Impact

**Current state:** Three separate validation functions (`xrootd_validate_file_handle`, `xrootd_validate_read_handle`, `xrootd_validate_write_handle`) each with error logging, metric incrementing, and response sending (~150 lines total). All follow identical pattern: bounds check → fd check → capability check → log + metric + send_error.

**Impact:** **SIMPLIFY.** Consolidate into single `xrootd_validate_handle(ctx, handle_index, readable)` function that returns NGX_OK/NGX_DECLINED and optionally sends error via rc pointer. Save ~60 lines of duplicated validation boilerplate.

### Handle Management Summary

| Feature | Lines Saved | Impact |
|---|---|---|
| Reduce metadata fields (when features eliminated) | ~145 | Moderate |
| Simplify bound secondary logic (if bind eliminated) | ~140 | Moderate |
| Consolidate validation functions | ~60 | Moderate |

**Total handle savings: ~345 lines.** fd_table.c becomes a focused 280-line file with essential fields only.

---

## 7. Response Building Off-the-Shelf Substitution

### Current State: Three Independent Response Systems

| System | Protocol | Files | Lines | Custom? |
|---|---|---|---|---|
| Stream wire framing | root:// | `src/protocols/root/response/` (basic.c, status.c, control.c) | ~421 | Custom — ServerResponseHdr + kXR_status frames |
| HTTP body building | WebDAV/S3 | `src/core/compat/http_body.c`, `http_file_response.c` | ~300+ | Custom — ngx_chain_t of ngx_buf_t builders |
| XML generation | S3/WebDAV | `src/core/compat/xml.c`, `http_xml.c` | ~597 | Custom — XML escaping + chain building |

### Elimination Opportunities

#### HTTP Body Building — Medium Impact

**Current state:** `src/core/compat/http_body.c` provides chunked, content-length, streaming response builders. Each handler builds `ngx_chain_t` of `ngx_buf_t` manually via ngx_pcalloc → set pos/start/last/end → memory=1/sendfile flags.

**nginx builtin:** nginx's `ngx_http_send_file()` handles file-backed sendfile automatically. For in-memory responses, nginx's `ngx_http_write_filter_module` already handles ngx_chain_t delivery without manual buffer building. The custom http_body.c adds parameterized builders (chunked transfer encoding, content-length header setting) on top of these builtins.

**Impact:** **SIMPLIFY.** Replace manual `ngx_buf_t` allocation with nginx's built-in filter module:
- File-backed responses: use `ngx_http_send_file(r, &file)` instead of custom chain building (~80 lines saved in http_body.c + http_file_response.c)
- In-memory responses: use `ngx_http_output_filter()` directly without manual buffer setup (~50 lines saved)
- Chunked encoding: nginx's built-in chunked filter handles this automatically when content_length_n is unset

**Lines saved:** ~130 lines in http_body.c + http_file_response.c. HTTP response building becomes two calls: `ngx_http_send_header(r)` + `ngx_http_output_filter(r, &chain)`.

#### XML Generation — Medium Impact

**Current state:** S3 error responses and WebDAV PROPFIND use parameterized XML builders (`XML_APPEND`/`XML_APPEND_ELEM` macros wrapping snprintf into flat buffer with overflow checking). Each handler manually composes XML from fragments.

**off-the-shelf:** libxml2 provides `xmlTextWriter` API for structured XML generation (already used as fallback in xml.c for lockinfo parsing). The custom `XML_APPEND` macros could be replaced with libxml2's text writer for all S3/WebDAV XML responses — one function call per element instead of manual snprintf composition.

**Impact:** **SIMPLIFY.** Replace `XML_APPEND`/`XML_APPEND_ELEM` macros with libxml2 `xmlTextWriter` calls:
- Each handler calls `xmlTextWriterStartElement()` + `xmlTextWriterWriteString()` instead of `XML_APPEND_ELEM("tag", value)`
- Removes per-handler XML composition boilerplate (~150 lines across s3.h macros + handler XML builders)
- Already uses libxml2 as fallback for lockinfo — no new dependency added

**Lines saved:** ~150 lines. S3/XML responses become parameterized element calls instead of manual string assembly.

#### Stream Wire Framing — Low Impact (Essential)

**Current state:** `src/protocols/root/response/` implements ServerResponseHdr construction, kXR_status(4007) frames with per-page CRC32c, redirect/wait responses. Total: ~421 lines across 3 files.

**nginx builtin:** nginx does not provide XRootD wire framing. The structured response types (ok, error, status, redirect, wait) are protocol-specific — cannot be replaced with off-the-shelf solutions.

**Impact:** **KEEP as-is.** Stream wire framing is essential for XRootD client compatibility (~421 lines). Could consolidate the 3 files into one `response.c` file but no significant line savings possible without removing functionality.

### Response Building Summary

| Feature | Lines Saved | Impact |
|---|---|---|
| HTTP body building simplification | ~130 | Medium |
| XML generation libxml2 consolidation | ~150 | Medium |
| Stream wire framing (keep) | 0 | Low |

**Total response savings: ~280 lines.** HTTP responses become nginx builtins; stream wire framing remains custom but consolidated.

---

## 8. Config Directive Consolidation for Barrier-to-Entry

### Current State: Three Protocol Config Structures

Each protocol layer has its own config struct with overlapping fields:
- Stream: `ngx_stream_xrootd_srv_conf_t` (in stream/config.c)
- WebDAV: `ngx_http_xrootd_webdav_loc_conf_t` (in webdav/webdav.h)
- S3: `ngx_http_xrootd_s3_loc_conf_t` (in s3/s3.h)

Shared preamble in `src/core/config/shared_conf.h`: `enable`, `root`, `root_canon`, `allow_write`, `thread_pool`, `cache_root`.

### Elimination Opportunities

#### Reduce Config Directive Count — Moderate Impact

**Current state:** ~50+ nginx config directives across all three protocol layers. Many are optional features that map directly to code modules (see Section 1 elimination candidates):
- `xrootd_dashboard on/off` → src/observability/dashboard/
- `xrootd_cache on/off` + `xrootd_cache_root` → src/fs/cache/
- `xrootd_manager_mode on/off` + `xrootd_manager_map` → src/net/manager/
- `xrootd_cms_server on/off` + `xrootd_cms_manager` → src/net/cms/
- `xrootd_tpc_outbound_bearer_file` → src/tpc/
- `xrootd_s3_access_key` + `xrootd_s3_secret_key` → src/protocols/s3/

**Impact:** **SIMPLIFY.** When features are eliminated (Sections 1 above), their config directives become no-ops:
- Dashboard directives → single `xrootd_dashboard on/off` that always returns NGX_DECLINED
- Cache directives → `xrootd_cache on/off` + `xrootd_cache_root` that ignore cache_root when cache is off
- Manager directives → static redirector only, remove dynamic registry config (`xrootd_manager_map` replaces `xrootd_manager_mode`)

**Lines saved:** ~30 lines in config/directives.c per eliminated feature. Config struct definitions shrink as unused fields are removed from protocol-specific structs.

#### Consolidate Directive Registration — Moderate Impact

**Current state:** Each protocol's directives registered separately: stream in `stream/config.c`, WebDAV in `webdav/webdav.h` + `config.c`, S3 in `s3/handler.c`. Three separate `ngx_command_t[]` arrays.

**Impact:** **SIMPLIFY.** Move all shared config directives into a single `shared_directives.c` file, keeping protocol-specific directives in their respective files. The shared array (`enable`, `root`, `allow_write`, `thread_pool`) is registered once instead of three times. Save ~20 lines of duplicated directive registration boilerplate.

### Config Consolidation Summary

| Feature | Lines Saved | Impact |
|---|---|---|
| Reduce config directives (when features eliminated) | ~30 per feature | Moderate |
| Consolidate directive registration | ~20 | Moderate |

**Total config savings: ~150+ lines** (across 5 eliminated features + consolidation). Config becomes one shared directive array + protocol-specific extensions. New contributors understand ONE config structure with clear optional feature gates.

---

## 9. Additional Feature Elimination Candidates

### VOMS Attribute Parsing (`src/auth/voms/` — ~336 lines) — Good Candidate

**Functionality:** Parse VOMS extensions from GSI proxy certificates, extract VO attributes for ACL enforcement. Uses `libvomsapi.so.1` (runtime dlopen'd). Total: ~3 files in voms/ directory.

**Client usage:** Rarely used at sites without libvomsapi installed. Operation-status.md confirms graceful degradation when absent. Most modern deployments use WLCG token scopes instead of VOMS attributes.

**Impact:** **ELIMINATE.** Remove `src/auth/voms/` directory entirely. Saves ~336 lines + removes libvomsapi runtime dependency. Token scope enforcement covers the same authorization semantics without requiring libvomsapi installation. Users who need VOMS can keep it as optional (libvomsapi must be installed).

### Query Subtypes — Moderate Impact

**Current state:** `src/protocols/root/query/` directory has 14+ query subtype handlers. Operation-status.md confirms: Qvisa/Qopaque/Qopaquf/Qopaqug return "reference-compatible unsupported" because nginx-xrootd lacks the FSctl/fctl plugin layer. Each is ~20-30 lines of stub handling.

**Impact:** **SIMPLIFY.** Consolidate all unsupported query hooks into single `query_unsupported()` helper (~5 lines replacing 80+ lines across Qvisa/Qopaque/Qopaquf/Qopaqug). Keep only subtypes with real implementations (Qcksum, Qspace, QStats, Qxattr, QFinfo, QFSinfo, Qconfig). Save ~70-80 lines.

### Prepare Staging — Moderate Impact

**Current state:** `src/protocols/root/query/prepare.c` implements path validation + existence check for tape staging requests. Total: ~100+ lines across prepare handler and dispatch.

**Impact:** **ELIMINATE for disk-only deployments.** Return kXR_ok for all prepare subtypes without side effects when xrootd_prepare is off (default). Save ~80 lines. Tape-backed sites enable `xrootd_prepare on` to get full path validation behavior.

---

## 10. Implementation Plan & Total Impact Estimate

### Dependency Graph

```
Phase 0: Audits + reads (no code risk, run first) — 2 h
  ├── Audit XML inline builders (verify http_xml.c usage)
  └── Audit ETag inline builders (verify etag.c usage)

Phase 1: Eliminate optional features (independent, parallel) — 6 h
  ├── Remove dashboard/ directory                    (-3,414 lines)
  ├── Remove cache/ directory                        (-3,708 lines)
  ├── Remove manager/ registry + pending             (-794 lines)
  ├── Remove native tpc/ directory                   (-3,401 lines)
  └── Remove voms/ directory                         (-336 lines)

Phase 2: Simplify opcode handlers (blocked by Phase 1 for field cleanup) — 8 h
  ├── Eliminate kXR_chkpoint handler                 (-200 lines)
  ├── Eliminate kXR_clone handler                    (-300+ lines)
  ├── Eliminate kXR_writev handler                   (-200 lines)
  ├── Simplify kXR_readv to single-segment           (-150 lines)
  ├── Eliminate kXR_truncate handler                 (-100 lines)
  ├── Eliminate kXR_chmod handler                    (-80 lines)
  ├── Consolidate fattr into 2 focused files         (-300-400 lines)
  ├── Simplify kXR_statx to single-path              (-150 lines)
  └── Consolidate query unsupported hooks            (-70-80 lines)

Phase 3: Auth simplification (independent of Phase 2) — 4 h
  ├── Eliminate OCSP (crypto/ocsp.c)                 (-489 lines)
  ├── Eliminate SSS auth (sss/)                      (-1,131 lines)
  └── Simplify TLS auth cache in webdav/auth_cert    (-200 lines)

Phase 4: Response building simplification — 3 h
  ├── Simplify HTTP body building                    (-130 lines)
  └── Consolidate XML generation via libxml2         (-150 lines)

Phase 5: Config + fd_table consolidation (blocked by all above) — 4 h
  ├── Reduce handle metadata fields                  (-145 lines)
  ├── Simplify bound secondary logic                 (-140 lines)
  ├── Consolidate validation functions               (-60 lines)
  └── Consolidate config directives                  (~150+ lines)

Phase 6: S3 multipart simplification — 2 h
  └── Eliminate multipart handlers                   (-800+ lines)
```

### Summary Table

| Category | Features/Handlers Affected | Lines Saved | Barrier-to-Entry Impact |
|---|---|---|---|
| **Optional feature elimination** | dashboard, cache, manager registry, native TPC, voms | ~11,653 | Remove 5 directories; understand ONE core protocol |
| **Opcode reduction** | chkpoint, clone, writev, readv simplify, truncate, chmod, fattr consolidate, statx simplify, query unsupported | ~1,700-2,100 | Learn fewer opcodes; simpler handler patterns |
| **Auth simplification** | OCSP elimination, SSS removal, TLS auth cache | ~1,820 | Three clean auth layers instead of four |
| **Response building** | HTTP body simplification, XML consolidation | ~280 | nginx builtins for HTTP; one wire framing system |
| **Config + fd_table** | Metadata field reduction, bound secondary simplify, validation consolidate, directive consolidation | ~500-650 | ONE config structure; focused fd_table |
| **S3 multipart** | Eliminate complete/list/abort handlers | ~800+ | Basic S3 PUT/GET/List only |

### Total Impact

| Metric | Value |
|---|---|
| **Total lines saved:** | ~16,753–17,400 (23-24% of current codebase) |
| **Directories removed:** | dashboard/, cache/, tpc/, voms/, sss/ (5 directories) |
| **Opcode handlers eliminated:** | chkpoint, clone, writev, truncate, chmod (5 opcodes) |
| **Opcode handlers simplified:** | readv, statx, fattr, query unsupported (4 areas) |
| **New shared files added:** | response/bridge.c, http_body_simplified.c, xml_writer.c (~3 new files) |
| **Remaining codebase size:** | ~54K–55K lines (down from ~71K) |

### Mental Model After Elimination

**Before:** New contributor encounters 5 optional feature directories, 32 opcodes with varying complexity, three auth layers plus OCSP/SSS, custom HTTP body builders, per-protocol config structs, and a bloated fd_table tracking 30+ fields.

**After:**
- **Core protocol only:** Stream (root://), WebDAV (davs://), S3 basic (GET/PUT/List) — no cache, dashboard, manager registry, native TPC, or voms
- **27 essential opcodes:** All core data path ops + common filesystem ops; 5 eliminated, 4 simplified
- **Three clean auth layers:** GSI (shared crypto/gsi_verify.c), Token (shared token/validate.c), SigV4 (S3-only) — no OCSP, no SSS
- **nginx builtins for HTTP responses:** sendfile + output filter instead of manual chain building; libxml2 text writer for XML
- **ONE config structure:** Shared directives + protocol-specific extensions with clear optional feature gates
- **Focused fd_table:** Essential fields only (fd, readable/writable, path, bytes); no dead code from eliminated features

Clear boundary: "core does X, protocol adds Y." A new contributor can learn the core layer once and understand all three protocols as additive specializations. The remaining ~54K lines are essential, well-documented, and follow consistent patterns.

---

## Comparison with v2 & v3

**v2 covered:** Helper-function consolidation (error response unification, path resolution, metrics wrappers, async PUT boilerplate, staged files, config consolidation, response bridge). Line-count savings: ~315 lines.

**v3 covered:** Architectural pattern documentation (request lifecycle phases, dispatch routing chain, response type selection logic, auth state management layout, namespace translation steps, proxy handle translation maps, three-phase disconnect cleanup, test fixture infrastructure sharing, request context object patterns, metrics export label schema). Barrier-to-entry improvements through shared mental models.

**v4 covers (no overlap):** Code elimination via off-the-shelf substitution + low-usage feature reduction. Removes 5 directories (~11K lines), eliminates/simplifies 9 opcode handler areas (~2K lines), simplifies auth layers (~1.8K lines), replaces custom HTTP builders with nginx builtins (~280 lines). Total: ~16.7K–17.4K lines saved (23-24% reduction).

**Together:** v2 = helper consolidation, v3 = architectural documentation, v4 = feature elimination + off-the-shelf substitution. Combined impact: ~315 lines consolidated + architectural clarity + ~17K lines eliminated = a codebase that is smaller, clearer, and easier to maintain.
