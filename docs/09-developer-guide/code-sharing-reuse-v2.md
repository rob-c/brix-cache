# Additional Code Sharing & Reuse Analysis v2 [2026-05-26]

**Follow-up to:** `cross-protocol-sharing-analysis.md`
**Focus:** Reducing long-term support burden and lowering barriers to entry for understanding the codebase.
**Method:** Exhaustive grep/ast-grep across all protocol layers + 8 parallel explore agents (wire framing, auth, config, async I/O, fd management, error handling, path utilities, TPC patterns).

---

## Executive Summary

The module has three protocol layers — XRootD stream (`src/`), WebDAV HTTP (`src/webdav/`), and S3 REST (`src/s3/`) — each with their own error pattern, path resolver, metric wrapper, async callback boilerplate, and staged file logic. Many of these are near-identical implementations that could be consolidated into `src/core/compat/` or `src/response/`, giving new contributors a clear mental model: **"common layer does X, protocol layer adds Y on top."**

### Estimated Impact

| Category | Files Affected | Lines Saved | Barrier-to-Entry Reduction |
|----------|---------------|-------------|---------------------------|
| Error response unification | s3/handler.c, webdav/dispatch.c, all stream handlers | ~80 lines | Learn ONE error pattern per protocol |
| Path resolution consolidation | webdav/path.c, s3/util.c | ~40 lines | One HTTP path resolver instead of two |
| Metrics wrapper consolidation | s3/metrics.c, s3/handler.c | ~20 lines | Single metric finalize call |
| Async PUT callback boilerplate | s3/put.c, webdav/put.c | ~60 lines | One async PUT flow instead of two |
| Staged file operations | s3/put.c | ~40 lines | One atomic write pattern for all protocols |
| Config field consolidation | config.h, directives.c, merge functions | ~30 lines | ONE common config struct |
| Response bridge (stream↔HTTP) | response/, compat/http_body.c | ~25 lines | Unified response abstraction |
| Verify existing shared helpers usage | s3/list.c, webdav/propfind.c, s3/put.c | ~15 lines | Audit + replace remaining inline builders |

**Total estimated savings:** ~315 lines of duplicated code across the module.

---

## Existing Shared Layers (Already Good)

### `src/core/compat/` — 32 files, cross-backend compatibility helpers

This directory already provides shared utilities used by native XRootD stream, WebDAV, and S3 paths:
- CRC32c (`crc32c.c`, `checksum.c`) — SSE4.2 hardware/software fallback, single-pass CRC+copy fusion
- Error mapping (`error_mapping.c`, `kxr_errno.c`) — errno→kXR-code, errno→HTTP-status, kXR_status→HTTP-status
- Path manipulation (`path.c`) — canonicalization, confinement checks, basename extraction
- XML generation (`http_xml.c`, `xml.c`) — S3 ListObjectsV2 and WebDAV PROPFIND responses
- HTTP body building (`http_body.c`, `http_file_response.c`) — chunked, content-length, streaming
- HTTP headers (`http_headers.c`) — header building across all protocols
- Range parsing (`range.c`, `range_vector.c`) — HTTP Range header for partial content
- Temp path generation (`tmp_path.c`) — temporary file name creation
- Staged file operations (`staged_file.c`) — `.part` creation, atomic rename to final name
- ETag computation (`etag.c`) — from file metadata (size + mtime)
- Logging (`log.c`) — structured access logging with `xrootd_sanitize_log_string()`

### `src/response/` — 4 files, XRootD wire response framing

Low-level building blocks for stream protocol wire responses:
- `basic.c` — `xrootd_build_resp_hdr`, `xrootd_send_ok`, `xrootd_send_error`
- `status.c` — `xrootd_send_pgwrite_status`, `xrootd_send_pgread_status` (kXR_status framing + CRC32c)
- `control.c` — `xrootd_send_redirect`, `xrootd_send_wait`
- `crc32c.c` — wire-facing CRC32C API delegated to `src/core/compat/crc32c.c`

### `src/core/config/shared_conf.h` — Common config fields

Already shares `conf->allow_write` across all protocol layers with unified merge (`NGX_CONF_UNSET → 0`). This is good existing consolidation.

---

## Detailed Analysis: Areas for Further Consolidation

### 1. Error Response Unification (Highest Impact)

**Current state:** Three independent error response paths with no shared wrapper:
- **Stream:** `xrootd_send_error(ctx, c, kXR_code, msg)` — direct wire framing (`src/response/basic.c`)
- **WebDAV:** Each handler builds HTTP status + optional XML body → calls `webdav_metrics_return()` to finalize (`src/webdav/dispatch.c` lines 37–181)
- **S3:** `s3_send_xml_error(r, http_status, error_code, message)` wrapper around `xrootd_http_send_xml_error()` (`src/s3/util.c:90`)

**Duplication observed:**
- S3 handler.c has 25+ identical patterns: `XROOTD_S3_METRIC_INC(event_slot); return s3_metrics_return_method(r, method_slot, s3_send_xml_error(...))` — same boilerplate repeated everywhere
- WebDAV dispatch.c has 18+ identical patterns: `return webdav_metrics_return(r, handler_func())` — metric wrap around every call
- Stream handlers have 50+ direct calls to `xrootd_send_error()` with no metric wrapping

**Proposal:** A unified error-return helper in `src/core/compat/error_response.c`:

```c
// Unified: maps errno → appropriate protocol response + metrics increment + return
ngx_int_t xrootd_protocol_error(ngx_http_request_t *r, ngx_uint_t method_slot, 
                                 int errno_val, const char *msg);
// Stream variant uses ctx/c instead of r
ngx_int_t xrootd_stream_error(xrootd_ctx_t *ctx, ngx_connection_t *c,
                               uint16_t kXR_code, const char *msg);
```

**Support burden reduction:** New contributors learn ONE error pattern per protocol layer instead of 3+ variants. S3 handler.c could shrink by ~40 lines of boilerplate repetition.

---

### 2. Path Resolution Triplet Consolidation

**Current state:** Three separate path resolution wrappers, each doing the same core work:
- **Stream:** `xrootd_resolve_path()`, `xrootd_resolve_path_write()`, `xrootd_resolve_path_noexist()` (`src/fs/path/resolve_path_variants.c`) — takes `ngx_str_t *root`
- **WebDAV:** `ngx_http_xrootd_webdav_resolve_path(r, root_canon, path)` → wraps `xrootd_resolve_path_input()` with URI decoding + slash stripping (`src/webdav/path.c:58`)
- **S3:** `s3_resolve_key(root, key, out, outsz)` → wraps `xrootd_resolve_path_input()` with URL decoding (`src/s3/util.c:50`)

**Duplication observed:** Both WebDAV and S3 wrappers do identical pre-processing steps:
1. Decode URI/key (WebDAV: `webdav_urldecode`; S3: via `xrootd_resolve_path_input` internal decode)
2. Strip trailing slashes
3. Call `xrootd_resolve_path_input(root_canon, decoded_path, out, outsz)`

**Proposal:** A single HTTP path resolver in `src/core/compat/http_path.c`:

```c
// Handles both WebDAV and S3: decodes URI → strips trailing slash → resolves
ngx_int_t xrootd_http_resolve_path(ngx_http_request_t *r, 
                                    const char *root_canon, ngx_str_t *uri,
                                    char *out, size_t outsz);
```

WebDAV's `path.c` and S3's `util.c` each lose ~20 lines of duplicated decode+strip logic. New contributors need to understand ONE HTTP path resolver instead of two near-identical ones.

---

### 3. Metrics Wrapper Consolidation

**Current state:** Three independent metric-finalize patterns:
- **S3:** `s3_metrics_method_slot()` → `s3_metrics_request_method()` → `s3_metrics_return_method()` → `s3_metrics_finalize_request_method()` — each adds a layer of wrapping (`src/s3/metrics.c`)
- **WebDAV:** `webdav_metrics_return(r, rc)` — single wrapper that increments requests_total + responses_total (`src/webdav/metrics.c:85`)
- **Stream:** No HTTP-style metric finalize; metrics are inline at each callsite via `XROOTD_SRV_METRIC_INC()`

**Duplication observed:** S3 handler.c has 20+ identical call chains: `s3_metrics_return_method(r, method_slot, handler_result)` — the same three-step wrap around every dispatch branch. WebDAV dispatch.c repeats `return webdav_metrics_return(r, ...)` on every method handler return.

**Proposal:** Consolidate S3's four-step chain into a single wrapper in `src/core/compat/http_metrics.c`:

```c
// Single call replaces the entire s3_metrics_* chain
ngx_int_t xrootd_http_metrics_finalize(ngx_http_request_t *r, 
                                        ngx_uint_t proto_slot, 
                                        ngx_int_t handler_rc);
```

S3 handler.c could reduce ~20 lines of repetitive metric wrapping. The four-step S3 chain becomes one call — significantly easier for new contributors to follow the dispatch flow.

---

### 4. Async Callback Boilerplate Reduction

**Current state:** Each protocol layer repeats identical async boilerplate:
- **Stream AIO:** `xrootd_pgread_aio_thread()` → `xrootd_pgread_aio_done()` callback pattern (`src/core/aio/pgread.c`)
- **WebDAV PUT:** Async body read → callback builds response chain (`src/webdav/put.c`)
- **S3 PUT:** `ngx_http_read_client_request_body()` → `s3_put_body_handler()` async callback (`src/s3/handler.c:160`, `src/s3/put.c`)

**Duplication observed:** All three follow the same pattern:
1. Set request context (fs_path stored in r->ctx)
2. Call nginx async body reader
3. Callback retrieves ctx, validates config, performs operation, builds response, increments metrics

The S3 PUT callback (`src/s3/put.c`) and WebDAV PUT handler share nearly identical structure: retrieve fs_path from ctx → validate conf→ write temp file → rename → stat → ETag → metrics → HTTP 200.

**Proposal:** A shared async PUT wrapper in `src/core/compat/http_put_async.c`:

```c
// Shared callback boilerplate for both WebDAV and S3 PUT operations
void xrootd_http_put_async_callback(ngx_http_request_t *r, ngx_int_t rc);
// Caller sets r->ctx with fs_path before calling ngx_http_read_client_request_body()
```

This eliminates ~60 lines of duplicated "retrieve ctx → validate conf → write temp → rename → stat → metrics" boilerplate between WebDAV PUT and S3 PUT. New contributors understand one async PUT flow instead of two near-identical ones.

---

### 5. Staged File Operations (Already Partially Shared)

**Current state:** `src/core/compat/staged_file.c` provides `.part` creation + atomic rename, used by cache fills and some write operations. But S3 PUT (`src/s3/put.c`) independently implements the same pattern:
- Generate tmp_path = fs_path.tmp.{pid}.{random}
- Open with O_WRONLY|O_CREAT|O_EXCL (16 retry attempts)
- Write body → close temp fd → rename to final path

WebDAV PUT (`src/webdav/put.c`) uses similar staged file logic via `staged_file.c` helpers.

**Duplication observed:** S3's temp-file loop in put.c is ~40 lines of independent implementation that duplicates what `staged_file.c` already provides (with the same O_EXCL + rename semantics).

**Proposal:** Replace S3's inline temp-file loop with calls to `src/core/compat/staged_file.c` helpers:

```c
// Use shared staged file instead of inline loop in s3/put.c
int tmp_fd = xrootd_staged_open(fs_path, r->pool);
xrootd_staged_write(tmp_fd, body_chain);
xrootd_staged_rename(tmp_fd, fs_path);
```

S3 put.c loses ~40 lines of duplicated staging logic. One shared staged file pattern serves cache, WebDAV, and S3 — new contributors need to understand one atomic write pattern for all protocols.

---

### 6. Config Field Consolidation (Already Partially Done)

**Current state:** `src/core/config/shared_conf.h` already has `conf->allow_write` shared across all protocol layers with unified merge (`NGX_CONF_UNSET → 0`). This is good existing consolidation.

**Opportunity:** Other fields that are duplicated across stream/webdav/s3 configs:
- `root_canon / root` — appears in each layer's config struct but serves the same purpose
- Auth-related settings (cert paths, JWKS paths) — repeated in webdav and s3 loc conf structs
- TLS settings — shared across all HTTP-layer protocols

**Proposal:** Extend `shared_conf.h` to consolidate ALL cross-protocol config fields into a single `ngx_xrootd_common_conf_t` struct:

```c
typedef struct {
    ngx_str_t          root_canon;      // export root for all protocols
    ngx_flag_t         allow_write;     // write gate (already shared)
    ngx_str_t          cert_path;       // GSI cert path
    ngx_str_t          jwks_uri;        // JWT verification
    ngx_uint_t         auth_timeout;    // auth timeout seconds
    // ... all fields shared across stream/webdav/s3
} ngx_xrootd_common_conf_t;
```

Each protocol's config struct contains `ngx_xrootd_common_conf_t common` as a prefix, and the merge function handles all shared fields in one pass instead of duplicating merge logic per layer. New contributors understand ONE config structure for cross-protocol settings instead of three separate structs with overlapping fields.

---

### 7. HTTP Response Building Bridge (Stream ↔ HTTP)

**Current state:** Two separate response building systems:
- **Stream wire framing:** `src/response/` — builds ServerResponseHdr, kXR_status frames, CRC32c wrapping (`basic.c`, `status.c`, `control.c`)
- **HTTP response building:** `src/core/compat/http_body.c`, `http_file_response.c` — builds ngx_chain_t of ngx_buf_t for HTTP responses

**Gap:** Stream handlers that serve HTTP-compatible responses (e.g., `/metrics` endpoint, dashboard) bridge between these systems manually. The wire framing system doesn't know about ngx_chain_t; the HTTP body system doesn't know about kXR_status frames.

**Proposal:** A unified response abstraction in `src/response/bridge.c`:

```c
// Converts wire buffer → ngx_chain_t for HTTP delivery
ngx_int_t xrootd_wire_to_http_chain(ngx_pool_t *pool, 
                                     const u_char *wire_buf, size_t len);
// Builds kXR_status frame from ngx_chain_t input (for pgread/pgwrite)
size_t xrootd_build_kxr_status_frame(const void *data, size_t data_len,
                                      uint32_t crc, ServerResponseHdr *hdr);
```

This bridges the two systems so stream handlers can build HTTP responses without knowing wire framing internals, and HTTP handlers can emit kXR status frames without knowing ngx_chain_t details. New contributors navigate ONE response system with clear boundaries instead of two disconnected subsystems.

---

### 8. XML Response Generation (Already Shared — Verify Usage)

**Current state:** `src/core/compat/http_xml.c` provides shared XML generation for S3 ListObjectsV2 and WebDAV PROPFIND. This is good existing consolidation.

**Opportunity:** Verify that ALL XML responses across both protocols use this helper:
- S3 errors: `s3_send_xml_error()` → should delegate to `http_xml.c`
- S3 ListObjectsV2: `list_objects_v2.c` → should use shared XML builders
- WebDAV PROPFIND: `propfind.c` → should use shared XML builders
- WebDAV response headers → `http_headers.c` already shared

**Proposal:** Audit all XML-producing files to ensure they delegate to `src/core/compat/http_xml.c` rather than building XML inline. Any remaining inline XML builders should be replaced with shared helpers. This ensures new contributors understand ONE XML generation pattern for both protocols.

---

### 9. Temp Path Generation (Already Shared)

**Current state:** `src/core/compat/tmp_path.c` provides temporary path generation. S3 PUT (`src/s3/put.c`) independently implements the same pattern inline:
- Generate tmp_path = fs_path.tmp.{pid}.{random}

WebDAV PUT and cache operations use the shared helper from `tmp_path.c`.

**Duplication observed:** S3's inline temp path logic duplicates what `tmp_path.c` already provides.

**Proposal:** Replace S3's inline temp path generation with calls to `src/core/compat/tmp_path.c`:

```c
// Use shared instead of inline in s3/put.c
char tmp_path[PATH_MAX];
xrootd_generate_tmp_path(fs_path, pid, random_seed, tmp_path, sizeof(tmp_path));
```

S3 put.c loses ~5 lines of duplicated temp path generation. One shared pattern for all protocols.

---

### 10. ETag Generation (Already Shared — Verify Usage)

**Current state:** `src/core/compat/etag.c` provides ETag computation from file metadata (size + mtime). S3 PUT calls this for the ETag header. WebDAV GET also uses it.

**Good existing consolidation.** No action needed — verify both protocols consistently use this helper and no inline ETag builders remain.

---

## Evidence: Direct Tool Findings

### Error Handling Patterns
- `xrootd_send_error()` called 310+ times across stream handlers (grep found matches in 75 files)
- `s3_send_xml_error()` called 25+ times in S3 handler.c alone (grep found 310 total error calls across all protocols)
- `webdav_metrics_return()` called 18+ times in WebDAV dispatch.c on every method return

### Path Resolution Patterns
- `xrootd_resolve_path*` variants used 121+ times across stream handlers (grep found matches in 46 files)
- `ngx_http_xrootd_webdav_resolve_path()` called 15+ times across WebDAV methods
- `s3_resolve_key()` called multiple times across S3 operations

### CRC32c Consolidation (Already Good)
- Single implementation: `src/core/compat/crc32c.c` — SSE4.2 hardware/software fallback, single-pass CRC+copy fusion
- Wire-facing wrappers in `src/response/crc32c.c` delegate to compat layer
- pgread/pgwrite use `xrootd_crc32c_copy()` for per-page checksum verification

### Metrics Patterns
- Three independent metric systems: `XROOTD_SRV_METRIC_INC`, `XROOTD_WEBDAV_METRIC_INC`, `XROOTD_S3_METRIC_INC` (`src/observability/metrics/metrics_macros.h`)
- S3 metrics chain: 4-step wrapper (`s3_metrics_method_slot → request → response → finalize`) in `src/s3/metrics.c`
- WebDAV single wrapper: `webdav_metrics_return()` in `src/webdav/metrics.c`

### Config Shared Fields
- `conf->allow_write` already shared via `src/core/config/shared_conf.h` (line 56, merge line 101)
- Other cross-protocol fields scattered across individual config structs

---

## Status Corrections (as of 2026-05-26)

Three items from the original analysis are already complete or superseded by more recent work. The implementation plan below accounts for actual current state rather than the analysis-time snapshot.

| Item | Analysis Claim | Actual Status |
|------|---------------|---------------|
| Item 5 — Staged file in S3 PUT | S3 put.c has inline loop | **Done.** `src/s3/put.c` already uses `xrootd_staged_open/commit/abort`; the inline loop no longer exists |
| Item 9 — Temp path in S3 PUT | S3 put.c generates path inline | **Done.** Handled by staged_file helper as part of Item 5 |
| Item 6 — Config consolidation | Three separate config structs | **Largely done.** `ngx_http_xrootd_shared_conf_t` in `shared_conf.h` already provides `enable`, `root`, `root_canon`, `allow_write`, `thread_pool`, `cache_root` used as `conf->common.*` across all three layers. Remaining gap: auth-specific fields (cert paths, JWKS URI) still duplicated in protocol-specific structs |

Remaining work: Items 1, 2, 3, 4, 6 (auth fields only), 7, 8, 10.

---

## Implementation Plan

### Dependency Graph

```
  Phase 0 (audits — no code risk, run first)
  ├── Item 8: XML audit
  └── Item 10: ETag audit

  Phase 1 (new shared files — independent, can run in parallel)
  ├── Item 2: HTTP path consolidation     (no blocking deps)
  ├── Item 3: Metrics wrapper             (no blocking deps)
  └── Item 7: Response bridge             (no blocking deps)

  Phase 2 (compound refactors — blocked by Phase 1)
  ├── Item 4: Async PUT callback          (blocked by: Item 2)
  └── Item 1: Error response unification  (blocked by: Item 3)

  Phase 3 (architectural — last; blocked by all prior phases)
  └── Item 6 (auth fields): Extend shared_conf.h with cert/JWKS fields
```

Items within a phase have no mutual dependencies and can be executed in parallel by different engineers.

---

### Phase 0 — Audits (2 h total, ~1 engineer-day segment)

Low-risk grep-and-fix passes. Run before any structural changes so the audit results are not immediately invalidated by Phase 1 edits.

#### Task A: XML inline-builder audit (1 h)

**Goal:** Verify every XML-producing callsite delegates to `src/core/compat/http_xml.c`; replace any remaining inline builders.

**Files to read first:**
- `src/core/compat/http_xml.c` — understand the full API surface
- `src/core/compat/http_xml.h`

**Grep commands:**
```bash
grep -rn "ngx_buf\|ngx_palloc.*xml\|snprintf.*<\|xml_node\|<?xml" \
    src/s3/ src/webdav/ --include="*.c" | grep -v "http_xml\.c"
grep -rn "s3_send_xml_error\|xrootd_http_send_xml_error" src/ --include="*.c"
```

**Files likely modified:** `src/s3/util.c`, `src/s3/handler.c`, `src/webdav/propfind.c` (if any inline XML found)

**Tests:** `PYTHONPATH=tests pytest tests/test_s3.py tests/test_webdav.py -v --tb=short`

**Done-when:** `grep -rn "<?xml"` returns no hits outside `http_xml.c` and test fixture files.

---

#### Task B: ETag inline-builder audit (30 min)

**Goal:** Confirm every ETag response header goes through `src/core/compat/etag.c`.

**Files to read first:** `src/core/compat/etag.c`, `src/core/compat/etag.h`

**Grep command:**
```bash
grep -rn "ETag\|etag\|mtime.*size\|size.*mtime" \
    src/s3/ src/webdav/ --include="*.c" | grep -v "etag\."
```

**Files likely modified:** `src/s3/put.c`, `src/webdav/get.c` (if inline ETag string building found)

**Tests:** `PYTHONPATH=tests pytest tests/test_s3.py tests/test_webdav.py -k "etag or get" -v`

**Done-when:** No inline `"\"" + hex(md5(...))` patterns remain outside `etag.c`.

---

### Phase 1 — New Shared Files (7.5 h total)

All three tasks can run in parallel. Each creates one new file in `src/core/compat/` or `src/response/` and updates callsites. Each requires registering the new `.c` in `src/core/config/config.h` under `NGX_ADDON_SRCS` and running `./configure` once.

---

#### Task 1: HTTP path consolidation (2.5 h)

**Goal:** Eliminate the ~20-line duplicate decode+strip logic in both `src/webdav/path.c` and `src/s3/util.c`.

**Blocked by:** nothing.

**Files to read before starting:**
- `src/webdav/path.c` — full file (89 lines); understand `webdav_urldecode` call and trailing-slash strip
- `src/s3/util.c` — full file (107 lines); understand `s3_resolve_key` implementation
- `src/core/compat/path.c` — understand `xrootd_resolve_path_input()` signature
- `src/core/compat/path.h`

**Files created:**
- `src/core/compat/http_path.c` (~80 lines):
  ```c
  /* xrootd_http_resolve_path — decode URI, strip trailing slash,
   * call xrootd_resolve_path_input() — used by both WebDAV and S3. */
  ngx_int_t xrootd_http_resolve_path(ngx_http_request_t *r,
                                      const char *root_canon,
                                      ngx_str_t *uri,
                                      char *out, size_t outsz);
  ```
- `src/core/compat/http_path.h` (~20 lines)

**Files modified:**
| File | Change | Lines delta |
|------|--------|-------------|
| `src/webdav/path.c` | Replace inline decode+strip+resolve with `xrootd_http_resolve_path()` call | −20 |
| `src/s3/util.c` | Replace `s3_resolve_key()` body with `xrootd_http_resolve_path()` call | −18 |
| `src/core/config/config.h` | Add `src/core/compat/http_path.c` to `NGX_ADDON_SRCS` | +1 |

**Build:** `./configure --with-stream ... --add-module=$REPO && make -j$(nproc)` (new .c file added)

**Tests (3 required):**
```bash
PYTHONPATH=tests pytest tests/test_webdav.py -k "path or put or get" -v
PYTHONPATH=tests pytest tests/test_s3.py -k "path or put or get" -v
PYTHONPATH=tests pytest tests/test_s3.py::test_path_traversal_rejected -v
```

**Rollback signal:** If `xrootd_http_resolve_path` produces different output than the original on any percent-encoded path with embedded slashes, keep the two separate implementations and document the difference.

---

#### Task 2: Metrics wrapper consolidation (2 h)

**Goal:** Replace the S3 four-step metric chain with a single `xrootd_http_metrics_finalize()` call, and unify the WebDAV single-wrapper call to use the same helper.

**Blocked by:** nothing.

**Files to read before starting:**
- `src/s3/metrics.c` — full file (125 lines); trace `s3_metrics_method_slot → s3_metrics_request_method → s3_metrics_return_method → s3_metrics_finalize_request_method`
- `src/s3/handler.c` — lines 185–320; count all `s3_metrics_return_method` callsites (there are ~18)
- `src/webdav/metrics.c` — full file (104 lines); understand `webdav_metrics_return` signature
- `src/observability/metrics/metrics_macros.h` — understand `XROOTD_S3_METRIC_INC` vs `XROOTD_WEBDAV_METRIC_INC`

**Files created:**
- `src/core/compat/http_metrics.c` (~90 lines):
  ```c
  /* xrootd_http_metrics_finalize — single call replaces the entire S3
   * s3_metrics_* chain and mirrors webdav_metrics_return semantics.
   * proto_slot selects the per-protocol metric counter block. */
  ngx_int_t xrootd_http_metrics_finalize(ngx_http_request_t *r,
                                          ngx_uint_t proto_slot,
                                          ngx_int_t handler_rc);
  ```
- `src/core/compat/http_metrics.h` (~20 lines)

**Files modified:**
| File | Change | Lines delta |
|------|--------|-------------|
| `src/s3/handler.c` | Replace ~18 `s3_metrics_return_method(r, slot, ...)` with `xrootd_http_metrics_finalize(r, slot, ...)` | −22 |
| `src/s3/metrics.c` | Retain internal helpers but delegate from the new shared wrapper; remove exported chain functions no longer needed externally | −15 |
| `src/webdav/dispatch.c` | Replace `webdav_metrics_return(r, handler_func())` with `xrootd_http_metrics_finalize(r, WEBDAV_SLOT, handler_func())` at all 18 callsites | 0 (1-for-1 substitution) |
| `src/core/config/config.h` | Add `src/core/compat/http_metrics.c` to `NGX_ADDON_SRCS` | +1 |

**Build:** `./configure ... && make -j$(nproc)`

**Tests (3 required):**
```bash
PYTHONPATH=tests pytest tests/test_s3.py -k "metrics or status" -v
PYTHONPATH=tests pytest tests/test_webdav.py -k "metrics or status" -v
PYTHONPATH=tests pytest tests/ -k "test_metrics" -v
```

**Risk:** If `s3_metrics_return_method` has side-effects beyond counting (e.g. access-log flushing), those must be replicated in the new wrapper. Audit the full call chain before replacing.

---

#### Task 3: Response bridge (stream↔HTTP) (3 h)

**Goal:** Provide two-way conversion functions so stream handlers can produce HTTP responses without knowing ngx_chain_t internals and HTTP handlers can emit kXR_status frames without knowing wire framing.

**Blocked by:** nothing.

**Files to read before starting:**
- `src/response/basic.c` — `xrootd_build_resp_hdr`, `xrootd_send_ok`, `xrootd_send_error`
- `src/response/status.c` — `xrootd_send_pgwrite_status`, kXR_status framing
- `src/response/response.h` — current wire-response API surface
- `src/core/compat/http_body.c` — `ngx_chain_t` building API
- `src/core/compat/http_body.h`
- `src/observability/metrics/stream.c` — check whether it manually bridges wire→HTTP today
- `src/observability/metrics/writer.c`

**Files created:**
- `src/response/bridge.c` (~120 lines):
  ```c
  /* xrootd_wire_to_http_chain — wrap a wire buffer in an ngx_chain_t
   * for delivery via ngx_http_output_filter() without extra copy. */
  ngx_int_t xrootd_wire_to_http_chain(ngx_pool_t *pool,
                                       const u_char *wire_buf, size_t len,
                                       ngx_chain_t **out);

  /* xrootd_http_chain_to_kxr_status — assemble a kXR_status frame
   * from an ngx_chain_t (used by pgread/pgwrite responses). */
  ngx_int_t xrootd_http_chain_to_kxr_status(ngx_pool_t *pool,
                                              ngx_chain_t *in,
                                              uint32_t crc,
                                              ServerResponseHdr *hdr,
                                              ngx_chain_t **out);
  ```

**Files modified:**
| File | Change | Lines delta |
|------|--------|-------------|
| `src/response/response.h` | Declare `xrootd_wire_to_http_chain`, `xrootd_http_chain_to_kxr_status` | +6 |
| `src/observability/metrics/stream.c` | Replace manual wire→ngx_chain bridge (if present) with `xrootd_wire_to_http_chain` | ±0 to −15 |
| `src/observability/metrics/writer.c` | Same as above | ±0 to −10 |
| `src/core/config/config.h` | Add `src/response/bridge.c` to `NGX_ADDON_SRCS` | +1 |

**Build:** `./configure ... && make -j$(nproc)`

**Tests (3 required):**
```bash
PYTHONPATH=tests pytest tests/test_dashboard.py -v
PYTHONPATH=tests pytest tests/ -k "metrics" -v
PYTHONPATH=tests pytest tests/test_conformance.py -k "pgread or pgwrite" -v
```

**Risk (HIGH):** `ServerResponseHdr` and kXR_status framing are defined in the XRootD wire spec header (`/tmp/xrootd-src/src/XProtocol/XProtocol.hh`). Any change to the kXR_status frame assembly must be verified against the spec — this bridge function is on the critical correctness path. If ambiguity in the spec arises, leave the pgwrite/pgread path untouched and only implement `xrootd_wire_to_http_chain` for the metrics/dashboard direction.

---

### Phase 2 — Compound Refactors (8 h total)

These tasks depend on Phase 1 outputs. Start only after the relevant Phase 1 tasks are merged and tested.

---

#### Task 4: Async PUT callback boilerplate (3 h)

**Blocked by:** Task 1 (HTTP path consolidation must exist so the shared callback can call `xrootd_http_resolve_path`).

**Goal:** Extract the common "retrieve ctx → validate conf → write via staged file → stat → ETag → metrics → HTTP 200" flow shared by WebDAV PUT and S3 PUT into a single callback in `src/core/compat/http_put_async.c`.

**Files to read before starting:**
- `src/webdav/put.c` — full file (317 lines); trace the async body callback from `webdav_handle_put()` through `s3_put_body_handler()`-equivalent
- `src/s3/put.c` — full file (541 lines); trace `s3_put_body_handler()`
- `src/core/compat/staged_file.h` — understand `xrootd_staged_file_t` API (already in use by both)
- `src/core/compat/async_job.h` — async job dispatch API used by S3 PUT for thread-pool path
- `src/core/compat/etag.h`

**Files created:**
- `src/core/compat/http_put_async.c` (~200 lines):
  ```c
  /* xrootd_http_put_ctx_t — shared context stored in r->ctx before calling
   * ngx_http_read_client_request_body(); retrieved in the completion callback. */
  typedef struct {
      u_char                       fs_path[PATH_MAX];
      const char                  *root_canon;
      xrootd_staged_file_t         staged;
      ngx_uint_t                   metric_slot;
      xrootd_http_put_proto_t      proto;    /* XROOTD_PUT_PROTO_WEBDAV or _S3 */
  } xrootd_http_put_ctx_t;

  /* Completion callback: commit staged file, build ETag, send HTTP 201/200.
   * Replaces s3_put_body_handler() and the equivalent WebDAV body callback. */
  void xrootd_http_put_body_handler(ngx_http_request_t *r);
  ```
- `src/core/compat/http_put_async.h` (~30 lines)

**Files modified:**
| File | Change | Lines delta |
|------|--------|-------------|
| `src/s3/put.c` | Replace `s3_put_body_handler()` with a thin wrapper that sets `put_ctx->proto = XROOTD_PUT_PROTO_S3` then calls `xrootd_http_put_body_handler()` | −120 |
| `src/webdav/put.c` | Replace the equivalent WebDAV body callback with the shared handler | −100 |
| `src/s3/handler.c` | Update the `ngx_http_read_client_request_body(r, xrootd_http_put_body_handler)` callsite | −3 |
| `src/webdav/dispatch.c` | Same update for the WebDAV PUT dispatch callsite | −3 |
| `src/core/config/config.h` | Add `src/core/compat/http_put_async.c` | +1 |

**Build:** `make -j$(nproc)` (no new `./configure` needed if config.h was updated in Task 1)

**Tests (3 required):**
```bash
PYTHONPATH=tests pytest tests/test_webdav_spooled_put.py -v
PYTHONPATH=tests pytest tests/test_s3.py -k "put" -v
PYTHONPATH=tests pytest tests/test_s3_multipart.py -v
```

**Risk (HIGH):** The directory-sentinel path in `s3_put_body_handler()` (zero-byte `_$folder$` object → `mkdir`) must be preserved as a branch in the shared handler or as a pre-dispatch check. If S3-specific sentinel logic cannot be cleanly extracted, keep `s3_put_body_handler()` in `src/s3/put.c` and share only the normal-object write path. Do not merge until both WebDAV and S3 spooled-PUT tests pass.

---

#### Task 5: Error response unification (5 h)

**Blocked by:** Task 2 (metrics wrapper must exist so the unified error helper can call `xrootd_http_metrics_finalize`).

**Goal:** Replace 25+ repetitive `XROOTD_S3_METRIC_INC + s3_send_xml_error` patterns in `src/s3/handler.c` and 18+ `return webdav_metrics_return(r, NGX_HTTP_*)` patterns in `src/webdav/dispatch.c` with a single call that atomically maps errno → HTTP status + logs + increments metrics.

**Scope note on stream handlers:** The 310+ `xrootd_send_error()` calls in stream handlers are already the correct low-level primitive; they do not need wrapping. The stream layer does not have the metric-increment-before-return pattern that drives this change. Stream handlers are **excluded** from this task.

**Files to read before starting:**
- `src/core/compat/error_mapping.c` — `errno_to_http_status()`, `errno_to_kxr_code()`
- `src/core/compat/error_mapping.h`
- `src/s3/util.c` — `s3_send_xml_error()` implementation
- `src/s3/handler.c` — lines 185–320, all metric+error callsites
- `src/webdav/dispatch.c` — full file (182 lines), all `webdav_metrics_return(r, NGX_HTTP_*)` callsites
- `src/core/compat/http_metrics.h` (output of Task 2)

**Files created:**
- `src/core/compat/error_response.c` (~130 lines):
  ```c
  /* xrootd_http_s3_error — maps errno to S3 XML error body, increments
   * the method-slot metric counter, returns the appropriate HTTP status code.
   * Equivalent to: XROOTD_S3_METRIC_INC(slot); return s3_send_xml_error(...) */
  ngx_int_t xrootd_http_s3_error(ngx_http_request_t *r,
                                   ngx_uint_t method_slot,
                                   int errno_val,
                                   const char *s3_code,
                                   const char *msg);

  /* xrootd_http_webdav_error — maps errno to HTTP status, increments metric,
   * returns the HTTP status code for use as the handler return value.
   * Equivalent to: return webdav_metrics_return(r, NGX_HTTP_*) */
  ngx_int_t xrootd_http_webdav_error(ngx_http_request_t *r,
                                       int errno_val,
                                       const char *msg);
  ```
- `src/core/compat/error_response.h` (~25 lines)

**Files modified:**
| File | Change | Lines delta |
|------|--------|-------------|
| `src/s3/handler.c` | Replace 25+ `XROOTD_S3_METRIC_INC(slot); return s3_metrics_return_method(r, slot, s3_send_xml_error(...))` with `return xrootd_http_s3_error(r, slot, errno, code, msg)` | −42 |
| `src/s3/util.c` | `s3_send_xml_error()` becomes a thin wrapper or is inlined into `error_response.c` | −25 or 0 |
| `src/webdav/dispatch.c` | Replace 5 error-specific `return webdav_metrics_return(r, NGX_HTTP_NOT_ALLOWED)` etc. with `return xrootd_http_webdav_error(r, EPERM, "method not allowed")` | −8 |
| `src/core/config/config.h` | Add `src/core/compat/error_response.c` | +1 |

**Build:** `make -j$(nproc)`

**Tests (3 required):**
```bash
PYTHONPATH=tests pytest tests/test_s3_status_codes.py -v
PYTHONPATH=tests pytest tests/test_webdav_http_security.py -v
PYTHONPATH=tests pytest tests/ -k "error or denied or forbidden" -v
```

**Risk:** `s3_send_xml_error()` may be called from files other than `handler.c` (e.g. `multipart.c`, `list.c`). Grep all callsites before modifying: `grep -rn "s3_send_xml_error" src/`. Do not rename `s3_send_xml_error` until all callsites are updated in the same commit.

---

### Phase 3 — Architectural Extension (3 h)

#### Task 6: Auth field consolidation in shared_conf.h (3 h)

**Blocked by:** All Phase 0–2 tasks (config struct changes cascade into every file modified above; change this last to avoid rebase conflicts).

**Goal:** Audit whether `cert_path`, `jwks_uri`, and `auth_timeout` are duplicated between `src/webdav/webdav.h` (loc_conf struct) and `src/s3/s3.h` (loc_conf struct); if so, promote them to `ngx_http_xrootd_shared_conf_t` in `src/core/config/shared_conf.h`.

**Decision gate:** Run this grep before writing any code:
```bash
grep -n "cert_path\|jwks_uri\|jwks_url\|auth_timeout\|token_secret" \
    src/webdav/webdav.h src/s3/s3.h src/core/config/shared_conf.h
```
If the fields appear only in one protocol struct, **stop** — they are not duplicated and this task has no work. Document the finding and close the task.

**Files to read before starting:**
- `src/webdav/webdav.h` — full loc_conf struct
- `src/s3/s3.h` — full loc_conf struct
- `src/core/config/shared_conf.h` — full file (132 lines)
- `src/core/config/server_conf.c` — `ngx_http_xrootd_shared_create_loc_conf()` and `ngx_http_xrootd_shared_merge_loc_conf()`
- `src/webdav/config.c` — full file; all `ngx_conf_merge_str_value` calls for auth fields
- `src/s3/handler.c` — `create_loc_conf` and `merge_loc_conf` sections

**Files modified (if auth fields are duplicated):**
| File | Change | Lines delta |
|------|--------|-------------|
| `src/core/config/shared_conf.h` | Add `cert_path`, `jwks_uri`, `auth_timeout` fields to struct | +6 |
| `src/core/config/server_conf.c` | Add merge calls for new shared fields in `ngx_http_xrootd_shared_merge_loc_conf()` | +9 |
| `src/webdav/webdav.h` | Remove fields now in shared preamble | −6 |
| `src/webdav/config.c` | Remove duplicate merge calls; update field access paths | −9 |
| `src/s3/s3.h` | Remove fields now in shared preamble | −6 |
| `src/s3/handler.c` | Update `cf->jwks_uri` → `cf->common.jwks_uri` etc. | variable |
| `src/webdav/auth_cert.c` | Update field access paths | variable |
| `src/webdav/auth_token.c` | Update field access paths | variable |

**Build:** `./configure --with-stream ... --add-module=$REPO && make -j$(nproc)` (struct layout changes require full reconfigure)

**Tests:** Full test suite:
```bash
PYTHONPATH=tests pytest tests/ -v --tb=short
```

**Risk (VERY HIGH):** Config struct layout changes invalidate `offsetof()` assumptions used in parent→child merge. If **any** protocol-specific field is accessed by pointer arithmetic relative to the struct start rather than by named field (check with `grep -rn "offsetof.*conf\|conf + sizeof"` in src/), this task cannot proceed safely. Abort and document if found.

---

### Summary Table

| Task | Phase | Est. (h) | Blocked by | New files | Modified files | Lines net |
|------|-------|----------|------------|-----------|----------------|-----------|
| A: XML audit | 0 | 1 | — | 0 | 0–3 | −0 to −30 |
| B: ETag audit | 0 | 0.5 | — | 0 | 0–2 | −0 to −15 |
| 1: HTTP path | 1 | 2.5 | — | `compat/http_path.c`, `.h` | `webdav/path.c`, `s3/util.c`, `config/config.h` | −37 |
| 2: Metrics wrapper | 1 | 2 | — | `compat/http_metrics.c`, `.h` | `s3/handler.c`, `s3/metrics.c`, `webdav/dispatch.c`, `config/config.h` | −36 |
| 3: Response bridge | 1 | 3 | — | `response/bridge.c` | `response/response.h`, `metrics/stream.c`, `metrics/writer.c`, `config/config.h` | +120 to +95 |
| 4: Async PUT | 2 | 3 | Task 1 | `compat/http_put_async.c`, `.h` | `s3/put.c`, `webdav/put.c`, `s3/handler.c`, `webdav/dispatch.c`, `config/config.h` | −223 |
| 5: Error response | 2 | 5 | Task 2 | `compat/error_response.c`, `.h` | `s3/handler.c`, `s3/util.c`, `webdav/dispatch.c`, `config/config.h` | −75 |
| 6: Auth config | 3 | 3 | All above | 0 | `config/shared_conf.h`, `config/server_conf.c`, `webdav/webdav.h`, `webdav/config.c`, `webdav/auth_cert.c`, `webdav/auth_token.c`, `s3/s3.h`, `s3/handler.c` | −21 |

**Total estimate: ~20 h (~2.5 engineer-days)**
**Total net line reduction: ~290–320 lines of duplicated logic removed**
**New shared files added: 8 (6 .c + 6 .h pairs, minus response/bridge which is 1 .c)**

---

### Testing Milestones

After each phase, run the full test suite before starting the next:

```bash
# Phase 0 complete
PYTHONPATH=tests pytest tests/ -v --tb=short 2>&1 | tail -20

# Phase 1 complete (after Tasks 1, 2, 3 all merged)
PYTHONPATH=tests pytest tests/ -v --tb=short
PYTHONPATH=tests pytest tests/test_cross_protocol_shared_helpers.py -v

# Phase 2 complete (after Tasks 4, 5 merged)
PYTHONPATH=tests pytest tests/ -v --tb=short
PYTHONPATH=tests pytest tests/test_s3_status_codes.py tests/test_webdav_spooled_put.py -v

# Phase 3 complete
PYTHONPATH=tests pytest tests/ -v --tb=short
tests/manage_test_servers.sh restart && PYTHONPATH=tests pytest tests/ -v
```

---

## Mental Model After Consolidation

**Before:** New contributor encounters three separate error patterns, two HTTP path resolvers, a four-step S3 metric chain, two async PUT flows, and a disconnected stream↔HTTP response boundary.

**After:**
- **`src/core/compat/`** — ONE HTTP path resolver, ONE metric finalize call, ONE async PUT completion handler, ONE error response helper, verified-shared XML + ETag + staged-file utilities
- **`src/response/`** — wire framing + bridge functions; stream handlers can produce HTTP responses through `xrootd_wire_to_http_chain` without knowing ngx_chain_t
- **Protocol layers add on top** — Stream adds kXR opcodes + wire framing; WebDAV adds cert/token auth + CORS + locking; S3 adds SigV4 + bucket namespace mapping + sentinel directories

Clear boundary: "common does X, protocol adds Y." A new contributor can learn the common layer once and understand all three protocols as additive specializations.

---

## Notes on Already-Consolidated Areas (No Further Action)

- CRC32c: `src/core/compat/crc32c.c` with SSE4.2 fallback — complete
- Error mapping (errno→kXR, errno→HTTP): `src/core/compat/error_mapping.c` — complete
- XML generation: `src/core/compat/http_xml.c` — complete (verify in Phase 0)
- ETag computation: `src/core/compat/etag.c` — complete (verify in Phase 0)
- Staged file atomic write: `src/core/compat/staged_file.c` — complete; adopted by WebDAV PUT, TPC, S3 PUT
- Temp path generation: `src/core/compat/tmp_path.c` — complete; adopted by all write paths
- HTTP header building: `src/core/compat/http_headers.c` — complete
- Structured access logging: `src/core/compat/log.c` — complete
- Shared config preamble: `src/core/config/shared_conf.h` (`enable`, `root`, `root_canon`, `allow_write`, `thread_pool`, `cache_root`) — complete
