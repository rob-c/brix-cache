# Cross-Protocol Opportunities

**Consolidated list of shared-code gaps across protocols, nginx built-in patterns not leveraged, and third-party library opportunities on AlmaLinux 8/9.**

[← Architecture overview](index.md)

---

## Mental model: what's already unified vs. what remains duplicated

The module has already consolidated a significant shared layer — path resolution for HTTP, JWT/WLCG token validation, PKI/OCSP, Prometheus shared-memory layout, cross-worker TPC rendezvous, checksum calculation, conditional headers, temporary-file staging, recursive filesystem cleanup, and filesystem-capacity arithmetic all live in `src/core/compat/` or protocol-agnostic modules that every handler reaches for. The remaining duplication is now mostly policy- or protocol-shape specific; the largest unshared gaps are config structs, CA store construction, HTTP header assembly helpers, file I/O boilerplate, error-response XML builders, and request-body parsing patterns.

```
┌────────────────────────────────────────────────────────────────────┐
│                    Protocol handler layer                          │
│                                                                    │
│  stream/   ──────────────────────────────────  src/connection/    │
│  (native XRootD)           WebDAV          S3  src/handshake/     │
│  src/session/          src/protocols/webdav/      src/protocols/s3/                   │
│  src/read/             src/protocols/webdav/tpc.c    src/protocols/s3/multipart*.c    │
│  src/write/                                                        │
│  src/tpc/                                                          │
└────────────────────┬───────────────────────────────────────────────┘
                     │  calls into
┌────────────────────▼───────────────────────────────────────────────┐
│                    Shared infrastructure layer                      │
│                                                                    │
│  src/core/compat/path.c      xrootd_http_resolve_path()  [HTTP+S3]     │
│  src/auth/token/             JWT validate + scope check  [all]         │
│  src/auth/crypto/            OCSP + PKI load             [all]         │
│  src/observability/metrics/metrics.h  shared-memory layout        [all]         │
│  src/tpc/key_registry.c SHM TPC key table           [stream+webdav]│
│  src/core/compat/crc32c.c    CRC32c for pgread/pgwrite   [stream]      │
│  src/core/compat/checksum.c  file checksums/digests      [stream+HTTP] │
│  src/core/compat/range.c     HTTP Range header parse     [webdav+s3]   │
│  src/core/compat/uri.c       percent-decode              [webdav+s3]   │
│  src/core/compat/etag.c      ETag generation             [webdav+s3]   │
│  src/core/compat/http_*.c    headers/body/conditions     [webdav+s3]   │
│  src/core/compat/fs_walk.c   dot-entry/remove-tree       [webdav+s3+query] │
│  src/core/compat/staged_file temp open/commit/abort      [webdav+s3]   │
│  src/net/cms/frame_io.c     CMS send-all + frame build  [cms paths]   │
│  src/core/compat/xml.c       minimal XML scanner         [webdav]      │
└────────────────────────────────────────────────────────────────────┘
```

See [cross-protocol-unification.md](cross-protocol-unification.md) for the full "what is already shared" and "completed unification work" tables. This file focuses on **remaining gaps** and **external opportunities**.

---

## A: Shared code gaps across protocols

### 1. Config directives — separate structs, overlapping fields

| Area | Stream (`src/core/config/server_conf.c`) | WebDAV (`src/protocols/webdav/config.c`) | S3 (`src/protocols/s3/module.c`) |
|------|-------------------------------------|-------------------------------|------------------------|
| Merge calls | ~60 `ngx_conf_merge_*` macros | ~30 macros + array inheritance + CA store + JWKS loading | 9 directives, no `merge_loc_conf` (single-location config) |
| Shared fields | `root`, `allow_write`, `cadir/cafile/crl`, `token_jwks/token_issuer/token_audience`, `verify_depth` | Same fields but **different sentinel values**, different defaults, separate struct members | Minimal overlap — S3 has its own `bucket_name`, `sigv4` config |
| Auth enum | `XROOTD_AUTH_ANON / GSI / TOKEN / SSS` (stream-specific) | `WEBDAV_AUTH_NONE / CERT / Bearer_TOKEN` (HTTP-specific) | No auth enum — relies on token or SigV4 directly |

**Opportunity:** Create a shared config preamble struct (`src/core/config/shared_conf.h`) with common fields and sentinel values, then each protocol struct embeds it. Reduces merge boilerplate from ~90 total calls to ~30 shared + per-protocol-specific.

### 2. CA store construction — duplicated X509_STORE builds

| Protocol | File | Approach |
|----------|------|----------|
| WebDAV | `src/protocols/webdav/config.c` → `webdav_build_ca_store()` | Reads `cadir`, `cafile`, `crl` from location config, builds `X509_STORE`, caches per-worker |
| Stream | `src/connection/postconfig.c` | Reads `cadir`, `cafile`, `crl` from server config, builds its own store during post-merge phase |

Both read the same file types (CA certs + CRLs), use OpenSSL APIs (`X509_STORE_add_cert`, `X509_CRL_load_file`), and cache the result. But they have separate implementations with different sentinel checks and error paths.

**Opportunity:** Move CA store building to `src/auth/crypto/pki_build.c` (new) or extend `pki_load.c`, exporting `xrootd_build_ca_store(cadir, cafile, crl)` that both protocols call. WebDAV already has a partially shared `webdav_verify_proxy_cert()` → `src/auth/crypto/gsi_verify.c`.

### 3. HTTP header assembly helpers — duplicated patterns despite compat layer

| Protocol | File(s) | What they do |
|----------|---------|--------------|
| S3 | `src/protocols/s3/util.c` (inline), `s3/headers.c` | Content-Type, Content-Length, ETag, Last-Modified, Range, CORS headers — built inline per-response |
| WebDAV | `src/protocols/webdav/headers.c`, `tpc_headers.c` | Same set of headers plus TPC Source/Credential header lookup |
| Stream | No HTTP headers — wire protocol framing only |

`src/core/compat/http_headers.c` already provides request-header lookup, value comparison, and response header set functions. But S3 still builds many headers inline rather than calling the compat helpers. WebDAV uses some but has its own `webdav_tpc_find_header()` for TPC-specific lookups alongside.

**Opportunity:** Audit every callsite in S3 and WebDAV where a standard HTTP header is set (Content-Type, Content-Length, ETag, Last-Modified, Range, Accept-Ranges). Replace inline construction with `src/core/compat/http_headers.c` helpers. Consolidate TPC header lookup into the compat layer.

### 4. File I/O boilerplate — sync pread(2) everywhere, async wrappers per protocol

| Protocol | Files | Pattern |
|----------|-------|---------|
| Stream | `read/read.c`, `read/pgread.c`, `read/readv.c` | `pread(2)` → build kXR_status wire response → send via stream output filter |
| WebDAV | `get.c`, `put.c` | `ngx_http_read_client_request_body()` for request body; file reads use `ngx_chain_t`/`ngx_buf_t` + `ngx_http_output_filter()` |
| S3 | `get.c`, `put.c` | Same nginx HTTP chain pattern as WebDAV but with separate staging and multipart logic |

Both HTTP protocols (WebDAV, S3) share the exact same response-building pattern: `ngx_chain_t` of `ngx_buf_t`, memory-backed for TLS, file-backed+sendfile for cleartext. But each has its own buffer allocation boilerplate, chain assembly loops, and sendfile setup.

**Opportunity:** Extract a shared HTTP file-response builder from `src/core/compat/http_file_response.c` (already partially exists) that handles: allocate chain → fill buffers from fd → set memory/file flags → attach to response. Both S3 and WebDAV GET paths call it instead of inline assembly.

### 5. Error response XML builders — similar structures, separate implementations

| Protocol | File(s) | Builder pattern |
|----------|---------|-----------------|
| S3 | `s3/xml.c` | Builds `<Error><Code>...</Code><Message>...</Message></Error>` using `xrootd_xml_write_text_element()` from compat |
| WebDAV | `webdav/propfind.c`, `lock.c` | Multi-Status XML, Lock XML — uses `webdav_escape_xml_text()` inline + `xrootd_xml_*` helpers |
| Stream | Wire protocol framing (kXR_status responses) | No XML — binary wire format with length-prefix framing |

S3 and WebDAV both build XML error/respone chains. S3's builder is more structured (single Error element). WebDAV has ad-hoc inline escaping (`webdav_escape_xml_text()`) mixed with compat helpers. Both use the same `xrootd_xml_write_text_element()` from `src/core/compat/xml.c` but wrap it differently.

**Opportunity:** Extend `src/core/compat/http_xml.c` with a generic XML error builder function that both S3 and WebDAV can call for standard error responses (AccessDenied, NoSuchKey, Conflict, etc.). WebDAV keeps its Multi-Status builder separate since it has protocol-specific structure.

### 6. Path validation constants — WEBDAV_PATH_* vs XROOTD_PATH_*

| Protocol | Constants file | Values |
|----------|---------------|--------|
| WebDAV | `src/protocols/webdav/` headers | `WEBDAV_PATH_MAX`, `WEBDAV_PATH_MIN` |
| Stream | `src/connection/` / `handshake/` | `XROOTD_PATH_MAX`, `XROOTD_PATH_*` |

Both validate path length and component count, but use different constants. The actual filesystem limits are the same (PATH_MAX = 4096 on Linux). Different names create confusion when comparing code.

**Opportunity:** Define shared path constants in `src/core/compat/path.h`: `XROOTD_PATH_MAX`, `XROOTD_PATH_MIN`. Replace protocol-specific constants with these shared values. The validation logic itself stays separate (HTTP vs wire input differences) but the thresholds unify.

### 7. CORS handling — only WebDAV has it

| Protocol | Config fields | Implementation |
|----------|--------------|----------------|
| WebDAV | `cors_origin`, `cors_credentials`, `cors_max_age` in loc_conf | Built inline per-response in `get.c`, `tpc_headers.c` |
| S3 | No CORS config | No CORS headers |
| Stream | No HTTP-level CORS | N/A (wire protocol) |

WebDAV CORS handling is the only protocol with origin/credentials/max-age config fields. It's built inline per-response rather than using a shared helper.

**Opportunity:** Create `src/core/compat/cors.c` with `xrootd_build_cors_headers(r, conf)` that both WebDAV and S3 (if CORS support is added later) can call. Currently only WebDAV uses it but the helper is protocol-agnostic.

### 8. Request body parsing — HTTP protocols duplicate nginx body reading

| Protocol | File(s) | Pattern |
|----------|---------|---------|
| WebDAV | `put.c`, `propfind.c` | `ngx_http_read_client_request_body()` → callback → process body |
| S3 | `put.c`, `delete.c` | Same pattern but with separate body mode handling (EMPTY/MEMORY/SPOOLED) and different callback logic |

Both HTTP protocols call `ngx_http_read_client_request_body()` but each has its own callback implementation, body-mode checks, and error handling. The nginx built-in function is the same; the wrapper boilerplate differs.

**Opportunity:** Create a shared request-body handler in `src/core/compat/http_body.c` (already partially exists with `xrootd_http_body_summary()`, `xrootd_http_body_write_to_fd()`). Both S3 and WebDAV PUT paths use it instead of inline callback setup.

### 9. Checksum calculation — pgread/pgwrite CRC32c vs S3 multipart CRC

| Protocol | File(s) | Algorithm |
|----------|---------|-----------|
| Stream (pgread/pgwrite) | `src/read/pgread.c`, `src/write/pgwrite.c` | CRC32c per-page, framed in kXR_status(4007) wire response |
| S3 (multipart) | `s3/multipart_upload.c`, `s3/multipart_complete.c` | MD5 of each part → ETag = concatenated hex MD5s |

Stream uses CRC32c via `src/core/compat/crc32c.c`. S3 uses MD5 for multipart ETags. Different algorithms, different framing, but both compute checksums over file data in chunks.

**Opportunity:** Extend `src/core/compat/checksum.c` with a generic chunked-checksum iterator that both protocols can use. Stream still wraps it in CRC32c/pgread framing; S3 wraps it in MD5/multipart ETag format. The chunk-reading boilerplate (pread loop, offset tracking, byte counters) becomes shared.

---

## B: Nginx built-in patterns not leveraged

### 1. `ngx_http_json_module` — JSON responses instead of XML error formats

**Current:** S3 builds XML error responses (`<Error><Code>...</Code><Message>...</Message>`). WebDAV PROPFIND returns XML Multi-Status. Both use `src/core/compat/xml.c` chain builders.

**Nginx built-in:** `ngx_http_json_module` provides JSON response building via `ngx_http_json_t` and `r->json` fields. Available when nginx is configured with `--with-http_json_module`.

**Opportunity:** Add optional JSON response support for S3 error responses (AWS SDKs accept both XML and JSON error formats). WebDAV stays XML since the WebDAV spec requires XML. This would reduce XML builder code in S3 by ~50%.

### 2. `ngx_http_limit_req_module` — rate limiting across protocols

**Current:** No rate limiting anywhere. All three protocols accept unlimited concurrent requests.

**Nginx built-in:** `limit_req_zone` and `limit_req` directives provide request-rate limiting with shared-memory zones, configurable burst/delay parameters. Works at http/server/location level.

**Opportunity:** Add `xrootd_limit_req_zone` / `xrootd_limit_req` directives to all three protocol configs. Rate-limit by client IP or token subject. Shared-memory zone visible to all workers — no custom implementation needed.

### 3. `ngx_http_geo_module` / `map` blocks — IP-based ACLs

**Current:** ACL logic in `src/auth/authz/acl.c` uses VO/user identity from auth tokens + path prefix matching. No IP-based restrictions.

**Nginx built-in:** `geo` and `map` directives create shared-memory lookup tables mapping client IPs to variables. Works at http level, visible to all server/location blocks.

**Opportunity:** Add optional IP whitelist/blacklist via nginx `geo` block. Stream XRootD can reference it in handshake; WebDAV/S3 can check it before auth. Reduces custom ACL code for simple IP-based policies.

### 4. `proxy_cache` directives — caching upstream responses (proxy mode)

**Current:** Proxy mode (XRootD transparent, WebDAV perimeter) relays backend responses verbatim. No caching layer.

**Nginx built-in:** `proxy_cache_path`, `proxy_cache`, `proxy_cache_key`, `proxy_cache_valid` provide full HTTP cache management with shared-memory zones, TTL policies, stale-while-revalidate. Works at http level.

**Opportunity:** Add proxy-cache directives to proxy-mode configs. Cache GET/PROPFIND responses from upstream backend. Stream proxy could cache `kXR_stat` and directory-list results. Reduces upstream load for repeated reads.

### 5. Log format variables — structured access logging

**Current:** Custom access log lines with protocol-specific fields. Each protocol writes its own log format strings.

**Nginx built-in:** `$remote_addr`, `$request_uri`, `$status`, `$body_bytes_sent`, `$http_authorization`, `$ssl_protocol` and many more built-in variables. Custom log formats via `log_format` directive.

**Opportunity:** Replace custom log string assembly with nginx log format variables where possible. Stream XRootD still needs protocol-specific fields (opcode, handle) but HTTP protocols can use standard nginx variables for client IP, request URI, status code, bytes sent. Reduces log-format boilerplate in WebDAV/S3.

### 6. `upstream` blocks with health checks — backend reliability (proxy mode)

**Current:** Proxy mode upstream is a single address string (`xrootd_proxy_upstream`). No health checking, no failover.

**Nginx built-in:** `upstream` block with multiple servers, `max_fails`, `fail_timeout`, `backup` servers. Built-in passive health checks (mark server down after N failures). Active health checks via third-party module or custom.

**Opportunity:** Add upstream block support to proxy-mode configs. Multiple backend servers with passive health checking and backup failover. Stream XRootD manager mode already has CMS-based registry but could use nginx upstream for simple multi-backend setups.

### 7. `subrequest` patterns — conditional header generation

**Current:** WebDAV OPTIONS handler builds Allow header by scanning implemented methods inline. S3 HEAD builds Content-Type from file extension lookup.

**Nginx built-in:** `ngx_http_subrequest()` allows one request to spawn a subrequest and receive its response body/status. Can be used for conditional logic without spawning external processes.

**Opportunity:** Use subrequests for OPTIONS Allow header generation (subrequest hits an internal location that returns the Allow list). For S3 Content-Type detection, use `map` directive instead of inline extension lookup. Reduces method-scan boilerplate.

### 8. `ngx_http_stub_status_module` — lightweight alternative to Prometheus handler

**Current:** Full Prometheus `/metrics` handler in `src/observability/metrics/stream.c`, `writer.c` with shared-memory zone reading, counter serialization, label formatting. ~300 lines of custom code.

**Nginx built-in:** `stub_status` provides basic connection/request counters (`Active connections`, `Total requests`, etc.) at `/nginx_status`. Very lightweight.

**Opportunity:** Add `stub_status` location alongside Prometheus handler for sites that want basic nginx-level metrics without the full XRootD counter set. No custom code needed — just a config directive.

---

## C: Third-party library opportunities on AlmaLinux 8/9

### 1. `libcrc32c` — CRC-32C acceleration beyond SSE4.2

**Current:** `src/core/compat/crc32c.c` implements CRC32c with SSE4.2 hardware instruction (`_mm_crc32_u8/u32/u64`) and a software fallback (table-based). Works well on modern x86 but has ~100 lines of inline assembly + software path.

**AlmaLinux 8/9 package:** `libcrc32c` (libcrc32c-devel) — provides hardware-accelerated CRC32C via Intel/AMD intrinsic functions, fallback to generic C implementation. API: `crc32c(uint32_t crc, const void *data, size_t length)`.

**Opportunity:** Replace `src/core/compat/crc32c.c` with libcrc32c library calls when available (configure-time detection). Software-only fallback for ARM/non-SSE4.2 platforms. Reduces inline assembly code, improves portability to ARM64 (AlmaLinux 9 supports aarch64).

### 2. `libjose` / `joseft` — JWK/JWT operations beyond jansson alone

**Current:** JWT validation uses:
- `src/auth/token/json.c` — minimal JSON scanner for claims extraction
- `src/auth/token/b64url.c` — base64url decode
- `src/auth/token/keys.c` / `jwks.c` — JWKS parsing + key lookup (Jansson-backed)
- `src/auth/gsi/token.c` — token validation with OpenSSL RSA/ECDSA signature verification

**AlmaLinux 8/9 packages:** `libjose` (`jose-devel`) — JWK operations, JWT encode/decode/sign/verify, base64url. API: `jose_jwk_from_json()`, `jose_jwt_verify()`, `jose_b64url_decode()`. Lightweight (~50KB library).

**Opportunity:** Replace manual JSON-scanner + base64url decode with libjose for JWT parsing and signature verification. Reduces token validation code by ~200 lines (json.c, b64url.c can be slimmed significantly). JWKS loading stays Jansson-backed since it needs full JSON tree traversal.

### 3. `libcurl` — shared library vs. external curl process spawning

**Current:** WebDAV HTTP-TPC (`src/protocols/webdav/tpc_curl.c`) spawns an **external `curl(1)` process** via fork+pipe+waitpid for COPY transfers with Source/Credential headers. ~80 lines of subprocess boilerplate per transfer.

**AlmaLinux 8/9 package:** `libcurl` (libcurl-devel) — already present on AlmaLinux as a dependency, but not used directly in the module. API: `curl_easy_init()`, `curl_easy_setopt()`, `curl_easy_perform()`.

**Opportunity:** Replace external curl process spawning with libcurl inline calls (`src/protocols/webdav/tpc_curl.c` → `src/protocols/webdav/tpc_libcurl.c`). Same Source/Credential header logic, but no fork/waitpid overhead. Reduces latency for TPC transfers (no subprocess startup), reduces subprocess boilerplate.

### 4. `zlib` — compression support (already present, could be leveraged)

**Current:** zlib is already linked (`-lz`) and used in checksum calculation via `crc32()` from zlib API. Not used for response compression or request body decompression.

**AlmaLinux 8/9 package:** `zlib` / `zlib-devel` — standard on AlmaLinux, already present. API: `deflate()`, `inflate()`, `compress()`.

**Opportunity:** Add optional gzip/deflate compression for large HTTP responses (WebDAV GET of large files, S3 GET). Use nginx's built-in `gzip` module + zlib decompression for incoming compressed request bodies. No new library needed — just leverage existing linkage.

### 5. `libxml2` — full XML parser vs. minimal scanner

**Current:** `src/core/compat/xml.c` provides a **minimal XML scanner** (token-by-token, no tree) used by WebDAV PROPFIND and LOCK handlers. ~60 lines of hand-written state machine.

**AlmaLinux 8/9 package:** `libxml2` (`libxml2-devel`) — already present on AlmaLinux as a dependency, but not directly linked in the module build. API: `xmlParseMemory()`, `xmlDocGetRootElement()`, XPath queries.

**Opportunity:** For WebDAV PROPFIND response building (which is XML), use libxml2 DOM construction instead of chain-append helpers. PROPFIND request parsing could also switch from minimal scanner to libxml2 tree. Lock/Unlock request parsing benefits similarly. The minimal scanner stays for simple single-element responses.

---

## Prioritized roadmap

| Priority | Area | Impact | Effort | Notes |
|----------|------|--------|--------|-------|
| **P0** | Config shared preamble (`src/core/config/shared_conf.h`) | ~60 merge calls → ~30 | Low | Same fields, different structs. Embed common struct in each protocol config. |
| **P0** | CA store builder (`src/auth/crypto/pki_build.c`) | Eliminates duplicated X509_STORE build | Medium | Both protocols read same files, use same OpenSSL APIs. |
| **P1** | HTTP header helpers audit → compat layer adoption | Reduces inline header assembly across S3/WebDAV | Low | `src/core/compat/http_headers.c` already exists. Just replace callsites. |
| **P1** | Request body handler (`src/core/compat/http_body.c`) expansion | Unifies WebDAV PUT/S3 PUT body reading | Medium | Both use same nginx callback pattern with different wrappers. |
| **P2** | Error response XML builder extension | S3 + WebDAV share standard error XML format | Low | `src/core/compat/xml.c` already has text element helpers. Add structured error builder. |
| **P2** | Path validation constants unification | Eliminates WEBDAV_PATH_* vs XROOTD_PATH_* confusion | Trivial | Same filesystem limits, different names. Shared header. |
| **P3** | Chunked checksum iterator (`src/core/compat/checksum.c`) | Unifies pgread CRC32c + S3 multipart MD5 loop boilerplate | Medium | Different algorithms but same chunk-reading pattern. |
| **P3** | CORS helper (`src/core/compat/cors.c`) | Protocol-agnostic CORS header builder | Low | Currently only WebDAV uses it; S3 may add CORS later. |

### External library opportunities

| Priority | Library | Impact | Effort | Notes |
|----------|---------|--------|--------|-------|
| **P0** | `libcrc32c` | ARM64 portability + cleaner CRC32c impl | Medium | Configure-time detection, software fallback. |
| **P1** | `libjose` | JWT validation code reduction (~200 lines) | Medium | Replace json.c/b64url.c minimal scanner. JWKS stays Jansson. |
| **P2** | `libcurl` inline TPC | No subprocess overhead for HTTP-TPC COPY | Medium | Same Source/Credential headers, no fork/waitpid. |
| **P3** | `libxml2` DOM building | PROPFIND/Lock XML construction simplification | Low | libxml2 already present on AlmaLinux. Optional linkage. |

---

## Non-goals (deliberately kept separate)

### Stream path resolution stays in `src/path/`
See [cross-protocol-unification.md](cross-protocol-unification.md#why-the-path-engines-stay-separate). HTTP (`src/core/compat/path.c`) and stream (`src/path/`) serve fundamentally different callers (decoded URI vs wire reqpath+handle, different ENOENT strategies, handle tracking). Merging adds branching complexity exceeding benefit.

### S3 SigV4 stays separate from WLCG bearer-token
S3 Signature Version 4 uses HMAC-SHA256 over request components with AWS credential scope. WLCG JWT uses RSA/ECDSA signature verification over claims. Different algorithms, different input structures, different scope semantics. Not worth merging.

### Native TPC stays separate from WebDAV curl-TPC
Native TPC uses SHM key registry for cross-process zero-copy rendezvous. WebDAV TPC uses libcurl (or external `curl(1)`) with HTTP Source/Credential headers. Different transport, different protocol semantics. Could share the credential-parsing JSON layer (`src/auth/token/oauth2.c` — already done).

### Stream wire framing stays separate from HTTP chain building
Stream XRootD uses length-prefix binary wire framing (kXR_status responses). HTTP protocols use `ngx_chain_t` of `ngx_buf_t`. Different output mechanisms, different buffering strategies. Each protocol's response builder is appropriate to its transport.

---

## Further reading

- [cross-protocol-unification.md](cross-protocol-unification.md) — what is already shared, completed unification work
- [Stream architecture](stream.md) — state machine, dispatch, read/write paths
- [WebDAV architecture](webdav.md) — method routing, TPC, GSI auth cache
- [S3 architecture](s3.md) — SigV4, multipart staging
- `src/core/compat/http_headers.c` — shared HTTP header helpers (currently underutilized by S3)
- `src/core/compat/xml.c` — minimal XML scanner (could be extended for error response builder)
- `src/core/config/server_conf.c` — Stream config directives (~60 merge calls)
- `src/protocols/webdav/config.c` — WebDAV config directives (~30 merge calls + CA store build)
