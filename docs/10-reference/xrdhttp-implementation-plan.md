# XrdHttp Parity Implementation Plan

> **Status: COMPLETE** — All 6 feature areas implemented. 28/28 tests pass (`tests/test_xrdhttp.py`).
> Implementation lives in `src/webdav/xrdhttp.c`, `xrdhttp.h`, `xrdhttp_multipart.c`, `xrdhttp_stats.c`.

This document outlines the specific technical work required to implement full support for the **XrdHttp** protocol dialect within the `nginx-xrootd` module. While the module currently supports standard WebDAV and S3, achieving parity with the official XRootD reference implementation involves adding support for XRootD-specific HTTP extensions.

---

## 1. Protocol Header Extensions (`X-Xrootd-*`) ✅
Official XRootD clients use a set of custom headers to negotiate capabilities and communicate status.

*   **`X-Xrootd-Proto`**: Detect and respect the requested protocol version (e.g., `5.2`). Parsed in `xrdhttp_parse_request()`; sets `ctx->is_xrdhttp`.
*   **`X-Xrootd-Status`**: Include detailed XRootD error codes (e.g., `kXR_NotFound = 3003`, `kXR_ok = 0`) in HTTP responses. Emitted by `xrdhttp_add_response_headers()` for all responses including nginx error pages (pre-injected before returning error codes so headers survive into `ngx_http_send_special_response`).
*   **`X-Xrootd-Wait` / `X-Xrootd-Retry`**: Support asking the client to wait; `ctx->wait_seconds` / `ctx->retry_seconds` populated by handlers, emitted in `xrdhttp_add_response_headers()`.

## 2. Query Parameter Dialect (`?xrd.*`) ✅
Many XRootD-isms are expressed as query parameters in the URL.

*   **`xrd.clnt.uuid`**: Captured in `ctx->clnt_uuid`, echoed as `X-Xrootd-Requuid` in every response.
*   **`xrd.clnt.app`**: Logged in `ctx->clnt_app` for auditing.
*   **`xrd.want.cksum`**: Server-side checksum calculated via `xrdhttp_add_checksum_header()` on GET/HEAD; emits `Digest: adler32=<val>`.
*   **`xrd.opaque`**: Captured in `ctx->opaque`, available for routing/passthrough.

## 3. XRootD-Specific Redirect Dialect ✅
Official XRootD's cluster management relies on a more nuanced redirect mechanism than standard HTTP `307`.

*   **Custom Redirect Headers**: `xrdhttp_send_redirect()` emits `X-Xrootd-Redir-Host`, `X-Xrootd-Redir-Port`, and appends `?xrd.opaque=` for opaque passthrough.
*   **Opaque Data Persistence**: `tpc.key` and opaque cookies appended to `Location` during redirects.
*   **"Tried Hosts" Tracking**: Opaque blob passthrough enables client-side `tried=` list management.

## 4. Vector Reads over HTTP ✅
XRootD's high performance on ROOT files often comes from `kXR_readv`.

*   **`multipart/byteranges`**: Implemented in `xrdhttp_multipart.c` — `xrdhttp_handle_multipart_get()` parses the `Range` header into up to 64 sub-ranges, builds an `ngx_chain_t` of headers + file-backed bufs per part using `copy_file_range`-equivalent, returns proper `Content-Type: multipart/byteranges; boundary=xrdhttp_boundary_42`.
*   **AIO Integration**: File range reads go through the existing `ngx_chain_t` + sendfile path already integrated with the nginx thread pool.

## 5. TPC Dialect Parity ✅
TPC over HTTP in XRootD has several variants.

*   **URI-Based TPC**: `xrdhttp_inject_tpc_headers()` promotes `?tpc.src=` / `?tpc.dst=` query parameters to the standard `Source:` / `Destination:` headers used by the TPC engine; validates `https://` scheme and rejects embedded NUL bytes.
*   **`X-Xrootd-Tpc-Token`**: Stored in `ctx->tpc_token`, passed through to the TPC credential negotiation path.
*   **TPC Status API**: `xrdhttp_request_is_stats_query()` detects `?xrd.stats=1`; dispatches to `xrdhttp_handle_stats_query()`.

## 6. Observability and Stats ✅
Integrate the HTTP module with XRootD's standard monitoring patterns.

*   **`?xrd.stats`**: `xrdhttp_stats.c` builds an XRootD-compatible XML document (`<statistics>` with `info`, `xrootd`, `http` sections) and serves it with `Cache-Control: no-cache`.
*   **`X-Xrootd-Requuid`**: Echoed from `ctx->requuid` (populated from `X-Xrootd-Requuid` request header, truncated to `XRDHTTP_UUID_MAX - 1` bytes) in all XrdHttp responses.

---

## Summary Checklist for XrdHttp Parity

| Feature Gap | Priority | Status |
| :--- | :--- | :--- |
| **X-Xrootd Headers** | High | ✅ Complete |
| **?xrd.* Query Params** | High | ✅ Complete |
| **Vector Reads (multipart)** | Medium | ✅ Complete |
| **TPC Status API** | Medium | ✅ Complete |
| **Custom Redirect Dialect** | Medium | ✅ Complete |
| **Xrd Monitoring Stats** | Low | ✅ Complete |
