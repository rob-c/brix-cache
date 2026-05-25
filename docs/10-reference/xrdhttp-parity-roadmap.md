# XrdHttp Parity Roadmap

The strategic work required to bring nginx-xrootd to full feature parity with the official `XrdHttp` protocol — specialized HEP data-transfer extensions, advanced TPC observability, and hierarchical cluster management.

---

## Phase 1: High-Fidelity TPC Observability
Official `XrdHttp` (and FTS) relies on periodic progress reporting for long-lived transfers.

*   **Asynchronous TPC Client:** Replace the current thread-pool-based `curl` execution with a fully asynchronous event-driven client or a managed process monitor to prevent thread-pool exhaustion during high-concurrency transfers.
    *   **Status: Implemented.** When `xrootd_webdav_tpc_marker_interval` is set, curl is forked without blocking the nginx event loop. A timer fires every 200 ms to poll `waitpid(WNOHANG)` — no thread is consumed during the transfer.
*   **Performance-Marker Streaming:** Implement support for `202 Accepted` responses with a chunked body. The module must stream WLCG Performance-Marker blocks back to FTS while the outbound transfer is in progress.
    *   **Status: Implemented.** Enable with `xrootd_webdav_tpc_marker_interval <seconds>` (e.g., `30` for production). The response is `202 Accepted` with `Content-Type: text/plain`; Perf Marker blocks are streamed every `<seconds>` seconds; the body ends with `success\r\n` or `failure\r\n`. Without the directive the legacy synchronous `201`/`204` path is preserved.
*   **TPC Status API:** Implement the XRootD-specific `tpc.src=...` status query dialect over HTTP to allow clients to poll for the state of a background pull.

## Phase 2: Advanced Authentication & Delegation
`XrdHttp` supports complex grid delegation patterns that are currently simplified in this module.

*   **Multi-hop GSI Delegation:** Implement the ability to receive a delegated proxy from a client and use it to authenticate outbound TPC connections to a third server.
*   **Token Refresh & Lifecycle:** Add a background worker or event-timer to refresh delegated OIDC tokens via `oidc-agent` or `token-exchange` endpoints during multi-hour transfers.
*   **S3 Advanced Auth:**
    *   ~~**Presigned URLs:** Support `X-Amz-Signature` query-string authentication for S3.~~ Implemented for static access-key SigV4.
    *   ~~**STS Tokens:** Parse `X-Amz-Security-Token` header/query forms.~~ Static-secret compatibility is implemented via `xrootd_s3_allow_unsigned_session_token`; dynamic temporary credential stores remain out of scope.
*   **Expanded Auth Protocols:** Evaluate the necessity of specialized modes like `krb5` or `host/pwd` for specific site requirements.

## Phase 3: Cluster Topology & Hierarchical Redirection
Official XRootD's `XrdHttp` is fully aware of `cmsd` cluster states.

*   **Hierarchical Redirection:** Implement `kYR_select`, `kYR_try`, and `kYR_redirect` logic for the HTTP layer. This allows a top-level Nginx redirector to coordinate with sub-managers and leaf nodes in a multi-tier hierarchy.
*   **Lateral Redirects:** Support for `307 Temporary Redirect` logic that accounts for XRootD's internal load-balancing and "tried hosts" lists.
*   **Upstream Auth-More:** Handle upstream servers that require multi-round authentication (`kXR_authmore`) during read-through cache-fill or TPC pull operations.

## Phase 4: Protocol Edge Cases & Performance
Fine-tuning the "look and feel" of the HTTP service to match `xrdcp davs://` expectations.

*   **XRootD-Specific Headers:** Support the full set of `X-Xrootd-*` and `TransferHeader-*` metadata headers used for server-side hints (e.g., `oss.asize`, `xrdcl.requuid`).
*   **Outbound `kXR_gotoTLS`:** Enable the outbound TPC client to handle in-protocol TLS upgrades when connecting to modern native XRootD sources.
*   **Asynchronous Staging (`kXR_prepare`):** Move beyond path-validation and implement a real staging queue that can return "staging in progress" status to HTTP clients, matching the behavior of tape-backed `XrdHttp` sites.

---

## Summary Checklist for Parity

| Feature Gap | Priority | Status in `nginx-xrootd` |
| :--- | :--- | :--- |
| **Performance Markers** | High | **Implemented** (`xrootd_webdav_tpc_marker_interval`) |
| **Async TPC** | High | **Implemented** (timer-based `waitpid` poll, no blocking thread) |
| **Token Refresh** | Medium | Missing (Critical for long transfers) |
| **Multi-tier Manager** | Medium | Stream redirects implemented; HTTP hierarchical redirect/proxy parity still pending |
| **S3 Presigned URLs** | Medium | **Implemented** for static access-key SigV4 |
| **Tape Staging** | Low | No-op (Path validation only) |
| **krb5 Auth** | Low | Not planned |
