# XrdHttp Parity Roadmap

This document outlines the strategic work required to bring the `nginx-xrootd` module to full feature parity with the official XRootD `XrdHttp` protocol. While the module currently provides robust WebDAV and S3 support, reaching parity involves implementing specialized HEP data-transfer extensions, advanced TPC observability, and hierarchical cluster management.

---

## Phase 1: High-Fidelity TPC Observability
Official `XrdHttp` (and FTS) relies on periodic progress reporting for long-lived transfers.

*   **Asynchronous TPC Client:** Replace the current thread-pool-based `curl` execution with a fully asynchronous event-driven client or a managed process monitor to prevent thread-pool exhaustion during high-concurrency transfers.
*   **Performance-Marker Streaming:** Implement support for `202 Accepted` responses with a chunked body. The module must stream `Performance-Marker:` lines (Transfer-Rate, Time-Since-Start, etc.) back to FTS while the outbound transfer is still in progress.
*   **TPC Status API:** Implement the XRootD-specific `tpc.src=...` status query dialect over HTTP to allow clients to poll for the state of a background pull.

## Phase 2: Advanced Authentication & Delegation
`XrdHttp` supports complex grid delegation patterns that are currently simplified in this module.

*   **Multi-hop GSI Delegation:** Implement the ability to receive a delegated proxy from a client and use it to authenticate outbound TPC connections to a third server.
*   **Token Refresh & Lifecycle:** Add a background worker or event-timer to refresh delegated OIDC tokens via `oidc-agent` or `token-exchange` endpoints during multi-hour transfers.
*   **S3 Advanced Auth:**
    *   **Presigned URLs:** Support `X-Amz-Signature` query-string authentication for S3.
    *   **STS Tokens:** Parse and validate `X-Amz-Security-Token` for temporary role-based access.
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
| **Performance Markers** | High | Missing (Needed for FTS observability) |
| **Async TPC** | High | Missing (Prevents thread-pool exhaustion) |
| **Token Refresh** | Medium | Missing (Critical for long transfers) |
| **Multi-tier Manager** | Medium | Partial (Only two-tier supported) |
| **S3 Presigned URLs** | Medium | Missing (Common for browser/SDK access) |
| **Tape Staging** | Low | No-op (Path validation only) |
| **krb5 Auth** | Low | Not planned |
