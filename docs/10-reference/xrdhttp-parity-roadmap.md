# XrdHttp Parity Roadmap

Strategic parity work for gnuBall's XrdHttp/WebDAV surface: what has
landed, what remains open, and where gnuBall intentionally differs from
the official `XrdHttp` implementation.

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

*   **Multi-hop GSI Delegation:** Native root TPC can authenticate outbound with
    ztn or GSI when configured. HTTP multi-hop proxy delegation remains narrower
    than the full upstream deployment ecosystem.
*   **Token Refresh & Lifecycle:** One-shot OIDC/token-exchange delegation is
    implemented for HTTP-TPC and native TPC. Mid-transfer delegated-token renewal
    for multi-hour transfers remains open.
*   **S3 Advanced Auth:**
    *   ~~**Presigned URLs:** Support `X-Amz-Signature` query-string authentication for S3.~~ Implemented for static access-key SigV4.
    *   ~~**STS Tokens:** Parse `X-Amz-Security-Token` header/query forms.~~ Static-secret compatibility is implemented via `xrootd_s3_allow_unsigned_session_token`; dynamic temporary credential stores remain out of scope.
*   **Expanded Auth Protocols:** Kerberos 5 is implemented as optional build-time
    support. `host` (`src/auth/host/`) and `pwd` (`src/auth/pwd/`) are now also implemented,
    completing the standard upstream stream-auth set.

## Phase 3: Cluster Topology & Hierarchical Redirection
Official XRootD's `XrdHttp` is fully aware of `cmsd` cluster states.

*   **Hierarchical Redirection:** Native stream `kYR_select` / `kYR_try`
    escalation is implemented and tested. HTTP-layer hierarchical redirect/proxy
    parity is still pending.
*   **Lateral Redirects:** Support for `307 Temporary Redirect` logic that accounts for XRootD's internal load-balancing and "tried hosts" lists.
*   **Upstream Auth-More:** Transparent upstream bootstrap handles ztn token
    auth; native TPC handles ztn/GSI through its own path. Transparent-upstream
    GSI and credentialed cache/write-through origin auth remain open.

## Phase 4: Protocol Edge Cases & Performance
Fine-tuning the "look and feel" of the HTTP service to match `xrdcp davs://` expectations.

*   **XRootD-Specific Headers:** Support the full set of `X-Xrootd-*` and `TransferHeader-*` metadata headers used for server-side hints (e.g., `oss.asize`, `xrdcl.requuid`).
*   **Outbound `kXR_gotoTLS`:** Transparent upstream connections support
    `kXR_gotoTLS`; native TPC source connections remain plain TCP and still need
    TLS-upgrade support.
*   **Asynchronous Staging (`kXR_prepare`):** FRM durable queue and Tape REST
    gateway support are implemented. Full upstream XrdFrm/MSS semantics remain
    deployment-specific parity work.

---

## Summary Checklist for Parity

| Feature Gap | Priority | Status in `nginx-xrootd` |
| :--- | :--- | :--- |
| **Performance Markers** | High | **Implemented** (`xrootd_webdav_tpc_marker_interval`) |
| **Async TPC** | High | **Implemented** (timer-based `waitpid` poll, no blocking thread) |
| **Token Refresh** | Medium | One-shot delegation implemented; mid-transfer renewal remains open |
| **Multi-tier Manager** | Medium | Native stream hierarchy implemented; HTTP hierarchical redirect/proxy parity still pending |
| **S3 Presigned URLs** | Medium | **Implemented** for static access-key SigV4 |
| **Tape Staging** | Low | FRM/Tape REST implemented; full XrdFrm/MSS parity partial |
| **krb5 Auth** | Low | Optional build-time support implemented; `host`/`pwd` now also implemented (`src/auth/host/`, `src/auth/pwd/`) |
