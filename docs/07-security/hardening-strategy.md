# Security Hardening Strategy: Defending Against Malicious Queries

This document outlines recommended architectural and implementation-level improvements to harden `nginx-xrootd` against malicious protocol queries, resource exhaustion, and memory-safety exploits.

## 1. Protocol Parsing & Memory Safety

The XRootD protocol is a binary format with length-prefixed payloads. Malicious clients can send inconsistent `dlen` values or deeply nested structures to trigger overflows or excessive allocations.

### Recommendations:
*   **Fuzz Testing Integration**: Implement a fuzzer (e.g., `AFL++` or `libFuzzer`) targeting the central dispatcher in `src/protocols/root/handshake/dispatch.c` and the query parser in `src/protocols/root/query/dispatch.c`.
*   **Integer Overflow Audit**: Conduct a systematic audit of all `dlen` and `offset` calculations. Specifically, ensure that adding header sizes to `cur_dlen` does not wrap around before reaching `ngx_palloc`.
*   **Strict String Boundaries**: While `ngx_str_t` is used extensively, some legacy handlers still convert to `char *`. Prohibit `strcpy` and `sprintf` in favor of `ngx_snprintf` and `ngx_cpystrn` with explicit boundary checks.
*   **Parser State Machine**: Transition the `kXR_protocol` and `kXR_login` handlers to a formal state machine to prevent "out-of-order" attacks (e.g., sending `kXR_open` before `kXR_protocol` completes).

## 2. Resource Management (DoS Prevention)

Recursive and batch operations are primary vectors for Denial of Service (DoS) attacks.

### Recommendations:
*   **Recursive Walk Guards**: `kXR_Qckscan` and `kXR_dirlist` (with `dstat`) must enforce strict depth and file-count limits. `kXR_Qckscan` is bounded by `xrootd_ckscan_depth` and `xrootd_ckscan_max_files`.
*   **Rate Limiting by Auth ID**: Integrate with Nginx's `limit_req` module to rate-limit `kXR_open` and `kXR_query` operations based on the authenticated `DN` or `JWT subject` rather than just the IP address.
*   **Memory Pool Capping**: Large query responses (like directory listings) currently allocate from the request pool. Implement a hard cap on pool growth per connection to prevent a single malicious client from exhausting worker memory.

## 3. Filesystem & Path Hardening

Path traversal and race conditions (TOCTOU) are critical risks in a filesystem proxy.

### Recommendations:
*   **`openat(2)` Migration**: Replace `xrootd_open_confined` logic with `openat(2)` using a file descriptor to the root export. This eliminates the risk of path-traversal via symlink swaps during the name-resolution phase.
*   **Symlink Policy**: Add a directive `xrootd_allow_symlinks` (off by default). When off, the server should use `O_NOFOLLOW` for all path-based operations and manually verify that no component of the path is a symlink.
*   **Confined Stat**: Ensure `kXR_stat` and `kXR_statx` resolve paths through the same confinement logic as `kXR_open`, preventing information leakage about files outside the export root.

## 4. Authentication & Authorization Resilience

Attackers may attempt to bypass scope checks or exploit weak signature verification.

### Recommendations:
*   **Scope Intersection Invariant**: Ensure that when multiple token scopes apply to a path, the server uses the **most restrictive** intersection of permissions.
*   **Macaroon Caveat Audit**: Harder validation for Macaroon `path:` caveats. If a caveat path is disjoint from the token's original scope, the entire token should be revoked immediately rather than silently ignoring the discrepancy.
*   **Signature Timing Attacks**: Use `CRYPTO_memcmp` or equivalent constant-time comparison for all HMAC and signature verification steps (SSS, Macaroons, JWT).

## 5. Summary of Implementation Priorities

| Priority | Feature | Target |
|---|---|---|
| **Critical** | `openat(2)` transition | `src/path/` |
| **High** | Fuzzing framework | `tests/fuzzing/` |
| **High** | Walk depth/count limits | `src/protocols/root/query/` |
| **Medium** | State-machine enforcement | `src/protocols/root/handshake/` |
| **Medium** | Rate-limiting by ID | `src/core/config/` |
