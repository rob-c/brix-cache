# Advanced Security Hardening: Defense-in-Depth Proposals

This document outlines "next-level" security enhancements for `nginx-xrootd`, focusing on runtime integrity, syscall-level isolation, and deep protocol validation.

## 1. Runtime Isolation: Seccomp-BPF
While NGINX provides process isolation, the XRootD module performs complex filesystem and network operations that expand the attack surface.

### Proposal:
*   **Restricted Syscall Profile**: Implement a tailored Seccomp-BPF filter for NGINX worker processes.
*   **Whitelisting**: Allow only necessary syscalls (`pread`, `pwrite`, `sendfile`, `stat`, `openat`). Block `execve`, `socket` (except for upstream), and `process_vm_writev`.
*   **Implementation**: Use `libseccomp` to load the profile during the worker initialization phase (`ngx_worker_process_init`).

## 2. Opaque Parameter (CGI) Sanitization
XRootD makes heavy use of "opaque" query strings (e.g., `?oss.asize=100&tpc.key=...`). These are currently parsed with basic string matching.

### Proposal:
*   **Schema-based Validation**: Define a strict schema for all recognized `oss.*`, `tpc.*`, and `auth.*` parameters.
*   **Type Enforcement**: Reject any parameter that does not match its expected type (e.g., `oss.asize` must be a positive integer).
*   **Illegal Byte Rejection**: Reject any opaque string containing control characters, shell metacharacters, or non-ASCII bytes before they reach the handler logic.

## 3. Protocol Downgrade Protection
Attackers may attempt to force a session into a lower security state (e.g., cleartext or unsigned) by spoofing `kXR_protocol` flags.

### Proposal:
*   **Minimum Security Level Enforcement**: Add a directive `xrootd_min_sec_level`. If a client attempts to negotiate a level below this (e.g., no TLS when `intense` is required), the server should terminate the connection immediately after the handshake.
*   **TLS Pinning for Upstream**: When acting as a proxy or cache, the module should require a valid, trusted certificate from the upstream origin, prohibiting fallback to cleartext even if requested by the client.

## 4. Metadata Side-Channel Mitigation
Frequent `kXR_stat` or `kXR_locate` queries against non-existent paths can leak information about the directory structure or overload the CMS registry.

### Proposal:
*   **Negative Cache with Backoff**: Implement a short-lived "negative cache" for non-existent paths. If a client repeatedly queries the same missing file, the server should introduce an artificial `kXR_wait` delay.
*   **Stat-Harvesting Detection**: Track the ratio of `stat` to `read` operations. A high ratio of metadata queries across a wide path range should trigger an automatic temporary block of the subject ID.

## 5. Formal Verification of ACL Logic
The intersection of AuthDB, VO ACLs, and Token Scopes is the most complex security path in the codebase.

### Proposal:
*   **Model Checking**: Use a formal tool (like TLA+ or a bounded model checker) to verify the path-resolution and ACL-intersection logic in `src/path/acl.c` and `src/handshake/policy.c`.
*   **Unit Test Invariants**: Create a "negative test suite" that exhaustively attempts to bypass every combination of ACL and Token Scope to ensure no edge-case permits unauthorized access.

## Summary of Advanced Priorities

| Priority | Feature | Category |
|---|---|---|
| **High** | Opaque Schema Validation | Protocol Integrity |
| **High** | Downgrade Protection | Transport Security |
| **Medium** | Seccomp-BPF Whitelisting | Runtime Isolation |
| **Medium** | Negative Stat Backoff | DoS Resilience |
| **Low** | Formal Verification | Assurance |
